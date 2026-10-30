package nodeops

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func minimalELF() []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], 62)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[58:], 64)
	return b
}

func bundleFiles() map[string][]byte {
	return map[string][]byte{
		"webscan": minimalELF(), "VERSION": []byte("v3.0.0\n"),
		"tools/bin/yara": []byte("#!/bin/sh\nexit 0\n"),
		"tools/lib/yara": []byte("fixture scanner"), "tools/lib/ld-linux-x86-64.so.2": []byte("fixture loader"),
		"tools/bin/clamdscan": []byte("fixture client"), "tools/lib/clamdscan": []byte("fixture client library"),
		"licenses/yara.txt": []byte("fixture copyright"),
	}
}

func bundleChecksums(files map[string][]byte) {
	var names []string
	for name := range files {
		if name != "SHA256SUMS" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var text strings.Builder
	for _, name := range names {
		text.WriteString(sha(files[name]) + "  ./" + name + "\n")
	}
	files["SHA256SUMS"] = []byte(text.String())
}

func archiveFiles(t *testing.T, files map[string][]byte, extra *tar.Header) []byte {
	t.Helper()
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tw := tar.NewWriter(gz)
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := tw.WriteHeader(&tar.Header{Name: "./" + name, Mode: 07777, Typeflag: tar.TypeReg, Size: int64(len(files[name]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if extra != nil {
		if err := tw.WriteHeader(extra); err != nil {
			t.Fatal(err)
		}
	}
	// Intentionally oversized entry headers are useful invalid fixtures. Their
	// incomplete payload does not need to become a well-formed source archive.
	tw.Close()
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func stageFixture(t *testing.T, raw []byte) (*LocalRuntime, Request) {
	t.Helper()
	root := testRoot(t)
	r := testRequest(root)
	r.Phase = "stage"
	r.Spec.Release, r.Spec.BundleSHA256, r.Spec.ArtifactBytes = "v3.0.0", sha(raw), uint64(len(raw))
	packageDir := filepath.Join(root, "packages", r.Spec.BundleSHA256)
	if err := os.MkdirAll(packageDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "agent-native.tar.gz"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	w := &LocalRuntime{root: root, probe: func(context.Context, string, Spec) error { return nil }}
	return w, r
}

func TestBundlePreparationPublishesVerifiedFilesAndReconciles(t *testing.T) {
	files := bundleFiles()
	bundleChecksums(files)
	w, r := stageFixture(t, archiveFiles(t, files, nil))
	// Unrelated live data is outside all prepared directories and must survive.
	live := filepath.Join(w.root, "agent-data")
	if err := os.WriteFile(live, []byte("new event after previous deployment"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := w.Apply(r)
	if err != nil || !validOutcome(out) {
		t.Fatal("valid bundle rejected", err)
	}
	dir := w.releaseDir(r.Spec)
	for name, data := range files {
		file := filepath.Join(dir, name)
		got, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal("different prepared file", name, err)
		}
		st, err := os.Stat(file)
		if err != nil || st.Mode().Perm() != bundleMode(name) {
			t.Fatal("archive privileges were retained", name)
		}
	}
	if err := os.Remove(filepath.Join(w.root, "packages", r.Spec.BundleSHA256, "agent-native.tar.gz")); err != nil {
		t.Fatal(err)
	}
	state, _, err := w.Reconcile(r)
	if state != "complete" || err != nil {
		t.Fatal("published stage was not reconciled", state, err)
	}
	if _, err := w.Apply(r); err != nil {
		t.Fatal("idempotent prepared stage requires original upload", err)
	}
	got, _ := os.ReadFile(live)
	if string(got) != "new event after previous deployment" {
		t.Fatal("preparation touched live data")
	}
	if err := os.WriteFile(filepath.Join(dir, "tools/lib/yara"), []byte("changed"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := w.VerifyCompleted(r, out); err == nil {
		t.Fatal("stale receipt accepted changed files")
	}
	state, _, err = w.Reconcile(r)
	if state != "unknown" || err == nil {
		t.Fatal("corruption was silently repaired", state, err)
	}
}

func TestBundlePreparationRejectsUnsafeArchives(t *testing.T) {
	cases := []struct {
		name  string
		extra *tar.Header
	}{
		{"parent", &tar.Header{Name: "../outside", Typeflag: tar.TypeReg}},
		{"absolute", &tar.Header{Name: "/tmp/outside", Typeflag: tar.TypeReg}},
		{"absolute-root-directory", &tar.Header{Name: "/", Typeflag: tar.TypeDir}},
		{"duplicate", &tar.Header{Name: "webscan", Typeflag: tar.TypeReg}},
		{"symlink", &tar.Header{Name: "tools/lib/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}},
		{"hardlink", &tar.Header{Name: "tools/lib/link", Typeflag: tar.TypeLink, Linkname: "webscan"}},
		{"fifo", &tar.Header{Name: "tools/lib/pipe", Typeflag: tar.TypeFifo}},
		{"large-file", &tar.Header{Name: "tools/lib/large", Typeflag: tar.TypeReg, Size: maxBundleFile + 1}},
		{"unexpected", &tar.Header{Name: "etc/config", Typeflag: tar.TypeReg}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := bundleFiles()
			bundleChecksums(files)
			w, r := stageFixture(t, archiveFiles(t, files, c.extra))
			if _, err := w.Apply(r); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			if _, err := os.Lstat(w.releaseDir(r.Spec)); !os.IsNotExist(err) {
				t.Fatal("failed preparation published files", err)
			}
			entries, _ := os.ReadDir(filepath.Join(w.root, "releases"))
			if len(entries) != 0 {
				t.Fatal("failed preparation left partial files")
			}
		})
	}
}

func TestBundleChecksumsVersionAndScannerFailuresDoNotPublish(t *testing.T) {
	for _, kind := range []string{"checksum", "missing-file", "missing-checksum", "version", "architecture", "probe", "probe-modifies-file", "gzip-crc", "trailing-data", "archive-digest", "missing-clamav", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			files := bundleFiles()
			if kind == "version" {
				files["VERSION"] = []byte("v3.0.1\n")
			}
			if kind == "architecture" {
				binary.LittleEndian.PutUint16(files["webscan"][18:], 183)
			}
			if kind == "missing-clamav" {
				delete(files, "tools/bin/clamdscan")
			}
			bundleChecksums(files)
			switch kind {
			case "checksum":
				files["webscan"] = append(files["webscan"], 'x')
			case "missing-file":
				delete(files, "webscan")
			case "missing-checksum":
				files["SHA256SUMS"] = []byte(strings.ReplaceAll(string(files["SHA256SUMS"]), sha(files["VERSION"])+"  ./VERSION\n", ""))
			}
			raw := archiveFiles(t, files, nil)
			if kind == "gzip-crc" {
				raw[len(raw)-8] ^= 0x01
			}
			if kind == "trailing-data" {
				raw = append(raw, 'x')
			}
			w, r := stageFixture(t, raw)
			if kind == "missing-clamav" {
				r.Spec.ClamAV = true
			}
			if kind == "probe" {
				w.probe = func(context.Context, string, Spec) error { return errors.New("sensitive command output") }
			}
			if kind == "probe-modifies-file" {
				w.probe = func(_ context.Context, dir string, _ Spec) error {
					return os.WriteFile(filepath.Join(dir, "VERSION"), []byte("changed"), 0600)
				}
			}
			if kind == "archive-digest" {
				file := filepath.Join(w.root, "packages", r.Spec.BundleSHA256, "agent-native.tar.gz")
				raw[len(raw)/2] ^= 1
				os.WriteFile(file, raw, 0600)
			}
			var err error
			if kind == "canceled" {
				ctx, stop := context.WithCancel(context.Background())
				stop()
				err = w.prepare(ctx, r.Spec)
			} else {
				_, err = w.Apply(r)
			}
			if err == nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatal("bad bundle accepted or command error leaked", err)
			}
			if _, err := os.Lstat(w.releaseDir(r.Spec)); !os.IsNotExist(err) {
				t.Fatal("invalid package published", err)
			}
		})
	}
}

type stageTestRuntime struct{ *LocalRuntime }

func (s stageTestRuntime) Apply(r Request) (Outcome, error) {
	if r.Phase == "preflight" {
		return Outcome{}, nil // only the host-dependent probe is substituted
	}
	return s.LocalRuntime.Apply(r)
}

func TestJournalStageReconcilesPublishedFilesAndRejectsStaleReceipt(t *testing.T) {
	files := bundleFiles()
	bundleChecksums(files)
	w, r := stageFixture(t, archiveFiles(t, files, nil))
	j := openTestJournal(t, filepath.Join(w.root, "node"), stageTestRuntime{w})
	r.Phase = "preflight"
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "stage"
	requireResult(t, j.Handle(r), "complete", "ok")
	db, err := j.database()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE phases SET status='running' WHERE phase='stage'"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	r.Epoch, r.Operation = 2, "inspect"
	requireResult(t, j.Handle(r), "complete", "ok")
	if err := os.RemoveAll(w.releaseDir(r.Spec)); err != nil {
		t.Fatal(err)
	}
	requireResult(t, j.Handle(r), "unknown", "artifact-invalid")
}

func TestBundlePreparationRefusesArchiveAndReleaseSymlinks(t *testing.T) {
	for _, kind := range []string{"archive", "release", "parent", "hardlink", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			files := bundleFiles()
			bundleChecksums(files)
			w, r := stageFixture(t, archiveFiles(t, files, nil))
			archive := filepath.Join(w.root, "packages", r.Spec.BundleSHA256, "agent-native.tar.gz")
			outside := filepath.Join(testRoot(t), "outside")
			if kind == "release" || kind == "parent" {
				os.MkdirAll(filepath.Join(w.root, "releases"), 0700)
				target := w.releaseDir(r.Spec)
				if kind == "parent" {
					target = filepath.Join(w.root, "releases")
					os.Remove(target)
				}
				if err := os.Symlink(filepath.Dir(outside), target); err != nil {
					t.Fatal(err)
				}
			} else if kind == "permissions" {
				os.Chmod(archive, 0644)
			} else {
				data, _ := os.ReadFile(archive)
				os.WriteFile(outside, data, 0600)
				os.Remove(archive)
				var err error
				if kind == "hardlink" {
					err = os.Link(outside, archive)
				} else {
					err = os.Symlink(outside, archive)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := w.Apply(r); err == nil {
				t.Fatal("unsafe archive path accepted")
			}
		})
	}
}

func TestBundleReaderHasFiniteBounds(t *testing.T) {
	if _, err := fileDigest(context.Background(), strings.NewReader("oversized"), 2); err == nil {
		t.Fatal("unbounded digest accepted")
	}
}

func TestDockerStageCannotClaimThatImagePreparationIsComplete(t *testing.T) {
	files := bundleFiles()
	bundleChecksums(files)
	w, r := stageFixture(t, archiveFiles(t, files, nil))
	r.Spec.Mode = "docker"
	if _, err := w.Apply(r); failureCode(err) != "artifact-invalid" {
		t.Fatal("Docker stage falsely reported image ready", err)
	}
}
