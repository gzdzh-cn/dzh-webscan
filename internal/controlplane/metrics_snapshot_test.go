package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

const fixtureMetricsSnapshot = "20261031113025-1ABC"
const fixtureOldMetricsSnapshot = "20261030113025-99FF"

type metricsSnapshotFixture struct {
	store           metricsSnapshotStore
	parent          string
	mu              sync.Mutex
	requests        []string
	create, cleanup string
	list            []string
	server          *httptest.Server
}

func newMetricsSnapshotFixture(t *testing.T) *metricsSnapshotFixture {
	t.Helper()
	f := &metricsSnapshotFixture{parent: privateTestDir(t), list: []string{fixtureOldMetricsSnapshot}}
	f.store.Directory = filepath.Join(f.parent, "storage")
	snapshot := filepath.Join(f.store.Directory, "snapshots", fixtureMetricsSnapshot)
	for _, name := range []string{"snapshots/" + fixtureOldMetricsSnapshot, "snapshots/" + fixtureMetricsSnapshot + "/data", "snapshots/" + fixtureMetricsSnapshot + "/metadata", "data/big/snapshots/" + fixtureMetricsSnapshot, "data/small/snapshots/" + fixtureMetricsSnapshot + "/2026_10/part", "indexdb/snapshots/" + fixtureMetricsSnapshot + "/0123456789ABCDEF"} {
		if err := os.MkdirAll(filepath.Join(f.store.Directory, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, part := range []struct{ from, to string }{
		{"../../../data/big/snapshots/" + fixtureMetricsSnapshot, "data/big"},
		{"../../../data/small/snapshots/" + fixtureMetricsSnapshot, "data/small"},
		{"../../indexdb/snapshots/" + fixtureMetricsSnapshot, "indexdb"},
	} {
		if err := os.Symlink(part.from, filepath.Join(snapshot, part.to)); err != nil {
			t.Fatal(err)
		}
	}
	for name, raw := range map[string][]byte{
		"data/small/snapshots/" + fixtureMetricsSnapshot + "/2026_10/part/timestamps.bin": {0, 1, 2, 3, 4},
		"indexdb/snapshots/" + fixtureMetricsSnapshot + "/0123456789ABCDEF/metaindex.bin": []byte("immutable index part"),
		"snapshots/" + fixtureMetricsSnapshot + "/metadata/minTimestampForCompositeIndex": []byte("1770000000000"),
		"snapshots/" + fixtureOldMetricsSnapshot + "/preserve":                            []byte("unrelated old snapshot"),
	} {
		if err := os.WriteFile(filepath.Join(f.store.Directory, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Production snapshot parts are hard-linked to live immutable parts. Their
	// exported copies must become independent, including when source is gone.
	if err := os.Link(filepath.Join(f.store.Directory, "data/small/snapshots/"+fixtureMetricsSnapshot+"/2026_10/part/timestamps.bin"), filepath.Join(f.store.Directory, "live-part")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshot, "metadata/empty"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.URL.RequestURI())
		switch r.URL.Path {
		case "/snapshot/list":
			json.NewEncoder(w).Encode(map[string]any{"status": "ok", "snapshots": f.list})
		case "/snapshot/create":
			if f.create != "" {
				fmt.Fprint(w, f.create)
			} else {
				json.NewEncoder(w).Encode(map[string]string{"status": "ok", "snapshot": fixtureMetricsSnapshot})
			}
		case "/snapshot/delete":
			if r.URL.Query().Get("snapshot") != fixtureMetricsSnapshot {
				t.Error("tried to delete another snapshot", r.URL)
				w.WriteHeader(500)
				return
			}
			if f.cleanup != "" {
				fmt.Fprint(w, f.cleanup)
			} else {
				fmt.Fprint(w, `{"status":"ok"}`)
			}
		default:
			t.Error("unexpected endpoint", r.URL)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(server.Close)
	f.store.URL, f.store.HTTP = server.URL, server.Client()
	f.server = server
	return f
}

func TestMetricsSnapshotIndependentBackupAndFreshRestore(t *testing.T) {
	f := newMetricsSnapshotFixture(t)
	ctx := context.Background()
	output := filepath.Join(f.parent, "backup")
	receipt, err := f.store.backup(ctx, output)
	if err != nil || !receipt.SnapshotClean || receipt.ManifestSHA256 == "" || receipt.Files != 4 || receipt.Bytes == 0 {
		t.Fatal(receipt, err)
	}
	if !reflect.DeepEqual(f.requests, []string{"/snapshot/list", "/snapshot/create", "/snapshot/delete?snapshot=" + fixtureMetricsSnapshot}) {
		t.Fatal(f.requests)
	}
	if raw, err := os.ReadFile(filepath.Join(f.store.Directory, "snapshots/"+fixtureOldMetricsSnapshot+"/preserve")); err != nil || string(raw) != "unrelated old snapshot" {
		t.Fatal("modified unrelated snapshot", err)
	}
	if err := os.RemoveAll(f.store.Directory); err != nil {
		t.Fatal(err)
	}
	manifest, err := verifyMetricsSnapshot(ctx, output, receipt.ManifestSHA256)
	if err != nil || !reflect.DeepEqual(manifest.Directories[:3], []string{"data", "data/big", "data/small"}) {
		t.Fatal(manifest.Directories, err)
	}
	newStorage := filepath.Join(f.parent, "restored")
	if err := restoreMetricsSnapshot(ctx, output, receipt.ManifestSHA256, newStorage); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(filepath.Join(newStorage, "data/small/2026_10/part/timestamps.bin")); err != nil || !bytes.Equal(raw, []byte{0, 1, 2, 3, 4}) {
		t.Fatal("lost part", raw, err)
	}
	if _, err := os.Lstat(filepath.Join(newStorage, "snapshot.json")); !os.IsNotExist(err) {
		t.Fatal("copied backup manifest into running storage", err)
	}
	for _, target := range []string{output, newStorage, filepath.Join(output, "nested")} {
		if err := restoreMetricsSnapshot(ctx, output, receipt.ManifestSHA256, target); err == nil {
			t.Fatal("overwrote existing storage or backup", target)
		}
	}
	if _, err := f.store.backup(ctx, output); err == nil || len(f.requests) != 3 {
		t.Fatal("existing backup contacted service or was replaced", f.requests, err)
	}
}

func TestMetricsSnapshotRejectsUnsafeSourceAndStillCleansOwnSnapshot(t *testing.T) {
	for _, kind := range []string{"live-symlink", "absolute-symlink", "nested-symlink", "symlink-component", "fifo", "writable-part", "extra-top-level"} {
		t.Run(kind, func(t *testing.T) {
			f := newMetricsSnapshotFixture(t)
			snapshot := filepath.Join(f.store.Directory, "snapshots", fixtureMetricsSnapshot)
			part := filepath.Join(f.store.Directory, "data/small/snapshots/"+fixtureMetricsSnapshot+"/2026_10/part")
			switch kind {
			case "live-symlink", "absolute-symlink":
				os.Remove(filepath.Join(snapshot, "data/small"))
				target := "../../../data/small"
				if kind == "absolute-symlink" {
					target = filepath.Join(f.store.Directory, "data/small/snapshots", fixtureMetricsSnapshot)
				}
				os.Symlink(target, filepath.Join(snapshot, "data/small"))
			case "nested-symlink":
				os.Symlink(filepath.Join(f.store.Directory, "live-part"), filepath.Join(part, "outside"))
			case "symlink-component":
				os.Rename(filepath.Join(f.store.Directory, "indexdb"), filepath.Join(f.store.Directory, "other-index"))
				os.Symlink("other-index", filepath.Join(f.store.Directory, "indexdb"))
			case "fifo":
				if err := unix.Mkfifo(filepath.Join(part, "pipe"), 0600); err != nil {
					t.Fatal(err)
				}
			case "writable-part":
				os.Chmod(filepath.Join(part, "timestamps.bin"), 0666)
			case "extra-top-level":
				os.WriteFile(filepath.Join(snapshot, "unexpected"), []byte("stop"), 0600)
			}
			output := filepath.Join(f.parent, "backup")
			receipt, err := f.store.backup(context.Background(), output)
			if err == nil || receipt.Directory != "" || !receipt.SnapshotClean {
				t.Fatal("unsafe source accepted or cleanup skipped", receipt, err)
			}
			if entries, _ := os.ReadDir(f.parent); len(entries) != 1 || entries[0].Name() != "storage" {
				t.Fatal("partial archive left behind", entries)
			}
			if len(f.requests) != 3 || !strings.Contains(f.requests[2], "snapshot="+fixtureMetricsSnapshot) {
				t.Fatal(f.requests)
			}
		})
	}
}

func TestMetricsSnapshotCorruptionNeverPublishesRestore(t *testing.T) {
	for _, mutation := range []string{"content", "truncation", "manifest", "extra-file", "missing-empty-dir", "symlink", "hardlink", "permissions", "directory-permissions"} {
		t.Run(mutation, func(t *testing.T) {
			f := newMetricsSnapshotFixture(t)
			output := filepath.Join(f.parent, "backup")
			receipt, err := f.store.backup(context.Background(), output)
			if err != nil {
				t.Fatal(err)
			}
			part := filepath.Join(output, "data/small/2026_10/part/timestamps.bin")
			switch mutation {
			case "content":
				os.WriteFile(part, []byte{5, 4, 3, 2, 1}, 0600)
			case "truncation":
				os.Truncate(part, 2)
			case "manifest":
				raw, _ := os.ReadFile(filepath.Join(output, "snapshot.json"))
				os.WriteFile(filepath.Join(output, "snapshot.json"), bytes.ReplaceAll(raw, []byte(`"format":1`), []byte(`"format":2`)), 0600)
			case "extra-file":
				os.WriteFile(filepath.Join(output, "metadata/extra"), []byte("not archived"), 0600)
			case "missing-empty-dir":
				os.Remove(filepath.Join(output, "data/big"))
			case "symlink":
				os.Remove(part)
				os.Symlink(filepath.Join(f.store.Directory, "live-part"), part)
			case "hardlink":
				os.Link(part, filepath.Join(f.parent, "alias"))
			case "permissions":
				os.Chmod(part, 0644)
			case "directory-permissions":
				os.Chmod(filepath.Dir(part), 0755)
			}
			restored := filepath.Join(f.parent, "restored")
			if err := restoreMetricsSnapshot(context.Background(), output, receipt.ManifestSHA256, restored); err == nil {
				t.Fatal("accepted corrupt backup", mutation)
			}
			if _, err := os.Lstat(restored); !os.IsNotExist(err) {
				t.Fatal("failed verification published a restore", err)
			}
		})
	}
}

func TestMetricsSnapshotAmbiguousCreateNeverDeletesAnotherSnapshot(t *testing.T) {
	for _, reply := range []string{
		`{"status":"ok","snapshot":"../../elsewhere"}`,
		`{"status":"ok","snapshot":"20261331113025-1ABC"}`,
		`{"status":"ok","snapshot":"` + fixtureOldMetricsSnapshot + `"}`,
		`{"status":"ok","snapshot":"` + fixtureMetricsSnapshot + `","snapshot":"` + fixtureOldMetricsSnapshot + `"}`,
		`{"status":"error","error":"secret credential must not be logged"}`,
		`{"status":"ok"}`,
	} {
		t.Run(fmt.Sprint(len(reply), reply[:min(18, len(reply))]), func(t *testing.T) {
			f := newMetricsSnapshotFixture(t)
			f.create = reply
			_, err := f.store.backup(context.Background(), filepath.Join(f.parent, "backup"))
			if err == nil || strings.Contains(err.Error(), "secret") || len(f.requests) != 2 {
				t.Fatal("ambiguous creation accepted, exposed details or deleted snapshot", err, f.requests)
			}
		})
	}
}

func TestMetricsSnapshotCleanupFailureRetainsVerifiedArtifact(t *testing.T) {
	f := newMetricsSnapshotFixture(t)
	f.cleanup = `{"status":"error","error":"private detail"}`
	receipt, err := f.store.backup(context.Background(), filepath.Join(f.parent, "backup"))
	if !errors.Is(err, errMetricsSnapshotCleanup) || receipt.SnapshotClean || receipt.Directory == "" {
		t.Fatal(receipt, err)
	}
	if _, err := verifyMetricsSnapshot(context.Background(), receipt.Directory, receipt.ManifestSHA256); err != nil {
		t.Fatal("discarded independently valid backup on cleanup failure", err)
	}
}

func TestMetricsSnapshotFailedCopyAndCleanupNeverClaimValidBackup(t *testing.T) {
	f := newMetricsSnapshotFixture(t)
	f.cleanup = `{"status":"error"}`
	if err := os.Symlink("/unrelated/path", filepath.Join(f.store.Directory, "snapshots/"+fixtureMetricsSnapshot+"/metadata/unexpected-link")); err != nil {
		t.Fatal(err)
	}
	receipt, err := f.store.backup(context.Background(), filepath.Join(f.parent, "backup"))
	if !errors.Is(err, errMetricsSnapshotCleanup) || !errors.Is(err, errMetricsSnapshot) || receipt.SnapshotClean || receipt.Snapshot != fixtureMetricsSnapshot || receipt.Directory != "" || receipt.ManifestSHA256 != "" {
		t.Fatal("failed copy or pending cleanup was reported as valid backup", receipt, err)
	}
}

func TestMetricsSnapshotRejectsEndpointRedirectionAndDestinationLinks(t *testing.T) {
	f := newMetricsSnapshotFixture(t)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, f.store.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirect.Close()
	for _, endpoint := range []string{redirect.URL, "http://192.0.2.1:8428", f.store.URL + "/prefix", f.store.URL + "?token=secret"} {
		v := f.store
		v.URL = endpoint
		if _, err := v.backup(context.Background(), filepath.Join(f.parent, "backup")); err == nil || len(f.requests) != 0 {
			t.Fatal("contacted redirected/unconfigured endpoint", endpoint, f.requests, err)
		}
	}
	if err := os.Symlink(f.parent, filepath.Join(f.parent, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{filepath.Join(f.parent, "alias/backup"), filepath.Join(f.store.Directory, "backups/backup")} {
		if _, err := f.store.backup(context.Background(), output); err == nil || len(f.requests) != 0 {
			t.Fatal("unsafe destination contacted service", err, f.requests)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.store.backup(ctx, filepath.Join(f.parent, "canceled")); err == nil || len(f.requests) != 0 {
		t.Fatal("canceled operation contacted service", err, f.requests)
	}
}

type metricsSnapshotTestTransport func(*http.Request) (*http.Response, error)

func (f metricsSnapshotTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type metricsSnapshotCancelReader struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r metricsSnapshotCancelReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if err == io.EOF {
		r.cancel()
	}
	return n, err
}

func TestMetricsSnapshotCancellationAfterCreateStillCleans(t *testing.T) {
	f := newMetricsSnapshotFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := f.store.HTTP.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	f.store.HTTP.Transport = metricsSnapshotTestTransport(func(r *http.Request) (*http.Response, error) {
		response, err := base.RoundTrip(r)
		if err == nil && r.URL.Path == "/snapshot/create" {
			response.Body = metricsSnapshotCancelReader{response.Body, cancel}
		}
		return response, err
	})
	receipt, err := f.store.backup(ctx, filepath.Join(f.parent, "backup"))
	if err == nil || !receipt.SnapshotClean || receipt.Directory != "" || receipt.Snapshot != fixtureMetricsSnapshot || len(f.requests) != 3 {
		t.Fatal("cancellation skipped cleanup or published incomplete backup", receipt, err, f.requests)
	}
}

func TestMetricsSnapshotVerificationCommandRequiresPinnedManifest(t *testing.T) {
	f := newMetricsSnapshotFixture(t)
	receipt, err := f.store.backup(context.Background(), filepath.Join(f.parent, "backup"))
	if err != nil {
		t.Fatal(err)
	}
	request := metricsSnapshotRestoreSpec{Format: 1, Directory: receipt.Directory, ManifestSHA256: receipt.ManifestSHA256}
	raw, _ := json.Marshal(request)
	source := filepath.Join(f.parent, "verify.json")
	os.WriteFile(source, raw, 0600)
	var out bytes.Buffer
	options := Options{Action: "verify-metrics-backup", Source: source, Config: "/does-not-read-live-configuration"}
	if err := Command(context.Background(), options, nil, &out); err != nil || !strings.Contains(out.String(), `"state":"verified"`) || !strings.Contains(out.String(), `"postgres_and_host_recovery_included":false`) {
		t.Fatal(out.String(), err)
	}
	for _, invalid := range [][]byte{
		bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1),
		bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"command":"something"`), 1),
		bytes.Replace(raw, []byte(receipt.ManifestSHA256), []byte(strings.Repeat("0", 64)), 1),
	} {
		os.WriteFile(source, invalid, 0600)
		out.Reset()
		if err := Command(context.Background(), options, nil, &out); err == nil || out.Len() != 0 {
			t.Fatal("invalid request/manifest accepted", err, out.String())
		}
	}
}
