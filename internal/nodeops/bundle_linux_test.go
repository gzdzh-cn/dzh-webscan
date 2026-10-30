//go:build linux

package nodeops

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/nodeconfig"
)

func TestRealNativeBundleToolsInDisposableLinuxContainer(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("WEBSCAN_V3_TEST_BUNDLE") != "1" {
		t.Skip("requires explicitly opted-in disposable Linux scanner container")
	}
	// Exercise the shipped scanner loader/libraries and native ELF from the
	// existing image, not a replacement shell script. Its v2 version is only a
	// package-validation fixture; this test does not start or migrate an Agent.
	raw, err := os.ReadFile("/usr/local/lib/webscan/agent-native.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	version := ""
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimPrefix(h.Name, "./") == "VERSION" {
			b, err := io.ReadAll(io.LimitReader(tr, 129))
			if err != nil || len(b) > 128 {
				t.Fatal("invalid fixture version", err)
			}
			version = strings.TrimSpace(string(b))
			break
		}
	}
	w, r := stageFixture(t, raw)
	w.probe = probeBundle
	r.Spec.Release = version
	attachConfiguration(t, w, &r, nil)
	if _, err := w.Apply(r); err != nil {
		t.Fatal("real bundle validation failed", err)
	}
	if err := w.VerifyCompleted(r, preparedOutcome()); err != nil {
		t.Fatal("real prepared bundle cannot be replayed", err)
	}
	// The actual scanner process must reject invalid rules before activation.
	dir := w.releaseDir(r.Spec)
	invalid := filepath.Join(testRoot(t), "invalid.yar")
	if err := os.WriteFile(invalid, []byte("rule broken { condition: }"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := bundleCommand(context.Background(), filepath.Join(dir, "tools/bin/yara"), "-w", invalid, "/dev/null"); err == nil {
		t.Fatal("broken YARA rules were accepted by real scanner")
	}
	attachConfiguration(t, w, &r, func(m *nodeconfig.Material) { m.YARA = []byte("rule broken { condition: }") })
	if _, err := w.Apply(r); err == nil {
		t.Fatal("invalid new configuration rules accepted by real scanner")
	}
	if _, err := os.Lstat(w.configurationDir(r.Spec)); !os.IsNotExist(err) {
		t.Fatal("invalid configuration was published", err)
	}
}

func TestRealDockerSaveArchiveInDisposableLinuxContainer(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("WEBSCAN_V3_TEST_IMAGE_ARCHIVE") != "1" {
		t.Skip("requires explicitly opted-in disposable Linux image archive fixture")
	}
	raw, err := os.ReadFile("/v3-tests/image-proof.json")
	if err != nil {
		t.Fatal(err)
	}
	var s Spec
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	root := testRoot(t)
	dir := filepath.Join(root, "images", s.ImageArchiveSHA256)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open("/v3-tests/agent-image.tar")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(filepath.Join(dir, "docker-image.tar"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(target, source)
	closeErr := target.Close()
	if err != nil || closeErr != nil {
		t.Fatal("copy archive", err, closeErr)
	}
	verified, err := verifiedImageArchive(context.Background(), root, s)
	if err != nil {
		t.Fatal("real Docker-save archive rejected", err)
	}
	verified.Close()
}
