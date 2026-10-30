package controlplane

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestBundleProvisionUsesPinnedArchiveAndSeparateDirectory(t *testing.T) {
	s := testStore(t)
	raw := bytes.Repeat([]byte("b"), 2048)
	a := ReleaseArtifact{SHA256: digest(raw), Bytes: uint64(len(raw))}
	file := filepath.Join(privateTestDir(t), "fixture-bundle.tar.gz")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	calls, valid := 0, true
	f := startNodeRPC(t, func(command string, ch ssh.Channel) {
		if strings.Contains(command, "artifact-verified") {
			io.ReadAll(ch)
			io.WriteString(ch, "artifact-missing\n")
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return
		}
		body, err := io.ReadAll(ch)
		mu.Lock()
		calls++
		valid = valid && err == nil && bytes.Equal(body, raw) && strings.Contains(command, "/packages/"+a.SHA256) && strings.Contains(command, "file=agent-native.tar.gz") && strings.Contains(command, "chmod 600") && !strings.Contains(command, file)
		mu.Unlock()
		io.WriteString(ch, "bundle-ready\n")
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	})
	f.native = a
	j, worker := setupRPCJob(t, s, f)
	if err := worker.ProvisionBundle(context.Background(), j, file); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 || !valid {
		t.Fatal("wrong archive upload", calls, valid)
	}
}

func TestBundleUploadScriptInDisposableLinuxContainer(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("WEBSCAN_V3_TEST_HELPER_INSTALL") != "1" {
		t.Skip("requires explicitly opted-in disposable root Linux container")
	}
	raw := []byte("verified compressed archive fixture")
	a := ReleaseArtifact{SHA256: digest(raw), Bytes: uint64(len(raw))}
	target := "/var/lib/webscan-deploy/v3/packages/" + a.SHA256
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("destination must start absent", err)
	}
	t.Cleanup(func() { os.RemoveAll(target) })
	run := func(body []byte) error {
		cmd := exec.Command("/bin/sh", "-c", artifactInstallCommand(a, "native"))
		cmd.Stdin = bytes.NewReader(body)
		out, err := cmd.CombinedOutput()
		if err == nil && string(out) != "bundle-ready\n" {
			t.Fatalf("unexpected archive upload output: %q", out)
		}
		return err
	}
	if err := run(raw[:len(raw)-1]); err == nil {
		t.Fatal("partial archive installed")
	}
	if err := run(raw); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(target, "agent-native.tar.gz"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("archive permissions", err)
	}
	if err := run(raw); err != nil {
		t.Fatal("verified cached archive not reusable", err)
	}
	bad := append([]byte{}, raw...)
	bad[0] ^= 1
	if err := run(bad); err == nil {
		t.Fatal("wrong bytes accepted")
	}
	got, err := os.ReadFile(filepath.Join(target, "agent-native.tar.gz"))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("cached archive overwritten after failure", err)
	}
}

func TestImageArchiveProvisionBindsSignedProofAndRejectsChangedFile(t *testing.T) {
	s := testStore(t)
	raw := bytes.Repeat([]byte("archive"), 200)
	a := ReleaseArtifact{SHA256: digest(raw), Bytes: uint64(len(raw))}
	file := filepath.Join(privateTestDir(t), "image.tar")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	calls, valid := 0, true
	f := startNodeRPC(t, func(command string, ch ssh.Channel) {
		if strings.Contains(command, "artifact-verified") {
			io.ReadAll(ch)
			io.WriteString(ch, "artifact-missing\n")
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return
		}
		body, err := io.ReadAll(ch)
		mu.Lock()
		calls++
		valid = valid && err == nil && bytes.Equal(body, raw) && strings.Contains(command, "/images/"+a.SHA256) && strings.Contains(command, "file=docker-image.tar") && strings.Contains(command, "chmod 600")
		mu.Unlock()
		io.WriteString(ch, "image-ready\n")
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	})
	f.mode, f.imageArchive, f.imageConfig = "docker", &a, strings.Repeat("e", 64)
	j, worker := setupRPCJob(t, s, f)
	req, err := worker.request(context.Background(), j, "apply")
	if err != nil || req.Spec.ImageArchiveSHA256 != a.SHA256 || req.Spec.ImageArchiveBytes != a.Bytes || req.Spec.ImageConfigSHA256 != f.imageConfig {
		t.Fatal("lost signed image proof", err)
	}
	if err := worker.ProvisionImageArchive(context.Background(), j, file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, bytes.Repeat([]byte("x"), len(raw)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := worker.ProvisionImageArchive(context.Background(), j, file); err == nil {
		t.Fatal("changed archive was uploaded")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 || !valid {
		t.Fatal("wrong image upload", calls, valid)
	}
}

func TestImageArchiveUploadScriptInDisposableLinuxContainer(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("WEBSCAN_V3_TEST_HELPER_INSTALL") != "1" {
		t.Skip("requires explicitly opted-in disposable root Linux container")
	}
	raw := []byte("verified Docker save archive fixture")
	a := ReleaseArtifact{SHA256: digest(raw), Bytes: uint64(len(raw))}
	target := "/var/lib/webscan-deploy/v3/images/" + a.SHA256
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("destination must start absent", err)
	}
	t.Cleanup(func() { os.RemoveAll(target) })
	run := func(body []byte) error {
		cmd := exec.Command("/bin/sh", "-c", artifactInstallCommand(a, "image"))
		cmd.Stdin = bytes.NewReader(body)
		out, err := cmd.CombinedOutput()
		if err == nil && string(out) != "image-ready\n" {
			t.Fatalf("unexpected output: %q", out)
		}
		return err
	}
	if err := run(raw[:len(raw)-1]); err == nil {
		t.Fatal("truncated image installed")
	}
	if err := run(raw); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(target, "docker-image.tar"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("image permissions", err)
	}
	if err := run(raw); err != nil {
		t.Fatal("cached image cannot be reused", err)
	}
	if err := run(bytes.Repeat([]byte("x"), len(raw))); err == nil {
		t.Fatal("corrupt image overwritten cache")
	}
	got, err := os.ReadFile(filepath.Join(target, "docker-image.tar"))
	if err != nil || !bytes.Equal(raw, got) {
		t.Fatal("cached image changed", err)
	}
}
