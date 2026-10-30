package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func helperFixture(t *testing.T) (string, []byte, ReleaseArtifact) {
	t.Helper()
	raw := bytes.Repeat([]byte("a"), 1024)
	h := sha256.Sum256(raw)
	a := ReleaseArtifact{hex.EncodeToString(h[:]), uint64(len(raw))}
	path := filepath.Join(privateTestDir(t), "release-helper")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path, raw, a
}

func TestLocalHelperVerificationRejectsUnsafeOrDifferentFiles(t *testing.T) {
	path, raw, a := helperFixture(t)
	f, err := verifiedHelper(context.Background(), path, a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("helper was not rewound", err)
	}
	if err := os.Symlink(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedHelper(context.Background(), path+".link", a); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedHelper(context.Background(), path, a); err == nil {
		t.Fatal("public helper accepted")
	}
	os.Chmod(path, 0600)
	bad := a
	bad.SHA256 = strings.Repeat("e", 64)
	if _, err := verifiedHelper(context.Background(), path, bad); err == nil {
		t.Fatal("untrusted bytes accepted")
	}
	bad = a
	bad.Bytes++
	if _, err := verifiedHelper(context.Background(), path, bad); err == nil {
		t.Fatal("wrong size accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifiedHelper(ctx, path, a); err == nil {
		t.Fatal("cancel ignored")
	}
	if err := os.Link(path, path+".hardlink"); err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedHelper(context.Background(), path, a); err == nil {
		t.Fatal("hardlink accepted")
	}
}

func TestHelperProvisionUsesFencedSSHAndVerifiedRelease(t *testing.T) {
	s := testStore(t)
	path, raw, a := helperFixture(t)
	var mu sync.Mutex
	calls := 0
	valid := true
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
		valid = valid && err == nil && bytes.Equal(body, raw) && strings.Contains(command, "/tools/"+a.SHA256) && strings.Contains(command, "sha256sum --check --status") && !strings.Contains(command, path) && !strings.Contains(command, "must-not-execute")
		mu.Unlock()
		io.WriteString(ch, "helper-ready\n")
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	})
	f.sha = a.SHA256
	j, worker := setupRPCJob(t, s, f)
	if err := worker.ProvisionHelper(context.Background(), j, path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("b"), len(raw)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := worker.ProvisionHelper(context.Background(), j, path); deploymentFailureCode(err) != "artifact-invalid" {
		t.Fatal("local corruption ignored", err)
	}
	// A completed/expired task cannot provision anything, even an otherwise
	// legitimate helper. It must first pass the same lease and plan checks.
	j.Epoch++
	if err := worker.ProvisionHelper(context.Background(), j, path); err == nil {
		t.Fatal("invalid lease accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 || !valid {
		t.Fatal("unexpected SSH upload", calls, valid)
	}
}

func TestHelperInstallationInDisposableLinuxContainer(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("WEBSCAN_V3_TEST_HELPER_INSTALL") != "1" {
		t.Skip("requires explicitly opted-in disposable root Linux container")
	}
	_, raw, a := helperFixture(t)
	target := "/var/lib/webscan-deploy/v3/tools/" + a.SHA256
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("test destination must start absent", err)
	}
	t.Cleanup(func() { os.RemoveAll(target) })
	run := func(body []byte) error {
		cmd := exec.Command("/bin/sh", "-c", helperInstallCommand(a))
		cmd.Stdin = bytes.NewReader(body)
		output, err := cmd.CombinedOutput()
		if err == nil && string(output) != "helper-ready\n" {
			t.Fatalf("unexpected helper output: %q", output)
		}
		return err
	}
	if err := run(raw[:len(raw)-1]); err == nil {
		t.Fatal("truncated transfer installed")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("failed checksum published a target", err)
	}
	if err := run(raw); err != nil {
		t.Fatal("verified upload failed", err)
	}
	file := filepath.Join(target, "webscan")
	st, err := os.Stat(file)
	if err != nil || st.Mode().Perm() != 0700 {
		t.Fatal("helper permissions", err)
	}
	content, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(content, raw) {
		t.Fatal("helper content differs", err)
	}
	if err := run(raw); err != nil {
		t.Fatal("response-loss replay failed", err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(privateTestDir(t), "unrelated")
	if err := os.WriteFile(outside, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, file); err != nil {
		t.Fatal(err)
	}
	if err := run(raw); err == nil {
		t.Fatal("destination symlink accepted")
	}
	content, err = os.ReadFile(outside)
	if err != nil || string(content) != "preserve" {
		t.Fatal("unrelated file overwritten", err)
	}
	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".stage-") {
			t.Fatal("temporary upload leaked")
		}
	}
}

func TestArtifactProvisionReusesOnlyVerifiedRemoteFiles(t *testing.T) {
	for _, response := range []string{"artifact-verified\n", "unrecognized\n"} {
		t.Run(strings.TrimSpace(response), func(t *testing.T) {
			s := testStore(t)
			path, _, a := helperFixture(t)
			var calls int
			var valid = true
			f := startNodeRPC(t, func(command string, ch ssh.Channel) {
				body, err := io.ReadAll(ch)
				calls++
				valid = valid && err == nil && len(body) == 0 && strings.Contains(command, "sha256sum --check --status") && strings.Contains(command, "%u:%a:%h:%s") && strings.Contains(command, "test ! -L")
				io.WriteString(ch, response)
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			})
			f.sha = a.SHA256
			j, w := setupRPCJob(t, s, f)
			err := w.ProvisionHelper(context.Background(), j, path)
			if response == "artifact-verified\n" && err != nil {
				t.Fatal(err)
			}
			if response != "artifact-verified\n" && deploymentFailureCode(err) != "artifact-invalid" {
				t.Fatal("unrecognized proof accepted", err)
			}
			if calls != 1 || !valid {
				t.Fatal("cache reuse did not validate immutable file", calls, valid)
			}
		})
	}
}

func TestArtifactReuseScriptRejectsUnsafeCache(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("WEBSCAN_V3_TEST_HELPER_INSTALL") != "1" {
		t.Skip("disposable Linux root required")
	}
	for _, kind := range []string{"helper", "native", "image", "configuration"} {
		t.Run(kind, func(t *testing.T) {
			raw := []byte("fresh cache fixture " + kind)
			a := ReleaseArtifact{SHA256: digest(raw), Bytes: uint64(len(raw))}
			check := func() (string, error) {
				b, e := exec.Command("/bin/sh", "-c", artifactReuseCommand(a, kind)).CombinedOutput()
				return string(b), e
			}
			if b, e := check(); e != nil || b != "artifact-missing\n" {
				t.Fatal(b, e)
			}
			cmd := exec.Command("/bin/sh", "-c", artifactInstallCommand(a, kind))
			cmd.Stdin = bytes.NewReader(raw)
			if b, e := cmd.CombinedOutput(); e != nil {
				t.Fatal(string(b), e)
			}
			if b, e := check(); e != nil || b != "artifact-verified\n" {
				t.Fatal(b, e)
			}
			folder, file := map[string]string{"helper": "tools", "native": "packages", "image": "images", "configuration": "configs"}[kind], map[string]string{"helper": "webscan", "native": "agent-native.tar.gz", "image": "docker-image.tar", "configuration": "node.json"}[kind]
			target := filepath.Join("/var/lib/webscan-deploy/v3", folder, a.SHA256)
			t.Cleanup(func() { os.RemoveAll(target) })
			p := filepath.Join(target, file)
			st, _ := os.Stat(p)
			os.Chmod(p, 0644)
			if _, e := check(); e == nil {
				t.Fatal("public cache accepted")
			}
			os.Chmod(p, st.Mode().Perm())
			bad := bytes.Repeat([]byte("x"), len(raw))
			os.WriteFile(p, bad, st.Mode().Perm())
			if _, e := check(); e == nil {
				t.Fatal("changed bytes accepted")
			}
			os.Remove(p)
			outside := filepath.Join(privateTestDir(t), "outside")
			os.WriteFile(outside, raw, st.Mode().Perm())
			os.Symlink(outside, p)
			if _, e := check(); e == nil {
				t.Fatal("symlink accepted")
			}
		})
	}
}
