package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

func configurationIdentity(t *testing.T, n Node) (nodepki.Bundle, []byte) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.Issue(nodepki.Node, n.ID, []string{n.ServerName}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ca.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return b, crl
}
func TestPrivateNodeConfigurationUsesSnapshotAndOmitsCenterSecrets(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("node-a")
	n.Config = json.RawMessage(`{"monitor":{"roots":["/www/custom"]},"private":{"password":"must-never-export-to-agent"}}`)
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	b, crl := configurationIdentity(t, n)
	root, err := filepath.EvalSymlinks(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	input := NodeConfigurationInput{Node: n.ID, Expected: 1, Identity: b, CRL: crl, Collectors: []string{"collector-a"}, Rules: []byte("rule safe { condition: false }"), Directory: root}
	release := signedRelease(t, releaseFixture())
	prepared, err := s.PrepareNodeConfiguration(ctx, release, input)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(prepared.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "must-never-export-to-agent") {
		t.Fatal("center secret copied to node artifact")
	}
	m, err := nodeconfig.Decode(raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != 2 || m.Node != n.ID || m.Version != 1 || m.Mode != "native" || m.SourceSHA256 == "" || m.Settings.Monitor.Roots[0] != "/www/custom" || m.Settings.ProbeDirectory != "/www/custom/.webscan-probe" {
		t.Fatal("snapshot mismatch")
	}
	if uint64(len(raw)) != prepared.Artifact.Bytes || digest(raw) != prepared.Artifact.SHA256 {
		t.Fatal("wrong artifact proof")
	}
	st, err := os.Stat(prepared.Path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("unsafe private artifact", err)
	}
	response, _ := json.Marshal(prepared)
	if bytes.Contains(response, []byte(root)) || bytes.Contains(response, []byte("PRIVATE")) {
		t.Fatal("private path/material in metadata")
	}
	cached, err := s.PrepareNodeConfiguration(ctx, release, input)
	if err != nil || cached.Path != prepared.Path {
		t.Fatal("identical prepared config not reusable", err)
	}
	input.Expected = 2
	if _, err := s.PrepareNodeConfiguration(ctx, release, input); err != ErrConflict {
		t.Fatal("outdated request accepted", err)
	}
	input.Expected = 1
	input.Identity.Key = []byte("invalid")
	if _, err := s.PrepareNodeConfiguration(ctx, release, input); err == nil {
		t.Fatal("wrong private key accepted")
	}
	var jobs, applied int
	if err := s.DB.QueryRow("SELECT count(*) FROM v3_deployment_jobs").Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow("SELECT applied_version FROM v3_nodes WHERE id=$1", n.ID).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 || applied != 0 {
		t.Fatal("private preparation changed deployment state")
	}
}
func TestNodeRuntimeSettingsRejectsUnknownFieldsAndInvalidLimits(t *testing.T) {
	for _, raw := range []string{`{"monitor":{"command":"id"}}`, `{"resources":{"cpus":0}}`, `{"transport":{"local_event_queue_max_mib":0}}`, `{"scan":{"auditd":{"enabled":true}}}`, `{"probe_directory":"/outside-roots"}`} {
		if _, err := nodeRuntimeSettings([]byte(raw)); err == nil {
			t.Fatal("unsupported or invalid settings accepted")
		}
	}
	settings, err := nodeRuntimeSettings([]byte(`{"monitor":{"roots":["/srv/www"]},"private":{"ssh_password":"never-runtime"}}`))
	if err != nil || settings.ProbeDirectory != "/srv/www/.webscan-probe" {
		t.Fatal("settings defaults were not merged", err)
	}
}
func TestConfigurationProvisionTransmitsOnlyTaskBoundPrivateArtifact(t *testing.T) {
	s := testStore(t)
	raw := []byte(`{"private":"node configuration fixture"}`)
	a := ReleaseArtifact{SHA256: digest(raw), Bytes: uint64(len(raw))}
	local := filepath.Join(privateTestDir(t), "configuration.json")
	if err := os.WriteFile(local, raw, 0600); err != nil {
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
		valid = valid && err == nil && bytes.Equal(body, raw) && strings.Contains(command, "/configs/"+a.SHA256) && strings.Contains(command, "file=node.json") && strings.Contains(command, "chmod 600")
		mu.Unlock()
		io.WriteString(ch, "configuration-ready\n")
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	})
	f.runtimeArtifact = &a
	j, worker := setupRPCJob(t, s, f)
	req, err := worker.request(context.Background(), j, "apply")
	if err != nil || req.Spec.RuntimeSHA256 != a.SHA256 || req.Spec.RuntimeBytes != a.Bytes || req.Spec.ConfigVersion != j.NodeVersion || req.Spec.ConfigSourceSHA256 != j.Plan.ConfigDigest || req.Spec.ServerName != j.Plan.Node.ServerName {
		t.Fatal("runtime proof not bound to task", err)
	}
	if err := worker.ProvisionConfiguration(context.Background(), j, local); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, bytes.Repeat([]byte("x"), len(raw)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := worker.ProvisionConfiguration(context.Background(), j, local); err == nil {
		t.Fatal("changed config uploaded")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 || !valid {
		t.Fatal("wrong private artifact transfer", calls, valid)
	}
}
func TestConfigurationUploadScriptInDisposableLinuxContainer(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("WEBSCAN_V3_TEST_HELPER_INSTALL") != "1" {
		t.Skip("requires explicitly opted-in disposable root Linux container")
	}
	raw := []byte("private configuration upload fixture")
	a := ReleaseArtifact{SHA256: digest(raw), Bytes: uint64(len(raw))}
	target := "/var/lib/webscan-deploy/v3/configs/" + a.SHA256
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("destination must start absent", err)
	}
	t.Cleanup(func() { os.RemoveAll(target) })
	run := func(raw []byte) error {
		cmd := exec.Command("/bin/sh", "-c", artifactInstallCommand(a, "configuration"))
		cmd.Stdin = bytes.NewReader(raw)
		out, err := cmd.CombinedOutput()
		if err == nil && string(out) != "configuration-ready\n" {
			t.Fatalf("wrong script result: %q", out)
		}
		return err
	}
	if err := run(raw[:len(raw)-1]); err == nil {
		t.Fatal("truncated config uploaded")
	}
	if err := run(raw); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(target, "node.json"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("unsafe uploaded configuration", err)
	}
	if err := run(raw); err != nil {
		t.Fatal("verified cached file rejected", err)
	}
}
