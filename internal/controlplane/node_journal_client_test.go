package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"webscan/internal/nodeops"
)

func TestNodePhaseTimeoutKeepsArtifactVerificationBounded(t *testing.T) {
	for _, lifecycle := range []bool{false, true} {
		for _, phase := range []string{"preflight", "stage", "backup", "activate", "verify", "finalize", "restore", "verify-rollback"} {
			want := 75 * time.Second
			if phase == "stage" || lifecycle && phase != "preflight" {
				want = 6 * time.Minute
			}
			if got := nodePhaseTimeout(lifecycle, phase); got != want {
				t.Errorf("lifecycle=%t phase=%s timeout=%s want=%s", lifecycle, phase, got, want)
			}
		}
	}
}

type rpcNodeHandler struct {
	mu    sync.Mutex
	calls map[string]int
}

func (h *rpcNodeHandler) Supports(string) bool { return true }
func (h *rpcNodeHandler) Apply(r nodeops.Request) (nodeops.Outcome, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls[r.Phase]++
	return nodeops.Outcome{}, nil
}
func (h *rpcNodeHandler) Reconcile(nodeops.Request) (string, nodeops.Outcome, error) {
	return "unknown", nodeops.Outcome{}, nil
}
func (h *rpcNodeHandler) count(phase string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls[phase]
}

type rpcFixture struct {
	connections     *atomic.Int32
	runtimeArtifact *ReleaseArtifact
	credential      SSHCredential
	sha             string
	serve           func(string, ssh.Channel)
	native          ReleaseArtifact
	mode            string
	imageArchive    *ReleaseArtifact
	imageConfig     string
}

func startNodeRPC(t *testing.T, serve func(string, ssh.Channel)) rpcFixture {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if meta.User() != "root" || string(password) != credentialFixture().Password {
			return nil, ErrCredentialUnavailable
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	connections := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(requests)
				for ch := range channels {
					if ch.ChannelType() != "session" {
						ch.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					channel, reqs, err := ch.Accept()
					if err != nil {
						continue
					}
					for req := range reqs {
						if req.Type != "exec" {
							req.Reply(false, nil)
							continue
						}
						var command struct{ Command string }
						if ssh.Unmarshal(req.Payload, &command) != nil {
							req.Reply(false, nil)
							break
						}
						req.Reply(true, nil)
						serve(command.Command, channel)
						break
					}
					channel.Close()
				}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done; wg.Wait() })
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	c := credentialFixture()
	c.Host = host
	c.Port = p
	c.Fingerprint = ssh.FingerprintSHA256(signer.PublicKey())
	return rpcFixture{connections: connections, credential: c, sha: strings.Repeat("b", 64), serve: serve}
}
func finishRPC(channel ssh.Channel, res nodeops.Result) {
	json.NewEncoder(channel).Encode(res)
	status := uint32(0)
	if res.Code != "ok" {
		status = 1
	}
	channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
}
func setupRPCJob(t *testing.T, s *Store, f rpcFixture) (DeploymentJob, *SSHNodeRuntime) {
	t.Helper()
	ctx := context.Background()
	n := nodeFixture("node-a")
	if f.mode != "" {
		n.Mode = f.mode
	}
	n.Config = json.RawMessage(`{"monitor":{"roots":["/www/$(must-not-execute);x"]},"scan":{"clamav":{"enabled":true}},"private":{"password":"never-in-node-rpc"}}`)
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	v, _ := testVault(t)
	raw, err := s.AddCredential(ctx, v, "admin", "rpc-credential", n.ID, 1, f.credential)
	if err != nil {
		t.Fatal(err)
	}
	var id struct {
		ID string `json:"id"`
	}
	json.Unmarshal(raw, &id)
	manifest := releaseFixture()
	manifest.Helper.SHA256 = f.sha
	if f.native.Bytes != 0 {
		manifest.Native = f.native
	}
	manifest.ImageArchive, manifest.ImageConfigSHA256 = f.imageArchive, f.imageConfig
	release := signedRelease(t, manifest)
	target := manifest.Native.SHA256
	if n.Mode == "docker" {
		target = manifest.Image[len(manifest.Image)-64:]
	}
	createDeployment(t, s, DeploymentRequest{Node: n.ID, Kind: "install", Expected: 1, Credential: id.ID, Release: "v3.0.0", SHA256: target, ManifestSHA256: release.SHA256(), RuntimeArtifact: f.runtimeArtifact}, "rpc-deploy")
	j := claimDeployment(t, s, "rpc-one")
	return j, &SSHNodeRuntime{Store: s, Vault: v, Release: release}
}

func TestNodeRPCRejectsChangedManifestBeforeConnecting(t *testing.T) {
	s := testStore(t)
	var mu sync.Mutex
	calls := 0
	f := startNodeRPC(t, func(_ string, ch ssh.Channel) {
		mu.Lock()
		calls++
		mu.Unlock()
	})
	j, runtime := setupRPCJob(t, s, f)
	m := releaseFixture()
	m.Helper.SHA256 = strings.Repeat("d", 64)
	runtime.Release = signedRelease(t, m)
	if _, err := runtime.Inspect(context.Background(), j); deploymentFailureCode(err) != "artifact-invalid" {
		t.Fatal("task accepted another helper", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Fatal("connected with a different manifest")
	}
}
func TestNodeRPCResponseLossReconcilesRealSQLiteReceipts(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	root, err := filepath.EvalSymlinks(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	backend := &rpcNodeHandler{calls: map[string]int{}}
	journal, err := nodeops.Open(root, backend)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	lost := false
	var invalid []string
	f := startNodeRPC(t, func(command string, channel ssh.Channel) {
		if !strings.Contains(command, strings.Repeat("b", 64)) || !strings.Contains(command, "sha256sum --check --status") || strings.Contains(command, "must-not-execute") {
			mu.Lock()
			invalid = append(invalid, "unverified command")
			mu.Unlock()
		}
		raw, err := io.ReadAll(io.LimitReader(channel, nodeops.MaxRequestBytes+1))
		if err != nil {
			return
		}
		if strings.Contains(string(raw), "never-in-node-rpc") || strings.Contains(string(raw), credentialFixture().Password) {
			mu.Lock()
			invalid = append(invalid, "secret in request")
			mu.Unlock()
		}
		var request nodeops.Request
		if json.Unmarshal(raw, &request) != nil {
			return
		}
		res := journal.Handle(request)
		mu.Lock()
		drop := !lost && request.Phase == "backup" && request.Operation == "apply"
		if drop {
			lost = true
		}
		mu.Unlock()
		if drop {
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
			return
		}
		finishRPC(channel, res)
	})
	j, runtime := setupRPCJob(t, s, f)
	runner := &DeploymentRunner{Store: s, Runtime: readinessFixtureRuntime{fullFixtureRuntime{runtime}, t, s}}
	if err = runner.Execute(ctx, j); err == nil {
		t.Fatal("lost SSH response ignored")
	}
	failed := reloadDeployment(t, s, j.ID)
	if !failed.CanRecover() || failed.Step != 2 || backend.count("backup") != 1 {
		t.Fatal("wrong interrupted phase", failed.Step, failed.Status)
	}
	if _, err = s.RecoverDeployment(ctx, "admin", "rpc-resume", j.ID, "forward", failed.PlanDigest, failed.LogCursor); err != nil {
		t.Fatal(err)
	}
	next := claimDeployment(t, s, "rpc-two")
	if err = runner.Execute(ctx, next); err != nil {
		t.Fatal(err)
	}
	completed := reloadDeployment(t, s, j.ID)
	if completed.Status != "succeeded" || backend.count("backup") != 1 {
		t.Fatal("replayed node action", completed.Status, backend.count("backup"))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(invalid) != 0 {
		t.Fatal(invalid)
	}
}

// This older protocol simulation intentionally has no runtime artifact. Full
// configured executors instead require immutable per-task configuration files.
type fullFixtureRuntime struct{ *SSHNodeRuntime }

func (fullFixtureRuntime) SupportsDeploymentPhase(string) bool { return true }

func TestPartialSSHRuntimeDoesNotArmRecoveryOrPretendInstallSuccess(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	root, err := filepath.EvalSymlinks(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	h := &rpcNodeHandler{calls: map[string]int{}}
	journal, err := nodeops.Open(root, h)
	if err != nil {
		t.Fatal(err)
	}
	f := startNodeRPC(t, func(_ string, ch ssh.Channel) {
		var r nodeops.Request
		if json.NewDecoder(ch).Decode(&r) == nil {
			finishRPC(ch, journal.Handle(r))
		}
	})
	j, runtime := setupRPCJob(t, s, f)
	err = (&DeploymentRunner{Store: s, Runtime: runtime}).Execute(ctx, j)
	if deploymentFailureCode(err) != "executor-unavailable" {
		t.Fatal("unsupported installer did not stop", err)
	}
	failed := reloadDeployment(t, s, j.ID)
	if failed.Status != "failed" || failed.Step != 2 || failed.RecoveryRequired || failed.CanRecover() || h.count("backup") != 0 {
		t.Fatal("unsupported phase created recovery obligation", failed)
	}
	var applied int64
	if err := s.DB.QueryRow("SELECT applied_version FROM v3_nodes WHERE id=$1", j.Node).Scan(&applied); err != nil || applied != 0 {
		t.Fatal("partial runtime marked node installed", applied, err)
	}
}
func TestNodeRPCRejectsOversizedOrTamperedResponses(t *testing.T) {
	for _, kind := range []string{"oversized", "tampered"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			f := startNodeRPC(t, func(_ string, ch ssh.Channel) {
				var r nodeops.Request
				json.NewDecoder(ch).Decode(&r)
				if kind == "oversized" {
					io.WriteString(ch, strings.Repeat("x", 128<<10))
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				}
				finishRPC(ch, nodeops.Result{Protocol: nodeops.Protocol, Job: "another-job", Node: r.Node, PlanDigest: r.PlanDigest, Epoch: r.Epoch, Phase: r.Phase, State: "complete", Code: "ok"})
			})
			j, runtime := setupRPCJob(t, s, f)
			_, err := runtime.Inspect(context.Background(), j)
			var failure DeploymentFailure
			if !errors.As(err, &failure) || failure.Code != "remote-state-unknown" {
				t.Fatal("invalid receipt accepted", err)
			}
		})
	}
}
func TestNodeRPCReceiptValidationAndBoundedCapture(t *testing.T) {
	req := nodeops.Request{Protocol: 1, Job: "job", Node: "node", PlanDigest: strings.Repeat("a", 64), Epoch: 3, Phase: "backup"}
	response := nodeops.Result{Protocol: 1, Job: req.Job, Node: req.Node, PlanDigest: req.PlanDigest, Epoch: 3, Phase: req.Phase, State: "complete", Code: "ok"}
	if proof, err := decodeNodeReceipt(req, response, nil); err != nil || proof.State != "complete" {
		t.Fatal(err)
	}
	for _, code := range []string{"fenced", "busy", "storage-failed", "phase-order", "executor-unavailable", "preflight-failed"} {
		bad := response
		bad.Code = code
		if _, err := decodeNodeReceipt(req, bad, nil); err == nil {
			t.Fatal("error code ignored", code)
		}
	}
	if _, err := decodeNodeReceipt(req, response, errors.New("SSH exit failure")); err == nil {
		t.Fatal("nonzero exit accepted as success")
	}
	capture := &nodeResponseCapture{}
	raw := []byte(strings.Repeat("a", 80<<10))
	if n, err := capture.Write(raw); n != len(raw) || err != nil || !capture.overflow || len(capture.raw) != 64<<10 {
		t.Fatal("unbounded node output")
	}
}

func TestNodeRPCInstallationReceiptBoundToFinalRequest(t *testing.T) {
	req := nodeops.Request{Protocol: nodeops.Protocol, Operation: "inspect", Job: "job", Node: "node", PlanDigest: strings.Repeat("a", 64), Epoch: 3, Phase: "finalize", Spec: nodeops.Spec{Mode: "native", MetricsPort: 19100, MonitorDirectories: []string{"/www"}}}
	res := nodeops.Result{Protocol: req.Protocol, Job: req.Job, Node: req.Node, PlanDigest: req.PlanDigest, Epoch: req.Epoch, Phase: req.Phase, State: "complete", Code: "ok", Installation: &nodeops.InstallationEvidence{CaptureSHA256: strings.Repeat("b", 64), ActiveSHA256: strings.Repeat("c", 64)}}
	proof, err := decodeNodeReceipt(req, res, nil)
	if err != nil || proof.Spec == nil || proof.Spec.MetricsPort != req.Spec.MetricsPort || proof.Installation == nil || *proof.Installation != *res.Installation {
		t.Fatal("final receipt lost request binding", err)
	}
	res.Installation.CaptureSHA256 = strings.Repeat("d", 64)
	if proof.Installation.CaptureSHA256 != strings.Repeat("b", 64) {
		t.Fatal("receipt kept mutable response pointer")
	}
	for _, bad := range []string{"wrong-phase", "recovery", "absent", "invalid-capture", "invalid-active", "failed-command"} {
		t.Run(bad, func(t *testing.T) {
			r, response := req, res
			evidence := *res.Installation
			response.Installation = &evidence
			var commandError error
			switch bad {
			case "wrong-phase":
				r.Phase, response.Phase = "verify", "verify"
			case "recovery":
				r.Recovery = &nodeops.RecoveryReference{}
			case "absent":
				response.State = "absent"
			case "invalid-capture":
				evidence.CaptureSHA256 = "invalid"
			case "invalid-active":
				evidence.ActiveSHA256 = strings.Repeat("C", 64)
			case "failed-command":
				commandError = errors.New("lost response")
			}
			if _, err := decodeNodeReceipt(r, response, commandError); err == nil {
				t.Fatal("untrusted installation receipt accepted")
			}
		})
	}
}
