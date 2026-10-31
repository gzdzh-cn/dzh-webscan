//go:build linux

package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"webscan/internal/nodeconfig"
	"webscan/internal/nodeops"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

// This test is deliberately unavailable on a host or ordinary Docker runner.
// The disposable guest owns its kernel, systemd, filesystem and nested Docker
// daemon. Only loopback exists; all SSH commands execute the actual helper.
func TestWebDeploymentKernelPublicAPIAndActualServices(t *testing.T) {
	mode := os.Getenv("WEBSCAN_V3_WEB_KERNEL_MODE")
	if mode != "native" && mode != "docker" {
		t.Skip("requires dedicated networkless web-deployment kernel guest")
	}
	marker, err := os.ReadFile("/v3-tests/kernel-guest")
	pid, pe := os.Readlink("/proc/1/exe")
	interfaces, ne := os.ReadDir("/sys/class/net")
	if os.Geteuid() != 0 || err != nil || string(marker) != "webscan-v3-networkless-kernel-guest\n" || pe != nil || pid != "/usr/lib/systemd/systemd" || ne != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("refusing non-isolated kernel environment")
	}
	for _, path := range []string{"/var/lib/webscan-v1", "/etc/webscan-agent", "/etc/systemd/system/webscan-agent-native.service"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refusing existing Agent state", path)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 22*time.Minute)
	defer cancel()
	f := webDeployFixture(t, time.Now().Add(-72*time.Hour))
	// Replace the ordinary unit fixture's synthetic release files with the
	// actual current-source helper, native scanners and Docker-save archive.
	actual := newTrustToolFixture(t)
	for source, target := range map[string]string{"/v3-tests/webscan": actual.helper, "/v3-tests/agent-native.tar.gz": actual.native, "/v3-tests/agent-image.tar": actual.image} {
		in, err := os.Open(source)
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			in.Close()
			t.Fatal(err)
		}
		_, err = io.Copy(out, in)
		in.Close()
		ce := out.Close()
		if err != nil || ce != nil {
			t.Fatal(err, ce)
		}
	}
	proofRaw, err := os.ReadFile("/v3-tests/image-proof.json")
	var proof nodeops.Spec
	if err != nil || json.Unmarshal(proofRaw, &proof) != nil {
		t.Fatal("image proof", err)
	}
	actual.sign.AgentImage, actual.sign.ImageConfigSHA256 = proof.AgentImage, proof.ImageConfigSHA256
	actual.sign.Output = filepath.Join(actual.root, "actual-release")
	var ignored bytes.Buffer
	if err := ReleaseCommand(ctx, actual.sign, &ignored); err != nil {
		t.Fatal(err)
	}
	actual.signed = actual.sign.Output
	originalVault := f.c.DeploymentTrust.VaultKeyFile
	f.c.DeploymentTrust = actual.config()
	f.c.DeploymentTrust.VaultKeyFile = originalVault
	f.t, err = loadDeploymentTrust(ctx, f.c.DeploymentTrust)
	if err != nil {
		t.Fatal(err)
	}
	f.c.Collector.Concurrency, f.c.Collector.Shards, f.c.Collector.IntervalSeconds = 4, 1, 10
	f.c.Central.Instance = "kernel-web-host"
	f.c.Executor.Concurrency = 1
	f.c.Executor.Enabled, f.c.Executor.Mode = true, "embedded"
	collectorDirectory := filepath.Join(filepath.Dir(f.c.Collector.CAFile), "kernel-collector")
	if err := os.Mkdir(collectorDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	collectorAnchor := filepath.Join(collectorDirectory, "ca.crt")
	localWrite(t, collectorAnchor, f.collector.CA)
	f.c.Collector.IdentityFile = filepath.Join(collectorDirectory, "active.pem")
	f.c.Collector.CertFile, f.c.Collector.KeyFile = "", ""
	if _, err := nodepki.PublishIdentity(ctx, collectorAnchor, f.c.Collector.IdentityFile, nodepki.Collector, "collector-a", "", f.collector, time.Now()); err != nil {
		t.Fatal("managed collector bootstrap", err)
	}
	if _, err := nodepki.NewPersistentFileTrust(f.c.Collector.CAFile, f.c.Collector.RevocationFile, f.c.Collector.RevocationStateDirectory, time.Now()); err != nil {
		t.Fatal(err)
	}

	var loseBackup atomic.Bool
	var lostResponses atomic.Int32
	remote := startNodeRPC(t, func(command string, channel ssh.Channel) {
		var input io.Reader = channel
		drop := false
		label := "artifact"
		if strings.HasSuffix(command, " node-v3 --lifecycle\n") {
			raw, err := io.ReadAll(io.LimitReader(channel, nodeops.MaxRequestBytes+1))
			if err != nil {
				return
			}
			var request nodeops.Request
			if json.Unmarshal(raw, &request) != nil {
				return
			}
			input = bytes.NewReader(raw)
			label = request.Operation + "/" + request.Phase
			drop = request.Operation == "apply" && request.Phase == "backup" && loseBackup.CompareAndSwap(true, false)
		}
		commandContext, stop := context.WithTimeout(ctx, 12*time.Minute)
		defer stop()
		cmd := exec.CommandContext(commandContext, "/bin/sh", "-c", command)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = input, channel, channel.Stderr()
		var diagnostic, responseDiagnostic bytes.Buffer
		cmd.Stderr = io.MultiWriter(channel.Stderr(), &diagnostic)
		if label == "inspect/preflight" {
			cmd.Stdout = io.MultiWriter(channel, &responseDiagnostic)
		}
		if drop {
			cmd.Stdout = io.Discard
		}
		began := time.Now()
		err := cmd.Run()
		status := uint32(0)
		if err != nil {
			status = 1
		}
		if drop && err == nil {
			status = 1
			lostResponses.Add(1)
		}
		t.Logf("actual SSH %s elapsed=%s exit=%d dropped=%t", label, time.Since(began).Round(time.Millisecond), status, drop)
		if diagnostic.Len() != 0 {
			// The guarded guest contains test-only identities. Helper diagnostics
			// carry fixed error codes, never request bodies or credentials.
			t.Logf("isolated helper diagnostic: %.1024s", diagnostic.Bytes())
		}
		if responseDiagnostic.Len() != 0 {
			t.Logf("isolated preflight response: %.1024s", responseDiagnostic.Bytes())
		}
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	})
	f.port, f.fingerprint = remote.credential.Port, remote.credential.Fingerprint
	site := "/v3-tests/web-monitor"
	if err := os.Mkdir(site, 0700); err != nil {
		t.Fatal(err)
	}
	settings := nodeconfig.DefaultSettings()
	settings.Monitor.Roots, settings.ProbeDirectory = []string{site}, site+"/.probe"
	settings.MetricsSourceIP = "127.0.0.1"
	config, _ := json.Marshal(settings)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listener.Addr().String()
	listener.Close()
	mustHistoryExec(t, f.s.DB, "UPDATE v3_nodes SET endpoint=$1,server_name='127.0.0.1',mode=$2,shard=0,config=$3 WHERE id='node-a'", endpoint, mode, string(config))
	apiConfig := f.api.Config
	apiConfig.DeploymentTrust = f.c.DeploymentTrust
	apiConfig.DeploymentTrust.HelperFile, apiConfig.DeploymentTrust.NativeBundleFile, apiConfig.DeploymentTrust.ImageArchiveFile = "", "", ""
	f.api = NewAPI(f.s, apiConfig)
	f.worker = &webDeploymentWorker{store: f.s, config: f.c, trust: f.t, instance: f.c.Central.Instance}
	runner, err := newDeploymentExecutor(ctx, f.s, f.c)
	if err != nil {
		t.Fatal(err)
	}
	workers := make(chan error, 3)
	go func() { workers <- f.worker.Run(ctx) }()
	go func() { workers <- runner.Run(ctx) }()
	// The metric sink is explicitly simulated; collection, TLS and PostgreSQL
	// readiness/acknowledgements are real. VM storage has a separate stack gate.
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body); w.WriteHeader(204) }))
	defer sink.Close()
	collector := &Collector{Store: f.s, Config: f.c, Metrics: &Metrics{WriteURL: sink.URL, QueryURL: sink.URL, HTTP: sink.Client()}}
	go func() { workers <- collector.Run(ctx) }()
	defer func() {
		cancel()
		for i := 0; i < 3; i++ {
			select {
			case <-workers:
			case <-time.After(15 * time.Second):
				t.Error("worker did not stop")
			}
		}
	}()
	server, assertCentralUnchanged := webKernelAPIContainer(t, ctx, f)
	process, started := os.Getpid(), controlplaneStartedAt
	call := func(method, path string, input any, key string) (int, []byte) {
		t.Helper()
		raw, _ := json.Marshal(input)
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: f.sessions["admin"]})
		r.Header.Set("X-CSRF-Token", "web-csrf")
		r.Header.Set("Idempotency-Key", key)
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}
	wait := func(check func() bool, label string) {
		t.Helper()
		for end := time.Now().Add(8 * time.Minute); time.Now().Before(end); {
			if check() {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-time.After(time.Second):
			}
		}
		t.Fatal("timed out", label)
	}
	wait(func() bool { return f.api.deploymentAvailability(ctx).Available }, "actual host readiness")
	prepare := func(path string, input any, key string) deploymentPreparation {
		t.Helper()
		t.Log("public preparation", key)
		status, raw := call("POST", path, input, key)
		var receipt deploymentPreparation
		if status != 202 || json.Unmarshal(raw, &receipt) != nil || receipt.ID == "" {
			t.Fatalf("submit %s: %d %s", path, status, raw)
		}
		var result deploymentPreparation
		wait(func() bool {
			status, raw = call("GET", "/api/v3/deployment-preparations/"+receipt.ID, nil, "")
			if status != 200 || json.Unmarshal(raw, &result) != nil {
				t.Fatalf("query preparation: %d %s", status, raw)
			}
			if result.Status == "failed" || result.Status == "expired" {
				t.Fatal("preparation failed", result.Kind, result.ErrorCode)
			}
			return result.Status == "succeeded"
		}, "preparation "+key)
		return result
	}
	pin := prepare("/api/v3/servers/node-a/ssh-fingerprint", map[string]any{"expected_version": 1, "ssh_port": f.port}, "kernel-pin")
	if pin.Result == nil || pin.Result.Fingerprint != f.fingerprint {
		t.Fatal("actual SSH fingerprint mismatch")
	}
	prepare("/api/v3/servers/node-a/ssh-credential", webDeploymentInput{Expected: 1, SSHPort: f.port, Password: remote.credential.Password, FingerprintPreparation: pin.ID, FingerprintToken: pin.Result.FingerprintToken}, "kernel-credential")
	version := int64(1)
	queue := func(kind, key string) string {
		t.Helper()
		p := prepare("/api/v3/servers/node-a/deployment-preview", map[string]any{"expected_version": version, "kind": kind}, key+"-prepare")
		if p.Result == nil || p.Result.Preview == nil || p.Result.Preview.Target.Mode != mode {
			t.Fatal("incorrect preview")
		}
		p = prepare("/api/v3/deployments", webDeploymentInput{Expected: version, Preparation: p.ID, PreviewToken: p.Result.Preview.Token}, key+"-confirm")
		if p.Result == nil || p.Result.Job == "" {
			t.Fatal("no durable job")
		}
		return p.Result.Job
	}
	jobStatus := func(id, want string) DeploymentJob {
		t.Helper()
		var j DeploymentJob
		wait(func() bool {
			var err error
			j, err = f.s.Deployment(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if j.Status == "failed" && want != "failed" {
				t.Fatal("actual deployment failed", j.Status, j.Phase(), j.ErrorCode)
			}
			return j.Status == want
		}, "job "+want)
		t.Logf("real %s job %s phase=%s status=%s", mode, id, j.Phase(), j.Status)
		return j
	}
	recover := func(j DeploymentJob, action, key string) {
		t.Helper()
		status, raw := call("POST", "/api/v3/deployments/"+j.ID+"/"+action, map[string]any{"plan_digest": j.PlanDigest, "log_cursor": j.LogCursor}, key)
		if status != 202 && status != 200 {
			t.Fatalf("recovery %s: %d %s", action, status, raw)
		}
	}
	id := queue("install", "kernel-install")
	jobStatus(id, "succeeded")
	if mode == "docker" {
		ref, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.Config.Image}}", "webscan-agent-go").Output()
		if err != nil || strings.TrimSpace(string(ref)) != strings.SplitN(proof.AgentImage, "@", 2)[0] || !strings.Contains(proof.AgentImage, ":"+actual.sign.Release+"@sha256:") {
			t.Fatal("readable version reference not retained", err)
		}
	}
	// New filesystem activity must travel from the actual Agent queue over mTLS.
	if err := os.WriteFile(site+"/acceptance.php", []byte("<?php echo 'isolated acceptance';"), 0600); err != nil {
		t.Fatal(err)
	}
	wait(func() bool {
		var n int
		err := f.s.DB.QueryRow("SELECT count(*) FROM v3_events WHERE node='node-a' AND payload->>'path'=$1", site+"/acceptance.php").Scan(&n)
		return err == nil && n >= 1
	}, "actual filesystem event persistence")
	for i, action := range []string{"resume", "rollback"} {
		n, err := scanNode(f.s.DB.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE id='node-a'"))
		if err != nil {
			t.Fatal(err)
		}
		settings.RetentionDays++
		n.Config, _ = json.Marshal(settings)
		if _, err = f.s.SaveNode(ctx, "admin", fmt.Sprintf("kernel-save-%d", i), n, version, 1); err != nil {
			t.Fatal(err)
		}
		version++
		loseBackup.Store(true)
		id = queue("upgrade", fmt.Sprintf("kernel-upgrade-%d", i))
		failed := jobStatus(id, "failed")
		if !failed.CanRecover() || failed.Step != 2 {
			t.Fatal("lost actual backup receipt not recoverable", failed.Step, failed.ErrorCode)
		}
		status, raw := call("GET", "/api/v3/deployments/"+id, nil, "")
		if status != 200 || !bytes.Contains(raw, []byte(`"can_resume":true`)) || !bytes.Contains(raw, []byte(`"can_rollback":true`)) {
			t.Fatal("missing real recovery actions", status, string(raw))
		}
		recover(failed, action, fmt.Sprintf("kernel-recover-%d", i))
		want := "succeeded"
		if action == "rollback" {
			want = "rolled_back"
		}
		jobStatus(id, want)
	}
	if lostResponses.Load() != 2 {
		t.Fatal("response loss did not happen after actual backup")
	}
	// Rollback deliberately leaves the desired draft unapplied. Apply that
	// exact saved configuration through the public flow before freezing all
	// current members for the explicit host-only CA task.
	jobStatus(queue("upgrade", "kernel-before-root"), "succeeded")
	webKernelMaintenance(t, ctx, f, mode, site, &version, wait, func(key string) { jobStatus(queue("upgrade", key), "succeeded") }, assertCentralUnchanged)
	webKernelRootRollout(t, ctx, f, mode, site, wait, assertCentralUnchanged)
	status, raw := call("GET", "/api/v3/servers/node-a/ssh-credential", nil, "")
	if status != 200 || bytes.Contains(raw, []byte(remote.credential.Password)) || os.Getpid() != process || !controlplaneStartedAt.Equal(started) {
		t.Fatal("session/process changed or credential leaked")
	}
	if tableCount(t, f.s, "v3_notifications") != 0 {
		t.Fatal("unexpected business notification")
	}
	assertCentralUnchanged()
	t.Log("HTTPS API -> durable host preparations -> pinned SSH -> real service -> mTLS collector passed; same API process and login retained; metric sink simulated")
}

func webKernelRootRollout(t *testing.T, ctx context.Context, f webDeploymentFixture, mode, site string, wait func(func() bool, string), unchanged func()) {
	t.Helper()
	identity := "/var/lib/webscan-v1/pki-identity/active.pem"
	anchor := "/var/lib/webscan-v1/pki-identity/ca.crt"
	floor := "/var/lib/webscan-v1/pki-trust"
	b, _, err := nodepki.ReadIdentityWithRootState(anchor, identity, floor, nodepki.Node, "node-a", time.Now())
	defer clear(b.Key)
	if err != nil {
		t.Fatal("actual node identity before root task", err)
	}
	credential, _, err := f.s.latestWebCredential(ctx, f.t.vault, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	inputs := []rootRotationNodeInput{{Node: "node-a", Credential: credential, Certificate: b.Certificate}}
	var task rootRotationTask
	wait(func() bool {
		var e error
		task, e = f.s.prepareRootRotation(ctx, f.c, f.t.vault, "admin", "kernel-root-task", f.t.release, inputs)
		return e == nil
	}, "root task waits for actual signing leases")
	serviceIdentity := func() string {
		t.Helper()
		program, args := "systemctl", []string{"show", "webscan-agent-native.service", "--property=MainPID,ActiveEnterTimestampMonotonic,NRestarts"}
		if mode == "docker" {
			program, args = "docker", []string{"inspect", "--format", "{{.Id}}/{{.State.Pid}}/{{.State.StartedAt}}/{{.RestartCount}}", "webscan-agent-go"}
		}
		raw, err := exec.CommandContext(ctx, program, args...).Output()
		if err != nil || len(bytes.TrimSpace(raw)) == 0 {
			t.Fatal("actual service identity unavailable", err)
		}
		return string(raw)
	}
	before := serviceIdentity()
	remote := &sshRootRotation{store: f.s, vault: f.t.vault, config: f.c, release: f.t.release, localHelper: f.t.config.HelperFile}
	runner := rootRotationRunner{store: f.s, vault: f.t.vault, config: f.c, release: f.t.release, runtime: remote}
	report := func(p rootRotationProgress) error {
		t.Logf("actual root rollout member=%s phase=%s status=%s", p.Member, p.Phase, p.Status)
		return nil
	}
	if err := runner.run(ctx, "admin", task.ID, false, report); err != nil {
		t.Fatal("actual pinned SSH dual-root rollout", err)
	}
	ready, _, err := f.s.readRootTask(ctx, f.t.vault, task.ID)
	if err != nil || ready.Status != "ready" || ready.Roots.Final != nil {
		t.Fatal("root retired before separate administrator finalization", err)
	}
	unchanged()
	if err := runner.run(ctx, "admin", task.ID, true, report); err != nil {
		t.Fatal("actual pinned SSH root finalization", err)
	}
	finished, _, err := f.s.readRootTask(ctx, f.t.vault, task.ID)
	if err != nil || finished.Status != "completed" || finished.Roots.Final == nil {
		t.Fatal("root task did not finish", err)
	}
	if serviceIdentity() != before {
		t.Fatal("root maintenance restarted actual Agent")
	}
	state, err := nodepki.ReadRootState(anchor, floor, time.Now())
	if err != nil || state.Final == nil {
		t.Fatal("actual node retained old online trust", err)
	}
	// Verify the server under its NEW CA and current SAN, then present the
	// original collector identity. Rejection must not merely be caused by a
	// stale hostname or inability to trust the new server certificate.
	node, err := scanNode(f.s.DB.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE id='node-a'"))
	if err != nil {
		t.Fatal(err)
	}
	oldCollector, err := tls.X509KeyPair(f.collector.Certificate, f.collector.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(state.Dual.NewCA) {
		t.Fatal("successor server trust unavailable")
	}
	connection, err := grpc.NewClient(node.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: node.ServerName, Certificates: []tls.Certificate{oldCollector}})))
	if err != nil {
		t.Fatal(err)
	}
	probe, stop := context.WithTimeout(ctx, 5*time.Second)
	_, err = agentv1.NewAgentServiceClient(connection).Capabilities(probe, &agentv1.CapabilitiesRequest{})
	stop()
	connection.Close()
	if err == nil {
		t.Fatal("actual Agent accepted retired-root collector after finalization")
	}
	if err := os.WriteFile(site+"/successor-acceptance.php", []byte("<?php echo 'new root';"), 0600); err != nil {
		t.Fatal(err)
	}
	wait(func() bool {
		var count int
		return f.s.DB.QueryRowContext(ctx, `SELECT count(*) FROM v3_events WHERE node='node-a' AND payload->>'path'=$1`, site+"/successor-acceptance.php").Scan(&count) == nil && count > 0
	}, "real collector persists events after root finalization")
	unchanged()
	t.Log("actual PostgreSQL task -> fixed SSH -> signed helper -> Agent dual trust, successor identity, new mTLS observations and explicit finalization passed without central/Agent restart")
}
