//go:build linux

package nodeops

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
	"webscan/internal/persist"
	agentv1 "webscan/sdk/agent/v1"
)

// Requires a dedicated disposable DinD daemon with no host socket, host data
// mounts, published ports or existing Agent state. Real generated Compose and
// real service commands are used. Induced response loss happens after the
// actual Docker command, not in an engine implementation substitute.
func TestDockerLifecycleOnDisposableNestedEngine(t *testing.T) {
	runDockerEngineLifecycle(t, false, false)
}

func TestDockerKernelLifecycleFinalizesAndRetainsEvents(t *testing.T) {
	requireDockerKernelGuest(t)
	runDockerEngineLifecycle(t, true, false)
}

func requireDockerKernelGuest(t *testing.T) {
	t.Helper()
	if os.Getenv("WEBSCAN_V3_TEST_DOCKER_KERNEL_GUEST") != "1" {
		t.Skip("requires explicit disposable x86_64 kernel guest")
	}
	marker, err := os.ReadFile("/v3-tests/kernel-guest")
	pidOne, pidErr := os.Readlink("/proc/1/exe")
	container, containerErr := exec.Command("systemd-detect-virt", "--container").Output()
	interfaces, networkErr := os.ReadDir("/sys/class/net")
	if err != nil || string(marker) != "webscan-v3-networkless-kernel-guest\n" || pidErr != nil || pidOne != "/usr/lib/systemd/systemd" || containerErr == nil || strings.TrimSpace(string(container)) != "none" || networkErr != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("refusing environment without full isolated kernel/systemd and loopback only")
	}
}

func runDockerEngineLifecycle(t *testing.T, kernel, recovery bool, nameChange ...bool) {
	t.Helper()
	changingName := len(nameChange) == 1 && nameChange[0]
	if os.Getenv("WEBSCAN_V3_TEST_DIND") != "1" {
		t.Skip("requires explicitly opted-in disposable nested Docker engine")
	}
	marker, err := os.ReadFile("/v3-tests/isolated-engine")
	if os.Geteuid() != 0 || err != nil || string(marker) != "webscan-v3-disposable-dind\n" {
		t.Fatal("isolated-engine marker missing")
	}
	timeout := 4 * time.Minute
	if kernel {
		timeout = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	listing, err := inventoryCommand(ctx, "docker", "--host", "unix:///var/run/docker.sock", "ps", "-aq")
	if err != nil || strings.TrimSpace(listing) != "" {
		t.Fatal("refusing nonempty daemon", err)
	}
	for _, path := range []string{agentDataDirectory, agentLogDirectory, legacyConfigurationRoot, nativeUnitPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refusing existing Agent state", path, err)
		}
	}
	// All data lives in the disposable daemon container's own filesystem.
	for _, path := range []string{agentDataDirectory, agentLogDirectory} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(path) })
	}
	raw, err := os.ReadFile("/v3-tests/agent-native.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	w, r := stageFixture(t, raw)
	w.probe = probeBundle
	r.Spec.Mode, r.Spec.Release = "docker", "v3.0.0-local-test"
	proof, err := os.ReadFile("/v3-tests/image-proof.json")
	if err != nil {
		t.Fatal(err)
	}
	var image Spec
	if json.Unmarshal(proof, &image) != nil || !image.imageArchiveValid() {
		t.Fatal("invalid image fixture")
	}
	r.Spec.AgentImage, r.Spec.ImageArchiveSHA256, r.Spec.ImageArchiveBytes, r.Spec.ImageConfigSHA256 = image.AgentImage, image.ImageArchiveSHA256, image.ImageArchiveBytes, image.ImageConfigSHA256
	imageDir := filepath.Join(w.root, "images", image.ImageArchiveSHA256)
	if err := os.MkdirAll(imageDir, 0700); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open("/v3-tests/agent-image.tar")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(filepath.Join(imageDir, "docker-image.tar"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(target, source)
	closeErr := target.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	site, err := os.MkdirTemp("/var/tmp", "webscan-v3-dind-monitor-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(site)
	r.Spec.MonitorDirectories = []string{site}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.Spec.MetricsPort = listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	now := time.Now().UTC().Truncate(time.Second)
	created := now
	if recovery {
		created = now.Add(-48 * time.Hour)
	}
	authority, err := nodepki.NewAuthority(created, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authority.Issue(nodepki.Node, r.Node, []string{"node.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := authority.Issue(nodepki.Collector, "collector-a", nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := authority.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	material := attachConfiguration(t, w, &r, func(m *nodeconfig.Material) {
		if recovery || changingName {
			m.Format = 2
		}
		m.CA, m.Certificate, m.Key, m.CRL = identity.CA, identity.Certificate, identity.Key, crl
		if kernel {
			m.Settings.Resources.CPUs = 1.25
		}
	})
	if outcome, err := w.Apply(r); err != nil {
		t.Fatal("actual bundle/config/image preparation", outcome, err)
	}
	activation := newDockerActivation(w)
	ids := []string{}
	t.Cleanup(func() {
		for _, id := range ids {
			cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
			cleanupContext, release, err := acquireServiceOperation(cleanup, w.root)
			if err == nil {
				_, err = inventoryCommand(cleanupContext, "docker", "--host", "unix:///var/run/docker.sock", "rm", "-f", id)
				release()
			}
			stop()
			if err != nil {
				t.Error("cleanup exact test container", err)
			}
		}
	})
	var activationErr error
	journalDir := filepath.Join(w.root, "journal")
	if recovery || changingName {
		journalDir = filepath.Join(w.root, "node")
	}
	if kernel {
		baseline := &dockerLifecycle{runtime: w, activation: activation, resources: nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}, preflight: LocalPreflight{}, stage: w}
		journal := openTestJournal(t, journalDir, baseline)
		for _, phase := range forward {
			r.Phase = phase
			result := journal.Handle(r)
			t.Logf("baseline phase=%s result=%+v", phase, result)
			if result.State != "complete" || result.Code != "ok" {
				// Activation can create a restarting container before it fails.
				// Remove that exact test object before deferred data cleanup.
				if candidate, err := activation.host.containerNamed(ctx, agentContainerName); err == nil && candidate != nil {
					ids = append(ids, candidate.ID)
				}
			}
			requireResult(t, result, "complete", "ok")
		}
	} else {
		// The translated container fixture does not certify kernel enforcement
		// or finalization. The separately named full-kernel test does both.
		r.Phase = "backup"
		if _, err := activation.backup.run(ctx, r); err != nil {
			t.Fatal("baseline backup", err)
		}
		r.Phase = "activate"
		activationErr = activation.run(ctx, r)
	}
	old, err := activation.host.containerNamed(ctx, agentContainerName)
	if err != nil || old == nil {
		t.Fatal("baseline container", err)
	}
	ids = append(ids, old.ID)
	if activationErr != nil {
		t.Fatal("baseline activation", activationErr)
	}
	pair, err := tls.X509KeyPair(collector.Certificate, collector.Key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(identity.CA)
	connection, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(r.Spec.MetricsPort)), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "node.test", Certificates: []tls.Certificate{pair}})))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	rpc := agentv1.NewAgentServiceClient(connection)
	ready := func() {
		t.Helper()
		for {
			call, stop := context.WithTimeout(ctx, time.Second)
			capability, err := rpc.Capabilities(call, &agentv1.CapabilitiesRequest{})
			metricsReady := !kernel
			if kernel && err == nil {
				metrics, metricsErr := rpc.ReadMetrics(call, &agentv1.ReadMetricsRequest{})
				if metricsErr == nil {
					for _, sample := range metrics.Samples {
						text := string(sample.PrometheusText)
						if strings.Contains(text, "webscan_collector_ready 1\n") && strings.Contains(text, "webscan_coverage_ok 1\n") {
							metricsReady = true
						}
					}
				}
			}
			stop()
			if err == nil && metricsReady && capability.NodeId == r.Node && capability.ConfigurationVersion == material.Version && capability.ConfigurationSha256 == material.SourceSHA256 {
				return
			}
			if ctx.Err() != nil {
				t.Fatal("real Agent not ready", ctx.Err())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	ready()
	originalPointer, err := readPrivate(filepath.Join(w.root, "active.json"), MaxRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	originalRequest, originalMaterial := r, material
	var nameCertificate []byte
	if changingName {
		nameCertificate = kernelChangeNodeName(t, ctx, w, r, material, authority, collector, crl)
		r, material = kernelNameTargetConfiguration(t, w, r, material)
	}
	// A different task using the same release/configuration must retain and
	// restore the exact original Docker ID, not recreate it via Compose.
	r.Job = "job-upgrade"
	r.PlanDigest = strings.Repeat("b", 64)
	r.Phase = "preflight"
	d := &dockerLifecycle{runtime: w, activation: activation, resources: nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}, preflight: &testHandler{}, stage: w}
	if kernel {
		d.preflight = LocalPreflight{}
	}
	j := openTestJournal(t, journalDir, d)
	finishThrough(t, j, r, "backup")
	originalCommand := activation.host.command
	lost := false
	activation.host.command = func(ctx context.Context, program string, args ...string) (string, error) {
		out, err := originalCommand(ctx, program, args...)
		if err == nil && program == "docker" && len(args) > 2 && args[2] == "start" && !lost {
			lost = true
			return out, errors.New("induced-response-loss")
		}
		return out, err
	}
	r.Phase = "activate"
	activationResult := j.Handle(r)
	activation.host.command = originalCommand
	current, err := activation.host.containerNamed(ctx, agentContainerName)
	if err != nil || current == nil {
		t.Fatal("target container", err)
	}
	ids = append(ids, current.ID)
	requireResult(t, activationResult, "unknown", "activation-failed")
	if current.ID == old.ID || !lost {
		t.Fatal("test did not perform real replacement")
	}
	before, err := activation.host.dockerRuntime(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	r.Epoch++
	r.Operation = "inspect"
	requireResult(t, j.Handle(r), "complete", "ok")
	after, err := activation.host.dockerRuntime(ctx, current.ID)
	if err != nil || before.State.Pid != after.State.Pid || before.State.StartedAt != after.State.StartedAt || before.RestartCount != after.RestartCount {
		t.Fatal("response reconciliation restarted real target", err)
	}
	ready()
	if changingName {
		kernelNameEndpoint(t, ctx, r, material, collector, crl, nameCertificate, material.ServerName)
	}
	if kernel {
		for _, phase := range []string{"verify", "finalize"} {
			r.Operation, r.Phase = "apply", phase
			result := j.Handle(r)
			t.Logf("target phase=%s result=%+v", phase, result)
			requireResult(t, result, "complete", "ok")
		}
		for _, phase := range forward {
			r.Operation, r.Phase = "inspect", phase
			result := j.Handle(r)
			t.Logf("target replay phase=%s result=%+v", phase, result)
			if result.State != "complete" {
				p, planErr := d.activationPlan(ctx, r, true)
				t.Logf("target replay diagnostics plan=%v", planErr)
				if planErr == nil {
					t.Logf("target replay diagnostics confirmation=%v", d.activation.confirm(ctx, r, p))
					_, proofErr := d.resources.inspectDocker(ctx, activation.host, current.ID, p.intent.Target, p.material.Settings.Resources)
					t.Logf("target replay diagnostics resources=%v", proofErr)
				}
			}
			requireResult(t, result, "complete", "ok")
		}
		last, err := activation.host.dockerRuntime(ctx, current.ID)
		if err != nil || before.State.Pid != last.State.Pid || before.State.StartedAt != last.State.StartedAt || before.RestartCount != last.RestartCount {
			t.Fatal("completed phase replay restarted the real target", err)
		}
	}
	file := filepath.Join(site, "after-activation.php")
	if err := os.WriteFile(file, []byte("<?php echo 'local isolated test';\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var eventID string
	for eventID == "" {
		batch, err := rpc.FetchEvents(ctx, &agentv1.FetchEventsRequest{Epoch: 1, Limit: 100, WaitSeconds: 1})
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range batch.Events {
			var payload map[string]any
			if json.Unmarshal(event.Json, &payload) == nil && payload["path"] == file {
				eventID = event.Id
			}
		}
		if ctx.Err() != nil {
			t.Fatal("real file event absent", ctx.Err())
		}
	}
	if recovery {
		recoverKernelIdentity(t, ctx, w, r, material, authority, collector, crl, eventID)
		ready()
	}
	// Verify actual policy drift, then exercise the real Journal rollback.
	locked, release, err := acquireServiceOperation(ctx, w.root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = activation.host.docker(locked, "update", "--memory", strconv.FormatInt((int64(material.Settings.Resources.MemoryMiB)+64)<<20, 10), current.ID)
	release()
	if err != nil {
		t.Fatal("induce actual policy drift", err)
	}
	r.Operation, r.Phase = "apply", "verify"
	requireResult(t, j.Handle(r), "unknown", "verification-failed")
	r.Phase = "restore"
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	restored, err := activation.host.containerNamed(ctx, agentContainerName)
	if err != nil || restored == nil || restored.ID != old.ID {
		t.Fatal("original object not restored", err)
	}
	pointer, err := readPrivate(filepath.Join(w.root, "active.json"), MaxRequestBytes)
	if err != nil || string(pointer) != string(originalPointer) {
		t.Fatal("original task pointer not restored", err)
	}
	if changingName {
		for _, name := range []string{originalMaterial.ServerName, material.ServerName} {
			kernelNameEndpoint(t, ctx, originalRequest, originalMaterial, collector, crl, nameCertificate, name)
		}
		material = originalMaterial
	}
	db, err := persist.OpenDB(filepath.Join(agentDataDirectory, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT count(*) FROM events WHERE id=? AND accepted IS NULL AND exported IS NOT NULL", eventID).Scan(&count); err != nil || count != 1 {
		t.Fatal("post-activation pending event lost", count, err)
	}
	failed, err := activation.host.container(ctx, current.ID)
	if err != nil || failed.Status == "running" || failed.Restart != "no" || !strings.HasPrefix(failed.Name, "/webscan-failed-") {
		t.Fatal("failed object not retained safely", err)
	}
	ready()
	if kernel {
		var active ActiveInstallation
		if err := json.Unmarshal(originalPointer, &active); err != nil {
			t.Fatal(err)
		}
		proof, err := d.resources.inspectDocker(ctx, activation.host, old.ID, active, material.Settings.Resources)
		if err != nil || proof.Kernel.CgroupVersion != 2 || proof.Kernel.PID < 1 {
			t.Fatal("restored original kernel policy not proven", proof, err)
		}
		t.Log("real x86_64 kernel: fresh install and upgrade finalized; process/cgroup limits, mTLS readiness, lost response, policy drift and original-ID/current-data rollback verified")
	} else {
		t.Log("real nested engine: stage/create/start, mTLS config ACK, real file event, lost-start reconciliation and exact-ID/current-data rollback passed; successful kernel verification/finalization not certified")
	}
}
