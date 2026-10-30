//go:build linux

package nodeops

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
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

// A real systemd manager and an independent Docker daemon share the guest's
// actual kernel and Agent database. No service/process/resource substitutes.
func TestKernelNativeDockerTransitionsRetainCurrentData(t *testing.T) {
	requireDockerKernelGuest(t)
	for _, mode := range []string{"native", "docker"} {
		t.Run("from-"+mode, func(t *testing.T) { runKernelModeTransition(t, mode) })
	}
}

func runKernelModeTransition(t *testing.T, originalMode string) {
	t.Helper()
	marker, err := os.ReadFile("/v3-tests/isolated-engine")
	if os.Geteuid() != 0 || os.Getenv("WEBSCAN_V3_TEST_DIND") != "1" || err != nil || string(marker) != "webscan-v3-disposable-dind\n" {
		t.Fatal("refusing unmarked Docker guest")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
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
	raw, err := os.ReadFile("/v3-tests/agent-native.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	w, base := stageFixture(t, raw)
	w.probe = probeBundle
	base.Spec.Mode, base.Spec.Release = originalMode, "v3.0.0-local-test"
	site, err := os.MkdirTemp("/var/tmp", "webscan-v3-transition-monitor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(site) })
	base.Spec.MonitorDirectories = []string{site}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base.Spec.MetricsPort = listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	proof, err := os.ReadFile("/v3-tests/image-proof.json")
	var image Spec
	if err != nil || json.Unmarshal(proof, &image) != nil || !image.imageArchiveValid() {
		t.Fatal("invalid pinned image fixture", err)
	}
	imageDirectory := filepath.Join(w.root, "images", image.ImageArchiveSHA256)
	if err := os.MkdirAll(imageDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	func() {
		source, err := os.Open("/v3-tests/agent-image.tar")
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		target, err := os.OpenFile(filepath.Join(imageDirectory, "docker-image.tar"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, copyErr := io.Copy(target, source)
		closeErr := target.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatal(copyErr, closeErr)
		}
	}()
	setMode := func(r *Request, mode string) {
		r.Spec.Mode = mode
		r.Spec.AgentImage, r.Spec.ImageArchiveSHA256, r.Spec.ImageConfigSHA256, r.Spec.ImageArchiveBytes = "", "", "", 0
		if mode == "docker" {
			r.Spec.AgentImage, r.Spec.ImageArchiveSHA256, r.Spec.ImageConfigSHA256, r.Spec.ImageArchiveBytes = image.AgentImage, image.ImageArchiveSHA256, image.ImageConfigSHA256, image.ImageArchiveBytes
		}
	}
	setMode(&base, originalMode)
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	node, err := ca.Issue(nodepki.Node, base.Node, []string{"node.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := ca.Issue(nodepki.Collector, "collector-a", nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ca.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	configure := func(r *Request, version int64, source string) nodeconfig.Material {
		m := attachConfiguration(t, w, r, func(m *nodeconfig.Material) {
			m.CA, m.Certificate, m.Key, m.CRL = node.CA, node.Certificate, node.Key, crl
			m.Settings.Resources.CPUs = 1.25
			m.Version, m.SourceSHA256 = version, strings.Repeat(source, 64)
		})
		r.Spec.ConfigVersion, r.Spec.ConfigSourceSHA256 = m.Version, m.SourceSHA256
		return m
	}
	originalMaterial := configure(&base, 1, "c")
	target := base
	target.Job, target.PlanDigest = "job-switch", strings.Repeat("b", 64)
	targetMode := "docker"
	if originalMode == "docker" {
		targetMode = "native"
	}
	setMode(&target, targetMode)
	targetMaterial := configure(&target, 2, "d")
	host := newInstallationHost(w.root)
	t.Cleanup(func() { cleanupKernelTransition(t, w, host, base.Node) })
	n := &nativeLifecycle{runtime: w, activation: newNativeActivation(w), resources: nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}, preflight: LocalPreflight{}}
	d := &dockerLifecycle{runtime: w, activation: newDockerActivation(w), resources: nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}, preflight: LocalPreflight{}, stage: w}
	driver := func(mode string) Handler {
		if mode == "native" {
			return n
		}
		return d
	}
	journalRoot := filepath.Join(w.root, "journal")
	apply := func(j *Journal, r Request, phases []string) {
		t.Helper()
		for _, phase := range phases {
			r.Phase, r.Operation = phase, "apply"
			result := j.Handle(r)
			t.Logf("mode=%s job=%s phase=%s result=%+v", r.Spec.Mode, r.Job, phase, result)
			requireResult(t, result, "complete", "ok")
		}
	}
	apply(openTestJournal(t, journalRoot, driver(originalMode)), base, forward)
	originalPointer, err := readPrivate(filepath.Join(w.root, "active.json"), MaxRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	original := kernelSingleWriter(t, ctx, w, host, base)
	pair, err := tls.X509KeyPair(collector.Certificate, collector.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(node.CA)
	conn, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(base.Spec.MetricsPort)), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: "node.test", RootCAs: roots, Certificates: []tls.Certificate{pair}})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rpc := agentv1.NewAgentServiceClient(conn)
	ready := func(m nodeconfig.Material) {
		t.Helper()
		minimum := time.Now().UnixMilli()
		deadline, stop := context.WithTimeout(ctx, 90*time.Second)
		defer stop()
		for deadline.Err() == nil {
			call, cancel := context.WithTimeout(deadline, 3*time.Second)
			capability, capErr := rpc.Capabilities(call, &agentv1.CapabilitiesRequest{})
			metrics, metricsErr := rpc.ReadMetrics(call, &agentv1.ReadMetricsRequest{AfterUnixMillis: minimum - 1})
			cancel()
			if capErr == nil && metricsErr == nil && capability.NodeId == m.Node && capability.ConfigurationVersion == m.Version && capability.ConfigurationSha256 == m.SourceSHA256 {
				if kernelLatestReadiness(metrics.Samples, minimum) {
					return
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("real Agent readiness/configuration/scanner timed out", m.Mode, deadline.Err())
	}
	event := func(name string, epoch uint64) string {
		t.Helper()
		path := filepath.Join(site, name+".php")
		if err := os.WriteFile(path, []byte("<?php /* isolated mode transition */\n"), 0600); err != nil {
			t.Fatal(err)
		}
		for ctx.Err() == nil {
			batch, err := rpc.FetchEvents(ctx, &agentv1.FetchEventsRequest{Epoch: epoch, Limit: 100, WaitSeconds: 1})
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range batch.Events {
				var payload map[string]any
				if json.Unmarshal(item.Json, &payload) == nil && payload["path"] == path {
					return item.Id
				}
			}
		}
		t.Fatal("real file event missing", ctx.Err())
		return ""
	}
	ready(originalMaterial)
	beforeID := event("before-switch", 1)
	j := openTestJournal(t, journalRoot, driver(targetMode))
	apply(j, target, forward[:3])
	// Lose a response only after the real target start. Reopen the persisted
	// journal and inspect the process, rather than invoking start twice.
	lost := false
	command := func(ctx context.Context, program string, args ...string) (string, error) {
		out, err := inventoryCommand(ctx, program, args...)
		started := program == "systemctl" && len(args) > 0 && args[0] == "start" || program == "docker" && len(args) > 2 && args[2] == "start"
		if err == nil && started && !lost {
			lost = true
			return out, errors.New("induced-real-start-response-loss")
		}
		return out, err
	}
	if targetMode == "native" {
		n.activation.host.command = command
	} else {
		d.activation.host.command = command
	}
	target.Phase, target.Operation = "activate", "apply"
	requireResult(t, j.Handle(target), "unknown", "activation-failed")
	n.activation.host.command, d.activation.host.command = inventoryCommand, inventoryCommand
	if !lost {
		t.Fatal("real target start did not lose its response")
	}
	current := kernelSingleWriter(t, ctx, w, host, target)
	target.Epoch++
	target.Operation = "inspect"
	j = openTestJournal(t, journalRoot, driver(targetMode))
	requireResult(t, j.Handle(target), "complete", "ok")
	if kernelSingleWriter(t, ctx, w, host, target).pid != current.pid {
		t.Fatal("lost response reconciliation restarted the target")
	}
	ready(targetMaterial)
	apply(j, target, forward[4:])
	if originalMode == "native" {
		if _, err := os.Lstat(nativeUnitPath); !os.IsNotExist(err) {
			t.Fatal("original native unit remains active", err)
		}
	} else {
		old, err := host.container(ctx, original.container)
		if err != nil || old.Status == "running" || old.Restart != "no" || old.Name != "/"+retiredDockerName(target) {
			t.Fatal("original Docker not retained quiescently", err)
		}
	}
	afterID := event("after-switch", 2)
	apply(j, target, rollback)
	ready(originalMaterial)
	restored := kernelSingleWriter(t, ctx, w, host, base)
	pointer, err := readPrivate(filepath.Join(w.root, "active.json"), MaxRequestBytes)
	if err != nil || !bytes.Equal(pointer, originalPointer) || originalMode == "docker" && restored.container != original.container {
		t.Fatal("original identity/pointer not restored", err)
	}
	// Read the actual current DB, then retrieve the same event IDs from the
	// restored real Agent; an old snapshot or freshly generated IDs cannot pass.
	db, err := persist.OpenReadOnly(filepath.Join(agentDataDirectory, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{beforeID, afterID} {
		var count int
		if err := db.QueryRow("SELECT count(*) FROM events WHERE id=? AND accepted IS NULL AND exported IS NOT NULL", id).Scan(&count); err != nil || count != 1 {
			db.Close()
			t.Fatal("current unconfirmed event lost on rollback", id, count, err)
		}
	}
	db.Close()
	batch, err := rpc.FetchEvents(ctx, &agentv1.FetchEventsRequest{Epoch: 3, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, item := range batch.Events {
		found[item.Id] = true
	}
	if !found[beforeID] || !found[afterID] {
		t.Fatal("restored Agent cannot replay both original event IDs")
	}
	for _, phase := range rollback {
		target.Phase, target.Operation = phase, "inspect"
		requireResult(t, j.Handle(target), "complete", "ok")
	}
	if kernelSingleWriter(t, ctx, w, host, base).pid != restored.pid {
		t.Fatal("rollback replay restarted the restored writer")
	}
	t.Logf("real %s -> %s -> %s: kernel limits, YARA, mTLS config versions, exactly one writer, lost-start continuation and original IDs/current events retained", originalMode, targetMode, originalMode)
}

type kernelWriter struct {
	pid       int
	container string
}

func kernelSingleWriter(t *testing.T, ctx context.Context, w *LocalRuntime, host installationHost, r Request) kernelWriter {
	t.Helper()
	i, err := host.inventory(ctx, r.Node, r.Spec.Mode)
	if err != nil || len(i.Services) != 1 || i.Mode != r.Spec.Mode || !i.Services[0].Running {
		t.Fatal("single running installation not proven", i, err)
	}
	material, err := w.configurationMaterial(ctx, r)
	if err != nil {
		t.Fatal("writer configuration not proven", err)
	}
	raw, err := readPrivate(filepath.Join(w.root, "active.json"), MaxRequestBytes)
	var active ActiveInstallation
	if err != nil || json.Unmarshal(raw, &active) != nil || active.Format != 1 || active.Node != r.Node || !reflect.DeepEqual(active.Spec, r.Spec) {
		t.Fatal("writer active pointer differs", err)
	}
	resources := nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}
	var writer kernelWriter
	if r.Spec.Mode == "native" {
		status, err := host.native(ctx, i.Services[0])
		if err != nil {
			t.Fatal(err)
		}
		writer.pid = status.MainPID
		if proof, err := resources.inspect(ctx, host, status, i.Services[0], material.Settings.Resources); err != nil || proof.PID != writer.pid {
			t.Fatal("actual native writer resource limits not effective", err)
		}
	} else {
		state, err := host.dockerRuntime(ctx, i.Services[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		writer.pid, writer.container = state.State.Pid, i.Services[0].ID
		if proof, err := resources.inspectDocker(ctx, host, writer.container, active, material.Settings.Resources); err != nil || proof.Kernel.PID != writer.pid {
			t.Fatal("actual Docker writer resource limits not effective", err)
		}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	writers := []int{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		args, err := host.processArguments(pid)
		if err == nil && len(args) == 4 && args[0] == filepath.Join(w.releaseDir(r.Spec), "webscan") && args[1] == "agent" && args[2] == "--config" && strings.HasPrefix(args[3], w.root+"/") {
			writers = append(writers, pid)
		}
	}
	if len(writers) != 1 || writers[0] != writer.pid {
		t.Fatal("actual kernel Agent writer set differs", writers, writer.pid)
	}
	return writer
}

// Persisted metrics survive mode switches. Only the newest sample collected
// after this readiness check began can prove the current process is ready.
func kernelLatestReadiness(samples []*agentv1.MetricsSample, minimum int64) bool {
	var latest *agentv1.MetricsSample
	for _, sample := range samples {
		if sample != nil && sample.UnixMillis >= minimum && (latest == nil || sample.UnixMillis > latest.UnixMillis) {
			latest = sample
		}
	}
	return latest != nil && bytes.Contains(latest.PrometheusText, []byte("webscan_collector_ready 1\n")) && bytes.Contains(latest.PrometheusText, []byte("webscan_coverage_ok 1\n")) && bytes.Contains(latest.PrometheusText, []byte("webscan_yara_ready 1\n"))
}

func TestKernelReadinessRejectsHistoricalSamples(t *testing.T) {
	ready := []byte("webscan_collector_ready 1\nwebscan_coverage_ok 1\nwebscan_yara_ready 1\n")
	for _, tt := range []struct {
		name    string
		samples []*agentv1.MetricsSample
		want    bool
	}{
		{"empty", nil, false},
		{"historical-ready", []*agentv1.MetricsSample{{UnixMillis: 99, PrometheusText: ready}}, false},
		{"latest-failed", []*agentv1.MetricsSample{{UnixMillis: 100, PrometheusText: ready}, {UnixMillis: 101, PrometheusText: []byte("webscan_collector_ready 0\n")}}, false},
		{"unordered-latest-ready", []*agentv1.MetricsSample{{UnixMillis: 101, PrometheusText: ready}, nil, {UnixMillis: 100}}, true},
		{"fresh-boundary", []*agentv1.MetricsSample{{UnixMillis: 100, PrometheusText: ready}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := kernelLatestReadiness(tt.samples, 100); got != tt.want {
				t.Fatalf("fresh latest readiness=%v want %v", got, tt.want)
			}
		})
	}
}

func cleanupKernelTransition(t *testing.T, w *LocalRuntime, host installationHost, node string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	ctx, release, err := acquireServiceOperation(ctx, w.root)
	if err != nil {
		t.Error("test cleanup lock", err)
		return
	}
	defer release()
	if _, err := os.Lstat(nativeUnitPath); err == nil {
		if _, err := inventoryCommand(ctx, "systemctl", "disable", "--now", nativeServiceName); err != nil {
			t.Error("stop exact test unit", err)
			return
		}
		if err := os.Remove(nativeUnitPath); err != nil {
			t.Error(err)
			return
		}
		if _, err := inventoryCommand(ctx, "systemctl", "daemon-reload"); err != nil {
			t.Error(err)
			return
		}
	}
	listing, err := host.docker(ctx, "ps", "-aq", "--no-trunc", "--filter", "label=io.webscan.managed=v3", "--filter", "label=io.webscan.node="+node)
	if err != nil {
		t.Error("list exact test containers", err)
		return
	}
	for _, id := range strings.Fields(listing) {
		if !validDigest(id) {
			t.Error("invalid test container ID")
			return
		}
		if _, err := host.docker(ctx, "rm", "-f", id); err != nil {
			t.Error("remove exact test container", err)
			return
		}
	}
	for _, path := range []string{agentDataDirectory, agentLogDirectory} {
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	}
}
