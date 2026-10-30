//go:build linux

package nodeops

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
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

// This test mutates fixed Agent paths and the real service manager. It must run
// only in the networkless, freshly generated kernel guest, never on a host or
// an ordinary container. No command, /proc, cgroup or service-state substitutes.
func TestNativeSystemdKernelLifecycleRetainsUnconfirmedEvents(t *testing.T) {
	runNativeSystemdKernelLifecycle(t, false, false)
}

func TestNativeSystemdKernelUpgradeRestoresOriginalAndRetainsEvents(t *testing.T) {
	runNativeSystemdKernelLifecycle(t, true, false)
}

func runNativeSystemdKernelLifecycle(t *testing.T, upgrade, recovery bool, nameChange ...bool) {
	t.Helper()
	changingName := len(nameChange) == 1 && nameChange[0]
	if os.Getenv("WEBSCAN_V3_TEST_SYSTEMD_GUEST") != "1" {
		t.Skip("requires explicit disposable x86_64 kernel guest")
	}
	marker, err := os.ReadFile("/v3-tests/kernel-guest")
	if err != nil || string(marker) != "webscan-v3-networkless-kernel-guest\n" || os.Geteuid() != 0 {
		t.Fatal("refusing unmarked environment")
	}
	pidOne, err := os.Readlink("/proc/1/exe")
	if err != nil || pidOne != "/usr/lib/systemd/systemd" {
		t.Fatal("real systemd PID 1 required", pidOne, err)
	}
	containerKind, containerErr := exec.Command("systemd-detect-virt", "--container").Output()
	if containerErr == nil || strings.TrimSpace(string(containerKind)) != "none" {
		t.Fatal("guest must boot in full machine mode", string(containerKind), containerErr)
	}
	if entries, err := os.ReadDir("/sys/class/net"); err != nil || len(entries) != 1 || entries[0].Name() != "lo" {
		t.Fatal("guest must have only loopback", err)
	}
	for _, path := range []string{agentDataDirectory, agentLogDirectory, legacyConfigurationRoot, nativeUnitPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refusing existing Agent installation", path, err)
		}
	}
	binary := os.Getenv("WEBSCAN_V3_TEST_NODE_BINARY")
	if binary == "" {
		t.Fatal("current CLI required")
	}
	raw := bundleWithCurrentAgent(t, binary)
	w, r := stageFixture(t, raw)
	w.probe = probeBundle
	version, err := exec.Command(binary, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	r.Spec.Release = strings.TrimSpace(string(version))
	site := testRoot(t)
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
	ca, err := nodepki.NewAuthority(created, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	node, err := ca.Issue(nodepki.Node, r.Node, []string{"127.0.0.1"}, now, time.Hour)
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
	m := attachConfiguration(t, w, &r, func(m *nodeconfig.Material) {
		if recovery || changingName {
			m.Format = 2
		}
		m.ServerName = "127.0.0.1"
		m.CA, m.Certificate, m.Key, m.CRL = node.CA, node.Certificate, node.Key, crl
		m.Settings.Resources.CPUs = 1.25
	})
	r.Spec.ServerName = m.ServerName
	n := &nativeLifecycle{runtime: w, activation: newNativeActivation(w), resources: nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}, preflight: LocalPreflight{}}
	n.activation.host.command = func(ctx context.Context, program string, args ...string) (string, error) {
		output, err := inventoryCommand(ctx, program, args...)
		if program == "systemctl" {
			t.Logf("real systemctl %v: output=%q error=%v", args, output, err)
		}
		return output, err
	}
	journalDir := filepath.Join(w.root, "journal")
	if recovery || changingName {
		journalDir = filepath.Join(w.root, "node")
	}
	j := openTestJournal(t, journalDir, n)
	t.Cleanup(func() {
		if t.Failed() {
			output, _ := exec.Command("journalctl", "-u", nativeServiceName, "--no-pager", "-n", "40").CombinedOutput()
			t.Logf("isolated service diagnostics: %s", output)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		ctx, release, err := acquireServiceOperation(ctx, w.root)
		if err != nil {
			t.Error(err)
			return
		}
		defer release()
		if _, err := os.Lstat(nativeUnitPath); err == nil {
			if _, err := inventoryCommand(ctx, "systemctl", "disable", "--now", nativeServiceName); err != nil {
				t.Error("guest cleanup could not stop Agent", err)
				return
			}
			os.Remove(nativeUnitPath)
			inventoryCommand(ctx, "systemctl", "daemon-reload")
		}
		for _, path := range []string{agentDataDirectory, agentLogDirectory} {
			if err := os.RemoveAll(path); err != nil {
				t.Error("remove disposable Agent data", err)
			}
		}
	})
	for _, phase := range []string{"preflight", "stage", "backup", "activate"} {
		r.Phase = phase
		result := j.Handle(r)
		t.Logf("phase=%s result=%+v", phase, result)
		if phase == "activate" && result.Code != "ok" {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			p, err := n.activation.plan(ctx, r)
			t.Logf("read-only activation plan diagnostic: %v", err)
			if err == nil {
				_, _, err := n.activation.state(ctx, p)
				t.Logf("read-only activation state diagnostic: %v", err)
			}
		}
		requireResult(t, result, "complete", "ok")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pid := func() int {
		t.Helper()
		text, err := exec.CommandContext(ctx, "systemctl", "show", nativeServiceName, "--property=MainPID", "--value").Output()
		value, parseErr := strconv.Atoi(strings.TrimSpace(string(text)))
		if err != nil || parseErr != nil || value < 1 {
			t.Fatal("systemd Agent PID unavailable", err, parseErr)
		}
		return value
	}
	initialPID := pid()
	pair, err := tls.X509KeyPair(collector.Certificate, collector.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(node.CA)
	connection, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(r.Spec.MetricsPort)), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: m.ServerName, RootCAs: roots, Certificates: []tls.Certificate{pair}})))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	rpc := agentv1.NewAgentServiceClient(connection)
	waitReady := func() {
		for {
			call, stop := context.WithTimeout(ctx, time.Second)
			capability, err := rpc.Capabilities(call, &agentv1.CapabilitiesRequest{})
			metrics, metricErr := rpc.ReadMetrics(call, &agentv1.ReadMetricsRequest{})
			stop()
			ready := false
			if err == nil && metricErr == nil && capability.NodeId == r.Node && capability.ConfigurationVersion == m.Version && capability.ConfigurationSha256 == m.SourceSHA256 {
				for _, sample := range metrics.Samples {
					if bytes.Contains(sample.PrometheusText, []byte("webscan_collector_ready 1\n")) && bytes.Contains(sample.PrometheusText, []byte("webscan_coverage_ok 1\n")) {
						ready = true
					}
				}
			}
			if ready {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("real systemd Agent readiness timeout", ctx.Err())
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	waitReady()
	for _, phase := range []string{"verify", "finalize"} {
		r.Phase = phase
		result := j.Handle(r)
		t.Logf("phase=%s result=%+v", phase, result)
		requireResult(t, result, "complete", "ok")
	}
	var originalPointer []byte
	originalRequest, originalMaterial := r, m
	var nameCertificate []byte
	if upgrade {
		originalPointer, err = readPrivate(filepath.Join(w.root, "active.json"), MaxRequestBytes)
		if err != nil {
			t.Fatal(err)
		}
		if changingName {
			nameCertificate = kernelChangeNodeName(t, ctx, w, r, m, ca, collector, crl)
			r, m = kernelNameTargetConfiguration(t, w, r, m)
		}
		r.Job, r.PlanDigest = "job-upgrade", strings.Repeat("b", 64)
		r.Operation, r.Epoch = "apply", 1
		for _, phase := range forward {
			r.Phase = phase
			result := j.Handle(r)
			t.Logf("upgrade phase=%s result=%+v", phase, result)
			requireResult(t, result, "complete", "ok")
		}
		upgradedPID := pid()
		if upgradedPID == initialPID {
			t.Fatal("upgrade did not replace the original Agent process")
		}
		initialPID = upgradedPID
		waitReady()
		if changingName {
			kernelNameEndpoint(t, ctx, r, m, collector, crl, nameCertificate, m.ServerName)
		}
	}
	// The manager's configured quota alone is insufficient. Temporarily remove
	// only this disposable Agent's kernel quota and require revalidation to fail.
	group, err := exec.CommandContext(ctx, "systemctl", "show", nativeServiceName, "--property=ControlGroup", "--value").Output()
	groupPath := strings.TrimSpace(string(group))
	if err != nil || !safeServicePath(groupPath) || filepath.Base(groupPath) != nativeServiceName {
		t.Fatal("Agent cgroup unavailable", err)
	}
	cpuPath := filepath.Join("/sys/fs/cgroup", groupPath, "cpu.max")
	originalQuota, err := os.ReadFile(cpuPath)
	if err != nil || string(originalQuota) != "125000 100000\n" {
		t.Fatal("real kernel quota mismatch", string(originalQuota), err)
	}
	func() {
		if err := os.WriteFile(cpuPath, []byte("max 100000\n"), 0); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(cpuPath, originalQuota, 0); err != nil {
				t.Error("restore disposable Agent quota", err)
			}
		}()
		r.Phase, r.Operation = "verify", "inspect"
		requireResult(t, j.Handle(r), "unknown", "verification-failed")
	}()
	// Reopen the durable journal and re-prove all completed phases against the
	// live manager and kernel. Receipt replay must not restart the writer.
	j = openTestJournal(t, journalDir, n)
	for _, phase := range forward {
		r.Phase, r.Operation = phase, "inspect"
		requireResult(t, j.Handle(r), "complete", "ok")
	}
	if pid() != initialPID {
		t.Fatal("reconciliation restarted Agent")
	}
	file := filepath.Join(site, "kernel-systemd.php")
	if err := os.WriteFile(file, []byte("<?php echo 'kernel-systemd';\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var eventID string
	for eventID == "" {
		batch, err := rpc.FetchEvents(ctx, &agentv1.FetchEventsRequest{Epoch: 1, Limit: 100, WaitSeconds: 1})
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range batch.Events {
			if bytes.Contains(event.Json, []byte(file)) {
				eventID = event.Id
			}
		}
		if ctx.Err() != nil {
			t.Fatal("real file event missing", ctx.Err())
		}
	}
	if recovery {
		recoverKernelIdentity(t, ctx, w, r, m, ca, collector, crl, eventID)
		initialPID = pid()
		waitReady()
	}
	for _, phase := range []string{"restore", "verify-rollback"} {
		r.Phase, r.Operation = phase, "apply"
		r.Epoch = 2
		result := j.Handle(r)
		t.Logf("phase=%s result=%+v", phase, result)
		requireResult(t, result, "complete", "ok")
	}
	if upgrade {
		pointer, err := readPrivate(filepath.Join(w.root, "active.json"), MaxRequestBytes)
		if err != nil || !bytes.Equal(pointer, originalPointer) {
			t.Fatal("rollback did not restore original installation pointer", err)
		}
		if pid() == initialPID {
			t.Fatal("rollback still running the target Agent")
		}
		if changingName {
			for _, name := range []string{originalMaterial.ServerName, m.ServerName} {
				kernelNameEndpoint(t, ctx, originalRequest, originalMaterial, collector, crl, nameCertificate, name)
			}
		}
	} else {
		if _, err := os.Lstat(nativeUnitPath); !os.IsNotExist(err) {
			t.Fatal("rollback left target unit", err)
		}
	}
	if _, err := os.Lstat(filepath.Join("/proc", strconv.Itoa(initialPID))); !os.IsNotExist(err) {
		t.Fatal("rollback left target process", err)
	}
	db, err := persist.OpenReadOnly(filepath.Join(agentDataDirectory, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var exported sql.NullString
	if err := db.QueryRow("SELECT exported FROM events WHERE id=? AND accepted IS NULL", eventID).Scan(&exported); err != nil || !exported.Valid {
		t.Fatal("rollback lost unconfirmed event", err)
	}
	text, err := os.ReadFile(exported.String)
	if err != nil || !bytes.Contains(text, []byte(eventID)) {
		t.Fatal("rollback export lost event identity", err)
	}
	if upgrade {
		// The restored real Agent legitimately holds the writer lock. Stop only
		// that owned service before checking that no target writer survived.
		locked, release, err := acquireServiceOperation(ctx, w.root)
		if err != nil {
			t.Fatal(err)
		}
		_, stopErr := inventoryCommand(locked, "systemctl", "disable", "--now", nativeServiceName)
		release()
		if stopErr != nil {
			t.Fatal("stop restored disposable Agent", stopErr)
		}
	}
	if lock, err := n.activation.backup.agentLock(); err != nil {
		t.Fatal("rollback left SQLite writer lock", err)
	} else {
		lock.Close()
	}
}
