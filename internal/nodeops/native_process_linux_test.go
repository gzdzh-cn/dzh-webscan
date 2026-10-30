//go:build linux

package nodeops

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
	"webscan/internal/persist"
	agentv1 "webscan/sdk/agent/v1"
)

func bundleWithCurrentAgent(t *testing.T, binary string) []byte {
	t.Helper()
	raw, err := os.ReadFile("/usr/local/lib/webscan/agent-native.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	zipped, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer zipped.Close()
	files := map[string][]byte{}
	reader := tar.NewReader(zipped)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err == nil && header.Typeflag == tar.TypeDir {
			continue
		}
		if err != nil || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > maxBundleFile {
			t.Fatal("invalid isolated tool fixture", err)
		}
		name := strings.TrimPrefix(header.Name, "./")
		data, err := io.ReadAll(io.LimitReader(reader, maxBundleFile+1))
		if err != nil || int64(len(data)) != header.Size {
			t.Fatal("invalid fixture data", err)
		}
		files[name] = data
	}
	files["webscan"], err = os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	version, err := exec.Command(binary, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	files["VERSION"] = version
	bundleChecksums(files)
	return archiveFiles(t, files, nil)
}

// Service-manager callbacks below are a test substitute; the launched Agent is
// the real current Linux CLI executable, with real /proc identity, SQLite lock,
// mTLS listener and graceful signal shutdown. This is not cgroup/systemd proof.
func TestNativeActivationRunsRealAgentProcessAndRollbackRetainsEvents(t *testing.T) {
	runNativeAgentProcess(t, false)
}

// The macOS Docker VM can translate amd64 through Rosetta. This separately
// named test exercises the process lifecycle but substitutes only the exe-path
// proof, never weakening the production ownership check for an emulator.
func TestNativeActivationRunsTranslatedAgentProcessAndRollbackRetainsEvents(t *testing.T) {
	runNativeAgentProcess(t, true)
}

func runNativeAgentProcess(t *testing.T, translated bool) {
	t.Helper()
	binary := os.Getenv("WEBSCAN_V3_TEST_NODE_BINARY")
	if binary == "" || os.Getenv("WEBSCAN_V3_TEST_BUNDLE") != "1" || os.Geteuid() != 0 {
		t.Skip("requires opted-in disposable Linux container and current compiled CLI")
	}
	// Rosetta special-cases a process reading its own exe, even with a numeric
	// PID. A separate reader observes the same identity as the installer does.
	selfRaw, err := exec.Command("readlink", filepath.Join("/proc", strconv.Itoa(os.Getpid()), "exe")).Output()
	if err != nil {
		t.Fatal(err)
	}
	selfExecutable := strings.TrimSpace(string(selfRaw))
	rosetta := selfExecutable == "/run/rosetta/rosetta"
	if rosetta != translated {
		t.Skip("test requires the matching native/translated Linux execution environment")
	}
	for _, path := range []string{agentDataDirectory, agentLogDirectory} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refusing existing Agent data", path, err)
		}
		t.Cleanup(func() { os.RemoveAll(path) })
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
	ca, err := nodepki.NewAuthority(now, 365*24*time.Hour)
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
		m.ServerName = "127.0.0.1"
		m.CA, m.Certificate, m.Key, m.CRL = node.CA, node.Certificate, node.Key, crl
	})
	r.Spec.ServerName = m.ServerName
	if err := w.prepare(context.Background(), r.Spec); err != nil {
		t.Fatal("current CLI bundle preparation", err)
	}
	if err := w.prepareConfiguration(context.Background(), r); err != nil {
		t.Fatal("current CLI configuration preparation", err)
	}
	if _, err := w.Apply(r); err != nil {
		t.Fatal(err)
	}
	host := newInstallationHost(w.root)
	host.configRoot = filepath.Join(w.root, "old-config")
	host.unitPath = filepath.Join(w.root, nativeServiceName)
	var child *exec.Cmd
	var childDone chan error
	if translated {
		t.Log("Rosetta lifecycle coverage; native /proc executable ownership still requires a native amd64 Linux host")
		readExecutable := host.processExecutable
		host.processExecutable = func(pid int) (string, error) {
			executable, err := readExecutable(pid)
			if err != nil || executable != selfExecutable || child == nil || pid != child.Process.Pid {
				return executable, err
			}
			return child.Path, nil
		}
	}
	enabled, loaded := false, false
	stop := func() error {
		if child == nil {
			return nil
		}
		child.Process.Signal(syscall.SIGTERM)
		select {
		case <-childDone:
			child = nil
			return nil
		case <-time.After(10 * time.Second):
			child.Process.Kill()
			<-childDone
			child = nil
			return fmt.Errorf("isolated Agent did not stop gracefully")
		}
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	})
	host.command = func(ctx context.Context, program string, args ...string) (string, error) {
		if program != "systemctl" || len(args) == 0 {
			return "", fmt.Errorf("unexpected service command")
		}
		switch args[0] {
		case "show":
			if !loaded {
				return "LoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=\nJob=0\nMainPID=0\n", fmt.Errorf("not found")
			}
			active, sub, pid, unitState := "inactive", "dead", 0, "disabled"
			if child != nil {
				active, sub, pid = "active", "running", child.Process.Pid
			}
			if enabled {
				unitState = "enabled"
			}
			return fmt.Sprintf("LoadState=loaded\nActiveState=%s\nSubState=%s\nFragmentPath=%s\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=%s\nJob=0\nMainPID=%d\n", active, sub, host.unitPath, unitState, pid), nil
		case "daemon-reload":
			_, err := os.Lstat(host.unitPath)
			loaded = err == nil
			return "", nil
		case "enable":
			enabled = true
			return "", nil
		case "disable":
			enabled = false
			if len(args) > 1 && args[1] == "--now" {
				return "", stop()
			}
			return "", nil
		case "start":
			if child != nil {
				return "", nil
			}
			child = exec.Command(filepath.Join(w.releaseDir(r.Spec), "webscan"), "agent", "--config", filepath.Join(w.configurationDir(r.Spec), "runtime.json"))
			child.Stdout, child.Stderr = io.Discard, io.Discard
			if err := child.Start(); err != nil {
				child = nil
				return "", err
			}
			childDone = make(chan error, 1)
			running := child
			done := childDone
			go func() { done <- running.Wait() }()
			return "", nil
		}
		return "", fmt.Errorf("unknown service command")
	}
	backup := &transitionBackup{root: w.root, data: agentDataDirectory, logs: agentLogDirectory, unit: host.unitPath, host: host}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r.Phase = "backup"
	if _, err := backup.run(ctx, r); err != nil {
		t.Fatal(err)
	}
	activation := &nativeActivation{runtime: w, backup: backup, host: host}
	r.Phase = "activate"
	if err := activation.run(ctx, r); err != nil {
		if child != nil {
			executable, executableErr := host.processExecutable(child.Process.Pid)
			arguments, argumentsErr := host.processArguments(child.Process.Pid)
			t.Logf("test process identity: executable=%q (%v), arguments=%q (%v)", executable, executableErr, arguments, argumentsErr)
		}
		t.Fatal("real process activation", err)
	}
	pid := child.Process.Pid
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
	for {
		call, stop := context.WithTimeout(ctx, time.Second)
		capability, err := rpc.Capabilities(call, &agentv1.CapabilitiesRequest{})
		metrics, metricErr := rpc.ReadMetrics(call, &agentv1.ReadMetricsRequest{})
		stop()
		ready := false
		if err == nil && metricErr == nil && capability.NodeId == r.Node && capability.ConfigurationVersion == m.Version && capability.ConfigurationSha256 == m.SourceSHA256 {
			for _, sample := range metrics.Samples {
				if strings.Contains(string(sample.PrometheusText), "webscan_collector_ready 1\n") && strings.Contains(string(sample.PrometheusText), "webscan_coverage_ok 1\n") {
					ready = true
				}
			}
		}
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("real Agent did not become ready", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	file := filepath.Join(site, "actual-cli.php")
	if err := os.WriteFile(file, []byte("<?php echo 'native-process';\n"), 0600); err != nil {
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
			t.Fatal("file event missing", ctx.Err())
		}
	}
	if err := activation.run(ctx, r); err != nil || child.Process.Pid != pid {
		t.Fatal("reconciliation restarted real writer", err)
	}
	r.Phase = "restore"
	if err := activation.restore(ctx, r); err != nil {
		t.Fatal("real process rollback", err)
	}
	if child != nil || enabled || loaded {
		t.Fatal("rollback left new service installed/running")
	}
	db, err := persist.OpenReadOnly(filepath.Join(agentDataDirectory, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var exported sql.NullString
	if err := db.QueryRow("SELECT exported FROM events WHERE id=? AND accepted IS NULL", eventID).Scan(&exported); err != nil || !exported.Valid {
		t.Fatal("rollback lost real file event", err)
	}
	text, err := os.ReadFile(exported.String)
	if err != nil || !bytes.Contains(text, []byte(eventID)) {
		t.Fatal("real event missing from legacy rollback file", err)
	}
	if lock, err := backup.agentLock(); err != nil {
		t.Fatal("stopped real writer still holds SQLite lock", err)
	} else {
		lock.Close()
	}
}
