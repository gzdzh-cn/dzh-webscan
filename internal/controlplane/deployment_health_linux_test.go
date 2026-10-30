//go:build linux

package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"webscan/internal/agent"
	"webscan/internal/common"
	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

// A real Agent, YARA, inotify, SQLite, mTLS and PostgreSQL are exercised. Service
// installation is not involved. The metrics HTTP writer is a controlled sink;
// this test certifies neither systemd deployment nor VictoriaMetrics durability.
func TestRealAgentHealthControlsDeploymentFinalization(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_AGENT_HEALTH") != "1" {
		t.Skip("requires disposable Linux/PG/YARA integration fixture")
	}
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	tool, err := exec.LookPath("yara")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := authority.Export()
	if err != nil {
		t.Fatal(err)
	}
	nodeIdentity, err := authority.Issue(nodepki.Node, "node-a", []string{"127.0.0.1"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	collectorIdentity, err := authority.Issue(nodepki.Collector, "collector-a", nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := authority.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := privateTestDir(t)
	monitor := filepath.Join(dir, "monitor")
	probe := filepath.Join(monitor, ".webscan-probe")
	if err := os.MkdirAll(probe, 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	in := deploymentFixture(t, s)
	settings := nodeconfig.DefaultSettings()
	settings.Monitor.Roots = []string{monitor}
	settings.ProbeDirectory = probe
	settings.ProbeSeconds = 10
	settings.MetricsSourceIP = "127.0.0.1"
	config, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	n := nodeFixture("node-a")
	n.Endpoint = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	n.ServerName = "127.0.0.1"
	n.Config = config
	if err := s.PutNode(ctx, n, 1, 256); err != nil {
		t.Fatal(err)
	}
	n, err = scanNode(s.DB.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE id=$1", n.ID))
	if err != nil {
		t.Fatal(err)
	}
	in.Expected = n.Version
	createDeployment(t, s, in, "actual-health-install")
	j := claimDeployment(t, s, "actual-health-executor")
	for j.Phase() != "verify" {
		if j.Phase() == "backup" {
			if err := s.ArmDeploymentRecovery(ctx, j); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, s, j.ID)
	}
	for name, raw := range map[string][]byte{"ca.crt": ca.CA, "ca.crl": crl, "identity.crt": nodeIdentity.Certificate, "identity.key": nodeIdentity.Key, "rules.yar": []byte("rule private_readiness { condition: false }\n")} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	material := nodeconfig.Material{Node: n.ID, Version: n.Version, SourceSHA256: digest(n.Config), Mode: "native", Release: in.Release, MetricsPort: port, Collectors: []string{"collector-a"}, Settings: settings}
	runtime, err := material.Runtime(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "data")
	runtime["data_dir"] = data
	runtime["log_dir"] = filepath.Join(dir, "logs")
	runtime["metrics_file"] = filepath.Join(data, "textfile/agent.prom")
	common.M(runtime["pull"])["revocation_state_directory"] = filepath.Join(data, "pki-trust")
	runtime["scanner_tools"] = common.Map{"yara": tool, "clamav": "/unused-disabled-scanner"}
	configPath := filepath.Join(dir, "runtime.json")
	if err := common.AtomicJSON(configPath, runtime); err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(runtime, configPath)
	if err != nil {
		t.Fatal(err)
	}
	agentCtx, stopAgent := context.WithCancel(ctx)
	agentDone := make(chan error, 1)
	go func() { agentDone <- a.Run(agentCtx) }()
	defer func() {
		stopAgent()
		if err := <-agentDone; err != nil && !errors.Is(err, context.Canceled) {
			t.Error("Agent failed", err)
		}
		a.Close()
	}()
	trust, err := nodepki.NewFileTrust(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.crl"), now)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CA)
	pair, err := tls.X509KeyPair(collectorIdentity.Certificate, collectorIdentity.Key)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: n.ServerName, Certificates: []tls.Certificate{pair}}
	policy := &nodeCertificatePolicy{trust: trust, node: n.ID}
	policy.wrapTLS(clientTLS)
	conn, err := grpc.NewClient(n.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)), grpc.WithUnaryInterceptor(policy.invoke))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := agentv1.NewAgentServiceClient(conn)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer sink.Close()
	c := &Collector{Store: s, trust: trust, Metrics: &Metrics{WriteURL: sink.URL, HTTP: sink.Client()}}
	l, err := s.Acquire(ctx, shardResource(n.Shard), "actual-health-collector")
	if err != nil {
		t.Fatal(err)
	}
	eventsCtx, stopEvents := context.WithCancel(ctx)
	eventsDone := make(chan struct{})
	go func() { defer close(eventsDone); c.events(eventsCtx, n, l, client) }()
	defer func() { stopEvents(); <-eventsDone }()
	leaseRenewed := time.Now()
	renewDeployment := func() {
		t.Helper()
		if time.Since(leaseRenewed) >= 5*time.Second {
			// This fixture calls phases directly; emulate the real runner's
			// renewal while waiting across multiple actual metric intervals.
			if err := s.RenewDeployment(ctx, j); err != nil {
				t.Fatal("test executor lost its deployment lease", err)
			}
			leaseRenewed = time.Now()
		}
	}
	collectUntil := func(wantHealthy bool) {
		t.Helper()
		for {
			renewDeployment()
			_, err = s.Acquire(ctx, l.Resource, l.Owner)
			if err != nil {
				t.Fatal(err)
			}
			collectErr := c.collect(ctx, n, l, client)
			if collectErr == nil {
				if err := c.observeRuntime(ctx, n, l, client); err != nil {
					t.Fatal(err)
				}
			}
			if collectErr == nil {
				var raw []byte
				var at int64
				err := s.DB.QueryRowContext(ctx, "SELECT sampled_at,metrics FROM v3_node_status WHERE node=$1 AND sampled_at IS NOT NULL", n.ID).Scan(&at, &raw)
				if err == nil {
					var values map[string]float64
					if json.Unmarshal(raw, &values) != nil {
						t.Fatal("invalid actual metrics")
					}
					healthy := validDeploymentHealth(n.Config, values, at, time.Now(), time.Time{})
					if healthy == wantHealthy && (wantHealthy || values["webscan_covered_roots"] == 0) {
						return
					}
				}
			}
			if !waitRetry(ctx, 100*time.Millisecond) {
				t.Fatal("actual Agent health did not converge", wantHealthy, ctx.Err())
			}
		}
	}
	collectUntil(true)
	for tableCount(t, s, "v3_node_readiness") != 2 {
		renewDeployment()
		if !waitRetry(ctx, 100*time.Millisecond) {
			t.Fatal(ctx.Err())
		}
	}
	// Empty long polls can prove transport readiness; separately establish that
	// this real watched file traversed Agent SQLite -> PG -> receipt ACK.
	for {
		renewDeployment()
		var id string
		err := s.DB.QueryRowContext(ctx, "SELECT id FROM v3_events WHERE node=$1 AND operation='probe' AND payload->>'path'=$2 ORDER BY received_at DESC LIMIT 1", n.ID, filepath.Join(probe, "heartbeat.php")).Scan(&id)
		if err != nil && err != sql.ErrNoRows {
			t.Fatal(err)
		}
		if err == nil {
			var confirmed int
			if err := a.DB.QueryRowContext(ctx, "SELECT count(*) FROM events WHERE id=? AND accepted IS NOT NULL", id).Scan(&confirmed); err != nil {
				t.Fatal(err)
			}
			if confirmed == 1 {
				break
			}
		}
		if !waitRetry(ctx, 100*time.Millisecond) {
			t.Fatal("real file probe was not stored and acknowledged", ctx.Err())
		}
	}
	if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal("actual healthy Agent not verified", err)
	}
	j = reloadDeployment(t, s, j.ID)
	// Moving only this test's monitored root removes real inotify watches. The
	// next real metrics sample must invalidate finalization, even after verify.
	if err := os.Rename(monitor, monitor+"-away"); err != nil {
		t.Fatal(err)
	}
	collectUntil(false)
	if err := s.CompleteDeploymentPhase(ctx, j); !errors.Is(err, ErrDeploymentNotReady) {
		t.Fatal("missing actual root finalized deployment", err)
	}
	var applied int64
	if err := s.DB.QueryRowContext(ctx, "SELECT applied_version FROM v3_nodes WHERE id=$1", n.ID).Scan(&applied); err != nil || applied != 0 {
		t.Fatal("unhealthy Agent marked applied", applied, err)
	}
	var count int
	if err := a.DB.QueryRow("SELECT count(*) FROM events WHERE payload LIKE '%scanner-readiness%'").Scan(&count); err != nil || count != 0 {
		t.Fatal("selftest created business event", count, err)
	}
	if strings.Contains(string(common.JSON(runtime)), "smtp") {
		t.Fatal("unexpected notification configuration")
	}
	if tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("health selftests queued business notifications")
	}
	t.Log("real Agent/YARA/inotify/SQLite/mTLS/PG health and file-probe ACK verified; actual lost root prevented finalization and applied_version")
}
