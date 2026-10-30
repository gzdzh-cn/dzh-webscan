package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"webscan/internal/nodepki"
	"webscan/internal/pull"
	agentv1 "webscan/sdk/agent/v1"
)

func TestActualMTLSCollectorSuppliesDeploymentReadiness(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := authority.Export()
	if err != nil {
		t.Fatal(err)
	}
	node, err := authority.Issue(nodepki.Node, "node-a", []string{"agent.test"}, now, time.Hour)
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
	dir := privateTestDir(t)
	for name, raw := range map[string][]byte{"ca.crt": ca.CA, "ca.crl": crl} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	trust, err := nodepki.NewFileTrust(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.crl"), now)
	if err != nil {
		t.Fatal(err)
	}
	serverTrust, err := nodepki.NewTrust(ca.CA, crl, now)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT NOT NULL,created REAL NOT NULL,accepted REAL)`); err != nil {
		t.Fatal(err)
	}
	source, err := pull.New(db, "node-a", "v3.0.0", nil, pull.Configuration{Version: 2, SHA256: digest([]byte("{}"))})
	if err != nil {
		t.Fatal(err)
	}
	serverPolicy := func(cert *x509.Certificate) error {
		return serverTrust.Verify(cert, nodepki.Collector, "collector-a", time.Now())
	}
	g := pull.NewServer(source, []string{"spiffe://webscan/collector/collector-a"}, serverPolicy)
	defer g.Stop()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CA)
	serverPair, err := tls.X509KeyPair(node.Certificate, node.Key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	defer server.Close()
	in := deploymentFixture(t, s)
	n := nodeFixture("node-a")
	n.Endpoint, n.ServerName = server.Listener.Addr().String(), "agent.test"
	if err := s.PutNode(context.Background(), n, 1, 256); err != nil {
		t.Fatal(err)
	}
	in.Expected = 2
	createDeployment(t, s, in, "network-install")
	j := claimDeployment(t, s, "network-executor")
	for j.Phase() != "verify" {
		if j.Phase() == "backup" {
			if err := s.ArmDeploymentRecovery(context.Background(), j); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.CompleteDeploymentPhase(context.Background(), j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, s, j.ID)
	}
	n, err = scanActiveNode(s.DB.QueryRow("SELECT "+activeNodeColumns+" FROM v3_active_nodes WHERE id=$1", j.Node))
	if err != nil {
		t.Fatal(err)
	}
	l, err := s.Acquire(context.Background(), shardResource(n.Shard), "network-collector")
	if err != nil {
		t.Fatal(err)
	}
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer vm.Close()
	c := &Collector{Store: s, trust: trust, Metrics: &Metrics{WriteURL: vm.URL, HTTP: vm.Client()}}
	clientPair, err := tls.X509KeyPair(collector.Certificate, collector.Key)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: n.ServerName, Certificates: []tls.Certificate{clientPair}}
	c.TLS = tlsConfig.Clone()
	c.Config.Central.Instance = "network-collector"
	c.Config.Collector.Shards, c.Config.Collector.Concurrency, c.Config.Collector.IntervalSeconds = 256, 2, 3600
	policy := &nodeCertificatePolicy{trust: trust, node: n.ID}
	policy.wrapTLS(tlsConfig)
	conn, err := grpc.NewClient(n.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithUnaryInterceptor(policy.invoke))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := agentv1.NewAgentServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := source.RecordMetrics(ctx, time.Now(), healthyDeploymentMetrics(t, n.Config, time.Now())); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO events VALUES(?,?,?,NULL)", "network-event", string(eventFixture("network-event", "modify").Json), float64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	// Run the actual collector loop with a one-hour interval. The active
	// deployment must wake its assigned node without waiting for startup jitter.
	runCtx, stopRun := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- c.Run(runCtx) }()
	defer func() { stopRun(); <-done }()
	for {
		var confirmed bool
		if err := db.QueryRowContext(ctx, "SELECT accepted IS NOT NULL FROM events WHERE id='network-event'").Scan(&confirmed); err != nil {
			t.Fatal(err)
		}
		if confirmed && tableCount(t, s, "v3_node_readiness") == 2 {
			break
		}
		if !waitRetry(ctx, 10*time.Millisecond) {
			t.Fatal("event transport did not confirm", ctx.Err())
		}
	}
	// Establish an independent connection for the existing-connection CRL
	// check below; it must acknowledge the same desired runtime configuration.
	if err := c.observeRuntime(ctx, n, l, client); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal("real collector evidence did not complete verification", err)
	}
	j = reloadDeployment(t, s, j.ID)
	// A revoked node on the same established HTTP/2 connection cannot refresh
	// its runtime evidence, and the next failure invalidates prior metrics proof.
	revoked, err := authority.Revoke(crl, [][]byte{node.Certificate}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crl"), revoked, 0600); err != nil {
		t.Fatal(err)
	}
	if !waitRetry(ctx, 1100*time.Millisecond) {
		t.Fatal(ctx.Err())
	}
	if err := c.observeRuntime(ctx, n, l, client); err == nil {
		t.Fatal("revoked node refreshed readiness")
	}
	c.failure(ctx, n, l, "metrics", "证书已失效")
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM v3_node_readiness WHERE kind='metrics'").Scan(&count); err != nil || count != 0 {
		t.Fatal("revoked peer retained metrics proof", count, err)
	}
	if err := s.CompleteDeploymentPhase(ctx, j); !errors.Is(err, ErrDeploymentNotReady) {
		t.Fatal("revoked transport completed finalization", err)
	}
}
