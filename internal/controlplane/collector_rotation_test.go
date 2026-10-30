package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"webscan/internal/nodepki"
	"webscan/internal/pull"
	agentv1 "webscan/sdk/agent/v1"
)

// Real PG leases, SQLite receipts and gRPC transport. The collector Run and
// node listener stay alive through both local and remote leaf replacement.
func TestCollectorReconnectsRotatedIdentitiesWithoutProcessRestart(t *testing.T) {
	s := testStore(t)
	dir := privateTestDir(t)
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := authority.Export()
	node, _ := authority.Issue(nodepki.Node, "node-a", []string{"agent.test"}, now, time.Hour)
	collector, _ := authority.Issue(nodepki.Collector, "collector-a", nil, now, time.Hour)
	crl, _ := authority.Revoke(nil, nil, now, time.Hour)
	caFile := filepath.Join(dir, "ca.crt")
	crlFile := filepath.Join(dir, "ca.crl")
	nodeFile := filepath.Join(dir, "node.pem")
	collectorFile := filepath.Join(dir, "collector.pem")
	for path, raw := range map[string][]byte{caFile: ca.CA, crlFile: crl} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	initialNode, err := nodepki.PublishIdentity(context.Background(), caFile, nodeFile, nodepki.Node, "node-a", "", node, now)
	if err != nil {
		t.Fatal(err)
	}
	initialCollector, err := nodepki.PublishIdentity(context.Background(), caFile, collectorFile, nodepki.Collector, "collector-a", "", collector, now)
	if err != nil {
		t.Fatal(err)
	}
	liveNode, err := nodepki.NewLiveIdentity(caFile, nodeFile, nodepki.Node, "node-a", now)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "node.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT NOT NULL,created REAL NOT NULL,accepted REAL)`); err != nil {
		t.Fatal(err)
	}
	source, err := pull.New(db, "node-a", "v3.0.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := nodepki.NewReceiverTrust(caFile, crlFile, filepath.Join(dir, "remote-trust"), now)
	if err != nil {
		t.Fatal(err)
	}
	var remoteSHA atomic.Value
	remoteSHA.Store("")
	g := pull.NewServerWithTrustUpdater(source, []string{"spiffe://webscan/collector/collector-a"}, func(ctx context.Context, cert *x509.Certificate, raw []byte) (*agentv1.UpdateTrustResponse, error) {
		r, err := trust.Publish(ctx, cert, raw, time.Now())
		if err != nil {
			return nil, err
		}
		remoteSHA.Store(r.SHA256)
		return &agentv1.UpdateTrustResponse{NodeId: "node-a", CrlSha256: r.SHA256, CrlNumber: r.Number, NextUpdateUnix: r.NextUpdate.Unix()}, nil
	}, func(cert *x509.Certificate) error {
		return trust.Verify(cert, nodepki.Collector, "collector-a", time.Now())
	})
	defer g.Stop()
	var clientSerial, serverSerial atomic.Value
	clientSerial.Store("")
	serverSerial.Store("")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientSerial.Store(r.TLS.PeerCertificates[0].SerialNumber.Text(16))
		}
		g.ServeHTTP(w, r)
	})
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CA)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		pair, err := liveNode.GetCertificate(info)
		if err == nil {
			serverSerial.Store(pair.Leaf.SerialNumber.Text(16))
		}
		return pair, err
	}}
	server.StartTLS()
	defer server.Close()
	n := nodeFixture("node-a")
	n.Endpoint = server.Listener.Addr().String()
	n.ServerName = "agent.test"
	if err := s.PutNode(context.Background(), n, 0, 256); err != nil {
		t.Fatal(err)
	}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer sink.Close()
	c := &Collector{Store: s, Metrics: &Metrics{WriteURL: sink.URL, HTTP: sink.Client()}}
	c.Config.Central.Instance = "rotation-collector-process"
	c.Config.Collector.CAFile = caFile
	c.Config.Collector.IdentityFile = collectorFile
	c.Config.Collector.RevocationFile = crlFile
	c.Config.Collector.Shards = 256
	c.Config.Collector.Concurrency = 2
	c.Config.Collector.IntervalSeconds = 3600
	ctx, stop := context.WithTimeout(context.Background(), 55*time.Second)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() {
		stop()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("collector did not drain cancelled runs")
		}
	}()
	wait := func(label string, f func() bool) {
		t.Helper()
		for !f() {
			select {
			case err := <-done:
				done <- err
				t.Fatal("collector exited", label, err)
			case <-ctx.Done():
				t.Fatal("timeout", label)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	insert := func(id string) {
		t.Helper()
		if _, err := db.Exec("INSERT INTO events VALUES(?,?,?,NULL)", id, string(eventFixture(id, "modify").Json), float64(time.Now().Unix())); err != nil {
			t.Fatal(err)
		}
	}
	confirmed := func(id string) bool {
		var b bool
		err := db.QueryRowContext(ctx, "SELECT accepted IS NOT NULL FROM events WHERE id=?", id).Scan(&b)
		return err == nil && b
	}
	insert("rotation-first")
	wait("first receipt", func() bool { return confirmed("rotation-first") })
	if clientSerial.Load().(string) != initialCollector.Serial {
		t.Fatal("initial client")
	}
	nextCollector, _ := authority.Issue(nodepki.Collector, "collector-a", nil, now, 2*time.Hour)
	next, err := nodepki.PublishIdentity(ctx, caFile, collectorFile, nodepki.Collector, "collector-a", initialCollector.CertificateSHA256, nextCollector, now)
	if err != nil {
		t.Fatal(err)
	}
	// New local key must drain the established HTTP/2 connection. Merely
	// configuring GetClientCertificate would leave the old connection alive.
	wait("client rotation reconnect", func() bool { return clientSerial.Load().(string) == next.Serial })
	insert("rotation-client")
	wait("rotated client receipt", func() bool { return confirmed("rotation-client") })
	nextNode, _ := authority.Issue(nodepki.Node, "node-a", []string{"agent.test"}, now, 2*time.Hour)
	nextServer, err := nodepki.PublishIdentity(ctx, caFile, nodeFile, nodepki.Node, "node-a", initialNode.CertificateSHA256, nextNode, now)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := authority.Revoke(crl, [][]byte{node.Certificate}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "next.crl")
	if err := os.WriteFile(tmp, revoked, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, crlFile); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	// Wake the existing long poll. Its old peer must be rejected after return;
	// the scheduler must reap it, reconnect, reread, and then confirm once.
	insert("rotation-remote")
	wait("remote rotation receipt", func() bool { return serverSerial.Load().(string) == nextServer.Serial && confirmed("rotation-remote") })
	wait("signed CRL was not automatically distributed", func() bool { return remoteSHA.Load().(string) == digest(revoked) })
	var count int
	if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM v3_events WHERE id IN ('rotation-first','rotation-client','rotation-remote')").Scan(&count); err != nil || count != 3 {
		t.Fatal("events lost or duplicated", count, err)
	}
}
