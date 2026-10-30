package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"webscan/internal/nodepki"
	"webscan/internal/pull"
	agentv1 "webscan/sdk/agent/v1"
)

type relayRPCRenewer struct{ client *renewalRelayClient }

func (r relayRPCRenewer) Status(ctx context.Context) (pull.IdentityStatus, error) {
	cap, err := r.client.Capabilities(ctx, &agentv1.CapabilitiesRequest{})
	if err != nil {
		return pull.IdentityStatus{}, err
	}
	return pull.IdentityStatus{SHA256: cap.CertificateSha256, ExpiresAt: time.Unix(cap.CertificateNotAfterUnix, 0)}, nil
}
func (r relayRPCRenewer) Prepare(ctx context.Context, expected string) ([]byte, error) {
	out, err := r.client.PrepareIdentityRenewal(ctx, &agentv1.PrepareIdentityRenewalRequest{NodeId: r.client.f.in.Request.Node, CertificateSha256: expected})
	if err != nil {
		return nil, err
	}
	return out.PublicRequestJson, nil
}
func (r relayRPCRenewer) Activate(ctx context.Context, expected, request string, cert []byte) (pull.IdentityStatus, error) {
	out, err := r.client.ActivateIdentityRenewal(ctx, &agentv1.ActivateIdentityRenewalRequest{NodeId: r.client.f.in.Request.Node, PreviousCertificateSha256: expected, RequestSha256: request, Certificate: cert})
	if err != nil {
		return pull.IdentityStatus{}, err
	}
	return pull.IdentityStatus{SHA256: out.CertificateSha256, ExpiresAt: time.Unix(out.CertificateNotAfterUnix, 0)}, nil
}

func TestNodeRenewalActualMTLSCollectorQueueHostAndActivation(t *testing.T) {
	f, n, l, _ := renewalRelayFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	trust, err := nodepki.NewTrust(f.node.CA, f.crl, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	collectorID := "renewal-collector"
	identity, err := f.ca.Issue(nodepki.Collector, collectorID, nil, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(identity.Key)
	db, err := sql.Open("sqlite", filepath.Join(privateTestDir(t), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT NOT NULL,created REAL NOT NULL,accepted REAL)`); err != nil {
		t.Fatal(err)
	}
	source, err := pull.New(db, n.ID, "v3.0.0-local-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	renewer := &renewalRelayClient{f: f}
	g := pull.NewServerWithManagedIdentity(source, []string{"spiffe://webscan/collector/" + collectorID}, nil, relayRPCRenewer{renewer}, func(cert *x509.Certificate) error {
		return trust.Verify(cert, nodepki.Collector, collectorID, time.Now())
	})
	defer g.Stop()
	live, err := nodepki.NewLiveIdentity(f.c.Collector.CAFile, f.identity, nodepki.Node, n.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(f.node.CA)
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	nodeTLS := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, GetCertificate: live.GetCertificate, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.TLS = nodeTLS.Clone()
	// httptest installs its localhost fallback certificate. Always select the
	// real managed configuration, including when an IP peer sends no SNI.
	server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return nodeTLS, nil }
	server.StartTLS()
	defer server.Close()
	pair, err := tls.X509KeyPair(identity.Certificate, identity.Key)
	if err != nil {
		t.Fatal(err)
	}
	newClient := func(expected string) (*grpc.ClientConn, agentv1.AgentServiceClient) {
		t.Helper()
		config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: n.ServerName, Certificates: []tls.Certificate{pair}}
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || digest(state.PeerCertificates[0].Raw) != expected {
				return nodepki.ErrIdentity
			}
			return trust.Verify(state.PeerCertificates[0], nodepki.Node, n.ID, time.Now())
		}
		conn, err := grpc.NewClient(server.Listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(config)))
		if err != nil {
			t.Fatal(err)
		}
		return conn, agentv1.NewAgentServiceClient(conn)
	}
	conn, client := newClient(f.in.Request.CertificateSHA256)
	defer conn.Close()
	collector := &Collector{Store: f.s}
	if rotated, err := collector.renewNodeIdentity(ctx, n, l, client); err != nil || rotated {
		t.Fatal("public network request not queued", err)
	}
	if err := f.s.Release(ctx, f.lease); err != nil {
		t.Fatal(err)
	}
	result, err := f.s.processNodeRenewalQueue(ctx, f.c, "network-host-issuer", 500)
	if err != nil || result.Signed != 1 {
		t.Fatal("isolated host signing failed", result, err)
	}
	if rotated, err := collector.renewNodeIdentity(ctx, n, l, client); err != nil || !rotated {
		t.Fatal("committed network certificate not activated", rotated, err)
	}
	var sha string
	if err := f.s.DB.QueryRow(`SELECT certificate_sha256 FROM v3_node_certificate_renewals`).Scan(&sha); err != nil {
		t.Fatal(err)
	}
	// LiveIdentity bounds disk reloads to one per second; the production
	// collector's reconciliation also closes and replaces the old transport.
	if !waitRetry(ctx, 1100*time.Millisecond) {
		t.Fatal(ctx.Err())
	}
	newConn, current := newClient(sha)
	defer newConn.Close()
	cap, err := current.Capabilities(ctx, &agentv1.CapabilitiesRequest{})
	if err != nil || cap.CertificateSha256 != sha || !cap.IdentityRenewal || renewer.activated != 1 {
		t.Fatal("same listener did not present new local-key identity", err)
	}
	if rotated, err := collector.renewNodeIdentity(ctx, n, l, current); err != nil || rotated {
		t.Fatal("new live identity caused repeated renewal/reconnect", err)
	}
}
