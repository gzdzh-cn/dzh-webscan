package pull

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

func TestRevokedCollectorCannotReuseExistingHTTP2Connection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := authority.Export()
	serverBundle, err := authority.Issue(nodepki.Node, "node-a", []string{"agent.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientBundle, err := authority.Issue(nodepki.Collector, "collector-a", nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := authority.Issue(nodepki.Collector, "collector-a", nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := authority.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := nodepki.NewTrust(ca.CA, crl, now)
	if err != nil {
		t.Fatal(err)
	}
	policy := func(cert *x509.Certificate) error {
		id, err := nodepki.PeerID(cert, nodepki.Collector)
		if err != nil {
			return err
		}
		return trust.Verify(cert, nodepki.Collector, id, time.Now())
	}
	source := testSource(t)
	g := NewServer(source, []string{"spiffe://webscan/collector/collector-a"}, policy)
	defer g.Stop()
	pair, err := tls.X509KeyPair(serverBundle.Certificate, serverBundle.Key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CA)
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	defer server.Close()
	connect := func(bundle nodepki.Bundle) (*grpc.ClientConn, agentv1.AgentServiceClient) {
		t.Helper()
		pair, err := tls.X509KeyPair(bundle.Certificate, bundle.Key)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := grpc.NewClient(server.Listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "agent.test", Certificates: []tls.Certificate{pair}})))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn, agentv1.NewAgentServiceClient(conn)
	}
	_, client := connect(clientBundle)
	call := func(client agentv1.AgentServiceClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{})
		return err
	}
	if err := call(client); err != nil {
		t.Fatal("initial connection rejected", err)
	}
	revoked, err := authority.Revoke(crl, [][]byte{clientBundle.Certificate}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.UpdateCRL(revoked, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := call(client); status.Code(err) != codes.PermissionDenied {
		t.Fatal("revoked existing connection accepted", err)
	}
	_, fresh := connect(rotated)
	if err := call(fresh); err != nil {
		t.Fatal("new certificate for the same identity rejected", err)
	}
	if err := call(client); status.Code(err) != codes.PermissionDenied {
		t.Fatal("rotation reauthorized old certificate", err)
	}
}
