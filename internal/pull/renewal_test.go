package pull

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

type renewalTestHandler struct {
	failed                     atomic.Bool
	reads, prepares, activates atomic.Int64
}

func (r *renewalTestHandler) Status(context.Context) (IdentityStatus, error) {
	r.reads.Add(1)
	if r.failed.Load() {
		return IdentityStatus{}, errors.New("private-path-must-not-leak")
	}
	return IdentityStatus{SHA256: strings.Repeat("a", 64), ExpiresAt: time.Unix(2000000000, 0)}, nil
}
func (r *renewalTestHandler) Prepare(ctx context.Context, expected string) ([]byte, error) {
	r.prepares.Add(1)
	if r.failed.Load() {
		return nil, errors.New("private-path-must-not-leak")
	}
	if expected != strings.Repeat("a", 64) {
		return nil, errors.New("stale")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("unbounded RPC")
	}
	return []byte("public-only-csr"), nil
}
func (r *renewalTestHandler) Activate(ctx context.Context, previous, request string, certificate []byte) (IdentityStatus, error) {
	r.activates.Add(1)
	if r.failed.Load() {
		return IdentityStatus{}, errors.New("private-path-must-not-leak")
	}
	if previous != strings.Repeat("a", 64) || request != strings.Repeat("b", 64) || !bytes.Equal(certificate, []byte("public-only-certificate")) {
		return IdentityStatus{}, errors.New("binding mismatch")
	}
	if _, ok := ctx.Deadline(); !ok {
		return IdentityStatus{}, errors.New("unbounded RPC")
	}
	return IdentityStatus{SHA256: strings.Repeat("c", 64), ExpiresAt: time.Unix(2000000001, 0)}, nil
}

func TestIdentityRenewalRPCRequiresAuthorizedCurrentCollector(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := a.Export()
	defer clear(root.Key)
	serverLeaf, _ := a.Issue(nodepki.Node, "node-a", []string{"agent.test"}, now, time.Hour)
	defer clear(serverLeaf.Key)
	collector, _ := a.Issue(nodepki.Collector, "one", nil, now, time.Hour)
	defer clear(collector.Key)
	outsider, _ := a.Issue(nodepki.Collector, "stranger", nil, now, time.Hour)
	defer clear(outsider.Key)
	crl, _ := a.Revoke(nil, nil, now, time.Hour)
	trust, err := nodepki.NewTrust(root.CA, crl, now)
	if err != nil {
		t.Fatal(err)
	}
	renewer := &renewalTestHandler{}
	g := NewServerWithManagedIdentity(testSource(t), []string{"spiffe://webscan/collector/one"}, nil, renewer, func(cert *x509.Certificate) error {
		id, err := nodepki.PeerID(cert, nodepki.Collector)
		if err != nil {
			return err
		}
		return trust.Verify(cert, nodepki.Collector, id, time.Now())
	})
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	serverPair, _ := tls.X509KeyPair(serverLeaf.Certificate, serverLeaf.Key)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(root.CA)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{serverPair}}
	server.StartTLS()
	defer func() { server.CloseClientConnections(); g.Stop(); server.Close() }()
	connect := func(server *httptest.Server, b nodepki.Bundle) agentv1.AgentServiceClient {
		t.Helper()
		pair, _ := tls.X509KeyPair(b.Certificate, b.Key)
		conn, err := grpc.NewClient(server.Listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "agent.test", Certificates: []tls.Certificate{pair}})))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return agentv1.NewAgentServiceClient(conn)
	}
	client, stranger := connect(server, collector), connect(server, outsider)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	prepare := &agentv1.PrepareIdentityRenewalRequest{NodeId: "node-a", CertificateSha256: strings.Repeat("a", 64)}
	activate := &agentv1.ActivateIdentityRenewalRequest{NodeId: "node-a", PreviousCertificateSha256: strings.Repeat("a", 64), RequestSha256: strings.Repeat("b", 64), Certificate: []byte("public-only-certificate")}
	// Possessing a listed mTLS identity is insufficient if the operator forgot
	// the mandatory current revocation policy for these mutating RPCs.
	withoutPolicy := NewServerWithManagedIdentity(testSource(t), []string{"spiffe://webscan/collector/one"}, nil, renewer)
	unsafeServer := httptest.NewUnstartedServer(withoutPolicy)
	unsafeServer.EnableHTTP2, unsafeServer.TLS = true, server.TLS.Clone()
	unsafeServer.StartTLS()
	defer func() { unsafeServer.CloseClientConnections(); withoutPolicy.Stop(); unsafeServer.Close() }()
	unsafeClient := connect(unsafeServer, collector)
	if _, err := unsafeClient.PrepareIdentityRenewal(ctx, prepare); status.Code(err) != codes.PermissionDenied || renewer.prepares.Load() != 0 {
		t.Fatal("missing revocation policy allowed private-key preparation", err)
	}
	if _, err := stranger.PrepareIdentityRenewal(ctx, prepare); status.Code(err) != codes.PermissionDenied || renewer.prepares.Load() != 0 {
		t.Fatal("unlisted peer prepared local key", err)
	}
	if _, err := stranger.ActivateIdentityRenewal(ctx, activate); status.Code(err) != codes.PermissionDenied || renewer.activates.Load() != 0 {
		t.Fatal("unlisted peer activated certificate", err)
	}
	capability, err := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{})
	if err != nil || !capability.IdentityRenewal || capability.CertificateSha256 != prepare.CertificateSha256 || capability.CertificateNotAfterUnix != 2000000000 {
		t.Fatal("managed capability missing", capability, err)
	}
	prepared, err := client.PrepareIdentityRenewal(ctx, prepare)
	if err != nil || prepared.NodeId != "node-a" || prepared.CertificateSha256 != prepare.CertificateSha256 || !validFingerprint(prepared.RequestSha256) || !bytes.Equal(prepared.PublicRequestJson, []byte("public-only-csr")) {
		t.Fatal("public request reply invalid", prepared, err)
	}
	applied, err := client.ActivateIdentityRenewal(ctx, activate)
	if err != nil || applied.NodeId != "node-a" || applied.RequestSha256 != activate.RequestSha256 || applied.CertificateSha256 != strings.Repeat("c", 64) || applied.CertificateNotAfterUnix != 2000000001 {
		t.Fatal("activation receipt invalid", applied, err)
	}
	renewer.failed.Store(true)
	for _, call := range []func() error{
		func() error { _, err := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{}); return err },
		func() error { _, err := client.PrepareIdentityRenewal(ctx, prepare); return err },
		func() error { _, err := client.ActivateIdentityRenewal(ctx, activate); return err },
	} {
		err := call()
		if status.Code(err) != codes.FailedPrecondition || strings.Contains(err.Error(), "private-path") {
			t.Fatal("failed state was masked or leaked", err)
		}
	}
	renewer.failed.Store(false)
	nextCRL, _ := a.Revoke(crl, [][]byte{collector.Certificate}, now, time.Hour)
	if err := trust.UpdateCRL(nextCRL, now); err != nil {
		t.Fatal(err)
	}
	previousReads, previousPrepares, previousActivates := renewer.reads.Load(), renewer.prepares.Load(), renewer.activates.Load()
	for _, call := range []func() error{
		func() error { _, err := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{}); return err },
		func() error { _, err := client.PrepareIdentityRenewal(ctx, prepare); return err },
		func() error { _, err := client.ActivateIdentityRenewal(ctx, activate); return err },
	} {
		if err := call(); status.Code(err) != codes.PermissionDenied {
			t.Fatal("revoked established connection reached renewal handler", err)
		}
	}
	if renewer.reads.Load() != previousReads || renewer.prepares.Load() != previousPrepares || renewer.activates.Load() != previousActivates {
		t.Fatal("revoked connection mutated identity")
	}
}

func TestIdentityRenewalRPCBoundsAndDisabledCompatibility(t *testing.T) {
	s := &Server{Source: testSource(t)}
	if _, err := s.PrepareIdentityRenewal(context.Background(), nil); status.Code(err) != codes.Unimplemented {
		t.Fatal(err)
	}
	if _, err := s.ActivateIdentityRenewal(context.Background(), nil); status.Code(err) != codes.Unimplemented {
		t.Fatal(err)
	}
	capability, err := s.Capabilities(context.Background(), &agentv1.CapabilitiesRequest{})
	if err != nil || capability.IdentityRenewal || capability.CertificateSha256 != "" || capability.CertificateNotAfterUnix != 0 {
		t.Fatal("legacy server invented certificate evidence", err)
	}
	handler := &renewalTestHandler{}
	s.IdentityRenewer = handler
	for _, request := range []*agentv1.PrepareIdentityRenewalRequest{nil, {NodeId: "other", CertificateSha256: strings.Repeat("a", 64)}, {NodeId: "node-a", CertificateSha256: strings.Repeat("A", 64)}, {NodeId: "node-a"}} {
		if _, err := s.PrepareIdentityRenewal(context.Background(), request); status.Code(err) != codes.InvalidArgument {
			t.Fatal("invalid preparation reached local state", err)
		}
	}
	for _, request := range []*agentv1.ActivateIdentityRenewalRequest{nil, {NodeId: "other"}, {NodeId: "node-a", PreviousCertificateSha256: strings.Repeat("a", 64), RequestSha256: strings.Repeat("b", 64), Certificate: bytes.Repeat([]byte{1}, MaxRenewalCertificateBytes+1)}} {
		if _, err := s.ActivateIdentityRenewal(context.Background(), request); status.Code(err) != codes.InvalidArgument {
			t.Fatal("invalid activation reached local state", err)
		}
	}
	if handler.prepares.Load() != 0 || handler.activates.Load() != 0 {
		t.Fatal("invalid arguments mutated state")
	}
}
