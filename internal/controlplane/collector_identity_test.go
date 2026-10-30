package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"webscan/internal/nodepki"
)

func TestCollectorChecksNodeIdentityBeforeACKAndAfterLongPoll(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := authority.Export()
	bundle, err := authority.Issue(nodepki.Node, "node-a", []string{"agent.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(bundle.Certificate, bundle.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
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
	policy := &nodeCertificatePolicy{trust: trust, node: "node-a"}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	policy.wrapTLS(config)
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	calls := 0
	setPeer := func(options []grpc.CallOption) {
		for _, option := range options {
			if p, ok := option.(grpc.PeerCallOption); ok {
				p.PeerAddr.AuthInfo = credentials.TLSInfo{State: state}
			}
		}
	}
	invoke := func(_ context.Context, _ string, _ any, _ any, _ *grpc.ClientConn, options ...grpc.CallOption) error {
		calls++
		setPeer(options)
		return config.VerifyConnection(state)
	}
	if err := policy.invoke(context.Background(), "ReadMetrics", nil, nil, nil, invoke); err != nil || calls != 1 {
		t.Fatal("initial request", err, calls)
	}
	wrong := &nodeCertificatePolicy{trust: trust, node: "node-b"}
	wrongTLS := &tls.Config{}
	wrong.wrapTLS(wrongTLS)
	if err := wrongTLS.VerifyConnection(state); err == nil {
		t.Fatal("certificate for another node accepted")
	}
	// A peer revoked while a long poll is in progress cannot commit its response.
	duringPoll := func(_ context.Context, _ string, _ any, _ any, _ *grpc.ClientConn, options ...grpc.CallOption) error {
		setPeer(options)
		revoked, err := authority.Revoke(crl, [][]byte{bundle.Certificate}, now, time.Hour)
		if err != nil {
			return err
		}
		return trust.UpdateCRL(revoked, time.Now())
	}
	if err := policy.invoke(context.Background(), "FetchEvents", nil, nil, nil, duringPoll); status.Code(err) != codes.Unauthenticated {
		t.Fatal("revoked long poll accepted", err)
	}
	if err := policy.invoke(context.Background(), "AckEvents", nil, nil, nil, invoke); status.Code(err) != codes.Unauthenticated || calls != 1 {
		t.Fatal("ACK sent to revoked node", err, calls)
	}
}

func TestCollectorBindsAuthorizationToActualRPCTransport(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := authority.Export()
	old, _ := authority.Issue(nodepki.Node, "node-a", []string{"agent.test"}, now, time.Hour)
	fresh, _ := authority.Issue(nodepki.Node, "node-a", []string{"agent.test"}, now, 2*time.Hour)
	parse := func(b nodepki.Bundle) *x509.Certificate {
		pair, err := tls.X509KeyPair(b.Certificate, b.Key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf
	}
	oldCert, freshCert := parse(old), parse(fresh)
	crl, err := authority.Revoke(nil, [][]byte{old.Certificate}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := nodepki.NewTrust(ca.CA, crl, now)
	if err != nil {
		t.Fatal(err)
	}
	cancelled := false
	p := &nodeCertificatePolicy{trust: trust, node: "node-a", onInvalid: func() { cancelled = true }}
	p.certificate.Store(freshCert)
	state := func(cert *x509.Certificate) credentials.TLSInfo {
		return credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}, PeerCertificates: []*x509.Certificate{cert}}}
	}
	// A new valid handshake must not authorize a still-running response on the
	// retired old transport. Check its actual peer, not the last cached peer.
	invokeOld := func(_ context.Context, _ string, _ any, _ any, _ *grpc.ClientConn, options ...grpc.CallOption) error {
		for _, o := range options {
			if o, ok := o.(grpc.PeerCallOption); ok {
				o.PeerAddr.AuthInfo = state(oldCert)
			}
		}
		return nil
	}
	if err := p.invoke(context.Background(), "FetchEvents", nil, nil, nil, invokeOld); status.Code(err) != codes.Unauthenticated || !cancelled {
		t.Fatal("old response used fresh peer identity", err)
	}
	cancelled = false
	oldContext := credentials.NewContextWithRequestInfo(context.Background(), credentials.RequestInfo{AuthInfo: state(oldCert)})
	if _, err := p.GetRequestMetadata(oldContext); status.Code(err) != codes.Unauthenticated || !cancelled {
		t.Fatal("old transport authorized request", err)
	}
	freshContext := credentials.NewContextWithRequestInfo(context.Background(), credentials.RequestInfo{AuthInfo: state(freshCert)})
	if _, err := p.GetRequestMetadata(freshContext); err != nil || !p.RequireTransportSecurity() {
		t.Fatal("valid transport rejected", err)
	}
	if _, err := p.GetRequestMetadata(context.Background()); err == nil {
		t.Fatal("missing transport accepted")
	}
}
