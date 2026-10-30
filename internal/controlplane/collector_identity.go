package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"webscan/internal/nodepki"
)

type certificateTrust interface {
	Verify(*x509.Certificate, string, string, time.Time) error
}
type nodeCertificatePolicy struct {
	trust       certificateTrust
	node        string
	onInvalid   func()
	certificate atomic.Pointer[x509.Certificate]
}

func (p *nodeCertificatePolicy) wrapTLS(config *tls.Config) {
	previous := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if previous != nil {
			if err := previous(state); err != nil {
				return err
			}
		}
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return nodepki.ErrIdentity
		}
		cert := state.PeerCertificates[0]
		if err := p.trust.Verify(cert, nodepki.Node, p.node, time.Now()); err != nil {
			return err
		}
		p.certificate.Store(cert)
		return nil
	}
}
func (p *nodeCertificatePolicy) check() error {
	return p.checkCertificate(p.certificate.Load())
}
func (p *nodeCertificatePolicy) checkCertificate(cert *x509.Certificate) error {
	if cert == nil || p.trust.Verify(cert, nodepki.Node, p.node, time.Now()) != nil {
		if cert != nil && p.onInvalid != nil {
			p.onInvalid()
		}
		return status.Error(codes.Unauthenticated, "子控证书身份或吊销校验失败")
	}
	return nil
}

func (p *nodeCertificatePolicy) checkAuth(auth credentials.AuthInfo) error {
	tlsInfo, ok := auth.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.PeerCertificates) == 0 {
		return status.Error(codes.Unauthenticated, "子控连接缺少已验证的证书身份")
	}
	return p.checkCertificate(tlsInfo.State.PeerCertificates[0])
}

// Check the actual selected transport before gRPC writes headers/body. A
// node-wide cached certificate cannot authorize an ACK on another connection
// while HTTP/2 transports overlap during replacement.
func (p *nodeCertificatePolicy) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	info, ok := credentials.RequestInfoFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "缺少子控连接认证信息")
	}
	return nil, p.checkAuth(info.AuthInfo)
}
func (*nodeCertificatePolicy) RequireTransportSecurity() bool { return true }
func (p *nodeCertificatePolicy) invoke(ctx context.Context, method string, request, response any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, options ...grpc.CallOption) error {
	// New connections are checked by TLS before their first request. Subsequent
	// requests are checked before sending, so revoked nodes cannot receive ACKs.
	if p.certificate.Load() != nil {
		if err := p.check(); err != nil {
			return err
		}
	}
	var actual peer.Peer
	options = append(options, grpc.Peer(&actual))
	if err := invoker(ctx, method, request, response, cc, options...); err != nil {
		return err
	}
	// Recheck after a long poll: CRL expiry/revocation while waiting cannot let
	// unauthenticated events or metrics enter the database.
	return p.checkAuth(actual.AuthInfo)
}
