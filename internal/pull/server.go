package pull

import (
	"context"
	"crypto/x509"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	agentv1 "webscan/sdk/agent/v1"
)

type Server struct {
	agentv1.UnimplementedAgentServiceServer
	Source          *Source
	TrustUpdater    TrustUpdater
	IdentityRenewer IdentityRenewer
}

// TrustUpdater must validate the complete pinned-CA snapshot, the collector
// against that snapshot, and its durable floor before committing anything.
type TrustUpdater func(context.Context, *x509.Certificate, []byte) (*agentv1.UpdateTrustResponse, error)

// Optional policy rechecks certificate lifecycle state on each RPC, including
// an existing connection. A policy failure never falls back to CN matching.
func NewServer(source *Source, identities []string, policies ...func(*x509.Certificate) error) *grpc.Server {
	return NewServerWithTrustUpdater(source, identities, nil, policies...)
}

func NewServerWithTrustUpdater(source *Source, identities []string, updater TrustUpdater, policies ...func(*x509.Certificate) error) *grpc.Server {
	return NewServerWithManagedIdentity(source, identities, updater, nil, policies...)
}

func NewServerWithManagedIdentity(source *Source, identities []string, updater TrustUpdater, renewer IdentityRenewer, policies ...func(*x509.Certificate) error) *grpc.Server {
	allowed := map[string]bool{}
	for _, v := range identities {
		if v != "" {
			allowed[v] = true
		}
	}
	g := grpc.NewServer(grpc.MaxRecvMsgSize(MaxBytes), grpc.MaxSendMsgSize(MaxBytes), grpc.UnaryInterceptor(func(ctx context.Context, r any, i *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "需要采集器证书")
		}
		auth, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok || len(auth.State.VerifiedChains) == 0 || len(auth.State.PeerCertificates) == 0 {
			return nil, status.Error(codes.Unauthenticated, "需要有效双向 TLS")
		}
		cert := auth.State.PeerCertificates[0]
		valid := allowed[cert.Subject.CommonName]
		for _, u := range cert.URIs {
			if strings.HasPrefix(u.String(), "spiffe://webscan/collector/") && allowed[u.String()] {
				valid = true
			}
		}
		if !valid {
			return nil, status.Error(codes.PermissionDenied, "证书不具有采集权限")
		}
		// Only the bounded update method may recover an expired CRL. Its
		// updater independently authenticates the same peer using the proposed
		// signed snapshot and the durable floor; ordinary RPCs remain closed.
		if i.FullMethod == agentv1.AgentService_UpdateTrust_FullMethodName && updater != nil {
			return next(ctx, r)
		}
		check := func() error {
			if (updater != nil || renewer != nil) && len(policies) == 0 {
				return status.Error(codes.PermissionDenied, "子控缺少普通采集的吊销校验规则")
			}
			for _, policy := range policies {
				if policy == nil || policy(cert) != nil {
					return status.Error(codes.PermissionDenied, "采集器证书已失效或吊销状态不可用")
				}
			}
			return nil
		}
		if err := check(); err != nil {
			return nil, err
		}
		result, err := next(ctx, r)
		if err == nil {
			err = check() // a long poll must not return data to a now-revoked peer
		}
		if err != nil {
			return nil, err
		}
		return result, nil
	}))
	agentv1.RegisterAgentServiceServer(g, &Server{Source: source, TrustUpdater: updater, IdentityRenewer: renewer})
	return g
}

func (s *Server) UpdateTrust(ctx context.Context, r *agentv1.UpdateTrustRequest) (*agentv1.UpdateTrustResponse, error) {
	if s.TrustUpdater == nil {
		return nil, status.Error(codes.Unimplemented, "此子控未启用吊销列表自动接收")
	}
	if r == nil || r.NodeId != s.Source.NodeID || len(r.Crl) == 0 || len(r.Crl) > agentv1.MaxTrustBytes {
		return nil, status.Error(codes.InvalidArgument, "节点或吊销列表参数不正确")
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "需要采集器证书")
	}
	auth, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(auth.State.VerifiedChains) == 0 || len(auth.State.PeerCertificates) == 0 {
		return nil, status.Error(codes.Unauthenticated, "需要有效双向 TLS")
	}
	result, err := s.TrustUpdater(ctx, auth.State.PeerCertificates[0], r.Crl)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "吊销列表校验或持久化失败，原身份和配置保留")
	}
	return result, nil
}
func (s *Server) Capabilities(ctx context.Context, _ *agentv1.CapabilitiesRequest) (*agentv1.CapabilitiesResponse, error) {
	result := s.Source.Capabilities()
	if s.IdentityRenewer != nil {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		current, err := s.IdentityRenewer.Status(ctx)
		if err != nil || !validFingerprint(current.SHA256) || current.ExpiresAt.IsZero() {
			return nil, status.Error(codes.FailedPrecondition, "活动身份证书或吊销规则不可用")
		}
		result.IdentityRenewal = true
		result.CertificateSha256 = current.SHA256
		result.CertificateNotAfterUnix = current.ExpiresAt.Unix()
	}
	return result, nil
}
func (s *Server) FetchEvents(ctx context.Context, r *agentv1.FetchEventsRequest) (*agentv1.EventBatch, error) {
	b, e := s.Source.Fetch(ctx, r.Epoch, int(r.Limit), time.Duration(r.WaitSeconds)*time.Second)
	if e != nil {
		return nil, status.Error(codes.FailedPrecondition, "事件读取失败，请检查参数、代次和本地队列")
	}
	return b, nil
}
func (s *Server) AckEvents(ctx context.Context, r *agentv1.AckEventsRequest) (*agentv1.AckEventsResponse, error) {
	n, e := s.Source.Ack(ctx, r)
	if e != nil {
		return nil, status.Error(codes.FailedPrecondition, "事件确认失败，请重新读取或检查采集代次")
	}
	return &agentv1.AckEventsResponse{Confirmed: n}, nil
}
func (s *Server) ReadMetrics(ctx context.Context, r *agentv1.ReadMetricsRequest) (*agentv1.MetricsBatch, error) {
	b, e := s.Source.Metrics(ctx, r.AfterUnixMillis)
	if e != nil {
		return nil, status.Error(codes.Unavailable, "指标暂时不可用")
	}
	return b, nil
}
