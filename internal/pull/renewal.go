package pull

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	agentv1 "webscan/sdk/agent/v1"
)

const MaxRenewalRequestBytes = 64 << 10
const MaxRenewalCertificateBytes = 16 << 10

type IdentityStatus struct {
	SHA256    string
	ExpiresAt time.Time
}

// Implementations keep pending private keys and the monotonic revocation
// policy on the node. These methods never accept paths, roles or SANs.
type IdentityRenewer interface {
	Status(context.Context) (IdentityStatus, error)
	Prepare(context.Context, string) ([]byte, error)
	Activate(context.Context, string, string, []byte) (IdentityStatus, error)
}

func validFingerprint(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == s
}

func (s *Server) PrepareIdentityRenewal(ctx context.Context, r *agentv1.PrepareIdentityRenewalRequest) (*agentv1.PreparedIdentityRenewal, error) {
	if s.IdentityRenewer == nil {
		return nil, status.Error(codes.Unimplemented, "此子控未启用活动身份证书续期")
	}
	if r == nil || r.NodeId != s.Source.NodeID || !validFingerprint(r.CertificateSha256) {
		return nil, status.Error(codes.InvalidArgument, "节点或原证书摘要不正确")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := s.IdentityRenewer.Prepare(ctx, r.CertificateSha256)
	if err != nil || len(raw) == 0 || len(raw) > MaxRenewalRequestBytes {
		return nil, status.Error(codes.FailedPrecondition, "证书续期请求校验或持久化失败，原身份保留")
	}
	sum := sha256.Sum256(raw)
	return &agentv1.PreparedIdentityRenewal{NodeId: s.Source.NodeID, CertificateSha256: r.CertificateSha256, RequestSha256: hex.EncodeToString(sum[:]), PublicRequestJson: raw}, nil
}

func (s *Server) ActivateIdentityRenewal(ctx context.Context, r *agentv1.ActivateIdentityRenewalRequest) (*agentv1.ActivatedIdentityRenewal, error) {
	if s.IdentityRenewer == nil {
		return nil, status.Error(codes.Unimplemented, "此子控未启用活动身份证书续期")
	}
	if r == nil || r.NodeId != s.Source.NodeID || !validFingerprint(r.PreviousCertificateSha256) || !validFingerprint(r.RequestSha256) || len(r.Certificate) == 0 || len(r.Certificate) > MaxRenewalCertificateBytes {
		return nil, status.Error(codes.InvalidArgument, "节点、续期摘要或公开证书参数不正确")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	current, err := s.IdentityRenewer.Activate(ctx, r.PreviousCertificateSha256, r.RequestSha256, r.Certificate)
	if err != nil || !validFingerprint(current.SHA256) || current.ExpiresAt.IsZero() {
		return nil, status.Error(codes.FailedPrecondition, "证书续期激活或持久化失败，请核对原身份与吊销规则")
	}
	return &agentv1.ActivatedIdentityRenewal{NodeId: s.Source.NodeID, RequestSha256: r.RequestSha256, CertificateSha256: current.SHA256, CertificateNotAfterUnix: current.ExpiresAt.Unix()}, nil
}
