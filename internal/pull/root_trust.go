package pull

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	agentv1 "webscan/sdk/agent/v1"
)

const MaxRootTrustBytes = 1 << 20

func (s *Server) RefreshRootTrust(ctx context.Context, r *agentv1.RefreshRootTrustRequest) (*agentv1.RefreshRootTrustResponse, error) {
	if s.RootTrustRefresher == nil {
		return nil, status.Error(codes.Unimplemented, "此子控未启用换根后的吊销资料刷新")
	}
	if r == nil || s.Source == nil || r.NodeId != s.Source.NodeID || len(r.SnapshotJson) == 0 || len(r.SnapshotJson) > MaxRootTrustBytes {
		return nil, status.Error(codes.InvalidArgument, "节点或信任快照参数不正确")
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "需要采集器证书")
	}
	auth, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(auth.State.VerifiedChains) == 0 || len(auth.State.PeerCertificates) == 0 {
		return nil, status.Error(codes.Unauthenticated, "需要有效双向 TLS")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, err := s.RootTrustRefresher(ctx, auth.State.PeerCertificates[0], r.SnapshotJson)
	if err != nil || result == nil || result.NodeId != s.Source.NodeID || !validFingerprint(result.SnapshotSha256) || !validFingerprint(result.Rotation) || (result.Phase != "dual" && result.Phase != "new-only") {
		return nil, status.Error(codes.FailedPrecondition, "信任资料刷新或持久化失败；不会开始或结束 CA 换根")
	}
	return result, nil
}
