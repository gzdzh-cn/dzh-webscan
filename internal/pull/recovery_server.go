package pull

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	agentv1 "webscan/sdk/agent/v1"
)

// Authorization and revocation remain in the existing mTLS interceptor. These
// methods receive only a fixed node identity and an opaque bounded cursor.
func (s *Server) RecoveryState(ctx context.Context, r *agentv1.RecoveryStateRequest) (*agentv1.RecoveryStateResponse, error) {
	if r == nil || r.NodeId != s.Source.NodeID {
		return nil, status.Error(codes.InvalidArgument, "恢复节点身份不匹配")
	}
	result, err := s.Source.RecoveryState(ctx, r.NodeId)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "只读恢复状态不可用；未修改事件队列和采集代次")
	}
	return result, nil
}
func (s *Server) ReadRecoveryEvents(ctx context.Context, r *agentv1.ReadRecoveryEventsRequest) (*agentv1.RecoveryEventsBatch, error) {
	if r == nil || r.NodeId != s.Source.NodeID || len(r.Cursor) > 2048 || r.Limit < 1 || r.Limit > MaxEvents {
		return nil, status.Error(codes.InvalidArgument, "恢复身份、游标或批次不正确")
	}
	result, err := s.Source.ReadRecoveryEvents(ctx, r.NodeId, r.Cursor, int(r.Limit))
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "恢复快照已变化或过期；请重新读取状态")
	}
	return result, nil
}
