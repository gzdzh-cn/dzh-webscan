package controlplane

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

type rootRefreshClient struct {
	agentv1.AgentServiceClient
	call func(*agentv1.RefreshRootTrustRequest) (*agentv1.RefreshRootTrustResponse, error)
}

func (c rootRefreshClient) RefreshRootTrust(_ context.Context, r *agentv1.RefreshRootTrustRequest, _ ...grpc.CallOption) (*agentv1.RefreshRootTrustResponse, error) {
	return c.call(r)
}
func (c rootRefreshClient) UpdateTrust(context.Context, *agentv1.UpdateTrustRequest, ...grpc.CallOption) (*agentv1.UpdateTrustResponse, error) {
	panic("root-set mode must never fall back to legacy single-root CRL")
}

func collectorRootTrustFixture(t *testing.T) (*nodepki.FileTrust, nodepki.RootSetReceipt) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	old, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	next, err := nodepki.NewAuthority(now, 2*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := old.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(anchor.Key)
	oldCRL, err := old.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCRL, err := next.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dual, err := old.AuthorizeRootRotation(next, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	directory := privateTestDir(t)
	caFile, crlFile, state := filepath.Join(directory, "ca.crt"), filepath.Join(directory, "ca.crl"), filepath.Join(directory, "trust")
	localWrite(t, caFile, anchor.CA)
	localWrite(t, crlFile, oldCRL)
	if _, err := nodepki.NewPersistentFileTrust(caFile, crlFile, state, now); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(nodepki.RootSetSnapshot{Format: 1, Dual: dual, OldCRL: oldCRL, NewCRL: newCRL})
	receipt, err := nodepki.PublishRootSet(context.Background(), state, anchor.CA, raw, now)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := nodepki.NewPersistentFileTrust(caFile, crlFile, state, now)
	if err != nil {
		t.Fatal(err)
	}
	return trust, receipt
}
func TestCollectorRootTrustRefreshRequiresExactAcknowledgementAndResendsAfterFailure(t *testing.T) {
	trust, receipt := collectorRootTrustFixture(t)
	state := nodeTrustSync{unsupported: true} // a previous legacy negotiation cannot bypass a new rotation
	calls := 0
	client := rootRefreshClient{call: func(r *agentv1.RefreshRootTrustRequest) (*agentv1.RefreshRootTrustResponse, error) {
		calls++
		if r.NodeId != "node-a" || digest(r.SnapshotJson) != receipt.SHA256 {
			t.Fatal("wrong request binding")
		}
		return &agentv1.RefreshRootTrustResponse{NodeId: r.NodeId, SnapshotSha256: receipt.SHA256, Rotation: receipt.Rotation, Phase: receipt.Phase}, nil
	}}
	for range 3 {
		if err := state.sync(context.Background(), trust, "node-a", client); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || state.rootSHA != receipt.SHA256 {
		t.Fatal("unchanged root snapshot resent", calls)
	}
	state.invalidate(status.Error(codes.PermissionDenied, "revocation changed"))
	if err := state.sync(context.Background(), trust, "node-a", client); err != nil || calls != 2 {
		t.Fatal("policy failure did not recheck remote trust", calls, err)
	}
}
func TestCollectorRootTrustNeverTreatsUnsupportedOrIncorrectResponseAsSuccess(t *testing.T) {
	for _, scenario := range []string{"unsupported", "nil", "wrong-node", "wrong-hash", "wrong-rotation", "wrong-phase"} {
		t.Run(scenario, func(t *testing.T) {
			trust, receipt := collectorRootTrustFixture(t)
			state := nodeTrustSync{}
			client := rootRefreshClient{call: func(r *agentv1.RefreshRootTrustRequest) (*agentv1.RefreshRootTrustResponse, error) {
				out := &agentv1.RefreshRootTrustResponse{NodeId: r.NodeId, SnapshotSha256: receipt.SHA256, Rotation: receipt.Rotation, Phase: receipt.Phase}
				switch scenario {
				case "unsupported":
					return nil, status.Error(codes.Unimplemented, "old Agent")
				case "nil":
					return nil, nil
				case "wrong-node":
					out.NodeId = "other"
				case "wrong-hash":
					out.SnapshotSha256 = strings.Repeat("c", 64)
				case "wrong-rotation":
					out.Rotation = strings.Repeat("c", 64)
				case "wrong-phase":
					out.Phase = "new-only"
				}
				return out, nil
			}}
			if err := state.sync(context.Background(), trust, "node-a", client); err == nil || state.rootSHA != "" || state.unsupported {
				t.Fatal("invalid receipt changed accepted trust", err)
			}
		})
	}
}
