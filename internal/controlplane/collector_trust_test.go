package controlplane

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

type trustUpdateClient struct {
	agentv1.AgentServiceClient
	call func(*agentv1.UpdateTrustRequest) (*agentv1.UpdateTrustResponse, error)
}

func (c trustUpdateClient) UpdateTrust(_ context.Context, r *agentv1.UpdateTrustRequest, _ ...grpc.CallOption) (*agentv1.UpdateTrustResponse, error) {
	return c.call(r)
}

func collectorTrustFixture(t *testing.T) (*nodepki.FileTrust, *nodepki.Authority, string, []byte, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	a, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := a.Export()
	defer clear(b.Key)
	crl, _ := a.Revoke(nil, nil, now, time.Hour)
	dir := privateTestDir(t)
	caFile, crlFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.crl")
	for p, raw := range map[string][]byte{caFile: b.CA, crlFile: crl} {
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	trust, err := nodepki.NewFileTrust(caFile, crlFile, now)
	if err != nil {
		t.Fatal(err)
	}
	return trust, a, crlFile, crl, now
}
func trustUpdateAck(t *testing.T, r *agentv1.UpdateTrustRequest) *agentv1.UpdateTrustResponse {
	t.Helper()
	block, _ := pem.Decode(r.Crl)
	if block == nil {
		t.Fatal("missing CRL")
	}
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.UpdateTrustResponse{NodeId: r.NodeId, CrlSha256: digest(r.Crl), CrlNumber: list.Number.Text(10), NextUpdateUnix: list.NextUpdate.Unix()}
}

func TestCollectorTrustSyncValidatesReceiptAndOnlyResendsOnChange(t *testing.T) {
	trust, a, file, crl, now := collectorTrustFixture(t)
	state := nodeTrustSync{}
	calls := 0
	client := trustUpdateClient{call: func(r *agentv1.UpdateTrustRequest) (*agentv1.UpdateTrustResponse, error) {
		calls++
		return trustUpdateAck(t, r), nil
	}}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := state.sync(ctx, trust, "node-a", client); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || state.sha != digest(crl) {
		t.Fatal("unchanged CRL retransmitted", calls)
	}
	next, _ := a.Revoke(crl, nil, now, time.Hour)
	tmp := file + ".new"
	if err := os.WriteFile(tmp, next, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, file); err != nil {
		t.Fatal(err)
	}
	// FileTrust has a shared one-second refresh cache across all node workers.
	time.Sleep(1100 * time.Millisecond)
	if err := state.sync(ctx, trust, "node-a", client); err != nil || calls != 2 || state.sha != digest(next) {
		t.Fatal("new CRL not sent", calls, err)
	}
	state.invalidate(status.Error(codes.PermissionDenied, "remote floor behind"))
	if err := state.sync(ctx, trust, "node-a", client); err != nil || calls != 3 {
		t.Fatal("policy failure did not recheck remote floor", err)
	}
}

func TestCollectorTrustSyncRejectsBadOrLostReceiptWithoutCachingSuccess(t *testing.T) {
	for _, kind := range []string{"nil", "node", "digest", "number", "expiry", "lost", "denied"} {
		t.Run(kind, func(t *testing.T) {
			trust, _, _, _, _ := collectorTrustFixture(t)
			state := nodeTrustSync{}
			calls := 0
			client := trustUpdateClient{call: func(r *agentv1.UpdateTrustRequest) (*agentv1.UpdateTrustResponse, error) {
				calls++
				ack := trustUpdateAck(t, r)
				switch kind {
				case "nil":
					return nil, nil
				case "node":
					ack.NodeId = "other"
				case "digest":
					ack.CrlSha256 = "other"
				case "number":
					ack.CrlNumber = "other"
				case "expiry":
					ack.NextUpdateUnix++
				case "lost":
					return nil, status.Error(codes.Unavailable, "response lost")
				case "denied":
					return nil, status.Error(codes.PermissionDenied, "rejected")
				}
				return ack, nil
			}}
			for i := 0; i < 2; i++ {
				if state.sync(context.Background(), trust, "node-a", client) == nil {
					t.Fatal("bad/lost receipt accepted")
				}
			}
			if calls != 2 || state.sha != "" || state.unsupported {
				t.Fatal("failure disabled or cached trust distribution")
			}
		})
	}
}

func TestCollectorTrustSyncCompatibilityDoesNotHideOtherFailures(t *testing.T) {
	trust, _, _, _, _ := collectorTrustFixture(t)
	calls := 0
	state := nodeTrustSync{}
	client := trustUpdateClient{call: func(r *agentv1.UpdateTrustRequest) (*agentv1.UpdateTrustResponse, error) {
		calls++
		return nil, status.Error(codes.Unimplemented, "old agent")
	}}
	for i := 0; i < 3; i++ {
		if err := state.sync(context.Background(), trust, "node-a", client); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || !state.unsupported || state.sha != "" {
		t.Fatal("legacy capability handling", calls)
	}
	if err := (&nodeTrustSync{}).sync(context.Background(), nil, "node-a", client); err != nil || calls != 1 {
		t.Fatal("no-policy legacy path changed")
	}
}
