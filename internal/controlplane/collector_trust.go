package controlplane

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

var errTrustDistribution = errors.New("节点吊销列表下发或确认失败")

// State is private to one node's sequential handshake/metrics worker. A normal
// reconnect keeps its durable remote floor; policy failures force a resend.
type nodeTrustSync struct {
	sha         string
	rootSHA     string
	unsupported bool
	failed      bool
}

func (s *nodeTrustSync) sync(ctx context.Context, trust *nodepki.FileTrust, node string, client agentv1.AgentServiceClient) error {
	if trust == nil {
		return nil
	}
	rootRaw, rootReceipt, err := trust.RootSnapshot(time.Now(), s.rootSHA)
	if err != nil {
		return errTrustDistribution
	}
	if rootReceipt.SHA256 != "" {
		if len(rootRaw) == 0 {
			return nil
		}
		if len(rootRaw) > nodepki.MaxRootSetBytes {
			return errTrustDistribution
		}
		r, err := client.RefreshRootTrust(ctx, &agentv1.RefreshRootTrustRequest{NodeId: node, SnapshotJson: rootRaw})
		// An old Agent cannot safely fall back to a single-CA CRL during a
		// rotation. Explicit installation/upgrade must precede participation.
		if err != nil || r == nil || r.NodeId != node || r.SnapshotSha256 != rootReceipt.SHA256 || r.Rotation != rootReceipt.Rotation || r.Phase != rootReceipt.Phase {
			return errTrustDistribution
		}
		s.rootSHA = rootReceipt.SHA256
		return nil
	}
	if s.unsupported {
		return nil
	}
	raw, sha, err := trust.Snapshot(time.Now(), s.sha)
	if err != nil {
		return errTrustDistribution
	}
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > agentv1.MaxTrustBytes {
		return errTrustDistribution
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return errTrustDistribution
	}
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil || list.Number == nil {
		return errTrustDistribution
	}
	r, err := client.UpdateTrust(ctx, &agentv1.UpdateTrustRequest{NodeId: node, Crl: raw})
	if status.Code(err) == codes.Unimplemented {
		// Additive capability: keep existing Agents collecting normally. Their
		// operator must still upgrade before their immutable old CRL expires.
		s.unsupported = true
		return nil
	}
	if err != nil || r == nil || r.NodeId != node || r.CrlSha256 != sha || r.CrlNumber != list.Number.Text(10) || r.NextUpdateUnix != list.NextUpdate.Unix() || r.NextUpdateUnix <= time.Now().Unix() {
		return errTrustDistribution
	}
	s.sha = sha
	return nil
}

func (s *nodeTrustSync) invalidate(err error) {
	if status.Code(err) == codes.PermissionDenied || status.Code(err) == codes.Unauthenticated {
		s.sha = ""
		s.rootSHA = ""
	}
}
