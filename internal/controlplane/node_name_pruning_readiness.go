package controlplane

import (
	"context"
	"errors"
	"time"

	"webscan/internal/nodepki"
)

var errNodeNamePruningNotReady = errors.New("名称裁剪后的节点尚未完成身份及采集验收")

// Completion requires the fresh, normally verified TLS peer and a sample
// collected after authorization, never a helper JSON success or old channel.
func (w *sshNodeNamePruning) observeAndConfirm(ctx context.Context, l Lease, id string) error {
	if !w.ready() {
		return errNodeNamePruning
	}
	j, err := w.store.checkNodeNamePruningLease(ctx, w.config, w.vault, l, id)
	if err != nil || j.Status != "signed" {
		return errNodeNamePruning
	}
	n, err := scanActiveNode(w.store.DB.QueryRowContext(ctx, `SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE id=$1`, j.Node))
	if err != nil || n.RuntimeEpoch != j.Plan.RuntimeEpoch || n.ServerName != j.Plan.ActiveName {
		return errNodeNamePruning
	}
	var certificate []byte
	if err := w.store.DB.QueryRowContext(ctx, `SELECT certificate FROM v3_node_certificate_renewals WHERE node=$1 AND parent_sha256=$2 AND request_kind='name-pruning'`, j.Node, j.ParentSHA256).Scan(&certificate); err != nil {
		return errNodeNamePruning
	}
	issued, err := provisioningCertificate(certificate)
	if err != nil {
		return errNodeNamePruning
	}
	crl, err := w.currentCRL(ctx, j)
	if err != nil {
		return err
	}
	ca, _, err := provisioningCertificateIssuer(w.config, issued, time.Now())
	if err != nil {
		return errNodeNamePruning
	}
	trust, err := nodepki.NewTrust(ca, crl, time.Now())
	if err != nil {
		return errNodeNamePruning
	}
	self, err := collectorIdentityMaterial(w.config, time.Now())
	defer clear(self.Key)
	if err != nil {
		return errNodeNamePruning
	}
	collector, err := provisioningCertificate(self.Certificate)
	if err != nil {
		return errNodeNamePruning
	}
	collectorID, err := nodepki.PeerID(collector, nodepki.Collector)
	if err != nil || trust.Verify(collector, nodepki.Collector, collectorID, time.Now()) != nil {
		return errNodeNamePruning
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ctx, deadline := context.WithDeadline(ctx, j.ExpiresAt)
	defer deadline()
	peer, err := observeMaintainedNodeIdentity(ctx, w.config, n, j.Plan.ActiveName, issued, trust, true, j.Intent.IssuedAt)
	if errors.Is(err, errNodeNameChangeNotReady) {
		return errNodeNamePruningNotReady
	}
	if err != nil {
		return err
	}
	return w.store.confirmNodeNamePruning(ctx, w.config, w.vault, l, id, peer)
}
