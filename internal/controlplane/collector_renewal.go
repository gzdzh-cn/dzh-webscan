package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

var errNodeRenewal = errors.New("节点证书续期尚未完成，请检查节点身份、运行配置与宿主签发服务")

// Called by the sequential per-node metrics worker after trust synchronization.
// It relays only public material and never opens the CA private key or Vault.
// A successful activation (including response-loss reconciliation) asks the
// caller to close this transport so the next handshake observes the new leaf.
func (c *Collector) renewNodeIdentity(ctx context.Context, n Node, l Lease, client agentv1.AgentServiceClient) (rotated bool, resultErr error) {
	defer func() {
		if errors.Is(resultErr, errNodeRenewalPaused) {
			resultErr = nil // Expected maintenance must not invalidate deployment readiness.
		}
	}()
	cap, err := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{})
	if err != nil {
		return false, err
	}
	if !validCapabilities(n, cap) {
		return false, errNodeRenewal
	}
	if !cap.IdentityRenewal {
		return false, nil // Compatible old nodes keep their existing behavior.
	}
	if err := c.Store.checkRenewalRuntime(ctx, n, l); err != nil {
		return false, err
	}
	if !releaseDigest(cap.CertificateSha256) || cap.CertificateNotAfterUnix <= time.Now().Unix() {
		return false, errNodeRenewal
	}
	var pending bool
	err = c.Store.DB.QueryRowContext(ctx, `SELECT j.activated_at IS NULL FROM v3_node_renewal_jobs j
 JOIN v3_node_certificate_renewals x ON x.node=j.node AND x.parent_sha256=j.parent_sha256 AND x.request_sha256=j.request_sha256 AND x.request_kind='renewal'
 WHERE j.node=$1 AND x.certificate_sha256=$2`, n.ID, cap.CertificateSha256).Scan(&pending)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if pending {
		err := c.Store.confirmNodeRenewal(ctx, n, l, cap.CertificateSha256, cap.CertificateNotAfterUnix)
		return err == nil, err
	}
	if time.Unix(cap.CertificateNotAfterUnix, 0).After(time.Now().Add(7 * 24 * time.Hour)) {
		return false, nil
	}
	prepared, err := client.PrepareIdentityRenewal(ctx, &agentv1.PrepareIdentityRenewalRequest{NodeId: n.ID, CertificateSha256: cap.CertificateSha256})
	if err != nil {
		return false, err
	}
	if prepared == nil || prepared.NodeId != n.ID || prepared.CertificateSha256 != cap.CertificateSha256 || prepared.RequestSha256 != digest(prepared.PublicRequestJson) {
		return false, errNodeRenewal
	}
	r, err := nodepki.ParseNodeRenewalRequest(prepared.PublicRequestJson)
	if err != nil || r.Node != n.ID || r.CertificateSHA256 != cap.CertificateSha256 || r.SHA256() != prepared.RequestSha256 {
		return false, errNodeRenewal
	}
	parent, err := provisioningCertificate(r.Certificate)
	if err != nil || parent.NotAfter.Unix() != cap.CertificateNotAfterUnix {
		return false, errNodeRenewal
	}
	j, err := c.Store.queueNodeRenewal(ctx, n, l, prepared.PublicRequestJson, 30*24)
	if err != nil {
		return false, err
	}
	delivery, err := c.Store.nodeRenewalDelivery(ctx, n, l, j.ParentSHA256, j.RequestSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil // The isolated host signer will pick up this durable job.
	}
	if err != nil {
		return false, err
	}
	activated, err := client.ActivateIdentityRenewal(ctx, &agentv1.ActivateIdentityRenewalRequest{NodeId: n.ID, PreviousCertificateSha256: j.ParentSHA256, RequestSha256: j.RequestSHA256, Certificate: delivery.Certificate})
	if err != nil {
		return false, err // Next capability read reconciles a lost response.
	}
	x := delivery.Receipt
	if activated == nil || activated.NodeId != n.ID || activated.RequestSha256 != j.RequestSHA256 || activated.CertificateSha256 != x.CertificateSHA256 || activated.CertificateNotAfterUnix != x.ExpiresAt.Unix() {
		return false, errNodeRenewal
	}
	return true, c.Store.confirmNodeRenewal(ctx, n, l, x.CertificateSHA256, x.ExpiresAt.Unix())
}
