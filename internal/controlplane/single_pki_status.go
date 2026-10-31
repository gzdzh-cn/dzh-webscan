package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"webscan/internal/nodepki"
)

// The host signer publishes only verified public metadata. No CA key, Vault
// or host path needs to be mounted into the API for its dashboard status.
func recordSinglePKIMaintenance(ctx context.Context, store *Store, spec singleInstallSpec, result nodeRenewalSigningResult, failure error) error {
	c := spec.configuration()
	now := time.Now().UTC()
	ca, err := readTrustData(c.Collector.CAFile, true, 64<<10)
	if err != nil {
		return errSinglePKI
	}
	b, identity, err := nodepki.ReadIdentityWithRootState(c.Collector.CAFile, c.Collector.IdentityFile, c.Collector.RevocationStateDirectory, nodepki.Collector, spec.Instance, now)
	defer clear(b.Key)
	if err != nil {
		return errSinglePKI
	}
	rootState, err := nodepki.ReadRootState(c.Collector.CAFile, c.Collector.RevocationStateDirectory, now)
	if err != nil {
		return errSinglePKI
	}
	crl, err := readTrustData(c.Collector.RevocationFile, true, nodepki.MaxCRLBytes)
	if err != nil {
		return errSinglePKI
	}
	if rootState.Format != 0 {
		crl = rootState.OldCRL
		if bytes.Equal(b.CA, rootState.Dual.NewCA) {
			crl = rootState.NewCRL
		}
		ca = b.CA
	}
	root, err := provisioningCertificate(ca)
	trust, trustErr := nodepki.NewPersistentFileTrust(c.Collector.CAFile, c.Collector.RevocationFile, c.Collector.RevocationStateDirectory, now)
	leaf, leafErr := provisioningCertificate(b.Certificate)
	if err != nil || trustErr != nil || leafErr != nil || trust.Verify(leaf, nodepki.Collector, spec.Instance, now) != nil {
		return errSinglePKI
	}
	reason := ""
	if failure != nil {
		reason = "节点证书签发暂不可用，已保留任务等待重试"
	} else if result.Failed > 0 {
		reason = "部分节点证书签发失败，已保留任务等待重试"
	}
	details, _ := json.Marshal(map[string]any{"collector_expires_at": identity.ExpiresAt, "ca_expires_at": root.NotAfter, "collector_certificate_sha256": identity.CertificateSHA256, "crl_sha256": digest(crl), "signed": result.Signed, "failed": result.Failed})
	_, err = store.DB.ExecContext(ctx, `INSERT INTO v3_role_status(role,instance,heartbeat,error,details) VALUES('pki-maintenance',$1,$2,$3,$4) ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error,details=excluded.details`, spec.Instance, now, reason, details)
	return err
}
