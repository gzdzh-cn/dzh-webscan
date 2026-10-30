package controlplane

import (
	"bytes"
	"context"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

// Only an existing leased task may use historical seed material. This never
// changes its immutable artifact or grants a new install/preview authority.
// The node repeats validation against its actual private identity and durable
// CRL before stopping services; a public successor is not remote readiness.
func (s *Store) validateDeploymentRuntimeConfiguration(ctx context.Context, c Config, release *TrustedRelease, j DeploymentJob, raw []byte) error {
	if err := s.checkDeploymentPlan(ctx, j); err != nil {
		return err
	}
	artifact := j.Plan.Request.RuntimeArtifact
	if artifact == nil || artifact.SHA256 != digest(raw) || artifact.Bytes != uint64(len(raw)) {
		return errProvisioning
	}
	n, err := scanNode(s.DB.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND version=$2`, j.Node, j.NodeVersion))
	if err != nil || digest(n.Config) != j.Plan.ConfigDigest {
		return ErrConflict
	}
	current, err := readTrustData(c.Collector.RevocationFile, false, nodepki.MaxCRLBytes)
	if err != nil {
		return errProvisioning
	}
	now := time.Now()
	m, decodeErr := nodeconfig.Decode(raw, now)
	defer func() { clear(m.Key) }()
	historical := decodeErr != nil || !bytes.Equal(bytes.TrimSpace(current), bytes.TrimSpace(m.CRL))
	if historical {
		// A valid immutable seed is still not an authorization to install an
		// obsolete CRL on an uninitialized node. Existing local-key issuance
		// evidence is mandatory before using the contextual decoder.
		clear(m.Key)
		m, err = nodeconfig.DecodeManagedRuntime(raw, now, current)
		if err != nil {
			return errProvisioning
		}
	}
	if err = validateProvisioningNode(n, m, release); err != nil {
		return err
	}
	check := m
	if historical || m.Format == 3 {
		ca, managed, err := managedNodeAuthority(ctx, s.DB, c, n)
		if err != nil || !managed || !bytes.Equal(bytes.TrimSpace(ca), bytes.TrimSpace(m.CA)) {
			return errNodeIdentity
		}
		check.Format, check.CRL, check.Certificate, check.Key = 3, current, nil, nil
	}
	if err = validateProvisioningTrust(c, check, now); err != nil {
		return err
	}
	if err = checkIssuerFloor(ctx, s.DB, check); err != nil {
		return err
	}
	return s.checkDeploymentPlan(ctx, j)
}
