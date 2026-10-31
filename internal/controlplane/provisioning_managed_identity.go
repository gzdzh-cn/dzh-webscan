package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

type provisioningReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// A committed node-local renewal is evidence that the original centrally held
// key is no longer authoritative for upgrades. It need not have a collector
// activation receipt yet: that response can be lost. The node independently
// proves its actual, currently valid private identity before any service stop.
// No private key is decrypted or reissued by this path.
func managedNodeAuthority(ctx context.Context, q provisioningReader, c Config, n Node) ([]byte, bool, error) {
	var certificate []byte
	var authority, sha string
	err := q.QueryRowContext(ctx, `SELECT authority,certificate,certificate_sha256 FROM (
	 SELECT authority,certificate,certificate_sha256,not_after,created_at,parent_sha256 FROM v3_node_certificate_renewals WHERE node=$1
	 UNION ALL SELECT authority,certificate,certificate_sha256,not_after,created_at,parent_sha256 FROM v3_root_identity_issuances WHERE role='node' AND subject=$1
	) identities ORDER BY not_after DESC,created_at DESC,parent_sha256 DESC LIMIT 1`, n.ID).Scan(&authority, &certificate, &sha)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var ca []byte
	err = q.QueryRowContext(ctx, `SELECT certificate FROM v3_pki_authorities WHERE sha256=$1`, authority).Scan(&ca)
	root, parseErr := provisioningCertificate(ca)
	if err != nil || parseErr != nil || digest(root.Raw) != authority {
		return nil, true, errNodeIdentity
	}
	crl, err := provisioningIssuerCRL(c, ca, time.Now())
	if err != nil {
		return nil, true, errNodeIdentity
	}
	if err = checkIssuerFloor(ctx, q, nodeconfig.Material{CA: ca, CRL: crl}); err != nil {
		return nil, true, err
	}
	cert, err := provisioningCertificate(certificate)
	trust, trustErr := nodepki.NewTrust(ca, crl, time.Now())
	if err != nil || trustErr != nil || digest(cert.Raw) != sha || cert.VerifyHostname(n.ServerName) != nil || trust.Verify(cert, nodepki.Node, n.ID, time.Now()) != nil {
		return nil, true, errNodeIdentity
	}
	// The oldest immutable seed pins this node's installation anchor. Existing
	// rolled nodes keep their original anchor/root history; nodes installed
	// after finalization can pin the successor directly using ordinary format 2.
	var anchor []byte
	if err := q.QueryRowContext(ctx, `SELECT a.certificate FROM v3_node_certificates n JOIN v3_pki_authorities a ON a.sha256=n.authority WHERE n.node=$1 ORDER BY n.created_at,n.id LIMIT 1`, n.ID).Scan(&anchor); err != nil {
		return nil, true, errNodeIdentity
	}
	if _, _, err := provisioningConfigurationTrust(c, anchor, true, time.Now()); err != nil {
		return nil, true, err
	}
	return anchor, true, nil
}

func provisioningNodeIdentity(ctx context.Context, q provisioningReader, c Config, v *Vault, id string, n Node, allowManaged bool) (nodepki.Bundle, bool, error) {
	if allowManaged {
		ca, managed, err := managedNodeAuthority(ctx, q, c, n)
		if err != nil {
			return nodepki.Bundle{}, managed, err
		}
		if managed {
			b := nodepki.Bundle{CA: ca}
			if id == "" {
				return b, true, nil
			}
			if !identifier.MatchString(id) {
				return nodepki.Bundle{}, true, errNodeIdentity
			}
			var authority string
			if err := q.QueryRowContext(ctx, `SELECT authority,certificate FROM v3_node_certificates WHERE id=$1 AND node=$2`, id, n.ID).Scan(&authority, &b.Certificate); err != nil {
				return nodepki.Bundle{}, true, errNodeIdentity
			}
			root, rootErr := provisioningCertificate(ca)
			cert, err := provisioningCertificate(b.Certificate)
			identity, identityErr := nodepki.Identity(nodepki.Node, n.ID)
			if rootErr != nil || err != nil || identityErr != nil || authority != digest(root.Raw) || cert.IsCA || len(cert.URIs) != 1 || cert.URIs[0].String() != identity || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || cert.CheckSignatureFrom(root) != nil {
				return nodepki.Bundle{}, true, errNodeIdentity
			}
			// This immutable seed is only a historical binding reference. Its
			// expiry/revocation must not authorize or invalidate a live successor.
			// Validate its original chain without relaxing any online TLS check.
			pool := x509.NewCertPool()
			pool.AddCert(root)
			if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: cert.NotBefore.Add(time.Second), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return nodepki.Bundle{}, true, errNodeIdentity
			}
			return b, true, nil
		}
	}
	b, err := readNodeIdentityFrom(ctx, q, c, v, id, n.ID)
	return b, false, err
}

func validateManagedDeployment(ctx context.Context, q provisioningReader, c Config, n Node, kind string, m nodeconfig.Material) error {
	if m.Format != 3 {
		return nil
	}
	if kind != "upgrade" {
		return errProvisioning
	}
	ca, managed, err := managedNodeAuthority(ctx, q, c, n)
	if err != nil || !managed || !bytes.Equal(bytes.TrimSpace(ca), bytes.TrimSpace(m.CA)) {
		return errNodeIdentity
	}
	return nil
}
