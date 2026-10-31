package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

// Read only public, durably authorized trust. A successor directory or an
// authority registry row alone never permits issuing or installing its leaves.
func provisioningRootState(c Config, now time.Time) (nodepki.RootSetSnapshot, error) {
	if c.Collector.RevocationStateDirectory == "" {
		return nodepki.RootSetSnapshot{}, nil
	}
	trust, err := nodepki.NewPersistentFileTrust(c.Collector.CAFile, c.Collector.RevocationFile, c.Collector.RevocationStateDirectory, now)
	if err != nil {
		return nodepki.RootSetSnapshot{}, errNodeIdentity
	}
	raw, receipt, err := trust.RootSnapshot(now, "")
	if err != nil {
		return nodepki.RootSetSnapshot{}, errNodeIdentity
	}
	if receipt.SHA256 == "" {
		return nodepki.RootSetSnapshot{}, nil
	}
	return nodepki.ParseRootSetSnapshot(raw)
}

func provisioningIssuerCRL(c Config, issuer []byte, now time.Time) ([]byte, error) {
	anchor, err := readTrustData(c.Collector.CAFile, false, 64<<10)
	if err != nil {
		return nil, errNodeIdentity
	}
	roots, err := provisioningRootState(c, now)
	if err != nil {
		return nil, err
	}
	var crl []byte
	switch {
	case roots.Format == 1 && bytes.Equal(issuer, roots.Dual.NewCA):
		crl = roots.NewCRL
	case bytes.Equal(bytes.TrimSpace(issuer), bytes.TrimSpace(anchor)) && roots.Final == nil:
		if roots.Format == 1 {
			crl = roots.OldCRL
		} else {
			crl, err = readTrustData(c.Collector.RevocationFile, false, nodepki.MaxCRLBytes)
		}
	default:
		return nil, errNodeIdentity
	}
	if err != nil {
		return nil, err
	}
	if _, err := nodepki.NewTrust(issuer, crl, now); err != nil {
		return nil, errNodeIdentity
	}
	return crl, nil
}

// A keyless upgrade retains the node's immutable anchor. After finalization
// its old CRL is historical configuration evidence, never runtime permission.
func provisioningConfigurationTrust(c Config, ca []byte, managed bool, now time.Time) ([]byte, *nodepki.RootSetSnapshot, error) {
	roots, err := provisioningRootState(c, now)
	if err != nil {
		return nil, nil, err
	}
	if managed && roots.Format == 1 {
		anchor, err := readTrustData(c.Collector.CAFile, false, 64<<10)
		if err != nil {
			return nil, nil, errNodeIdentity
		}
		if bytes.Equal(bytes.TrimSpace(ca), bytes.TrimSpace(anchor)) {
			return roots.OldCRL, &roots, nil
		}
	}
	crl, err := provisioningIssuerCRL(c, ca, now)
	return crl, nil, err
}

func decodeProvisioningMaterial(c Config, raw []byte, now time.Time) (nodeconfig.Material, error) {
	// Try the normal strict decoder first; successor-anchored fresh nodes use
	// the existing format. Only an authenticated original-anchor rotation can
	// authorize inspection of an expired keyless artifact.
	m, err := nodeconfig.Decode(raw, now)
	if err == nil {
		return m, nil
	}
	roots, rootErr := provisioningRootState(c, now)
	if rootErr != nil || roots.Format != 1 {
		return nodeconfig.Material{}, errNodeIdentity
	}
	var header struct {
		Format int    `json:"format"`
		CA     []byte `json:"ca"`
	}
	anchor, anchorErr := readTrustData(c.Collector.CAFile, false, 64<<10)
	if json.Unmarshal(raw, &header) != nil || header.Format != 3 || anchorErr != nil || !bytes.Equal(header.CA, anchor) {
		return nodeconfig.Material{}, errNodeIdentity
	}
	return nodeconfig.DecodeManagedRootRuntime(raw, now, roots)
}

func checkConfigurationIssuerFloor(ctx context.Context, q provisioningReader, c Config, m nodeconfig.Material) error {
	_, roots, err := provisioningConfigurationTrust(c, m.CA, m.Format == 3, time.Now())
	if err != nil {
		return err
	}
	at := time.Now()
	if roots != nil {
		if !bytes.Equal(m.CRL, roots.OldCRL) {
			return errNodeIdentity
		}
		block, _ := pem.Decode(m.CRL)
		if block == nil {
			return errNodeIdentity
		}
		list, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return errNodeIdentity
		}
		at = list.ThisUpdate
	}
	return checkIssuerFloorAt(ctx, q, m, at)
}

// Resolve the issuer of a saved public identity, including an expired leaf
// used for pinned-SSH recovery. This grants no leaf authentication exception.
func provisioningCertificateIssuer(c Config, certificate *x509.Certificate, now time.Time) ([]byte, []byte, error) {
	if certificate == nil {
		return nil, nil, errNodeIdentity
	}
	anchor, err := readTrustData(c.Collector.CAFile, false, 64<<10)
	if err != nil {
		return nil, nil, errNodeIdentity
	}
	roots, err := provisioningRootState(c, now)
	if err != nil {
		return nil, nil, err
	}
	candidates := [][]byte{anchor}
	if roots.Format == 1 {
		candidates = [][]byte{roots.Dual.NewCA}
		if roots.Final == nil {
			candidates = append(candidates, anchor)
		}
	}
	for _, ca := range candidates {
		root, err := provisioningCertificate(ca)
		if err == nil && certificate.CheckSignatureFrom(root) == nil {
			crl, err := provisioningIssuerCRL(c, ca, now)
			return ca, crl, err
		}
	}
	return nil, nil, errNodeIdentity
}
