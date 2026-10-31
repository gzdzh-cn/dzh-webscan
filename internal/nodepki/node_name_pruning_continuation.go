package nodepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"slices"
	"time"
)

// IssuanceSHA256 names the immutable ORIGINAL issuance, not a new short-lived
// continuation proof. It is not validation or signing authorization.
func (r NodeNamePruningRequest) IssuanceSHA256() string {
	if r.Kind == namePruningKind && len(r.OriginalRequest) == 0 && len(r.ContinuationCertificate) == 0 {
		return r.SHA256()
	}
	if r.Kind != namePruningContinuationKind && r.Kind != namePruningReconciliationKind {
		return ""
	}
	original, err := ParseNodeNamePruningRequest(r.OriginalRequest)
	if err != nil || original.Kind != namePruningKind {
		return ""
	}
	return original.SHA256()
}

func namePruningOriginal(r NodeNamePruningRequest) (NodeNamePruningRequest, error) {
	if r.Kind == namePruningKind {
		return r, nil
	}
	if r.Kind != namePruningContinuationKind && r.Kind != namePruningReconciliationKind {
		return NodeNamePruningRequest{}, ErrIdentity
	}
	original, err := ParseNodeNamePruningRequest(r.OriginalRequest)
	if err != nil || original.Kind != namePruningKind {
		return NodeNamePruningRequest{}, ErrIdentity
	}
	return original, nil
}

// ValidateNodeNamePruningReceipt verifies an ORIGINAL public request and its
// already-issued successor with current trust, even after its intent/parent
// expires. No proof of present possession or administrator authority is implied.
func ValidateNodeNamePruningReceipt(ca, crl []byte, original NodeNamePruningRequest, certificate []byte, now time.Time) error {
	old, csr, err := validateNamePruningInitial(ca, crl, original, original.Intent, now, true)
	if err != nil || len(certificate) == 0 || len(certificate) > 16<<10 {
		return ErrIdentity
	}
	return validateNameChangeLeaf(ca, crl, old, csr, original.Intent.Node, certificate, now)
}

func validateNamePruningContinuation(ca, crl []byte, r NodeNamePruningRequest, expected NodeNamePruningIntent, now time.Time) (*x509.Certificate, *x509.CertificateRequest, error) {
	if !validNamePruningIntent(expected, now) || r.Intent.SHA256() != expected.SHA256() || r.Format != 1 || (r.Kind != namePruningContinuationKind && r.Kind != namePruningReconciliationKind) || len(r.Proof) != ed25519.SignatureSize || r.SHA256() == "" {
		return nil, nil, ErrIdentity
	}
	original, err := namePruningOriginal(r)
	if err != nil || original.Intent.Node != expected.Node || original.Intent.AuthoritySHA256 != expected.AuthoritySHA256 || original.Intent.CertificateSHA256 != expected.CertificateSHA256 || original.Intent.ActiveName != expected.ActiveName || !slices.Equal(original.Intent.Names, expected.Names) || original.Intent.ConfigurationSHA256 != expected.ConfigurationSHA256 || original.Intent.RuntimeEpoch != expected.RuntimeEpoch || original.Intent.Challenge == expected.Challenge || original.Intent.IssuedAt.After(expected.IssuedAt) || !bytes.Equal(original.Certificate, r.Certificate) || !bytes.Equal(original.CSR, r.CSR) {
		return nil, nil, ErrIdentity
	}
	old, csr, err := validateNamePruningInitial(ca, crl, original, original.Intent, now, true)
	if err != nil || ValidateNodeNamePruningReceipt(ca, crl, original, r.ContinuationCertificate, now) != nil {
		return nil, nil, ErrIdentity
	}
	leaf, err := parseCertificate(r.ContinuationCertificate)
	if err != nil {
		return nil, nil, ErrIdentity
	}
	proofIdentity := leaf
	if r.Kind == namePruningReconciliationKind {
		trust, err := NewTrust(ca, crl, now)
		if err != nil || trust.Verify(old, Node, expected.Node, now) != nil {
			return nil, nil, ErrIdentity
		}
		proofIdentity = old
	}
	key, ok := proofIdentity.PublicKey.(ed25519.PublicKey)
	payload, err := namePruningProof(r)
	if err != nil || !ok || !ed25519.Verify(key, payload, r.Proof) {
		return nil, nil, ErrIdentity
	}
	return old, csr, nil
}

// PrepareNodeNamePruningContinuation proves the still-active original parent or
// exact active successor for a NEW short-lived administrator intent. It retains
// the original local CSR/key, creates no files and cannot enter the signing primitive. The controller must
// match the exact original SQL issuance before admitting/replaying this proof.
func PrepareNodeNamePruningContinuation(ctx context.Context, caFile, identityFile, trustDirectory string, crl []byte, expected NodeNamePruningIntent, original NodeNamePruningRequest, certificate []byte, now time.Time) (NodeNamePruningRequest, error) {
	var empty NodeNamePruningRequest
	if !validNamePruningIntent(expected, now) || !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile || filepath.Dir(identityFile) == trustDirectory || secureDirectory(filepath.Dir(identityFile)) != nil || secureDirectory(trustDirectory) != nil {
		return empty, ErrIdentity
	}
	ctx, cancel := context.WithDeadline(ctx, expected.ExpiresAt)
	defer cancel()
	ctx, finish := context.WithTimeout(ctx, 5*time.Second)
	defer finish()
	// Incoming signed CRL may advance an expired floor, but never roll it back.
	lock, err := authorityLock(ctx, trustDirectory)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	ca, floor, err := maintenanceIssuerMaterial(caFile, trustDirectory, expected.AuthoritySHA256, now)
	if err != nil || ValidateCRLAdvance(ca, floor, crl, now) != nil || ValidateNodeNamePruningReceipt(ca, crl, original, certificate, now) != nil {
		return empty, ErrRevocation
	}
	var result NodeNamePruningRequest
	err = WithIdentitySnapshot(ctx, filepath.Dir(identityFile), func() error {
		saved, key, err := readNamePruningPendingAt(namePruningPending(identityFile, original.Intent), ca, crl, original.Intent, now, true)
		defer clear(key)
		if err != nil || saved.SHA256() != original.SHA256() {
			return ErrIdentity
		}
		active, record, err := ReadIdentityWithRootState(caFile, identityFile, trustDirectory, Node, expected.Node, now)
		defer clear(active.Key)
		leaf, parseErr := parseCertificate(certificate)
		if err != nil || parseErr != nil || (record.CertificateSHA256 != publicSHA(leaf.Raw) && record.CertificateSHA256 != expected.CertificateSHA256) {
			return ErrIdentity
		}
		block, _ := pem.Decode(active.Key)
		if block == nil {
			return ErrIdentity
		}
		defer clear(block.Bytes)
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		private, ok := parsed.(ed25519.PrivateKey)
		defer clear(private)
		if err != nil || !ok {
			return ErrIdentity
		}
		raw, err := json.Marshal(original)
		if err != nil {
			return ErrIdentity
		}
		kind := namePruningContinuationKind
		if record.CertificateSHA256 == expected.CertificateSHA256 {
			kind = namePruningReconciliationKind
		}
		r := NodeNamePruningRequest{Format: 1, Kind: kind, Intent: expected, Certificate: original.Certificate, CSR: original.CSR, OriginalRequest: raw, ContinuationCertificate: append([]byte{}, certificate...)}
		payload, err := namePruningProof(r)
		if err != nil {
			return err
		}
		r.Proof = ed25519.Sign(private, payload)
		if err := ValidateNodeNamePruningRequest(ca, crl, r, expected, now); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		result = r
		return nil
	})
	if err != nil {
		return empty, err
	}
	return result, nil
}
