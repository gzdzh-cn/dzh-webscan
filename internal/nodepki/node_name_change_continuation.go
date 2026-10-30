package nodepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"time"
)

// Historical proof and CURRENT revocation are independent. This never validates
// today's CRL at an old time or grants online authentication to an expired leaf.
func verifyNameChangeParent(trust *Trust, root, old *x509.Certificate, node string, at time.Time, historical bool) error {
	if !historical {
		return trust.Verify(old, Node, node, at)
	}
	id, err := PeerID(old, Node)
	if err != nil || id != node {
		return ErrIdentity
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := old.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return ErrIdentity
	}
	trust.mu.RLock()
	defer trust.mu.RUnlock()
	if trust.revoked[old.SerialNumber.String()] {
		return ErrRevocation
	}
	return nil
}

// IssuanceSHA256 names the immutable ORIGINAL issuance, not a new short-lived
// continuation proof. It is not validation or signing authorization.
func (r NodeNameChangeRequest) IssuanceSHA256() string {
	if r.Kind == nameChangeKind && len(r.OriginalRequest) == 0 && len(r.ContinuationCertificate) == 0 {
		return r.SHA256()
	}
	if r.Kind != nameChangeContinuationKind && r.Kind != nameChangeReconciliationKind {
		return ""
	}
	original, err := ParseNodeNameChangeRequest(r.OriginalRequest)
	if err != nil || original.Kind != nameChangeKind {
		return ""
	}
	return original.SHA256()
}

func nameChangeOriginal(r NodeNameChangeRequest) (NodeNameChangeRequest, error) {
	if r.Kind == nameChangeKind {
		return r, nil
	}
	if r.Kind != nameChangeContinuationKind && r.Kind != nameChangeReconciliationKind {
		return NodeNameChangeRequest{}, ErrIdentity
	}
	original, err := ParseNodeNameChangeRequest(r.OriginalRequest)
	if err != nil || original.Kind != nameChangeKind {
		return NodeNameChangeRequest{}, ErrIdentity
	}
	return original, nil
}

// ValidateNodeNameChangeReceipt verifies an ORIGINAL public request and its
// already-issued successor with current trust, even after its intent/parent
// expires. No proof of present possession or administrator authority is implied.
func ValidateNodeNameChangeReceipt(ca, crl []byte, original NodeNameChangeRequest, certificate []byte, now time.Time) error {
	old, csr, err := validateNameChangeInitial(ca, crl, original, original.Intent, now, true)
	if err != nil || len(certificate) == 0 || len(certificate) > 16<<10 {
		return ErrIdentity
	}
	return validateNameChangeLeaf(ca, crl, old, csr, original.Intent.Node, certificate, now)
}

func validateNameChangeContinuation(ca, crl []byte, r NodeNameChangeRequest, expected NodeNameChangeIntent, now time.Time) (*x509.Certificate, *x509.CertificateRequest, error) {
	if !validNameChangeIntent(expected, now) || !sameNameChangeIntent(r.Intent, expected) || r.Format != 1 || (r.Kind != nameChangeContinuationKind && r.Kind != nameChangeReconciliationKind) || len(r.Proof) != ed25519.SignatureSize || r.SHA256() == "" {
		return nil, nil, ErrIdentity
	}
	original, err := nameChangeOriginal(r)
	if err != nil || original.Intent.Node != expected.Node || original.Intent.AuthoritySHA256 != expected.AuthoritySHA256 || original.Intent.CertificateSHA256 != expected.CertificateSHA256 || original.Intent.ServerName != expected.ServerName || original.Intent.Challenge == expected.Challenge || original.Intent.IssuedAt.After(expected.IssuedAt) || !bytes.Equal(original.Certificate, r.Certificate) || !bytes.Equal(original.CSR, r.CSR) {
		return nil, nil, ErrIdentity
	}
	old, csr, err := validateNameChangeInitial(ca, crl, original, original.Intent, now, true)
	if err != nil || ValidateNodeNameChangeReceipt(ca, crl, original, r.ContinuationCertificate, now) != nil {
		return nil, nil, ErrIdentity
	}
	leaf, err := parseCertificate(r.ContinuationCertificate)
	if err != nil {
		return nil, nil, ErrIdentity
	}
	proofIdentity := leaf
	if r.Kind == nameChangeReconciliationKind {
		trust, err := NewTrust(ca, crl, now)
		if err != nil || trust.Verify(old, Node, expected.Node, now) != nil {
			return nil, nil, ErrIdentity
		}
		proofIdentity = old
	}
	key, ok := proofIdentity.PublicKey.(ed25519.PublicKey)
	payload, err := nameChangeProof(r)
	if err != nil || !ok || !ed25519.Verify(key, payload, r.Proof) {
		return nil, nil, ErrIdentity
	}
	return old, csr, nil
}

// PrepareNodeNameChangeContinuation proves the still-active original parent or
// exact active successor for a NEW short-lived administrator intent. It retains
// the original local CSR/key, creates no files and cannot enter the signing primitive. The controller must
// match the exact original SQL issuance before admitting/replaying this proof.
func PrepareNodeNameChangeContinuation(ctx context.Context, caFile, identityFile, trustDirectory string, crl []byte, expected NodeNameChangeIntent, original NodeNameChangeRequest, certificate []byte, now time.Time) (NodeNameChangeRequest, error) {
	var empty NodeNameChangeRequest
	if !validNameChangeIntent(expected, now) || !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile || filepath.Dir(identityFile) == trustDirectory || secureDirectory(filepath.Dir(identityFile)) != nil || secureDirectory(trustDirectory) != nil {
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
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return empty, ErrIdentity
	}
	pinned, err := readIdentityFile(filepath.Join(trustDirectory, "ca.crt"), 64<<10, true)
	if err != nil || !bytes.Equal(bytes.TrimSpace(ca), bytes.TrimSpace(pinned)) {
		return empty, ErrIdentity
	}
	floor, err := readIdentityFile(filepath.Join(trustDirectory, "ca.crl"), MaxCRLBytes, true)
	if err != nil || ValidateCRLAdvance(ca, floor, crl, now) != nil || ValidateNodeNameChangeReceipt(ca, crl, original, certificate, now) != nil {
		return empty, ErrRevocation
	}
	var result NodeNameChangeRequest
	err = WithIdentitySnapshot(ctx, filepath.Dir(identityFile), func() error {
		saved, key, err := readNameChangePendingAt(nameChangePending(identityFile, original.Intent), ca, crl, original.Intent, now, true)
		defer clear(key)
		if err != nil || saved.SHA256() != original.SHA256() {
			return ErrIdentity
		}
		active, record, err := ReadIdentity(caFile, identityFile, Node, expected.Node, now)
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
		kind := nameChangeContinuationKind
		if record.CertificateSHA256 == expected.CertificateSHA256 {
			kind = nameChangeReconciliationKind
		}
		r := NodeNameChangeRequest{Format: 1, Kind: kind, Intent: expected, Certificate: original.Certificate, CSR: original.CSR, OriginalRequest: raw, ContinuationCertificate: append([]byte{}, certificate...)}
		payload, err := nameChangeProof(r)
		if err != nil {
			return err
		}
		r.Proof = ed25519.Sign(private, payload)
		if err := ValidateNodeNameChangeRequest(ca, crl, r, expected, now); err != nil {
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
