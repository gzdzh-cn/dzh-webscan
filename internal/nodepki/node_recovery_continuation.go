package nodepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"reflect"
	"time"
)

// recoverySuccessor validates a public receipt against the original local CSR
// and CURRENT trust. Possessing this public certificate alone is insufficient:
// preparation additionally proves its active private key, and the controller
// must match the exact committed issuance before accepting a continuation.
func recoverySuccessor(ca, crl []byte, r NodeRenewalRequest, certificate []byte, now time.Time) (*x509.Certificate, error) {
	if len(certificate) == 0 || len(certificate) > 16<<10 {
		return nil, ErrIdentity
	}
	old, csr, err := validateNodeRenewal(ca, r, now, true)
	if err != nil {
		return nil, err
	}
	if err := recoveryParentTrust(ca, crl, old, now); err != nil {
		return nil, err
	}
	leaf, err := parseCertificate(certificate)
	if err != nil || !leaf.NotAfter.After(old.NotAfter) || !reflect.DeepEqual(leaf.PublicKey, csr.PublicKey) || !reflect.DeepEqual(leaf.DNSNames, csr.DNSNames) || !reflect.DeepEqual(leaf.IPAddresses, csr.IPAddresses) {
		return nil, ErrIdentity
	}
	trust, err := NewTrust(ca, crl, now)
	if err != nil || trust.Verify(leaf, Node, r.Node, now) != nil {
		return nil, ErrRevocation
	}
	return leaf, nil
}

// PrepareNodeRecoveryContinuation is a separate pinned-SSH operation for a
// NEW administrator-authorized task after activation. It signs that task's
// challenge with the already active replacement key, retains the original
// renewal request verbatim, and neither rotates keys nor reads private history
// or the installation seed. The controller must require the exact existing
// issuance; this request cannot enter the offline signing primitive.
// Trust -> identity lock order matches activation and controlled startup.
func PrepareNodeRecoveryContinuation(ctx context.Context, caFile, identityFile, trustDirectory string, crl []byte, expected NodeRecoveryIntent, certificate []byte, now time.Time) (NodeRecoveryRequest, error) {
	var empty NodeRecoveryRequest
	if !validRecoveryIntent(expected, now) || !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile || !filepath.IsAbs(trustDirectory) || filepath.Clean(trustDirectory) != trustDirectory || trustDirectory == filepath.Dir(identityFile) || secureDirectory(trustDirectory) != nil || secureDirectory(filepath.Dir(identityFile)) != nil {
		return empty, ErrIdentity
	}
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
	if err != nil || ValidateCRLAdvance(ca, floor, crl, now) != nil {
		return empty, ErrRevocation
	}
	var result NodeRecoveryRequest
	err = WithIdentitySnapshot(ctx, filepath.Dir(identityFile), func() error {
		b, record, err := ReadIdentity(caFile, identityFile, Node, expected.Node, now)
		defer clear(b.Key)
		if err != nil || record.CertificateSHA256 == expected.CertificateSHA256 {
			return ErrIdentity
		}
		pending, err := renewalPending(filepath.Dir(identityFile), expected.CertificateSHA256)
		if err != nil {
			return err
		}
		renewal, key, err := readNodeRenewal(pending, ca, expected.Node, expected.CertificateSHA256, now)
		clear(key)
		if err != nil {
			return ErrIdentity
		}
		leaf, err := recoverySuccessor(ca, crl, renewal, certificate, now)
		if err != nil || record.CertificateSHA256 != publicSHA(leaf.Raw) {
			return ErrIdentity
		}
		block, _ := pem.Decode(b.Key)
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
		r := NodeRecoveryRequest{Format: 1, Kind: recoveryContinuationKind, Intent: expected, Renewal: renewal, ContinuationCertificate: append([]byte{}, certificate...)}
		payload, err := recoveryProofPayload(r)
		if err != nil {
			return err
		}
		r.Proof = ed25519.Sign(private, payload)
		if err := ValidateNodeRecoveryRequest(ca, crl, r, expected, now); err != nil {
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
