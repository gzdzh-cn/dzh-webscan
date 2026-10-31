package nodepki

// Root authorization is separate from CRL renewal and leaf renewal. It binds
// one explicitly approved replacement CA and cannot be used to change an
// identity, SAN, source policy or node configuration.
import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

var ErrRootRotation = errors.New("CA 换根授权、双根信任或确认记录无效；原信任资料未修改")

type RootAuthorization struct {
	Format              int       `json:"format"`
	Rotation            string    `json:"rotation"`
	Phase               string    `json:"phase"`
	AnchorSHA256        string    `json:"anchor_sha256"`
	NewCA               []byte    `json:"new_ca"`
	MembersSHA256       string    `json:"members_sha256"`
	PreviousSHA256      string    `json:"previous_sha256,omitempty"`
	ConfirmationsSHA256 string    `json:"confirmations_sha256,omitempty"`
	IssuedAt            time.Time `json:"issued_at"`
	AnchorSignature     []byte    `json:"anchor_signature"`
	SuccessorSignature  []byte    `json:"successor_signature"`
}

func rootAuthorizationMessage(a RootAuthorization) []byte {
	a.AnchorSignature, a.SuccessorSignature = nil, nil
	raw, _ := json.Marshal(a)
	return append([]byte("webscan-v3/explicit-root-rotation/v1\x00"), raw...)
}

func RootAuthorizationSHA256(a RootAuthorization) string {
	raw, _ := json.Marshal(a)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func RootFingerprint(ca []byte) (string, error) {
	cert, err := parseCertificate(ca)
	if err != nil {
		return "", ErrRootRotation
	}
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:]), nil
}

// Both keys sign the same domain-separated authorization. An exact previous
// dual-root authorization is mandatory for removing the old root. The caller
// must obtain ConfirmationsSHA256 from its committed rollout evidence, never
// from a browser-supplied list of acknowledgements.
func (a *Authority) AuthorizeRootRotation(next *Authority, rotation, members string, previous *RootAuthorization, confirmations string, now time.Time) (RootAuthorization, error) {
	var out RootAuthorization
	if a == nil || next == nil || len(a.key) != ed25519.PrivateKeySize || len(next.key) != ed25519.PrivateKeySize || !validAuthority(a.certificate, now) || !validAuthority(next.certificate, now) || !recoverySHA(rotation) || !recoverySHA(members) || bytes.Equal(a.certificate.Raw, next.certificate.Raw) || bytes.Equal(a.certificate.PublicKey.(ed25519.PublicKey), next.certificate.PublicKey.(ed25519.PublicKey)) {
		return out, ErrRootRotation
	}
	anchor, _ := RootFingerprint(certificatePEM(a.certificate))
	out = RootAuthorization{Format: 1, Rotation: rotation, Phase: "dual", AnchorSHA256: anchor, NewCA: certificatePEM(next.certificate), MembersSHA256: members, IssuedAt: now.UTC().Truncate(time.Second)}
	if previous != nil {
		if VerifyRootAuthorization(certificatePEM(a.certificate), *previous, nil, now, false) != nil || previous.Phase != "dual" || previous.Rotation != rotation || previous.MembersSHA256 != members || !bytes.Equal(previous.NewCA, out.NewCA) || !recoverySHA(confirmations) || now.Before(previous.IssuedAt) {
			return RootAuthorization{}, ErrRootRotation
		}
		out.Phase, out.PreviousSHA256, out.ConfirmationsSHA256 = "new-only", RootAuthorizationSHA256(*previous), confirmations
	} else if confirmations != "" {
		return RootAuthorization{}, ErrRootRotation
	}
	message := rootAuthorizationMessage(out)
	out.AnchorSignature = ed25519.Sign(a.key, message)
	out.SuccessorSignature = ed25519.Sign(next.key, message)
	return out, nil
}

// firstApplication requires fresh explicit authorization; replaying an already
// accepted durable authorization is allowed later, without renewing it. The
// original root remains a historical signature anchor after retirement, never
// an accepted TLS issuer in the new-only phase.
func VerifyRootAuthorization(anchor []byte, a RootAuthorization, previous *RootAuthorization, now time.Time, firstApplication bool) error {
	old, err := parseCertificate(anchor)
	if err != nil || a.Format != 1 || !recoverySHA(a.Rotation) || !recoverySHA(a.MembersSHA256) || a.IssuedAt.IsZero() || a.IssuedAt.After(now) || !validAuthority(old, a.IssuedAt) {
		return ErrRootRotation
	}
	fingerprint, _ := RootFingerprint(anchor)
	next, err := parseCertificate(a.NewCA)
	if err != nil || len(a.NewCA) > 64<<10 || fingerprint != a.AnchorSHA256 || bytes.Equal(old.Raw, next.Raw) || !validAuthority(next, now) || bytes.Equal(old.PublicKey.(ed25519.PublicKey), next.PublicKey.(ed25519.PublicKey)) || a.IssuedAt.Before(next.NotBefore) {
		return ErrRootRotation
	}
	if firstApplication && now.Sub(a.IssuedAt) > 10*time.Minute {
		return ErrRootRotation
	}
	switch a.Phase {
	case "dual":
		if a.PreviousSHA256 != "" || a.ConfirmationsSHA256 != "" || previous != nil {
			return ErrRootRotation
		}
	case "new-only":
		if previous == nil || previous.Phase != "dual" || a.PreviousSHA256 != RootAuthorizationSHA256(*previous) || a.Rotation != previous.Rotation || a.MembersSHA256 != previous.MembersSHA256 || !bytes.Equal(a.NewCA, previous.NewCA) || !recoverySHA(a.ConfirmationsSHA256) || a.IssuedAt.Before(previous.IssuedAt) || VerifyRootAuthorization(anchor, *previous, nil, now, false) != nil {
			return ErrRootRotation
		}
	default:
		return ErrRootRotation
	}
	message := rootAuthorizationMessage(a)
	if !ed25519.Verify(old.PublicKey.(ed25519.PublicKey), message, a.AnchorSignature) || !ed25519.Verify(next.PublicKey.(ed25519.PublicKey), message, a.SuccessorSignature) {
		return ErrRootRotation
	}
	return nil
}

// A complete root-set snapshot carries a separate CRL floor for each issuer.
// Serial numbers are scoped by issuer, so equal serials across roots cannot
// accidentally revoke or authorize one another.
type RootSetSnapshot struct {
	Format int                `json:"format"`
	Dual   RootAuthorization  `json:"dual"`
	Final  *RootAuthorization `json:"final,omitempty"`
	OldCRL []byte             `json:"old_crl"`
	NewCRL []byte             `json:"new_crl"`
}

type RootSet struct {
	roots []*x509.Certificate
	trust []*Trust
	pool  *x509.CertPool
	raw   []byte
}

func NewRootSet(anchor []byte, s RootSetSnapshot, now time.Time) (*RootSet, error) {
	return newRootSet(anchor, s, now, false)
}

// Expired authentic CRLs can furnish TLS issuer keys only for the restricted
// receiver update path. Trust.Verify still checks each RPC at the real time.
func newRootSet(anchor []byte, s RootSetSnapshot, now time.Time, historical bool) (*RootSet, error) {
	if s.Format != 1 || VerifyRootAuthorization(anchor, s.Dual, nil, now, false) != nil {
		return nil, ErrRootRotation
	}
	if s.Final != nil && VerifyRootAuthorization(anchor, *s.Final, &s.Dual, now, false) != nil {
		return nil, ErrRootRotation
	}
	raw, _ := json.Marshal(s)
	p := &RootSet{pool: x509.NewCertPool(), raw: raw}
	add := func(ca, crl []byte) error {
		at := now
		if historical {
			root, err := parseCertificate(ca)
			if err != nil || !validAuthority(root, now) {
				return ErrRootRotation
			}
			list, err := parseCRL(crl, root)
			if err != nil || list.ThisUpdate.After(now) {
				return ErrRootRotation
			}
			at = list.ThisUpdate
		}
		t, err := NewTrust(ca, crl, at)
		if err != nil {
			return ErrRootRotation
		}
		p.roots = append(p.roots, t.ca)
		p.trust = append(p.trust, t)
		p.pool.AddCert(t.ca)
		return nil
	}
	if s.Final == nil {
		if err := add(anchor, s.OldCRL); err != nil {
			return nil, err
		}
	}
	if err := add(s.Dual.NewCA, s.NewCRL); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *RootSet) Verify(cert *x509.Certificate, role, id string, now time.Time) error {
	if p == nil || cert == nil {
		return ErrRootRotation
	}
	for i, root := range p.roots {
		if cert.CheckSignatureFrom(root) == nil {
			return p.trust[i].Verify(cert, role, id, now)
		}
	}
	return ErrIdentity
}

func (p *RootSet) Pool() *x509.CertPool {
	if p == nil {
		return nil
	}
	return p.pool.Clone()
}

// Advancing the root set cannot undo finalization, change the approved CA,
// replace membership or remove either issuer's historical revocations.
func ValidateRootSetAdvance(anchor []byte, previous, next RootSetSnapshot, now time.Time) error {
	return validateRootSetAdvance(anchor, previous, next, now, true)
}

func validateRootSetAdvance(anchor []byte, previous, next RootSetSnapshot, now time.Time, freshAuthorization bool) error {
	if _, err := NewRootSet(anchor, next, now); err != nil {
		return err
	}
	if previous.Format == 0 {
		if next.Final != nil || VerifyRootAuthorization(anchor, next.Dual, nil, now, freshAuthorization) != nil {
			return ErrRootRotation
		}
		return nil
	}
	if previous.Format != 1 || RootAuthorizationSHA256(previous.Dual) != RootAuthorizationSHA256(next.Dual) || previous.Final != nil && (next.Final == nil || RootAuthorizationSHA256(*previous.Final) != RootAuthorizationSHA256(*next.Final)) {
		return ErrRootRotation
	}
	if previous.Final == nil && next.Final != nil && VerifyRootAuthorization(anchor, *next.Final, &previous.Dual, now, freshAuthorization) != nil {
		return ErrRootRotation
	}
	if ValidateCRLAdvance(previous.Dual.NewCA, previous.NewCRL, next.NewCRL, now) != nil {
		return ErrRootRotation
	}
	return rootHistoryAdvance(anchor, previous, next)
}
