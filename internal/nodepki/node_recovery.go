package nodepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"reflect"
	"time"
)

// NodeRecoveryIntent is public, but not self-authorizing. The controller must
// persist it against the actor, node/config version, pinned SSH host and current
// runtime before sending it. A network renewal request cannot opt into recovery.
type NodeRecoveryIntent struct {
	Format            int       `json:"format"`
	Node              string    `json:"node"`
	AuthoritySHA256   string    `json:"authority_sha256"`
	CertificateSHA256 string    `json:"certificate_sha256"`
	Challenge         string    `json:"challenge"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// NodeRecoveryRequest contains no private key. The expired parent signs the
// initial recovery; continuation uses the already active successor in a
// separate domain. Both retain the original CSR proof and bind the request
// to one short-lived, controller-issued SSH recovery intent.
type NodeRecoveryRequest struct {
	Format                  int                `json:"format"`
	Kind                    string             `json:"kind"`
	Intent                  NodeRecoveryIntent `json:"intent"`
	Renewal                 NodeRenewalRequest `json:"renewal"`
	Proof                   []byte             `json:"proof"`
	ContinuationCertificate []byte             `json:"continuation_certificate,omitempty"`
}

const recoveryKind = "ssh-expired-identity"
const recoveryContinuationKind = "ssh-recovery-continuation"

func recoverySHA(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func validRecoveryIntent(i NodeRecoveryIntent, now time.Time) bool {
	_, err := Identity(Node, i.Node)
	return err == nil && i.Format == 1 && recoverySHA(i.AuthoritySHA256) && recoverySHA(i.CertificateSHA256) && recoverySHA(i.Challenge) &&
		!i.IssuedAt.IsZero() && !i.IssuedAt.After(now) && now.Before(i.ExpiresAt) && i.ExpiresAt.After(i.IssuedAt) && i.ExpiresAt.Sub(i.IssuedAt) <= 10*time.Minute
}

func sameRecoveryIntent(a, b NodeRecoveryIntent) bool {
	return a.Format == b.Format && a.Node == b.Node && a.AuthoritySHA256 == b.AuthoritySHA256 && a.CertificateSHA256 == b.CertificateSHA256 && a.Challenge == b.Challenge && a.IssuedAt.Equal(b.IssuedAt) && a.ExpiresAt.Equal(b.ExpiresAt)
}

// NewNodeRecoveryIntent creates a ten-minute challenge. This does not persist
// or authorize it; the caller must commit its guarded intent before SSH use.
func NewNodeRecoveryIntent(node, authoritySHA, parentSHA string, now time.Time) (NodeRecoveryIntent, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return NodeRecoveryIntent{}, ErrIdentity
	}
	i := NodeRecoveryIntent{1, node, authoritySHA, parentSHA, hex.EncodeToString(nonce[:]), now.UTC(), now.UTC().Add(10 * time.Minute)}
	if !validRecoveryIntent(i, now) {
		return NodeRecoveryIntent{}, ErrIdentity
	}
	return i, nil
}

func recoveryProofPayload(r NodeRecoveryRequest) ([]byte, error) {
	r.Proof = nil
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRenewalBytes {
		return nil, ErrIdentity
	}
	domain := "webscan-v3/node-ssh-recovery-proof/v1\x00"
	if r.Kind == recoveryContinuationKind {
		domain = "webscan-v3/node-ssh-recovery-continuation-proof/v1\x00"
	}
	return append([]byte(domain), raw...), nil
}

func (r NodeRecoveryRequest) SHA256() string {
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRenewalBytes {
		return ""
	}
	return publicSHA(raw)
}

func ParseNodeRecoveryRequest(raw []byte) (NodeRecoveryRequest, error) {
	var r NodeRecoveryRequest
	if len(raw) == 0 || len(raw) > MaxRenewalBytes || json.Unmarshal(raw, &r) != nil {
		return NodeRecoveryRequest{}, ErrIdentity
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) || r.Format != 1 || (r.Kind != recoveryKind && r.Kind != recoveryContinuationKind) || r.SHA256() == "" || r.Kind == recoveryKind && len(r.ContinuationCertificate) != 0 || r.Kind == recoveryContinuationKind && (len(r.ContinuationCertificate) == 0 || len(r.ContinuationCertificate) > 16<<10) {
		return NodeRecoveryRequest{}, ErrIdentity
	}
	return r, nil
}

// The historical chain and key proof are checked separately. In particular we
// do not validate a current CRL at an old date, or let expiry bypass revocation.
func recoveryParentTrust(ca, crl []byte, old *x509.Certificate, now time.Time) error {
	if old == nil || now.Before(old.NotAfter) {
		return ErrIdentity
	}
	t, err := NewTrust(ca, crl, now)
	if err != nil {
		return err
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.revoked[old.SerialNumber.String()] {
		return ErrRevocation
	}
	return nil
}

// ValidateNodeRecoveryParent is an offline public precheck before issuing a
// challenge. This is not proof of key possession or authority to recover; the
// complete request and durable administrator intent are checked separately.
func ValidateNodeRecoveryParent(ca, crl, certificate []byte, id string, now time.Time) error {
	root, err := parseCertificate(ca)
	if err != nil || !validAuthority(root, now) {
		return ErrIdentity
	}
	old, err := parseCertificate(certificate)
	if err != nil || old.IsCA || len(old.ExtKeyUsage) != 1 || old.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || now.Before(old.NotBefore) || now.Before(old.NotAfter) || old.NotAfter.After(root.NotAfter) || old.NotAfter.Sub(old.NotBefore) > 90*24*time.Hour+5*time.Minute || len(old.DNSNames)+len(old.IPAddresses) < 1 || len(old.DNSNames)+len(old.IPAddresses) > 16 {
		return ErrIdentity
	}
	actual, err := PeerID(old, Node)
	if err != nil || actual != id {
		return ErrIdentity
	}
	if _, ok := old.PublicKey.(ed25519.PublicKey); !ok {
		return ErrIdentity
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := old.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: old.NotAfter.Add(-time.Second), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return ErrIdentity
	}
	return recoveryParentTrust(ca, crl, old, now)
}

// ValidateNodeRecoveryRequest requires a separately retrieved durable intent;
// echoing the request's own intent is not controller authorization. It never
// relaxes Trust.Verify or the normal online renewal validation path.
func ValidateNodeRecoveryRequest(ca, crl []byte, r NodeRecoveryRequest, expected NodeRecoveryIntent, now time.Time) error {
	if r.Format != 1 || (r.Kind != recoveryKind && r.Kind != recoveryContinuationKind) || !sameRecoveryIntent(r.Intent, expected) || !validRecoveryIntent(expected, now) || len(r.Proof) != ed25519.SignatureSize || r.SHA256() == "" || r.Renewal.Node != expected.Node || r.Renewal.AuthoritySHA256 != expected.AuthoritySHA256 || r.Renewal.CertificateSHA256 != expected.CertificateSHA256 || r.Kind == recoveryKind && len(r.ContinuationCertificate) != 0 {
		return ErrIdentity
	}
	old, _, err := validateNodeRenewal(ca, r.Renewal, now, true)
	if err != nil {
		return err
	}
	public, ok := old.PublicKey.(ed25519.PublicKey)
	if r.Kind == recoveryContinuationKind {
		leaf, err := recoverySuccessor(ca, crl, r.Renewal, r.ContinuationCertificate, now)
		if err != nil {
			return err
		}
		public, ok = leaf.PublicKey.(ed25519.PublicKey)
	}
	payload, err := recoveryProofPayload(r)
	if !ok || err != nil || !ed25519.Verify(public, payload, r.Proof) {
		return ErrIdentity
	}
	return recoveryParentTrust(ca, crl, old, now)
}

// PrepareNodeRecovery is only for a root-owned, pinned-SSH helper. The current
// signed CRL must additionally be advanced against the node's durable floor by
// that helper. No private key leaves this function or the node's state files.
func PrepareNodeRecovery(ctx context.Context, caFile, identityFile string, crl []byte, intent NodeRecoveryIntent, now time.Time) (NodeRecoveryRequest, error) {
	var empty NodeRecoveryRequest
	if !validRecoveryIntent(intent, now) {
		return empty, ErrIdentity
	}
	b, record, err := readIdentity(caFile, identityFile, Node, intent.Node, now, true)
	defer clear(b.Key)
	if err != nil || record.CertificateSHA256 != intent.CertificateSHA256 {
		return empty, ErrIdentity
	}
	root, err := parseCertificate(b.CA)
	if err != nil || publicSHA(root.Raw) != intent.AuthoritySHA256 {
		return empty, ErrIdentity
	}
	old, err := parseCertificate(b.Certificate)
	if err != nil {
		return empty, ErrIdentity
	}
	if err = recoveryParentTrust(b.CA, crl, old, now); err != nil {
		return empty, err
	}
	renewal, err := prepareNodeRenewal(ctx, caFile, identityFile, intent.Node, intent.CertificateSHA256, now, true)
	if err != nil || !bytes.Equal(renewal.Certificate, b.Certificate) {
		return empty, ErrIdentity
	}
	r := NodeRecoveryRequest{Format: 1, Kind: recoveryKind, Intent: intent, Renewal: renewal}
	block, _ := pem.Decode(b.Key)
	if block == nil {
		return empty, ErrIdentity
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return empty, ErrIdentity
	}
	defer clear(private)
	payload, err := recoveryProofPayload(r)
	if err != nil {
		return empty, err
	}
	r.Proof = ed25519.Sign(private, payload)
	if err := ValidateNodeRecoveryRequest(b.CA, crl, r, intent, now); err != nil {
		return empty, err
	}
	return r, nil
}

// SignNodeRecoveryRegistered is a distinct offline issuance primitive, not an
// RPC. The controller must recheck its actor/version/SSH/registry/lease guards
// and atomically persist the public issuance in accept before delivery. The
// newest authority CRL is checked again under its lock, even if a relay already
// validated the request. The node-owned CSR key never reaches the issuer.
func SignNodeRecoveryRegistered(ctx context.Context, directory string, r NodeRecoveryRequest, expected NodeRecoveryIntent, now time.Time, lifetime time.Duration, accept func(Bundle, []byte) error) error {
	// A continuation proves the already issued identity, never permission to
	// issue another leaf. Its controller path may only replay the SQL ledger.
	if r.Kind != recoveryKind || !sameRecoveryIntent(r.Intent, expected) || !validRecoveryIntent(expected, now) {
		return ErrIdentity
	}
	return signNodeRenewalRegistered(ctx, directory, r.Renewal, now, lifetime, &r, accept)
}

// PublishNodeRecoveryTrust advances an EXISTING node trust floor during the
// explicitly authorized SSH recovery. It neither initializes missing state nor
// changes its CA pin. Online receivers do not call this method; they continue
// to authenticate a current allowlisted collector with ReceiverTrust.Publish.
// Replaying the same valid recovery is safe, but cannot lower a newer floor or
// remove revocations even when the previously accepted CRL has expired.
func PublishNodeRecoveryTrust(ctx context.Context, caFile, directory string, raw []byte, r NodeRecoveryRequest, expected NodeRecoveryIntent, now time.Time) (CRLReceipt, error) {
	var empty CRLReceipt
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || secureDirectory(directory) != nil {
		return empty, ErrRevocation
	}
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return empty, ErrIdentity
	}
	if err := ValidateNodeRecoveryRequest(ca, raw, r, expected, now); err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	lock, err := authorityLock(ctx, directory)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	pinned, err := readIdentityFile(filepath.Join(directory, "ca.crt"), 64<<10, true)
	if err != nil {
		return empty, ErrIdentity
	}
	root, err := parseCertificate(ca)
	if err != nil {
		return empty, ErrIdentity
	}
	previous, err := parseCertificate(pinned)
	if err != nil || !bytes.Equal(previous.Raw, root.Raw) {
		return empty, ErrIdentity
	}
	floor, err := readIdentityFile(filepath.Join(directory, "ca.crl"), MaxCRLBytes, true)
	if err != nil || ValidateCRLAdvance(ca, floor, raw, now) != nil {
		return empty, ErrRevocation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if !bytes.Equal(floor, raw) {
		if err := replaceCRL(directory, raw); err != nil {
			return empty, err
		}
	}
	list, _ := parseCRL(raw, root) // signed, current and monotonic above
	return CRLReceipt{publicSHA(raw), list.Number.Text(10), list.NextUpdate}, nil
}

// ActivateNodeRecovery rechecks the intent and CURRENT durable trust policy,
// including parent revocation, immediately before the ordinary local-key CAS.
// Keep the trust lock through publication so another process cannot advance
// the floor between authorization and activation. Trust and identity use
// distinct private directories; missing state is never initialized here.
func ActivateNodeRecovery(ctx context.Context, caFile, identityFile, trustDirectory string, r NodeRecoveryRequest, expected NodeRecoveryIntent, certificate []byte, now time.Time) (IdentityRecord, error) {
	var empty IdentityRecord
	if len(r.ContinuationCertificate) != 0 && !bytes.Equal(r.ContinuationCertificate, certificate) {
		return empty, ErrIdentity
	}
	if !filepath.IsAbs(trustDirectory) || filepath.Clean(trustDirectory) != trustDirectory || trustDirectory == filepath.Dir(identityFile) || secureDirectory(trustDirectory) != nil {
		return empty, ErrRevocation
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
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
	if err != nil {
		return empty, ErrIdentity
	}
	root, err := parseCertificate(ca)
	if err != nil {
		return empty, ErrIdentity
	}
	prior, err := parseCertificate(pinned)
	if err != nil || !bytes.Equal(root.Raw, prior.Raw) {
		return empty, ErrIdentity
	}
	crl, err := readIdentityFile(filepath.Join(trustDirectory, "ca.crl"), MaxCRLBytes, true)
	if err != nil {
		return empty, ErrRevocation
	}
	if err := ValidateNodeRecoveryRequest(ca, crl, r, expected, now); err != nil {
		return empty, err
	}
	trust, err := NewTrust(ca, crl, now)
	if err != nil {
		return empty, err
	}
	return ActivateNodeRenewal(ctx, caFile, identityFile, expected.Node, expected.CertificateSHA256, r.Renewal.SHA256(), certificate, now, func(cert *x509.Certificate) error {
		return trust.Verify(cert, Node, expected.Node, now)
	})
}

// WithRecoveredNodeIdentity authorizes a fixed service start only after the
// issued recovery identity is already active. It never activates a candidate.
// Keep the trust and identity locks in publication order until the callback
// returns, so revocation/rotation cannot race the local service operation. The
// callback must not acquire either lock or wait for Agent RPC readiness.
func WithRecoveredNodeIdentity(ctx context.Context, caFile, identityFile, trustDirectory string, r NodeRecoveryRequest, expected NodeRecoveryIntent, certificate []byte, now time.Time, use func(IdentityRecord) error) error {
	if len(r.ContinuationCertificate) != 0 && !bytes.Equal(r.ContinuationCertificate, certificate) {
		return ErrIdentity
	}
	if use == nil || len(certificate) == 0 || len(certificate) > 16<<10 || !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile || !filepath.IsAbs(trustDirectory) || filepath.Clean(trustDirectory) != trustDirectory || trustDirectory == filepath.Dir(identityFile) || secureDirectory(trustDirectory) != nil || secureDirectory(filepath.Dir(identityFile)) != nil {
		return ErrIdentity
	}
	lock, err := authorityLock(ctx, trustDirectory)
	if err != nil {
		return err
	}
	defer lock.Close()
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return ErrIdentity
	}
	pinned, err := readIdentityFile(filepath.Join(trustDirectory, "ca.crt"), 64<<10, true)
	if err != nil || !bytes.Equal(bytes.TrimSpace(ca), bytes.TrimSpace(pinned)) {
		return ErrIdentity
	}
	crl, err := readIdentityFile(filepath.Join(trustDirectory, "ca.crl"), MaxCRLBytes, true)
	if err != nil || ValidateNodeRecoveryRequest(ca, crl, r, expected, now) != nil {
		return ErrRevocation
	}
	return WithIdentitySnapshot(ctx, filepath.Dir(identityFile), func() error {
		b, record, err := ReadIdentity(caFile, identityFile, Node, expected.Node, now)
		defer clear(b.Key)
		if err != nil {
			return ErrIdentity
		}
		leaf, err := parseCertificate(certificate)
		if err != nil || record.CertificateSHA256 != publicSHA(leaf.Raw) {
			return ErrIdentity
		}
		_, csr, err := validateNodeRenewal(ca, r.Renewal, now, true)
		if err != nil || !reflect.DeepEqual(leaf.PublicKey, csr.PublicKey) || !reflect.DeepEqual(leaf.DNSNames, csr.DNSNames) || !reflect.DeepEqual(leaf.IPAddresses, csr.IPAddresses) {
			return ErrIdentity
		}
		trust, err := NewTrust(ca, crl, now)
		if err != nil || trust.Verify(leaf, Node, expected.Node, now) != nil {
			return ErrRevocation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return use(record)
	})
}
