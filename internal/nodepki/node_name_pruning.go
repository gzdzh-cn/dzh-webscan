package nodepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// NodeNamePruningIntent is a separate, short-lived authorization to remove
// unused SANs. The controller must derive Names from the APPLIED runtime and
// every still-required recovery configuration, then durably bind this intent
// to the actor, configuration, credential and node lease. Request-supplied
// Names/ConfigurationSHA256/RuntimeEpoch are never evidence of that authority.
// This primitive is deliberately not reachable through ordinary renewal.
type NodeNamePruningIntent struct {
	Format              int       `json:"format"`
	Node                string    `json:"node"`
	AuthoritySHA256     string    `json:"authority_sha256"`
	CertificateSHA256   string    `json:"certificate_sha256"`
	ConfigurationSHA256 string    `json:"configuration_sha256"`
	RuntimeEpoch        int64     `json:"runtime_epoch"`
	ActiveName          string    `json:"active_name"`
	Names               []string  `json:"names"`
	Challenge           string    `json:"challenge"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type NodeNamePruningRequest struct {
	Format                  int                   `json:"format"`
	Kind                    string                `json:"kind"`
	Intent                  NodeNamePruningIntent `json:"intent"`
	Certificate             []byte                `json:"certificate"`
	CSR                     []byte                `json:"csr"`
	Proof                   []byte                `json:"proof"`
	OriginalRequest         json.RawMessage       `json:"original_request,omitempty"`
	ContinuationCertificate []byte                `json:"continuation_certificate,omitempty"`
}

const namePruningKind = "ssh-node-name-pruning"
const namePruningContinuationKind = "ssh-node-name-pruning-continuation"
const namePruningReconciliationKind = "ssh-node-name-pruning-pending"

func validNamePruningIntent(i NodeNamePruningIntent, now time.Time) bool {
	if _, err := Identity(Node, i.Node); err != nil || i.Format != 1 || !recoverySHA(i.AuthoritySHA256) || !recoverySHA(i.CertificateSHA256) || !recoverySHA(i.ConfigurationSHA256) || i.RuntimeEpoch < 1 || !canonicalPruningNames(i.ActiveName, i.Names) || !recoverySHA(i.Challenge) || i.IssuedAt.IsZero() || i.IssuedAt.After(now) || !now.Before(i.ExpiresAt) || !i.ExpiresAt.After(i.IssuedAt) || i.ExpiresAt.Sub(i.IssuedAt) > 10*time.Minute {
		return false
	}
	return true
}

func canonicalPruningNames(active string, names []string) bool {
	if !canonicalServerName(active) || len(names) == 0 || len(names) >= 16 || !slices.IsSorted(names) || !slices.Contains(names, active) {
		return false
	}
	for n, name := range names {
		if !canonicalServerName(name) || n > 0 && name == names[n-1] {
			return false
		}
	}
	return true
}

func NewNodeNamePruningIntent(node, authority, parent, configuration string, epoch int64, active string, names []string, now time.Time) (NodeNamePruningIntent, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return NodeNamePruningIntent{}, err
	}
	i := NodeNamePruningIntent{1, node, authority, parent, configuration, epoch, active, slices.Clone(names), hex.EncodeToString(nonce[:]), now.UTC(), now.UTC().Add(10 * time.Minute)}
	if !validNamePruningIntent(i, now) {
		return NodeNamePruningIntent{}, ErrIdentity
	}
	return i, nil
}

func (i NodeNamePruningIntent) SHA256() string {
	raw, err := json.Marshal(i)
	if err != nil {
		return ""
	}
	return publicSHA(append([]byte("webscan-v3/node-name-pruning-intent/v1\x00"), raw...))
}

func (r NodeNamePruningRequest) SHA256() string {
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRenewalBytes {
		return ""
	}
	return publicSHA(raw)
}

func namePruningProof(r NodeNamePruningRequest) ([]byte, error) {
	r.Proof = nil
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRenewalBytes {
		return nil, ErrIdentity
	}
	domain := "webscan-v3/node-name-pruning-proof/v1\x00"
	if r.Kind == namePruningContinuationKind {
		domain = "webscan-v3/node-name-pruning-continuation-proof/v1\x00"
	} else if r.Kind == namePruningReconciliationKind {
		domain = "webscan-v3/node-name-pruning-pending-proof/v1\x00"
	}
	return append([]byte(domain), raw...), nil
}

func ParseNodeNamePruningRequest(raw []byte) (NodeNamePruningRequest, error) {
	var r NodeNamePruningRequest
	if len(raw) == 0 || len(raw) > MaxRenewalBytes || json.Unmarshal(raw, &r) != nil {
		return NodeNamePruningRequest{}, ErrIdentity
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) || r.Format != 1 || (r.Kind != namePruningKind && r.Kind != namePruningContinuationKind && r.Kind != namePruningReconciliationKind) || len(r.Certificate) == 0 || len(r.Certificate) > 16<<10 || len(r.CSR) == 0 || len(r.CSR) > 16<<10 || len(r.Proof) != ed25519.SignatureSize {
		return NodeNamePruningRequest{}, ErrIdentity
	}
	if r.Kind == namePruningKind && (len(r.OriginalRequest) != 0 || len(r.ContinuationCertificate) != 0) || r.Kind != namePruningKind && (len(r.OriginalRequest) == 0 || len(r.ContinuationCertificate) == 0 || len(r.ContinuationCertificate) > 16<<10) {
		return NodeNamePruningRequest{}, ErrIdentity
	}
	return r, nil
}

// Keep the original SAN ordering so the exact subset is unambiguous. No
// wildcard expansion, DNS/IP aliasing, addition or identity change is allowed.
func namePruningTemplate(old *x509.Certificate, names []string) (*x509.Certificate, error) {
	if old == nil || len(old.DNSNames)+len(old.IPAddresses) > 16 || len(names) == 0 || len(names) >= len(old.DNSNames)+len(old.IPAddresses) {
		return nil, ErrIdentity
	}
	next := *old
	next.DNSNames, next.IPAddresses = nil, nil
	seen := map[string]bool{}
	for _, name := range old.DNSNames {
		if !canonicalServerName(name) || net.ParseIP(name) != nil || seen[name] {
			return nil, ErrIdentity
		}
		seen[name] = true
		if slices.Contains(names, name) {
			next.DNSNames = append(next.DNSNames, name)
		}
	}
	for _, ip := range old.IPAddresses {
		name := ip.String()
		if !canonicalServerName(name) || seen[name] {
			return nil, ErrIdentity
		}
		seen[name] = true
		if slices.Contains(names, name) {
			next.IPAddresses = append(next.IPAddresses, append(net.IP(nil), ip...))
		}
	}
	if len(next.DNSNames)+len(next.IPAddresses) != len(names) {
		return nil, ErrIdentity
	}
	return &next, nil
}

// ValidateNodeNamePruningScope is a pure subset/format check for controller
// planning. It does not authenticate a certificate, actor or runtime, nor
// produce an authorization, request, challenge or private key.
func ValidateNodeNamePruningScope(certificate []byte, active string, names []string) error {
	if len(certificate) == 0 || len(certificate) > 16<<10 || !canonicalPruningNames(active, names) {
		return ErrIdentity
	}
	old, err := parseCertificate(certificate)
	if err != nil || old.VerifyHostname(active) != nil {
		return ErrIdentity
	}
	_, err = namePruningTemplate(old, names)
	return err
}

func validateNamePruning(ca, crl []byte, r NodeNamePruningRequest, expected NodeNamePruningIntent, now time.Time) (*x509.Certificate, *x509.CertificateRequest, error) {
	if r.Kind == namePruningContinuationKind || r.Kind == namePruningReconciliationKind {
		return validateNamePruningContinuation(ca, crl, r, expected, now)
	}
	return validateNamePruningInitial(ca, crl, r, expected, now, false)
}

func validateNamePruningInitial(ca, crl []byte, r NodeNamePruningRequest, expected NodeNamePruningIntent, now time.Time, historical bool) (*x509.Certificate, *x509.CertificateRequest, error) {
	checkedAt := now
	if historical {
		checkedAt = expected.IssuedAt
		if checkedAt.After(now) {
			return nil, nil, ErrIdentity
		}
	}
	if !validNamePruningIntent(expected, checkedAt) || r.Intent.SHA256() != expected.SHA256() || r.Format != 1 || r.Kind != namePruningKind || len(r.OriginalRequest) != 0 || len(r.ContinuationCertificate) != 0 || r.SHA256() == "" || len(r.Certificate) == 0 || len(r.Certificate) > 16<<10 || len(r.Proof) != ed25519.SignatureSize {
		return nil, nil, ErrIdentity
	}
	root, err := parseCertificate(ca)
	if err != nil || !validAuthority(root, now) || publicSHA(root.Raw) != expected.AuthoritySHA256 {
		return nil, nil, ErrIdentity
	}
	old, err := parseCertificate(r.Certificate)
	if err != nil || publicSHA(old.Raw) != expected.CertificateSHA256 || old.IsCA || len(old.ExtKeyUsage) != 1 || old.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || old.NotAfter.Sub(old.NotBefore) > 90*24*time.Hour+5*time.Minute || old.NotAfter.After(root.NotAfter) || old.VerifyHostname(expected.ActiveName) != nil {
		return nil, nil, ErrIdentity
	}
	trust, err := NewTrust(ca, crl, now)
	if err != nil || verifyNameChangeParent(trust, root, old, expected.Node, checkedAt, historical) != nil {
		return nil, nil, ErrRevocation
	}
	key, ok := old.PublicKey.(ed25519.PublicKey)
	payload, err := namePruningProof(r)
	if err != nil || !ok || !ed25519.Verify(key, payload, r.Proof) {
		return nil, nil, ErrIdentity
	}
	target, err := namePruningTemplate(old, expected.Names)
	if err != nil {
		return nil, nil, err
	}
	csr, err := canonicalNodeCSR(r.CSR, expected.Node, target)
	return old, csr, err
}

func ValidateNodeNamePruningRequest(ca, crl []byte, r NodeNamePruningRequest, expected NodeNamePruningIntent, now time.Time) error {
	_, _, err := validateNamePruning(ca, crl, r, expected, now)
	return err
}

func namePruningPending(identity string, i NodeNamePruningIntent) string {
	return filepath.Join(filepath.Dir(identity), "name-prunings", i.SHA256())
}

func readNamePruningPending(dir string, ca, crl []byte, i NodeNamePruningIntent, now time.Time) (NodeNamePruningRequest, []byte, error) {
	return readNamePruningPendingAt(dir, ca, crl, i, now, false)
}

func readNamePruningPendingAt(dir string, ca, crl []byte, i NodeNamePruningIntent, now time.Time, historical bool) (NodeNamePruningRequest, []byte, error) {
	var empty NodeNamePruningRequest
	if secureDirectory(dir) != nil {
		return empty, nil, ErrIdentity
	}
	raw, err := readIdentityFile(filepath.Join(dir, "request.json"), MaxRenewalBytes, true)
	if err != nil {
		return empty, nil, ErrIdentity
	}
	r, err := ParseNodeNamePruningRequest(raw)
	if err != nil {
		return empty, nil, err
	}
	_, csr, err := validateNamePruningInitial(ca, crl, r, i, now, historical)
	if err != nil {
		return empty, nil, err
	}
	rawKey, err := readIdentityFile(filepath.Join(dir, "key.pem"), 4096, true)
	if err != nil {
		return empty, nil, ErrIdentity
	}
	reject := func() (NodeNamePruningRequest, []byte, error) { clear(rawKey); return empty, nil, ErrIdentity }
	block, tail := pem.Decode(rawKey)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(tail)) != 0 {
		return reject()
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	defer clear(key)
	if err != nil || !ok || !bytes.Equal(key.Public().(ed25519.PublicKey), csr.PublicKey.(ed25519.PublicKey)) {
		return reject()
	}
	return r, rawKey, nil
}

// Prepare stores one local key/CSR per exact intent. It never repairs partial
// state by minting a replacement key, changes the active leaf or contacts CA.
func PrepareNodeNamePruning(ctx context.Context, caFile, identityFile, trustDirectory string, i NodeNamePruningIntent, now time.Time) (NodeNamePruningRequest, error) {
	var out NodeNamePruningRequest
	if !validNamePruningIntent(i, now) || !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile || filepath.Dir(identityFile) == trustDirectory || secureDirectory(filepath.Dir(identityFile)) != nil {
		return out, ErrIdentity
	}
	ctx, cancel := context.WithDeadline(ctx, i.ExpiresAt)
	defer cancel()
	ctx, finish := context.WithTimeout(ctx, 5*time.Second)
	defer finish()
	err := nameChangeTrust(ctx, caFile, trustDirectory, i.AuthoritySHA256, now, func(ca, crl []byte) error {
		lock, err := authorityLock(ctx, filepath.Dir(identityFile))
		if err != nil {
			return err
		}
		defer lock.Close()
		active, record, err := ReadIdentityWithRootState(caFile, identityFile, trustDirectory, Node, i.Node, now)
		defer clear(active.Key)
		if err != nil || record.CertificateSHA256 != i.CertificateSHA256 {
			return ErrIdentity
		}
		pending := namePruningPending(identityFile, i)
		if _, err := os.Lstat(pending); !os.IsNotExist(err) {
			r, key, err := readNamePruningPending(pending, ca, crl, i, now)
			clear(key)
			out = r
			return err
		}
		old, err := parseCertificate(active.Certificate)
		if err != nil {
			return err
		}
		target, err := namePruningTemplate(old, i.Names)
		if err != nil {
			return err
		}
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		defer clear(key)
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: Node + ":" + i.Node}, URIs: old.URIs, DNSNames: target.DNSNames, IPAddresses: target.IPAddresses}, key)
		if err != nil {
			return ErrIdentity
		}
		r := NodeNamePruningRequest{Format: 1, Kind: namePruningKind, Intent: i, Certificate: active.Certificate, CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})}
		block, _ := pem.Decode(active.Key)
		if block == nil {
			return ErrIdentity
		}
		defer clear(block.Bytes)
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		prior, ok := parsed.(ed25519.PrivateKey)
		defer clear(prior)
		if err != nil || !ok {
			return ErrIdentity
		}
		payload, err := namePruningProof(r)
		if err != nil {
			return err
		}
		r.Proof = ed25519.Sign(prior, payload)
		if err := ValidateNodeNamePruningRequest(ca, crl, r, i, now); err != nil {
			return err
		}
		encoded, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return ErrIdentity
		}
		defer clear(encoded)
		rawKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
		defer clear(rawKey)
		raw, _ := json.Marshal(r)
		parent := filepath.Dir(pending)
		if err := os.Mkdir(parent, 0700); err != nil && !os.IsExist(err) {
			return errStorage
		}
		if secureDirectory(parent) != nil {
			return errStorage
		}
		stage, err := os.MkdirTemp(parent, ".name-pruning-*")
		if err != nil {
			return errStorage
		}
		defer os.RemoveAll(stage)
		for name, data := range map[string][]byte{"request.json": raw, "key.pem": rawKey} {
			if err := writeExclusive(filepath.Join(stage, name), data); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if syncDir(stage) != nil || identityRenameNoReplace(stage, pending) != nil || syncDir(parent) != nil {
			return errStorage
		}
		out = r
		return nil
	})
	if err != nil {
		return NodeNamePruningRequest{}, err
	}
	if err := ctx.Err(); err != nil {
		return NodeNamePruningRequest{}, err
	}
	return out, nil
}

// The callback must commit a unique parent-successor issuance in the shared
// ledger BEFORE delivery. This function is not a queue, authorization service
// or retry endpoint, and it deliberately accepts no expired-intent exception.
func SignNodeNamePruningRegistered(ctx context.Context, directory string, r NodeNamePruningRequest, expected NodeNamePruningIntent, now time.Time, lifetime time.Duration, accept func(Bundle, []byte) error) error {
	if accept == nil || r.Kind != namePruningKind || len(r.OriginalRequest) != 0 || len(r.ContinuationCertificate) != 0 || !validNamePruningIntent(expected, now) || lifetime < time.Hour || lifetime > 90*24*time.Hour || secureDirectory(directory) != nil {
		return ErrIdentity
	}
	ctx, cancel := context.WithDeadline(ctx, expected.ExpiresAt)
	defer cancel()
	ctx, finish := context.WithTimeout(ctx, 5*time.Second)
	defer finish()
	lock, err := authorityLock(ctx, directory)
	if err != nil {
		return err
	}
	defer lock.Close()
	a, err := loadMaintenanceAuthority(directory, now)
	if err != nil {
		return err
	}
	defer clear(a.key)
	crl, _, err := latestCRL(directory, a)
	if err != nil {
		return err
	}
	ca := certificatePEM(a.certificate)
	old, csr, err := validateNamePruning(ca, crl, r, expected, now)
	if err != nil {
		return err
	}
	if !now.Add(lifetime).After(old.NotAfter) || now.Add(lifetime).After(a.certificate.NotAfter) {
		return ErrIdentity
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: Node + ":" + expected.Node}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(lifetime), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, URIs: csr.URIs, DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses}
	if template.NotBefore.Before(a.certificate.NotBefore) {
		template.NotBefore = a.certificate.NotBefore
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, csr.PublicKey, a.key)
	if err != nil {
		return ErrIdentity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := accept(Bundle{CA: ca, Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, crl); err != nil {
		return err
	}
	return ctx.Err()
}

func ValidateNodeNamePruningCertificate(ca, crl []byte, r NodeNamePruningRequest, expected NodeNamePruningIntent, certificate []byte, now time.Time) error {
	old, csr, err := validateNamePruning(ca, crl, r, expected, now)
	if err != nil || len(certificate) == 0 || len(certificate) > 16<<10 {
		return ErrIdentity
	}
	if r.Kind != namePruningKind && !bytes.Equal(certificate, r.ContinuationCertificate) {
		return ErrIdentity
	}
	return validateNameChangeLeaf(ca, crl, old, csr, expected.Node, certificate, now)
}

// Retain the former private identity and activate the node-held CSR key. No
// configuration, CA, listener or service is changed. Retired names cease to
// work on NEW TLS connections; existing connections need normal revalidation.
func ActivateNodeNamePruning(ctx context.Context, caFile, identityFile, trustDirectory string, r NodeNamePruningRequest, expected NodeNamePruningIntent, certificate []byte, now time.Time) (IdentityRecord, error) {
	var out IdentityRecord
	if !validNamePruningIntent(expected, now) || !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile || filepath.Dir(identityFile) == trustDirectory || len(certificate) == 0 || len(certificate) > 16<<10 {
		return out, ErrIdentity
	}
	if r.Kind == namePruningContinuationKind {
		err := WithPrunedNodeIdentity(ctx, caFile, identityFile, trustDirectory, r, expected, certificate, now, func(_ context.Context, record IdentityRecord) error { out = record; return nil })
		return out, err
	}
	ctx, cancel := context.WithDeadline(ctx, expected.ExpiresAt)
	defer cancel()
	ctx, finish := context.WithTimeout(ctx, 5*time.Second)
	defer finish()
	err := nameChangeTrust(ctx, caFile, trustDirectory, expected.AuthoritySHA256, now, func(ca, crl []byte) error {
		if err := ValidateNodeNamePruningCertificate(ca, crl, r, expected, certificate, now); err != nil {
			return err
		}
		original, err := namePruningOriginal(r)
		if err != nil {
			return err
		}
		saved, key, err := readNamePruningPendingAt(namePruningPending(identityFile, original.Intent), ca, crl, original.Intent, now, r.Kind != namePruningKind)
		defer clear(key)
		if err != nil || saved.SHA256() != original.SHA256() {
			return ErrIdentity
		}
		out, err = publishIdentityMaterial(ctx, identityFile, "", Node, expected.Node, expected.CertificateSHA256, ca, nil, Bundle{CA: ca, Certificate: certificate, Key: key}, now)
		return err
	})
	if err != nil {
		return IdentityRecord{}, err
	}
	if err := ctx.Err(); err != nil {
		return IdentityRecord{}, err
	}
	return out, nil
}
