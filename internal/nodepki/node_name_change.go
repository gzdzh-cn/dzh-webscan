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
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// NodeNameChangeIntent is not self-authorizing. A controller must persist it
// against the administrator, saved target configuration, original live runtime,
// pinned SSH credential and node lease before sending it. This operation is
// separate from renewal and cannot change the node, CA, role or listener.
type NodeNameChangeIntent struct {
	Format            int       `json:"format"`
	Node              string    `json:"node"`
	AuthoritySHA256   string    `json:"authority_sha256"`
	CertificateSHA256 string    `json:"certificate_sha256"`
	ServerName        string    `json:"server_name"`
	Challenge         string    `json:"challenge"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// Only public material crosses SSH. The new private key is generated and kept
// on the node, in a directory unique to the exact authorized intent.
type NodeNameChangeRequest struct {
	Format                  int                  `json:"format"`
	Kind                    string               `json:"kind"`
	Intent                  NodeNameChangeIntent `json:"intent"`
	Certificate             []byte               `json:"certificate"`
	CSR                     []byte               `json:"csr"`
	Proof                   []byte               `json:"proof"`
	OriginalRequest         json.RawMessage      `json:"original_request,omitempty"`
	ContinuationCertificate []byte               `json:"continuation_certificate,omitempty"`
}

const nameChangeKind = "ssh-node-name-change"
const nameChangeContinuationKind = "ssh-node-name-change-continuation"
const nameChangeReconciliationKind = "ssh-node-name-change-pending"

func canonicalServerName(name string) bool {
	if ip, err := netip.ParseAddr(name); err == nil {
		return ip.Zone() == "" && !ip.Is4In6() && ip.String() == name
	}
	return len(name) > 0 && len(name) <= 253 && name == strings.ToLower(name) && dnsName.MatchString(name)
}

func validNameChangeIntent(i NodeNameChangeIntent, now time.Time) bool {
	_, err := Identity(Node, i.Node)
	return err == nil && i.Format == 1 && recoverySHA(i.AuthoritySHA256) && recoverySHA(i.CertificateSHA256) && canonicalServerName(i.ServerName) && recoverySHA(i.Challenge) && !i.IssuedAt.IsZero() && !i.IssuedAt.After(now) && now.Before(i.ExpiresAt) && i.ExpiresAt.After(i.IssuedAt) && i.ExpiresAt.Sub(i.IssuedAt) <= 10*time.Minute
}

func sameNameChangeIntent(a, b NodeNameChangeIntent) bool {
	return a.Format == b.Format && a.Node == b.Node && a.AuthoritySHA256 == b.AuthoritySHA256 && a.CertificateSHA256 == b.CertificateSHA256 && a.ServerName == b.ServerName && a.Challenge == b.Challenge && a.IssuedAt.Equal(b.IssuedAt) && a.ExpiresAt.Equal(b.ExpiresAt)
}

func NewNodeNameChangeIntent(node, authority, parent, serverName string, now time.Time) (NodeNameChangeIntent, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return NodeNameChangeIntent{}, err
	}
	i := NodeNameChangeIntent{1, node, authority, parent, serverName, hex.EncodeToString(nonce[:]), now.UTC(), now.UTC().Add(10 * time.Minute)}
	if !validNameChangeIntent(i, now) {
		return NodeNameChangeIntent{}, ErrIdentity
	}
	return i, nil
}

func (i NodeNameChangeIntent) SHA256() string {
	raw, err := json.Marshal(i)
	if err != nil {
		return ""
	}
	return publicSHA(raw)
}
func (r NodeNameChangeRequest) SHA256() string {
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRenewalBytes {
		return ""
	}
	return publicSHA(raw)
}
func nameChangeProof(r NodeNameChangeRequest) ([]byte, error) {
	r.Proof = nil
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRenewalBytes {
		return nil, ErrIdentity
	}
	domain := "webscan-v3/node-name-change-proof/v1\x00"
	if r.Kind == nameChangeReconciliationKind {
		domain = "webscan-v3/node-name-change-pending-proof/v1\x00"
	}
	if r.Kind == nameChangeContinuationKind {
		domain = "webscan-v3/node-name-change-continuation-proof/v1\x00"
	}
	return append([]byte(domain), raw...), nil
}
func ParseNodeNameChangeRequest(raw []byte) (NodeNameChangeRequest, error) {
	var r NodeNameChangeRequest
	if len(raw) == 0 || len(raw) > MaxRenewalBytes || json.Unmarshal(raw, &r) != nil {
		return NodeNameChangeRequest{}, ErrIdentity
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, raw) || r.Format != 1 || (r.Kind != nameChangeKind && r.Kind != nameChangeContinuationKind && r.Kind != nameChangeReconciliationKind) || len(r.Certificate) == 0 || len(r.Certificate) > 16<<10 || len(r.CSR) == 0 || len(r.CSR) > 16<<10 || len(r.Proof) != ed25519.SignatureSize {
		return NodeNameChangeRequest{}, ErrIdentity
	}
	if r.Kind == nameChangeKind && (len(r.OriginalRequest) != 0 || len(r.ContinuationCertificate) != 0) || r.Kind != nameChangeKind && (len(r.OriginalRequest) == 0 || len(r.ContinuationCertificate) == 0 || len(r.ContinuationCertificate) > 16<<10) {
		return NodeNameChangeRequest{}, ErrIdentity
	}
	return r, nil
}

// Keep every existing SAN while adding exactly the saved new name. This
// overlap allows both the old running configuration and the new one to verify
// the same leaf during a rolling switch or configuration rollback. It does not
// authorize arbitrary CSR SANs, wildcards, a new SPIFFE identity or a new CA.
func nameChangeTemplate(old *x509.Certificate, name string) (*x509.Certificate, error) {
	if old == nil || old.VerifyHostname(name) == nil || len(old.DNSNames)+len(old.IPAddresses) < 1 || len(old.DNSNames)+len(old.IPAddresses) >= 16 {
		return nil, ErrIdentity
	}
	next := *old
	next.DNSNames = append([]string(nil), old.DNSNames...)
	next.IPAddresses = append([]net.IP(nil), old.IPAddresses...)
	if ip := net.ParseIP(name); ip != nil {
		next.IPAddresses = append(next.IPAddresses, ip)
	} else {
		next.DNSNames = append(next.DNSNames, name)
	}
	return &next, nil
}

func validateNameChange(ca, crl []byte, r NodeNameChangeRequest, expected NodeNameChangeIntent, now time.Time) (*x509.Certificate, *x509.CertificateRequest, error) {
	if r.Kind == nameChangeContinuationKind || r.Kind == nameChangeReconciliationKind {
		return validateNameChangeContinuation(ca, crl, r, expected, now)
	}
	return validateNameChangeInitial(ca, crl, r, expected, now, false)
}

func validateNameChangeInitial(ca, crl []byte, r NodeNameChangeRequest, expected NodeNameChangeIntent, now time.Time, historical bool) (*x509.Certificate, *x509.CertificateRequest, error) {
	checkedAt := now
	if historical {
		checkedAt = expected.IssuedAt
		if checkedAt.After(now) {
			return nil, nil, ErrIdentity
		}
	}
	if !sameNameChangeIntent(r.Intent, expected) || !validNameChangeIntent(expected, checkedAt) || r.Format != 1 || r.Kind != nameChangeKind || len(r.OriginalRequest) != 0 || len(r.ContinuationCertificate) != 0 || r.SHA256() == "" || len(r.Certificate) == 0 || len(r.Certificate) > 16<<10 || len(r.Proof) != ed25519.SignatureSize {
		return nil, nil, ErrIdentity
	}
	root, err := parseCertificate(ca)
	if err != nil || !validAuthority(root, now) || publicSHA(root.Raw) != expected.AuthoritySHA256 {
		return nil, nil, ErrIdentity
	}
	old, err := parseCertificate(r.Certificate)
	if err != nil || publicSHA(old.Raw) != expected.CertificateSHA256 || old.IsCA || len(old.ExtKeyUsage) != 1 || old.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || old.NotAfter.Sub(old.NotBefore) > 90*24*time.Hour+5*time.Minute || old.NotAfter.After(root.NotAfter) {
		return nil, nil, ErrIdentity
	}
	trust, err := NewTrust(ca, crl, now)
	if err != nil || verifyNameChangeParent(trust, root, old, expected.Node, checkedAt, historical) != nil {
		return nil, nil, ErrRevocation
	}
	payload, err := nameChangeProof(r)
	key, ok := old.PublicKey.(ed25519.PublicKey)
	if err != nil || !ok || !ed25519.Verify(key, payload, r.Proof) {
		return nil, nil, ErrIdentity
	}
	next, err := nameChangeTemplate(old, expected.ServerName)
	if err != nil {
		return nil, nil, err
	}
	csr, err := canonicalNodeCSR(r.CSR, expected.Node, next)
	return old, csr, err
}

func ValidateNodeNameChangeRequest(ca, crl []byte, r NodeNameChangeRequest, expected NodeNameChangeIntent, now time.Time) error {
	_, _, err := validateNameChange(ca, crl, r, expected, now)
	return err
}

func nameChangePending(identity string, i NodeNameChangeIntent) string {
	return filepath.Join(filepath.Dir(identity), "name-changes", i.SHA256())
}

func readNameChangePending(dir string, ca, crl []byte, i NodeNameChangeIntent, now time.Time) (NodeNameChangeRequest, []byte, error) {
	return readNameChangePendingAt(dir, ca, crl, i, now, false)
}
func readNameChangePendingAt(dir string, ca, crl []byte, i NodeNameChangeIntent, now time.Time, historical bool) (NodeNameChangeRequest, []byte, error) {
	var empty NodeNameChangeRequest
	if secureDirectory(dir) != nil {
		return empty, nil, ErrIdentity
	}
	raw, err := readIdentityFile(filepath.Join(dir, "request.json"), MaxRenewalBytes, true)
	if err != nil {
		return empty, nil, ErrIdentity
	}
	r, err := ParseNodeNameChangeRequest(raw)
	if err != nil {
		return empty, nil, err
	}
	_, csr, err := validateNameChangeInitial(ca, crl, r, i, now, historical)
	if err != nil {
		return empty, nil, err
	}
	rawKey, err := readIdentityFile(filepath.Join(dir, "key.pem"), 4096, true)
	if err != nil {
		return empty, nil, ErrIdentity
	}
	reject := func() (NodeNameChangeRequest, []byte, error) { clear(rawKey); return empty, nil, ErrIdentity }
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

func nameChangeTrust(ctx context.Context, caFile, directory string, now time.Time, use func([]byte, []byte) error) error {
	if use == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || secureDirectory(directory) != nil {
		return ErrRevocation
	}
	lock, err := authorityLock(ctx, directory)
	if err != nil {
		return err
	}
	defer lock.Close()
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return ErrIdentity
	}
	pinned, err := readIdentityFile(filepath.Join(directory, "ca.crt"), 64<<10, true)
	if err != nil {
		return ErrIdentity
	}
	root, e1 := parseCertificate(ca)
	prior, e2 := parseCertificate(pinned)
	if e1 != nil || e2 != nil || !bytes.Equal(root.Raw, prior.Raw) {
		return ErrIdentity
	}
	crl, err := readIdentityFile(filepath.Join(directory, "ca.crl"), MaxCRLBytes, true)
	if err != nil {
		return ErrRevocation
	}
	if _, err := NewTrust(ca, crl, now); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return use(ca, crl)
}

// Prepare never connects, signs a leaf or activates an identity. It requires
// an existing current trust floor and active source identity; a retry returns
// the immutable saved CSR, never replacing missing/corrupt pending key state.
func PrepareNodeNameChange(ctx context.Context, caFile, identityFile, trustDirectory string, i NodeNameChangeIntent, now time.Time) (NodeNameChangeRequest, error) {
	var out NodeNameChangeRequest
	if !validNameChangeIntent(i, now) || !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile || filepath.Dir(identityFile) == trustDirectory || secureDirectory(filepath.Dir(identityFile)) != nil {
		return out, ErrIdentity
	}
	ctx, cancel := context.WithDeadline(ctx, i.ExpiresAt)
	defer cancel()
	ctx, finish := context.WithTimeout(ctx, 5*time.Second)
	defer finish()
	err := nameChangeTrust(ctx, caFile, trustDirectory, now, func(ca, crl []byte) error {
		lock, err := authorityLock(ctx, filepath.Dir(identityFile))
		if err != nil {
			return err
		}
		defer lock.Close()
		active, record, err := ReadIdentity(caFile, identityFile, Node, i.Node, now)
		defer clear(active.Key)
		if err != nil || record.CertificateSHA256 != i.CertificateSHA256 {
			return ErrIdentity
		}
		pending := nameChangePending(identityFile, i)
		if _, err := os.Lstat(pending); !os.IsNotExist(err) {
			r, key, err := readNameChangePending(pending, ca, crl, i, now)
			clear(key)
			out = r
			return err
		}
		old, err := parseCertificate(active.Certificate)
		if err != nil {
			return err
		}
		target, err := nameChangeTemplate(old, i.ServerName)
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
		r := NodeNameChangeRequest{Format: 1, Kind: nameChangeKind, Intent: i, Certificate: active.Certificate, CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})}
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
		payload, err := nameChangeProof(r)
		if err != nil {
			return err
		}
		r.Proof = ed25519.Sign(prior, payload)
		if err := ValidateNodeNameChangeRequest(ca, crl, r, i, now); err != nil {
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
		stage, err := os.MkdirTemp(parent, ".name-change-*")
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
		return NodeNameChangeRequest{}, err
	}
	if err := ctx.Err(); err != nil {
		return NodeNameChangeRequest{}, err
	}
	return out, nil
}

// The controller must durably commit the exact intent/request/issuance in the
// callback before any public certificate is delivered. This primitive does
// not itself implement a shared issuance ledger or expose a signing API.
func SignNodeNameChangeRegistered(ctx context.Context, directory string, r NodeNameChangeRequest, expected NodeNameChangeIntent, now time.Time, lifetime time.Duration, accept func(Bundle, []byte) error) error {
	if r.Kind != nameChangeKind || accept == nil || !validNameChangeIntent(expected, now) || lifetime < time.Hour || lifetime > 90*24*time.Hour || secureDirectory(directory) != nil {
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
	old, csr, err := validateNameChange(ca, crl, r, expected, now)
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

// ValidateNodeNameChangeCertificate checks an issued public receipt against the
// exact authorized CSR and overlap SAN set without reading a private node key.
// The issuer uses it for both first issuance and committed-receipt replay.
func ValidateNodeNameChangeCertificate(ca, crl []byte, r NodeNameChangeRequest, expected NodeNameChangeIntent, certificate []byte, now time.Time) error {
	old, csr, err := validateNameChange(ca, crl, r, expected, now)
	if err != nil || len(certificate) == 0 || len(certificate) > 16<<10 {
		return ErrIdentity
	}
	if r.Kind != nameChangeKind && !bytes.Equal(certificate, r.ContinuationCertificate) {
		return ErrIdentity
	}
	return validateNameChangeLeaf(ca, crl, old, csr, expected.Node, certificate, now)
}

func validateNameChangeLeaf(ca, crl []byte, old *x509.Certificate, csr *x509.CertificateRequest, node string, certificate []byte, now time.Time) error {
	leaf, err := parseCertificate(certificate)
	if err != nil || leaf.Subject.CommonName != Node+":"+node || len(leaf.Subject.Names) != 1 || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.UnknownExtKeyUsage) != 0 || len(leaf.EmailAddresses) != 0 || !reflect.DeepEqual(leaf.DNSNames, csr.DNSNames) || len(leaf.IPAddresses) != len(csr.IPAddresses) || !leaf.NotAfter.After(old.NotAfter) {
		return ErrIdentity
	}
	for n, ip := range leaf.IPAddresses {
		if !ip.Equal(csr.IPAddresses[n]) {
			return ErrIdentity
		}
	}
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, csr.PublicKey.(ed25519.PublicKey)) {
		return ErrIdentity
	}
	trust, err := NewTrust(ca, crl, now)
	if err != nil || trust.Verify(leaf, Node, node, now) != nil {
		return ErrIdentity
	}
	return nil
}

// Activation uses the node-held CSR key and the existing durable CRL, while
// holding trust -> identity locks. It preserves the previous private identity
// and never changes the CA, runtime configuration, listener or service.
func ActivateNodeNameChange(ctx context.Context, caFile, identityFile, trustDirectory string, r NodeNameChangeRequest, expected NodeNameChangeIntent, certificate []byte, now time.Time) (IdentityRecord, error) {
	var out IdentityRecord
	if !validNameChangeIntent(expected, now) || !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile || filepath.Dir(identityFile) == trustDirectory || len(certificate) == 0 || len(certificate) > 16<<10 {
		return out, ErrIdentity
	}
	if r.Kind == nameChangeContinuationKind {
		err := WithNameChangedNodeIdentity(ctx, caFile, identityFile, trustDirectory, r, expected, certificate, now, func(ctx context.Context, record IdentityRecord) error { out = record; return nil })
		if err != nil {
			return IdentityRecord{}, err
		}
		return out, nil
	}
	ctx, cancel := context.WithDeadline(ctx, expected.ExpiresAt)
	defer cancel()
	ctx, finish := context.WithTimeout(ctx, 5*time.Second)
	defer finish()
	err := nameChangeTrust(ctx, caFile, trustDirectory, now, func(ca, crl []byte) error {
		if err := ValidateNodeNameChangeRequest(ca, crl, r, expected, now); err != nil {
			return err
		}
		original, err := nameChangeOriginal(r)
		if err != nil {
			return err
		}
		saved, key, err := readNameChangePendingAt(nameChangePending(identityFile, original.Intent), ca, crl, original.Intent, now, r.Kind != nameChangeKind)
		defer clear(key)
		if err != nil || saved.SHA256() != original.SHA256() {
			return ErrIdentity
		}
		if err := ValidateNodeNameChangeCertificate(ca, crl, r, expected, certificate, now); err != nil {
			return err
		}

		out, err = PublishIdentity(ctx, caFile, identityFile, Node, expected.Node, expected.CertificateSHA256, Bundle{CA: ca, Certificate: certificate, Key: key}, now)
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
