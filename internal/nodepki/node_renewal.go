package nodepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

const MaxRenewalBytes = 64 << 10

// NodeRenewalRequest contains public material only. The replacement key stays
// in the node's private state directory; collectors and issuers never receive it.
// Its canonical JSON digest is also the signing registry's idempotency binding.
type NodeRenewalRequest struct {
	Format            int    `json:"format"`
	Node              string `json:"node"`
	AuthoritySHA256   string `json:"authority_sha256"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Certificate       []byte `json:"certificate"`
	CSR               []byte `json:"csr"`
	Proof             []byte `json:"proof"`
}

// Network relays accept exactly the bounded canonical public form produced by
// the node. Unknown/duplicate fields and alternate JSON encodings are rejected.
func ParseNodeRenewalRequest(raw []byte) (NodeRenewalRequest, error) {
	var r NodeRenewalRequest
	if len(raw) == 0 || len(raw) > MaxRenewalBytes || json.Unmarshal(raw, &r) != nil {
		return NodeRenewalRequest{}, ErrIdentity
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) || r.SHA256() == "" {
		return NodeRenewalRequest{}, ErrIdentity
	}
	return r, nil
}

// ValidateNodeRenewalRequest needs public trust material only. Relays validate
// possession and the requested identity before admitting a durable signing job;
// the isolated issuer repeats these checks with its current trust floor.
func ValidateNodeRenewalRequest(ca, crl []byte, r NodeRenewalRequest, now time.Time) error {
	old, _, err := validateNodeRenewal(ca, r, now, false)
	if err != nil {
		return err
	}
	trust, err := NewTrust(ca, crl, now)
	if err != nil {
		return err
	}
	return trust.Verify(old, Node, r.Node, now)
}

func publicSHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (r NodeRenewalRequest) SHA256() string {
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRenewalBytes {
		return ""
	}
	return publicSHA(raw)
}

// The active node key countersigns the complete new-key request. Possessing
// another node's public certificate is not sufficient to ask the issuer for
// its identity, even through a compromised or mistaken relay.
func renewalProofPayload(r NodeRenewalRequest) ([]byte, error) {
	r.Proof = nil
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRenewalBytes {
		return nil, ErrIdentity
	}
	return append([]byte("webscan-v3/node-renewal-proof/v1\x00"), raw...), nil
}

func canonicalNodeCSR(raw []byte, id string, old *x509.Certificate) (*x509.CertificateRequest, error) {
	return canonicalIdentityCSR(raw, Node, id, old)
}

func canonicalIdentityCSR(raw []byte, role, id string, old *x509.Certificate) (*x509.CertificateRequest, error) {
	if len(raw) == 0 || len(raw) > 16<<10 {
		return nil, ErrIdentity
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrIdentity
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.SignatureAlgorithm != x509.PureEd25519 || len(csr.Subject.Names) != 1 || csr.Subject.CommonName != role+":"+id || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 1 || len(old.URIs) != 1 || csr.URIs[0].String() != old.URIs[0].String() || !reflect.DeepEqual(csr.DNSNames, old.DNSNames) || len(csr.IPAddresses) != len(old.IPAddresses) {
		return nil, ErrIdentity
	}
	key, ok := csr.PublicKey.(ed25519.PublicKey)
	prior, priorOK := old.PublicKey.(ed25519.PublicKey)
	if !ok || !priorOK || bytes.Equal(key, prior) {
		return nil, ErrIdentity
	}
	for i := range csr.IPAddresses {
		if !csr.IPAddresses[i].Equal(old.IPAddresses[i]) {
			return nil, ErrIdentity
		}
	}
	// No CA, usage, alternate identity or arbitrary extension can be requested.
	if len(csr.Extensions) != 1 || !csr.Extensions[0].Id.Equal([]int{2, 5, 29, 17}) || len(csr.Attributes) != 1 || !csr.Attributes[0].Type.Equal([]int{1, 2, 840, 113549, 1, 9, 14}) {
		return nil, ErrIdentity
	}
	return csr, nil
}

func validateNodeRenewal(ca []byte, r NodeRenewalRequest, now time.Time, allowExpired bool) (*x509.Certificate, *x509.CertificateRequest, error) {
	root, err := parseCertificate(ca)
	if err != nil || !validAuthority(root, now) || r.Format != 1 || len(r.Proof) != ed25519.SignatureSize || len(r.Certificate) > 16<<10 || r.SHA256() == "" || r.AuthoritySHA256 != publicSHA(root.Raw) {
		return nil, nil, ErrIdentity
	}
	old, err := parseCertificate(r.Certificate)
	if err != nil || publicSHA(old.Raw) != r.CertificateSHA256 || old.IsCA || len(old.ExtKeyUsage) != 1 || old.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(old.DNSNames)+len(old.IPAddresses) < 1 || len(old.DNSNames)+len(old.IPAddresses) > 16 || old.NotAfter.Sub(old.NotBefore) > 90*24*time.Hour+5*time.Minute || old.NotAfter.After(root.NotAfter) {
		return nil, nil, ErrIdentity
	}
	id, err := PeerID(old, Node)
	if err != nil || r.Node != id {
		return nil, nil, ErrIdentity
	}
	check := now
	if allowExpired && !now.Before(old.NotAfter) {
		check = old.NotAfter.Add(-time.Second)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := old.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: check, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil || now.Before(old.NotBefore) {
		return nil, nil, ErrIdentity
	}
	priorKey, ok := old.PublicKey.(ed25519.PublicKey)
	payload, err := renewalProofPayload(r)
	if !ok || err != nil || !ed25519.Verify(priorKey, payload, r.Proof) {
		return nil, nil, ErrIdentity
	}
	csr, err := canonicalNodeCSR(r.CSR, id, old)
	return old, csr, err
}

func renewalPending(directory, expected string) (string, error) {
	raw, err := hex.DecodeString(expected)
	if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != expected {
		return "", ErrIdentity
	}
	return filepath.Join(directory, "renewals", expected), nil
}

func readNodeRenewal(directory string, ca []byte, id, expected string, now time.Time) (NodeRenewalRequest, []byte, error) {
	var r NodeRenewalRequest
	if secureDirectory(directory) != nil {
		return r, nil, ErrIdentity
	}
	raw, err := readIdentityFile(filepath.Join(directory, "request.json"), MaxRenewalBytes, true)
	if err != nil || json.Unmarshal(raw, &r) != nil {
		return r, nil, ErrIdentity
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(raw, canonical) || r.Node != id || r.CertificateSHA256 != expected {
		return NodeRenewalRequest{}, nil, ErrIdentity
	}
	_, csr, err := validateNodeRenewal(ca, r, now, true)
	if err != nil {
		return NodeRenewalRequest{}, nil, err
	}
	key, err := readIdentityFile(filepath.Join(directory, "key.pem"), 4096, true)
	if err != nil {
		return NodeRenewalRequest{}, nil, ErrIdentity
	}
	block, tail := pem.Decode(key)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(tail)) != 0 {
		clear(key)
		return NodeRenewalRequest{}, nil, ErrIdentity
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := parsed.(ed25519.PrivateKey)
	defer clear(private)
	if err != nil || !ok || !bytes.Equal(private.Public().(ed25519.PublicKey), csr.PublicKey.(ed25519.PublicKey)) {
		clear(key)
		return NodeRenewalRequest{}, nil, ErrIdentity
	}
	return r, key, nil
}

// PrepareNodeRenewal does no signing or networking. A retry for the same active
// leaf returns the same CSR and reuses the durably stored pending private key.
func PrepareNodeRenewal(ctx context.Context, caFile, identityFile, id, expected string, now time.Time) (NodeRenewalRequest, error) {
	return prepareNodeRenewal(ctx, caFile, identityFile, id, expected, now, false)
}

func PrepareNodeRenewalWithRootState(ctx context.Context, caFile, identityFile, directory, id, expected string, now time.Time) (NodeRenewalRequest, error) {
	return prepareNodeRenewalWithRootState(ctx, caFile, identityFile, directory, id, expected, now, false)
}

// Recovery is deliberately private: ordinary preparation must never authorize
// an expired identity, even when an old pending request already exists.
func prepareNodeRenewal(ctx context.Context, caFile, identityFile, id, expected string, now time.Time, recovery bool) (NodeRenewalRequest, error) {
	return prepareNodeRenewalWithRootState(ctx, caFile, identityFile, "", id, expected, now, recovery)
}

func prepareNodeRenewalWithRootState(ctx context.Context, caFile, identityFile, directory, id, expected string, now time.Time, recovery bool) (NodeRenewalRequest, error) {
	var empty NodeRenewalRequest
	if !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile || secureDirectory(filepath.Dir(identityFile)) != nil {
		return empty, ErrIdentity
	}
	lock, err := authorityLock(ctx, filepath.Dir(identityFile))
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	b, record, err := readIdentityWithRootState(caFile, identityFile, directory, Node, id, now, recovery)
	defer clear(b.Key)
	if err != nil || record.CertificateSHA256 != expected || recovery && now.Before(record.ExpiresAt) {
		return empty, ErrIdentity
	}
	pending, err := renewalPending(filepath.Dir(identityFile), expected)
	if err != nil {
		return empty, err
	}
	if _, err := os.Lstat(pending); !os.IsNotExist(err) {
		r, key, err := readNodeRenewal(pending, b.CA, id, expected, now)
		clear(key)
		return r, err
	}
	old, _ := parseCertificate(b.Certificate)
	root, _ := parseCertificate(b.CA)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return empty, ErrIdentity
	}
	defer clear(key)
	priorPublic, ok := old.PublicKey.(ed25519.PublicKey)
	if !ok || bytes.Equal(public, priorPublic) {
		return empty, ErrIdentity
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: Node + ":" + id}, URIs: old.URIs, DNSNames: old.DNSNames, IPAddresses: old.IPAddresses}, key)
	if err != nil {
		return empty, ErrIdentity
	}
	r := NodeRenewalRequest{Format: 1, Node: id, AuthoritySHA256: publicSHA(root.Raw), CertificateSHA256: expected, Certificate: b.Certificate, CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})}
	oldBlock, _ := pem.Decode(b.Key)
	if oldBlock == nil {
		return empty, ErrIdentity
	}
	defer clear(oldBlock.Bytes)
	parsedOld, err := x509.ParsePKCS8PrivateKey(oldBlock.Bytes)
	oldKey, ok := parsedOld.(ed25519.PrivateKey)
	if err != nil || !ok {
		return empty, ErrIdentity
	}
	defer clear(oldKey)
	payload, err := renewalProofPayload(r)
	if err != nil {
		return empty, err
	}
	r.Proof = ed25519.Sign(oldKey, payload)
	if _, _, err := validateNodeRenewal(b.CA, r, now, recovery); err != nil {
		return empty, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return empty, ErrIdentity
	}
	defer clear(private)
	raw, _ := json.Marshal(r)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	defer clear(keyPEM)
	parent := filepath.Dir(pending)
	if err := os.Mkdir(parent, 0700); err != nil && !os.IsExist(err) {
		return empty, errStorage
	}
	if secureDirectory(parent) != nil {
		return empty, errStorage
	}
	stage, err := os.MkdirTemp(parent, ".renewal-*")
	if err != nil {
		return empty, errStorage
	}
	defer os.RemoveAll(stage)
	for name, content := range map[string][]byte{"request.json": raw, "key.pem": keyPEM} {
		if err := writeExclusive(filepath.Join(stage, name), content); err != nil {
			return empty, err
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if syncDir(stage) != nil || identityRenameNoReplace(stage, pending) != nil || syncDir(parent) != nil {
		return empty, errStorage
	}
	return r, nil
}

// SignNodeRenewalRegistered signs only the same node identity and SANs with a
// new CSR-owned key. The caller must bind the public request to a saved runtime
// and persist its idempotent issuance receipt in the callback before delivery.
// It returns no private leaf key, never changes CRLs and never distributes data.
func SignNodeRenewalRegistered(ctx context.Context, directory string, r NodeRenewalRequest, now time.Time, lifetime time.Duration, accept func(Bundle, []byte) error) error {
	return signNodeRenewalRegistered(ctx, directory, r, now, lifetime, nil, accept)
}

func signNodeRenewalRegistered(ctx context.Context, directory string, r NodeRenewalRequest, now time.Time, lifetime time.Duration, recovery *NodeRecoveryRequest, accept func(Bundle, []byte) error) error {
	if accept == nil || lifetime < time.Hour || lifetime > 90*24*time.Hour || secureDirectory(directory) != nil {
		return ErrIdentity
	}
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
	ca := certificatePEM(a.certificate)
	old, csr, err := validateNodeRenewal(ca, r, now, recovery != nil)
	if err != nil || !now.Add(lifetime).After(old.NotAfter) || now.Add(lifetime).After(a.certificate.NotAfter) {
		return ErrIdentity
	}
	crl, _, err := latestCRL(directory, a)
	if err != nil {
		return err
	}
	trust, err := NewTrust(ca, crl, now)
	if err != nil {
		return ErrRevocation
	}
	if recovery == nil {
		err = trust.Verify(old, Node, r.Node, now)
	} else {
		err = ValidateNodeRecoveryRequest(ca, crl, *recovery, recovery.Intent, now)
	}
	if err != nil {
		return ErrRevocation
	}
	serial, err := randomSerial()
	if err != nil {
		return ErrIdentity
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: Node + ":" + r.Node}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(lifetime), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, URIs: old.URIs, DNSNames: old.DNSNames, IPAddresses: old.IPAddresses}
	if template.NotBefore.Before(a.certificate.NotBefore) {
		template.NotBefore = a.certificate.NotBefore
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, a.certificate, csr.PublicKey, a.key)
	if err != nil {
		return ErrIdentity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return accept(Bundle{CA: ca, Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})}, crl)
}

// ActivateNodeRenewal only accepts a signed certificate for the locally held
// CSR key. Its mandatory policy must check the installed current CRL floor.
// Pending keys are retained privately for response-loss reconciliation/backup.
func ActivateNodeRenewal(ctx context.Context, caFile, identityFile, id, expected, requestSHA string, certificate []byte, now time.Time, verify func(*x509.Certificate) error) (IdentityRecord, error) {
	return ActivateNodeRenewalWithRootState(ctx, caFile, identityFile, "", id, expected, requestSHA, certificate, now, verify)
}

func ActivateNodeRenewalWithRootState(ctx context.Context, caFile, identityFile, directory, id, expected, requestSHA string, certificate []byte, now time.Time, verify func(*x509.Certificate) error) (IdentityRecord, error) {
	var empty IdentityRecord
	if verify == nil || len(certificate) == 0 || len(certificate) > 16<<10 || !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile {
		return empty, ErrIdentity
	}
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return empty, ErrIdentity
	}
	if directory != "" {
		// The request remains same-issuer. Using the active material's issuer
		// never grants a leaf-renewal RPC authority to perform a root change.
		current, _, err := readIdentityWithRootState(caFile, identityFile, directory, Node, id, now, true)
		defer clear(current.Key)
		if err != nil {
			return empty, err
		}
		ca = current.CA
	}
	return activateNodeRenewalMaterial(ctx, identityFile, id, expected, requestSHA, ca, certificate, now, verify, func(b Bundle) (IdentityRecord, error) {
		return PublishIdentityWithRootState(ctx, caFile, identityFile, directory, Node, id, expected, b, now)
	})
}

// The caller chooses and locks the approved issuer; activation still checks the
// exact retained local CSR/key, public certificate, parent and current policy.
func activateNodeRenewalMaterial(ctx context.Context, identityFile, id, expected, requestSHA string, ca, certificate []byte, now time.Time, verify func(*x509.Certificate) error, publish func(Bundle) (IdentityRecord, error)) (IdentityRecord, error) {
	var empty IdentityRecord
	pending, err := renewalPending(filepath.Dir(identityFile), expected)
	if err != nil {
		return empty, err
	}
	r, key, err := readNodeRenewal(pending, ca, id, expected, now)
	defer clear(key)
	if err != nil || r.SHA256() != requestSHA {
		return empty, ErrIdentity
	}
	old, csr, err := validateNodeRenewal(ca, r, now, true)
	if err != nil {
		return empty, err
	}
	leaf, err := parseCertificate(certificate)
	if err != nil || !reflect.DeepEqual(leaf.DNSNames, old.DNSNames) || len(leaf.IPAddresses) != len(old.IPAddresses) {
		return empty, ErrIdentity
	}
	for i := range leaf.IPAddresses {
		if !leaf.IPAddresses[i].Equal(old.IPAddresses[i]) {
			return empty, ErrIdentity
		}
	}
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, csr.PublicKey.(ed25519.PublicKey)) || verify(leaf) != nil {
		return empty, ErrIdentity
	}
	return publish(Bundle{CA: ca, Certificate: certificate, Key: key})
}
