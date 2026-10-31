package nodepki

// Root identity rollover is deliberately separate from online renewal. The
// administrative task authenticates each host and freezes membership before
// calling these local primitives. No private leaf key leaves that host.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

type RootIdentityRequest struct {
	Format            int    `json:"format"`
	Authorization     string `json:"authorization_sha256"`
	Role              string `json:"role"`
	ID                string `json:"id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Certificate       []byte `json:"certificate"`
	CSR               []byte `json:"csr"`
	Proof             []byte `json:"proof"`
}

func (r RootIdentityRequest) SHA256() string {
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRenewalBytes {
		return ""
	}
	return publicSHA(raw)
}

func rootIdentityProof(r RootIdentityRequest) []byte {
	r.Proof = nil
	raw, _ := json.Marshal(r)
	return append([]byte("webscan-v3/explicit-root-identity/v1\x00"), raw...)
}

func ParseRootIdentityRequest(raw []byte) (RootIdentityRequest, error) {
	var r RootIdentityRequest
	if len(raw) == 0 || len(raw) > MaxRenewalBytes || json.Unmarshal(raw, &r) != nil {
		return RootIdentityRequest{}, ErrRootRotation
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(raw, canonical) || r.Format != 1 || !recoverySHA(r.Authorization) || !recoverySHA(r.CertificateSHA256) || len(r.Certificate) == 0 || len(r.Certificate) > 16<<10 || len(r.CSR) == 0 || len(r.CSR) > 16<<10 || len(r.Proof) != ed25519.SignatureSize {
		return RootIdentityRequest{}, ErrRootRotation
	}
	if _, err := Identity(r.Role, r.ID); err != nil {
		return RootIdentityRequest{}, ErrRootRotation
	}
	return r, nil
}

func validateRootIdentityRequest(anchor []byte, snapshot RootSetSnapshot, r RootIdentityRequest, now time.Time) (*x509.Certificate, *x509.CertificateRequest, error) {
	return validateRootIdentityRequestAt(anchor, snapshot, r, now, now)
}

// An already signed successor supplies its authenticated issuance time. This
// allows exact receipt replay after its predecessor expires, without ever
// admitting a new request or issuing a new certificate from an expired proof.
func validateRootIdentityRequestAt(anchor []byte, snapshot RootSetSnapshot, r RootIdentityRequest, at, now time.Time) (*x509.Certificate, *x509.CertificateRequest, error) {
	raw, _ := json.Marshal(r)
	if _, err := ParseRootIdentityRequest(raw); err != nil || RootAuthorizationSHA256(snapshot.Dual) != r.Authorization {
		return nil, nil, ErrRootRotation
	}
	if _, err := NewRootSet(anchor, snapshot, now); err != nil {
		return nil, nil, err
	}
	old, err := parseCertificate(r.Certificate)
	root, rootErr := parseCertificate(anchor)
	if err != nil || rootErr != nil {
		return nil, nil, ErrRootRotation
	}
	trustAt := now
	if !at.Equal(now) && snapshot.Final != nil {
		list, err := parseCRL(snapshot.OldCRL, root)
		if err != nil || list.ThisUpdate.After(now) {
			return nil, nil, ErrRootRotation
		}
		trustAt = list.ThisUpdate
	}
	trust, trustErr := NewTrust(anchor, snapshot.OldCRL, trustAt)
	if err != nil || rootErr != nil || trustErr != nil || at.After(now) || at.Before(snapshot.Dual.IssuedAt) || verifyRootParentAt(trust, old, r.Role, r.ID, at) != nil || publicSHA(old.Raw) != r.CertificateSHA256 || old.NotAfter.Sub(old.NotBefore) > 90*24*time.Hour+5*time.Minute {
		return nil, nil, ErrRootRotation
	}
	key, ok := old.PublicKey.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(key, rootIdentityProof(r), r.Proof) {
		return nil, nil, ErrRootRotation
	}
	csr, err := canonicalIdentityCSR(r.CSR, r.Role, r.ID, old)
	return old, csr, err
}

// ValidateRootIdentityRequest verifies the public proof and CSR before a host
// task durably admits it. Canonical parsing alone is not proof of possession.
func ValidateRootIdentityRequest(anchor []byte, snapshot RootSetSnapshot, r RootIdentityRequest, now time.Time) error {
	_, _, err := validateRootIdentityRequest(anchor, snapshot, r, now)
	return err
}

// Trust is already authenticated at the current time (or its final historical
// CRL). Check certificate validity separately at an authenticated issuance time.
func verifyRootParentAt(trust *Trust, leaf *x509.Certificate, role, id string, at time.Time) error {
	identity, err := Identity(role, id)
	usage := x509.ExtKeyUsageClientAuth
	if role == Node {
		usage = x509.ExtKeyUsageServerAuth
	}
	if err != nil || trust == nil || leaf == nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != usage {
		return ErrIdentity
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: trust.roots, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return ErrIdentity
	}
	trust.mu.RLock()
	defer trust.mu.RUnlock()
	if trust.revoked[leaf.SerialNumber.String()] {
		return ErrRevocation
	}
	return nil
}

func rootIdentityPending(identityFile, authorization, expected string) (string, error) {
	if !recoverySHA(authorization) || !recoverySHA(expected) {
		return "", ErrRootRotation
	}
	return filepath.Join(filepath.Dir(identityFile), "root-identities", authorization, expected), nil
}

func readRootIdentityPending(directory string, anchor []byte, snapshot RootSetSnapshot, role, id, expected string, certificate []byte, now time.Time) (RootIdentityRequest, []byte, error) {
	var r RootIdentityRequest
	if secureDirectory(directory) != nil {
		return r, nil, ErrRootRotation
	}
	raw, err := readIdentityFile(filepath.Join(directory, "request.json"), MaxRenewalBytes, true)
	if err != nil {
		return r, nil, ErrRootRotation
	}
	r, err = ParseRootIdentityRequest(raw)
	if err != nil || r.Role != role || r.ID != id || r.CertificateSHA256 != expected {
		return RootIdentityRequest{}, nil, ErrRootRotation
	}
	var csr *x509.CertificateRequest
	if len(certificate) == 0 {
		_, csr, err = validateRootIdentityRequest(anchor, snapshot, r, now)
	} else {
		_, csr, err = validateRootIdentityIssuedRequest(anchor, snapshot, r, certificate, now)
	}
	if err != nil {
		return r, nil, err
	}
	key, err := readIdentityFile(filepath.Join(directory, "key.pem"), 4096, true)
	if err != nil {
		return r, nil, ErrRootRotation
	}
	block, tail := pem.Decode(key)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(tail)) != 0 {
		clear(key)
		return r, nil, ErrRootRotation
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := parsed.(ed25519.PrivateKey)
	defer clear(private)
	if err != nil || !ok || !bytes.Equal(private.Public().(ed25519.PublicKey), csr.PublicKey.(ed25519.PublicKey)) {
		clear(key)
		return r, nil, ErrRootRotation
	}
	return r, key, nil
}

func PrepareRootIdentity(ctx context.Context, caFile, identityFile, floor, role, id, authorization, expected string, now time.Time) (RootIdentityRequest, error) {
	var empty RootIdentityRequest
	if floor == filepath.Dir(identityFile) || !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile || secureDirectory(filepath.Dir(identityFile)) != nil || secureDirectory(floor) != nil {
		return empty, ErrRootRotation
	}
	// Same order as activation and consistent backup.
	for _, directory := range []string{floor, filepath.Dir(identityFile)} {
		lock, err := authorityLock(ctx, directory)
		if err != nil {
			return empty, err
		}
		defer lock.Close()
	}
	anchor, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return empty, ErrRootRotation
	}
	snapshot, _, err := readRootSetSnapshot(floor, anchor)
	if err != nil || snapshot.Format != 1 || snapshot.Final != nil || RootAuthorizationSHA256(snapshot.Dual) != authorization {
		return empty, ErrRootRotation
	}
	b, prior, err := ReadIdentityWithRootState(caFile, identityFile, floor, role, id, now)
	defer clear(b.Key)
	if err != nil || prior.CertificateSHA256 != expected || !bytes.Equal(b.CA, anchor) {
		return empty, ErrRootRotation
	}
	pending, err := rootIdentityPending(identityFile, authorization, expected)
	if err != nil {
		return empty, err
	}
	if _, err := os.Lstat(pending); !os.IsNotExist(err) {
		r, key, err := readRootIdentityPending(pending, anchor, snapshot, role, id, expected, nil, now)
		clear(key)
		return r, err
	}
	leaf, err := parseCertificate(b.Certificate)
	if err != nil {
		return empty, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return empty, err
	}
	defer clear(key)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: role + ":" + id}, URIs: leaf.URIs, DNSNames: leaf.DNSNames, IPAddresses: leaf.IPAddresses}, key)
	if err != nil {
		return empty, err
	}
	r := RootIdentityRequest{Format: 1, Authorization: authorization, Role: role, ID: id, CertificateSHA256: expected, Certificate: b.Certificate, CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})}
	block, _ := pem.Decode(b.Key)
	if block == nil {
		return empty, ErrRootRotation
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	priorKey, ok := parsed.(ed25519.PrivateKey)
	defer clear(priorKey)
	if err != nil || !ok {
		return empty, ErrRootRotation
	}
	r.Proof = ed25519.Sign(priorKey, rootIdentityProof(r))
	if _, _, err := validateRootIdentityRequest(anchor, snapshot, r, now); err != nil {
		return empty, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return empty, err
	}
	defer clear(private)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	defer clear(keyPEM)
	raw, _ := json.Marshal(r)
	for _, directory := range []string{filepath.Dir(filepath.Dir(pending)), filepath.Dir(pending)} {
		if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
			return empty, errStorage
		}
		if secureDirectory(directory) != nil || syncDir(filepath.Dir(directory)) != nil {
			return empty, errStorage
		}
	}
	stage, err := os.MkdirTemp(filepath.Dir(pending), ".identity-*")
	if err != nil {
		return empty, errStorage
	}
	defer os.RemoveAll(stage)
	if writeExclusive(filepath.Join(stage, "request.json"), raw) != nil || writeExclusive(filepath.Join(stage, "key.pem"), keyPEM) != nil || syncDir(stage) != nil || ctx.Err() != nil || identityRenameNoReplace(stage, pending) != nil || syncDir(filepath.Dir(pending)) != nil {
		return empty, errStorage
	}
	return r, nil
}

// The caller must commit one immutable issuance receipt before delivering it.
// It may only sign during dual trust, and never returns a private leaf key.
func SignRootIdentityRegistered(ctx context.Context, successor string, anchor []byte, snapshot RootSetSnapshot, r RootIdentityRequest, now time.Time, lifetime time.Duration, accept func(Bundle) error) error {
	if accept == nil || snapshot.Final != nil || lifetime < time.Hour || lifetime > 90*24*time.Hour || secureDirectory(successor) != nil {
		return ErrRootRotation
	}
	old, csr, err := validateRootIdentityRequest(anchor, snapshot, r, now)
	if err != nil {
		return err
	}
	lock, err := authorityLock(ctx, successor)
	if err != nil {
		return err
	}
	defer lock.Close()
	a, err := loadMaintenanceAuthority(successor, now)
	if err != nil {
		return err
	}
	defer clear(a.key)
	if !bytes.Equal(certificatePEM(a.certificate), snapshot.Dual.NewCA) || !now.Add(lifetime).After(old.NotAfter) || now.Add(lifetime).After(a.certificate.NotAfter) {
		return ErrRootRotation
	}
	crl, _, err := latestCRL(successor, a)
	if err != nil || !bytes.Equal(crl, snapshot.NewCRL) {
		return ErrRootRotation
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	usage := x509.ExtKeyUsageServerAuth
	if r.Role == Collector {
		usage = x509.ExtKeyUsageClientAuth
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: r.Role + ":" + r.ID}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(lifetime), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: old.URIs, DNSNames: old.DNSNames, IPAddresses: old.IPAddresses}
	if template.NotBefore.Before(a.certificate.NotBefore) {
		template.NotBefore = a.certificate.NotBefore
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, a.certificate, csr.PublicKey, a.key)
	if err != nil || ctx.Err() != nil {
		return ErrRootRotation
	}
	return accept(Bundle{CA: snapshot.Dual.NewCA, Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})})
}

// Validate the complete public issuance before persisting or replaying it.
// Matching a CA signature alone is insufficient: the exact node-local CSR,
// prior identity, role and SAN set must survive the transition unchanged.
func ValidateRootIdentityCertificate(anchor []byte, snapshot RootSetSnapshot, r RootIdentityRequest, certificate []byte, now time.Time) error {
	_, _, err := validateRootIdentityIssuedRequest(anchor, snapshot, r, certificate, now)
	return err
}

func validateRootIdentityIssuedRequest(anchor []byte, snapshot RootSetSnapshot, r RootIdentityRequest, certificate []byte, now time.Time) (*x509.Certificate, *x509.CertificateRequest, error) {
	leaf, err := parseCertificate(certificate)
	trust, trustErr := NewTrust(snapshot.Dual.NewCA, snapshot.NewCRL, now)
	if err != nil || trustErr != nil || trust.Verify(leaf, r.Role, r.ID, now) != nil {
		return nil, nil, ErrRootRotation
	}
	old, csr, err := validateRootIdentityRequestAt(anchor, snapshot, r, leaf.NotBefore.Add(5*time.Minute), now)
	if err != nil {
		return nil, nil, err
	}
	if !leaf.NotAfter.After(old.NotAfter) || leaf.NotAfter.Sub(leaf.NotBefore) > 90*24*time.Hour+5*time.Minute || !reflect.DeepEqual(leaf.DNSNames, old.DNSNames) || !reflect.DeepEqual(leaf.IPAddresses, old.IPAddresses) || !reflect.DeepEqual(leaf.URIs, old.URIs) {
		return nil, nil, ErrRootRotation
	}
	key, ok := leaf.PublicKey.(ed25519.PublicKey)
	requested, csrOK := csr.PublicKey.(ed25519.PublicKey)
	if !ok || !csrOK || !bytes.Equal(key, requested) {
		return nil, nil, ErrRootRotation
	}
	return old, csr, nil
}

func ActivateRootIdentity(ctx context.Context, caFile, identityFile, floor, role, id, authorization, expected, requestSHA string, certificate []byte, now time.Time) (IdentityRecord, error) {
	var empty IdentityRecord
	anchor, err := readTrustFile(caFile, 64<<10)
	if err != nil || len(certificate) == 0 || len(certificate) > 16<<10 {
		return empty, ErrRootRotation
	}
	snapshot, _, err := readRootSetSnapshot(floor, anchor)
	if err != nil || RootAuthorizationSHA256(snapshot.Dual) != authorization {
		return empty, ErrRootRotation
	}
	pending, err := rootIdentityPending(identityFile, authorization, expected)
	if err != nil {
		return empty, err
	}
	r, key, err := readRootIdentityPending(pending, anchor, snapshot, role, id, expected, certificate, now)
	defer clear(key)
	if err != nil || r.SHA256() != requestSHA {
		return empty, ErrRootRotation
	}
	old, csr, err := validateRootIdentityIssuedRequest(anchor, snapshot, r, certificate, now)
	if err != nil {
		return empty, err
	}
	if ValidateRootIdentityCertificate(anchor, snapshot, r, certificate, now) != nil {
		return empty, ErrRootRotation
	}
	leaf, err := parseCertificate(certificate)
	if err != nil || !reflect.DeepEqual(leaf.DNSNames, old.DNSNames) || len(leaf.IPAddresses) != len(old.IPAddresses) {
		return empty, ErrRootRotation
	}
	for i := range leaf.IPAddresses {
		if !leaf.IPAddresses[i].Equal(old.IPAddresses[i]) {
			return empty, ErrRootRotation
		}
	}
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, csr.PublicKey.(ed25519.PublicKey)) {
		return empty, ErrRootRotation
	}
	return publishIdentity(ctx, caFile, identityFile, floor, authorization, role, id, expected, Bundle{CA: snapshot.Dual.NewCA, Certificate: certificate, Key: key}, now)
}
