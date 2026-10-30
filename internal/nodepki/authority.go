// Package nodepki implements the private v3 Agent/collector certificate contract.
// It never installs a trust root, accepts an unverified CSR, or exports keys as JSON.
package nodepki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const Node = "node"
const Collector = "collector"

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var dnsName = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
var ErrIdentity = errors.New("证书身份、签名或有效期不正确")
var ErrRevocation = errors.New("证书吊销列表无效、过期或发生回退")

// Keys are deliberately omitted from JSON, including accidental logging.
type Bundle struct {
	CA          []byte `json:"-"`
	Certificate []byte `json:"-"`
	Key         []byte `json:"-"`
}
type Authority struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
}

func NewAuthority(now time.Time, lifetime time.Duration) (*Authority, error) {
	if lifetime < 365*24*time.Hour || lifetime > 10*365*24*time.Hour {
		return nil, ErrIdentity
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "webscan-v3-node-ca"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(lifetime), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}
	return &Authority{cert, key}, nil
}
func randomSerial() (*big.Int, error) {
	// 159 random bits keep DER serials positive and below the RFC 5280 limit.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		return randomSerial()
	}
	return serial, nil
}
func certificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
func parseCertificate(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrIdentity
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrIdentity
	}
	return cert, nil
}
func (a *Authority) Export() (Bundle, error) {
	if a == nil || a.certificate == nil || len(a.key) != ed25519.PrivateKeySize {
		return Bundle{}, ErrIdentity
	}
	key, err := x509.MarshalPKCS8PrivateKey(a.key)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{CA: certificatePEM(a.certificate), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})}, nil
}
func ParseAuthority(certPEM, keyPEM []byte, now time.Time) (*Authority, error) {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrIdentity
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrIdentity
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || !validAuthority(cert, now) || !bytes.Equal(cert.PublicKey.(ed25519.PublicKey), key.Public().(ed25519.PublicKey)) {
		return nil, ErrIdentity
	}
	return &Authority{cert, key}, nil
}
func validAuthority(cert *x509.Certificate, now time.Time) bool {
	_, ok := cert.PublicKey.(ed25519.PublicKey)
	return ok && cert.IsCA && cert.BasicConstraintsValid && cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) == x509.KeyUsageCertSign|x509.KeyUsageCRLSign && cert.CheckSignatureFrom(cert) == nil && !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)
}
func Identity(role, id string) (string, error) {
	if (role != Node && role != Collector) || !identifier.MatchString(id) {
		return "", ErrIdentity
	}
	return "spiffe://webscan/" + role + "/" + id, nil
}

func PeerID(cert *x509.Certificate, role string) (string, error) {
	if cert == nil || len(cert.URIs) != 1 {
		return "", ErrIdentity
	}
	value := cert.URIs[0].String()
	prefix := "spiffe://webscan/" + role + "/"
	if !strings.HasPrefix(value, prefix) {
		return "", ErrIdentity
	}
	id := strings.TrimPrefix(value, prefix)
	canonical, err := Identity(role, id)
	if err != nil || canonical != value {
		return "", ErrIdentity
	}
	return id, nil
}
func (a *Authority) Issue(role, id string, names []string, now time.Time, lifetime time.Duration) (Bundle, error) {
	identity, err := Identity(role, id)
	if err != nil || a == nil || !validAuthority(a.certificate, now) || lifetime < time.Hour || lifetime > 90*24*time.Hour || now.Add(lifetime).After(a.certificate.NotAfter) {
		return Bundle{}, ErrIdentity
	}
	if role == Collector && len(names) != 0 || role == Node && (len(names) < 1 || len(names) > 16) {
		return Bundle{}, ErrIdentity
	}
	uri, _ := url.Parse(identity)
	serial, err := randomSerial()
	if err != nil {
		return Bundle{}, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: role + ":" + id}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(lifetime), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{uri}}
	if template.NotBefore.Before(a.certificate.NotBefore) {
		template.NotBefore = a.certificate.NotBefore
	}
	if role == Node {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || seen[name] || len(name) > 253 {
			return Bundle{}, ErrIdentity
		}
		seen[name] = true
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if dnsName.MatchString(name) {
			template.DNSNames = append(template.DNSNames, name)
		} else {
			return Bundle{}, ErrIdentity
		}
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Bundle{}, err
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, a.certificate, public, a.key)
	if err != nil {
		return Bundle{}, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{CA: certificatePEM(a.certificate), Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}, nil
}
