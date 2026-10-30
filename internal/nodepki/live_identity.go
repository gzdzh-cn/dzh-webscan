package nodepki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// An identity file contains exactly one leaf certificate and one PKCS8 key.
// Replacing one private file prevents mixed certificate/key reads. Roots and
// CRLs are separate: replacing a leaf never changes the trust policy.
const MaxIdentityBytes = 128 << 10

type IdentityRecord struct {
	CertificateSHA256 string    `json:"certificate_sha256"`
	Serial            string    `json:"serial"`
	ID                string    `json:"id"`
	Role              string    `json:"role"`
	ExpiresAt         time.Time `json:"expires_at"`
	Changed           bool      `json:"changed"`
}

func identityRecord(cert *x509.Certificate, role, id string) IdentityRecord {
	sum := sha256.Sum256(cert.Raw)
	return IdentityRecord{CertificateSHA256: hex.EncodeToString(sum[:]), Serial: cert.SerialNumber.Text(16), ID: id, Role: role, ExpiresAt: cert.NotAfter}
}

func identityPair(raw, ca []byte, role, id string, now time.Time, allowExpired bool) (*tls.Certificate, IdentityRecord, error) {
	var empty IdentityRecord
	raw = bytes.TrimSpace(raw)
	if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, empty, ErrIdentity
	}
	certBlock, rest := pem.Decode(raw)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(certBlock.Headers) != 0 {
		return nil, empty, ErrIdentity
	}
	rest = bytes.TrimSpace(rest)
	if !bytes.HasPrefix(rest, []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, empty, ErrIdentity
	}
	keyBlock, tail := pem.Decode(rest)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(keyBlock.Headers) != 0 || len(bytes.TrimSpace(tail)) != 0 {
		return nil, empty, ErrIdentity
	}
	root, err := parseCertificate(ca)
	if err != nil || !validAuthority(root, now) {
		return nil, empty, ErrIdentity
	}
	pair, err := tls.X509KeyPair(raw, raw)
	if err != nil || len(pair.Certificate) != 1 {
		return nil, empty, ErrIdentity
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, empty, ErrIdentity
	}
	actual, err := PeerID(cert, role)
	if err != nil || id != "" && id != actual || cert.IsCA || len(cert.ExtKeyUsage) != 1 || now.Before(cert.NotBefore) || cert.NotAfter.After(root.NotAfter) || cert.NotAfter.Sub(cert.NotBefore) > 90*24*time.Hour+5*time.Minute {
		return nil, empty, ErrIdentity
	}
	usage := x509.ExtKeyUsageClientAuth
	if role == Node {
		usage = x509.ExtKeyUsageServerAuth
	}
	if cert.ExtKeyUsage[0] != usage || role == Collector && (len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0) || role == Node && len(cert.DNSNames)+len(cert.IPAddresses) < 1 {
		return nil, empty, ErrIdentity
	}
	checkTime := now
	if allowExpired && !now.Before(cert.NotAfter) {
		checkTime = cert.NotAfter.Add(-time.Second)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: checkTime, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return nil, empty, ErrIdentity
	}
	pair.Leaf = cert
	return &pair, identityRecord(cert, role, actual), nil
}

// ReadIdentity is private material, never a response model. An expired leaf
// may only be inspected by the explicit offline renewal tool, not used in TLS.
func ReadIdentity(caFile, file, role, id string, now time.Time) (Bundle, IdentityRecord, error) {
	return readIdentity(caFile, file, role, id, now, false)
}
func readIdentity(caFile, file, role, id string, now time.Time, allowExpired bool) (Bundle, IdentityRecord, error) {
	var b Bundle
	var r IdentityRecord
	if !filepath.IsAbs(file) || filepath.Clean(file) != file || secureDirectory(filepath.Dir(file)) != nil {
		return b, r, ErrIdentity
	}
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return b, r, ErrIdentity
	}
	raw, err := readIdentityFile(file, MaxIdentityBytes, true)
	if err != nil {
		return b, r, ErrIdentity
	}
	defer clear(raw)
	_, r, err = identityPair(raw, ca, role, id, now, allowExpired)
	if err != nil {
		return b, r, err
	}
	cert, rest := pem.Decode(raw)
	key, _ := pem.Decode(rest)
	b.CA, b.Certificate, b.Key = ca, pem.EncodeToMemory(cert), pem.EncodeToMemory(key)
	return b, r, nil
}

type LiveIdentity struct {
	mu             sync.Mutex
	ca             []byte
	file, role, id string
	pair           *tls.Certificate
	record         IdentityRecord
	last           time.Time
	lastError      error
}

func NewLiveIdentity(caFile, file, role, id string, now time.Time) (*LiveIdentity, error) {
	if !filepath.IsAbs(file) || filepath.Clean(file) != file || secureDirectory(filepath.Dir(file)) != nil {
		return nil, ErrIdentity
	}
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return nil, ErrIdentity
	}
	l := &LiveIdentity{ca: ca, file: file, role: role, id: id}
	if _, err := l.Certificate(now); err != nil {
		return nil, err
	}
	return l, nil
}

// Certificate fails closed for new handshakes if publication is damaged or
// expired. Existing connections are governed by the per-RPC peer CRL policy.
// A live reader pins its original CA and exact SPIFFE identity; CA rollover is
// an explicit trust operation, never an effect of replacing this file.
func (l *LiveIdentity) Certificate(now time.Time) (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.certificateLocked(now)
}

func (l *LiveIdentity) certificateLocked(now time.Time) (*tls.Certificate, error) {
	if l.pair == nil || now.Before(l.last) || now.Sub(l.last) >= time.Second {
		var pair *tls.Certificate
		var record IdentityRecord
		raw, err := readIdentityFile(l.file, MaxIdentityBytes, true)
		if err == nil {
			pair, record, err = identityPair(raw, l.ca, l.role, l.id, now, false)
		}
		clear(raw)
		if err == nil && l.pair != nil && record.ExpiresAt.Before(l.record.ExpiresAt) {
			err = ErrIdentity
		}
		if err == nil {
			l.pair, l.record, l.id = pair, record, record.ID
		}
		l.last, l.lastError = now, err
	}
	if l.lastError != nil || l.pair == nil || now.Before(l.pair.Leaf.NotBefore) || !now.Before(l.pair.Leaf.NotAfter) {
		return nil, ErrIdentity
	}
	return l.pair, nil
}
func (l *LiveIdentity) Record(now time.Time) (IdentityRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.certificateLocked(now); err != nil {
		return IdentityRecord{}, err
	}
	return l.record, nil
}
func (l *LiveIdentity) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	pair, err := l.Certificate(time.Now())
	if err == nil && info != nil {
		err = info.SupportsCertificate(pair)
	}
	return pair, err
}
func (l *LiveIdentity) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	pair, err := l.Certificate(time.Now())
	if err == nil && info != nil {
		err = info.SupportsCertificate(pair)
	}
	return pair, err
}

// PublishIdentity is a compare-and-swap activation, not an issuer. The caller
// supplies an already signed same-CA leaf and the public fingerprint it saw.
// A prior private copy is durably preserved before replacement. No process or
// service is restarted, and a failed validation leaves the active file intact.
func PublishIdentity(ctx context.Context, caFile, file, role, id, expected string, b Bundle, now time.Time) (IdentityRecord, error) {
	var empty IdentityRecord
	if _, err := Identity(role, id); err != nil || !filepath.IsAbs(file) || filepath.Clean(file) != file || file == caFile || secureDirectory(filepath.Dir(file)) != nil {
		return empty, ErrIdentity
	}
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return empty, ErrIdentity
	}
	pinned, err := parseCertificate(ca)
	other, e2 := parseCertificate(b.CA)
	if err != nil || e2 != nil || !bytes.Equal(pinned.Raw, other.Raw) {
		return empty, ErrIdentity
	}
	raw := append(append([]byte{}, b.Certificate...), b.Key...)
	defer clear(raw)
	if len(raw) > MaxIdentityBytes {
		return empty, ErrIdentity
	}
	_, record, err := identityPair(raw, ca, role, id, now, false)
	if err != nil {
		return empty, ErrIdentity
	}
	lock, err := authorityLock(ctx, filepath.Dir(file))
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	old, err := readIdentityFile(file, MaxIdentityBytes, true)
	if err == nil {
		defer clear(old)
		_, prior, e := identityPair(old, ca, role, id, now, true)
		if e != nil {
			return empty, ErrIdentity
		}
		if record.CertificateSHA256 == prior.CertificateSHA256 {
			return record, nil
		}
		if expected != prior.CertificateSHA256 || !record.ExpiresAt.After(prior.ExpiresAt) {
			return empty, ErrIdentity
		}
		if err := preserveIdentity(file, prior.CertificateSHA256, old); err != nil {
			return empty, err
		}
	} else {
		if _, e := os.Lstat(file); !os.IsNotExist(e) || expected != "" {
			return empty, ErrIdentity
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".identity-*")
	if err != nil {
		return empty, errStorage
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, err = tmp.Write(raw)
	if err == nil {
		err = tmp.Sync()
	}
	closed := tmp.Close()
	if err != nil || closed != nil || ctx.Err() != nil {
		return empty, errStorage
	}
	if len(old) == 0 {
		if err := os.Link(name, file); err != nil {
			return empty, errStorage
		}
		if err := os.Remove(name); err != nil {
			return empty, errStorage
		}
	} else if err := os.Rename(name, file); err != nil {
		return empty, errStorage
	}
	if err := syncDir(filepath.Dir(file)); err != nil {
		return empty, err
	}
	record.Changed = true
	return record, nil
}

func preserveIdentity(file, sha string, raw []byte) error {
	dir := file + ".history"
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return errStorage
	}
	if secureDirectory(dir) != nil {
		return errStorage
	}
	path := filepath.Join(dir, sha+".pem")
	if _, err := os.Lstat(path); err == nil {
		old, err := readIdentityFile(path, MaxIdentityBytes, true)
		defer clear(old)
		if err != nil || !bytes.Equal(old, raw) {
			return errStorage
		}
	} else if !os.IsNotExist(err) {
		return errStorage
	} else {
		tmp, err := os.CreateTemp(dir, ".history-*")
		if err != nil {
			return errStorage
		}
		name := tmp.Name()
		defer os.Remove(name)
		_, err = tmp.Write(raw)
		if err == nil {
			err = tmp.Sync()
		}
		closed := tmp.Close()
		if err != nil || closed != nil {
			return errStorage
		}
		if err := os.Link(name, path); err != nil {
			return errStorage
		}
		if err := os.Remove(name); err != nil {
			return errStorage
		}
	}
	return syncDir(dir)
}
