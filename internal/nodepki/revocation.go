package nodepki

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sort"
	"sync"
	"time"
)

const MaxCRLBytes = 4 << 20
const maxRevoked = 100000

func parseCRL(raw []byte, ca *x509.Certificate) (*x509.RevocationList, error) {
	if len(raw) == 0 || len(raw) > MaxCRLBytes {
		return nil, ErrRevocation
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "X509 CRL" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrRevocation
	}
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil || list.CheckSignatureFrom(ca) != nil || list.Number == nil || list.Number.Sign() < 1 || len(list.RevokedCertificateEntries) > maxRevoked {
		return nil, ErrRevocation
	}
	return list, nil
}

// Revoke creates a complete signed snapshot, never a delta. The previous
// snapshot may have expired but must be authentic; revocations cannot disappear
// during renewal. Persist it atomically before publishing any newer revision.
func (a *Authority) Revoke(previous []byte, certificates [][]byte, now time.Time, lifetime time.Duration) ([]byte, error) {
	if a == nil || !validAuthority(a.certificate, now) || lifetime < time.Hour || lifetime > 7*24*time.Hour || now.Add(lifetime).After(a.certificate.NotAfter) {
		return nil, ErrRevocation
	}
	number := big.NewInt(1)
	entries := map[string]x509.RevocationListEntry{}
	if len(previous) > 0 {
		old, err := parseCRL(previous, a.certificate)
		if err != nil || old.ThisUpdate.After(now) {
			return nil, ErrRevocation
		}
		number.Add(old.Number, big.NewInt(1))
		for _, entry := range old.RevokedCertificateEntries {
			entries[entry.SerialNumber.String()] = entry
		}
	}
	for _, raw := range certificates {
		cert, err := parseCertificate(raw)
		if err != nil || cert.IsCA || cert.CheckSignatureFrom(a.certificate) != nil {
			return nil, ErrIdentity
		}
		serial := cert.SerialNumber.String()
		if _, ok := entries[serial]; !ok {
			entries[serial] = x509.RevocationListEntry{SerialNumber: cert.SerialNumber, RevocationTime: now, ReasonCode: 5}
		}
	}
	if len(entries) > maxRevoked {
		return nil, ErrRevocation
	}
	sorted := make([]x509.RevocationListEntry, 0, len(entries))
	for _, entry := range entries {
		sorted = append(sorted, entry)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].SerialNumber.Cmp(sorted[j].SerialNumber) < 0 })
	raw, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: number, ThisUpdate: now, NextUpdate: now.Add(lifetime), RevokedCertificateEntries: sorted}, a.certificate, a.key)
	if err != nil {
		return nil, ErrRevocation
	}
	result := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: raw})
	if len(result) > MaxCRLBytes {
		return nil, ErrRevocation
	}
	return result, nil
}

type Trust struct {
	ca                     *x509.Certificate
	roots                  *x509.CertPool
	mu                     sync.RWMutex
	number                 *big.Int
	listSHA                [32]byte
	thisUpdate, nextUpdate time.Time
	revoked                map[string]bool
}

func (t *Trust) validAt(now time.Time) bool {
	if t == nil || !validAuthority(t.ca, now) {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.number != nil && !now.Before(t.thisUpdate) && now.Before(t.nextUpdate)
}

func NewTrust(ca, crl []byte, now time.Time) (*Trust, error) {
	cert, err := parseCertificate(ca)
	if err != nil || !validAuthority(cert, now) {
		return nil, ErrIdentity
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	t := &Trust{ca: cert, roots: pool}
	if err := t.UpdateCRL(crl, now); err != nil {
		return nil, err
	}
	return t, nil
}
func (t *Trust) UpdateCRL(raw []byte, now time.Time) error {
	list, err := parseCRL(raw, t.ca)
	if err != nil || list.ThisUpdate.After(now) || !now.Before(list.NextUpdate) || list.NextUpdate.Sub(list.ThisUpdate) > 7*24*time.Hour {
		return ErrRevocation
	}
	sum := sha256.Sum256(list.Raw)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.number != nil {
		cmp := list.Number.Cmp(t.number)
		if cmp < 0 || cmp == 0 && sum != t.listSHA || list.ThisUpdate.Before(t.thisUpdate) {
			return ErrRevocation
		}
		// Increasing the number cannot un-revoke a previously revoked certificate.
		next := map[string]bool{}
		for _, e := range list.RevokedCertificateEntries {
			next[e.SerialNumber.String()] = true
		}
		for serial := range t.revoked {
			if !next[serial] {
				return ErrRevocation
			}
		}
	}
	revoked := map[string]bool{}
	for _, e := range list.RevokedCertificateEntries {
		if e.SerialNumber.Sign() < 1 || e.RevocationTime.After(list.ThisUpdate) {
			return ErrRevocation
		}
		serial := e.SerialNumber.String()
		if revoked[serial] {
			return ErrRevocation
		}
		revoked[serial] = true
	}
	t.number = new(big.Int).Set(list.Number)
	t.listSHA = sum
	t.thisUpdate = list.ThisUpdate
	t.nextUpdate = list.NextUpdate
	t.revoked = revoked
	return nil
}

// Verify must also be invoked for each RPC on existing HTTP/2 connections.
// TLS handshake verification alone would leave a revoked long-lived peer active.
func (t *Trust) Verify(cert *x509.Certificate, role, id string, now time.Time) error {
	identity, err := Identity(role, id)
	if err != nil || cert == nil || cert.IsCA || len(cert.URIs) != 1 || cert.URIs[0].String() != identity || len(cert.ExtKeyUsage) != 1 {
		return ErrIdentity
	}
	usage := x509.ExtKeyUsageClientAuth
	if role == Node {
		usage = x509.ExtKeyUsageServerAuth
	}
	if cert.ExtKeyUsage[0] != usage {
		return ErrIdentity
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: t.roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return ErrIdentity
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.number == nil || now.Before(t.thisUpdate) || !now.Before(t.nextUpdate) || t.revoked[cert.SerialNumber.String()] {
		return ErrRevocation
	}
	return nil
}
