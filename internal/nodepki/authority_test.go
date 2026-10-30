package nodepki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testAuthority(t *testing.T) (*Authority, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	a, err := NewAuthority(now, 2*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return a, now
}
func testLeaf(t *testing.T, a *Authority, role, id string, now time.Time) (Bundle, *x509.Certificate) {
	t.Helper()
	var names []string
	if role == Node {
		names = []string{"node.test", "127.0.0.1"}
	}
	b, err := a.Issue(role, id, names, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(b.Certificate, b.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return b, cert
}
func TestCertificateRolesIdentityAndAuthorityRoundTrip(t *testing.T) {
	a, now := testAuthority(t)
	exported, err := a.Export()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ParseAuthority(exported.CA, exported.Key, now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.certificate.Raw, a.certificate.Raw) {
		t.Fatal("authority changed")
	}
	raw, _ := json.Marshal(exported)
	if string(raw) != "{}" {
		t.Fatal("secret JSON export", string(raw))
	}
	crl, err := a.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrust(exported.CA, crl, now)
	if err != nil {
		t.Fatal(err)
	}
	serials := map[string]bool{}
	for _, role := range []string{Node, Collector} {
		b, cert := testLeaf(t, restored, role, "host-001", now)
		if serials[cert.SerialNumber.String()] {
			t.Fatal("serial reused")
		}
		serials[cert.SerialNumber.String()] = true
		if cert.SerialNumber.BitLen() > 159 {
			t.Fatal("serial exceeds certificate limit")
		}
		raw, _ := json.Marshal(b)
		if string(raw) != "{}" {
			t.Fatal("private key entered JSON")
		}
		if err := trust.Verify(cert, role, "host-001", now); err != nil {
			t.Fatal(err)
		}
		if id, err := PeerID(cert, role); err != nil || id != "host-001" {
			t.Fatal("wrong canonical identity", id, err)
		}
		wrong := Node
		if role == Node {
			wrong = Collector
		}
		if trust.Verify(cert, wrong, "host-001", now) == nil || trust.Verify(cert, role, "other", now) == nil {
			t.Fatal("cross-role or cross-node authentication")
		}
		if role == Node && cert.VerifyHostname("node.test") != nil {
			t.Fatal("missing node SAN")
		}
		if role == Collector && len(cert.DNSNames) != 0 {
			t.Fatal("collector given server names")
		}
		if trust.Verify(cert, role, "host-001", now.Add(25*time.Hour)) == nil {
			t.Fatal("expired certificate accepted")
		}
	}
	for _, change := range []struct {
		role, id string
		names    []string
		ttl      time.Duration
	}{
		{"admin", "a", nil, time.Hour}, {Node, "../a", []string{"a"}, time.Hour}, {Node, "a", nil, time.Hour},
		{Node, "a", []string{"*.test"}, time.Hour}, {Node, "a", []string{"https://node.test"}, time.Hour},
		{Node, "a", []string{"a", "a"}, time.Hour}, {Collector, "a", []string{"a"}, time.Hour},
		{Collector, "a", nil, 0}, {Node, "a", []string{"a"}, 91 * 24 * time.Hour},
	} {
		if _, err := a.Issue(change.role, change.id, change.names, now, change.ttl); err == nil {
			t.Fatal("invalid leaf accepted", change)
		}
	}
	other, _ := testAuthority(t)
	otherKey, _ := other.Export()
	for _, pair := range []struct{ cert, key []byte }{
		{exported.CA, otherKey.Key}, {append(exported.CA, exported.CA...), exported.Key}, {exported.CA, append(exported.Key, exported.Key...)}, {exported.CA, []byte("invalid")},
	} {
		if _, err := ParseAuthority(pair.cert, pair.key, now); err == nil {
			t.Fatal("invalid authority imported")
		}
	}
	if _, err := ParseAuthority(exported.CA, exported.Key, now.Add(3*365*24*time.Hour)); err == nil {
		t.Fatal("expired authority accepted")
	}
}
func TestCRLRenewalRevocationAndMonotonicSnapshots(t *testing.T) {
	a, now := testAuthority(t)
	b, cert := testLeaf(t, a, Collector, "collector-a", now)
	initial, err := a.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	exported, _ := a.Export()
	trust, err := NewTrust(exported.CA, initial, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.Verify(cert, Collector, "collector-a", now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Minute)
	revoked, err := a.Revoke(initial, [][]byte{b.Certificate, b.Certificate}, later, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.UpdateCRL(revoked, later); err != nil {
		t.Fatal(err)
	}
	if trust.Verify(cert, Collector, "collector-a", later) == nil {
		t.Fatal("revoked peer accepted")
	}
	if err := trust.UpdateCRL(initial, later); err == nil {
		t.Fatal("CRL rollback accepted")
	}
	if err := trust.UpdateCRL(revoked, later); err != nil {
		t.Fatal("same CRL rejected", err)
	}
	renewed, err := a.Revoke(revoked, nil, later.Add(2*time.Hour), time.Hour)
	if err != nil {
		t.Fatal("expired authentic snapshot cannot be renewed", err)
	}
	if err := trust.UpdateCRL(renewed, later.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if trust.Verify(cert, Collector, "collector-a", later.Add(2*time.Hour)) == nil {
		t.Fatal("renewal removed revocation")
	}
	other, _ := testAuthority(t)
	wrong, _ := other.Revoke(nil, nil, now, time.Hour)
	for _, raw := range [][]byte{nil, []byte("broken"), wrong, append(revoked, revoked...)} {
		if trust.UpdateCRL(raw, later) == nil {
			t.Fatal("invalid CRL accepted")
		}
	}
	if _, err := a.Revoke(wrong, nil, later, time.Hour); err == nil {
		t.Fatal("foreign authority revocations accepted")
	}
	if _, err := a.Revoke(nil, [][]byte{exported.CA}, later, time.Hour); err == nil {
		t.Fatal("CA revoked as leaf")
	}
	// Even a newer correctly signed snapshot may not silently remove a revoke.
	list, err := parseCRL(renewed, a.certificate)
	if err != nil {
		t.Fatal(err)
	}
	list.Number.Add(list.Number, big.NewInt(1))
	list.RevokedCertificateEntries = nil
	list.RevokedCertificates = nil
	raw, err := x509.CreateRevocationList(rand.Reader, list, a.certificate, a.key)
	if err != nil {
		t.Fatal(err)
	}
	if trust.UpdateCRL(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: raw}), later.Add(2*time.Hour)) == nil {
		t.Fatal("signed un-revocation accepted")
	}
	if _, err := NewTrust(exported.CA, initial, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired initial CRL accepted")
	}
	if _, err := NewTrust(exported.CA, revoked, now); err == nil {
		t.Fatal("future CRL accepted")
	}
}
func TestPeerIDRejectsAmbiguousURIs(t *testing.T) {
	for _, raw := range []string{"spiffe://webscan/collector/a?role=admin", "spiffe://webscan/collector/a/extra", "spiffe://webscan/collector/%61", "spiffe://other/collector/a", "spiffe://webscan/node/a"} {
		uri, _ := url.Parse(raw)
		if _, err := PeerID(&x509.Certificate{URIs: []*url.URL{uri}}, Collector); err == nil {
			t.Fatal("ambiguous URI accepted", raw)
		}
	}
	uri, _ := url.Parse("spiffe://webscan/collector/a")
	if _, err := PeerID(&x509.Certificate{URIs: []*url.URL{uri, uri}}, Collector); err == nil {
		t.Fatal("multiple identities accepted")
	}
}
func TestFilePolicyReloadsOnExistingPeerAndFailsClosed(t *testing.T) {
	a, now := testAuthority(t)
	b, cert := testLeaf(t, a, Collector, "collector-a", now)
	fresh, _ := testLeaf(t, a, Collector, "collector-a", now)
	ca, _ := a.Export()
	initial, _ := a.Revoke(nil, nil, now, time.Hour)
	dir := t.TempDir()
	capath, crlpath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.crl")
	os.WriteFile(capath, ca.CA, 0600)
	os.WriteFile(crlpath, initial, 0600)
	policy, err := NewFileTrust(capath, crlpath, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Verify(cert, Collector, "collector-a", now); err != nil {
		t.Fatal(err)
	}
	revoked, _ := a.Revoke(initial, [][]byte{b.Certificate}, now.Add(time.Second), time.Hour)
	temp := filepath.Join(dir, "new.crl")
	os.WriteFile(temp, revoked, 0600)
	if err := os.Rename(temp, crlpath); err != nil {
		t.Fatal(err)
	}
	if policy.Verify(cert, Collector, "collector-a", now.Add(2*time.Second)) == nil {
		t.Fatal("existing peer not revoked")
	}
	freshCert, _ := parseCertificate(fresh.Certificate)
	if err := policy.Verify(freshCert, Collector, "collector-a", now.Add(2*time.Second)); err != nil {
		t.Fatal("rotation rejected", err)
	}
	os.WriteFile(crlpath, initial, 0600)
	if policy.Verify(freshCert, Collector, "collector-a", now.Add(3*time.Second)) == nil {
		t.Fatal("stale file accepted")
	}
	os.WriteFile(crlpath, revoked, 0600)
	if err := policy.Verify(freshCert, Collector, "collector-a", now.Add(4*time.Second)); err != nil {
		t.Fatal("recovery failed", err)
	}
	os.Remove(crlpath)
	if policy.Verify(freshCert, Collector, "collector-a", now.Add(5*time.Second)) == nil {
		t.Fatal("missing CRL accepted")
	}
	os.Symlink(capath, crlpath)
	if _, err := NewFileTrust(capath, crlpath, now); err == nil {
		t.Fatal("symlink accepted")
	}
	os.Remove(crlpath)
	os.WriteFile(crlpath, revoked, 0666)
	os.Chmod(crlpath, 0666)
	if _, err := NewFileTrust(capath, crlpath, now.Add(time.Second)); err == nil {
		t.Fatal("writable CRL accepted")
	}
}
func TestConcurrentCRLReadsAndRenewal(t *testing.T) {
	a, now := testAuthority(t)
	_, cert := testLeaf(t, a, Node, "node-a", now)
	crl, _ := a.Revoke(nil, nil, now, time.Hour)
	ca, _ := a.Export()
	trust, err := NewTrust(ca.CA, crl, now)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := trust.Verify(cert, Node, "node-a", now); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		if err := trust.UpdateCRL(crl, now); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	// Public-key data alone cannot be parsed as an authority private key.
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParseAuthority(ca.CA, public, now); err == nil {
		t.Fatal("public key imported as authority")
	}
}
