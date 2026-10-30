package nodepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func nodeRenewalFixture(t *testing.T) (*Authority, string, string, string, NodeRenewalRequest, []byte, time.Time) {
	t.Helper()
	a, _, ca, seed, state, now := seededIdentityFixture(t)
	ctx := context.Background()
	record, err := SeedNodeIdentity(ctx, ca, seed, state, "node-a", now)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(filepath.Dir(state), "authority")
	b, _ := a.Export()
	defer clear(b.Key)
	crl, err := a.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := SeedAuthority(ctx, root, b, crl, now); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(state, "active.pem")
	r, err := PrepareNodeRenewal(ctx, ca, file, "node-a", record.CertificateSHA256, now)
	if err != nil {
		t.Fatal(err)
	}
	return a, root, ca, file, r, crl, now
}

func TestNodeRenewalLocalKeySigningActivationAndLostResponse(t *testing.T) {
	_, authority, ca, file, r, crl, now := nodeRenewalFixture(t)
	ctx := context.Background()
	old, _, err := ReadIdentity(ca, file, Node, "node-a", now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(old.Key)
	retry, err := PrepareNodeRenewal(ctx, ca, file, "node-a", r.CertificateSHA256, now)
	if err != nil || retry.SHA256() != r.SHA256() || !bytes.Equal(retry.CSR, r.CSR) {
		t.Fatal("pending key was regenerated on retry", err)
	}
	publicJSON, _ := json.Marshal(r)
	if bytes.Contains(publicJSON, []byte("PRIVATE KEY")) || bytes.Contains(publicJSON, []byte(base64.StdEncoding.EncodeToString(old.Key))) {
		t.Fatal("private key in public request")
	}
	var certificate, issuedCRL []byte
	err = SignNodeRenewalRegistered(ctx, authority, r, now, 3*time.Hour, func(b Bundle, current []byte) error {
		if len(b.Key) != 0 {
			t.Fatal("issuer received a node private key")
		}
		certificate, issuedCRL = append([]byte{}, b.Certificate...), append([]byte{}, current...)
		return nil
	})
	if err != nil || !bytes.Equal(crl, issuedCRL) {
		t.Fatal("CSR signing changed CRL", err)
	}
	trust, err := NewTrust(old.CA, crl, now)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(cert *x509.Certificate) error { return trust.Verify(cert, Node, "node-a", now) }
	record, err := ActivateNodeRenewal(ctx, ca, file, "node-a", r.CertificateSHA256, r.SHA256(), certificate, now, verify)
	if err != nil || !record.Changed || record.CertificateSHA256 == r.CertificateSHA256 {
		t.Fatal("renewal not activated", err)
	}
	lost, err := ActivateNodeRenewal(ctx, ca, file, "node-a", r.CertificateSHA256, r.SHA256(), certificate, now, verify)
	if err != nil || lost.Changed || lost.CertificateSHA256 != record.CertificateSHA256 {
		t.Fatal("lost response not idempotent", err)
	}
	current, _, err := ReadIdentity(ca, file, Node, "node-a", now)
	if err != nil || bytes.Equal(current.Key, old.Key) {
		t.Fatal("replacement private key not local or unchanged", err)
	}
	defer clear(current.Key)
	prior, err := os.ReadFile(file + ".history/" + r.CertificateSHA256 + ".pem")
	if err != nil || !bytes.Equal(prior, append(append([]byte{}, old.Certificate...), old.Key...)) {
		t.Fatal("old identity not retained", err)
	}
	if _, err := PrepareNodeRenewal(ctx, ca, file, "node-a", r.CertificateSHA256, now); err == nil {
		t.Fatal("stale prepare accepted after activation")
	}
}

func TestNodeRenewalNetworkRequestCanonicalBounds(t *testing.T) {
	_, _, _, _, request, _, _ := nodeRenewalFixture(t)
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseNodeRenewalRequest(raw)
	if err != nil || parsed.SHA256() != request.SHA256() {
		t.Fatal("node-produced public request rejected", err)
	}
	for name, content := range map[string][]byte{
		"empty":      nil,
		"oversized":  bytes.Repeat([]byte{' '}, MaxRenewalBytes+1),
		"unknown":    append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"private_key":"must-not-be-accepted"}`)...),
		"duplicate":  append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"format":1}`)...),
		"whitespace": append([]byte{' '}, raw...),
		"trailing":   append(append([]byte{}, raw...), []byte(`{}`)...),
		"broken":     []byte(`{"node":`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNodeRenewalRequest(content); err == nil {
				t.Fatal("unbounded or ambiguous public request accepted")
			}
		})
	}
}

func TestNodeRenewalConcurrentPrepareAndPrivatePendingState(t *testing.T) {
	_, _, ca, file, r, _, now := nodeRenewalFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next, err := PrepareNodeRenewal(context.Background(), ca, file, "node-a", r.CertificateSHA256, now)
			if err != nil || next.SHA256() != r.SHA256() {
				t.Error("concurrent request diverged", err)
			}
		}()
	}
	wg.Wait()
	pending, _ := renewalPending(filepath.Dir(file), r.CertificateSHA256)
	for _, p := range []string{filepath.Dir(pending), pending, filepath.Join(pending, "key.pem"), filepath.Join(pending, "request.json")} {
		st, err := os.Lstat(p)
		if err != nil || st.IsDir() && st.Mode().Perm() != 0700 || !st.IsDir() && st.Mode().Perm() != 0600 {
			t.Fatal("unsafe pending state", p, err)
		}
	}
	if err := os.Remove(filepath.Join(pending, "key.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareNodeRenewal(context.Background(), ca, file, "node-a", r.CertificateSHA256, now); err == nil {
		t.Fatal("lost pending key silently regenerated")
	}
}

func TestNodeRenewalSignerRejectsEscalationCorruptionAndRevocation(t *testing.T) {
	a, authority, caFile, file, initial, crl, now := nodeRenewalFixture(t)
	old, _ := parseCertificate(initial.Certificate)
	makeCSR := func(change func(*x509.CertificateRequest), reuse bool) []byte {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		if reuse {
			b, _, err := ReadIdentity(caFile, file, Node, "node-a", now)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(b.Key)
			block, _ := pem.Decode(b.Key)
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			key = parsed.(ed25519.PrivateKey)
		}
		request := &x509.CertificateRequest{Subject: pkix.Name{CommonName: Node + ":node-a"}, DNSNames: old.DNSNames, IPAddresses: old.IPAddresses, URIs: old.URIs}
		change(request)
		raw, err := x509.CreateCertificateRequest(rand.Reader, request, key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})
	}
	for _, kind := range []string{"node", "root", "fingerprint", "dns", "subject", "same-key", "extra-extension", "broken-signature", "forged-proof", "oversize", "expired", "short-lifetime"} {
		t.Run(kind, func(t *testing.T) {
			r := initial
			at, lifetime := now, 3*time.Hour
			switch kind {
			case "node":
				r.Node = "other"
			case "root":
				r.AuthoritySHA256 = r.CertificateSHA256
			case "fingerprint":
				r.CertificateSHA256 = r.AuthoritySHA256
			case "dns":
				r.CSR = makeCSR(func(c *x509.CertificateRequest) { c.DNSNames = []string{"other.test"} }, false)
			case "subject":
				r.CSR = makeCSR(func(c *x509.CertificateRequest) { c.Subject.CommonName = Collector + ":node-a" }, false)
			case "same-key":
				r.CSR = makeCSR(func(*x509.CertificateRequest) {}, true)
			case "extra-extension":
				r.CSR = makeCSR(func(c *x509.CertificateRequest) {
					c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0}}}
				}, false)
			case "broken-signature":
				block, _ := pem.Decode(r.CSR)
				block.Bytes[len(block.Bytes)-1] ^= 1
				r.CSR = pem.EncodeToMemory(block)
			case "forged-proof":
				r.Proof = append([]byte{}, r.Proof...)
				r.Proof[0] ^= 1
			case "oversize":
				r.CSR = bytes.Repeat([]byte("x"), MaxRenewalBytes+1)
			case "expired":
				at = now.Add(2 * time.Hour)
			case "short-lifetime":
				lifetime = time.Hour
			}
			if kind != "forged-proof" && kind != "oversize" {
				counterSignNodeRenewal(t, caFile, file, &r, now)
			}
			called := false
			err := SignNodeRenewalRegistered(context.Background(), authority, r, at, lifetime, func(Bundle, []byte) error { called = true; return nil })
			if err == nil || called {
				t.Fatal("invalid CSR signed", kind, err)
			}
		})
	}
	revoked, err := a.Revoke(crl, [][]byte{initial.Certificate}, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := SeedAuthority(context.Background(), filepath.Join(filepath.Dir(authority), "revoked-authority"), mustAuthorityBundle(t, a), revoked, now); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := SignNodeRenewalRegistered(context.Background(), filepath.Join(filepath.Dir(authority), "revoked-authority"), initial, now, 3*time.Hour, func(Bundle, []byte) error { called = true; return nil }); err == nil || called {
		t.Fatal("revoked leaf renewed", err)
	}
}

func mustAuthorityBundle(t *testing.T, a *Authority) Bundle {
	t.Helper()
	b, err := a.Export()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(b.Key) })
	return b
}

func TestNodeRenewalActivationRejectsUnboundOrDeniedCertificate(t *testing.T) {
	a, authority, ca, file, r, _, now := nodeRenewalFixture(t)
	var cert []byte
	if err := SignNodeRenewalRegistered(context.Background(), authority, r, now, 3*time.Hour, func(b Bundle, _ []byte) error { cert = append([]byte{}, b.Certificate...); return nil }); err != nil {
		t.Fatal(err)
	}
	other, _ := a.Issue(Node, "node-a", []string{"node.test"}, now, 3*time.Hour)
	for _, kind := range []string{"receipt", "wrong-key", "denied", "nil-policy", "node", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			body, requestSHA, id := cert, r.SHA256(), "node-a"
			verify := func(*x509.Certificate) error { return nil }
			switch kind {
			case "receipt":
				requestSHA = r.AuthoritySHA256
			case "wrong-key":
				body = other.Certificate
			case "denied":
				verify = func(*x509.Certificate) error { return ErrRevocation }
			case "nil-policy":
				verify = nil
			case "node":
				id = "node-b"
			case "oversize":
				body = bytes.Repeat([]byte("x"), 16<<10+1)
			}
			if _, err := ActivateNodeRenewal(context.Background(), ca, file, id, r.CertificateSHA256, requestSHA, body, now, verify); err == nil {
				t.Fatal("unbound activation succeeded")
			}
			b, current, err := ReadIdentity(ca, file, Node, "node-a", now)
			clear(b.Key)
			if err != nil || current.CertificateSHA256 != r.CertificateSHA256 {
				t.Fatal("failed activation changed identity", err)
			}
		})
	}
	rejected := errors.New("isolated issuance registry failure")
	if err := SignNodeRenewalRegistered(context.Background(), authority, r, now, 3*time.Hour, func(Bundle, []byte) error { return rejected }); !errors.Is(err, rejected) {
		t.Fatal("failed registry acceptance suppressed", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PrepareNodeRenewal(ctx, ca, file, "node-a", r.CertificateSHA256, now); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled preparation succeeded", err)
	}
}

func counterSignNodeRenewal(t *testing.T, ca, file string, request *NodeRenewalRequest, now time.Time) {
	t.Helper()
	b, _, err := ReadIdentity(ca, file, Node, "node-a", now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	block, _ := pem.Decode(b.Key)
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := parsed.(ed25519.PrivateKey)
	defer clear(key)
	payload, err := renewalProofPayload(*request)
	if err != nil {
		t.Fatal(err)
	}
	request.Proof = ed25519.Sign(key, payload)
}
