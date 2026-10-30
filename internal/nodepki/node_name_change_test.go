package nodepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type nameChangeFixture struct {
	liveFixture
	authority, trust string
	crl              []byte
	intent           NodeNameChangeIntent
	request          NodeNameChangeRequest
}

func newNameChangeFixture(t *testing.T, name string) nameChangeFixture {
	t.Helper()
	f := nameChangeFixture{liveFixture: newLiveFixture(t, Node, "node-a")}
	t.Cleanup(func() { clear(f.b.Key) })
	ctx := context.Background()
	var err error
	f.crl, err = f.a.Revoke(nil, nil, f.now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.authority = filepath.Join(f.root, "authority")
	b, err := f.a.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	if err := SeedAuthority(ctx, f.authority, b, f.crl, f.now); err != nil {
		t.Fatal(err)
	}
	f.trust = filepath.Join(f.root, "trust")
	seed := filepath.Join(f.root, "crl.pem")
	if err := os.WriteFile(seed, f.crl, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewReceiverTrust(f.caFile, seed, f.trust, f.now); err != nil {
		t.Fatal(err)
	}
	root, _ := parseCertificate(f.b.CA)
	f.intent, err = NewNodeNameChangeIntent("node-a", publicSHA(root.Raw), f.record.CertificateSHA256, name, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.request, err = PrepareNodeNameChange(ctx, f.caFile, f.file, f.trust, f.intent, f.now)
	if err != nil {
		t.Fatal("prepare name change", err)
	}
	return f
}
func signNameChangeFixture(t *testing.T, f nameChangeFixture) []byte {
	t.Helper()
	var certificate []byte
	if err := SignNodeNameChangeRegistered(context.Background(), f.authority, f.request, f.intent, f.now, 3*time.Hour, func(b Bundle, crl []byte) error {
		if len(b.Key) != 0 || !bytes.Equal(crl, f.crl) {
			t.Fatal("signer exposed private key or changed CRL")
		}
		certificate = append([]byte(nil), b.Certificate...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestNodeNameChangeLocalKeyOverlapAndReplay(t *testing.T) {
	for _, name := range []string{"new-agent.test", "192.0.2.31", "2001:db8::31"} {
		t.Run(name, func(t *testing.T) {
			f := newNameChangeFixture(t, name)
			ctx := context.Background()
			old, err := os.ReadFile(f.file)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := PrepareNodeNameChange(ctx, f.caFile, f.file, f.trust, f.intent, f.now)
			if err != nil || retry.SHA256() != f.request.SHA256() {
				t.Fatal("retry generated another request", err)
			}
			raw, _ := json.Marshal(f.request)
			if _, err := ParseNodeNameChangeRequest(raw); err != nil {
				t.Fatal(err)
			}
			if _, err := ParseNodeRenewalRequest(raw); err == nil {
				t.Fatal("name change accepted as ordinary renewal")
			}
			if bytes.Contains(raw, []byte("PRIVATE KEY")) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(old))) {
				t.Fatal("public request exposed key")
			}
			if err := ValidateNodeNameChangeRequest(f.b.CA, f.crl, f.request, f.intent, f.now); err != nil {
				t.Fatal(err)
			}
			certificate := signNameChangeFixture(t, f)
			leaf, err := parseCertificate(certificate)
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range []string{"agent.test", "127.0.0.1", name} {
				if leaf.VerifyHostname(n) != nil {
					t.Fatal("overlap missing", n)
				}
			}
			first, err := ActivateNodeNameChange(ctx, f.caFile, f.file, f.trust, f.request, f.intent, certificate, f.now)
			if err != nil || !first.Changed {
				t.Fatal("activation", err)
			}
			second, err := ActivateNodeNameChange(ctx, f.caFile, f.file, f.trust, f.request, f.intent, certificate, f.now)
			if err != nil || second.Changed || second.CertificateSHA256 != first.CertificateSHA256 {
				t.Fatal("lost response replay", err)
			}
			active, _, err := ReadIdentity(f.caFile, f.file, Node, "node-a", f.now)
			defer clear(active.Key)
			if err != nil || bytes.Equal(active.Key, f.b.Key) {
				t.Fatal("new key not locally activated", err)
			}
			history, err := os.ReadFile(f.file + ".history/" + f.intent.CertificateSHA256 + ".pem")
			if err != nil || !bytes.Equal(history, old) {
				t.Fatal("old private identity not retained", err)
			}
			if _, err := PrepareNodeNameChange(ctx, f.caFile, f.file, f.trust, f.intent, f.now); err == nil {
				t.Fatal("stale source prepared after activation")
			}
			// Normal renewal now preserves the approved overlap; it cannot request a
			// third name or change the original format/validation contract.
			next, err := PrepareNodeRenewal(ctx, f.caFile, f.file, "node-a", first.CertificateSHA256, f.now)
			if err != nil || ValidateNodeRenewalRequest(f.b.CA, f.crl, next, f.now) != nil {
				t.Fatal("ordinary renewal after migration", err)
			}
			csrBlock, _ := pem.Decode(next.CSR)
			csr, _ := x509.ParseCertificateRequest(csrBlock.Bytes)
			if len(csr.DNSNames)+len(csr.IPAddresses) != 3 {
				t.Fatal("renewal lost overlap SANs")
			}
			if err := filepath.WalkDir(filepath.Join(f.root, "name-changes"), func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				st, err := d.Info()
				if err != nil {
					return err
				}
				want := os.FileMode(0600)
				if d.IsDir() {
					want = 0700
				}
				if st.Mode().Perm() != want {
					t.Errorf("unsafe pending state %s", path)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeNameChangeIntentCanonicalNamesAndLimits(t *testing.T) {
	for _, name := range []string{"", "NEW.test", "node.test.", "*.test", "http://node.test", "node.test:19100", "[::1]", "::ffff:192.0.2.1", "fe80::1%en0", "2001:0db8::1", "a/b", " bad.test", strings.Repeat("a", 254)} {
		if _, err := NewNodeNameChangeIntent("node-a", strings.Repeat("a", 64), strings.Repeat("b", 64), name, time.Now()); err == nil {
			t.Fatalf("unsafe/noncanonical name accepted %q", name)
		}
	}
	f := newNameChangeFixture(t, "new.test")
	for _, scenario := range []string{"expired", "future", "long", "node", "authority", "parent", "name", "nonce"} {
		t.Run(scenario, func(t *testing.T) {
			i := f.intent
			switch scenario {
			case "expired":
				i.ExpiresAt = f.now
			case "future":
				i.IssuedAt = f.now.Add(time.Second)
			case "long":
				i.ExpiresAt = i.IssuedAt.Add(11 * time.Minute)
			case "node":
				i.Node = "other-node"
			case "authority":
				i.AuthoritySHA256 = strings.Repeat("c", 64)
			case "parent":
				i.CertificateSHA256 = strings.Repeat("c", 64)
			case "name":
				i.ServerName = "other.test"
			case "nonce":
				i.Challenge = strings.Repeat("c", 64)
			}
			if ValidateNodeNameChangeRequest(f.b.CA, f.crl, f.request, i, f.now) == nil {
				t.Fatal("mismatched intent accepted")
			}
		})
	}
	old, _ := parseCertificate(f.b.Certificate)
	if _, err := nameChangeTemplate(old, "agent.test"); err == nil {
		t.Fatal("unnecessary name rotation accepted")
	}
	crowded := *old
	crowded.DNSNames = nil
	crowded.IPAddresses = nil
	for n := 0; n < 16; n++ {
		crowded.DNSNames = append(crowded.DNSNames, strings.Repeat("a", n+1)+".test")
	}
	if _, err := nameChangeTemplate(&crowded, "new.test"); err == nil {
		t.Fatal("over 16 SANs accepted")
	}
}

func nameChangeOldKey(t *testing.T, f nameChangeFixture) ed25519.PrivateKey {
	t.Helper()
	b, _, err := ReadIdentity(f.caFile, f.file, Node, "node-a", f.now)
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
	return parsed.(ed25519.PrivateKey)
}
func signNameChangeProofForTest(t *testing.T, f nameChangeFixture, r *NodeNameChangeRequest) {
	t.Helper()
	key := nameChangeOldKey(t, f)
	defer clear(key)
	payload, err := nameChangeProof(*r)
	if err != nil {
		t.Fatal(err)
	}
	r.Proof = ed25519.Sign(key, payload)
}
func TestNodeNameChangeRejectsForgedCSRAndCrossProtocolProof(t *testing.T) {
	f := newNameChangeFixture(t, "new.test")
	for _, scenario := range []string{"proof", "renewal-domain", "kind", "certificate", "extra-san", "missing-old-san", "other-uri", "wrong-cn", "extra-extension", "same-key", "unknown-field", "duplicate-field", "whitespace", "trailing-json", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			raw, _ := json.Marshal(f.request)
			r, _ := ParseNodeNameChangeRequest(raw)
			if scenario == "unknown-field" || scenario == "duplicate-field" || scenario == "whitespace" || scenario == "trailing-json" || scenario == "oversize" {
				switch scenario {
				case "unknown-field":
					raw = append(raw[:len(raw)-1], []byte(`,"secret":"reject"}`)...)
				case "duplicate-field":
					raw = append(raw[:len(raw)-1], []byte(`,"format":1}`)...)
				case "whitespace":
					raw = append([]byte(" "), raw...)
				case "trailing-json":
					raw = append(raw, []byte(`{}`)...)
				case "oversize":
					raw = bytes.Repeat([]byte("x"), MaxRenewalBytes+1)
				}
				if _, err := ParseNodeNameChangeRequest(raw); err == nil {
					t.Fatal("noncanonical request accepted")
				}
				return
			}
			switch scenario {
			case "proof":
				r.Proof[0] ^= 1
			case "renewal-domain":
				key := nameChangeOldKey(t, f)
				defer clear(key)
				payload, _ := renewalProofPayload(NodeRenewalRequest{Format: 1, Node: f.intent.Node, Certificate: f.b.Certificate, CSR: r.CSR})
				r.Proof = ed25519.Sign(key, payload)
			case "kind":
				r.Kind = "ordinary-renewal"
			case "certificate":
				r.Certificate = []byte("invalid")
			default:
				block, _ := pem.Decode(r.CSR)
				csr, err := x509.ParseCertificateRequest(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(key)
				template := &x509.CertificateRequest{Subject: csr.Subject, URIs: csr.URIs, DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses}
				switch scenario {
				case "extra-san":
					template.DNSNames = append(template.DNSNames, "unapproved.test")
				case "missing-old-san":
					template.DNSNames = []string{"new.test"}
				case "other-uri":
					template.URIs = nil
				case "wrong-cn":
					template.Subject = pkix.Name{CommonName: "node:other"}
				case "extra-extension":
					template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x00}}}
				case "same-key":
					clear(key)
					key = nameChangeOldKey(t, f)
					defer clear(key)
				}
				der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
				if err != nil {
					t.Fatal(err)
				}
				r.CSR = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
				signNameChangeProofForTest(t, f, &r)
			}
			if ValidateNodeNameChangeRequest(f.b.CA, f.crl, r, f.intent, f.now) == nil {
				t.Fatal("unapproved name request accepted")
			}
			if err := SignNodeNameChangeRegistered(context.Background(), f.authority, r, f.intent, f.now, 3*time.Hour, func(Bundle, []byte) error { t.Fatal("forged request reached commit"); return nil }); err == nil {
				t.Fatal("forged request signed")
			}
		})
	}
}

func TestNodeNameChangeActivationCurrentFloorAndLocalMaterial(t *testing.T) {
	for _, scenario := range []string{"revoked-parent", "revoked-new", "expired-floor", "missing-floor", "wrong-root", "request-mismatch", "key-missing", "key-corrupt", "key-permissions", "key-symlink", "request-symlink", "active-changed", "expired-intent", "wrong-certificate", "wrong-pending-cert"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeFixture(t, "new.test")
			certificate := signNameChangeFixture(t, f)
			before, err := os.ReadFile(f.file)
			if err != nil {
				t.Fatal(err)
			}
			pending := nameChangePending(f.file, f.intent)
			request := f.request
			now := f.now
			switch scenario {
			case "revoked-parent", "revoked-new":
				revoked := f.b.Certificate
				if scenario == "revoked-new" {
					revoked = certificate
				}
				next, err := f.a.Revoke(f.crl, [][]byte{revoked}, f.now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.trust, "ca.crl"), next, 0600); err != nil {
					t.Fatal(err)
				}
			case "expired-floor":
				expired, err := f.a.Revoke(nil, nil, f.now.Add(-2*time.Hour), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.trust, "ca.crl"), expired, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-floor":
				os.Remove(filepath.Join(f.trust, "ca.crl"))
			case "wrong-root":
				other, _ := NewAuthority(f.now, 365*24*time.Hour)
				b, _ := other.Export()
				defer clear(b.Key)
				os.WriteFile(filepath.Join(f.trust, "ca.crt"), b.CA, 0600)
			case "request-mismatch":
				request.Proof = append([]byte(nil), request.Proof...)
				request.Proof[0] ^= 1
			case "key-missing":
				os.Remove(filepath.Join(pending, "key.pem"))
			case "key-corrupt":
				os.WriteFile(filepath.Join(pending, "key.pem"), []byte("invalid"), 0600)
			case "key-permissions":
				os.Chmod(filepath.Join(pending, "key.pem"), 0644)
			case "key-symlink", "request-symlink":
				name := "key.pem"
				if scenario == "request-symlink" {
					name = "request.json"
				}
				original := filepath.Join(pending, name)
				target := original + ".original"
				os.Rename(original, target)
				os.Symlink(target, original)
			case "active-changed":
				other, err := f.a.Issue(Node, "node-a", []string{"agent.test"}, f.now, 4*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(other.Key)
				if _, err := PublishIdentity(context.Background(), f.caFile, f.file, Node, "node-a", f.record.CertificateSHA256, other, f.now); err != nil {
					t.Fatal(err)
				}
				before, _ = os.ReadFile(f.file)
			case "expired-intent":
				now = f.intent.ExpiresAt
			case "wrong-certificate":
				other, err := f.a.Issue(Node, "node-a", []string{"agent.test", "127.0.0.1", "new.test"}, f.now, 3*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(other.Key)
				certificate = other.Certificate
			case "wrong-pending-cert":
				request.Certificate = []byte("broken")
			}
			if _, err := ActivateNodeNameChange(context.Background(), f.caFile, f.file, f.trust, request, f.intent, certificate, now); err == nil {
				t.Fatal("unproven candidate activated")
			}
			after, err := os.ReadFile(f.file)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed activation overwrote active identity", err)
			}
		})
	}
}

func TestNodeNameChangeSigningCommitFailureAndRevocation(t *testing.T) {
	for _, scenario := range []string{"callback", "revocation", "expiry", "short-lifetime", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeFixture(t, "new.test")
			before, _ := os.ReadFile(f.file)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now := f.now
			lifetime := 3 * time.Hour
			sentinel := errors.New("isolated transaction rollback")
			if scenario == "canceled" {
				cancel()
			}
			if scenario == "expiry" {
				now = f.intent.ExpiresAt
			}
			if scenario == "short-lifetime" {
				lifetime = time.Hour
			}
			if scenario == "revocation" {
				parent := filepath.Join(f.root, "parent.crt")
				if err := os.WriteFile(parent, f.b.Certificate, 0600); err != nil {
					t.Fatal(err)
				}
				if err := Command(ctx, Options{Action: "revoke", Authority: f.authority, Certificate: parent}, &bytes.Buffer{}); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			err := SignNodeNameChangeRegistered(ctx, f.authority, f.request, f.intent, now, lifetime, func(Bundle, []byte) error { calls++; return sentinel })
			if err == nil || scenario == "callback" && (!errors.Is(err, sentinel) || calls != 1) || scenario != "callback" && calls != 0 {
				t.Fatal("uncommitted or invalid signing result", err, calls)
			}
			after, _ := os.ReadFile(f.file)
			if !bytes.Equal(before, after) {
				t.Fatal("signing mutated node identity")
			}
		})
	}
}

func TestNodeNameChangeActualMTLSKeepsListenerAndBothNames(t *testing.T) {
	f := newNameChangeFixture(t, "new.test")
	live, err := NewLiveIdentity(f.caFile, f.file, Node, "node-a", f.now)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := f.a.Issue(Collector, "collector-a", nil, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(collector.Key)
	pair, err := tls.X509KeyPair(collector.Certificate, collector.Key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(f.b.CA)
	trust, err := NewTrust(f.b.CA, f.crl, f.now)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, GetCertificate: live.GetCertificate, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) != 1 {
			return ErrIdentity
		}
		return trust.Verify(s.PeerCertificates[0], Collector, "collector-a", time.Now())
	}}
	call := func(name string, want bool) string {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			raw, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(3 * time.Second))
			done <- tls.Server(raw, server).Handshake()
		}()
		raw, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
		if err != nil {
			listener.Close()
			<-done
			t.Fatal(err)
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(3 * time.Second))
		conn := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: name, Certificates: []tls.Certificate{pair}, VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) != 1 {
				return ErrIdentity
			}
			return trust.Verify(s.PeerCertificates[0], Node, "node-a", time.Now())
		}})
		err = conn.Handshake()
		if err != nil {
			raw.Close()
		}
		remoteErr := <-done
		if !want {
			if err == nil {
				t.Fatal("unapproved hostname verified before migration")
			}
			return ""
		}
		if err != nil || remoteErr != nil {
			t.Fatal("normal mTLS/name validation failed", name, err, remoteErr)
		}
		return publicSHA(conn.ConnectionState().PeerCertificates[0].Raw)
	}
	if got := call("agent.test", true); got != f.record.CertificateSHA256 {
		t.Fatal("wrong initial peer")
	}
	call("new.test", false)
	certificate := signNameChangeFixture(t, f)
	result, err := ActivateNodeNameChange(context.Background(), f.caFile, f.file, f.trust, f.request, f.intent, certificate, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// Refresh the normal live identity cache; no listener or process restart.
	// The preceding real handshakes may cross the fixture's truncated second.
	// Advance from the actual current clock, so the one-second reload cache is
	// always expired instead of occasionally reusing the original leaf.
	if _, err := live.Certificate(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agent.test", "new.test", "127.0.0.1"} {
		if got := call(name, true); got != result.CertificateSHA256 {
			t.Fatal("stale peer after migration", name, "peer", got, "expected", result.CertificateSHA256, "cached", live.record.CertificateSHA256)
		}
	}
}

func TestNodeNameChangeConcurrentPreparationAndActivation(t *testing.T) {
	f := newNameChangeFixture(t, "new.test")
	var wg sync.WaitGroup
	results := make(chan NodeNameChangeRequest, 6)
	errs := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := PrepareNodeNameChange(context.Background(), f.caFile, f.file, f.trust, f.intent, f.now)
			if err != nil {
				errs <- err
			} else {
				results <- r
			}
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for r := range results {
		if r.SHA256() != f.request.SHA256() {
			t.Fatal("concurrent prepare produced another key")
		}
	}
	certificate := signNameChangeFixture(t, f)
	records := make(chan IdentityRecord, 6)
	errs = make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := ActivateNodeNameChange(context.Background(), f.caFile, f.file, f.trust, f.request, f.intent, certificate, f.now)
			if err != nil {
				errs <- err
			} else {
				records <- r
			}
		}()
	}
	wg.Wait()
	close(records)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	changes := 0
	for r := range records {
		if r.Changed {
			changes++
		}
	}
	if changes != 1 {
		t.Fatal("activation not idempotent", changes)
	}
}

func TestNodeNameChangeLocksCancelWithoutPublication(t *testing.T) {
	for _, phase := range []string{"prepare-trust", "prepare-identity", "sign-authority", "activate-trust", "activate-identity"} {
		t.Run(phase, func(t *testing.T) {
			f := newNameChangeFixture(t, "new.test")
			certificate := signNameChangeFixture(t, f)
			before, err := os.ReadFile(f.file)
			if err != nil {
				t.Fatal(err)
			}
			dir := f.trust
			if strings.Contains(phase, "identity") {
				dir = filepath.Dir(f.file)
			}
			if phase == "sign-authority" {
				dir = f.authority
			}
			lock, err := authorityLock(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if strings.HasPrefix(phase, "prepare") {
				_, err = PrepareNodeNameChange(ctx, f.caFile, f.file, f.trust, f.intent, f.now)
			} else if strings.HasPrefix(phase, "activate") {
				_, err = ActivateNodeNameChange(ctx, f.caFile, f.file, f.trust, f.request, f.intent, certificate, f.now)
			} else {
				err = SignNodeNameChangeRegistered(ctx, f.authority, f.request, f.intent, f.now, 3*time.Hour, func(Bundle, []byte) error { t.Fatal("unfenced callback ran"); return nil })
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("held lock ignored cancellation", err)
			}
			after, e := os.ReadFile(f.file)
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("lock timeout changed identity", e)
			}
		})
	}
}

func TestNodeNameChangePreparationDoesNotRepairMissingState(t *testing.T) {
	for _, scenario := range []string{"missing-trust", "missing-identity", "missing-key", "corrupt-request", "public-pending", "same-lock-directory", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeFixture(t, "new.test")
			before, _ := os.ReadFile(f.file)
			pending := nameChangePending(f.file, f.intent)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			trust := f.trust
			switch scenario {
			case "missing-trust":
				if err := os.RemoveAll(f.trust); err != nil {
					t.Fatal(err)
				}
			case "missing-identity":
				if err := os.Remove(f.file); err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				if err := os.Remove(filepath.Join(pending, "key.pem")); err != nil {
					t.Fatal(err)
				}
			case "corrupt-request":
				if err := os.WriteFile(filepath.Join(pending, "request.json"), []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public-pending":
				if err := os.Chmod(pending, 0755); err != nil {
					t.Fatal(err)
				}
			case "same-lock-directory":
				trust = filepath.Dir(f.file)
			case "canceled":
				cancel()
			}
			if _, err := PrepareNodeNameChange(ctx, f.caFile, f.file, trust, f.intent, f.now); err == nil {
				t.Fatal("unsafe preparation accepted")
			}
			if scenario == "missing-identity" {
				if _, err := os.Lstat(f.file); !os.IsNotExist(err) {
					t.Fatal("missing active identity repaired")
				}
				return
			}
			after, err := os.ReadFile(f.file)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed preparation changed active identity", err)
			}
			if scenario == "missing-key" {
				if _, err := os.Lstat(filepath.Join(pending, "key.pem")); !os.IsNotExist(err) {
					t.Fatal("missing pending key regenerated")
				}
			}
			if scenario == "missing-trust" {
				if _, err := os.Lstat(f.trust); !os.IsNotExist(err) {
					t.Fatal("missing trust initialized")
				}
			}
		})
	}
}

func TestNodeNameChangeDoesNotReportCanceledCommitAsSuccess(t *testing.T) {
	f := newNameChangeFixture(t, "new.test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := false
	err := SignNodeNameChangeRegistered(ctx, f.authority, f.request, f.intent, f.now, 3*time.Hour, func(Bundle, []byte) error { called = true; cancel(); return nil })
	if !called || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled callback reported successful delivery", err)
	}
}

func TestNodeNameChangeActivationRejectsSignedScopeExpansion(t *testing.T) {
	for _, scenario := range []string{"extra-dns", "missing-old-dns", "missing-ip", "email", "extra-usage", "extra-key-usage", "wrong-subject", "wrong-role", "ca", "not-extending"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeFixture(t, "new.test")
			certificate := signNameChangeFixture(t, f)
			before, err := os.ReadFile(f.file)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := parseCertificate(certificate)
			if err != nil {
				t.Fatal(err)
			}
			leaf.ExtraExtensions = nil
			// Parsed RawSubject otherwise overrides Subject on re-encoding.
			leaf.RawSubject = nil
			switch scenario {
			case "extra-dns":
				leaf.DNSNames = append(leaf.DNSNames, "unapproved.test")
			case "missing-old-dns":
				leaf.DNSNames = []string{"new.test"}
			case "missing-ip":
				leaf.IPAddresses = nil
			case "email":
				leaf.EmailAddresses = []string{"unapproved@example.test"}
			case "extra-usage":
				leaf.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
			case "extra-key-usage":
				leaf.KeyUsage |= x509.KeyUsageCertSign
			case "wrong-subject":
				leaf.Subject = pkix.Name{CommonName: "node:other"}
			case "wrong-role":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			case "ca":
				leaf.IsCA = true
			case "not-extending":
				leaf.NotAfter = f.now.Add(time.Hour)
			}
			der, err := x509.CreateCertificate(rand.Reader, leaf, f.a.certificate, leaf.PublicKey, f.a.key)
			if err != nil {
				t.Fatal(err)
			}
			candidate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			if _, err := ActivateNodeNameChange(context.Background(), f.caFile, f.file, f.trust, f.request, f.intent, candidate, f.now); err == nil {
				t.Fatal("scope-expanded CA leaf activated")
			}
			after, e := os.ReadFile(f.file)
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("invalid signed candidate changed identity", e)
			}
		})
	}
}
