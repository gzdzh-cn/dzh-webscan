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
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type namePruningFixture struct {
	nameChangeFixture
	i      NodeNamePruningIntent
	r      NodeNamePruningRequest
	parent []byte
}

func newNamePruningFixture(t *testing.T, names []string, target ...string) namePruningFixture {
	t.Helper()
	active := "new.test"
	if len(target) > 0 {
		active = target[0]
	}
	f := namePruningFixture{nameChangeFixture: newNameChangeFixture(t, active)}
	ctx := context.Background()
	f.parent = signNameChangeFixture(t, f.nameChangeFixture)
	record, err := ActivateNodeNameChange(ctx, f.caFile, f.file, f.trust, f.request, f.intent, f.parent, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.i, err = NewNodeNamePruningIntent("node-a", f.intent.AuthoritySHA256, record.CertificateSHA256, strings.Repeat("a", 64), 3, active, names, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.r, err = PrepareNodeNamePruning(ctx, f.caFile, f.file, f.trust, f.i, f.now)
	if err != nil {
		t.Fatal("pruning preparation", err)
	}
	return f
}

func signNamePruningFixture(t *testing.T, f namePruningFixture) []byte {
	t.Helper()
	var certificate []byte
	if err := SignNodeNamePruningRegistered(context.Background(), f.authority, f.r, f.i, f.now, 4*time.Hour, func(b Bundle, crl []byte) error {
		if len(b.Key) != 0 || !bytes.Equal(crl, f.crl) {
			t.Fatal("pruning signer leaked private material or altered trust")
		}
		certificate = slices.Clone(b.Certificate)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return certificate
}

func pruningKey(t *testing.T, f namePruningFixture) ed25519.PrivateKey {
	t.Helper()
	b, _, err := ReadIdentity(f.caFile, f.file, Node, f.i.Node, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	block, _ := pem.Decode(b.Key)
	defer clear(block.Bytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key.(ed25519.PrivateKey)
}

func signPruningProof(t *testing.T, f namePruningFixture, r *NodeNamePruningRequest) {
	t.Helper()
	key := pruningKey(t, f)
	defer clear(key)
	payload, err := namePruningProof(*r)
	if err != nil {
		t.Fatal(err)
	}
	r.Proof = ed25519.Sign(key, payload)
}

func TestNodeNamePruningSubsetLocalKeyAndReplay(t *testing.T) {
	for _, names := range [][]string{{"new.test"}, {"127.0.0.1", "new.test"}, {"agent.test", "new.test"}} {
		t.Run(strings.Join(names, "+"), func(t *testing.T) {
			f := newNamePruningFixture(t, names)
			ctx := context.Background()
			before, _ := os.ReadFile(f.file)
			retry, err := PrepareNodeNamePruning(ctx, f.caFile, f.file, f.trust, f.i, f.now)
			if err != nil || retry.SHA256() != f.r.SHA256() {
				t.Fatal("preparation did not reuse the saved key/CSR", err)
			}
			raw, _ := json.Marshal(f.r)
			if _, err := ParseNodeNamePruningRequest(raw); err != nil {
				t.Fatal(err)
			}
			if _, err := ParseNodeNameChangeRequest(raw); err == nil {
				t.Fatal("pruning accepted as name addition")
			}
			if _, err := ParseNodeRenewalRequest(raw); err == nil {
				t.Fatal("pruning accepted as ordinary renewal")
			}
			certificate := signNamePruningFixture(t, f)
			leaf, _ := parseCertificate(certificate)
			if len(leaf.DNSNames)+len(leaf.IPAddresses) != len(names) {
				t.Fatal("certificate not the exact authorized subset")
			}
			for _, name := range []string{"agent.test", "127.0.0.1", "new.test"} {
				if (leaf.VerifyHostname(name) == nil) != slices.Contains(names, name) {
					t.Fatal("wrong retained name", name)
				}
			}
			first, err := ActivateNodeNamePruning(ctx, f.caFile, f.file, f.trust, f.r, f.i, certificate, f.now)
			if err != nil || !first.Changed {
				t.Fatal(err)
			}
			second, err := ActivateNodeNamePruning(ctx, f.caFile, f.file, f.trust, f.r, f.i, certificate, f.now)
			if err != nil || second.Changed || second.CertificateSHA256 != first.CertificateSHA256 {
				t.Fatal("lost-response replay changed identity", err)
			}
			prior, err := os.ReadFile(f.file + ".history/" + f.i.CertificateSHA256 + ".pem")
			if err != nil || !bytes.Equal(before, prior) {
				t.Fatal("previous identity not preserved", err)
			}
			if _, err := PrepareNodeNamePruning(ctx, f.caFile, f.file, f.trust, f.i, f.now); err == nil {
				t.Fatal("stale parent prepared after activation")
			}
			r, err := PrepareNodeRenewal(ctx, f.caFile, f.file, f.i.Node, first.CertificateSHA256, f.now)
			if err != nil || ValidateNodeRenewalRequest(f.b.CA, f.crl, r, f.now) != nil {
				t.Fatal("normal renewal no longer works", err)
			}
			block, _ := pem.Decode(r.CSR)
			csr, _ := x509.ParseCertificateRequest(block.Bytes)
			if len(csr.DNSNames)+len(csr.IPAddresses) != len(names) {
				t.Fatal("ordinary renewal restored retired names")
			}
			if err := filepath.WalkDir(filepath.Join(f.root, "name-prunings"), func(path string, d os.DirEntry, err error) error {
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
					t.Error("unsafe pruning file mode", path)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeNamePruningRejectsUnboundIntentAndCSR(t *testing.T) {
	f := newNamePruningFixture(t, []string{"new.test"})
	for _, scenario := range []string{"active-removed", "added-name", "empty", "all-names", "duplicate", "unsorted", "wildcard", "ip-alias", "uppercase", "epoch", "configuration", "challenge", "expired", "future", "too-long", "proof", "kind", "other-intent", "extra-san", "missing-san", "other-node", "same-key", "extension", "renewal-domain", "addition-domain"} {
		t.Run(scenario, func(t *testing.T) {
			raw, _ := json.Marshal(f.r)
			r, _ := ParseNodeNamePruningRequest(raw)
			expected := f.i
			expected.Names = slices.Clone(f.i.Names)
			switch scenario {
			case "active-removed":
				expected.Names = []string{"agent.test"}
			case "added-name":
				expected.Names = []string{"new.test", "unapproved.test"}
			case "empty":
				expected.Names = nil
			case "all-names":
				expected.Names = []string{"127.0.0.1", "agent.test", "new.test"}
			case "duplicate":
				expected.Names = []string{"new.test", "new.test"}
			case "unsorted":
				expected.Names = []string{"new.test", "agent.test"}
			case "wildcard":
				expected.Names = []string{"*.test", "new.test"}
			case "ip-alias":
				expected.Names = []string{"::ffff:127.0.0.1", "new.test"}
			case "uppercase":
				expected.Names = []string{"NEW.test", "new.test"}
			case "epoch":
				expected.RuntimeEpoch = 0
			case "configuration":
				expected.ConfigurationSHA256 = "invalid"
			case "challenge":
				expected.Challenge = "invalid"
			case "expired":
				expected.ExpiresAt = f.now
			case "future":
				expected.IssuedAt = f.now.Add(time.Second)
			case "too-long":
				expected.ExpiresAt = f.now.Add(11 * time.Minute)
			case "proof":
				r.Proof[0] ^= 1
			case "kind":
				r.Kind = nameChangeKind
			case "other-intent":
				r.Intent.RuntimeEpoch++
			case "renewal-domain", "addition-domain":
				key := pruningKey(t, f)
				defer clear(key)
				payload := []byte("webscan-v3/node-renewal-proof/v1\x00")
				if scenario == "addition-domain" {
					payload = []byte("webscan-v3/node-name-change-proof/v1\x00")
				}
				copy := r
				copy.Proof = nil
				raw, _ := json.Marshal(copy)
				r.Proof = ed25519.Sign(key, append(payload, raw...))
			default:
				block, _ := pem.Decode(r.CSR)
				csr, _ := x509.ParseCertificateRequest(block.Bytes)
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				defer clear(key)
				template := &x509.CertificateRequest{Subject: csr.Subject, URIs: csr.URIs, DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses}
				switch scenario {
				case "extra-san":
					template.DNSNames = append(template.DNSNames, "agent.test")
				case "missing-san":
					template.DNSNames = nil
				case "other-node":
					template.Subject = pkix.Name{CommonName: "node:other"}
					template.URIs = nil
				case "same-key":
					clear(key)
					key = pruningKey(t, f)
					defer clear(key)
				case "extension":
					template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x00}}}
				}
				der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
				if err != nil {
					t.Fatal(err)
				}
				r.CSR = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
				signPruningProof(t, f, &r)
			}
			if scenario != "proof" && scenario != "kind" && scenario != "other-intent" && scenario != "renewal-domain" && scenario != "addition-domain" && !strings.HasSuffix(scenario, "san") && scenario != "other-node" && scenario != "same-key" && scenario != "extension" {
				r.Intent = expected
				signPruningProof(t, f, &r)
			}
			if ValidateNodeNamePruningRequest(f.b.CA, f.crl, r, expected, f.now) == nil {
				t.Fatal("unapproved pruning accepted")
			}
			if err := SignNodeNamePruningRegistered(context.Background(), f.authority, r, expected, f.now, 4*time.Hour, func(Bundle, []byte) error { t.Fatal("invalid request reached ledger"); return nil }); err == nil {
				t.Fatal("invalid pruning signed")
			}
		})
	}
}

func TestNodeNamePruningCanonicalRequestAndIntentCopy(t *testing.T) {
	f := newNamePruningFixture(t, []string{"new.test"})
	raw, _ := json.Marshal(f.r)
	for _, altered := range [][]byte{append([]byte(" "), raw...), append(slices.Clone(raw), []byte("{}")...), append(slices.Clone(raw[:len(raw)-1]), []byte(`,"format":1}`)...), append(slices.Clone(raw[:len(raw)-1]), []byte(`,"unknown":true}`)...), bytes.Repeat([]byte("x"), MaxRenewalBytes+1)} {
		if _, err := ParseNodeNamePruningRequest(altered); err == nil {
			t.Fatal("noncanonical pruning accepted")
		}
	}
	names := []string{"new.test"}
	i, err := NewNodeNamePruningIntent(f.i.Node, f.i.AuthoritySHA256, f.i.CertificateSHA256, f.i.ConfigurationSHA256, f.i.RuntimeEpoch, f.i.ActiveName, names, f.now)
	if err != nil {
		t.Fatal(err)
	}
	names[0] = "changed.test"
	if i.Names[0] != "new.test" {
		t.Fatal("authorization retained caller-owned name slice")
	}
	for _, names := range [][]string{nil, {"agent.test"}, {"new.test", "new.test"}, {"new.test", "agent.test"}} {
		if _, err := NewNodeNamePruningIntent(f.i.Node, f.i.AuthoritySHA256, f.i.CertificateSHA256, f.i.ConfigurationSHA256, f.i.RuntimeEpoch, f.i.ActiveName, names, f.now); err == nil {
			t.Fatal("invalid intent constructed", names)
		}
	}
}

func TestNodeNamePruningIPv6SubsetAndScopeLimits(t *testing.T) {
	f := newNamePruningFixture(t, []string{"127.0.0.1", "2001:db8::31"}, "2001:db8::31")
	certificate := signNamePruningFixture(t, f)
	if _, err := ActivateNodeNamePruning(context.Background(), f.caFile, f.file, f.trust, f.r, f.i, certificate, f.now); err != nil {
		t.Fatal(err)
	}
	leaf, err := parseCertificate(certificate)
	if err != nil || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 2 || leaf.VerifyHostname("2001:db8::31") != nil || leaf.VerifyHostname("127.0.0.1") != nil || leaf.VerifyHostname("agent.test") == nil {
		t.Fatal("incorrect IP-only subset", err)
	}
	names := []string{"a.test", "b.test", "c.test", "d.test", "e.test", "f.test", "g.test", "h.test", "i.test", "j.test", "k.test", "l.test", "m.test", "n.test", "o.test", "p.test"}
	b, err := f.a.Issue(Node, "node-a", names, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	if err := ValidateNodeNamePruningScope(b.Certificate, "a.test", names[:15]); err != nil {
		t.Fatal("maximum allowed subset rejected", err)
	}
	for _, keep := range [][]string{nil, names, {"a.test", "unknown.test"}, {"b.test", "a.test"}, {"a.test", "a.test"}} {
		if ValidateNodeNamePruningScope(b.Certificate, "a.test", keep) == nil {
			t.Fatal("invalid/no-op subset accepted", keep)
		}
	}
}

func TestNodeNamePruningActivationRejectsDamagedStateAndRevocation(t *testing.T) {
	for _, scenario := range []string{"parent-revoked", "successor-revoked", "missing-floor", "expired-floor", "missing-key", "corrupt-key", "key-permissions", "symlink-key", "symlink-request", "missing-request", "request-mismatch", "expired-intent", "active-changed", "wrong-leaf"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNamePruningFixture(t, []string{"new.test"})
			certificate := signNamePruningFixture(t, f)
			pending := namePruningPending(f.file, f.i)
			now := f.now
			r := f.r
			switch scenario {
			case "parent-revoked", "successor-revoked":
				revoked := f.parent
				if scenario == "successor-revoked" {
					revoked = certificate
				}
				next, err := f.a.Revoke(f.crl, [][]byte{revoked}, f.now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.trust, "ca.crl"), next, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-floor":
				os.Remove(filepath.Join(f.trust, "ca.crl"))
			case "expired-floor":
				expired, err := f.a.Revoke(nil, nil, f.now.Add(-2*time.Hour), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				os.WriteFile(filepath.Join(f.trust, "ca.crl"), expired, 0600)
			case "missing-key":
				os.Remove(filepath.Join(pending, "key.pem"))
			case "corrupt-key":
				os.WriteFile(filepath.Join(pending, "key.pem"), []byte("broken"), 0600)
			case "key-permissions":
				os.Chmod(filepath.Join(pending, "key.pem"), 0644)
			case "symlink-key", "symlink-request":
				name := "key.pem"
				if scenario == "symlink-request" {
					name = "request.json"
				}
				path := filepath.Join(pending, name)
				os.Rename(path, path+".original")
				os.Symlink(path+".original", path)
			case "missing-request":
				os.Remove(filepath.Join(pending, "request.json"))
			case "request-mismatch":
				r.Proof = slices.Clone(r.Proof)
				r.Proof[0] ^= 1
			case "expired-intent":
				now = f.i.ExpiresAt
			case "active-changed":
				b, err := f.a.Issue(Node, "node-a", []string{"new.test"}, f.now, 5*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(b.Key)
				if _, err := PublishIdentity(context.Background(), f.caFile, f.file, Node, "node-a", f.i.CertificateSHA256, b, f.now); err != nil {
					t.Fatal(err)
				}
			case "wrong-leaf":
				certificate = f.parent
			}
			before, _ := os.ReadFile(f.file)
			if _, err := ActivateNodeNamePruning(context.Background(), f.caFile, f.file, f.trust, r, f.i, certificate, now); err == nil {
				t.Fatal("unsafe pruning activated")
			}
			after, _ := os.ReadFile(f.file)
			if !bytes.Equal(before, after) {
				t.Fatal("failed pruning changed active identity")
			}
			if slices.Contains([]string{"missing-key", "corrupt-key", "key-permissions", "symlink-key", "symlink-request", "missing-request"}, scenario) {
				if _, err := PrepareNodeNamePruning(context.Background(), f.caFile, f.file, f.trust, f.i, f.now); err == nil {
					t.Fatal("partial state silently repaired")
				}
			}
		})
	}
}

func TestNodeNamePruningSigningFailureLeavesIdentity(t *testing.T) {
	for _, scenario := range []string{"commit", "revoke", "expiry", "lifetime", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNamePruningFixture(t, []string{"new.test"})
			before, _ := os.ReadFile(f.file)
			now, lifetime := f.now, 4*time.Hour
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "revoke":
				parent := filepath.Join(f.root, "pruning-parent.crt")
				os.WriteFile(parent, f.parent, 0600)
				if err := Command(ctx, Options{Action: "revoke", Authority: f.authority, Certificate: parent}, &bytes.Buffer{}); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				now = f.i.ExpiresAt
			case "lifetime":
				lifetime = 3 * time.Hour
			case "canceled":
				cancel()
			}
			sentinel := errors.New("test transaction rolled back")
			calls := 0
			err := SignNodeNamePruningRegistered(ctx, f.authority, f.r, f.i, now, lifetime, func(Bundle, []byte) error { calls++; return sentinel })
			if err == nil || scenario == "commit" && (!errors.Is(err, sentinel) || calls != 1) || scenario != "commit" && calls != 0 {
				t.Fatal("invalid signing outcome", err, calls)
			}
			after, _ := os.ReadFile(f.file)
			if !bytes.Equal(before, after) {
				t.Fatal("signing changed node identity")
			}
		})
	}
}

func TestNodeNamePruningConcurrentPreparationAndActivation(t *testing.T) {
	f := newNamePruningFixture(t, []string{"new.test"})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			r, err := PrepareNodeNamePruning(context.Background(), f.caFile, f.file, f.trust, f.i, f.now)
			if err != nil || r.SHA256() != f.r.SHA256() {
				t.Error("concurrent preparation", err)
			}
		})
	}
	wg.Wait()
	certificate := signNamePruningFixture(t, f)
	for range 8 {
		wg.Go(func() {
			if _, err := ActivateNodeNamePruning(context.Background(), f.caFile, f.file, f.trust, f.r, f.i, certificate, f.now); err != nil {
				t.Error("concurrent activation", err)
			}
		})
	}
	wg.Wait()
}

func TestNodeNamePruningRejectsSignedScopeExpansion(t *testing.T) {
	for _, scenario := range []string{"retired-dns", "unapproved-dns", "missing-required-ip", "email", "extra-usage", "extra-key-usage", "wrong-node", "wrong-role", "ca", "not-extending"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNamePruningFixture(t, []string{"127.0.0.1", "new.test"})
			certificate := signNamePruningFixture(t, f)
			leaf, err := parseCertificate(certificate)
			if err != nil {
				t.Fatal(err)
			}
			leaf.ExtraExtensions, leaf.RawSubject = nil, nil
			switch scenario {
			case "retired-dns":
				leaf.DNSNames = append(leaf.DNSNames, "agent.test")
			case "unapproved-dns":
				leaf.DNSNames = append(leaf.DNSNames, "unapproved.test")
			case "missing-required-ip":
				leaf.IPAddresses = nil
			case "email":
				leaf.EmailAddresses = []string{"unapproved@example.test"}
			case "extra-usage":
				leaf.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
			case "extra-key-usage":
				leaf.KeyUsage |= x509.KeyUsageCertSign
			case "wrong-node":
				leaf.Subject = pkix.Name{CommonName: "node:other"}
			case "wrong-role":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			case "ca":
				leaf.IsCA = true
			case "not-extending":
				leaf.NotAfter = f.now.Add(3 * time.Hour)
			}
			der, err := x509.CreateCertificate(rand.Reader, leaf, f.a.certificate, leaf.PublicKey, f.a.key)
			if err != nil {
				t.Fatal(err)
			}
			candidate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			if ValidateNodeNamePruningCertificate(f.b.CA, f.crl, f.r, f.i, candidate, f.now) == nil {
				t.Fatal("invalid CA receipt accepted")
			}
			before, _ := os.ReadFile(f.file)
			if _, err := ActivateNodeNamePruning(context.Background(), f.caFile, f.file, f.trust, f.r, f.i, candidate, f.now); err == nil {
				t.Fatal("invalid CA receipt activated")
			}
			after, _ := os.ReadFile(f.file)
			if !bytes.Equal(before, after) {
				t.Fatal("invalid receipt changed identity")
			}
		})
	}
}

func TestNodeNamePruningLockCancellationAndCommittedCancellation(t *testing.T) {
	f := newNamePruningFixture(t, []string{"new.test"})
	certificate := signNamePruningFixture(t, f)
	before, _ := os.ReadFile(f.file)
	for _, dir := range []string{f.trust, filepath.Dir(f.file), f.authority} {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			lock, err := authorityLock(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if dir == f.authority {
				err = SignNodeNamePruningRegistered(ctx, f.authority, f.r, f.i, f.now, 4*time.Hour, func(Bundle, []byte) error { t.Error("canceled signing reached commit"); return nil })
			} else {
				_, err = ActivateNodeNamePruning(ctx, f.caFile, f.file, f.trust, f.r, f.i, certificate, f.now)
			}
			if err == nil {
				t.Fatal("lock cancellation ignored")
			}
			after, _ := os.ReadFile(f.file)
			if !bytes.Equal(before, after) {
				t.Fatal("canceled operation published identity")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := SignNodeNamePruningRegistered(ctx, f.authority, f.r, f.i, f.now, 4*time.Hour, func(Bundle, []byte) error { calls++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("canceled callback reported signing success", err, calls)
	}
}

func TestNodeNamePruningActualMTLSDropsOnlyRetiredNames(t *testing.T) {
	f := newNamePruningFixture(t, []string{"127.0.0.1", "new.test"})
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
				t.Fatal("retired name still verified")
			}
			return ""
		}
		if err != nil || remoteErr != nil {
			t.Fatal("normal mTLS failed", name, err, remoteErr)
		}
		return publicSHA(conn.ConnectionState().PeerCertificates[0].Raw)
	}
	parent, _ := parseCertificate(f.parent)
	for _, name := range []string{"agent.test", "new.test", "127.0.0.1"} {
		if call(name, true) != publicSHA(parent.Raw) {
			t.Fatal("unexpected overlap peer")
		}
	}
	certificate := signNamePruningFixture(t, f)
	result, err := ActivateNodeNamePruning(context.Background(), f.caFile, f.file, f.trust, f.r, f.i, certificate, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.Certificate(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	call("agent.test", false)
	for _, name := range []string{"new.test", "127.0.0.1"} {
		if call(name, true) != result.CertificateSHA256 {
			t.Fatal("stale peer after pruning")
		}
	}
}
