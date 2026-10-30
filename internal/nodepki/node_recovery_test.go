package nodepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
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

type recoveryFixture struct {
	authority                  *Authority
	directory, ca, file        string
	caBytes, crl, old, seedCRL []byte
	intent                     NodeRecoveryIntent
	request                    NodeRecoveryRequest
	now                        time.Time
}

func newRecoveryFixture(t *testing.T) recoveryFixture {
	t.Helper()
	a, dir, ca, file, pending, crl, now := nodeRenewalFixture(t)
	at := now.Add(26 * time.Hour)
	caBytes, current, changed, err := RefreshCRL(context.Background(), dir, at, time.Hour, 24*time.Hour)
	if err != nil || !changed {
		t.Fatal("fixture CRL was not refreshed", err)
	}
	intent, err := NewNodeRecoveryIntent("node-a", pending.AuthoritySHA256, pending.CertificateSHA256, at)
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	r, err := PrepareNodeRecovery(context.Background(), ca, file, current, intent, at)
	if err != nil || r.Renewal.SHA256() != pending.SHA256() {
		t.Fatal("historical pending CSR was not reused", err)
	}
	return recoveryFixture{a, dir, ca, file, caBytes, current, old, crl, intent, r, at}
}

func TestNodeRecoveryExpiredParentKeepsLocalKeyAndOnlineRejection(t *testing.T) {
	f := newRecoveryFixture(t)
	ctx := context.Background()
	for _, raw := range [][]byte{f.seedCRL, f.crl} {
		if err := ValidateNodeRenewalRequest(f.caBytes, raw, f.request.Renewal, f.now); err == nil {
			t.Fatal("expired leaf authorized ordinary online renewal")
		}
	}
	if _, err := PrepareNodeRenewal(ctx, f.ca, f.file, "node-a", f.intent.CertificateSHA256, f.now); err == nil {
		t.Fatal("ordinary preparation accepted expired active leaf")
	}
	if _, _, err := ReadIdentity(f.ca, f.file, Node, "node-a", f.now); err == nil {
		t.Fatal("expired identity readable as live credential")
	}
	if _, err := NewLiveIdentity(f.ca, f.file, Node, "node-a", f.now); err == nil {
		t.Fatal("expired identity usable by TLS")
	}
	called := false
	if err := SignNodeRenewalRegistered(ctx, f.directory, f.request.Renewal, f.now, 3*time.Hour, func(Bundle, []byte) error { called = true; return nil }); err == nil || called {
		t.Fatal("ordinary signer accepted expired parent")
	}
	raw, _ := json.Marshal(f.request)
	if bytes.Contains(raw, []byte("PRIVATE KEY")) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(f.old))) {
		t.Fatal("private material in SSH public response")
	}
	var certificate []byte
	rejected := errors.New("fixture registration failed")
	if err := SignNodeRecoveryRegistered(ctx, f.directory, f.request, f.intent, f.now, 3*time.Hour, func(Bundle, []byte) error { return rejected }); !errors.Is(err, rejected) {
		t.Fatal("registration failure was hidden", err)
	}
	still, _ := os.ReadFile(f.file)
	if !bytes.Equal(still, f.old) {
		t.Fatal("failed issuance replaced active identity")
	}
	err := SignNodeRecoveryRegistered(ctx, f.directory, f.request, f.intent, f.now, 3*time.Hour, func(b Bundle, crl []byte) error {
		if len(b.Key) != 0 || !bytes.Equal(crl, f.crl) || !bytes.Equal(b.CA, f.caBytes) {
			t.Fatal("issuer changed trust or returned a private key")
		}
		certificate = append([]byte{}, b.Certificate...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	trustDirectory := filepath.Join(filepath.Dir(f.directory), "trust")
	if err := initializeTrustState(trustDirectory, f.caBytes, f.crl, f.now); err != nil {
		t.Fatal(err)
	}
	r := f.request.Renewal
	activated, err := ActivateNodeRecovery(ctx, f.ca, f.file, trustDirectory, f.request, f.intent, certificate, f.now)
	if err != nil || !activated.Changed {
		t.Fatal("expired parent could not be replaced", err)
	}
	retry, err := ActivateNodeRecovery(ctx, f.ca, f.file, trustDirectory, f.request, f.intent, certificate, f.now)
	if err != nil || retry.Changed || retry.CertificateSHA256 != activated.CertificateSHA256 {
		t.Fatal("lost activation response not idempotent", err)
	}
	prior, err := os.ReadFile(f.file + ".history/" + r.CertificateSHA256 + ".pem")
	if err != nil || !bytes.Equal(prior, f.old) {
		t.Fatal("original private identity lost", err)
	}
	live, err := NewLiveIdentity(f.ca, f.file, Node, "node-a", f.now)
	if err != nil {
		t.Fatal("recovered credential cannot start TLS", err)
	}
	if _, err := live.Certificate(f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareNodeRenewal(ctx, f.ca, f.file, "node-a", activated.CertificateSHA256, f.now); err != nil {
		t.Fatal("normal local-key renewal did not resume", err)
	}
	if _, err := PrepareNodeRecovery(ctx, f.ca, f.file, f.crl, f.intent, f.now); err == nil {
		t.Fatal("old recovery intent remained usable after activation")
	}
}

func TestNodeRecoveryActivationRechecksDurablePolicy(t *testing.T) {
	for _, kind := range []string{"parent-revoked", "replacement-revoked", "expired-crl", "missing-crl", "missing-directory", "wrong-ca", "expired-intent", "wrong-intent", "wrong-key", "same-directory", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			f := newRecoveryFixture(t)
			ctx := context.Background()
			var certificate []byte
			if err := SignNodeRecoveryRegistered(ctx, f.directory, f.request, f.intent, f.now, 3*time.Hour, func(b Bundle, _ []byte) error {
				certificate = append([]byte{}, b.Certificate...)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(filepath.Dir(f.directory), "trust")
			if err := initializeTrustState(dir, f.caBytes, f.crl, f.now); err != nil {
				t.Fatal(err)
			}
			expected, at := f.intent, f.now
			switch kind {
			case "parent-revoked", "replacement-revoked":
				leaf := f.request.Renewal.Certificate
				if kind == "replacement-revoked" {
					leaf = certificate
				}
				crl, err := f.authority.Revoke(f.crl, [][]byte{leaf}, f.now, 24*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "ca.crl"), crl, 0600); err != nil {
					t.Fatal(err)
				}
			case "expired-crl":
				os.WriteFile(filepath.Join(dir, "ca.crl"), f.seedCRL, 0600)
			case "missing-crl":
				os.Remove(filepath.Join(dir, "ca.crl"))
			case "missing-directory":
				os.RemoveAll(dir)
			case "wrong-ca":
				a, _ := NewAuthority(f.now, 365*24*time.Hour)
				b, _ := a.Export()
				defer clear(b.Key)
				os.WriteFile(filepath.Join(dir, "ca.crt"), b.CA, 0600)
			case "expired-intent":
				at = expected.ExpiresAt
			case "wrong-intent":
				expected.Node = "node-b"
			case "wrong-key":
				b, err := f.authority.Issue(Node, "node-a", []string{"node.test"}, f.now, 3*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(b.Key)
				certificate = b.Certificate
			case "same-directory":
				dir = filepath.Dir(f.file)
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if _, err := ActivateNodeRecovery(ctx, f.ca, f.file, dir, f.request, expected, certificate, at); err == nil {
				t.Fatal("stale or unsafe activation accepted")
			}
			after, err := os.ReadFile(f.file)
			if err != nil || !bytes.Equal(after, f.old) {
				t.Fatal("failed activation replaced prior identity", err)
			}
		})
	}
}

func signRecoveryProof(t *testing.T, f recoveryFixture, r *NodeRecoveryRequest) {
	t.Helper()
	b, _, err := readIdentity(f.ca, f.file, Node, "node-a", f.now, true)
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
	payload, err := recoveryProofPayload(*r)
	if err != nil {
		t.Fatal(err)
	}
	r.Proof = ed25519.Sign(key, payload)
}

func TestNodeRecoveryIntentBindingAndCanonicalBoundary(t *testing.T) {
	f := newRecoveryFixture(t)
	raw, _ := json.Marshal(f.request)
	parsed, err := ParseNodeRecoveryRequest(raw)
	if err != nil || parsed.SHA256() != f.request.SHA256() {
		t.Fatal("canonical request did not round trip", err)
	}
	if _, err := ParseNodeRenewalRequest(raw); err == nil {
		t.Fatal("recovery wrapper accepted as online renewal")
	}
	online, _ := json.Marshal(f.request.Renewal)
	if _, err := ParseNodeRecoveryRequest(online); err == nil {
		t.Fatal("online CSR accepted as SSH intent proof")
	}
	for name, content := range map[string][]byte{
		"empty": nil, "large": bytes.Repeat([]byte{'x'}, MaxRenewalBytes+1),
		"whitespace": append([]byte{' '}, raw...), "trailing": append(append([]byte{}, raw...), '\n'),
		"unknown":   append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"extra":true}`)...),
		"duplicate": append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"format":1}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNodeRecoveryRequest(content); err == nil {
				t.Fatal("ambiguous or oversized recovery request accepted")
			}
		})
	}
	for _, kind := range []string{"expired", "future", "long", "zero-challenge", "node", "root", "parent", "challenge", "intent-proof", "online-proof", "kind", "format", "no-proof", "not-expired"} {
		t.Run(kind, func(t *testing.T) {
			r, expected, at := f.request, f.intent, f.now
			switch kind {
			case "expired":
				at = expected.ExpiresAt
			case "future":
				expected.IssuedAt = at.Add(time.Second)
				r.Intent = expected
			case "long":
				expected.ExpiresAt = expected.IssuedAt.Add(10*time.Minute + time.Nanosecond)
				r.Intent = expected
			case "zero-challenge":
				expected.Challenge = ""
				r.Intent = expected
			case "node":
				expected.Node = "node-b"
			case "root":
				expected.AuthoritySHA256 = expected.CertificateSHA256
			case "parent":
				expected.CertificateSHA256 = expected.AuthoritySHA256
			case "challenge":
				i, _ := NewNodeRecoveryIntent(expected.Node, expected.AuthoritySHA256, expected.CertificateSHA256, at)
				expected.Challenge = i.Challenge
			case "intent-proof":
				r.Intent.ExpiresAt = r.Intent.ExpiresAt.Add(-time.Second)
				expected = r.Intent
			case "online-proof":
				r.Proof = r.Renewal.Proof
			case "kind":
				r.Kind = "online"
			case "format":
				r.Format++
			case "no-proof":
				r.Proof = nil
			case "not-expired":
				at = at.Add(-26 * time.Hour)
				r.Intent.IssuedAt, r.Intent.ExpiresAt = at, at.Add(10*time.Minute)
				expected = r.Intent
				signRecoveryProof(t, f, &r)
			}
			if err := ValidateNodeRecoveryRequest(f.caBytes, f.crl, r, expected, at); err == nil {
				t.Fatal("invalid recovery binding accepted")
			}
			called := false
			if err := SignNodeRecoveryRegistered(context.Background(), f.directory, r, expected, at, 3*time.Hour, func(Bundle, []byte) error { called = true; return nil }); err == nil || called {
				t.Fatal("invalid recovery reached issuance callback", err)
			}
		})
	}
}

func TestNodeRecoveryCurrentRevocationCannotBeBypassed(t *testing.T) {
	f := newRecoveryFixture(t)
	ctx := context.Background()
	revoked, err := f.authority.Revoke(f.crl, [][]byte{f.request.Renewal.Certificate}, f.now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(filepath.Dir(f.directory), "revoked")
	if err := SeedAuthority(ctx, root, mustAuthorityBundle(t, f.authority), revoked, f.now); err != nil {
		t.Fatal(err)
	}
	for name, crl := range map[string][]byte{"revoked-parent": revoked, "expired-crl": f.seedCRL, "corrupt-crl": []byte("broken")} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateNodeRecoveryRequest(f.caBytes, crl, f.request, f.intent, f.now); err == nil {
				t.Fatal("invalid current revocation policy accepted")
			}
			if _, err := PrepareNodeRecovery(ctx, f.ca, f.file, crl, f.intent, f.now); err == nil {
				t.Fatal("invalid current policy accepted during local preparation")
			}
		})
	}
	called := false
	// The request was prepared before revocation. The issuer must use its own
	// latest CRL rather than a relay's earlier successful policy check.
	if err := SignNodeRecoveryRegistered(ctx, root, f.request, f.intent, f.now, 3*time.Hour, func(Bundle, []byte) error { called = true; return nil }); err == nil || called {
		t.Fatal("newly revoked parent was recovered", err)
	}
	if err := ValidateNodeRecoveryRequest(f.caBytes, f.crl, f.request, f.intent, f.now.Add(366*24*time.Hour)); err == nil {
		t.Fatal("expired authority accepted")
	}
}

func TestNodeRecoveryParentPrecheckIsHistoricalOnly(t *testing.T) {
	f := newRecoveryFixture(t)
	if err := ValidateNodeRecoveryParent(f.caBytes, f.crl, f.request.Renewal.Certificate, "node-a", f.now); err != nil {
		t.Fatal("authentic expired parent not inspectable", err)
	}
	current, err := f.authority.Issue(Node, "node-a", []string{"node.test"}, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(current.Key)
	collector, err := f.authority.Issue(Collector, "node-a", nil, f.now.Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(collector.Key)
	revoked, err := f.authority.Revoke(f.crl, [][]byte{f.request.Renewal.Certificate}, f.now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := NewAuthority(f.now, 365*24*time.Hour)
	b, _ := other.Export()
	defer clear(b.Key)
	for _, kind := range []string{"current", "collector", "other-node", "other-root", "revoked", "expired-crl", "damaged"} {
		t.Run(kind, func(t *testing.T) {
			ca, crl, cert, id := f.caBytes, f.crl, f.request.Renewal.Certificate, "node-a"
			switch kind {
			case "current":
				cert = current.Certificate
			case "collector":
				cert = collector.Certificate
			case "other-node":
				id = "node-b"
			case "other-root":
				ca = b.CA
			case "revoked":
				crl = revoked
			case "expired-crl":
				crl = f.seedCRL
			case "damaged":
				cert = []byte("broken")
			}
			if err := ValidateNodeRecoveryParent(ca, crl, cert, id, f.now); err == nil {
				t.Fatal("invalid historical precheck accepted")
			}
		})
	}
}

func TestNodeRecoveryFreshPendingConcurrencyAndPrivateState(t *testing.T) {
	f := newRecoveryFixture(t)
	ctx := context.Background()
	pending, _ := renewalPending(filepath.Dir(f.file), f.intent.CertificateSHA256)
	if err := os.RemoveAll(pending); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	requests := make(chan NodeRecoveryRequest, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := PrepareNodeRecovery(ctx, f.ca, f.file, f.crl, f.intent, f.now)
			if err != nil {
				t.Error(err)
				return
			}
			requests <- r
		}()
	}
	wg.Wait()
	close(requests)
	var first NodeRecoveryRequest
	for r := range requests {
		if first.Format != 0 && first.SHA256() != r.SHA256() {
			t.Fatal("concurrent recovery regenerated private pending key")
		}
		first = r
	}
	if first.Format != 1 {
		t.Fatal("no recovery completed")
	}
	intent, err := NewNodeRecoveryIntent("node-a", f.intent.AuthoritySHA256, f.intent.CertificateSHA256, f.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	r, err := PrepareNodeRecovery(ctx, f.ca, f.file, f.crl, intent, f.now.Add(time.Minute))
	if err != nil || r.Renewal.SHA256() != first.Renewal.SHA256() || r.SHA256() == first.SHA256() || bytes.Equal(r.Proof, first.Proof) {
		t.Fatal("new challenge did not bind same durable pending key", err)
	}
	for _, path := range []string{pending, filepath.Join(pending, "key.pem"), filepath.Join(pending, "request.json")} {
		st, err := os.Lstat(path)
		if err != nil || st.IsDir() && st.Mode().Perm() != 0700 || !st.IsDir() && st.Mode().Perm() != 0600 {
			t.Fatal("unsafe recovery state", err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := PrepareNodeRecovery(cancelled, f.ca, f.file, f.crl, intent, f.now.Add(time.Minute)); err == nil {
		t.Fatal("cancelled preparation succeeded")
	}
	before, _ := os.ReadFile(f.file)
	if !bytes.Equal(before, f.old) {
		t.Fatal("preparation changed active private identity")
	}
}

func TestNodeRecoveryTrustAdvancePreservesFloorAndLivePolicy(t *testing.T) {
	f := newRecoveryFixture(t)
	ctx := context.Background()
	dir := filepath.Join(filepath.Dir(f.directory), "receiver-floor")
	// The installed floor, like the active identity, has expired. Only a
	// complete newer signed CRL is allowed to advance this existing state.
	if err := initializeTrustState(dir, f.caBytes, f.seedCRL, f.intent.IssuedAt.Add(-26*time.Hour)); err != nil {
		t.Fatal(err)
	}
	receiver, err := NewReceiverTrust(f.ca, "unused-after-initialization", dir, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := receiver.Snapshot(f.now, ""); err == nil {
		t.Fatal("expired floor became live trust")
	}
	receipt, err := PublishNodeRecoveryTrust(ctx, f.ca, dir, f.crl, f.request, f.intent, f.now)
	if err != nil || receipt.SHA256 != publicSHA(f.crl) {
		t.Fatal("SSH recovery could not advance expired floor", err)
	}
	lost, err := PublishNodeRecoveryTrust(ctx, f.ca, dir, f.crl, f.request, f.intent, f.now)
	if err != nil || lost != receipt {
		t.Fatal("lost floor receipt not idempotent", err)
	}
	if raw, _, err := receiver.Snapshot(f.now.Add(time.Second), ""); err != nil || !bytes.Equal(raw, f.crl) {
		t.Fatal("existing receiver did not observe durable recovery floor", err)
	}
	old, _ := parseCertificate(f.request.Renewal.Certificate)
	if err := receiver.Verify(old, Node, "node-a", f.now.Add(time.Second)); err == nil {
		t.Fatal("trust publication authorized expired peer")
	}
	// Accept another certificate's revocation, then present a later signed
	// list whose issuer omitted that entry. A larger revision is insufficient.
	other, err := f.authority.Issue(Collector, "worker-a", nil, f.now, 3*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(other.Key)
	revoked, err := f.authority.Revoke(f.crl, [][]byte{other.Certificate}, f.now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishNodeRecoveryTrust(ctx, f.ca, dir, revoked, f.request, f.intent, f.now); err != nil {
		t.Fatal("unrelated revocation could not be preserved", err)
	}
	without, _ := f.authority.Revoke(f.crl, nil, f.now, 24*time.Hour)
	without, _ = f.authority.Revoke(without, nil, f.now, 24*time.Hour)
	for name, raw := range map[string][]byte{"rollback": f.crl, "unrevocation": without, "expired": f.seedCRL, "damaged": []byte("broken")} {
		t.Run(name, func(t *testing.T) {
			before, _ := os.ReadFile(filepath.Join(dir, "ca.crl"))
			if _, err := PublishNodeRecoveryTrust(ctx, f.ca, dir, raw, f.request, f.intent, f.now); err == nil {
				t.Fatal("invalid recovery trust transition accepted")
			}
			after, _ := os.ReadFile(filepath.Join(dir, "ca.crl"))
			if !bytes.Equal(before, after) {
				t.Fatal("failed trust transition changed durable floor")
			}
		})
	}
	if _, err := NewReceiverTrust(f.ca, "unused", dir, f.now); err != nil {
		t.Fatal("receiver could not restart after recovery", err)
	}
}

func TestNodeRecoveryTrustRefusesMissingCorruptOrUnsafeState(t *testing.T) {
	for _, kind := range []string{"missing", "missing-ca", "wrong-ca", "missing-crl", "damaged-crl", "linked-crl", "linked-ca", "hardlink-crl", "public-dir", "public-crl", "expired-intent", "wrong-intent", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			f := newRecoveryFixture(t)
			ctx := context.Background()
			dir := filepath.Join(filepath.Dir(f.directory), "receiver-floor")
			if err := initializeTrustState(dir, f.caBytes, f.seedCRL, f.now.Add(-26*time.Hour)); err != nil {
				t.Fatal(err)
			}
			crlPath, caPath := filepath.Join(dir, "ca.crl"), filepath.Join(dir, "ca.crt")
			expected, at := f.intent, f.now
			switch kind {
			case "missing":
				os.RemoveAll(dir)
			case "missing-ca":
				os.Remove(caPath)
			case "wrong-ca":
				a, _ := NewAuthority(f.now, 365*24*time.Hour)
				b, _ := a.Export()
				defer clear(b.Key)
				os.WriteFile(caPath, b.CA, 0600)
			case "missing-crl":
				os.Remove(crlPath)
			case "damaged-crl":
				os.WriteFile(crlPath, []byte("broken"), 0600)
			case "linked-crl", "linked-ca":
				path := crlPath
				if kind == "linked-ca" {
					path = caPath
				}
				os.Rename(path, path+".original")
				os.Symlink(path+".original", path)
			case "hardlink-crl":
				os.Link(crlPath, crlPath+".other")
			case "public-dir":
				os.Chmod(dir, 0755)
			case "public-crl":
				os.Chmod(crlPath, 0644)
			case "expired-intent":
				at = expected.ExpiresAt
			case "wrong-intent":
				expected.Node = "node-b"
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			before, beforeErr := os.ReadFile(crlPath)
			if _, err := PublishNodeRecoveryTrust(ctx, f.ca, dir, f.crl, f.request, expected, at); err == nil {
				t.Fatal("unsafe recovery state accepted")
			}
			after, afterErr := os.ReadFile(crlPath)
			if !bytes.Equal(before, after) || (beforeErr == nil) != (afterErr == nil) {
				t.Fatal("failed recovery initialized or altered trust")
			}
		})
	}
}
