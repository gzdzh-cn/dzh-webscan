package nodepki

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNodeNameChangeContinuationAfterActivationAndExpiry(t *testing.T) {
	f := newNameChangeFixture(t, "next.test")
	cert := signNameChangeFixture(t, f)
	ctx := context.Background()
	if _, err := ActivateNodeNameChange(ctx, f.caFile, f.file, f.trust, f.request, f.intent, cert, f.now); err != nil {
		t.Fatal(err)
	}
	at := f.intent.ExpiresAt.Add(time.Second)
	fresh, err := NewNodeNameChangeIntent(f.intent.Node, f.intent.AuthoritySHA256, f.intent.CertificateSHA256, f.intent.ServerName, at)
	if err != nil {
		t.Fatal(err)
	}
	files := []string{f.file, filepath.Join(nameChangePending(f.file, f.intent), "request.json"), filepath.Join(nameChangePending(f.file, f.intent), "key.pem"), f.file + ".history/" + f.intent.CertificateSHA256 + ".pem"}
	before := map[string][]byte{}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = raw
		defer clear(raw)
	}
	if _, err := PrepareNodeNameChange(ctx, f.caFile, f.file, f.trust, fresh, at); err == nil {
		t.Fatal("active successor accepted as original parent")
	}
	if err := WithNameChangedNodeIdentity(ctx, f.caFile, f.file, f.trust, f.request, f.intent, cert, at, func(ctx context.Context, _ IdentityRecord) error { t.Fatal("expired task executed"); return nil }); err == nil {
		t.Fatal("expired task accepted")
	}
	r, err := PrepareNodeNameChangeContinuation(ctx, f.caFile, f.file, f.trust, f.crl, fresh, f.request, cert, at)
	if err != nil || r.IssuanceSHA256() != f.request.SHA256() || r.SHA256() == f.request.SHA256() {
		t.Fatal("continuation lost issuance/authorization separation", err)
	}
	raw, _ := json.Marshal(r)
	parsed, err := ParseNodeNameChangeRequest(raw)
	if err != nil || parsed.SHA256() != r.SHA256() || bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("invalid public continuation", err)
	}
	called := false
	if err := SignNodeNameChangeRegistered(ctx, f.authority, r, fresh, at, 3*time.Hour, func(Bundle, []byte) error { called = true; return nil }); err == nil || called {
		t.Fatal("continuation issued another leaf")
	}
	for i := 0; i < 2; i++ {
		calls := 0
		if err := WithNameChangedNodeIdentity(ctx, f.caFile, f.file, f.trust, r, fresh, cert, at, func(ctx context.Context, record IdentityRecord) error {
			calls++
			if record.Changed {
				t.Fatal("verification changed identity")
			}
			return nil
		}); err != nil || calls != 1 {
			t.Fatal("continuation verification", err)
		}
		out, err := ActivateNodeNameChange(ctx, f.caFile, f.file, f.trust, r, fresh, cert, at)
		if err != nil || out.Changed {
			t.Fatal("continuation rewrote identity", err)
		}
	}
	for path, want := range before {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("continuation altered retained state", err)
		}
		clear(got)
	}
	if err := os.Remove(files[3]); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.authority, "ca.key")); err != nil {
		t.Fatal(err)
	}
	retry, err := PrepareNodeNameChangeContinuation(ctx, f.caFile, f.file, f.trust, f.crl, fresh, f.request, cert, at)
	if err != nil || retry.SHA256() != r.SHA256() {
		t.Fatal("retry required historical key/CA or generated another proof", err)
	}
	// The original parent may expire while its already activated successor remains valid.
	later := f.now.Add(2 * time.Hour)
	laterIntent, _ := NewNodeNameChangeIntent(f.intent.Node, f.intent.AuthoritySHA256, f.intent.CertificateSHA256, f.intent.ServerName, later)
	laterRequest, err := PrepareNodeNameChangeContinuation(ctx, f.caFile, f.file, f.trust, f.crl, laterIntent, f.request, cert, later)
	if err != nil || ValidateNodeNameChangeRequest(f.b.CA, f.crl, laterRequest, laterIntent, later) != nil {
		t.Fatal("valid successor could not continue after original parent expiry", err)
	}
}

func TestNodeNameChangeContinuationRejectsUnsafeState(t *testing.T) {
	for _, scenario := range []string{"other-active", "wrong-receipt", "expired-leaf", "expired-crl", "expired-intent", "wrong-node", "wrong-parent", "wrong-ca", "wrong-target", "revoked-parent", "revoked-leaf", "rollback-crl", "missing-floor", "missing-pending", "pending-link", "active-link", "unsafe-trust", "same-directory", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeFixture(t, "next.test")
			cert := signNameChangeFixture(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			{
				if _, err := ActivateNodeNameChange(ctx, f.caFile, f.file, f.trust, f.request, f.intent, cert, f.now); err != nil {
					t.Fatal(err)
				}
			}
			at := f.intent.ExpiresAt.Add(time.Second)
			fresh, _ := NewNodeNameChangeIntent(f.intent.Node, f.intent.AuthoritySHA256, f.intent.CertificateSHA256, f.intent.ServerName, at)
			floor, crl := f.trust, f.crl
			switch scenario {
			case "other-active", "wrong-receipt":
				other, err := f.a.Issue(Node, f.intent.Node, []string{"agent.test", "next.test"}, at, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(other.Key)
				if scenario == "wrong-receipt" {
					cert = other.Certificate
				} else {
					if err := os.WriteFile(f.file, append(append([]byte{}, other.Certificate...), other.Key...), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "expired-leaf":
				at = f.now.Add(4 * time.Hour)
				fresh, _ = NewNodeNameChangeIntent(f.intent.Node, f.intent.AuthoritySHA256, f.intent.CertificateSHA256, f.intent.ServerName, at)
			case "expired-crl":
				var err error
				crl, err = f.a.Revoke(nil, nil, f.now.Add(-2*time.Hour), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
			case "expired-intent":
				fresh = f.intent
			case "wrong-node":
				fresh.Node = "other-node"
			case "wrong-parent":
				fresh.CertificateSHA256 = strings.Repeat("0", 64)
			case "wrong-ca":
				fresh.AuthoritySHA256 = strings.Repeat("0", 64)
			case "wrong-target":
				fresh.ServerName = "unapproved.test"
			case "revoked-parent", "revoked-leaf":
				revoked := f.request.Certificate
				if scenario == "revoked-leaf" {
					revoked = cert
				}
				var err error
				crl, err = f.a.Revoke(f.crl, [][]byte{revoked}, at, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
			case "rollback-crl":
				newer, err := f.a.Revoke(f.crl, nil, at, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(floor, "ca.crl"), newer, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-floor":
				os.Remove(filepath.Join(floor, "ca.crl"))
			case "missing-pending", "pending-link":
				pending := nameChangePending(f.file, f.intent)
				os.RemoveAll(pending)
				if scenario == "pending-link" {
					if err := os.Symlink(filepath.Dir(f.file), pending); err != nil {
						t.Fatal(err)
					}
				}
			case "active-link":
				os.Rename(f.file, f.file+".off")
				os.Symlink(f.file+".off", f.file)
			case "unsafe-trust":
				os.Chmod(floor, 0755)
			case "same-directory":
				floor = filepath.Dir(f.file)
			case "canceled":
				cancel()
			}
			r, err := PrepareNodeNameChangeContinuation(ctx, f.caFile, f.file, floor, crl, fresh, f.request, cert, at)
			if err == nil || r.Format != 0 || len(r.Proof) != 0 {
				t.Fatal("unsafe state produced continuation", err)
			}
		})
	}
}

func TestNodeNameChangeContinuationProofBindsCurrentKeyAndDomain(t *testing.T) {
	f := newNameChangeFixture(t, "next.test")
	cert := signNameChangeFixture(t, f)
	ctx := context.Background()
	if _, err := ActivateNodeNameChange(ctx, f.caFile, f.file, f.trust, f.request, f.intent, cert, f.now); err != nil {
		t.Fatal(err)
	}
	at := f.intent.ExpiresAt.Add(time.Second)
	fresh, _ := NewNodeNameChangeIntent(f.intent.Node, f.intent.AuthoritySHA256, f.intent.CertificateSHA256, f.intent.ServerName, at)
	r, err := PrepareNodeNameChangeContinuation(ctx, f.caFile, f.file, f.trust, f.crl, fresh, f.request, cert, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"old-proof", "challenge", "target", "original-request", "missing-receipt", "nested", "wrong-csr", "normal-kind", "pending-kind"} {
		t.Run(scenario, func(t *testing.T) {
			bad, expected := r, fresh
			switch scenario {
			case "old-proof":
				bad.Proof = f.request.Proof
			case "challenge":
				bad.Intent.Challenge = strings.Repeat("1", 64)
				expected = bad.Intent
			case "target":
				bad.Intent.ServerName = "unapproved.test"
				expected = bad.Intent
			case "original-request":
				original := f.request
				original.Proof = make([]byte, 64)
				bad.OriginalRequest, _ = json.Marshal(original)
			case "missing-receipt":
				bad.ContinuationCertificate = nil
			case "nested":
				bad.OriginalRequest, _ = json.Marshal(r)
			case "wrong-csr":
				bad.CSR = []byte("untrusted")
			case "pending-kind":
				bad.Kind = nameChangeReconciliationKind
			case "normal-kind":
				bad.Kind = nameChangeKind
			}
			if err := ValidateNodeNameChangeRequest(f.b.CA, f.crl, bad, expected, at); err == nil {
				t.Fatal("invalid key/domain/binding accepted")
			}
		})
	}
}

func TestNodeNameChangePendingReconciliationRetainsOriginalKey(t *testing.T) {
	f := newNameChangeFixture(t, "next.test")
	cert := signNameChangeFixture(t, f)
	ctx := context.Background()
	at := f.intent.ExpiresAt.Add(time.Second)
	fresh, _ := NewNodeNameChangeIntent(f.intent.Node, f.intent.AuthoritySHA256, f.intent.CertificateSHA256, f.intent.ServerName, at)
	r, err := PrepareNodeNameChangeContinuation(ctx, f.caFile, f.file, f.trust, f.crl, fresh, f.request, cert, at)
	if err != nil || r.Kind != nameChangeReconciliationKind || r.IssuanceSHA256() != f.request.SHA256() {
		t.Fatal("pending reconciliation failed", err)
	}
	called := false
	if err := SignNodeNameChangeRegistered(ctx, f.authority, r, fresh, at, 3*time.Hour, func(Bundle, []byte) error { called = true; return nil }); err == nil || called {
		t.Fatal("pending reconciliation signed another leaf")
	}
	for i := 0; i < 2; i++ {
		out, err := ActivateNodeNameChange(ctx, f.caFile, f.file, f.trust, r, fresh, cert, at)
		if err != nil || out.Changed != (i == 0) {
			t.Fatal("pending activation/replay", err)
		}
		if err := WithNameChangedNodeIdentity(ctx, f.caFile, f.file, f.trust, r, fresh, cert, at, func(ctx context.Context, _ IdentityRecord) error { return nil }); err != nil {
			t.Fatal("pending receipt cannot verify after activation", err)
		}
	}
}
