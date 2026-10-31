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

func TestNodeNamePruningContinuationAfterActivationAndExpiry(t *testing.T) {
	f := newNamePruningFixture(t, []string{"new.test"})
	cert := signNamePruningFixture(t, f)
	ctx := context.Background()
	if _, err := ActivateNodeNamePruning(ctx, f.caFile, f.file, f.trust, f.r, f.i, cert, f.now); err != nil {
		t.Fatal(err)
	}
	at := f.i.ExpiresAt.Add(time.Second)
	fresh, err := NewNodeNamePruningIntent(f.i.Node, f.i.AuthoritySHA256, f.i.CertificateSHA256, f.i.ConfigurationSHA256, f.i.RuntimeEpoch, f.i.ActiveName, f.i.Names, at)
	if err != nil {
		t.Fatal(err)
	}
	files := []string{f.file, filepath.Join(namePruningPending(f.file, f.i), "request.json"), filepath.Join(namePruningPending(f.file, f.i), "key.pem"), f.file + ".history/" + f.i.CertificateSHA256 + ".pem"}
	before := map[string][]byte{}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = raw
		defer clear(raw)
	}
	if _, err := PrepareNodeNamePruning(ctx, f.caFile, f.file, f.trust, fresh, at); err == nil {
		t.Fatal("active successor accepted as original parent")
	}
	if err := WithPrunedNodeIdentity(ctx, f.caFile, f.file, f.trust, f.r, f.i, cert, at, func(ctx context.Context, _ IdentityRecord) error { t.Fatal("expired task executed"); return nil }); err == nil {
		t.Fatal("expired task accepted")
	}
	r, err := PrepareNodeNamePruningContinuation(ctx, f.caFile, f.file, f.trust, f.crl, fresh, f.r, cert, at)
	if err != nil || r.IssuanceSHA256() != f.r.SHA256() || r.SHA256() == f.r.SHA256() {
		t.Fatal("continuation lost issuance/authorization separation", err)
	}
	raw, _ := json.Marshal(r)
	parsed, err := ParseNodeNamePruningRequest(raw)
	if err != nil || parsed.SHA256() != r.SHA256() || bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("invalid public continuation", err)
	}
	called := false
	if err := SignNodeNamePruningRegistered(ctx, f.authority, r, fresh, at, 3*time.Hour, func(Bundle, []byte) error { called = true; return nil }); err == nil || called {
		t.Fatal("continuation issued another leaf")
	}
	for i := 0; i < 2; i++ {
		calls := 0
		if err := WithPrunedNodeIdentity(ctx, f.caFile, f.file, f.trust, r, fresh, cert, at, func(ctx context.Context, record IdentityRecord) error {
			calls++
			if record.Changed {
				t.Fatal("verification changed identity")
			}
			return nil
		}); err != nil || calls != 1 {
			t.Fatal("continuation verification", err)
		}
		out, err := ActivateNodeNamePruning(ctx, f.caFile, f.file, f.trust, r, fresh, cert, at)
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
	retry, err := PrepareNodeNamePruningContinuation(ctx, f.caFile, f.file, f.trust, f.crl, fresh, f.r, cert, at)
	if err != nil || retry.SHA256() != r.SHA256() {
		t.Fatal("retry required historical key/CA or generated another proof", err)
	}
	// The original parent may expire while its already activated successor remains valid.
	later := f.now.Add(3*time.Hour + 30*time.Minute)
	laterIntent, _ := NewNodeNamePruningIntent(f.i.Node, f.i.AuthoritySHA256, f.i.CertificateSHA256, f.i.ConfigurationSHA256, f.i.RuntimeEpoch, f.i.ActiveName, f.i.Names, later)
	laterRequest, err := PrepareNodeNamePruningContinuation(ctx, f.caFile, f.file, f.trust, f.crl, laterIntent, f.r, cert, later)
	if err != nil || ValidateNodeNamePruningRequest(f.b.CA, f.crl, laterRequest, laterIntent, later) != nil {
		t.Fatal("valid successor could not continue after original parent expiry", err)
	}
}

func TestNodeNamePruningContinuationRejectsUnsafeState(t *testing.T) {
	for _, scenario := range []string{"other-active", "wrong-receipt", "expired-leaf", "expired-crl", "expired-intent", "wrong-node", "wrong-parent", "wrong-ca", "wrong-target", "wrong-config", "wrong-epoch", "wrong-names", "revoked-parent", "revoked-leaf", "rollback-crl", "missing-floor", "missing-pending", "pending-link", "active-link", "unsafe-trust", "same-directory", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNamePruningFixture(t, []string{"new.test"})
			cert := signNamePruningFixture(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			{
				if _, err := ActivateNodeNamePruning(ctx, f.caFile, f.file, f.trust, f.r, f.i, cert, f.now); err != nil {
					t.Fatal(err)
				}
			}
			at := f.i.ExpiresAt.Add(time.Second)
			fresh, _ := NewNodeNamePruningIntent(f.i.Node, f.i.AuthoritySHA256, f.i.CertificateSHA256, f.i.ConfigurationSHA256, f.i.RuntimeEpoch, f.i.ActiveName, f.i.Names, at)
			floor, crl := f.trust, f.crl
			switch scenario {
			case "other-active", "wrong-receipt":
				other, err := f.a.Issue(Node, f.i.Node, []string{"new.test"}, at, time.Hour)
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
				at = f.now.Add(5 * time.Hour)
				fresh, _ = NewNodeNamePruningIntent(f.i.Node, f.i.AuthoritySHA256, f.i.CertificateSHA256, f.i.ConfigurationSHA256, f.i.RuntimeEpoch, f.i.ActiveName, f.i.Names, at)
			case "expired-crl":
				var err error
				crl, err = f.a.Revoke(nil, nil, f.now.Add(-2*time.Hour), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
			case "expired-intent":
				fresh = f.i
			case "wrong-node":
				fresh.Node = "other-node"
			case "wrong-parent":
				fresh.CertificateSHA256 = strings.Repeat("0", 64)
			case "wrong-ca":
				fresh.AuthoritySHA256 = strings.Repeat("0", 64)
			case "wrong-target":
				fresh.ActiveName = "unapproved.test"
			case "wrong-config":
				fresh.ConfigurationSHA256 = strings.Repeat("b", 64)
			case "wrong-epoch":
				fresh.RuntimeEpoch++
			case "wrong-names":
				fresh.Names = []string{"agent.test", "new.test"}
			case "revoked-parent", "revoked-leaf":
				revoked := f.r.Certificate
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
				pending := namePruningPending(f.file, f.i)
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
			r, err := PrepareNodeNamePruningContinuation(ctx, f.caFile, f.file, floor, crl, fresh, f.r, cert, at)
			if err == nil || r.Format != 0 || len(r.Proof) != 0 {
				t.Fatal("unsafe state produced continuation", err)
			}
		})
	}
}

func TestNodeNamePruningContinuationProofBindsCurrentKeyAndDomain(t *testing.T) {
	f := newNamePruningFixture(t, []string{"new.test"})
	cert := signNamePruningFixture(t, f)
	ctx := context.Background()
	if _, err := ActivateNodeNamePruning(ctx, f.caFile, f.file, f.trust, f.r, f.i, cert, f.now); err != nil {
		t.Fatal(err)
	}
	at := f.i.ExpiresAt.Add(time.Second)
	fresh, _ := NewNodeNamePruningIntent(f.i.Node, f.i.AuthoritySHA256, f.i.CertificateSHA256, f.i.ConfigurationSHA256, f.i.RuntimeEpoch, f.i.ActiveName, f.i.Names, at)
	r, err := PrepareNodeNamePruningContinuation(ctx, f.caFile, f.file, f.trust, f.crl, fresh, f.r, cert, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"old-proof", "challenge", "target", "config", "epoch", "names", "original-request", "missing-receipt", "nested", "wrong-csr", "normal-kind", "pending-kind"} {
		t.Run(scenario, func(t *testing.T) {
			bad, expected := r, fresh
			switch scenario {
			case "old-proof":
				bad.Proof = f.r.Proof
			case "challenge":
				bad.Intent.Challenge = strings.Repeat("1", 64)
				expected = bad.Intent
			case "target":
				bad.Intent.ActiveName = "unapproved.test"
				expected = bad.Intent
			case "config":
				bad.Intent.ConfigurationSHA256 = strings.Repeat("b", 64)
				expected = bad.Intent
			case "epoch":
				bad.Intent.RuntimeEpoch++
				expected = bad.Intent
			case "names":
				bad.Intent.Names = []string{"agent.test", "new.test"}
				expected = bad.Intent
			case "original-request":
				original := f.r
				original.Proof = make([]byte, 64)
				bad.OriginalRequest, _ = json.Marshal(original)
			case "missing-receipt":
				bad.ContinuationCertificate = nil
			case "nested":
				bad.OriginalRequest, _ = json.Marshal(r)
			case "wrong-csr":
				bad.CSR = []byte("untrusted")
			case "pending-kind":
				bad.Kind = namePruningReconciliationKind
			case "normal-kind":
				bad.Kind = namePruningKind
			}
			if err := ValidateNodeNamePruningRequest(f.b.CA, f.crl, bad, expected, at); err == nil {
				t.Fatal("invalid key/domain/binding accepted")
			}
		})
	}
}

func TestNodeNamePruningPendingReconciliationRetainsOriginalKey(t *testing.T) {
	f := newNamePruningFixture(t, []string{"new.test"})
	cert := signNamePruningFixture(t, f)
	ctx := context.Background()
	at := f.i.ExpiresAt.Add(time.Second)
	fresh, _ := NewNodeNamePruningIntent(f.i.Node, f.i.AuthoritySHA256, f.i.CertificateSHA256, f.i.ConfigurationSHA256, f.i.RuntimeEpoch, f.i.ActiveName, f.i.Names, at)
	r, err := PrepareNodeNamePruningContinuation(ctx, f.caFile, f.file, f.trust, f.crl, fresh, f.r, cert, at)
	if err != nil || r.Kind != namePruningReconciliationKind || r.IssuanceSHA256() != f.r.SHA256() {
		t.Fatal("pending reconciliation failed", err)
	}
	called := false
	if err := SignNodeNamePruningRegistered(ctx, f.authority, r, fresh, at, 3*time.Hour, func(Bundle, []byte) error { called = true; return nil }); err == nil || called {
		t.Fatal("pending reconciliation signed another leaf")
	}
	for i := 0; i < 2; i++ {
		out, err := ActivateNodeNamePruning(ctx, f.caFile, f.file, f.trust, r, fresh, cert, at)
		if err != nil || out.Changed != (i == 0) {
			t.Fatal("pending activation/replay", err)
		}
		if err := WithPrunedNodeIdentity(ctx, f.caFile, f.file, f.trust, r, fresh, cert, at, func(ctx context.Context, _ IdentityRecord) error { return nil }); err != nil {
			t.Fatal("pending receipt cannot verify after activation", err)
		}
	}
}
