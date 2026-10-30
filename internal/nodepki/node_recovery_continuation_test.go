package nodepki

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNodeRecoveryContinuationAfterActivationAndIntentExpiry(t *testing.T) {
	f, floor, certificate := recoveryStartFixture(t, true)
	ctx := context.Background()
	at := f.intent.ExpiresAt.Add(time.Second)
	fresh, err := NewNodeRecoveryIntent(f.intent.Node, f.intent.AuthoritySHA256, f.intent.CertificateSHA256, at)
	if err != nil {
		t.Fatal(err)
	}
	active, err := os.ReadFile(f.file)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(active)
	parentHistory := f.file + ".history/" + f.intent.CertificateSHA256 + ".pem"
	beforeHistory, err := os.ReadFile(parentHistory)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(beforeHistory)
	pending, _ := renewalPending(filepath.Dir(f.file), f.intent.CertificateSHA256)
	pendingKey, err := os.ReadFile(filepath.Join(pending, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pendingKey)
	if _, err := PrepareNodeRecovery(ctx, f.ca, f.file, f.crl, fresh, at); err == nil {
		t.Fatal("ordinary recovery treated replacement as expired parent")
	}
	if err := WithRecoveredNodeIdentity(ctx, f.ca, f.file, floor, f.request, f.intent, certificate, at, func(IdentityRecord) error { t.Fatal("expired intent started service"); return nil }); err == nil {
		t.Fatal("expired original intent authorized startup")
	}
	r, err := PrepareNodeRecoveryContinuation(ctx, f.ca, f.file, floor, f.crl, fresh, certificate, at)
	if err != nil || r.Renewal.SHA256() != f.request.Renewal.SHA256() || r.Kind != recoveryContinuationKind || !bytes.Equal(r.ContinuationCertificate, certificate) {
		t.Fatal("fresh continuation lost original issuance binding", err)
	}
	raw, _ := json.Marshal(r)
	if _, err := ParseNodeRecoveryRequest(raw); err != nil {
		t.Fatal("canonical continuation not parseable", err)
	}
	if bytes.Contains(raw, []byte("PRIVATE KEY")) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(pendingKey))) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(active))) {
		t.Fatal("continuation exposed private material")
	}
	if err := ValidateNodeRecoveryRequest(f.caBytes, f.crl, r, fresh, at); err != nil {
		t.Fatal("active-key proof not independently verifiable", err)
	}
	called := false
	if err := SignNodeRecoveryRegistered(ctx, f.directory, r, fresh, at, time.Hour, func(Bundle, []byte) error { called = true; return nil }); err == nil || called {
		t.Fatal("continuation issued another leaf")
	}
	for i := 0; i < 2; i++ {
		calls := 0
		if err := WithRecoveredNodeIdentity(ctx, f.ca, f.file, floor, r, fresh, certificate, at, func(record IdentityRecord) error {
			calls++
			if record.Changed || record.CertificateSHA256 == fresh.CertificateSHA256 {
				t.Fatal("continuation used expired parent")
			}
			return nil
		}); err != nil || calls != 1 {
			t.Fatal("fresh authorization cannot start/reconcile", err)
		}
		got, err := ActivateNodeRecovery(ctx, f.ca, f.file, floor, r, fresh, certificate, at)
		if err != nil || got.Changed {
			t.Fatal("continuation activation rewrote identity", err)
		}
	}
	for file, want := range map[string][]byte{f.file: active, parentHistory: beforeHistory, filepath.Join(pending, "key.pem"): pendingKey} {
		got, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("continuation changed private state", err)
		}
		clear(got)
	}
	// A retry is deterministic and needs neither historical parent key nor CA
	// signing key. Those remain backup responsibilities, never fallback input.
	if err := os.Remove(parentHistory); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.directory, "ca.key")); err != nil {
		t.Fatal(err)
	}
	retry, err := PrepareNodeRecoveryContinuation(ctx, f.ca, f.file, floor, f.crl, fresh, certificate, at)
	if err != nil || retry.SHA256() != r.SHA256() {
		t.Fatal("response loss required old private key or generated a new request", err)
	}
}

func TestNodeRecoveryContinuationRejectsUnsafeState(t *testing.T) {
	for _, scenario := range []string{"not-active", "different-active", "wrong-receipt", "expired-leaf", "expired-intent", "wrong-node", "wrong-parent", "wrong-ca", "revoked-parent", "revoked-leaf", "expired-crl", "rollback-crl", "missing-floor", "missing-trust", "missing-pending", "pending-link", "active-link", "unsafe-trust", "same-directory", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f, floor, certificate := recoveryStartFixture(t, scenario != "not-active")
			at := f.intent.ExpiresAt.Add(time.Second)
			fresh, err := NewNodeRecoveryIntent(f.intent.Node, f.intent.AuthoritySHA256, f.intent.CertificateSHA256, at)
			if err != nil {
				t.Fatal(err)
			}
			crl := f.crl
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "different-active", "wrong-receipt":
				b, err := f.authority.Issue(Node, f.intent.Node, []string{"node.test"}, at, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(b.Key)
				if scenario == "wrong-receipt" {
					certificate = b.Certificate
				} else if err := os.WriteFile(f.file, append(append([]byte{}, b.Certificate...), b.Key...), 0600); err != nil {
					t.Fatal(err)
				}
			case "expired-leaf":
				at = f.now.Add(4 * time.Hour)
				fresh, _ = NewNodeRecoveryIntent(f.intent.Node, f.intent.AuthoritySHA256, f.intent.CertificateSHA256, at)
			case "expired-intent":
				fresh = f.intent
			case "wrong-node":
				fresh.Node = "other-node"
			case "wrong-parent":
				fresh.CertificateSHA256 = strings.Repeat("a", 64)
			case "wrong-ca":
				fresh.AuthoritySHA256 = strings.Repeat("a", 64)
			case "revoked-parent", "revoked-leaf":
				cert := f.request.Renewal.Certificate
				if scenario == "revoked-leaf" {
					cert = certificate
				}
				crl, err = f.authority.Revoke(f.crl, [][]byte{cert}, at, 24*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
			case "expired-crl":
				crl = f.seedCRL
			case "rollback-crl":
				newer, err := f.authority.Revoke(f.crl, nil, at, 24*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(floor, "ca.crl"), newer, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-floor":
				os.Remove(filepath.Join(floor, "ca.crl"))
			case "missing-trust":
				os.RemoveAll(floor)
			case "missing-pending", "pending-link":
				pending, _ := renewalPending(filepath.Dir(f.file), f.intent.CertificateSHA256)
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
			r, err := PrepareNodeRecoveryContinuation(ctx, f.ca, f.file, floor, crl, fresh, certificate, at)
			if err == nil || r.Format != 0 || len(r.Proof) != 0 {
				t.Fatal("unsafe continuation produced a proof", err)
			}
		})
	}
}

func TestNodeRecoveryContinuationProofIsBoundToActiveKeyAndDomain(t *testing.T) {
	f, floor, certificate := recoveryStartFixture(t, true)
	at := f.intent.ExpiresAt.Add(time.Second)
	fresh, _ := NewNodeRecoveryIntent(f.intent.Node, f.intent.AuthoritySHA256, f.intent.CertificateSHA256, at)
	r, err := PrepareNodeRecoveryContinuation(context.Background(), f.ca, f.file, floor, f.crl, fresh, certificate, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"challenge", "old-proof", "normal-kind", "missing-certificate", "parent-certificate", "wrong-expected", "expired", "different-receipt"} {
		t.Run(scenario, func(t *testing.T) {
			bad, expected, now := r, fresh, at
			switch scenario {
			case "challenge":
				bad.Intent.Challenge = strings.Repeat("a", 64)
				expected = bad.Intent
			case "old-proof":
				bad.Proof = f.request.Proof
			case "normal-kind":
				bad.Kind = recoveryKind
			case "missing-certificate":
				bad.ContinuationCertificate = nil
			case "parent-certificate":
				bad.ContinuationCertificate = f.request.Renewal.Certificate
			case "wrong-expected":
				expected.Challenge = strings.Repeat("a", 64)
			case "expired":
				now = fresh.ExpiresAt
			case "different-receipt":
				bad.ContinuationCertificate = append(append([]byte{}, certificate...), '\n')
			}
			if err := ValidateNodeRecoveryRequest(f.caBytes, f.crl, bad, expected, now); err == nil {
				t.Fatal("proof accepted after changing its domain or binding")
			}
		})
	}
	// Old format JSON is byte-for-byte compatible when the optional field is
	// absent. Its canonical request digest remains the existing ledger key.
	raw, _ := json.Marshal(f.request)
	if bytes.Contains(raw, []byte("continuation")) {
		t.Fatal("ordinary recovery canonical representation changed")
	}
}
