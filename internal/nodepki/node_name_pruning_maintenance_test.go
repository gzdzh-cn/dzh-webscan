package nodepki

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNodeNamePruningMaintenanceRequiresExistingTrustAndActiveIdentity(t *testing.T) {
	for _, scenario := range []string{"ready", "before-activation", "missing-pending-key", "missing-floor", "revoked", "expired", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNamePruningFixture(t, []string{"new.test"})
			certificate := signNamePruningFixture(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario != "before-activation" {
				if _, err := ActivateNodeNamePruning(ctx, f.caFile, f.file, f.trust, f.r, f.i, certificate, f.now); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(f.file)
			defer clear(before)
			now := f.now
			switch scenario {
			case "missing-pending-key":
				os.Remove(filepath.Join(namePruningPending(f.file, f.i), "key.pem"))
			case "missing-floor":
				os.Remove(filepath.Join(f.trust, "ca.crl"))
			case "revoked":
				crl, err := f.a.Revoke(f.crl, [][]byte{certificate}, f.now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := replaceCRL(f.trust, crl); err != nil {
					t.Fatal(err)
				}
			case "expired":
				now = f.i.ExpiresAt.Add(time.Second)
			case "canceled":
				cancel()
			}
			called := false
			err := WithPrunedNodeIdentity(ctx, f.caFile, f.file, f.trust, f.r, f.i, certificate, now, func(ctx context.Context, r IdentityRecord) error {
				called = true
				leaf, _ := parseCertificate(certificate)
				if r.CertificateSHA256 != publicSHA(leaf.Raw) {
					t.Fatal("not using exact pruned identity")
				}
				return nil
			})
			if (scenario == "ready") != (err == nil && called) || scenario != "ready" && called {
				t.Fatal("unproven active identity allowed runtime inspection", scenario, err)
			}
			after, _ := os.ReadFile(f.file)
			defer clear(after)
			if !bytes.Equal(before, after) {
				t.Fatal("read-only verification changed identity")
			}
		})
	}
}

func TestNodeNamePruningTrustAdvancesWithoutForgettingRevocations(t *testing.T) {
	f := newNamePruningFixture(t, []string{"new.test"})
	ctx := context.Background()
	other, err := f.a.Issue(Node, "other-node", []string{"other.test"}, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(other.Key)
	next, err := f.a.Revoke(f.crl, [][]byte{other.Certificate}, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishNodeNamePruningTrust(ctx, f.caFile, f.trust, next, f.r, f.i, f.now); err != nil {
		t.Fatal("valid CRL advance rejected", err)
	}
	if _, err := PublishNodeNamePruningTrust(ctx, f.caFile, f.trust, f.crl, f.r, f.i, f.now); err == nil {
		t.Fatal("CRL rollback accepted")
	}
	got, _ := os.ReadFile(filepath.Join(f.trust, "ca.crl"))
	if !bytes.Equal(got, next) {
		t.Fatal("lost existing revocation")
	}
	if err := os.Remove(filepath.Join(f.trust, "ca.crl")); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishNodeNamePruningTrust(ctx, f.caFile, f.trust, next, f.r, f.i, f.now); err == nil {
		t.Fatal("recreated missing trust floor")
	}
}
