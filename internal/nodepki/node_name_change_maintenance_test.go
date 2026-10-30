package nodepki

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNodeNameChangeTrustAdvanceRequiresExactAuthorizationAndExistingFloor(t *testing.T) {
	for _, scenario := range []string{"advance", "replay", "rollback", "missing-floor", "other-pin", "revoked-parent", "wrong-intent", "expired", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeFixture(t, "next.test")
			next, err := f.a.Revoke(f.crl, nil, f.now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			intent, now := f.intent, f.now
			floor := filepath.Join(f.trust, "ca.crl")
			switch scenario {
			case "replay":
				if _, err := PublishNodeNameChangeTrust(ctx, f.caFile, f.trust, next, f.request, intent, now); err != nil {
					t.Fatal(err)
				}
			case "rollback":
				if err := os.WriteFile(floor, next, 0600); err != nil {
					t.Fatal(err)
				}
				next = f.crl
			case "missing-floor":
				if err := os.Remove(floor); err != nil {
					t.Fatal(err)
				}
			case "other-pin":
				if err := os.WriteFile(filepath.Join(f.trust, "ca.crt"), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "revoked-parent":
				next, err = f.a.Revoke(f.crl, [][]byte{f.request.Certificate}, f.now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
			case "wrong-intent":
				intent.ServerName = "unapproved.test"
			case "expired":
				now = f.now.Add(11 * time.Minute)
			case "canceled":
				cancel()
			}
			before, _ := os.ReadFile(floor)
			receipt, err := PublishNodeNameChangeTrust(ctx, f.caFile, f.trust, next, f.request, intent, now)
			after, _ := os.ReadFile(floor)
			if scenario == "advance" || scenario == "replay" {
				if err != nil || receipt.SHA256 != publicSHA(next) || !bytes.Equal(next, after) {
					t.Fatal("valid floor advance/replay failed", err)
				}
			} else if err == nil || receipt.SHA256 != "" || !bytes.Equal(before, after) {
				t.Fatal("unverified request changed durable trust", err)
			}
		})
	}
}

func TestNodeNameChangeReadOnlyVerificationRequiresActiveExactReceipt(t *testing.T) {
	for _, scenario := range []string{"active", "not-active", "expired", "missing-request", "revoked", "callback-failed"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeFixture(t, "next.test")
			certificate := signNameChangeFixture(t, f)
			ctx := context.Background()
			if scenario != "not-active" {
				if _, err := ActivateNodeNameChange(ctx, f.caFile, f.file, f.trust, f.request, f.intent, certificate, f.now); err != nil {
					t.Fatal(err)
				}
			}
			now := f.now
			switch scenario {
			case "expired":
				now = now.Add(11 * time.Minute)
			case "missing-request":
				if err := os.Remove(filepath.Join(nameChangePending(f.file, f.intent), "request.json")); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				crl, err := f.a.Revoke(f.crl, [][]byte{certificate}, f.now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.trust, "ca.crl"), crl, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(f.file)
			defer clear(before)
			calls := 0
			failed := errors.New("isolated-resource-check-failed")
			err := WithNameChangedNodeIdentity(ctx, f.caFile, f.file, f.trust, f.request, f.intent, certificate, now, func(ctx context.Context, record IdentityRecord) error {
				calls++
				if record.Changed || record.CertificateSHA256 == f.intent.CertificateSHA256 {
					t.Fatal("verification activated or accepted original identity")
				}
				for _, dir := range []string{f.trust, filepath.Dir(f.file)} {
					wait, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
					lock, err := authorityLock(wait, dir)
					cancel()
					if lock != nil {
						lock.Close()
					}
					if err == nil {
						t.Fatal("trust/identity lock not held through verification")
					}
				}
				if scenario == "callback-failed" {
					return failed
				}
				return nil
			})
			after, _ := os.ReadFile(f.file)
			defer clear(after)
			if !bytes.Equal(before, after) {
				t.Fatal("read-only verification changed identity")
			}
			if scenario == "active" {
				if err != nil || calls != 1 {
					t.Fatal("valid verification failed", err)
				}
			} else if scenario == "callback-failed" {
				if !errors.Is(err, failed) || calls != 1 {
					t.Fatal("callback failure lost", err)
				}
			} else if err == nil || calls != 0 {
				t.Fatal("unverified identity authorized resource check", err)
			}
		})
	}
}

// Host verification includes checksum reads, scanner probes and actual manager
// and kernel inspections. Its operation budget must not be the five-second
// budget used for a small certificate publication.
func TestNodeNameChangeVerificationAllowsBoundedHostInspection(t *testing.T) {
	f := newNameChangeFixture(t, "next.test")
	certificate := signNameChangeFixture(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := ActivateNodeNameChange(ctx, f.caFile, f.file, f.trust, f.request, f.intent, certificate, f.now); err != nil {
		t.Fatal(err)
	}
	err := WithNameChangedNodeIdentity(ctx, f.caFile, f.file, f.trust, f.request, f.intent, certificate, f.now, func(ctx context.Context, _ IdentityRecord) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5100 * time.Millisecond):
			return nil
		}
	})
	if err != nil {
		t.Fatal("valid bounded host inspection rejected", err)
	}
}

func TestNodeNameChangeVerificationPropagatesOperationContext(t *testing.T) {
	for _, scenario := range []string{"operation-budget", "caller-deadline", "caller-cancel", "authorization-expiry", "lock-wait"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeFixture(t, "next.test")
			if scenario == "authorization-expiry" {
				var err error
				f.now = time.Now().UTC()
				f.intent, err = NewNodeNameChangeIntent(f.intent.Node, f.intent.AuthoritySHA256, f.intent.CertificateSHA256, f.intent.ServerName, f.now)
				if err != nil {
					t.Fatal(err)
				}
				f.intent.ExpiresAt = time.Now().UTC().Add(3 * time.Second)
				f.request, err = PrepareNodeNameChange(context.Background(), f.caFile, f.file, f.trust, f.intent, time.Now())
				if err != nil {
					t.Fatal(err)
				}
			}
			certificate := signNameChangeFixture(t, f)
			if _, err := ActivateNodeNameChange(context.Background(), f.caFile, f.file, f.trust, f.request, f.intent, certificate, time.Now()); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(f.file)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(before)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var wantedDeadline time.Time
			if scenario == "caller-deadline" || scenario == "lock-wait" {
				wantedDeadline = time.Now().Add(75 * time.Millisecond)
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(ctx, wantedDeadline)
				defer stop()
			}
			if scenario == "lock-wait" {
				lock, err := authorityLock(ctx, f.trust)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			}
			started := time.Now()
			calls := 0
			err = WithNameChangedNodeIdentity(ctx, f.caFile, f.file, f.trust, f.request, f.intent, certificate, time.Now(), func(op context.Context, _ IdentityRecord) error {
				calls++
				deadline, ok := op.Deadline()
				if !ok || deadline.After(started.Add(NameChangeVerificationTimeout+time.Second)) {
					t.Fatal("missing or unbounded verification context")
				}
				switch scenario {
				case "operation-budget":
					if deadline.Before(started.Add(NameChangeVerificationTimeout - time.Second)) {
						t.Fatal("publication budget reused for host inspection")
					}
					return nil
				case "caller-cancel":
					cancel()
				case "caller-deadline":
					if !deadline.Equal(wantedDeadline) {
						t.Fatal("caller deadline extended")
					}
				case "authorization-expiry":
					if !deadline.Equal(f.intent.ExpiresAt) {
						t.Fatal("authorization deadline extended")
					}
				default:
					t.Fatal("lock wait reached verification")
				}
				<-op.Done()
				// A callback returning nil cannot hide cancellation/expiry.
				return nil
			})
			if scenario == "operation-budget" {
				if err != nil || calls != 1 {
					t.Fatal("valid inspection rejected", err)
				}
			} else {
				wanted := error(context.DeadlineExceeded)
				if scenario == "caller-cancel" {
					wanted = context.Canceled
				}
				if !errors.Is(err, wanted) || (scenario == "lock-wait" && calls != 0) || (scenario != "lock-wait" && calls != 1) {
					t.Fatal("operation context lost", err, calls)
				}
			}
			after, err := os.ReadFile(f.file)
			defer clear(after)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("read-only acceptance changed identity", err)
			}
		})
	}
}
