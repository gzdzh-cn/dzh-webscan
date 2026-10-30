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

func recoveryStartFixture(t *testing.T, activate bool) (recoveryFixture, string, []byte) {
	t.Helper()
	f := newRecoveryFixture(t)
	floor := filepath.Join(filepath.Dir(f.directory), "start-trust")
	if err := initializeTrustState(floor, f.caBytes, f.crl, f.now); err != nil {
		t.Fatal(err)
	}
	var certificate []byte
	if err := SignNodeRecoveryRegistered(context.Background(), f.directory, f.request, f.intent, f.now, 3*time.Hour, func(b Bundle, _ []byte) error {
		certificate = b.Certificate
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if activate {
		if _, err := ActivateNodeRecovery(context.Background(), f.ca, f.file, floor, f.request, f.intent, certificate, f.now); err != nil {
			t.Fatal(err)
		}
	}
	return f, floor, certificate
}

func TestNodeRecoveryStartRequiresAlreadyActiveCSRIdentity(t *testing.T) {
	for _, scenario := range []string{"active", "not-activated", "unrelated-csr", "expired-intent"} {
		t.Run(scenario, func(t *testing.T) {
			f, floor, certificate := recoveryStartFixture(t, scenario != "not-activated")
			if scenario == "unrelated-csr" {
				other, err := f.authority.Issue(Node, f.intent.Node, []string{"node.test"}, f.now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(other.Key)
				certificate = other.Certificate
				if err := os.WriteFile(f.file, append(append([]byte{}, other.Certificate...), other.Key...), 0600); err != nil {
					t.Fatal(err)
				}
			}
			at := f.now
			if scenario == "expired-intent" {
				at = at.Add(11 * time.Minute)
			}
			before, err := os.ReadFile(f.file)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(before)
			calls := 0
			err = WithRecoveredNodeIdentity(context.Background(), f.ca, f.file, floor, f.request, f.intent, certificate, at, func(record IdentityRecord) error {
				calls++
				if record.CertificateSHA256 == f.intent.CertificateSHA256 || record.Changed {
					t.Fatal("start initialized or used parent identity")
				}
				return nil
			})
			if scenario == "active" {
				if err != nil || calls != 1 {
					t.Fatal("active recovery rejected", err, calls)
				}
			} else if err == nil || calls != 0 {
				t.Fatal("unverified identity authorized callback", err, calls)
			}
			after, err := os.ReadFile(f.file)
			defer clear(after)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("start changed active identity", err)
			}
		})
	}
}

func TestNodeRecoveryStartLocksTrustAndIdentityThroughServiceOperation(t *testing.T) {
	f, floor, certificate := recoveryStartFixture(t, true)
	failed := errors.New("service-start-failed")
	err := WithRecoveredNodeIdentity(context.Background(), f.ca, f.file, floor, f.request, f.intent, certificate, f.now, func(IdentityRecord) error {
		for _, dir := range []string{floor, filepath.Dir(f.file)} {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			lock, err := authorityLock(ctx, dir)
			cancel()
			if lock != nil {
				lock.Close()
			}
			if err == nil {
				t.Fatal("trust or identity could change during service operation")
			}
		}
		return failed
	})
	if !errors.Is(err, failed) {
		t.Fatal("service error was hidden", err)
	}
	for _, dir := range []string{floor, filepath.Dir(f.file)} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		lock, err := authorityLock(ctx, dir)
		cancel()
		if err != nil {
			t.Fatal("failed start leaked lock", err)
		}
		lock.Close()
	}
}
