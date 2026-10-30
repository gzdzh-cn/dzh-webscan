package nodepki

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type receiverFixture struct {
	a                             *Authority
	now                           time.Time
	root, caFile, seedFile, state string
	seed                          []byte
	caller, other                 *x509.Certificate
	callerPEM                     []byte
	receiver                      *ReceiverTrust
}

func newReceiverFixture(t *testing.T) receiverFixture {
	t.Helper()
	f := receiverFixture{now: time.Now().UTC().Truncate(time.Second), root: commandRoot(t)}
	var err error
	f.a, err = NewAuthority(f.now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := f.a.Export()
	defer clear(b.Key)
	f.caFile, f.seedFile, f.state = filepath.Join(f.root, "ca.crt"), filepath.Join(f.root, "seed.crl"), filepath.Join(f.root, "state")
	f.seed, err = f.a.Revoke(nil, nil, f.now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for p, raw := range map[string][]byte{f.caFile: b.CA, f.seedFile: f.seed} {
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	one, _ := f.a.Issue(Collector, "one", nil, f.now, 7*24*time.Hour)
	defer clear(one.Key)
	two, _ := f.a.Issue(Collector, "two", nil, f.now, 7*24*time.Hour)
	defer clear(two.Key)
	f.callerPEM, f.caller = one.Certificate, mustParseReceiverCertificate(t, one.Certificate)
	f.other = mustParseReceiverCertificate(t, two.Certificate)
	f.receiver, err = NewReceiverTrust(f.caFile, f.seedFile, f.state, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func mustParseReceiverCertificate(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	c, err := parseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestReceiverRecoversExpiredFloorAndRestartsWithoutSeedRollback(t *testing.T) {
	f := newReceiverFixture(t)
	later := f.now.Add(25 * time.Hour)
	r, err := NewReceiverTrust(f.caFile, f.seedFile, f.state, later)
	if err != nil {
		t.Fatal("expired authentic floor cannot receive renewal", err)
	}
	if r.Verify(f.caller, Collector, "one", later) == nil {
		t.Fatal("expired floor authorizes ordinary RPC")
	}
	next, _ := f.a.Revoke(f.seed, nil, later, 24*time.Hour)
	receipt, err := r.Publish(context.Background(), f.caller, next, later)
	if err != nil || receipt.Number != "2" || receipt.SHA256 == "" || !receipt.NextUpdate.After(later) {
		t.Fatal(receipt, err)
	}
	if err := r.Verify(f.caller, Collector, "one", later); err != nil {
		t.Fatal("new policy not immediately active", err)
	}
	// A lost response is retried without rewriting a different state.
	if same, err := r.Publish(context.Background(), f.caller, next, later); err != nil || same != receipt {
		t.Fatal("retry", same, err)
	}
	seed, _ := os.ReadFile(f.seedFile)
	if !bytes.Equal(seed, f.seed) {
		t.Fatal("immutable installation material changed")
	}
	if err := os.Remove(f.seedFile); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewReceiverTrust(f.caFile, f.seedFile, f.state, later)
	if err != nil || restarted.Verify(f.caller, Collector, "one", later) != nil {
		t.Fatal("restart reused seed", err)
	}
	if _, err := restarted.Publish(context.Background(), f.caller, f.seed, later); err == nil {
		t.Fatal("expired/lower snapshot restored")
	}
}

func TestReceiverRejectsRevokedCallerAndCannotEraseRevocations(t *testing.T) {
	f := newReceiverFixture(t)
	next, _ := f.a.Revoke(f.seed, [][]byte{f.callerPEM}, f.now, time.Hour)
	if _, err := f.receiver.Publish(context.Background(), f.other, next, f.now); err != nil {
		t.Fatal(err)
	}
	if f.receiver.Verify(f.caller, Collector, "one", f.now) == nil {
		t.Fatal("revoked peer remained authorized")
	}
	third, _ := f.a.Revoke(next, nil, f.now, time.Hour)
	if _, err := f.receiver.Publish(context.Background(), f.caller, third, f.now); err == nil {
		t.Fatal("revoked caller updated trust")
	}
	// A higher validly signed number still cannot remove the accepted revocation.
	forgedBranch, _ := f.a.Revoke(f.seed, nil, f.now, time.Hour)
	forgedBranch, _ = f.a.Revoke(forgedBranch, nil, f.now, time.Hour)
	if _, err := f.receiver.Publish(context.Background(), f.other, forgedBranch, f.now); err == nil {
		t.Fatal("higher branch removed revocation")
	}
	restarted, err := NewReceiverTrust(f.caFile, f.seedFile, f.state, f.now)
	if err != nil || restarted.Verify(f.caller, Collector, "one", f.now) == nil {
		t.Fatal("restart erased revocation", err)
	}
	before, _ := os.ReadFile(filepath.Join(f.state, "ca.crl"))
	if !bytes.Equal(before, next) {
		t.Fatal("rejected request changed disk")
	}
}

func TestReceiverRejectsDamagedFloorLinksWrongCAAndRole(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "public", "link", "directory", "wrong-ca", "role", "bad-list"} {
		t.Run(kind, func(t *testing.T) {
			f := newReceiverFixture(t)
			path := filepath.Join(f.state, "ca.crl")
			next, _ := f.a.Revoke(f.seed, nil, f.now, time.Hour)
			peer := f.caller
			switch kind {
			case "missing":
				os.Remove(path)
			case "corrupt":
				os.WriteFile(path, []byte("broken"), 0600)
			case "public":
				os.Chmod(path, 0644)
			case "link":
				os.Rename(path, path+".old")
				os.Symlink(path+".old", path)
			case "directory":
				os.Chmod(f.state, 0755)
			case "wrong-ca":
				other, _ := NewAuthority(f.now, 365*24*time.Hour)
				next, _ = other.Revoke(nil, nil, f.now, time.Hour)
			case "role":
				leaf, _ := f.a.Issue(Node, "one", []string{"node.test"}, f.now, time.Hour)
				defer clear(leaf.Key)
				peer = mustParseReceiverCertificate(t, leaf.Certificate)
			case "bad-list":
				next = []byte("not a CRL")
			}
			if _, err := f.receiver.Publish(context.Background(), peer, next, f.now); err == nil {
				t.Fatal("unsafe state or caller accepted")
			}
			if kind == "missing" || kind == "corrupt" || kind == "public" || kind == "link" || kind == "directory" {
				if _, err := NewReceiverTrust(f.caFile, f.seedFile, f.state, f.now); err == nil {
					t.Fatal("restart repaired damaged floor")
				}
			}
		})
	}
}

func TestReceiverConcurrentPublishAndLockCancellation(t *testing.T) {
	f := newReceiverFixture(t)
	second, _ := f.a.Revoke(f.seed, nil, f.now, time.Hour)
	third, _ := f.a.Revoke(second, nil, f.now, time.Hour)
	var wg sync.WaitGroup
	for _, raw := range [][]byte{second, third} {
		wg.Add(1)
		go func(raw []byte) { defer wg.Done(); f.receiver.Publish(context.Background(), f.caller, raw, f.now) }(raw)
	}
	wg.Wait()
	got, _ := os.ReadFile(filepath.Join(f.state, "ca.crl"))
	if !bytes.Equal(got, third) {
		t.Fatal("concurrent receiver rolled back")
	}
	lock, err := authorityLock(context.Background(), f.state)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := f.receiver.Publish(ctx, f.caller, third, f.now); err == nil {
		t.Fatal("blocked writer ignored cancellation")
	}
}

func TestSharedTrustSnapshotCachesPublicBytesWithoutExposingMutableMemory(t *testing.T) {
	f := newReceiverFixture(t)
	raw, sha, err := f.receiver.Snapshot(f.now, "")
	if err != nil || !bytes.Equal(raw, f.seed) || sha == "" {
		t.Fatal(err)
	}
	raw[0] ^= 1
	if again, _, err := f.receiver.Snapshot(f.now, ""); err != nil || !bytes.Equal(again, f.seed) {
		t.Fatal("caller mutated cache", err)
	}
	if same, digest, err := f.receiver.Snapshot(f.now, sha); err != nil || same != nil || digest != sha {
		t.Fatal("unchanged snapshot copied", err)
	}
	if _, _, err := f.receiver.Snapshot(f.now.Add(25*time.Hour), sha); err == nil {
		t.Fatal("expired snapshot exported")
	}
}
