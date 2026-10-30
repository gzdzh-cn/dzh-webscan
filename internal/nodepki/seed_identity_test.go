package nodepki

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func seededIdentityFixture(t *testing.T) (*Authority, Bundle, string, string, string, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	a, err := NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := a.Issue(Node, "node-a", []string{"node.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0700)
	seed := filepath.Join(dir, "seed")
	if err := os.Mkdir(seed, 0700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"ca.crt": b.CA, "identity.crt": b.Certificate, "identity.key": b.Key} {
		if err := os.WriteFile(filepath.Join(seed, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return a, b, filepath.Join(seed, "ca.crt"), seed, filepath.Join(dir, "pki-identity"), now
}

func TestSeedNodeIdentitySurvivesRotationRestartAndConfigurationRollback(t *testing.T) {
	a, b, ca, seed, dir, now := seededIdentityFixture(t)
	ctx := context.Background()
	initial, err := SeedNodeIdentity(ctx, ca, seed, dir, "node-a", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, filepath.Join(dir, "active.pem"), filepath.Join(dir, "ca.crt")} {
		st, err := os.Lstat(p)
		if err != nil || st.IsDir() && st.Mode().Perm() != 0700 || !st.IsDir() && st.Mode().Perm() != 0600 {
			t.Fatal("private state permissions", p, err)
		}
	}
	next, _ := a.Issue(Node, "node-a", []string{"node.test"}, now, 3*time.Hour)
	file := filepath.Join(dir, "active.pem")
	renewed, err := PublishIdentity(ctx, ca, file, Node, "node-a", initial.CertificateSHA256, next, now)
	if err != nil {
		t.Fatal(err)
	}
	// Even an expired, damaged or absent old seed must not undo renewal or
	// prevent restarting an already initialized node with a current identity.
	for _, path := range []string{filepath.Join(seed, "identity.key"), filepath.Join(seed, "identity.crt")} {
		os.Remove(path)
	}
	restarted, err := SeedNodeIdentity(ctx, ca, seed, dir, "node-a", now.Add(2*time.Hour))
	if err != nil || restarted.CertificateSHA256 != renewed.CertificateSHA256 {
		t.Fatal("renewed identity was replaced by seed", restarted, err)
	}
	old, err := os.ReadFile(file + ".history/" + initial.CertificateSHA256 + ".pem")
	if err != nil || !bytes.Equal(old, append(append([]byte{}, b.Certificate...), b.Key...)) {
		t.Fatal("old private identity not retained", err)
	}
	if _, err := SeedNodeIdentity(ctx, ca, seed, dir, "other-node", now); err == nil {
		t.Fatal("cross-node state reuse accepted")
	}
	if _, err := SeedNodeIdentity(ctx, ca, seed, dir, "node-a", now.Add(4*time.Hour)); err == nil {
		t.Fatal("expired live identity restored from seed")
	}
}

func TestSeedNodeIdentityRefusesUnsafeOrIncompleteState(t *testing.T) {
	for _, kind := range []string{"empty", "missing-leaf", "missing-pin", "wrong-pin", "public-directory", "public-leaf", "linked-directory", "linked-leaf", "hardlinked-leaf", "damaged-leaf"} {
		t.Run(kind, func(t *testing.T) {
			_, _, ca, seed, dir, now := seededIdentityFixture(t)
			ctx := context.Background()
			if _, err := SeedNodeIdentity(ctx, ca, seed, dir, "node-a", now); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "active.pem")
			switch kind {
			case "empty":
				os.Remove(file)
				os.Remove(filepath.Join(dir, "ca.crt"))
			case "missing-leaf":
				os.Remove(file)
			case "missing-pin":
				os.Remove(filepath.Join(dir, "ca.crt"))
			case "wrong-pin":
				other, _ := NewAuthority(now, 365*24*time.Hour)
				b, _ := other.Export()
				os.WriteFile(filepath.Join(dir, "ca.crt"), b.CA, 0600)
			case "public-directory":
				os.Chmod(dir, 0755)
			case "public-leaf":
				os.Chmod(file, 0644)
			case "linked-directory":
				os.Rename(dir, dir+"-old")
				os.Symlink(dir+"-old", dir)
			case "linked-leaf":
				os.Rename(file, file+"-old")
				os.Symlink(file+"-old", file)
			case "hardlinked-leaf":
				os.Link(file, file+"-other")
			case "damaged-leaf":
				os.WriteFile(file, []byte("broken"), 0600)
			}
			if _, err := SeedNodeIdentity(ctx, ca, seed, dir, "node-a", now); err == nil {
				t.Fatal("initialized state repaired implicitly", kind)
			}
		})
	}
}

func TestSeedNodeIdentityConcurrentInitializationAndCancellation(t *testing.T) {
	_, _, ca, seed, dir, now := seededIdentityFixture(t)
	var wg sync.WaitGroup
	results := make(chan IdentityRecord, 8)
	errors := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := SeedNodeIdentity(context.Background(), ca, seed, dir, "node-a", now)
			results <- r
			errors <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	var sha string
	for r := range results {
		if sha != "" && sha != r.CertificateSHA256 || r.CertificateSHA256 == "" {
			t.Fatal("concurrent initialization diverged")
		}
		sha = r.CertificateSHA256
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SeedNodeIdentity(ctx, ca, seed, dir+"-cancelled", "node-a", now); err == nil {
		t.Fatal("cancelled initialization succeeded")
	}
	if _, err := os.Lstat(dir + "-cancelled"); !os.IsNotExist(err) {
		t.Fatal("cancelled initialization published state", err)
	}
}

func TestSeedNodeIdentityInvalidSeedNeverPublishesState(t *testing.T) {
	for _, kind := range []string{"wrong-node", "wrong-root", "expired", "public-key-file", "linked-certificate", "damaged-key"} {
		t.Run(kind, func(t *testing.T) {
			_, _, ca, seed, dir, now := seededIdentityFixture(t)
			id := "node-a"
			switch kind {
			case "wrong-node":
				id = "node-b"
			case "wrong-root":
				other, _ := NewAuthority(now, 365*24*time.Hour)
				b, _ := other.Export()
				os.WriteFile(ca, b.CA, 0600)
			case "expired":
				now = now.Add(2 * time.Hour)
			case "public-key-file":
				os.Chmod(filepath.Join(seed, "identity.key"), 0644)
			case "linked-certificate":
				os.Rename(filepath.Join(seed, "identity.crt"), filepath.Join(seed, "old.crt"))
				os.Symlink(filepath.Join(seed, "old.crt"), filepath.Join(seed, "identity.crt"))
			case "damaged-key":
				os.WriteFile(filepath.Join(seed, "identity.key"), []byte("broken"), 0600)
			}
			if _, err := SeedNodeIdentity(context.Background(), ca, seed, dir, id, now); err == nil {
				t.Fatal("invalid seed accepted")
			}
			if _, err := os.Lstat(dir); !os.IsNotExist(err) {
				t.Fatal("invalid seed published state", err)
			}
		})
	}
}

func TestNodeIdentitySnapshotSerializesConcurrentPublication(t *testing.T) {
	a, _, ca, seed, dir, now := seededIdentityFixture(t)
	initial, err := SeedNodeIdentity(context.Background(), ca, seed, dir, "node-a", now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := a.Issue(Node, "node-a", []string{"node.test"}, now, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "active.pem")
	err = WithIdentitySnapshot(context.Background(), dir, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		publication := make(chan error, 1)
		go func() {
			_, err := PublishIdentity(ctx, ca, file, Node, "node-a", initial.CertificateSHA256, next, now)
			publication <- err
		}()
		if err := <-publication; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("publication bypassed snapshot lock: %v", err)
		}
		b, current, err := ReadIdentity(ca, file, Node, "node-a", now)
		clear(b.Key)
		if err != nil || current.CertificateSHA256 != initial.CertificateSHA256 {
			t.Fatal("active identity changed during capture", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishIdentity(context.Background(), ca, file, Node, "node-a", initial.CertificateSHA256, next, now); err != nil {
		t.Fatal("snapshot lock not released", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if err := WithIdentitySnapshot(ctx, dir, func() error { called = true; return nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled capture executed", err, called)
	}
}
