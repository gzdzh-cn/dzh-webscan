package nodepki

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMaintenanceSnapshotLocksWritersAndReleasesOnFailure(t *testing.T) {
	root := commandRoot(t)
	dirs := []string{filepath.Join(root, "issuer"), filepath.Join(root, "trust"), filepath.Join(root, "identity")}
	for _, dir := range dirs {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	successor := SuccessorAuthorityDirectory(dirs[0])
	if err := os.Mkdir(successor, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("isolated capture failed")
	err := WithMaintenanceSnapshot(context.Background(), dirs[0], dirs[1], dirs[2], func() error {
		for _, dir := range append(append([]string{}, dirs...), successor) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			lock, err := authorityLock(ctx, dir)
			cancel()
			if lock != nil {
				lock.Close()
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("writer escaped snapshot lock", err)
			}
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	for _, dir := range dirs {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		lock, err := authorityLock(ctx, dir)
		cancel()
		if err != nil {
			t.Fatal("failed capture leaked a lock", err)
		}
		lock.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if err := WithMaintenanceSnapshot(ctx, dirs[0], dirs[1], dirs[2], func() error { called = true; return nil }); err == nil || called {
		t.Fatal("canceled snapshot entered capture")
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(dirs[0], alias); err != nil {
		t.Fatal(err)
	}
	if err := WithMaintenanceSnapshot(context.Background(), alias, dirs[1], dirs[2], func() error { called = true; return nil }); err == nil || called {
		t.Fatal("snapshot accepted linked authority")
	}
}
