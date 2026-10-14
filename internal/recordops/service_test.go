package recordops

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"webscan/internal/persist"
)

func TestDurableReplayOwnershipAndFileTombstone(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	db, e := persist.OpenDB(filepath.Join(root, "test.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s, e := New(db, root)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	os.WriteFile(filepath.Join(root, "a.yaml"), []byte("data"), 0600)
	j, e := s.Create(ctx, "admin", "backup", "key", []string{"a.yaml"})
	if e != nil {
		t.Fatal(e)
	}
	other, e := s.Create(ctx, "admin", "backup", "key", []string{"a.yaml"})
	if e != nil || other.ID != j.ID {
		t.Fatal("idempotence")
	}
	if _, e = s.Create(ctx, "admin", "backup", "key", []string{"b.yaml"}); e == nil {
		t.Fatal("scope conflict")
	}
	if _, e = s.Job(ctx, "other", j.ID); e == nil {
		t.Fatal("ownership")
	}
	os.Rename(filepath.Join(root, "a.yaml"), filepath.Join(root, ".delete-a.yaml"))
	restarted, e := New(db, root)
	if e != nil {
		t.Fatal(e)
	}
	restarted.Apply = func(ctx context.Context, kind, id string) (string, string, error) {
		return "deleted", "", RemoveFile(root, id)
	}
	if e = restarted.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	done, e := restarted.Job(ctx, "admin", j.ID)
	if e != nil || done.Status != "complete" || len(done.Results) != 1 {
		t.Fatal(done, e)
	}
	if _, e = os.Stat(filepath.Join(root, ".delete-a.yaml")); !os.IsNotExist(e) {
		t.Fatal("tombstone left")
	}
	os.Symlink("/tmp", filepath.Join(root, "bad.yaml"))
	if e = RemoveFile(root, "bad.yaml"); e == nil {
		t.Fatal("symlink followed")
	}
	if e = RemoveFile(root, "../outside"); e == nil {
		t.Fatal("path traversal")
	}
}
