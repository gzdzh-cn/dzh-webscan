package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/recordops"
	"webscan/internal/website"
)

type legacyBackupFixture struct {
	db              *sql.DB
	path, directory string
	ids             []string
	doc             []byte
}

func legacyBackups(t *testing.T, count int) legacyBackupFixture {
	t.Helper()
	f := legacyBackupFixture{path: filepath.Join(t.TempDir(), "backups.sqlite3"), directory: privateTestDir(t)}
	var err error
	f.db, err = persist.OpenDB(f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Close() })
	mustHistoryExec(t, f.db, `CREATE TABLE website_backups(id TEXT PRIMARY KEY,created INTEGER NOT NULL,source TEXT NOT NULL,count INTEGER NOT NULL,digest TEXT NOT NULL,restored INTEGER NOT NULL DEFAULT 0,result TEXT NOT NULL DEFAULT '');`+recordops.Schema)
	f.doc = common.JSON(backupDocument(website.SiteConfig{Name: "原网站备份", URL: "https://old-backup.example.test/", Node: "historical-node", Keyword: "原关键词", Slow: true}))
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("%032x", i+1)
		f.ids = append(f.ids, id)
		if err = os.WriteFile(filepath.Join(f.directory, id+".json"), f.doc, 0600); err != nil {
			t.Fatal(err)
		}
		mustHistoryExec(t, f.db, `INSERT INTO website_backups VALUES(?,?,'manual',1,?,?,?)`, id, time.Now().Unix()-1000, digest(f.doc), time.Now().Unix()-500, "新增 1，更新 0，不变 0")
	}
	return f
}

func backupArchive(t *testing.T, s *Store, f legacyBackupFixture) string {
	t.Helper()
	r, err := s.ArchiveSQLite(context.Background(), f.path, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	return r.Source
}

func TestLegacyWebsiteBackupsPreserveMetadataResumeAndFreeze(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	f := legacyBackups(t, 3)
	source := backupArchive(t, s, f)
	second := filepath.Join(f.directory, f.ids[1]+".json")
	if err := os.Remove(second); err != nil {
		t.Fatal(err)
	}
	r, err := s.MapWebsiteBackupArchive(ctx, source, f.directory)
	if err == nil || r.Complete || r.ReadyForCutover || r.Imported != 1 || tableCount(t, s, "v3_website_backups") != 1 {
		t.Fatal("missing file lost committed progress or claimed complete", r, err)
	}
	if _, err = s.CreateWebsiteBackup(ctx, "admin", "blocked-by-import"); err != ErrMigrationPending {
		t.Fatal("import did not freeze writes", err)
	}
	if err = os.WriteFile(second, f.doc, 0600); err != nil {
		t.Fatal(err)
	}
	r, err = s.MapWebsiteBackupArchive(ctx, source, f.directory)
	if err != nil || !r.Complete || r.Imported != 3 || r.Processed != 3 || r.ReadyForCutover {
		t.Fatal(r, err)
	}
	if tableCount(t, s, "v3_websites") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("backup import activated websites or notifications")
	}
	rows, err := s.WebsiteBackups(ctx, retentionCursor{}, 20)
	if err != nil || len(rows) != 3 {
		t.Fatal(rows, err)
	}
	for _, b := range rows {
		if b.CanDelete || b.DeleteReason == "" || b.Source != "manual" || b.Restored == nil || !strings.Contains(string(b.Result), "新增 1") || !strings.Contains(string(b.Result), "legacy_id") {
			t.Fatal("lost original metadata or migration protection", b)
		}
		doc, e := s.ExportWebsiteBackup(ctx, b.ID)
		if e != nil || len(doc.Sites) != 1 || doc.Sites[0].Node != "historical-node" || doc.Sites[0].Keyword != "原关键词" {
			t.Fatal(doc, e)
		}
	}
	if err = os.Remove(filepath.Join(f.directory, f.ids[0]+".json")); err != nil {
		t.Fatal(err)
	}
	again, err := s.MapWebsiteBackupArchive(ctx, source, f.directory)
	if err != nil || !again.Complete || again.Imported != 3 || tableCount(t, s, "v3_website_backups") != 3 {
		t.Fatal("repeat re-read old files or duplicated backups", again, err)
	}
	if _, err = s.PreviewWebsiteBackup(ctx, "admin", rows[0].ID); err != ErrMigrationPending {
		t.Fatal("import authorized a restore", err)
	}
}

func TestLegacyWebsiteBackupsRejectPendingDeletionBeforeBinding(t *testing.T) {
	s := testStore(t)
	f := legacyBackups(t, 1)
	mustHistoryExec(t, f.db, `INSERT INTO record_operations(id,kind,status) VALUES('old-delete','website-backup','pending')`)
	source := backupArchive(t, s, f)
	r, err := s.MapWebsiteBackupArchive(context.Background(), source, f.directory)
	if err == nil || r.Complete || tableCount(t, s, "v3_migration_domains") != 0 || tableCount(t, s, "v3_website_backups") != 0 {
		t.Fatal("pending old delete bound or imported backups", r, err)
	}
	mustHistoryExec(t, f.db, `UPDATE record_operations SET status='complete'`)
	source = backupArchive(t, s, f)
	r, err = s.MapWebsiteBackupArchive(context.Background(), source, f.directory)
	if err != nil || !r.Complete || r.Processed != 2 || r.Imported != 1 {
		t.Fatal(r, err)
	}
}

func TestLegacyWebsiteBackupsRefuseChangedPayloadAndOccupiedDomain(t *testing.T) {
	for _, kind := range []string{"digest", "count", "format", "live", "source"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			f := legacyBackups(t, 1)
			if kind == "count" {
				mustHistoryExec(t, f.db, `UPDATE website_backups SET count=2`)
			}
			if kind == "format" {
				f.doc = []byte(`{"format_version":2}`)
				mustHistoryExec(t, f.db, `UPDATE website_backups SET digest=?`, digest(f.doc))
				if err := os.WriteFile(filepath.Join(f.directory, f.ids[0]+".json"), f.doc, 0600); err != nil {
					t.Fatal(err)
				}
			}
			source := backupArchive(t, s, f)
			if kind == "digest" {
				if err := os.WriteFile(filepath.Join(f.directory, f.ids[0]+".json"), []byte("private original contents changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "live" {
				if _, err := s.CreateWebsiteBackup(context.Background(), "admin", "existing-backup"); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "source" {
				if _, err := s.MapWebsiteBackupArchive(context.Background(), source, f.directory); err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, f.db, `UPDATE website_backups SET source='import'`)
				source = backupArchive(t, s, f)
			}
			r, err := s.MapWebsiteBackupArchive(context.Background(), source, f.directory)
			if err == nil || r.Complete || strings.Contains(err.Error(), "private original") {
				t.Fatal("invalid backup accepted or leaked", r, err)
			}
			want := 0
			if kind == "source" || kind == "live" {
				want = 1
			}
			if tableCount(t, s, "v3_website_backups") != want {
				t.Fatal("failed import changed existing backups")
			}
		})
	}
}

func TestLegacyWebsiteBackupReaderRejectsLinksAndUnsafeFiles(t *testing.T) {
	f := legacyBackups(t, 1)
	dir, err := privateDirectory(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	file := filepath.Join(f.directory, f.ids[0]+".json")
	for _, id := range []string{"../secret", strings.Repeat("A", 32), strings.Repeat("0", 31), strings.Repeat("0", 64)} {
		if _, err = readLegacyWebsiteBackup(dir, id); err == nil {
			t.Fatal("unsafe basename accepted")
		}
	}
	if err = os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readLegacyWebsiteBackup(dir, f.ids[0]); err == nil {
		t.Fatal("public file accepted")
	}
	if err = os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(t.TempDir(), "secret"), file); err != nil {
		t.Fatal(err)
	}
	if _, err = readLegacyWebsiteBackup(dir, f.ids[0]); err == nil {
		t.Fatal("symlink accepted")
	}
	if err = os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err = unix.Mkfifo(file, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readLegacyWebsiteBackup(dir, f.ids[0]); err == nil {
		t.Fatal("fifo accepted")
	}
	if err = os.Remove(file); err != nil {
		t.Fatal(err)
	}
	fp, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = fp.Truncate(websiteBackupStoredLimit + 1); err != nil {
		t.Fatal(err)
	}
	fp.Close()
	if _, err = readLegacyWebsiteBackup(dir, f.ids[0]); err == nil {
		t.Fatal("oversized file accepted")
	}
}
