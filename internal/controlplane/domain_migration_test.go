package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/website"
)

func legacyWebsiteFixture(t *testing.T, count int) (*sql.DB, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.sqlite3")
	db, err := persist.OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	const schema = `CREATE TABLE website_admin(id INTEGER PRIMARY KEY,username TEXT,password_hash TEXT,revision INTEGER,modified INTEGER);
CREATE TABLE website_sessions(token_hash TEXT PRIMARY KEY,revision INTEGER,csrf TEXT,expires INTEGER,created INTEGER);
CREATE TABLE websites(id INTEGER PRIMARY KEY,name TEXT,url TEXT,node TEXT,keyword TEXT,slow INTEGER,paused INTEGER,deleted INTEGER,version INTEGER,state TEXT);
CREATE TABLE website_incidents(id INTEGER PRIMARY KEY,site INTEGER,kind TEXT,started INTEGER,ended INTEGER,reason TEXT);`
	if _, err = db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("original-password-123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO website_admin VALUES(1,'original-admin',?,7,?)", string(hash), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	valid := digest([]byte("valid-cookie"))
	expired := digest([]byte("expired-cookie"))
	revoked := digest([]byte("revoked-cookie"))
	for _, session := range []struct {
		hash              string
		revision, expires int64
	}{{valid, 7, time.Now().Add(time.Hour).Unix()}, {expired, 7, time.Now().Add(-time.Hour).Unix()}, {revoked, 6, time.Now().Add(time.Hour).Unix()}} {
		if _, err = db.Exec("INSERT INTO website_sessions VALUES(?,?,?,?,?)", session.hash, session.revision, "fixture-csrf-token", session.expires, time.Now().UnixNano()); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= count; i++ {
		state := website.State{Status: "normal", Checks: 12, Passed: 12}
		if i == 1 {
			state = website.State{Status: "down", Checks: 15, Passed: 12, Failures: 3, Incident: 100, DownSince: time.Now().Add(-time.Hour).Unix()}
		}
		if _, err = db.Exec("INSERT INTO websites VALUES(?,?,?,'node-old','关键词',1,0,0,3,?)", i, fmt.Sprintf("原网站-%d", i), fmt.Sprintf("https://old-%d.example.test/", i), string(common.JSON(state))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec("INSERT INTO website_incidents VALUES(100,1,'outage',?,NULL,'原故障')", time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	return db, path, valid
}

func TestMapWebsiteArchivePreservesLiveIdentityAndKeepsMigrationFenced(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	source, path, valid := legacyWebsiteFixture(t, 3)
	// Invalid source lifetimes must not bypass the 12-hour absolute limit.
	if _, err := source.Exec("INSERT INTO website_sessions VALUES(?,?,?,?,?)", digest([]byte("overlong-cookie")), 7, "fixture-csrf-token", time.Now().Add(24*time.Hour).Unix(), time.Now().UnixNano()); err != nil {
		t.Fatal(err)
	}
	archive, err := s.ArchiveSQLite(ctx, path, filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := s.MapWebsiteArchive(ctx, archive.Source)
	if err != nil || !report.Complete || report.ReadyForCutover || report.Processed != 9 || report.Imported != 6 {
		t.Fatal(report, err)
	}
	// Repeating the same snapshot is a checkpointed no-op.
	again, err := s.MapWebsiteArchive(ctx, archive.Source)
	if err != nil || again.Imported != report.Imported {
		t.Fatal(again, err)
	}
	site, err := s.Site(ctx, 1)
	if err != nil || site.Name != "原网站-1" || site.Node != "node-old" || site.Version != 3 || site.State.Incident != 100 || !site.MigrationPending {
		t.Fatal(site, err)
	}
	incidents, err := s.SiteIncidents(ctx, 1, 0, 20)
	if err != nil || len(incidents) != 1 || incidents[0].ID != 100 || incidents[0].Ended != nil {
		t.Fatal(incidents, err)
	}
	var hash string
	var revision int64
	if err = s.DB.QueryRow("SELECT password_hash,revision FROM v3_accounts WHERE username='original-admin'").Scan(&hash, &revision); err != nil || revision != 7 || bcrypt.CompareHashAndPassword([]byte(hash), []byte("original-password-123")) != nil {
		t.Fatal(revision, err)
	}
	if tableCount(t, s, "v3_sessions") != 1 {
		t.Fatal("revived expired or revoked session")
	}
	var expiry time.Time
	if err = s.DB.QueryRow("SELECT expires_at FROM v3_sessions WHERE token_hash=$1", valid).Scan(&expiry); err != nil || time.Until(expiry) > time.Hour {
		t.Fatal("session lifetime extended", expiry, err)
	}
	jobs, err := s.ClaimSites(ctx, "shadow", 10)
	if err != nil || len(jobs) != 0 {
		t.Fatal("migration started checks before cutover", jobs, err)
	}
	if _, err = s.SaveSite(ctx, "original-admin", "edit-imported", SiteInput{ID: 1, Name: site.Name, URL: site.URL}, site.Version); err != ErrMigrationPending {
		t.Fatal("edited fenced imported site", err)
	}
	if tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("migration sent notices")
	}
	var count int
	if err = source.QueryRow("SELECT count(*) FROM websites").Scan(&count); err != nil || count != 3 {
		t.Fatal("changed source", count, err)
	}
	if _, err = s.SaveSite(ctx, "original-admin", "create-during-import", SiteInput{Name: "阻止新建", URL: "https://new.example.test"}, 0); err != ErrMigrationPending {
		t.Fatal("created during migration", err)
	}
	// Test-only activation to verify sequence preservation, not a cutover API.
	mustHistoryExec(t, s.DB, "UPDATE v3_migration_domains SET pending=false")
	newSite := savedSite(t, s, "new-after-import")
	if newSite.ID <= 3 {
		t.Fatal("reused imported identity")
	}
}

func TestMapWebsiteArchiveResumesFailedBatch(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, path, _ := legacyWebsiteFixture(t, 503)
	archive, err := s.ArchiveSQLite(ctx, path, filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`CREATE FUNCTION interrupt_site_mapping() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.id=501 THEN RAISE EXCEPTION 'test interruption'; END IF; RETURN NEW; END$$;CREATE TRIGGER interrupt_site_mapping BEFORE INSERT ON v3_websites FOR EACH ROW EXECUTE FUNCTION interrupt_site_mapping()`); err != nil {
		t.Fatal(err)
	}
	partial, err := s.MapWebsiteArchive(ctx, archive.Source)
	if err == nil || partial.Processed < 500 || partial.Complete {
		t.Fatal("interruption ignored")
	}
	if count := tableCount(t, s, "v3_websites"); count != 500 {
		t.Fatal("short transaction boundary", count)
	}
	if _, err = s.DB.Exec("DROP TRIGGER interrupt_site_mapping ON v3_websites"); err != nil {
		t.Fatal(err)
	}
	report, err := s.MapWebsiteArchive(ctx, archive.Source)
	if err != nil || !report.Complete || report.ReadyForCutover || tableCount(t, s, "v3_websites") != 503 {
		t.Fatal(report, err)
	}
	if tableCount(t, s, "v3_accounts") != 1 || tableCount(t, s, "v3_sessions") != 1 {
		t.Fatal("duplicated account/session after resume")
	}
}

func TestMapWebsiteArchiveRejectsCorruptionAndLiveTarget(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, path, _ := legacyWebsiteFixture(t, 2)
	archive, err := s.ArchiveSQLite(ctx, path, filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`UPDATE v3_legacy_records SET payload=jsonb_set(payload,'{name,value}','"tampered"') WHERE source=$1 AND table_name='websites' AND record_key='1'`, archive.Source); err != nil {
		t.Fatal(err)
	}
	if _, err = s.MapWebsiteArchive(ctx, archive.Source); err == nil || !strings.Contains(err.Error(), "摘要") {
		t.Fatal("corrupt staging accepted", err)
	}
	if tableCount(t, s, "v3_websites") != 0 {
		t.Fatal("partially imported corrupt batch")
	}
	target := testStore(t)
	savedSite(t, target, "live")
	if _, err = target.MapWebsiteArchive(ctx, archive.Source); err == nil {
		t.Fatal("overwrote live target")
	}
	if tableCount(t, target, "v3_websites") != 1 {
		t.Fatal("live target changed")
	}
	if _, err = s.MapWebsiteArchive(ctx, "not-a-digest"); err == nil {
		t.Fatal("accepted arbitrary source")
	}
}

func TestDomainImportRawRecordsRemainLossless(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, path, _ := legacyWebsiteFixture(t, 1)
	archive, err := s.ArchiveSQLite(ctx, path, filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.MapWebsiteArchive(ctx, archive.Source); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err = s.DB.QueryRow("SELECT payload FROM v3_legacy_records WHERE source=$1 AND table_name='websites' AND record_key='1'", archive.Source).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var record archivedRecord
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record["keyword"].Type != "text" || record["keyword"].Value != "关键词" {
		t.Fatal("source lost", record)
	}
}
