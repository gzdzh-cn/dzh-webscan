package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
	"webscan/internal/website"
)

func websiteBackupID(t *testing.T, raw json.RawMessage, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &b) != nil || !validArchiveSource(b.ID) {
		t.Fatal("invalid backup identity")
	}
	return b.ID
}

func backupDocument(sites ...website.SiteConfig) website.BackupDocument {
	if sites == nil {
		sites = []website.SiteConfig{}
	}
	return website.BackupDocument{Format: 1, Created: time.Now().UTC().Format(time.RFC3339Nano), Sites: sites}
}

func canonicalBackupResponse(t *testing.T, raw []byte) string {
	t.Helper()
	v, err := common.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return string(common.JSON(v))
}

func TestWebsiteBackupStrictParsingAndLegacyFormat(t *testing.T) {
	doc := backupDocument(website.SiteConfig{Name: "site", URL: "https://example.test/", Slow: true})
	raw := common.JSON(doc)
	parsed, err := parseWebsiteBackup(raw, websiteBackupImportLimit)
	if err != nil || len(parsed.Sites) != 1 || parsed.Sites[0].URL != doc.Sites[0].URL {
		t.Fatal(parsed, err)
	}
	for _, bad := range []string{
		`{"format_version":1,"format_version":1,"created_at":"2026-10-18T00:00:00Z","websites":[]}`,
		strings.Replace(string(raw), `"name":"site"`, `"name":"site","name":"duplicate"`, 1),
		strings.Replace(string(raw), `"format_version":1`, `"format_version":2`, 1),
		strings.Replace(string(raw), `"name":"site"`, `"private_key":"private-backup-key"`, 1),
		strings.Replace(string(raw), `"name":"site"`, `"name":"site\u0000"`, 1),
		strings.Replace(string(raw), `"name":"site"`, `"name":"site","keyword":"bad\u0000"`, 1),
		strings.Replace(string(raw), `"name":"site"`, "\"name\":\"bad\xff\"", 1),
		string(raw) + " {}", "null", strings.Repeat("x", websiteBackupImportLimit+1),
	} {
		if _, err = parseWebsiteBackup([]byte(bad), websiteBackupImportLimit); err == nil || strings.Contains(err.Error(), "private-backup-key") {
			t.Fatal("invalid document accepted or leaked")
		}
	}
	doc.Sites = append(doc.Sites, doc.Sites[0])
	if _, err = parseWebsiteBackup(common.JSON(doc), websiteBackupImportLimit); err == nil {
		t.Fatal("duplicate normalized URL accepted")
	}
}

func TestWebsiteBackupSnapshotsIdempotencyAndProtectedDeletion(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_ = savedSite(t, s, "backup-one")
	_ = savedSite(t, s, "backup-two")
	raw, err := s.CreateWebsiteBackup(ctx, "admin", "snapshot-one")
	id := websiteBackupID(t, raw, err)
	again, err := s.CreateWebsiteBackup(ctx, "admin", "snapshot-one")
	if err != nil || canonicalBackupResponse(t, again) != canonicalBackupResponse(t, raw) || tableCount(t, s, "v3_website_backups") != 1 {
		t.Fatal("repeat duplicated snapshot", err)
	}
	doc, err := s.ExportWebsiteBackup(ctx, id)
	if err != nil || len(doc.Sites) != 2 || doc.Format != 1 {
		t.Fatal(doc, err)
	}
	raw, err = s.ImportWebsiteBackup(ctx, "admin", "import-one", common.JSON(doc))
	other := websiteBackupID(t, raw, err)
	if tableCount(t, s, "v3_websites") != 2 {
		t.Fatal("import applied configuration")
	}
	p, err := s.PreviewWebsiteBackup(ctx, "admin", id)
	if err != nil || p.Unchanged != 2 || p.Token == "" {
		t.Fatal(p, err)
	}
	list, err := s.WebsiteBackups(ctx, retentionCursor{}, 1)
	if err != nil || len(list) != 1 || list[0].ID != other || !list[0].CanDelete {
		t.Fatal(list, err)
	}
	list, err = s.WebsiteBackups(ctx, retentionCursor{list[0].Created, list[0].ID}, 1)
	if err != nil || len(list) != 1 || list[0].ID != id || list[0].CanDelete || list[0].DeleteReason == "" {
		t.Fatal(list, err)
	}
	result, err := s.DeleteWebsiteBackups(ctx, "admin", "delete-selected", []string{id, other})
	var deleted struct {
		Deleted int                 `json:"deleted"`
		Skipped []map[string]string `json:"skipped"`
	}
	if err != nil || json.Unmarshal(result, &deleted) != nil || deleted.Deleted != 1 || len(deleted.Skipped) != 1 || deleted.Skipped[0]["id"] != id || deleted.Skipped[0]["reason"] == "" {
		t.Fatal("partial deletion claimed all success", err)
	}
	if tableCount(t, s, "v3_websites") != 2 || tableCount(t, s, "v3_website_backups") != 1 {
		t.Fatal("deleting a backup changed active websites")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_website_backup_previews SET expires_at=clock_timestamp()-interval '1 second'`)
	if _, err = s.DeleteWebsiteBackups(ctx, "admin", "delete-expired", []string{id}); err != nil || tableCount(t, s, "v3_website_backups") != 0 {
		t.Fatal(err)
	}
}

func TestWebsiteBackupMergeRetainsIdentityHistoryAndRejectsStaleResult(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	old := savedSite(t, s, "backup-restore")
	job := claimSite(t, s, old.ID, "old-check")
	mustHistoryExec(t, s.DB, `INSERT INTO v3_website_incidents(id,site,kind,started,reason) VALUES(100,$1,'outage',floor(extract(epoch FROM clock_timestamp()))::bigint-100,'existing outage')`, old.ID)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_website_outbox(site,node,kind,message,created) VALUES($1,'','failure','existing pending',floor(extract(epoch FROM clock_timestamp()))::bigint-30)`, old.ID)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_notifications(node,event_id,channel,payload) VALUES('','website:existing','feishu','{"source":"website","message":"existing pending"}')`)
	doc := backupDocument(website.SiteConfig{Name: "restored", URL: old.URL, Keyword: "changed", Paused: true, Node: "missing-node"}, website.SiteConfig{Name: "new", URL: "https://new-backup.example.test/"})
	raw, err := s.ImportWebsiteBackup(ctx, "admin", "restore-import", common.JSON(doc))
	id := websiteBackupID(t, raw, err)
	p, err := s.PreviewWebsiteBackup(ctx, "admin", id)
	if err != nil || p.Added != 1 || p.Updated != 1 || len(p.Unknown) != 1 || p.Unknown[0] != "missing-node" {
		t.Fatal(p, err)
	}
	if _, err = s.RestoreWebsiteBackup(ctx, "other-user", "wrong-owner", id, p.Token); !errors.Is(err, ErrBackupPreview) {
		t.Fatal("preview not bound to account", err)
	}
	result, err := s.RestoreWebsiteBackup(ctx, "admin", "restore-once", id, p.Token)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.RestoreWebsiteBackup(ctx, "admin", "restore-once", id, p.Token)
	if err != nil || canonicalBackupResponse(t, again) != canonicalBackupResponse(t, result) {
		t.Fatal("lost response applied twice", err)
	}
	current, err := s.Site(ctx, old.ID)
	if err != nil || current.Name != "restored" || current.Node != "" || !current.Paused || current.Version != old.Version+1 {
		t.Fatal(current, err)
	}
	if err = s.ApplySiteResult(ctx, job, website.Result{Time: time.Now().Unix()}); err == nil {
		t.Fatal("pre-restore check overwrote restored configuration")
	}
	if tableCount(t, s, "v3_notifications") != 1 || tableCount(t, s, "v3_website_outbox") != 1 || tableCount(t, s, "v3_website_incidents") != 1 || tableCount(t, s, "v3_websites") != 2 || tableCount(t, s, "v3_website_backups") != 2 {
		t.Fatal("restore lost identity, omitted prior backup, or sent a notice")
	}
	var info WebsiteBackupPreview
	if err = json.Unmarshal(result, &info); err != nil || !validArchiveSource(info.Before) {
		t.Fatal(info, err)
	}
	before, err := s.ExportWebsiteBackup(ctx, info.Before)
	if err != nil || len(before.Sites) != 1 || before.Sites[0].Name != old.Name {
		t.Fatal("pre-restore snapshot wrong", err)
	}
	// Soft-delete and restore the same URL: retain its original business ID.
	if _, err = s.DeleteSites(ctx, "admin", "delete-for-restore", []SiteVersion{{old.ID, current.Version}}); err != nil {
		t.Fatal(err)
	}
	p, err = s.PreviewWebsiteBackup(ctx, "admin", id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RestoreWebsiteBackup(ctx, "admin", "restore-deleted", id, p.Token); err != nil {
		t.Fatal(err)
	}
	if current, err = s.Site(ctx, old.ID); err != nil || current.Name != "restored" || tableCount(t, s, "v3_websites") != 2 {
		t.Fatal("soft-deleted URL was duplicated", current, err)
	}
}

func TestWebsiteBackupPreviewConfigVersionAndFailureAtomicity(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	old := savedSite(t, s, "backup-version")
	raw, err := s.CreateWebsiteBackup(ctx, "admin", "version-snapshot")
	id := websiteBackupID(t, raw, err)
	p, err := s.PreviewWebsiteBackup(ctx, "admin", id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveSite(ctx, "admin", "change-before-restore", SiteInput{ID: old.ID, Name: "changed", URL: old.URL}, old.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RestoreWebsiteBackup(ctx, "admin", "stale-preview", id, p.Token); !errors.Is(err, ErrBackupPreview) {
		t.Fatal("configuration change did not invalidate preview", err)
	}
	doc := backupDocument()
	for i := 0; i < 503; i++ {
		doc.Sites = append(doc.Sites, website.SiteConfig{Name: fmt.Sprintf("bulk-%d", i), URL: fmt.Sprintf("https://bulk-%d.example.test/", i)})
	}
	raw, err = s.ImportWebsiteBackup(ctx, "admin", "bulk-import", common.JSON(doc))
	id = websiteBackupID(t, raw, err)
	p, err = s.PreviewWebsiteBackup(ctx, "admin", id)
	if err != nil || p.Added != 503 {
		t.Fatal(p, err)
	}
	mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_backup_batch() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.name='bulk-501' THEN RAISE EXCEPTION 'private-backup-detail'; END IF;RETURN NEW;END$$; CREATE TRIGGER fail_backup_batch BEFORE INSERT ON v3_websites FOR EACH ROW EXECUTE FUNCTION fail_backup_batch()`)
	count := tableCount(t, s, "v3_website_backups")
	if _, err = s.RestoreWebsiteBackup(ctx, "admin", "bulk-restore", id, p.Token); err == nil || tableCount(t, s, "v3_websites") != 1 || tableCount(t, s, "v3_website_backups") != count {
		t.Fatal("failed second batch partially committed")
	}
	mustHistoryExec(t, s.DB, `DROP TRIGGER fail_backup_batch ON v3_websites;DROP FUNCTION fail_backup_batch()`)
	if _, err = s.RestoreWebsiteBackup(ctx, "admin", "bulk-restore", id, p.Token); err != nil || tableCount(t, s, "v3_websites") != 504 {
		t.Fatal("rolled back request could not retry", err)
	}
}

func TestWebsiteBackupSchema9UpgradeGateAndDisasterRestore(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_ = savedSite(t, s, "backup-disaster")
	dropManualHistoryForTest(t, s)
	mustHistoryExec(t, s.DB, `DROP TABLE v3_website_backup_previews;DROP TABLE v3_website_backups;DROP INDEX v3_websites_restore_url;DELETE FROM v3_schema WHERE version=10`)
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema 9 upgraded without backup")
	}
	dir := filepath.Join(t.TempDir(), "before-schema10")
	if err := s.Upgrade(ctx, dir); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	header, err := inspectPGBackup(files[0])
	if err != nil || header.Version != 9 {
		t.Fatal(header, err)
	}
	raw, err := s.CreateWebsiteBackup(ctx, "admin", "disaster-snapshot")
	id := websiteBackupID(t, raw, err)
	if _, err = s.PreviewWebsiteBackup(ctx, "admin", id); err != nil {
		t.Fatal(err)
	}
	backup, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, restored, "v3_website_backups") != 1 || tableCount(t, restored, "v3_website_backup_previews") != 0 || tableCount(t, restored, "v3_websites") != 1 {
		t.Fatal("disaster restore lost backups or revived preview authorizations")
	}
	if _, err = restored.ExportWebsiteBackup(ctx, id); err != nil {
		t.Fatal("restored document failed digest check", err)
	}
}

func TestWebsiteBackupAPIAuthCSRFAndFailures(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.Provision(ctx, "admin", "backup-api-password-123"); err != nil {
		t.Fatal(err)
	}
	const cookie = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mustHistoryExec(t, s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,'admin',1,'csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(cookie)))
	a := &API{Store: s}
	call := func(method, path, body, csrf string, auth bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "/api/v3/website-backups"+path, strings.NewReader(body))
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", "api-backup"+strings.ReplaceAll(path, "/", "-"))
		if auth {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: cookie})
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "", "", "", false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "", "{}", "", true); w.Code != 403 {
		t.Fatal(w.Code)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='viewer'`)
	if w := call("POST", "", "{}", "csrf", true); w.Code != 403 {
		t.Fatal(w.Code)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='admin'`)
	if w := call("POST", "/import", `{"private_key":"private-backup-credential"}`, "csrf", true); w.Code != 400 || strings.Contains(w.Body.String(), "private-backup-credential") {
		t.Fatal(w.Code, w.Body.String())
	}
	w := call("POST", "", "{}", "csrf", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	id := websiteBackupID(t, w.Body.Bytes(), nil)
	if w = call("GET", "/"+id+"/export", "", "", true); w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), ".json") {
		t.Fatal(w.Code)
	}
	if w = call("POST", "/"+id+"/preview", "{}", "csrf", true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = call("GET", "?limit=201", "", "", true); w.Code != 400 {
		t.Fatal(w.Code)
	}
	s.DB.Close()
	if w = call("GET", "", "", "", true); w.Code != 503 {
		t.Fatal("database failure masqueraded as logout", w.Code)
	}
}

func TestWebsiteBackupLargeSnapshotDisasterRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	mustHistoryExec(t, s.DB, `INSERT INTO v3_websites(name,url) SELECT 'large-'||i,'https://large-'||i||'.example.test/'||repeat('a',1800) FROM generate_series(1,5000) i`)
	raw, err := s.CreateWebsiteBackup(ctx, "admin", "large-snapshot")
	id := websiteBackupID(t, raw, err)
	doc, err := s.ExportWebsiteBackup(ctx, id)
	if err != nil || len(doc.Sites) != 5000 || len(common.JSON(doc)) < 8<<20 {
		t.Fatal("large legal snapshot was truncated", len(doc.Sites), err)
	}
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal("database backup rejected legal snapshot", err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	doc, err = restored.ExportWebsiteBackup(ctx, id)
	if err != nil || len(doc.Sites) != 5000 || tableCount(t, restored, "v3_websites") != 5000 {
		t.Fatal("large restore lost configuration", err)
	}
}

func TestWebsiteBackupFrozenMigrationAndRegistryPreviewChanges(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	site := savedSite(t, s, "backup-registry")
	raw, err := s.CreateWebsiteBackup(ctx, "admin", "registry-snapshot")
	id := websiteBackupID(t, raw, err)
	p, err := s.PreviewWebsiteBackup(ctx, "admin", id)
	if err != nil {
		t.Fatal(err)
	}
	// Probe results do not modify configuration, so the preview stays valid.
	mustHistoryExec(t, s.DB, `UPDATE v3_websites SET state='{"status":"normal","checks":10}' WHERE id=$1`, site.ID)
	if _, err = s.RestoreWebsiteBackup(ctx, "admin", "probe-only-restore", id, p.Token); err != nil {
		t.Fatal("routine probe expired a configuration preview", err)
	}
	p, err = s.PreviewWebsiteBackup(ctx, "admin", id)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PutNode(ctx, nodeFixture("new-node"), 0, 256); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RestoreWebsiteBackup(ctx, "admin", "registry-stale", id, p.Token); !errors.Is(err, ErrBackupPreview) {
		t.Fatal("registry change did not expire preview", err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source) VALUES('settings',repeat('b',64))`)
	if _, err = s.CreateWebsiteBackup(ctx, "admin", "frozen-create"); !errors.Is(err, ErrMigrationPending) {
		t.Fatal(err)
	}
	if _, err = s.PreviewWebsiteBackup(ctx, "admin", id); !errors.Is(err, ErrMigrationPending) {
		t.Fatal(err)
	}
	if _, err = s.DeleteWebsiteBackups(ctx, "admin", "frozen-delete", []string{id}); !errors.Is(err, ErrMigrationPending) {
		t.Fatal(err)
	}
	items, err := s.WebsiteBackups(ctx, retentionCursor{}, 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range items {
		if b.CanDelete || b.DeleteReason == "" {
			t.Fatal("frozen backups advertised deletion")
		}
	}
}
