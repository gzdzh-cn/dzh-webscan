package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
)

func historyPreview(t *testing.T, s *Store, scope HistoryScope) HistoryPreview {
	t.Helper()
	p, err := s.PreviewHistory(context.Background(), "admin", scope)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func historyJob(t *testing.T, s *Store, p HistoryPreview, kind string, first bool) HistoryJob {
	t.Helper()
	raw, err := s.SubmitHistory(context.Background(), "admin", "history-"+token()[:24], p.Token, kind, first, !first)
	if err != nil {
		t.Fatal(err)
	}
	var j HistoryJob
	if json.Unmarshal(raw, &j) != nil || j.ID == "" {
		t.Fatal("missing job")
	}
	return j
}
func historyLease(t *testing.T, s *Store) Lease {
	t.Helper()
	l, err := s.Acquire(context.Background(), "retention", "manual-test-"+token()[:16])
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func finishHistory(t *testing.T, s *Store, l Lease, j HistoryJob) HistoryJob {
	t.Helper()
	var err error
	for i := 0; i < 150 && (j.Status == "queued" || j.Status == "running"); i++ {
		j, err = s.HistoryBatch(context.Background(), l, j.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if j.Status == "queued" || j.Status == "running" {
		t.Fatal("history job did not finish", j)
	}
	return j
}

func dropManualHistoryForTest(t *testing.T, s *Store) {
	t.Helper()
	dropConfigurationBackupsForTest(t, s)
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_deployment_previews;DROP INDEX v3_deployment_node_history;DROP TABLE v3_node_certificates;DROP TABLE v3_pki_authorities;DROP TABLE v3_history_export_parts;DROP TABLE v3_history_jobs;DROP TABLE v3_history_items;DROP TABLE v3_history_previews;DROP TABLE v3_history_gates;DELETE FROM v3_schema WHERE version>=11`)
}

func TestManualHistoryScopeValidationAndStableSelectors(t *testing.T) {
	now := time.Now()
	valid := HistoryScope{Categories: []string{"events"}}
	if _, err := valid.validate(now); err != nil || now.Sub(valid.Before) != 30*24*time.Hour {
		t.Fatal(valid, err)
	}
	key := eventRecordKey("events", "node-a", "id/原记录")
	scoped := HistoryScope{Categories: []string{"events"}, Records: []string{key}}
	if _, err := scoped.validate(now); err != nil || now.Sub(scoped.Before) != 24*time.Hour {
		t.Fatal(scoped, err)
	}
	for _, v := range []HistoryScope{
		{}, {Categories: []string{"metrics"}}, {Categories: []string{"audit"}}, {Categories: []string{"events", "events"}},
		{Categories: []string{"events"}, Before: now.Add(-time.Hour)},
		{Categories: []string{"events"}, Records: []string{key, key}},
		{Categories: []string{"events"}, Records: []string{"event:bad"}},
		{Categories: []string{"events"}, Records: []string{"notification:-1"}},
		{Categories: []string{"events"}, Records: []string{"website-incident:01"}},
		{Categories: []string{"events"}, Records: []string{"server-health:"}},
		{Categories: []string{"events"}, Records: make([]string, 201)},
		{Categories: []string{"events"}, Records: []string{}},
	} {
		if _, err := v.validate(now); err == nil {
			t.Fatal("unsafe scope accepted", v)
		}
	}
	for _, k := range []string{key, "server-health:old/告警", "website-incident:12", "notification:98"} {
		if _, err := historySelectorFor(k); err != nil {
			t.Fatal(k, err)
		}
	}
}

func TestManualHistoryPreviewFixesScopeAndProtectsNewMatches(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	oldEvent(t, s, "selected", false, 40, nil)
	oldEvent(t, s, "scan-running", false, 40, common.Map{"scan": common.Map{"status": "running"}})
	oldEvent(t, s, "security", true, 40, nil)
	oldEvent(t, s, "recent", false, 0, nil)
	oldEvent(t, s, "probe", false, 40, nil)
	mustHistoryExec(t, s.DB, "UPDATE v3_events SET operation='probe' WHERE id='probe'")
	p := historyPreview(t, s, HistoryScope{Categories: []string{"events"}})
	if p.Eligible != 1 || p.Protected != 1 || p.Version != 1 || p.Token == "" {
		t.Fatal(p)
	}
	oldEvent(t, s, "added-after-preview", false, 40, nil)
	if _, err := s.SubmitHistory(ctx, "another-user", "wrong-owner", p.Token, "cleanup", false, true); !errors.Is(err, ErrHistoryPreview) {
		t.Fatal("preview owner not bound", err)
	}
	if _, err := s.SubmitHistory(ctx, "admin", "no-confirm", p.Token, "cleanup", false, false); !errors.Is(err, ErrHistoryInput) {
		t.Fatal("unconfirmed deletion allowed", err)
	}
	raw, err := s.SubmitHistory(ctx, "admin", "fixed-scope", p.Token, "cleanup", false, true)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := s.SubmitHistory(ctx, "admin", "fixed-scope", p.Token, "cleanup", false, true)
	if err != nil || canonicalBackupResponse(t, raw) != canonicalBackupResponse(t, repeated) {
		t.Fatal("repeat created another job", err)
	}
	var j HistoryJob
	_ = json.Unmarshal(raw, &j)
	l := historyLease(t, s)
	j = finishHistory(t, s, l, j)
	if j.Deleted != 1 || j.Skipped != 1 || j.Status != "partial" || tableCount(t, s, "v3_events") != 5 || tableCount(t, s, "v3_event_keys") != 6 {
		t.Fatal(j)
	}
	var leak bool
	if err = s.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM v3_audit WHERE result::text LIKE $1 UNION ALL SELECT 1 FROM v3_requests WHERE response::text LIKE $1)", "%"+p.Token+"%").Scan(&leak); err != nil || leak {
		t.Fatal("preview token leaked", err)
	}
	p = historyPreview(t, s, HistoryScope{Categories: []string{"events"}, IncludeProbes: true, Records: []string{eventRecordKey("events", "node-a", "probe"), eventRecordKey("events", "node-a", "recent")}})
	if p.Eligible != 1 || p.Protected != 1 {
		t.Fatal(p)
	}
	j = finishHistory(t, s, l, historyJob(t, s, p, "cleanup", false))
	if j.Deleted != 1 || j.Skipped != 1 {
		t.Fatal(j)
	}
}

func TestManualHistoryRechecksProtectionAndConfiguration(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	oldEvent(t, s, "protected-late", false, 40, nil)
	p := historyPreview(t, s, HistoryScope{Categories: []string{"events"}})
	j := historyJob(t, s, p, "cleanup", false)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_notifications(node,event_id,channel,payload) VALUES('node-a','protected-late','feishu','{}')`)
	l := historyLease(t, s)
	j = finishHistory(t, s, l, j)
	if j.Deleted != 0 || j.Skipped != 1 || tableCount(t, s, "v3_notifications") != 1 {
		t.Fatal(j)
	}
	p = historyPreview(t, s, HistoryScope{Categories: []string{"events"}})
	mustHistoryExec(t, s.DB, "UPDATE v3_settings SET version=version+1")
	if _, err := s.SubmitHistory(ctx, "admin", "stale-preview", p.Token, "cleanup", false, true); !errors.Is(err, ErrHistoryPreview) {
		t.Fatal(err)
	}
	p = historyPreview(t, s, HistoryScope{Categories: []string{"events"}})
	j = historyJob(t, s, p, "cleanup", false)
	mustHistoryExec(t, s.DB, "UPDATE v3_settings SET version=version+1")
	j = finishHistory(t, s, l, j)
	if j.Status != "cancelled" || j.Deleted != 0 {
		t.Fatal(j)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source) VALUES('fixture',repeat('a',64))`)
	if _, err := s.PreviewHistory(ctx, "admin", HistoryScope{Categories: []string{"events"}}); !errors.Is(err, ErrMigrationPending) {
		t.Fatal("migration preview allowed", err)
	}
}

func TestManualHistory500BatchFailureRestartAndSharedLease(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	mustHistoryExec(t, s.DB, `INSERT INTO v3_event_keys SELECT 'node-a',g::text,'fixture',clock_timestamp()-interval '40 days' FROM generate_series(1,503) g; INSERT INTO v3_events SELECT node,id,received_at,'write',false,'{}' FROM v3_event_keys`)
	p := historyPreview(t, s, HistoryScope{Categories: []string{"events"}})
	j := historyJob(t, s, p, "cleanup", false)
	l := historyLease(t, s)
	j, err := s.HistoryBatch(ctx, l, j.ID)
	if err != nil || j.Deleted != 500 || j.Scanned != 500 || tableCount(t, s, "v3_events") != 3 {
		t.Fatal(j, err)
	}
	if err = s.RunRetentionRound(ctx, "other-worker"); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("automatic cleanup overlapped manual lease", err)
	}
	mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_history_fixture() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'PRIVATE_fixture'; END$$;CREATE TRIGGER fail_history_fixture BEFORE DELETE ON v3_events FOR EACH ROW EXECUTE FUNCTION fail_history_fixture()`)
	if _, err = s.HistoryBatch(ctx, l, j.ID); err == nil {
		t.Fatal("failure ignored")
	}
	saved, err := s.HistoryJob(ctx, "admin", j.ID)
	if err != nil || saved.Deleted != 500 || saved.Scanned != 500 {
		t.Fatal(saved, err)
	}
	mustHistoryExec(t, s.DB, `DROP TRIGGER fail_history_fixture ON v3_events`)
	if err = s.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
	next := historyLease(t, s)
	if _, err = s.HistoryBatch(ctx, l, j.ID); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("old cleaner survived takeover", err)
	}
	other := &Store{DB: s.DB}
	j = finishHistory(t, other, next, saved)
	if j.Deleted != 503 || j.Scanned != 503 || tableCount(t, s, "v3_events") != 0 || tableCount(t, s, "v3_event_keys") != 503 {
		t.Fatal(j)
	}
}

func TestManualHistoryNotificationDependenciesAndOriginalEventSurvival(t *testing.T) {
	s := testStore(t)
	oldEvent(t, s, "original", false, 40, nil)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_notifications(node,event_id,channel,payload,created_at,done_at) VALUES('node-a','original','email','{"smtp_password":"PRIVATE-password"}',clock_timestamp()-interval '40 days',clock_timestamp()-interval '40 days'); INSERT INTO v3_notification_attempts(notification,epoch,success,result) SELECT id,g,true,'PRIVATE-attempt' FROM v3_notifications CROSS JOIN generate_series(1,1203)g`)
	p := historyPreview(t, s, HistoryScope{Categories: []string{"email"}})
	if p.Eligible != 1 {
		t.Fatal(p)
	}
	j := historyJob(t, s, p, "cleanup", false)
	l := historyLease(t, s)
	j = finishHistory(t, s, l, j)
	if j.Deleted != 1 || j.Scanned != 1 || j.DependentDeleted != 1203 || tableCount(t, s, "v3_notification_attempts") != 0 || tableCount(t, s, "v3_events") != 1 {
		t.Fatal(j)
	}
}

func TestManualHistoryExportFirstVerifiesFilesAndPreventsUnbackedDeletion(t *testing.T) {
	s := testStore(t)
	s.ExportDirectory = privateTestDir(t)
	ctx := context.Background()
	oldEvent(t, s, "export-protected", false, 40, nil)
	p := historyPreview(t, s, HistoryScope{Categories: []string{"events"}})
	j := historyJob(t, s, p, "cleanup", true)
	l := historyLease(t, s)
	var err error
	for j.Phase == "export" {
		j, err = s.HistoryBatch(ctx, l, j.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !j.ExportReady || j.Exported != 1 || j.Deleted != 0 || j.ExportExpires == nil {
		t.Fatal(j)
	}
	var part string
	if err = s.DB.QueryRow("SELECT id FROM v3_history_export_parts WHERE job=$1 AND ready", j.ID).Scan(&part); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(s.ExportDirectory, part+".jsonl"), []byte("corrupted export"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.HistoryBatch(ctx, l, j.ID); !errors.Is(err, ErrHistoryExport) {
		t.Fatal("corrupt export accepted", err)
	}
	if tableCount(t, s, "v3_events") != 1 {
		t.Fatal("deleted after export became unreadable")
	}
	_ = s.Release(ctx, l)
	if err = s.RunRetentionRound(ctx, "file-error-worker"); !errors.Is(err, ErrHistoryExport) {
		t.Fatal(err)
	}
	j, err = s.HistoryJob(ctx, "admin", j.ID)
	if err != nil || j.Status != "failed" || j.Deleted != 0 {
		t.Fatal(j, err)
	}
}

func TestManualHistoryExportFileIntentFailureResumeAndExpiry(t *testing.T) {
	s := testStore(t)
	s.ExportDirectory = privateTestDir(t)
	ctx := context.Background()
	oldEvent(t, s, "export-resume", false, 40, nil)
	p := historyPreview(t, s, HistoryScope{Categories: []string{"events"}})
	j := historyJob(t, s, p, "export", false)
	l := historyLease(t, s)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_export_fixture() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'PRIVATE-export'; END$$;CREATE TRIGGER fail_export_fixture BEFORE UPDATE ON v3_history_jobs FOR EACH ROW EXECUTE FUNCTION fail_export_fixture()`)
	if _, err := s.HistoryBatch(ctx, l, j.ID); err == nil {
		t.Fatal("file/db interruption ignored")
	}
	if tableCount(t, s, "v3_history_export_parts") != 1 {
		t.Fatal("file intent was lost")
	}
	var orphan string
	_ = s.DB.QueryRow("SELECT id FROM v3_history_export_parts WHERE NOT ready").Scan(&orphan)
	if st, err := os.Stat(filepath.Join(s.ExportDirectory, orphan+".jsonl")); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("private file intent missing", err)
	}
	mustHistoryExec(t, s.DB, `DROP TRIGGER fail_export_fixture ON v3_history_jobs`)
	j = finishHistory(t, s, l, j)
	if j.Exported != 1 || !j.ExportReady || j.Status != "succeeded" || tableCount(t, s, "v3_events") != 1 {
		t.Fatal(j)
	}
	mustHistoryExec(t, s.DB, "UPDATE v3_history_export_parts SET created_at=clock_timestamp()-interval '2 days' WHERE NOT ready")
	if err := s.HistoryGC(ctx, l); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.ExportDirectory, orphan+".jsonl")); !os.IsNotExist(err) || tableCount(t, s, "v3_history_export_parts") != 1 {
		t.Fatal("orphan expiry failed", err)
	}
	mustHistoryExec(t, s.DB, "UPDATE v3_history_jobs SET export_expires_at=clock_timestamp()-interval '1 second',finished_at=clock_timestamp()-interval '2 days'")
	if err := s.HistoryGC(ctx, l); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_history_export_parts") != 0 || tableCount(t, s, "v3_history_items") != 0 {
		t.Fatal("expired export or fixed selection not reclaimed")
	}
	entries, err := os.ReadDir(s.ExportDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatal("expired files retained", err)
	}
}

func TestManualHistoryExportUsesPublicFieldsAndRecordIDs(t *testing.T) {
	s := testStore(t)
	s.ExportDirectory = privateTestDir(t)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_notifications(node,event_id,channel,recipient,payload,result,created_at,done_at) VALUES('node-a','notice','email','a@example.test','{"smtp_password":"PRIVATE"}','PRIVATE SMTP response',clock_timestamp()-interval '40 days',clock_timestamp()-interval '40 days')`)
	p := historyPreview(t, s, HistoryScope{Categories: []string{"email"}})
	j := finishHistory(t, s, historyLease(t, s), historyJob(t, s, p, "export", false))
	var part historyPart
	if err := s.DB.QueryRow("SELECT id,ordinal,bytes,sha256 FROM v3_history_export_parts WHERE job=$1 AND ready", j.ID).Scan(&part.ID, &part.Ordinal, &part.Bytes, &part.SHA256); err != nil {
		t.Fatal(err)
	}
	d, err := s.historyDirectory()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	raw, err := readHistoryPart(context.Background(), d, part)
	if err != nil || strings.Contains(string(raw), "PRIVATE") || !strings.Contains(string(raw), "notification:") || !strings.Contains(string(raw), "a@example.test") {
		t.Fatal("export lost public identity or leaked internals", err)
	}
}

func TestManualHistoryServerWebsiteAndMigratedEventProtection(t *testing.T) {
	s := testStore(t)
	site := savedSite(t, s, "manual-incident")
	mustHistoryExec(t, s.DB, `INSERT INTO v3_website_incidents(id,site,kind,started,ended,reason) VALUES(1,$1,'outage',extract(epoch FROM clock_timestamp()-interval '45 days'),extract(epoch FROM clock_timestamp()-interval '40 days'),'old'),(2,$1,'outage',extract(epoch FROM clock_timestamp()-interval '40 days'),NULL,'current')`, site.ID)
	p := historyPreview(t, s, HistoryScope{Categories: []string{"website-incidents"}})
	if p.Eligible != 1 || p.Protected != 1 {
		t.Fatal(p)
	}
	l := historyLease(t, s)
	j := finishHistory(t, s, l, historyJob(t, s, p, "cleanup", false))
	if j.Deleted != 1 || j.Skipped != 1 || tableCount(t, s, "v3_websites") != 1 {
		t.Fatal(j)
	}
	// A migrated observation must leave a replay tombstone, not an Agent ack.
	mustHistoryExec(t, s.DB, `INSERT INTO v3_imported_events(migration_source,node,id,event_id,digest,received_at,operation,security,payload) VALUES(repeat('a',64),'node-a','imported','legacy-event','fixture',clock_timestamp()-interval '40 days','write',false,'{}')`)
	p = historyPreview(t, s, HistoryScope{Categories: []string{"events"}})
	j = finishHistory(t, s, l, historyJob(t, s, p, "cleanup", false))
	if j.Deleted != 1 || tableCount(t, s, "v3_event_history_tombstones") != 1 || tableCount(t, s, "v3_event_keys") != 0 {
		t.Fatal(j)
	}
}
