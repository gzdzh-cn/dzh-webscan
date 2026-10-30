package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManualHistoryPinsAutomaticRetentionAndPublicEligibility(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{"retention":{"sqlite_events_days":10,"security_events_days":10}}'`)
	oldEvent(t, s, "ordinary", false, 20, nil)
	oldEvent(t, s, "security", true, 20, nil)
	oldEvent(t, s, "unselected", false, 20, nil)
	oldEvent(t, s, "recent", false, 0, nil)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_imported_events(migration_source,node,id,event_id,digest,received_at,operation,security,payload) VALUES(repeat('a',64),'node-a','imported','legacy','fixture',clock_timestamp()-interval '20 days','write',false,'{}'),(repeat('a',64),'node-a','imported-security','legacy-security','fixture',clock_timestamp()-interval '20 days','scan',true,'{}')`)
	records := []string{eventRecordKey("events", "node-a", "ordinary"), eventRecordKey("events", "node-a", "security"), eventRecordKey("migrated_events", "node-a", "imported"), eventRecordKey("migrated_events", "node-a", "imported-security")}
	p := historyPreview(t, s, HistoryScope{Categories: []string{"events", "security-events"}, Records: records})
	if p.Eligible != 4 {
		t.Fatal(p)
	}
	j := historyJob(t, s, p, "cleanup", false)
	events, err := s.Events(ctx, EventFilter{Since: time.Now().Add(-25 * 24 * time.Hour), Until: time.Now().Add(time.Hour), Limit: 20})
	if err != nil || len(events) != 6 {
		t.Fatal(events, err)
	}
	for _, v := range events {
		if v.ID == "unselected" {
			if !v.CanDelete {
				t.Fatal("eligible event disabled", v)
			}
			continue
		}
		if v.CanDelete || v.DeleteReason == "" {
			t.Fatal("job pin missing in unified list", v)
		}
	}
	l, auto := retentionFixture(t, s)
	auto = finishRetention(t, s, l, auto)
	if auto.Deleted != 1 || auto.Protected != 4 || tableCount(t, s, "v3_events") != 3 || tableCount(t, s, "v3_imported_events") != 2 {
		t.Fatal("automatic cleanup ignored fixed job scope", auto)
	}
	j = finishHistory(t, s, l, j)
	if j.Deleted != 4 || j.Skipped != 0 || tableCount(t, s, "v3_events") != 1 || tableCount(t, s, "v3_imported_events") != 0 {
		t.Fatal("manual worker could not release own pins", j)
	}
}

func TestManualHistoryNodeCategoryAndHealthProtection(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.PutNode(ctx, nodeFixture("node-a"), 0, 256); err != nil {
		t.Fatal(err)
	}
	if err := s.PutNode(ctx, nodeFixture("node-b"), 0, 256); err != nil {
		t.Fatal(err)
	}
	oldEvent(t, s, "a-event", false, 20, nil)
	oldEvent(t, s, "a-security", true, 20, nil)
	oldEvent(t, s, "b-event", false, 20, nil)
	mustHistoryExec(t, s.DB, `UPDATE v3_events SET node='node-b' WHERE id='b-event'`)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_health_events(id,node,kind,phase,time,message,payload) VALUES('old-health','node-a','memory','resolved',extract(epoch FROM clock_timestamp()-interval '20 days'),'old','{}'),('active-health','node-a','cpu','firing',extract(epoch FROM clock_timestamp()-interval '14 days'),'active','{}');INSERT INTO v3_health_rules VALUES('node-a:cpu','node-a','cpu','firing',extract(epoch FROM clock_timestamp()-interval '15 days'),0,0,0,'{}')`)
	list, err := s.HealthHistory(ctx, "node-a", "", time.Now().Add(-25*24*time.Hour), time.Now(), healthCursor{}, 20)
	if err != nil || len(list) != 2 {
		t.Fatal(list, err)
	}
	for _, v := range list {
		if v.CanDelete != (v.ID == "old-health") {
			t.Fatal("health protection mismatch", v)
		}
	}
	p := historyPreview(t, s, HistoryScope{Categories: []string{"events", "server-alerts"}, Node: "node-a", Before: time.Now().Add(-10 * 24 * time.Hour)})
	if p.Eligible != 2 || p.Protected != 1 {
		t.Fatal(p)
	}
	j := finishHistory(t, s, historyLease(t, s), historyJob(t, s, p, "cleanup", false))
	if j.Deleted != 2 || j.Skipped != 1 || tableCount(t, s, "v3_events") != 2 || tableCount(t, s, "v3_health_events") != 1 {
		t.Fatal(j)
	}
	site := savedSite(t, s, "node-filtered-incident")
	mustHistoryExec(t, s.DB, "UPDATE v3_websites SET node='node-a' WHERE id=$1", site.ID)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_website_incidents(site,kind,started,ended,reason) VALUES($1,'outage',extract(epoch FROM clock_timestamp()-interval '25 days'),extract(epoch FROM clock_timestamp()-interval '20 days'),'old')`, site.ID)
	incidents, err := s.SiteIncidents(ctx, site.ID, 0, 20)
	if err != nil || len(incidents) != 1 || !incidents[0].CanDelete {
		t.Fatal(incidents, err)
	}
	p = historyPreview(t, s, HistoryScope{Categories: []string{"website-incidents"}, Node: "node-b", Before: time.Now().Add(-10 * 24 * time.Hour)})
	if p.Eligible != 0 || p.Protected != 0 {
		t.Fatal("node filter ignored", p)
	}
	p = historyPreview(t, s, HistoryScope{Categories: []string{"website-incidents"}, Node: "node-a", Before: time.Now().Add(-10 * 24 * time.Hour)})
	if p.Eligible != 1 {
		t.Fatal(p)
	}
}

func TestManualHistoryNativeDeletionRemovesDuplicateDisplayRecords(t *testing.T) {
	s := testStore(t)
	oldEvent(t, s, "native", false, 40, nil)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_imported_events(migration_source,node,id,event_id,digest,received_at,operation,security,payload) SELECT repeat('a',64),'node-a','import-'||g,'native','fixture',clock_timestamp()-interval '40 days','write',false,'{}' FROM generate_series(1,1203)g`)
	p := historyPreview(t, s, HistoryScope{Categories: []string{"events"}, Records: []string{eventRecordKey("events", "node-a", "native")}})
	if p.Eligible != 1 {
		t.Fatal(p)
	}
	j := finishHistory(t, s, historyLease(t, s), historyJob(t, s, p, "cleanup", false))
	if j.Deleted != 1 || j.Scanned != 1 || j.DependentDeleted != 1203 || tableCount(t, s, "v3_imported_events") != 0 || tableCount(t, s, "v3_event_keys") != 1 {
		t.Fatal(j)
	}
}

func TestManualHistorySchema11BackupGateAndDisasterRestore(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	historyAPISession(t, s, "admin", "admin")
	savedSite(t, s, "preserved")
	oldEvent(t, s, "preserved-history", false, 40, nil)
	dropManualHistoryForTest(t, s)
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema10 upgraded without backup")
	}
	insecure := filepath.Join(privateTestDir(t), "insecure")
	if err := os.Mkdir(insecure, 0755); err != nil {
		t.Fatal(err)
	}
	if err := s.Upgrade(ctx, insecure); err == nil {
		t.Fatal("upgraded despite failed backup")
	}
	version, err := currentSchema(ctx, s.DB)
	if err != nil || version != 10 {
		t.Fatal(version, err)
	}
	directory := privateTestDir(t)
	if err = s.Upgrade(ctx, directory); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	path := filepath.Join(directory, entries[0].Name())
	header, err := inspectPGBackup(path)
	if err != nil || header.Version != 10 {
		t.Fatal(header, err)
	}
	old := emptyTestStore(t)
	if err = old.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	if v, err := currentSchema(ctx, old.DB); err != nil || v != 10 {
		t.Fatal(v, err)
	}
	if tableCount(t, old, "v3_events") != 1 || tableCount(t, old, "v3_sessions") != 1 {
		t.Fatal("schema10 backup lost data")
	}
	s.ExportDirectory = privateTestDir(t)
	l := historyLease(t, s)
	j := finishHistory(t, s, l, historyJob(t, s, historyPreview(t, s, HistoryScope{Categories: []string{"events"}}), "export", false))
	pending := historyJob(t, s, historyPreview(t, s, HistoryScope{Categories: []string{"events"}}), "cleanup", true)
	path, err = s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"v3_accounts", "v3_sessions", "v3_websites", "v3_events", "v3_event_keys", "v3_history_jobs", "v3_audit"} {
		if tableCount(t, s, table) != tableCount(t, restored, table) {
			t.Fatal("restore lost history", table)
		}
	}
	resumed, err := restored.HistoryJob(ctx, "admin", pending.ID)
	if err != nil || resumed.Status != "cancelled" || resumed.Deleted != 0 || resumed.ExportReady {
		t.Fatal("destructive task restored as authorized", resumed, err)
	}
	exported, err := restored.HistoryJob(ctx, "admin", j.ID)
	var ready int
	if e := restored.DB.QueryRow("SELECT count(*) FROM v3_history_export_parts WHERE ready OR sha256 <> '' OR bytes <> 0").Scan(&ready); e != nil {
		t.Fatal(e)
	}
	if err != nil || exported.ExportReady || ready != 0 {
		t.Fatal("external file evidence survived DB restore", err)
	}
	var valid int
	if err = restored.DB.QueryRow("SELECT count(*) FROM v3_history_previews WHERE NOT used OR expires_at>clock_timestamp()").Scan(&valid); err != nil || valid != 0 {
		t.Fatal("old preview revived", valid, err)
	}
	if v, err := currentSchema(ctx, restored.DB); err != nil || v != SchemaVersion {
		t.Fatal(v, err)
	}
}

func TestManualHistoryExportRejectsSymlinksAndInsecureFiles(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	parent := privateTestDir(t)
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	s.ExportDirectory = link
	if _, err := s.historyDirectory(); !errors.Is(err, ErrHistoryExport) {
		t.Fatal("symlink directory accepted", err)
	}
	s.ExportDirectory = target
	d, err := s.historyDirectory()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	part := historyPart{ID: token(), Ordinal: 1, Bytes: 3, SHA256: digest([]byte("{}\n"))}
	outside := filepath.Join(parent, "outside")
	if err = os.WriteFile(outside, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	partPath := filepath.Join(target, part.ID+".jsonl")
	if err = os.Symlink(outside, partPath); err != nil {
		t.Fatal(err)
	}
	if _, err = readHistoryPart(ctx, d, part); !errors.Is(err, ErrHistoryExport) {
		t.Fatal("symlink file accepted", err)
	}
	if err = os.Remove(partPath); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(partPath, []byte("{}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readHistoryPart(ctx, d, part); !errors.Is(err, ErrHistoryExport) {
		t.Fatal("public file accepted", err)
	}
	if err = os.Chmod(partPath, 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readHistoryPart(ctx, d, part); err != nil || string(raw) != "{}\n" {
		t.Fatal("valid private file rejected", err)
	}
	part.SHA256 = strings.Repeat("0", 64)
	if _, err = readHistoryPart(ctx, d, part); !errors.Is(err, ErrHistoryExport) {
		t.Fatal("bad checksum accepted", err)
	}
}

func TestManualHistoryBudgetLeavesAutomaticRetentionTime(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	oldEvent(t, s, "manual-slow", false, 40, nil)
	oldEvent(t, s, "auto-ready", false, 40, nil)
	p := historyPreview(t, s, HistoryScope{Categories: []string{"events"}, Records: []string{eventRecordKey("events", "node-a", "manual-slow")}})
	j := historyJob(t, s, p, "cleanup", false)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION slow_history_fixture() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_sleep(2);RETURN NEW;END$$;CREATE TRIGGER slow_history_fixture BEFORE UPDATE ON v3_history_jobs FOR EACH ROW EXECUTE FUNCTION slow_history_fixture()`)
	if err := s.RunRetentionRound(ctx, "fair-cleaner"); err != nil {
		t.Fatal(err)
	}
	var manual, automatic bool
	if err := s.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM v3_events WHERE id='manual-slow'),EXISTS(SELECT 1 FROM v3_events WHERE id='auto-ready')").Scan(&manual, &automatic); err != nil || !manual || automatic {
		t.Fatal("manual export starved automatic cleanup or lost rollback", manual, automatic, err)
	}
	saved, err := s.HistoryJob(ctx, "admin", j.ID)
	if err != nil || saved.Status != "queued" || saved.Deleted != 0 {
		t.Fatal("budget yield marked failed or advanced progress", saved, err)
	}
}

func TestManualHistoryExpiredExportCannotAuthorizeCleanup(t *testing.T) {
	s := testStore(t)
	s.ExportDirectory = privateTestDir(t)
	oldEvent(t, s, "expires-before-delete", false, 2, nil)
	p := historyPreview(t, s, HistoryScope{Categories: []string{"events"}, Records: []string{eventRecordKey("events", "node-a", "expires-before-delete")}})
	j := historyJob(t, s, p, "cleanup", true)
	l := historyLease(t, s)
	for j.Phase == "export" {
		var err error
		j, err = s.HistoryBatch(context.Background(), l, j.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	mustHistoryExec(t, s.DB, "UPDATE v3_history_jobs SET export_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", j.ID)
	if _, err := s.HistoryBatch(context.Background(), l, j.ID); !errors.Is(err, ErrHistoryExport) {
		t.Fatal("expired export authorized deletion", err)
	}
	if tableCount(t, s, "v3_events") != 1 {
		t.Fatal("deleted without valid export")
	}
}

func TestManualHistoryLowDiskStopsExportBeforeDeletion(t *testing.T) {
	directory := os.Getenv("WEBSCAN_V3_TEST_EXPORT_DISK_LOW")
	if directory == "" {
		t.Skip("requires isolated Linux container with a private tmpfs smaller than the export reserve")
	}
	s := testStore(t)
	s.ExportDirectory = directory
	oldEvent(t, s, "low-disk", false, 2, nil)
	p := historyPreview(t, s, HistoryScope{Categories: []string{"events"}, Records: []string{eventRecordKey("events", "node-a", "low-disk")}})
	j := historyJob(t, s, p, "cleanup", true)
	if err := s.RunRetentionRound(context.Background(), "low-disk-cleaner"); !errors.Is(err, ErrHistoryExport) {
		t.Fatal("low disk not rejected", err)
	}
	saved, err := s.HistoryJob(context.Background(), "admin", j.ID)
	if err != nil || saved.Status != "failed" || saved.Exported != 0 || saved.Deleted != 0 || tableCount(t, s, "v3_events") != 1 {
		t.Fatal("export failure lost source", saved, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed export left untracked bytes", entries, err)
	}
}
