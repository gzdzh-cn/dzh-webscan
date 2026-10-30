package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/recordops"
)

func operationAuditFixture(t *testing.T, count int) (string, *sql.DB) {
	t.Helper()
	path := filepath.Join(privateTestDir(t), "legacy-audit.sqlite3")
	db, err := persist.OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mustHistoryExec(t, db, recordops.Schema+`CREATE TABLE retention_jobs(id TEXT PRIMARY KEY,owner TEXT,kind TEXT,created INTEGER,updated INTEGER,status TEXT,scope TEXT,processed INTEGER,skipped INTEGER,message TEXT,preview TEXT,export_job TEXT);`)
	now := time.Now().Unix() - 2*86400
	for i := 1; i <= count; i++ {
		id := fmt.Sprintf("%032x", i)
		results := common.JSON([]recordops.Result{{ID: "12", Status: "deleted", Reason: "PRIVATE original provider/path detail"}})
		mustHistoryExec(t, db, `INSERT INTO record_operations(id,owner,kind,request_key,created,updated,status,ids,cursor,results) VALUES(?,'admin','website',?,?,?,'complete','["12"]',1,?)`, id, "PRIVATE-request-"+id, now-60, now, string(results))
	}
	mustHistoryExec(t, db, `INSERT INTO retention_jobs VALUES('old-cleanup','admin','cleanup',?,?,'complete','[{"source":"events","node":"node-a","before":100,"upper":9007199254740993}]',12,3,'PRIVATE error','PRIVATE-preview','PRIVATE-export')`, now-60, now)
	return path, db
}
func archiveOperationAudit(t *testing.T, s *Store, path string) string {
	t.Helper()
	report, err := s.ArchiveSQLite(context.Background(), path, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	return report.Source
}

func TestOperationAuditMigrationPreservesIdentityCountsAndNeverReauthorizes(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	path, _ := operationAuditFixture(t, 2)
	source := archiveOperationAudit(t, s, path)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_audit(username,kind,resource,result) VALUES('admin','existing','original','{}')`)
	report, err := s.MapOperationAuditArchive(ctx, source)
	if err != nil || !report.Complete || report.Imported != 3 || report.ReadyForCutover {
		t.Fatal(report, err)
	}
	var count, private int
	if err = s.DB.QueryRow(`SELECT count(*),count(*) FILTER(WHERE result::text LIKE '%PRIVATE%') FROM v3_audit WHERE kind LIKE 'legacy-%'`).Scan(&count, &private); err != nil || count != 3 || private != 0 {
		t.Fatal("original identities or private-field filtering", count, private, err)
	}
	var result []byte
	if err = s.DB.QueryRow(`SELECT result FROM v3_audit WHERE kind='legacy-retention_jobs'`).Scan(&result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result), "9007199254740993") || !strings.Contains(string(result), `"processed": 12`) || !strings.Contains(string(result), `"download_available": false`) {
		t.Fatal(string(result))
	}
	rowsBefore := tableCount(t, s, "v3_audit")
	report, err = s.MapOperationAuditArchive(ctx, source)
	if err != nil || !report.Complete || report.Imported != 3 || tableCount(t, s, "v3_audit") != rowsBefore {
		t.Fatal("repeat duplicated audit", report, err)
	}
	if tableCount(t, s, "v3_history_jobs") != 0 || tableCount(t, s, "v3_history_previews") != 0 || tableCount(t, s, "v3_deployment_jobs") != 0 {
		t.Fatal("old authorization became a runnable task")
	}
	otherPath, _ := operationAuditFixture(t, 1)
	other := archiveOperationAudit(t, s, otherPath)
	report, err = s.MapOperationAuditArchive(ctx, other)
	if err != nil || !report.Complete || report.Imported != 2 {
		t.Fatal("second SQLite identity collided", report, err)
	}
	if err = s.DB.QueryRow(`SELECT count(DISTINCT resource) FROM v3_audit WHERE kind LIKE 'legacy-%'`).Scan(&count); err != nil || count != 5 {
		t.Fatal("source-bound identity lost", count, err)
	}
	archive, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, archive); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, target, "v3_audit") != tableCount(t, s, "v3_audit") || tableCount(t, target, "v3_migration_domains") != 2 {
		t.Fatal("restored audit lost original identity or migration freeze")
	}
}

func TestOperationAuditMigrationRefusesPendingBeforeBinding(t *testing.T) {
	for _, table := range []string{"record_operations", "retention_jobs"} {
		t.Run(table, func(t *testing.T) {
			s := testStore(t)
			path, db := operationAuditFixture(t, 1)
			mustHistoryExec(t, db, "UPDATE "+table+" SET status='running'")
			report, err := s.MapOperationAuditArchive(context.Background(), archiveOperationAudit(t, s, path))
			if err == nil || report.Complete || report.Imported != 0 || tableCount(t, s, "v3_migration_domains") != 0 || tableCount(t, s, "v3_audit") != 0 {
				t.Fatal("pending task was converted or bound", report, err)
			}
		})
	}
}

func TestOperationAuditMigrationPartialProgressResumeAndRemainingDigest(t *testing.T) {
	s := testStore(t)
	path, _ := operationAuditFixture(t, 503)
	ctx := context.Background()
	source := archiveOperationAudit(t, s, path)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_audit_fixture() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='legacy-record_operations' AND NEW.result->>'legacy_id'='000000000000000000000000000001f5' THEN RAISE EXCEPTION 'PRIVATE-audit-detail'; END IF;RETURN NEW;END$$;CREATE TRIGGER fail_audit_fixture BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION fail_audit_fixture()`)
	report, err := s.MapOperationAuditArchive(ctx, source)
	if err == nil || strings.Contains(err.Error(), "PRIVATE") || report.Complete || report.Imported != 500 {
		t.Fatal("batch failure lost committed progress or leaked details", report, err)
	}

	var original []byte
	if err = s.DB.QueryRow("SELECT payload FROM v3_legacy_records WHERE source=$1 AND table_name='record_operations' AND record_key='501'", source).Scan(&original); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_legacy_records SET payload=payload||'{"status":{"type":"text","value":"partial"}}'::jsonb WHERE source=$1 AND table_name='record_operations' AND record_key='501'`, source)
	report, err = s.MapOperationAuditArchive(ctx, source)
	if err == nil || report.Complete || report.Imported != 500 {
		t.Fatal("changed remaining batch accepted", report, err)
	}
	mustHistoryExec(t, s.DB, "UPDATE v3_legacy_records SET payload=$2 WHERE source=$1 AND table_name='record_operations' AND record_key='501'", source, original)
	mustHistoryExec(t, s.DB, "DROP TRIGGER fail_audit_fixture ON v3_audit")
	report, err = s.MapOperationAuditArchive(ctx, source)
	if err != nil || !report.Complete || report.Imported != 504 {
		t.Fatal(report, err)
	}
	var n int
	if err = s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind LIKE 'legacy-%'`).Scan(&n); err != nil || n != 504 {
		t.Fatal("resume duplicated records", n, err)
	}
}

func TestOperationAuditRejectsMalformedCompletionAndPreserves365DayPolicy(t *testing.T) {
	tests := []struct{ name, sql string }{
		{"null-time", "UPDATE record_operations SET updated=NULL"},
		{"unfinished-cursor", "UPDATE record_operations SET cursor=0"},
		{"mismatched-result", "UPDATE record_operations SET results='[{\"id\":\"13\",\"status\":\"deleted\"}]'"},
		{"incorrect-state", "UPDATE record_operations SET status='partial'"},
		{"invalid-scope", "UPDATE retention_jobs SET scope='[{\"source\":\"arbitrary-table\"}]'"},
		{"negative-count", "UPDATE retention_jobs SET skipped=-1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			path, db := operationAuditFixture(t, 1)
			mustHistoryExec(t, db, tc.sql)
			r, err := s.MapOperationAuditArchive(context.Background(), archiveOperationAudit(t, s, path))
			if err == nil || r.Complete {
				t.Fatal(r, err)
			}
		})
	}
	s := testStore(t)
	path, db := operationAuditFixture(t, 1)
	ctx := context.Background()
	old := time.Now().Add(-400 * 24 * time.Hour).Unix()
	mustHistoryExec(t, db, "UPDATE record_operations SET created=?,updated=?", old-60, old)
	source := archiveOperationAudit(t, s, path)
	if _, err := s.MapOperationAuditArchive(ctx, source); err != nil {
		t.Fatal(err)
	}
	if err := s.Housekeeping(ctx, "audit-cleaner"); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := s.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM v3_audit WHERE kind='legacy-record_operations')").Scan(&exists); err != nil || !exists {
		t.Fatal("migration audit pruned before cutover", err)
	}
	mustHistoryExec(t, s.DB, "UPDATE v3_migration_domains SET pending=false") // Isolated simulation only; not a cutover command.
	if err := s.Housekeeping(ctx, "audit-cleaner"); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM v3_audit WHERE kind='legacy-record_operations')").Scan(&exists); err != nil || exists {
		t.Fatal("original completion time was not retained", err)
	}
}
