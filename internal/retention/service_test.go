package retention_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"webscan/internal/central"
	"webscan/internal/common"
	"webscan/internal/notify"
	"webscan/internal/persist"
	"webscan/internal/retention"
	"webscan/internal/telemetry"
)

func fixture(t *testing.T) (*retention.Service, *sql.DB, *sql.DB, common.Map) {
	t.Helper()
	root := t.TempDir()
	db, e := persist.OpenDB(filepath.Join(root, "events-v1.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(central.Schema + notify.Schema + `CREATE TABLE websites(id INTEGER PRIMARY KEY,node TEXT);CREATE TABLE website_incidents(id INTEGER PRIMARY KEY,site INTEGER,kind TEXT,started INTEGER,ended INTEGER,reason TEXT);CREATE TABLE website_outbox(id INTEGER PRIMARY KEY,site INTEGER);`)
	if e != nil {
		t.Fatal(e)
	}
	m, e := telemetry.Open(root, nil, common.Map{"history_days": 15, "raw_hours": 48})
	if e != nil {
		t.Fatal(e)
	}
	c := common.Map{"data_dir": root, "backup_dir": filepath.Join(root, "backup"), "monitoring": common.Map{"history_days": 15}, "retention": common.Map{"sqlite_events_days": 30, "delivery_records_days": 30, "security_events_days": 90, "website_incidents_days": 30, "server_alerts_days": 15}}
	s, e := retention.New(db, m.DB, func() common.Map { return c })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close(); m.DB.Close() })
	return s, db, m.DB, c
}
func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, e := db.Exec(q, args...); e != nil {
		t.Fatal(e)
	}
}
func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if e := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func drive(t *testing.T, s *retention.Service, j *retention.Job) {
	t.Helper()
	for i := 0; i < 20; i++ {
		if e := s.Tick(context.Background()); e != nil {
			t.Fatal(e)
		}
		v, e := s.Job(context.Background(), j.Owner, j.ID)
		if e != nil {
			t.Fatal(e)
		}
		if v.Status == "complete" {
			return
		}
		if v.Status == "failed" {
			t.Fatal(v)
		}
	}
	t.Fatal("did not finish")
}
func TestAutomaticIndependentRetentionAndProtection(t *testing.T) {
	s, d, m, _ := fixture(t)
	now := time.Now().Unix()
	old := now - 45*86400
	mustExec(t, d, "INSERT INTO events VALUES('n','old','d',?,?)", `{"operation":"modify"}`, old)
	mustExec(t, d, "INSERT INTO events VALUES('n','security','d',?,?)", `{"operation":"scan","scan":{"status":"matched"}}`, old)
	mustExec(t, d, "INSERT INTO events VALUES('n','pending','d',?,?)", `{"operation":"modify"}`, old)
	mustExec(t, d, "INSERT INTO tasks(node,event_id,target,payload,created,next_try) VALUES('n','pending','email','{}',?,0)", old)
	mustExec(t, d, "INSERT INTO email_recipients(task_id,recipient,next_try) SELECT id,'a@example.com',0 FROM tasks")
	mustExec(t, d, "INSERT INTO websites VALUES(1,'n')")
	mustExec(t, d, "INSERT INTO website_incidents VALUES(1,1,'outage',?,NULL,'timeout')", old)
	mustExec(t, d, "INSERT INTO website_incidents VALUES(2,1,'outage',?,?,'timeout')", old, old+10)
	mustExec(t, m, "INSERT INTO health_events VALUES('old','n','cpu','resolved',?,'x','{}')", old)
	mustExec(t, m, "INSERT INTO health_events VALUES('current','n','cpu','firing',?,'x','{}')", old+100)
	mustExec(t, m, "INSERT INTO health_rules VALUES('r','n','cpu','firing',?,?,0,0,'{}')", old+50, now)
	if e := s.Tick(context.Background()); e != nil {
		t.Fatal(e)
	}
	if count(t, d, "events") != 2 || count(t, d, "tasks") != 1 || count(t, d, "email_recipients") != 1 || count(t, d, "website_incidents") != 1 || count(t, m, "health_events") != 1 {
		t.Fatal("protected data removed or expired data left")
	}
}
func TestManualExportOwnershipRevisionAndConfirmationPrerequisite(t *testing.T) {
	s, d, _, c := fixture(t)
	old := time.Now().Unix() - 40*86400
	mustExec(t, d, "INSERT INTO events VALUES('n','safe','d',?,?)", `{"operation":"modify","path":"/www/a.php","token":"secret-not-exported"}`, old)
	ctx := context.Background()
	p, e := s.Preview(ctx, "admin", retention.Filter{Category: "events", Before: time.Now().Unix() - 86400})
	if e != nil {
		t.Fatal(e)
	}
	id := common.S(p["id"])
	if _, e = s.Create(ctx, "other", "cleanup", id, ""); e == nil {
		t.Fatal("ownership bypass")
	}
	if _, e = s.Create(ctx, "admin", "cleanup", id, "missing"); e == nil {
		t.Fatal("export prerequisite bypass")
	}
	j, e := s.Create(ctx, "admin", "export", id, "")
	if e != nil {
		t.Fatal(e)
	}
	drive(t, s, j)
	path, e := s.Download(ctx, "admin", j.ID)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path)
	if e != nil || strings.Contains(string(raw), "secret-not-exported") || !strings.Contains(string(raw), "/www/a.php") {
		t.Fatal(string(raw), e)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	if _, e = s.Download(ctx, "other", j.ID); e == nil {
		t.Fatal("download ownership bypass")
	}
	j, e = s.Create(ctx, "admin", "cleanup", id, j.ID)
	if e != nil {
		t.Fatal(e)
	}
	drive(t, s, j)
	if count(t, d, "events") != 0 {
		t.Fatal("not cleaned")
	}
	common.M(c["retention"])["sqlite_events_days"] = 31
	if _, e = s.Create(ctx, "admin", "cleanup", id, ""); e == nil {
		t.Fatal("stale preview accepted")
	}
}
func TestBoundedBatchRestartAndPendingNotificationHistory(t *testing.T) {
	s, d, _, c := fixture(t)
	old := time.Now().Unix() - 50*86400
	tx, _ := d.Begin()
	for i := 0; i < 1101; i++ {
		if _, e := tx.Exec("INSERT INTO events VALUES('n',?,'d',?,?)", fmt.Sprint(i), `{"operation":"modify"}`, old); e != nil {
			t.Fatal(e)
		}
	}
	tx.Commit()
	mustExec(t, d, "INSERT INTO tasks(id,node,event_id,target,payload,created,next_try,done) VALUES(10,'n','done','email','{}',?,0,?)", old, old)
	mustExec(t, d, "INSERT INTO email_recipients(task_id,recipient,next_try,done) VALUES(10,'a@example.com',0,?)", old)
	mustExec(t, d, "INSERT INTO email_attempts(task_id,recipient,time,result) VALUES(10,'a@example.com',?,'ok')", old)
	mustExec(t, d, "INSERT INTO delivery_records(task_id,target,time,status) VALUES(10,'email',?,'ok')", old)
	p, e := s.Preview(context.Background(), "admin", retention.Filter{Category: "all", Before: time.Now().Unix() - 86400})
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.Create(context.Background(), "admin", "cleanup", common.S(p["id"]), "")
	if e != nil {
		t.Fatal(e)
	}
	restarted, e := retention.New(d, s.Metrics, func() common.Map { return c })
	if e != nil {
		t.Fatal(e)
	}
	drive(t, restarted, j)
	if count(t, d, "events") != 0 || count(t, d, "tasks") != 0 || count(t, d, "email_attempts") != 0 || count(t, d, "delivery_records") != 0 {
		t.Fatal("linked history not cleaned")
	}
}
func TestLeaseAndPreviewExpiry(t *testing.T) {
	s, d, _, _ := fixture(t)
	ctx := context.Background()
	mustExec(t, d, "INSERT INTO retention_lock VALUES(1,'another',?)", time.Now().Unix()+60)
	if e := s.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	if count(t, d, "retention_jobs") != 0 {
		t.Fatal("lease ignored")
	}
	if _, e := s.Preview(ctx, "admin", retention.Filter{Category: "events", Before: time.Now().Unix()}); e == nil {
		t.Fatal("recent cleanup accepted")
	}
	p, e := s.Preview(ctx, "admin", retention.Filter{Category: "events", Before: time.Now().Unix() - 86400})
	if e != nil {
		t.Fatal(e)
	}
	mustExec(t, d, "UPDATE retention_previews SET created=?", time.Now().Unix()-601)
	if _, e = s.Create(ctx, "admin", "cleanup", common.S(p["id"]), ""); e == nil {
		t.Fatal("expired preview accepted")
	}
}
func TestMetricsCommitCrashJournalRetainsAccurateProgress(t *testing.T) {
	s, d, m, _ := fixture(t)
	old := time.Now().Unix() - 50*86400
	mustExec(t, m, "INSERT INTO health_events VALUES('crashed','n','cpu','resolved',?,'x','{}')", old)
	p, e := s.Preview(context.Background(), "admin", retention.Filter{Category: "server", Before: time.Now().Unix() - 86400})
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.Create(context.Background(), "admin", "cleanup", common.S(p["id"]), "")
	if e != nil {
		t.Fatal(e)
	}
	// Simulate a crash after the metrics commit but before the event DB cursor commit.
	mustExec(t, d, "INSERT INTO retention_batches VALUES(?,0,0,?)", j.ID, fmt.Sprintf(`[{"id":1,"node":"n","time":%d,"raw":"{}"}]`, old))
	mustExec(t, m, "DELETE FROM health_events WHERE rowid=1")
	drive(t, s, j)
	result, e := s.Job(context.Background(), "admin", j.ID)
	if e != nil || result.Processed != 1 || count(t, d, "retention_batches") != 0 {
		t.Fatal(result, e)
	}
}
func TestMigrationBackupFailureStopsAndPreviewRechecksProtection(t *testing.T) {
	s, d, _, _ := fixture(t)
	old := time.Now().Unix() - 40*86400
	mustExec(t, d, "INSERT INTO events VALUES('n','later-pending','d','{}',?)", old)
	p, e := s.Preview(context.Background(), "admin", retention.Filter{Category: "events", Before: time.Now().Unix() - 86400})
	if e != nil {
		t.Fatal(e)
	}
	mustExec(t, d, "INSERT INTO tasks(node,event_id,target,payload,created,next_try) VALUES('n','later-pending','email','{}',?,0)", old)
	j, e := s.Create(context.Background(), "admin", "cleanup", common.S(p["id"]), "")
	if e != nil {
		t.Fatal(e)
	}
	drive(t, s, j)
	if count(t, d, "events") != 1 {
		t.Fatal("new protection ignored")
	}
	root := t.TempDir()
	db, e := persist.OpenDB(filepath.Join(root, "events.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	mustExec(t, db, central.Schema+notify.Schema)
	bad := filepath.Join(root, "not-directory")
	os.WriteFile(bad, []byte("x"), 0600)
	if _, e = retention.New(db, nil, func() common.Map { return common.Map{"backup_dir": bad} }); e == nil {
		t.Fatal("backup failure ignored")
	}
	var tables int
	db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='retention_jobs'").Scan(&tables)
	if tables != 0 {
		t.Fatal("migration ran without backup")
	}
}
func TestCleanupTransactionFailureLeavesRecordsAndReportsFailure(t *testing.T) {
	s, d, _, _ := fixture(t)
	old := time.Now().Unix() - 40*86400
	mustExec(t, d, "INSERT INTO events VALUES('n','disk-fixture','d','{}',?)", old)
	mustExec(t, d, `CREATE TRIGGER simulate_disk_failure BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'disk full'); END`)
	p, e := s.Preview(context.Background(), "admin", retention.Filter{Category: "events", Before: time.Now().Unix() - 86400})
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.Create(context.Background(), "admin", "cleanup", common.S(p["id"]), "")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Tick(context.Background()); e == nil {
		t.Fatal("error ignored")
	}
	result, e := s.Job(context.Background(), "admin", j.ID)
	if e != nil || result.Status != "failed" || result.Processed != 0 || count(t, d, "events") != 1 {
		t.Fatal(result, e)
	}
}

func TestUnavailableMetricDatabaseIsNotEmptyHistory(t *testing.T) {
	s, _, m, _ := fixture(t)
	if e := m.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Preview(context.Background(), "admin", retention.Filter{Category: "server", Before: time.Now().Unix() - 30*86400}); e == nil {
		t.Fatal("closed database was reported as an empty preview")
	}
	if _, e := s.Status(context.Background()); e == nil {
		t.Fatal("closed database was reported as empty statistics")
	}
}
