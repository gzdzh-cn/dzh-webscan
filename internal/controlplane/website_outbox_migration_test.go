package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"webscan/internal/central"
	"webscan/internal/notify"
)

func legacyWebsiteQueueFixture(t *testing.T, count int) (*sql.DB, string) {
	t.Helper()
	db, path, _ := legacyWebsiteFixture(t, count)
	mustHistoryExec(t, db, central.Schema+notify.Schema+`CREATE TABLE website_outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,site INTEGER NOT NULL,node TEXT NOT NULL,kind TEXT NOT NULL,message TEXT NOT NULL,created INTEGER NOT NULL)`)
	return db, path
}
func legacyWebsiteNotice(t *testing.T, db *sql.DB, id, site int, kind, message string) {
	t.Helper()
	mustHistoryExec(t, db, "INSERT INTO website_outbox VALUES(?,?,'old-node',?,?,?)", id, site, kind, message, time.Now().Unix()-60)
}
func legacyWebsiteTask(t *testing.T, db *sql.DB, id int, event string) {
	t.Helper()
	at := time.Now().Unix() - 120
	mustHistoryExec(t, db, "INSERT INTO tasks(id,node,event_id,target,payload,created,next_try,attempts,lease) VALUES(?,'central',?,'feishu',?, ?,?,0,0)", id, event, `{"source":"website","node_id":"old-node","notice_kind":"outage","message":"原排队通知","site_ids":[1]}`, at, at)
}
func TestWebsiteOutboxMigrationBothOrdersKeepQueuesFrozen(t *testing.T) {
	for _, queueFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(queueFirst), func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			db, path := legacyWebsiteQueueFixture(t, 3)
			legacyWebsiteNotice(t, db, 40, 1, "outage", "故障1")
			legacyWebsiteNotice(t, db, 41, 2, "outage", "故障2")
			legacyWebsiteNotice(t, db, 42, 1, "recovery", "恢复1")
			legacyWebsiteTask(t, db, 300, "website:8:0")
			source := archiveFiles(t, s, path)
			if queueFirst {
				if _, err := s.MapNotificationArchive(ctx, source); err != nil {
					t.Fatal(err)
				}
			}
			report, err := s.MapWebsiteArchive(ctx, source)
			if err != nil || !report.Complete || report.ReadyForCutover {
				t.Fatal(report, err)
			}
			if !queueFirst {
				if _, err = s.MapNotificationArchive(ctx, source); err != nil {
					t.Fatal(err)
				}
			}
			again, err := s.MapWebsiteArchive(ctx, source)
			if err != nil || again.Imported != report.Imported {
				t.Fatal(again, err)
			}
			websiteSettingsFixture(t, s)
			l, err := s.Acquire(ctx, "website-flush", "mapping")
			if err != nil {
				t.Fatal(err)
			}
			if err = s.FlushWebsiteNotices(ctx, l); err != nil || tableCount(t, s, "v3_notifications") != 1 {
				t.Fatal("migration enqueued notices", err)
			}
			if claimed, err := s.claimNotification(ctx, "feishu", "mapping-sender"); err != nil || claimed != nil {
				t.Fatal(claimed, err)
			}
			if jobs, err := s.ClaimSites(ctx, "mapping-sites", 1); err != nil || len(jobs) != 0 {
				t.Fatal(jobs, err)
			}
			if err = s.ResetPassword(ctx, "original-admin", "fixture-password-123"); err != ErrMigrationPending {
				t.Fatal("modified frozen credentials", err)
			}
			r := httptest.NewRequest("POST", "/api/v3/login", strings.NewReader(`{"username":"original-admin","password":"original-password-123"}`))
			w := httptest.NewRecorder()
			(&API{Store: s}).ServeHTTP(w, r)
			if w.Code != 503 || !strings.Contains(w.Body.String(), "migration_pending") {
				t.Fatal("login changed frozen sessions", w.Code, w.Body.String())
			}

			backup, err := s.BackupPostgres(ctx, privateTestDir(t))
			if err != nil {
				t.Fatal(err)
			}
			restored := emptyTestStore(t)
			if err = restored.RestorePostgres(ctx, backup); err != nil || tableCount(t, restored, "v3_website_outbox") != 3 {
				t.Fatal(err)
			}
			// Test-only activation. Production activation remains unavailable until all
			// domains, final deltas and the rollback path are complete.
			mustHistoryExec(t, s.DB, "UPDATE v3_migration_domains SET pending=false;UPDATE v3_notifications SET migration_pending=false")
			if err = s.FlushWebsiteNotices(ctx, l); err != nil || tableCount(t, s, "v3_notifications") != 7 {
				t.Fatal(err, tableCount(t, s, "v3_notifications"))
			}
			if err = s.FlushWebsiteNotices(ctx, l); err != nil || tableCount(t, s, "v3_notifications") != 7 {
				t.Fatal("replayed queue", err)
			}
			var old int
			_ = s.DB.QueryRow("SELECT count(*) FROM v3_notifications WHERE event_id='website:8:0'").Scan(&old)
			if old != 1 {
				t.Fatal("expanded original channels", old)
			}
			var event string
			_ = s.DB.QueryRow("SELECT event_id FROM v3_notifications WHERE payload->>'message'='故障1' AND channel='email'").Scan(&event)
			if event != "website:40:0" {
				t.Fatal("changed pending identity", event)
			}
			mustHistoryExec(t, s.DB, "INSERT INTO v3_website_outbox(site,node,kind,message,created) VALUES(3,'','outage','new',1)")
			var maximum int64
			_ = s.DB.QueryRow("SELECT max(id) FROM v3_website_outbox").Scan(&maximum)
			if maximum <= 42 {
				t.Fatal("reused imported ID", maximum)
			}
			var unchanged int
			_ = db.QueryRow("SELECT count(*) FROM website_outbox").Scan(&unchanged)
			if unchanged != 3 {
				t.Fatal("modified source")
			}
		})
	}
}
func TestWebsiteOutboxMigrationRejectsBadDependenciesAndOverlap(t *testing.T) {
	for _, kind := range []string{"missing task archive", "missing site", "overlap", "invalid message", "wrong source", "live target"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			db, path := legacyWebsiteQueueFixture(t, 1)
			site := 1
			if kind == "missing site" {
				site = 999
			}
			message := "原消息"
			if kind == "invalid message" {
				message = ""
			}
			legacyWebsiteNotice(t, db, 40, site, "outage", message)
			if kind == "overlap" {
				legacyWebsiteTask(t, db, 300, "website:40:0")
			}
			if kind == "wrong source" {
				f := legacyHistoryFixture(t)
				other := archiveFiles(t, s, f.queuePath)
				if _, err := s.MapNotificationArchive(ctx, other); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "live target" {
				savedSite(t, s, "already-live")
			}
			source := archiveFiles(t, s, path)
			if kind == "missing task archive" {
				mustHistoryExec(t, s.DB, "UPDATE v3_imports SET complete=false WHERE source=$1 AND table_name='tasks'", source)
			}
			if report, err := s.MapWebsiteArchive(ctx, source); err == nil || report.Complete || tableCount(t, s, "v3_website_outbox") != 0 {
				t.Fatal(report, err)
			}
		})
	}
}
func TestWebsiteOutboxMigrationResumesAt500AndPreservesProtectedRecords(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	db, path := legacyWebsiteQueueFixture(t, 1)
	for i := 1; i <= 503; i++ {
		legacyWebsiteNotice(t, db, i, 1, "outage", "原消息")
	}
	source := archiveFiles(t, s, path)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_old_website_notice() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.id=501 THEN RAISE EXCEPTION 'private-original-message'; END IF; RETURN NEW; END$$;CREATE TRIGGER fail_old_website_notice BEFORE INSERT ON v3_website_outbox FOR EACH ROW EXECUTE FUNCTION fail_old_website_notice()`)
	report, err := s.MapWebsiteArchive(ctx, source)
	if err == nil || report.Complete || tableCount(t, s, "v3_website_outbox") != 500 || strings.Contains(err.Error(), "private-original-message") {
		t.Fatal(report, err)
	}
	mustHistoryExec(t, s.DB, "DROP TRIGGER fail_old_website_notice ON v3_website_outbox")
	report, err = s.MapWebsiteArchive(ctx, source)
	if err != nil || !report.Complete || tableCount(t, s, "v3_website_outbox") != 503 {
		t.Fatal(report, err)
	}
	if tableCount(t, s, "v3_accounts") != 1 || tableCount(t, s, "v3_sessions") != 1 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("identity or queue changed")
	}
}

func TestWebsiteOutboxInvalidTextKeepsSnapshotAndDoesNotCompleteArchive(t *testing.T) {
	s := testStore(t)
	db, path := legacyWebsiteQueueFixture(t, 1)
	legacyWebsiteNotice(t, db, 40, 1, "outage", "private-original\x00message")
	report, err := s.ArchiveSQLite(context.Background(), path, privateTestDir(t))
	if err == nil || report.ReadyForCutover || report.Snapshot == "" || strings.Contains(err.Error(), "private-original") {
		t.Fatal(report, err)
	}
	if _, err = os.Stat(report.Snapshot); err != nil {
		t.Fatal("lost original snapshot", err)
	}
	var complete bool
	if err = s.DB.QueryRow("SELECT COALESCE(bool_and(complete),false) FROM v3_imports WHERE source=$1 AND table_name='website_outbox'", report.Source).Scan(&complete); err != nil || complete {
		t.Fatal(complete, err)
	}
}

func TestWebsiteImportInitializationCannotRaceLiveMutation(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, path := legacyWebsiteQueueFixture(t, 1)
	source := archiveFiles(t, s, path)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	changed := make(chan error, 1)
	go func() {
		_, err := s.mutation(ctx, "admin", "live-before-map", "save-website", "0", nil, func(tx *sql.Tx) (any, error) {
			close(entered)
			<-release
			_, err := tx.ExecContext(ctx, "INSERT INTO v3_websites(name,url) VALUES('live','https://live.example.test')")
			return map[string]bool{"saved": true}, err
		})
		changed <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	mapped := make(chan error, 1)
	go func() { _, err := s.MapWebsiteArchive(ctx, source); mapped <- err }()
	for {
		var waiting bool
		if err := s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=773376002 AND NOT granted)").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-mapped:
			t.Fatal("mapping bypassed mutation fence", err)
		default:
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(10 * time.Millisecond)
	}
	once.Do(func() { close(release) })
	if err := <-changed; err != nil {
		t.Fatal(err)
	}
	if err := <-mapped; err == nil {
		t.Fatal("overwrote live mutation")
	}
	if tableCount(t, s, "v3_websites") != 1 || tableCount(t, s, "v3_accounts") != 0 || tableCount(t, s, "v3_migration_domains") != 0 {
		t.Fatal("live data or migration fence corrupted")
	}
}

func TestWebsiteOutboxTaskOverlapUsesFullNodeIdentity(t *testing.T) {
	s := testStore(t)
	db, path := legacyWebsiteQueueFixture(t, 1)
	legacyWebsiteNotice(t, db, 40, 1, "outage", "网站通知")
	legacyWebsiteTask(t, db, 300, "website:40:0")
	mustHistoryExec(t, db, "UPDATE tasks SET node='other-node' WHERE id=300")
	source := archiveFiles(t, s, path)
	report, err := s.MapWebsiteArchive(context.Background(), source)
	if err != nil || !report.Complete || tableCount(t, s, "v3_website_outbox") != 1 {
		t.Fatal("different node's task blocked website history", report, err)
	}
}
