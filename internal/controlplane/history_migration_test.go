package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/central"
	"webscan/internal/common"
	"webscan/internal/notify"
	"webscan/internal/persist"
	"webscan/internal/telemetry"
	agentv1 "webscan/sdk/agent/v1"
)

type legacyHistories struct {
	health, queue         *sql.DB
	healthPath, queuePath string
	at                    int64
}

func legacyHistoryFixture(t *testing.T) legacyHistories {
	t.Helper()
	dir := t.TempDir()
	h, err := telemetry.Open(dir, nil, common.Map{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.DB.Close() })
	qpath := filepath.Join(dir, "events-v1.sqlite3")
	q, err := persist.OpenDB(qpath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	if _, err = q.Exec(central.Schema + notify.Schema); err != nil {
		t.Fatal(err)
	}
	return legacyHistories{h.DB, q, filepath.Join(dir, "metrics-v1.sqlite3"), qpath, time.Now().Unix() - 1000}
}
func (f legacyHistories) event(t *testing.T, id, node, kind, batch string, done any) {
	t.Helper()
	st := telemetry.RuleState{Key: node + ":" + kind, Node: node, Kind: kind, Phase: "firing", Since: f.at - 60, Last: f.at, Reminder: f.at}
	message := "原告警 " + id
	if _, err := f.health.Exec("INSERT INTO health_events VALUES(?,?,?,'firing',?,?,?)", id, node, kind, f.at, message, string(common.JSON(st))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.health.Exec("INSERT INTO alert_outbox VALUES(?,?,'firing',?,?,?)", id, node, message, f.at, done); err != nil {
		t.Fatal(err)
	}
	if batch != "" {
		if _, err := f.health.Exec("INSERT INTO alert_batches VALUES(?,?,'firing',?,?,?)", batch, node, message, f.at, done); err != nil {
			t.Fatal(err)
		}
		if _, err := f.health.Exec("INSERT INTO alert_members VALUES(?,?)", id, batch); err != nil {
			t.Fatal(err)
		}
	}
}
func (f legacyHistories) task(t *testing.T, id int, event, target string, payload common.Map, done any) {
	t.Helper()
	if _, err := f.queue.Exec("INSERT INTO tasks(id,node,event_id,target,payload,created,next_try,attempts,lease,done) VALUES(?,'central',?,?,?,?,?,2,?,?)", id, event, target, string(common.JSON(payload)), float64(f.at)+0.25, float64(f.at)+1.5, float64(f.at)+2.75, done); err != nil {
		t.Fatal(err)
	}
}
func archiveHistory(t *testing.T, s *Store, f legacyHistories) (string, string) {
	t.Helper()
	h, err := s.ArchiveSQLite(context.Background(), f.healthPath, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	q, err := s.ArchiveSQLite(context.Background(), f.queuePath, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	return h.Source, q.Source
}
func mustHistoryExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestHistoryMigrationPreservesQueuesAndLostAdmissionWithoutSending(t *testing.T) {
	s, n, collector, c := healthFixture(t)
	ctx := context.Background()
	f := legacyHistoryFixture(t)
	f.event(t, "lost-response", n.ID, "memory", "原批次/已接收", nil)
	f.event(t, "old-exact", n.ID, "disk:/", "原批次/待接收", nil)
	f.event(t, "done-event", n.ID, "load", "done-batch", float64(f.at)+0.75)
	f.event(t, "removed-event", "removed-node", "memory", "", nil)
	st := telemetry.RuleState{Key: n.ID + ":memory", Node: n.ID, Kind: "memory", Phase: "firing", Since: f.at - 60, Last: f.at, Reminder: f.at}
	// Disabling a v2 rule only updated its column, not the old payload.
	mustHistoryExec(t, f.health, "INSERT INTO health_rules VALUES(?,?,?,'disabled',?,?,0,?,?)", st.Key, n.ID, st.Kind, st.Since, st.Last, st.Reminder, string(common.JSON(st)))
	f.task(t, 41, "native:原批次/已接收", "feishu", common.Map{"source": "health", "node_id": n.ID, "notice_kind": "firing", "message": "原告警 lost-response"}, float64(f.at)+0.5)
	f.task(t, 42, "website:fixture", "email", common.Map{"operation": "website_down", "message": "原网站故障"}, nil)
	mustHistoryExec(t, f.queue, "INSERT INTO email_recipients VALUES(42,'a@example.test',3,?,0,?,'已提交邮件服务器'),(42,'b@example.test',4,?, ?,NULL,'暂时失败')", f.at, float64(f.at)+0.5, f.at, float64(f.at)+10.125)
	mustHistoryExec(t, f.queue, "INSERT INTO delivery_records VALUES(1,41,'feishu',?,'http=200,business=0')", float64(f.at)+0.5)
	mustHistoryExec(t, f.queue, "INSERT INTO email_attempts VALUES(1,42,'a@example.test',?,'已提交邮件服务器'),(2,42,'b@example.test',?,'包含旧私密响应的错误')", f.at, f.at)
	history := make([]float64, 601)
	for i := range history {
		history[i] = float64(f.at) + float64(i)/1000
	}
	mustHistoryExec(t, f.queue, "INSERT INTO kv VALUES('feishu_rate_history',?)", string(common.JSON(history)))
	hs, qs := archiveHistory(t, s, f)
	qreport, err := s.MapNotificationArchive(ctx, qs)
	if err != nil || !qreport.Complete || qreport.ReadyForCutover {
		t.Fatal(qreport, err)
	}
	if notice, err := s.claimNotification(ctx, "email", "fenced"); err != nil || notice != nil {
		t.Fatal("import sent a notification", notice, err)
	}
	report, err := s.MapHealthArchive(ctx, hs, qs)
	if err != nil || !report.Complete || report.ReadyForCutover {
		t.Fatal(report, err)
	}
	if healthPhase(t, s, "memory").Phase != "disabled" {
		t.Fatal("stale payload reenabled a rule")
	}
	if tableCount(t, s, "v3_nodes") != 1 || tableCount(t, s, "v3_node_identities") != 2 {
		t.Fatal("invented a live removed node")
	}
	if tableCount(t, s, "v3_notifications") != 3 || tableCount(t, s, "v3_notification_attempts") != 3 {
		t.Fatal("lost queue/attempt rows")
	}
	var pending bool
	if err = s.DB.QueryRow("SELECT done_at IS NULL FROM v3_health_batches WHERE id='原批次/已接收'").Scan(&pending); err != nil || pending {
		t.Fatal("lost admission was not reconciled", err)
	}
	var key, result string
	var attempts int
	var next time.Time
	if err = s.DB.QueryRow("SELECT delivery_key,attempts,next_try,result FROM v3_notifications WHERE migration_task=42 AND recipient='b@example.test'").Scan(&key, &attempts, &next, &result); err != nil || attempts != 4 || key != digest([]byte("42:b@example.test")) || next.Unix() != f.at+10 || strings.Contains(result, "私密") {
		t.Fatal(attempts, next, result, err)
	}
	if delta := next.Sub(time.Unix(f.at+10, 125000000)); delta > time.Microsecond || delta < -time.Microsecond {
		t.Fatal("fractional lease lost", next)
	}
	if err = healthObserve(s, n, collector, c, time.Now().Unix(), false, nil); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_health_cursors") != 0 {
		t.Fatal("migration changed live alert state")
	}
	disabled := n
	disabled.Enabled = false
	if _, err = s.SaveNode(ctx, "admin", "disable-during-import", disabled, n.Version, 256); !errors.Is(err, ErrMigrationPending) {
		t.Fatal("migration allowed changing imported health state", err)
	}
	if accepted, _, err := s.Ingest(ctx, n, collector, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{eventFixture("during-migration", "modify")}}); !errors.Is(err, ErrMigrationPending) || len(accepted) != 0 || tableCount(t, s, "v3_events") != 0 {
		t.Fatal("migration acknowledged new live events", accepted, err)
	}
	flush, err := s.Acquire(ctx, "health-flush", "migration-test")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, flush); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_notifications") != 3 {
		t.Fatal("pending migration enqueued health")
	}
	// Test-only activation. No production cutover command is exposed.
	mustHistoryExec(t, s.DB, "UPDATE v3_migration_domains SET pending=false;UPDATE v3_notifications SET migration_pending=false")
	if err = s.FlushHealth(ctx, flush); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_health_batches") != 3 || tableCount(t, s, "v3_notifications") != 5 {
		t.Fatal("regrouped old batch or expanded old admitted channels")
	}
	if err = s.FlushHealth(ctx, flush); err != nil || tableCount(t, s, "v3_notifications") != 5 {
		t.Fatal("replayed a completed batch", err)
	}
	var members []byte
	if err = s.DB.QueryRow("SELECT payload->'members' FROM v3_notifications WHERE event_id='server-alert:原批次/待接收' LIMIT 1").Scan(&members); err != nil || string(members) != `["old-exact"]` {
		t.Fatal(string(members), err)
	}
	// Removed-node pending history remains visible for reconciliation.
	if err = s.DB.QueryRow("SELECT done_at IS NULL FROM v3_health_outbox WHERE id='removed-event'").Scan(&pending); err != nil || !pending {
		t.Fatal("discarded removed-node pending history", err)
	}
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"v3_node_identities", "v3_nodes", "v3_health_rules", "v3_health_events", "v3_health_outbox", "v3_health_batches", "v3_notifications", "v3_notification_attempts", "v3_migration_domains"} {
		if tableCount(t, s, table) != tableCount(t, restored, table) {
			t.Fatal("restore lost", table)
		}
	}
}

func TestNotificationHistoryMappingResumesBatchesAndRejectsMismatchedPair(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	f := legacyHistoryFixture(t)
	for i := 1; i <= 503; i++ {
		f.task(t, i, fmt.Sprintf("file:%d", i), "feishu", common.Map{"operation": "modify"}, nil)
	}
	hs, qs := archiveHistory(t, s, f)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION interrupt_notice_mapping() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.migration_task=501 THEN RAISE EXCEPTION 'private-source-secret'; END IF; RETURN NEW; END$$;
 CREATE TRIGGER interrupt_notice_mapping BEFORE INSERT ON v3_notifications FOR EACH ROW EXECUTE FUNCTION interrupt_notice_mapping()`)
	partial, err := s.MapNotificationArchive(ctx, qs)
	if err == nil || partial.Complete || partial.Processed != 500 || strings.Contains(err.Error(), "private-source-secret") || tableCount(t, s, "v3_notifications") != 500 {
		t.Fatal(partial, err)
	}
	mustHistoryExec(t, s.DB, "DROP TRIGGER interrupt_notice_mapping ON v3_notifications")
	report, err := s.MapNotificationArchive(ctx, qs)
	if err != nil || !report.Complete || report.Imported != 503 || tableCount(t, s, "v3_notifications") != 503 {
		t.Fatal(report, err)
	}
	if _, err = s.MapHealthArchive(ctx, hs, qs); err != nil {
		t.Fatal(err)
	}
	again, err := s.MapNotificationArchive(ctx, qs)
	if err != nil || again.Imported != 503 {
		t.Fatal(again, err)
	}
	other := legacyHistoryFixture(t)
	other.task(t, 1001, "other", "feishu", common.Map{"message": "different source"}, nil)
	_, otherQS := archiveHistory(t, s, other)
	if _, err = s.MapHealthArchive(ctx, hs, otherQS); err == nil {
		t.Fatal("accepted mismatched notification source")
	}
}

func TestHistoryMigrationRejectsMissingRecipientsCorruptionAndLiveData(t *testing.T) {
	t.Run("missing recipients", func(t *testing.T) {
		s := testStore(t)
		f := legacyHistoryFixture(t)
		f.task(t, 1, "file", "email", common.Map{"message": "pending"}, nil)
		_, qs := archiveHistory(t, s, f)
		if _, err := s.MapNotificationArchive(context.Background(), qs); err == nil || !strings.Contains(err.Error(), "收件人") {
			t.Fatal(err)
		}
		if tableCount(t, s, "v3_notifications") != 0 {
			t.Fatal("guessed recipients")
		}
	})
	t.Run("staging digest", func(t *testing.T) {
		s := testStore(t)
		f := legacyHistoryFixture(t)
		f.task(t, 1, "file", "feishu", common.Map{}, nil)
		_, qs := archiveHistory(t, s, f)
		mustHistoryExec(t, s.DB, `UPDATE v3_legacy_records SET payload=jsonb_set(payload,'{node,value}','"changed"') WHERE source=$1 AND table_name='tasks'`, qs)
		if _, err := s.MapNotificationArchive(context.Background(), qs); err == nil || !strings.Contains(err.Error(), "摘要") {
			t.Fatal(err)
		}
	})
	t.Run("live domain", func(t *testing.T) {
		s := testStore(t)
		f := legacyHistoryFixture(t)
		_, qs := archiveHistory(t, s, f)
		mustHistoryExec(t, s.DB, `INSERT INTO v3_notifications(node,event_id,channel,recipient,payload) VALUES('live','live','feishu','','{}')`)
		if _, err := s.MapNotificationArchive(context.Background(), qs); err == nil {
			t.Fatal("overwrote live queue")
		}
		if tableCount(t, s, "v3_migration_domains") != 0 {
			t.Fatal("failed initialization fenced live service")
		}
	})
	t.Run("missing members", func(t *testing.T) {
		s := testStore(t)
		f := legacyHistoryFixture(t)
		mustHistoryExec(t, f.health, "INSERT INTO alert_batches VALUES('broken','node','firing','message',?,NULL)", f.at)
		hs, qs := archiveHistory(t, s, f)
		if _, err := s.MapNotificationArchive(context.Background(), qs); err != nil {
			t.Fatal(err)
		}
		if report, err := s.MapHealthArchive(context.Background(), hs, qs); err == nil || report.Complete {
			t.Fatal(report, err)
		}
	})
}

func TestHealthHistorySchema5UpgradeBacksUpBeforeIdentityMigration(t *testing.T) {
	s := emptyTestStore(t)
	ctx := context.Background()
	for _, schema := range []string{Schema, websiteSchema, deploymentSchema, deploymentReadinessSchema, healthSchema} {
		mustHistoryExec(t, s.DB, schema)
	}
	if err := putNode(ctx, s.DB, nodeFixture("existing-node"), 0, 256); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("upgraded schema5 without backup")
	}
	if err := s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_node_identities") != 1 {
		t.Fatal("existing identity not seeded")
	}
	if err := s.PutNode(ctx, nodeFixture("new-node"), 0, 256); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_node_identities") != 2 {
		t.Fatal("node trigger did not register identity")
	}
}

func TestHealthHistoryCursorSupportsMigratedIdentifiers(t *testing.T) {
	c := healthCursor{Time: 1, ID: "原事件/1:legacy"}
	got, err := decodeHealthCursor(c.encode())
	if err != nil || got != c {
		t.Fatal(got, err)
	}
	for _, id := range []string{"", strings.Repeat("x", 257), "invalid\x00"} {
		if _, err := decodeHealthCursor((healthCursor{Time: 1, ID: id}).encode()); err == nil {
			t.Fatal("accepted invalid history cursor")
		}
	}
}

func TestHistoryMigrationWriterFenceSerializesEmptyTargetCheck(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	f := legacyHistoryFixture(t)
	f.task(t, 1, "pending", "feishu", common.Map{"message": "pending"}, nil)
	_, source := archiveHistory(t, s, f)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil || held {
		t.Fatal(held, err)
	}
	// Initialization must wait for the already-started writer, rather than
	// observing an empty target and importing across an uncommitted live row.
	deadline, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, err = s.MapNotificationArchive(deadline, source)
	cancel()
	if err == nil || tableCount(t, s, "v3_migration_domains") != 0 {
		t.Fatal("initialization crossed live writer", err)
	}
	if _, err = tx.Exec(`INSERT INTO v3_notifications(node,event_id,channel,recipient,payload) VALUES('live','live','feishu','','{}')`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.MapNotificationArchive(ctx, source); err == nil {
		t.Fatal("overwrote committed live writer")
	}
}

func TestHealthHistoryMappingResumesAndReconcilesInEitherOrder(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	f := legacyHistoryFixture(t)
	for i := 1; i <= 503; i++ {
		f.event(t, fmt.Sprintf("event-%04d", i), "historical-node", "memory", "", nil)
	}
	hs, qs := archiveHistory(t, s, f)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION interrupt_health_mapping() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.id='event-0501' THEN RAISE EXCEPTION 'test interruption'; END IF; RETURN NEW; END$$;
 CREATE TRIGGER interrupt_health_mapping BEFORE INSERT ON v3_health_events FOR EACH ROW EXECUTE FUNCTION interrupt_health_mapping()`)
	partial, err := s.MapHealthArchive(ctx, hs, qs)
	if err == nil || partial.Complete || partial.Processed != 500 || tableCount(t, s, "v3_health_events") != 500 {
		t.Fatal(partial, err)
	}
	if notice, err := s.claimNotification(ctx, "feishu", "partial"); err != nil || notice != nil {
		t.Fatal(notice, err)
	}
	mustHistoryExec(t, s.DB, "DROP TRIGGER interrupt_health_mapping ON v3_health_events")
	if report, err := s.MapHealthArchive(ctx, hs, qs); err != nil || !report.Complete || tableCount(t, s, "v3_health_outbox") != 503 {
		t.Fatal(report, err)
	}
	if report, err := s.MapNotificationArchive(ctx, qs); err != nil || !report.Complete {
		t.Fatal(report, err)
	}
	if tableCount(t, s, "v3_nodes") != 0 || tableCount(t, s, "v3_node_identities") != 1 {
		t.Fatal("created historical active endpoint")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = enqueueNotice(ctx, tx, "live", "new", common.Map{}, "health_failures"); !errors.Is(err, ErrMigrationPending) {
		t.Fatal("live writer crossed import fence", err)
	}
}

func TestHistoryMigrationValidatesDependencyGraphAndLegacyTargets(t *testing.T) {
	for _, which := range []string{"batch payload", "member identity", "pending loki", "completed legacy"} {
		t.Run(which, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			f := legacyHistoryFixture(t)
			f.event(t, "event", "historical-node", "memory", "batch", nil)
			payload := common.Map{"source": "health", "node_id": "historical-node", "notice_kind": "firing", "message": "原告警 event"}
			switch which {
			case "batch payload":
				payload["message"] = "wrong"
				f.task(t, 1, "native:batch", "feishu", payload, nil)
			case "member identity":
				mustHistoryExec(t, f.health, "UPDATE alert_batches SET node='other'")
			case "pending loki":
				f.task(t, 1, "loki-old", "loki", common.Map{}, nil)
			case "completed legacy":
				f.task(t, 1, "loki-old", "loki", common.Map{}, float64(f.at))
				f.task(t, 2, "finished-email", "email", common.Map{"message": "done"}, float64(f.at))
				mustHistoryExec(t, f.queue, "INSERT INTO delivery_records VALUES(100,999,'feishu',?,'orphan')", f.at)
			}
			hs, qs := archiveHistory(t, s, f)
			qr, qerr := s.MapNotificationArchive(ctx, qs)
			if which == "pending loki" {
				if qerr == nil || qr.Complete {
					t.Fatal(qr, qerr)
				}
				return
			}
			if qerr != nil {
				t.Fatal(qerr)
			}
			hr, herr := s.MapHealthArchive(ctx, hs, qs)
			if which != "completed legacy" {
				if herr == nil || hr.Complete {
					t.Fatal(hr, herr)
				}
				return
			}
			if herr != nil || !hr.Complete || tableCount(t, s, "v3_notifications") != 1 || tableCount(t, s, "v3_notification_attempts") != 0 {
				t.Fatal(hr, herr)
			}
			var pending bool
			if err := s.DB.QueryRow("SELECT done_at IS NULL FROM v3_notifications").Scan(&pending); err != nil || pending {
				t.Fatal("revived completed email", err)
			}
		})
	}
}

func TestHistoryTimestampValidation(t *testing.T) {
	for _, v := range []archivedValue{{Type: "real", Value: "NaN"}, {Type: "real", Value: "+Inf"}, {Type: "integer", Value: "-1"}, {Type: "real", Value: "253402300800"}, {Type: "text", Value: "100"}, {Type: "null"}} {
		if _, err := (archivedRecord{"time": v}).timestamp("time", false); err == nil {
			t.Fatal("accepted invalid timestamp", v)
		}
	}
	if value, err := (archivedRecord{"time": {Type: "null"}}).timestamp("time", true); err != nil || value != nil {
		t.Fatal(value, err)
	}
}

func TestHistoryReconciliationResumesAfterCommitted500Members(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	f := legacyHistoryFixture(t)
	for i := 1; i <= 503; i++ {
		id := fmt.Sprintf("event-%04d", i)
		batch := fmt.Sprintf("batch-%04d", i)
		f.event(t, id, "old-node", "memory", batch, nil)
		f.task(t, i, "native:"+batch, "feishu", common.Map{"source": "health", "node_id": "old-node", "notice_kind": "firing", "message": "原告警 " + id}, nil)
	}
	hs, qs := archiveHistory(t, s, f)
	if _, err := s.MapHealthArchive(ctx, hs, qs); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `CREATE FUNCTION interrupt_reconciliation() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.id='batch-0501' THEN RAISE EXCEPTION 'private-reconciliation-detail'; END IF; RETURN NEW; END$$;
 CREATE TRIGGER interrupt_reconciliation BEFORE UPDATE ON v3_health_batches FOR EACH ROW EXECUTE FUNCTION interrupt_reconciliation()`)
	report, err := s.MapNotificationArchive(ctx, qs)
	if err == nil || report.Complete || report.Processed != 503 || strings.Contains(err.Error(), "private-reconciliation-detail") {
		t.Fatal(report, err)
	}
	var done int
	if err = s.DB.QueryRow("SELECT count(*) FROM v3_health_outbox WHERE done_at IS NOT NULL").Scan(&done); err != nil || done != 500 {
		t.Fatal("reconciliation transaction was not bounded", done, err)
	}
	mustHistoryExec(t, s.DB, "DROP TRIGGER interrupt_reconciliation ON v3_health_batches")
	if report, err = s.MapNotificationArchive(ctx, qs); err != nil || !report.Complete || report.ReadyForCutover {
		t.Fatal(report, err)
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM v3_health_outbox WHERE done_at IS NOT NULL").Scan(&done); err != nil || done != 503 || tableCount(t, s, "v3_notifications") != 503 {
		t.Fatal(done, err)
	}
	backup, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if notice, err := restored.claimNotification(ctx, "feishu", "restore-fenced"); err != nil || notice != nil {
		t.Fatal("restore released migration fence", notice, err)
	}
}

func TestHistoryPendingBatchesRespectMaintenanceAndSharedFlushBudget(t *testing.T) {
	s, n, _, _ := healthFixture(t)
	ctx := context.Background()
	at := time.Now().Unix() - 1000
	for i := 1; i <= 2; i++ {
		batch := fmt.Sprintf("immutable-%d", i)
		mustHistoryExec(t, s.DB, "INSERT INTO v3_health_batches VALUES($1,$2,'firing','original message',$3,NULL)", batch, n.ID, at+int64(i))
		mustHistoryExec(t, s.DB, `INSERT INTO v3_health_events SELECT $1::text||'-'||i,$2,'memory','firing',$3,'original message',jsonb_build_object('key',$2::text||':memory') FROM generate_series(1,300) i`, batch, n.ID, at)
		mustHistoryExec(t, s.DB, `INSERT INTO v3_health_outbox(id,node,phase,message,created,batch) SELECT id,node,phase,message,time,$1 FROM v3_health_events WHERE id LIKE $1::text||'-%'`, batch)
	}
	seedHealthNotice(t, s, n, "load", at)
	l, err := s.Acquire(ctx, "health-flush", "budget-test")
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=jsonb_set(payload,'{monitoring,maintenance_nodes}',$1)`, common.JSON([]string{n.ID}))
	if err = s.FlushHealth(ctx, l); err != nil || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("maintenance sent existing batch", err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=jsonb_set(payload,'{monitoring,maintenance_nodes}','[]')`)
	if err = s.FlushHealth(ctx, l); err != nil {
		t.Fatal(err)
	}
	var done int
	if err = s.DB.QueryRow("SELECT count(*) FROM v3_health_outbox WHERE done_at IS NOT NULL").Scan(&done); err != nil || done != 301 {
		t.Fatal("first flush exceeded shared budget", done, err)
	}
	if err = s.FlushHealth(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM v3_health_outbox WHERE done_at IS NOT NULL").Scan(&done); err != nil || done != 601 || tableCount(t, s, "v3_notifications") != 6 {
		t.Fatal("batch identity or remaining flush", done, err)
	}
}
