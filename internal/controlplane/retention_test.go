package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"webscan/internal/common"
	agentv1 "webscan/sdk/agent/v1"
)

func TestRetentionPolicyDefaultsInheritanceAndValidation(t *testing.T) {
	p, err := retentionPolicy(common.Map{})
	if err != nil || p != (RetentionPolicy{30, 30, 30, 15, 30}) {
		t.Fatal(p, err)
	}
	p, err = retentionPolicy(common.Map{"retention": common.Map{"sqlite_events_days": 90}, "monitoring": common.Map{"history_days": 70}})
	if err != nil || p.Security != 90 || p.Servers != 70 {
		t.Fatal(p, err)
	}
	for _, v := range []any{nil, "30", true, 0, -1, 3651, 1.5, json.Number("nan")} {
		if _, err = retentionPolicy(common.Map{"retention": common.Map{"sqlite_events_days": v}}); err == nil {
			t.Fatalf("accepted invalid days %v", v)
		}
	}
	for _, v := range []int{1, 3650} {
		p = RetentionPolicy{v, v, v, v, v}
		if err = p.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []any{nil, []any{}, true, "30"} {
		if _, err = retentionPolicy(common.Map{"retention": v}); err == nil {
			t.Fatal("invalid retention object accepted")
		}
	}
}

func TestRetentionPolicyAtomicVersionIdempotencyAndPrivateSettings(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(`UPDATE v3_settings SET payload='{"email":{"password":"private-fixture"},"retention":{"custom_legacy":20}}'`); err != nil {
		t.Fatal(err)
	}
	p := RetentionPolicy{60, 120, 30, 90, 60}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.SaveRetentionPolicy(ctx, "admin", "policy-one", p, 1)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	v, err := s.RetentionPolicy(ctx)
	if err != nil || v.Version != 2 || v.Policy != p {
		t.Fatal(v, err)
	}
	if _, err = s.SaveRetentionPolicy(ctx, "admin", "conflicting", p, 1); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	p.Events = 31
	if _, err = s.SaveRetentionPolicy(ctx, "admin", "policy-one", p, 1); !errors.Is(err, ErrRequestConflict) {
		t.Fatal(err)
	}
	var saved string
	if err = s.DB.QueryRow("SELECT payload::text FROM v3_settings").Scan(&saved); err != nil || !strings.Contains(saved, "private-fixture") || !strings.Contains(saved, "custom_legacy") {
		t.Fatal(saved, err)
	}
	var leak bool
	if err = s.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM v3_audit WHERE result::text LIKE '%private-fixture%' UNION ALL SELECT 1 FROM v3_requests WHERE response::text LIKE '%private-fixture%')`).Scan(&leak); err != nil || leak {
		t.Fatal("private settings leaked", err)
	}
	if tableCount(t, s, "v3_audit") != 1 {
		t.Fatal("duplicate policy audit")
	}
}

func retentionFixture(t *testing.T, s *Store) (Lease, RetentionJob) {
	t.Helper()
	ctx := context.Background()
	l, err := s.Acquire(ctx, "retention", "cleaner-one")
	if err != nil {
		t.Fatal(err)
	}
	j, err := s.ScheduleRetention(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	return l, j
}
func finishRetention(t *testing.T, s *Store, l Lease, j RetentionJob) RetentionJob {
	t.Helper()
	var err error
	for i := 0; i < 40 && j.Status == "running"; i++ {
		j, err = s.RetentionBatch(context.Background(), l, j.ID)
		if err != nil {
			t.Fatal("cleanup stage", j.Stage, err)
		}
	}
	if j.Status != "succeeded" {
		t.Fatal("cleanup did not finish", j)
	}
	return j
}
func oldEvent(t *testing.T, s *Store, id string, security bool, days int, payload common.Map) {
	t.Helper()
	if payload == nil {
		payload = common.Map{"operation": "write"}
	}
	if _, err := s.DB.Exec(`WITH receipt AS (INSERT INTO v3_event_keys(node,id,digest,received_at) VALUES('node-a',$1,'fixture',clock_timestamp()-($2::integer*interval '1 day')) RETURNING *) INSERT INTO v3_events SELECT node,id,received_at,'write',$3,$4 FROM receipt`, id, days, security, common.JSON(payload)); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionBatchIndependentPeriodsProtectionAndReceiptSurvival(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.SaveRetentionPolicy(ctx, "admin", "retention", RetentionPolicy{30, 90, 30, 15, 30}, 1); err != nil {
		t.Fatal(err)
	}
	oldEvent(t, s, "expired", false, 40, nil)
	oldEvent(t, s, "recent", false, 1, nil)
	oldEvent(t, s, "security-kept", true, 40, nil)
	oldEvent(t, s, "security-expired", true, 100, nil)
	oldEvent(t, s, "scan-pending", false, 40, common.Map{"scan": common.Map{"status": "pending"}})
	oldEvent(t, s, "notify-pending", false, 40, nil)
	if _, err := s.DB.Exec(`INSERT INTO v3_notifications(node,event_id,channel,payload,created_at) VALUES('node-a','notify-pending','feishu','{}',clock_timestamp()-interval '40 days')`); err != nil {
		t.Fatal(err)
	}
	l, j := retentionFixture(t, s)
	j = finishRetention(t, s, l, j)
	if j.Deleted != 2 || tableCount(t, s, "v3_events") != 4 || tableCount(t, s, "v3_event_keys") != 6 || j.Protected < 3 {
		t.Fatal(j)
	}
	if _, err := s.RetentionBatch(ctx, Lease{Resource: "retention", Owner: l.Owner, Epoch: l.Epoch + 1}, j.ID); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale cleanup accepted", err)
	}
	rescheduled, err := s.ScheduleRetention(ctx, l)
	if err != nil || rescheduled.ID != j.ID || rescheduled.Status != "succeeded" {
		t.Fatal(rescheduled, err)
	}
}

func TestRetentionBatch500RowsRestartFailureAndPolicyChange(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(`INSERT INTO v3_event_keys SELECT 'node-a',g::text,'fixture',clock_timestamp()-interval '40 days' FROM generate_series(1,503) g;
 INSERT INTO v3_events SELECT node,id,received_at,'write',false,'{}' FROM v3_event_keys`); err != nil {
		t.Fatal(err)
	}
	l, j := retentionFixture(t, s)
	j, err := s.RetentionBatch(ctx, l, j.ID)
	if err != nil || j.Scanned != 500 || j.Deleted != 500 || j.Stage != 0 {
		t.Fatal(j, err)
	}
	if _, err = s.DB.Exec(`CREATE FUNCTION fail_retention_fixture() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-fixture'; END$$; CREATE TRIGGER fail_retention_fixture BEFORE DELETE ON v3_events FOR EACH ROW EXECUTE FUNCTION fail_retention_fixture()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RetentionBatch(ctx, l, j.ID); err == nil {
		t.Fatal("deletion failure ignored")
	}
	var scanned int
	if err = s.DB.QueryRow("SELECT scanned FROM v3_retention_jobs WHERE id=$1", j.ID).Scan(&scanned); err != nil || scanned != 500 || tableCount(t, s, "v3_events") != 3 {
		t.Fatal(scanned, err)
	}
	if _, err = s.DB.Exec(`DROP TRIGGER fail_retention_fixture ON v3_events; UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource='retention'`); err != nil {
		t.Fatal(err)
	}
	next, err := s.Acquire(ctx, "retention", "cleaner-two")
	if err != nil || next.Epoch <= l.Epoch {
		t.Fatal(next, err)
	}
	other := &Store{DB: s.DB}
	resumed, err := other.ScheduleRetention(ctx, next)
	if err != nil || resumed.ID != j.ID {
		t.Fatal(resumed, err)
	}
	if _, err = other.RetentionBatch(ctx, l, j.ID); !errors.Is(err, ErrLeaseLost) {
		t.Fatal(err)
	}
	resumed = finishRetention(t, other, next, resumed)
	if resumed.Deleted != 503 || tableCount(t, s, "v3_events") != 0 {
		t.Fatal(resumed)
	}
	// A new round must stop using an old, shorter cutoff after settings change.
	if _, err = s.DB.Exec(`UPDATE v3_retention_jobs SET slot=slot-1`); err != nil {
		t.Fatal(err)
	}
	j, err = s.ScheduleRetention(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveRetentionPolicy(ctx, "admin", "lengthen", RetentionPolicy{90, 90, 90, 90, 90}, 1); err != nil {
		t.Fatal(err)
	}
	j, err = s.RetentionBatch(ctx, next, j.ID)
	if err != nil || j.Status != "cancelled" {
		t.Fatal(j, err)
	}
}

func TestRetentionCompletedNotificationGraphAndLeaseProtection(t *testing.T) {
	s := testStore(t)
	if _, err := s.DB.Exec(`INSERT INTO v3_notifications(node,event_id,channel,recipient,payload,created_at,done_at) VALUES
 ('node-a','finished','email','one@example.test','{}',clock_timestamp()-interval '60 days',clock_timestamp()-interval '40 days'),
 ('node-a','finished','email','two@example.test','{}',clock_timestamp()-interval '60 days',clock_timestamp()-interval '40 days'),
 ('node-b','partly-finished','email','one@example.test','{}',clock_timestamp()-interval '60 days',clock_timestamp()-interval '40 days'),
 ('node-b','partly-finished','email','two@example.test','{}',clock_timestamp()-interval '60 days',NULL),
 ('node-c','leased','feishu','','{}',clock_timestamp()-interval '60 days',clock_timestamp()-interval '40 days'),
 ('node-d','recent-recipient','email','one@example.test','{}',clock_timestamp()-interval '60 days',clock_timestamp()-interval '40 days'),
 ('node-d','recent-recipient','email','two@example.test','{}',clock_timestamp()-interval '60 days',clock_timestamp()-interval '1 day');
 UPDATE v3_notifications SET lease_until=clock_timestamp()+interval '1 hour' WHERE event_id='leased';
 INSERT INTO v3_notification_attempts(notification,epoch,success,result) SELECT id,1,true,'fixture' FROM v3_notifications`); err != nil {
		t.Fatal(err)
	}
	l, j := retentionFixture(t, s)
	j = finishRetention(t, s, l, j)
	if j.Deleted != 2 || tableCount(t, s, "v3_notifications") != 5 || tableCount(t, s, "v3_notification_attempts") != 5 {
		t.Fatal(j)
	}
}

func TestRetentionMigrationFreezeAndBackupGate(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(`INSERT INTO v3_migration_domains(domain,source) VALUES('events',repeat('a',64))`); err != nil {
		t.Fatal(err)
	}
	l, err := s.Acquire(ctx, "retention", "cleaner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ScheduleRetention(ctx, l); !errors.Is(err, ErrMigrationPending) {
		t.Fatal(err)
	}
	if _, err = s.SaveRetentionPolicy(ctx, "admin", "frozen", RetentionPolicy{1, 1, 1, 1, 1}, 1); !errors.Is(err, ErrMigrationPending) {
		t.Fatal(err)
	}
	old := emptyTestStore(t)
	for _, schema := range []string{Schema, websiteSchema, deploymentSchema, deploymentReadinessSchema, healthSchema, migrationSchema, eventHistorySchema, websiteOutboxSchema} {
		if _, err = old.DB.Exec(schema); err != nil {
			t.Fatal(err)
		}
	}
	if err = old.Migrate(ctx); err == nil {
		t.Fatal("migration without backup")
	}
	var v int
	if err = old.DB.QueryRow("SELECT max(version) FROM v3_schema").Scan(&v); err != nil || v != 8 {
		t.Fatal(v, err)
	}
	if err = old.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	if _, err = old.RetentionPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	l, j := retentionFixture(t, old)
	j, err = old.RetentionBatch(ctx, l, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, old.DB, `INSERT INTO v3_event_history_tombstones VALUES('archived-node','deleted-event',repeat('c',64))`)
	mustHistoryExec(t, old.DB, `INSERT INTO v3_role_status(role,instance,heartbeat) VALUES('retention','prior-worker',clock_timestamp())`)
	path, err := old.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, target, "v3_retention_jobs") != 1 {
		t.Fatal("lost cleanup cursor")
	}
	if tableCount(t, target, "v3_event_history_tombstones") != 1 {
		t.Fatal("lost history deletion identity")
	}
	status, err := target.RetentionStatus(ctx)
	if err != nil || status.Healthy != nil || status.Heartbeat != nil {
		t.Fatal("restored stale worker as healthy", status, err)
	}
}

func TestRetentionCleanupAndLateReplayAreSerialized(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n := nodeFixture("node-a")
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	p := common.Map{"node_id": n.ID, "event_id": "concurrent-late", "operation": "write"}
	_, hash, err := canonicalEvent(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO v3_imported_events VALUES('concurrent','node-a','concurrent-late',clock_timestamp()-interval '40 days','write',false,$1,$2,'fixture')`, common.JSON(p), hash); err != nil {
		t.Fatal(err)
	}
	l, j := retentionFixture(t, s)
	for range 2 {
		j, err = s.RetentionBatch(ctx, l, j.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	gate, err := s.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if _, err = gate.ExecContext(ctx, "SELECT pg_advisory_lock(773376011)"); err != nil {
		t.Fatal(err)
	}
	defer gate.ExecContext(context.Background(), "SELECT pg_advisory_unlock(773376011)")
	mustHistoryExec(t, s.DB, `CREATE FUNCTION wait_retention_replay() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_advisory_xact_lock(773376011); RETURN OLD; END$$;CREATE TRIGGER wait_retention_replay BEFORE DELETE ON v3_imported_events FOR EACH ROW EXECUTE FUNCTION wait_retention_replay()`)
	cleaned := make(chan error, 1)
	go func() { _, e := s.RetentionBatch(ctx, l, j.ID); cleaned <- e }()
	for {
		var waiting bool
		if err = s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=773376011 AND NOT granted)").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(10 * time.Millisecond)
	}
	collector, err := s.Acquire(ctx, shardResource(n.Shard), "collector")
	if err != nil {
		t.Fatal(err)
	}
	replayed := make(chan error, 1)
	go func() {
		a, r, e := s.Ingest(ctx, n, collector, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{{Id: "concurrent-late", Json: common.JSON(p)}}})
		if e == nil && (len(a) != 1 || len(r) != 0) {
			e = errors.New("not accepted")
		}
		replayed <- e
	}()
	for {
		var waiting bool
		if err = s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE query LIKE 'SELECT pg_advisory_xact_lock(hashtextextended(%' AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case e := <-replayed:
			t.Fatal("replay overtook cleanup", e)
		default:
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = gate.ExecContext(ctx, "SELECT pg_advisory_unlock(773376011)"); err != nil {
		t.Fatal(err)
	}
	if err = <-cleaned; err != nil {
		t.Fatal(err)
	}
	if err = <-replayed; err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_events") != 0 || tableCount(t, s, "v3_event_keys") != 1 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("cleanup/replay race resurrected data")
	}
}

func TestRetentionDeletedImportedReplayDoesNotResurrect(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("node-a")
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	n, err := scanActiveNode(s.DB.QueryRowContext(ctx, "SELECT "+activeNodeColumns+" FROM v3_active_nodes WHERE id=$1", n.ID))
	if err != nil {
		t.Fatal(err)
	}
	p := common.Map{"node_id": n.ID, "event_id": "late", "operation": "write", "path": "/fixture"}
	_, hash, err := canonicalEvent(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`UPDATE v3_settings SET payload='{"feishu":{"enabled":true,"notifications":{"file_changes":true}}}'`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO v3_imported_events(id,node,event_id,received_at,operation,payload,digest,migration_source) VALUES('legacy','node-a','late',clock_timestamp()-interval '40 days','write',$1,$2,'fixture')`, common.JSON(p), hash); err != nil {
		t.Fatal(err)
	}
	l, j := retentionFixture(t, s)
	j = finishRetention(t, s, l, j)
	if j.Deleted != 1 || tableCount(t, s, "v3_event_history_tombstones") != 1 || tableCount(t, s, "v3_event_keys") != 0 {
		t.Fatal(j)
	}
	collector, err := s.Acquire(ctx, shardResource(n.Shard), "collector")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		accepted, rejected, e := s.Ingest(ctx, n, collector, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{{Id: "late", Json: common.JSON(p)}}})
		if e != nil || len(accepted) != 1 || len(rejected) != 0 {
			t.Fatal(accepted, rejected, e)
		}
	}
	if tableCount(t, s, "v3_events") != 0 || tableCount(t, s, "v3_notifications") != 0 || tableCount(t, s, "v3_event_keys") != 1 {
		t.Fatal("deleted history or notice resurrected")
	}
	// A different payload must still be rejected against the actual receipt.
	p["path"] = "/other"
	_, rejected, err := s.Ingest(ctx, n, collector, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{{Id: "late", Json: common.JSON(p)}}})
	if err != nil || len(rejected) != 1 {
		t.Fatal(rejected, err)
	}
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, target, "v3_event_keys") != 1 || tableCount(t, target, "v3_event_history_tombstones") != 1 || tableCount(t, target, "v3_events") != 0 {
		t.Fatal("backup resurrected history")
	}
}

func TestRetentionWebsiteAndServerCurrentRecordsProtected(t *testing.T) {
	s := testStore(t)
	site := savedSite(t, s, "retention")
	if _, err := s.DB.Exec(`INSERT INTO v3_website_incidents(site,kind,started,ended,reason) VALUES($1,'down',extract(epoch FROM clock_timestamp()-interval '60 days')::bigint,extract(epoch FROM clock_timestamp()-interval '40 days')::bigint,'old'),($1,'down',extract(epoch FROM clock_timestamp()-interval '60 days')::bigint,NULL,'ongoing')`, site.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`
 INSERT INTO v3_node_identities VALUES('node-a');
 INSERT INTO v3_health_events VALUES('old','node-a','cpu','resolved',extract(epoch FROM clock_timestamp()-interval '40 days')::bigint,'old','{}'),('current','node-a','cpu','firing',extract(epoch FROM clock_timestamp()-interval '30 days')::bigint,'current','{}');
 INSERT INTO v3_health_rules VALUES('node-a:cpu','node-a','cpu','firing',extract(epoch FROM clock_timestamp()-interval '35 days')::bigint,1,0,0,'{}')`); err != nil {
		t.Fatal(err)
	}
	l, j := retentionFixture(t, s)
	j = finishRetention(t, s, l, j)
	if j.Deleted != 2 || tableCount(t, s, "v3_website_incidents") != 1 || tableCount(t, s, "v3_health_events") != 1 {
		t.Fatal(j)
	}
	var reason string
	if err := s.DB.QueryRow("SELECT reason FROM v3_website_incidents").Scan(&reason); err != nil || reason != "ongoing" {
		t.Fatal(reason, err)
	}
	// Audit stays outside business deletion.
	if tableCount(t, s, "v3_audit") == 0 {
		t.Fatal("cleanup unaudited")
	}
}

func TestRetentionDifferentOwnersCannotScheduleConcurrentRuns(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	l, j := retentionFixture(t, s)
	if _, err := s.Acquire(ctx, "retention", "other"); !errors.Is(err, ErrLeaseLost) {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := range 4 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.RetentionBatch(ctx, l, j.ID)
			if err != nil {
				errs <- fmt.Errorf("worker %d: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_retention_jobs") != 1 {
		t.Fatal("duplicate cleanup jobs")
	}
}

func TestRetentionCompletedOutboxGraphsAndFailureMessage(t *testing.T) {
	s := testStore(t)
	site := savedSite(t, s, "retention-graph")
	if _, err := s.DB.Exec(`INSERT INTO v3_website_outbox(site,node,kind,message,created,done_at) VALUES($1,'node-a','outage','old',extract(epoch FROM clock_timestamp()-interval '50 days')::bigint,clock_timestamp()-interval '40 days')`, site.ID); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_node_identities VALUES('node-a');
 INSERT INTO v3_health_batches VALUES('old-batch','node-a','firing','old',extract(epoch FROM clock_timestamp()-interval '50 days')::bigint,clock_timestamp()-interval '40 days');
 INSERT INTO v3_health_events VALUES('old-event','node-a','cpu','firing',extract(epoch FROM clock_timestamp()-interval '50 days')::bigint,'old','{}');
 INSERT INTO v3_health_outbox VALUES('old-event','node-a','firing','old',extract(epoch FROM clock_timestamp()-interval '50 days')::bigint,'old-batch',clock_timestamp()-interval '40 days','done')`)
	l, j := retentionFixture(t, s)
	j = finishRetention(t, s, l, j)
	if j.Deleted != 3 || tableCount(t, s, "v3_health_batches") != 0 || tableCount(t, s, "v3_health_outbox") != 0 || tableCount(t, s, "v3_website_outbox") != 0 {
		t.Fatal(j)
	}
	oldEvent(t, s, "failure", false, 40, nil)
	mustHistoryExec(t, s.DB, `UPDATE v3_retention_jobs SET slot=slot-1;CREATE FUNCTION fail_cleanup_message() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-fixture-password'; END$$;CREATE TRIGGER fail_cleanup_message BEFORE DELETE ON v3_events FOR EACH ROW EXECUTE FUNCTION fail_cleanup_message()`)
	if err := s.RunRetentionRound(context.Background(), l.Owner); err == nil {
		t.Fatal("cleanup error hidden")
	}
	if err := s.RunRetentionRound(context.Background(), l.Owner); err == nil {
		t.Fatal("retry error hidden")
	}
	var failedAudits int
	if err := s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='retention-retrying'`).Scan(&failedAudits); err != nil || failedAudits != 1 {
		t.Fatal("repeated failure flooded audit", failedAudits, err)
	}
	jobs, err := s.RetentionJobs(context.Background(), retentionCursor{}, 1)
	if err != nil || len(jobs) != 1 || jobs[0].Status != "running" || jobs[0].Deleted != 0 || !strings.Contains(jobs[0].Message, "失败") || strings.Contains(jobs[0].Message, "password") {
		t.Fatal(jobs, err)
	}
	if tableCount(t, s, "v3_events") != 1 {
		t.Fatal("partial failed transaction committed")
	}
}

func TestRetentionLargeAttemptGraphUsesBoundedResumableBatches(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	mustHistoryExec(t, s.DB, `INSERT INTO v3_notifications(node,event_id,channel,payload,created_at,done_at) VALUES('old-node','large-attempts','feishu','{}',clock_timestamp()-interval '60 days',clock_timestamp()-interval '40 days');
 INSERT INTO v3_notification_attempts(notification,epoch,success,result) SELECT n.id,g,false,'old attempt' FROM v3_notifications n,generate_series(1,1503) g`)
	l, j := retentionFixture(t, s)
	var err error
	for j.Stage < 6 {
		j, err = s.RetentionBatch(ctx, l, j.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	j, err = s.RetentionBatch(ctx, l, j.ID)
	if err != nil || j.Deleted != 0 || j.DependentDeleted != 500 || j.Stage != 6 || j.Protected != 0 || tableCount(t, s, "v3_notifications") != 1 || tableCount(t, s, "v3_notification_attempts") != 1003 {
		t.Fatal(j, err)
	}
	// A new Store resumes the same parent rather than cascading unbounded work.
	j = finishRetention(t, &Store{DB: s.DB}, l, j)
	if j.Deleted != 1 || j.DependentDeleted != 1503 || tableCount(t, s, "v3_notification_attempts") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal(j)
	}
}

func TestRetentionLargeDuplicateGraphKeepsReceiptAndCompletes(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	oldEvent(t, s, "many-copies", false, 40, nil)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_imported_events SELECT g::text,'node-a','many-copies',clock_timestamp()-interval '40 days','write',false,'{}','fixture','source' FROM generate_series(1,1503) g`)
	l, j := retentionFixture(t, s)
	j, err := s.RetentionBatch(ctx, l, j.ID)
	if err != nil || j.Deleted != 0 || j.DependentDeleted != 500 || j.Stage != 0 || tableCount(t, s, "v3_events") != 1 {
		t.Fatal(j, err)
	}
	j = finishRetention(t, s, l, j)
	if j.Deleted != 1 || j.DependentDeleted != 1503 || tableCount(t, s, "v3_event_keys") != 1 || tableCount(t, s, "v3_imported_events") != 0 || tableCount(t, s, "v3_events") != 0 {
		t.Fatal(j)
	}
}
