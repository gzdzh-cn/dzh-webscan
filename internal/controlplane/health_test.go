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
	"webscan/internal/telemetry"
	agentv1 "webscan/sdk/agent/v1"
)

func healthFixture(t *testing.T) (*Store, Node, Lease, common.Map) {
	t.Helper()
	s := testStore(t)
	n := nodeFixture("health-node")
	if err := s.PutNode(context.Background(), n, 0, 256); err != nil {
		t.Fatal(err)
	}
	l, err := s.Acquire(context.Background(), shardResource(n.Shard), "health-collector")
	if err != nil {
		t.Fatal(err)
	}
	config := common.Map{"interval_seconds": 30, "repeat_hours": 4, "alerts": common.Map{"node_unreachable_seconds": 60, "memory_enabled": true, "memory_duration_seconds": 60}, "group_wait_seconds": 15, "group_interval_seconds": 0}
	root := common.Map{"monitoring": config, "feishu": common.Map{"enabled": true, "notifications": common.Map{"health_failures": true, "health_recoveries": true}}, "email": common.Map{"enabled": true, "recipients": []string{"test@example.test"}, "notifications": common.Map{"health_failures": true, "health_recoveries": true}}}
	if _, err = s.DB.Exec("UPDATE v3_settings SET payload=$1", common.JSON(root)); err != nil {
		t.Fatal(err)
	}
	return s, n, l, config
}
func healthObserve(s *Store, n Node, l Lease, c common.Map, at int64, ok bool, values map[string]float64) error {
	ctx := context.Background()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.FenceNode(ctx, tx, n, l); err != nil {
		return err
	}
	// Match CommitMetrics/failure's status lock before the health cursor.
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_node_status(node) VALUES($1) ON CONFLICT(node) DO UPDATE SET updated_at=clock_timestamp()", n.ID); err != nil {
		return err
	}
	if err = s.evaluateHealth(ctx, tx, n, telemetry.Snapshot{OK: ok, Values: values}, at*1000, c, 1); err != nil {
		return err
	}
	return tx.Commit()
}
func healthPhase(t *testing.T, s *Store, kind string) telemetry.RuleState {
	t.Helper()
	var raw []byte
	var phase string
	var st telemetry.RuleState
	if err := s.DB.QueryRow("SELECT payload,phase FROM v3_health_rules WHERE kind=$1", kind).Scan(&raw, &phase); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	st.Phase = phase
	return st
}
func TestHealthDurationRecoveryUnknownMaintenanceAndLease(t *testing.T) {
	s, n, l, c := healthFixture(t)
	at := time.Now().Unix() - 1000
	observe := func(at int64, ok bool, v map[string]float64) {
		t.Helper()
		if err := healthObserve(s, n, l, c, at, ok, v); err != nil {
			t.Fatal(err)
		}
	}
	for _, delta := range []int64{0, 30, 60} {
		observe(at+delta, false, nil)
	}
	if healthPhase(t, s, "node_unreachable").Phase != "firing" || tableCount(t, s, "v3_health_events") != 1 {
		t.Fatal("duration did not fire")
	}
	observe(at+90, true, nil)
	observe(at+90, true, nil) // Duplicate cannot be a second recovery sample.
	observe(at+80, true, nil) // Nor can an older response.
	if healthPhase(t, s, "node_unreachable").Recovery != 1 {
		t.Fatal("duplicate recovery")
	}
	observe(at+120, true, nil)
	if healthPhase(t, s, "node_unreachable").Phase != "normal" || tableCount(t, s, "v3_health_events") != 2 {
		t.Fatal("did not recover")
	}
	for _, delta := range []int64{150, 180, 210} {
		observe(at+delta, true, map[string]float64{"memory_percent": 99})
	}
	observe(at+240, true, nil)
	if healthPhase(t, s, "memory").Phase != "firing" {
		t.Fatal("unknown measurement resolved")
	}
	c["maintenance_nodes"] = []string{n.ID}
	observe(at+270, true, map[string]float64{"memory_percent": 0})
	if healthPhase(t, s, "memory").Phase != "firing" {
		t.Fatal("maintenance resolved")
	}
	delete(c, "maintenance_nodes")
	observe(at+300, true, map[string]float64{"memory_percent": 0})
	if healthPhase(t, s, "memory").Recovery != 1 {
		t.Fatal("maintenance counted toward recovery")
	}
	common.M(c["alerts"])["memory_enabled"] = false
	before := tableCount(t, s, "v3_health_events")
	observe(at+330, true, nil)
	if healthPhase(t, s, "memory").Phase != "disabled" || before != tableCount(t, s, "v3_health_events") {
		t.Fatal("disabling emitted recovery")
	}
	if err := s.Release(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if err := healthObserve(s, n, l, c, at+400, false, nil); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("unfenced evaluator", err)
	}
}

func TestHealthMetricCommitReplayFailureAndAtomicOutbox(t *testing.T) {
	s, n, l, _ := healthFixture(t)
	ctx := context.Background()
	// A fresh low-memory sample starts a pending alarm, replay must not fire it.
	batch := func(at int64) *agentv1.MetricsBatch {
		return &agentv1.MetricsBatch{NodeId: n.ID, Samples: []*agentv1.MetricsSample{{UnixMillis: at, PrometheusText: []byte("node_memory_MemTotal_bytes 100\nnode_memory_MemAvailable_bytes 1\nwebscan_agent_heartbeat_seconds 1\n")}}}
	}
	if err := s.CommitMetrics(ctx, n, l, batch(time.Now().Add(-time.Hour).UnixMilli()), telemetry.Baseline{}); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_health_rules") != 0 {
		t.Fatal("historical replay evaluated live alarms")
	}
	if err := s.CommitMetrics(ctx, n, l, batch(time.Now().UnixMilli()), telemetry.Baseline{}); err != nil {
		t.Fatal(err)
	}
	if healthPhase(t, s, "memory").Phase != "pending" {
		t.Fatal("live metrics not evaluated")
	}
	// Force next live evaluation to fire without waiting in wall-clock time.
	if _, err := s.DB.Exec(`UPDATE v3_health_rules SET payload=jsonb_set(payload,'{since}',to_jsonb((extract(epoch FROM clock_timestamp())::bigint-120))) WHERE kind='memory';UPDATE v3_health_cursors SET observed=0;
 CREATE FUNCTION reject_health() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'fixture'; END$$;
 CREATE TRIGGER reject_health BEFORE INSERT ON v3_health_outbox FOR EACH ROW EXECUTE FUNCTION reject_health()`); err != nil {
		t.Fatal(err)
	}
	var cursor int64
	if err := s.DB.QueryRow("SELECT sampled_at FROM v3_metric_cursors").Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitMetrics(ctx, n, l, batch(cursor+1), telemetry.Baseline{}); err == nil {
		t.Fatal("outbox failure accepted")
	}
	after, _, err := s.MetricCursor(ctx, n.ID)
	if err != nil || after != cursor || tableCount(t, s, "v3_health_events") != 0 {
		t.Fatal("non-atomic health commit", after, err)
	}
	if _, err = s.DB.Exec("DROP TRIGGER reject_health ON v3_health_outbox"); err != nil {
		t.Fatal(err)
	}
	if err = s.CommitMetrics(ctx, n, l, batch(cursor+1), telemetry.Baseline{}); err != nil {
		t.Fatal(err)
	}
	if healthPhase(t, s, "memory").Phase != "firing" || tableCount(t, s, "v3_health_outbox") != 1 {
		t.Fatal("retry lost alarm")
	}
	collector := &Collector{Store: s}
	collector.failure(ctx, n, l, "protocol", "协议不可用")
	if healthPhase(t, s, "node_unreachable").Phase != "pending" {
		t.Fatal("protocol failures not evaluated")
	}
}

func TestHealthConcurrentObservationAndCPUGaps(t *testing.T) {
	s, n, l, c := healthFixture(t)
	at := time.Now().Unix() - 1000
	if err := healthObserve(s, n, l, c, at, false, nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); failures <- healthObserve(s, n, l, c, at+60, false, nil) }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if tableCount(t, s, "v3_health_events") != 1 {
		t.Fatal("duplicate concurrent firing")
	}
	common.M(c["alerts"])["cpu_enabled"] = true
	common.M(c["alerts"])["cpu_duration_seconds"] = 30
	for delta := int64(90); delta <= 420; delta += 30 {
		if err := healthObserve(s, n, l, c, at+delta, true, map[string]float64{"cpu_percent": 99}); err != nil {
			t.Fatal(err)
		}
	}
	if healthPhase(t, s, "cpu").Phase != "firing" {
		t.Fatal("weighted CPU average did not become known")
	}
	if err := healthObserve(s, n, l, c, at+450, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := healthObserve(s, n, l, c, at+480, true, map[string]float64{"cpu_percent": 0}); err != nil {
		t.Fatal(err)
	}
	if healthPhase(t, s, "cpu").Recovery != 0 {
		t.Fatal("reset/missing CPU recovered firing alert")
	}
	if count := tableCount(t, s, "v3_health_samples"); count > 11 {
		t.Fatal("unbounded CPU window", count)
	}
}

func seedHealthNotice(t *testing.T, s *Store, n Node, kind string, created int64) {
	t.Helper()
	id := fmt.Sprintf("%s-%d", kind, created)
	st := telemetry.RuleState{Key: n.ID + ":" + kind, Node: n.ID, Kind: kind, Phase: "firing", Since: created}
	if _, err := s.DB.Exec("INSERT INTO v3_health_rules VALUES($1,$2,$3,'firing',$4,$4,0,$4,$5) ON CONFLICT(key) DO NOTHING", st.Key, n.ID, kind, created, common.JSON(st)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("INSERT INTO v3_health_events VALUES($1,$2,$3,'firing',$4,$3,$5)", id, n.ID, kind, created, common.JSON(st)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("INSERT INTO v3_health_outbox(id,node,phase,message,created) VALUES($1,$2,'firing',$3,$4)", id, n.ID, kind, created); err != nil {
		t.Fatal(err)
	}
}
func TestHealthGroupedNotificationTransactionAndRetry(t *testing.T) {
	s, n, _, _ := healthFixture(t)
	ctx := context.Background()
	at := time.Now().Unix() - 120
	for i := range 8 {
		seedHealthNotice(t, s, n, fmt.Sprintf("disk%d", i), at)
	}
	l, err := s.Acquire(ctx, "health-flush", "notifier")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`CREATE FUNCTION reject_health_notice() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'fixture'; END$$;
 CREATE TRIGGER reject_health_notice BEFORE INSERT ON v3_notifications FOR EACH ROW EXECUTE FUNCTION reject_health_notice()`); err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, l); err == nil {
		t.Fatal("ignored enqueue failure")
	}
	if tableCount(t, s, "v3_health_batches") != 0 {
		t.Fatal("partial batch commit")
	}
	if _, err = s.DB.Exec("DROP TRIGGER reject_health_notice ON v3_notifications"); err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, l); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_health_batches") != 1 || tableCount(t, s, "v3_notifications") != 2 {
		t.Fatal("duplicate or ungrouped notices")
	}
	var message string
	if err = s.DB.QueryRow("SELECT message FROM v3_health_batches").Scan(&message); err != nil || !strings.Contains(message, "8 项") {
		t.Fatal(message, err)
	}
	feishu, err := s.claimNotification(ctx, "feishu", "sender")
	if err != nil || feishu == nil {
		t.Fatal(feishu, err)
	}
	if err = s.finishNotification(ctx, feishu, true); err != nil {
		t.Fatal(err)
	}
	email, err := s.claimNotification(ctx, "email", "sender")
	if err != nil || email == nil {
		t.Fatal(email, err)
	}
	if err = s.finishNotification(ctx, email, false); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err = s.DB.QueryRow("SELECT count(*) FROM v3_notifications WHERE done_at IS NULL").Scan(&pending); err != nil || pending != 1 {
		t.Fatal(pending, err)
	}
}
func TestHealthDiskInhibitionAndNodeDisable(t *testing.T) {
	s, n, l, c := healthFixture(t)
	at := time.Now().Unix() - 120
	for _, delta := range []int64{0, 30, 60} {
		if err := healthObserve(s, n, l, c, at+delta, true, map[string]float64{"disk_percent:/": 99, "webscan_agent_heartbeat_seconds": float64(at + delta)}); err != nil {
			t.Fatal(err)
		}
	}
	if tableCount(t, s, "v3_health_events") != 2 || tableCount(t, s, "v3_health_outbox") != 1 {
		t.Fatal("disk warning was not inhibited")
	}
	n.Enabled = false
	if _, err := s.SaveNode(context.Background(), "admin", "disable-health", n, 1, 256); err != nil {
		t.Fatal(err)
	}
	var stillPending int
	if err := s.DB.QueryRow("SELECT count(*) FROM v3_health_outbox WHERE done_at IS NULL").Scan(&stillPending); err != nil || stillPending != 1 {
		t.Fatal("saved draft changed live alarms", stillPending, err)
	}
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	snapshot, err := captureSavedNodeTx(context.Background(), tx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = publishNodeRuntimeTx(context.Background(), tx, n.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := s.DB.QueryRow("SELECT count(*) FROM v3_health_outbox WHERE done_at IS NULL").Scan(&pending); err != nil || pending != 0 {
		t.Fatal("disabled pending alarms retained", pending, err)
	}
	if healthPhase(t, s, "disk:/:critical").Phase != "disabled" {
		t.Fatal("disabled node retained current alarm")
	}
}
func TestHealthSchema4MigrationAndBackupRoundTrip(t *testing.T) {
	s := emptyTestStore(t)
	ctx := context.Background()
	for _, schema := range []string{Schema, websiteSchema, deploymentSchema, deploymentReadinessSchema} {
		if _, err := s.DB.Exec(schema); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema4 upgraded without backup")
	}
	if v, err := currentSchema(ctx, s.DB); err != nil || v != 4 {
		t.Fatal(v, err)
	}
	if err := s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	n := nodeFixture("health-node")
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	seedHealthNotice(t, s, n, "disk", time.Now().Unix()-100)
	l, err := s.Acquire(ctx, "health-flush", "notifier")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, l); err != nil {
		t.Fatal(err)
	}
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"v3_health_rules", "v3_health_events", "v3_health_outbox", "v3_health_batches"} {
		if tableCount(t, s, table) != tableCount(t, target, table) {
			t.Fatal("lost health state", table)
		}
	}
}

func TestHealthInhibitedBacklogDoesNotStarveOtherNodes(t *testing.T) {
	s, n, _, _ := healthFixture(t)
	ctx := context.Background()
	at := time.Now().Unix() - 120
	seedHealthNotice(t, s, n, "node_unreachable", at+1)
	// These are older than the unreachable notice and span the full batch limit.
	if _, err := s.DB.Exec(`INSERT INTO v3_health_events SELECT 'blocked-'||i,$1,'disk','firing',$2,'blocked',jsonb_build_object('key',$1::text||':disk') FROM generate_series(1,500) i`, n.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO v3_health_outbox(id,node,phase,message,created) SELECT id,node,phase,message,time FROM v3_health_events WHERE kind='disk'`); err != nil {
		t.Fatal(err)
	}
	other := nodeFixture("other-health-node")
	if err := s.PutNode(ctx, other, 0, 256); err != nil {
		t.Fatal(err)
	}
	seedHealthNotice(t, s, other, "memory", at+2)
	l, err := s.Acquire(ctx, "health-flush", "notifier")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, l); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err = s.DB.QueryRow("SELECT count(*) FROM v3_health_outbox WHERE done_at IS NULL").Scan(&remaining); err != nil || remaining != 500 {
		t.Fatal("inhibited node blocked healthy nodes", remaining, err)
	}
	if tableCount(t, s, "v3_notifications") != 4 {
		t.Fatal("missing per-channel notifications")
	}
	if _, err = s.DB.Exec("UPDATE v3_health_rules SET phase='normal' WHERE kind='node_unreachable'"); err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM v3_health_outbox WHERE done_at IS NULL").Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("outage inhibited notices never resumed", remaining, err)
	}
}

func TestHealthGroupWaitIntervalAndMaintenance(t *testing.T) {
	s, n, _, _ := healthFixture(t)
	ctx := context.Background()
	at := time.Now().Unix()
	seedHealthNotice(t, s, n, "memory", at)
	l, err := s.Acquire(ctx, "health-flush", "notifier")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, l); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_health_batches") != 0 {
		t.Fatal("group wait ignored")
	}
	if _, err = s.DB.Exec(`UPDATE v3_health_outbox SET created=created-100;UPDATE v3_settings SET payload=jsonb_set(payload,'{monitoring,maintenance_nodes}', '["health-node"]')`); err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, l); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_health_batches") != 0 {
		t.Fatal("maintenance ignored")
	}
	if _, err = s.DB.Exec(`UPDATE v3_settings SET payload=jsonb_set(payload,'{monitoring,maintenance_nodes}', '[]')`); err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, l); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_health_batches") != 1 {
		t.Fatal("maintenance did not resume")
	}
	seedHealthNotice(t, s, n, "clock", at-100)
	if _, err = s.DB.Exec(`UPDATE v3_settings SET payload=jsonb_set(payload,'{monitoring,group_interval_seconds}', '300')`); err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, l); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_health_batches") != 1 {
		t.Fatal("group interval ignored")
	}
	if _, err = s.DB.Exec(`UPDATE v3_health_batches SET done_at=done_at-interval '301 seconds'`); err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, l); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_health_batches") != 2 {
		t.Fatal("group interval did not resume")
	}
	if err = s.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err = s.FlushHealth(ctx, l); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("expired flusher lease accepted", err)
	}
}

func TestHealthNotifierRunsFlusherAndIndependentChannels(t *testing.T) {
	s, n, _, _ := healthFixture(t)
	seedHealthNotice(t, s, n, "memory", time.Now().Unix()-120)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	worker := &Notifier{Store: s, Instance: "health-notifier", Sender: fakeNotificationSender{}}
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	defer func() { cancel(); <-done }()
	for {
		var complete, retried int
		err := s.DB.QueryRow("SELECT count(*) FILTER(WHERE channel='email' AND done_at IS NOT NULL),count(*) FILTER(WHERE channel='feishu' AND done_at IS NULL AND attempts>0) FROM v3_notifications").Scan(&complete, &retried)
		if err != nil {
			t.Fatal(err)
		}
		if complete == 1 && retried == 1 {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("health outbox was not flushed by notifier", ctx.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
	var reason string
	if err := s.DB.QueryRow("SELECT error FROM v3_role_status WHERE role='server-health'").Scan(&reason); err != nil || reason != "" {
		t.Fatal(reason, err)
	}
	var leaks int
	if err := s.DB.QueryRow("SELECT count(*) FROM v3_notification_attempts WHERE result LIKE '%simulated secret%'").Scan(&leaks); err != nil || leaks != 0 {
		t.Fatal("sender error leaked", leaks, err)
	}
}

func TestHealthCollectorRejectsStaleEmptyBatch(t *testing.T) {
	s, n, l, _ := healthFixture(t)
	ctx := context.Background()
	c := &Collector{Store: s}
	c.Config.Collector.IntervalSeconds = 30
	client := metricClient{batch: &agentv1.MetricsBatch{NodeId: n.ID}}
	if err := c.collect(ctx, n, l, client); err == nil {
		t.Fatal("empty first batch accepted")
	}
	if _, err := s.DB.Exec("INSERT INTO v3_metric_cursors VALUES($1,$2,'{}')", n.ID, time.Now().Add(-time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := c.collect(ctx, n, l, client); err == nil {
		t.Fatal("stale empty response accepted")
	}
	if _, err := s.DB.Exec("UPDATE v3_metric_cursors SET sampled_at=$1", time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := c.collect(ctx, n, l, client); err != nil {
		t.Fatal("fresh empty response was not allowed", err)
	}
	if _, err := s.DB.Exec("UPDATE v3_metric_cursors SET sampled_at=$1", time.Now().Add(time.Minute).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := c.collect(ctx, n, l, client); err == nil {
		t.Fatal("future cursor concealed empty metric failure")
	}
}

func TestHealthFreshnessBoundaries(t *testing.T) {
	c := common.Map{"interval_seconds": 30}
	now := int64(1000000)
	for _, v := range []struct {
		sample int64
		fresh  bool
	}{{now, true}, {now - 90000, true}, {now - 90001, false}, {now + 5000, true}, {now + 5001, false}} {
		if actual := healthFresh(v.sample, now, c); actual != v.fresh {
			t.Fatal(v, actual)
		}
	}
}

func TestHealthUsesActualCollectorInterval(t *testing.T) {
	s, n, l, _ := healthFixture(t)
	ctx := context.Background()
	at := time.Now().Unix() - 600
	st := telemetry.RuleState{Key: n.ID + ":node_unreachable", Node: n.ID, Kind: "node_unreachable", Phase: "pending", Since: at, Last: at}
	if _, err := s.DB.Exec("INSERT INTO v3_health_rules VALUES($1,$2,$3,$4,$5,$5,0,0,$6)", st.Key, n.ID, st.Kind, st.Phase, at, common.JSON(st)); err != nil {
		t.Fatal(err)
	}
	c := &Collector{Store: s}
	c.Config.Collector.IntervalSeconds = 3600
	c.failure(ctx, n, l, "metrics", "指标采集失败")
	if healthPhase(t, s, "node_unreachable").Phase != "firing" {
		t.Fatal("long sampling interval reset pending duration")
	}
	if _, err := s.DB.Exec("UPDATE v3_health_cursors SET observed=0"); err != nil {
		t.Fatal(err)
	}
	batch := &agentv1.MetricsBatch{NodeId: n.ID, Samples: []*agentv1.MetricsSample{{UnixMillis: time.Now().Add(-3 * time.Minute).UnixMilli(), PrometheusText: []byte("node_memory_MemTotal_bytes 100\nnode_memory_MemAvailable_bytes 50\n")}}}
	if err := s.commitMetrics(ctx, n, l, batch, telemetry.Baseline{}, 3600); err != nil {
		t.Fatal(err)
	}
	if healthPhase(t, s, "node_unreachable").Recovery != 1 {
		t.Fatal("actual sample interval was not used for freshness")
	}
}
