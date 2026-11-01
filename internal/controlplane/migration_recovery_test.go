package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"webscan/internal/common"
)

func recoveryCoordinatorFixture(t *testing.T) (*shadowFixture, string, time.Time) {
	t.Helper()
	f := newShadowFixture(t)
	ctx := context.Background()
	var exists bool
	if e := f.store.DB.QueryRow("SELECT to_regclass('v3_migration_recovery_state') IS NOT NULL").Scan(&exists); e != nil || !exists {
		t.Fatal("production recovery schema not registered", e)
	}
	// Existing fixture has deliberately malformed rows; remove these before the
	// synthetic backup checkpoint, so actual later retained replay is meaningful.
	if _, e := f.source.DB.Exec("DELETE FROM events"); e != nil {
		t.Fatal(e)
	}
	backupAt := time.Now().UTC()
	time.Sleep(20 * time.Millisecond)
	if e := f.source.RecordMetrics(ctx, time.Now(), []byte("node_memory_MemTotal_bytes 123456\nnode_memory_MemAvailable_bytes 123456\n")); e != nil {
		t.Fatal(e)
	}
	for _, event := range []struct {
		id       string
		accepted bool
	}{{"accepted-after-backup", true}, {"pending-after-backup", false}} {
		var accepted any
		if event.accepted {
			accepted = float64(time.Now().UnixMilli()) / 1000
		}
		raw := common.JSON(common.Map{"node_id": f.node.ID, "event_id": event.id, "operation": "modify", "path": "/isolated/disaster-recovery"})
		if _, e := f.source.DB.Exec("INSERT INTO events(id,payload,created,accepted) VALUES(?,?,?,?)", event.id, raw, float64(time.Now().UnixMilli())/1000, accepted); e != nil {
			t.Fatal(e)
		}
	}
	tx, e := f.store.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = HoldMigrationRecoveryTx(ctx, tx, digest([]byte("synthetic-verified-backup")), backupAt); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	var generation string
	if e = f.store.DB.QueryRow("SELECT generation FROM v3_migration_recovery_state WHERE id=1").Scan(&generation); e != nil {
		t.Fatal(e)
	}
	return f, generation, backupAt
}
func TestMigrationRecoveryActualMTLSAcceptedReplayEpochGateAndExplicitNoticeSuppression(t *testing.T) {
	f, generation, _ := recoveryCoordinatorFixture(t)
	ctx := context.Background()
	if os.Getenv("WEBSCAN_V3_TEST_VM") == "" || os.Getenv("WEBSCAN_V3_TEST_RAW_VM") == "" {
		t.Skip("actual isolated dual VM is required for full recovery")
	}
	f.config.Metrics.QueryURL = os.Getenv("WEBSCAN_V3_TEST_VM")
	f.config.Metrics.WriteURL = f.config.Metrics.QueryURL
	f.config.Metrics.RawURL = os.Getenv("WEBSCAN_V3_TEST_RAW_VM")
	if _, e := f.store.DB.Exec(`INSERT INTO v3_accounts VALUES('recovery-admin','synthetic-not-login-hash',1,'admin')`); e != nil {
		t.Fatal(e)
	}
	if _, e := f.store.DB.Exec(`INSERT INTO v3_notifications(node,event_id,channel,payload) VALUES($1,'accepted-after-backup','email','{}')`, f.node.ID); e != nil {
		t.Fatal(e)
	}
	start, e := f.store.BeginMigrationRecovery(ctx, generation)
	if e != nil || start.Phase != "reconciling" || start.UnknownNotifications != 1 || len(start.Nodes) != 1 {
		t.Fatal(start, e)
	}
	sqliteBefore := shadowSQLSnapshot(t, f.source.DB, []string{"events", "pull_state", "pull_receipts", "pull_metrics", "delivery_failures", "delivery_status", "pull_recovery_retention"})
	businessBefore := shadowBusinessSnapshot(t, f.store)
	report, e := f.store.RunMigrationRecovery(ctx, f.config, generation)
	if e != nil || len(report.Nodes) != 1 || report.Nodes[0].State != "complete" || !report.Nodes[0].RetentionComplete || report.Nodes[0].RemoteEpoch != 7 || report.Nodes[0].ReadEvents != 2 || report.UnknownNotifications != 3 || report.Ready {
		t.Fatal(report, e)
	}
	if !reflect.DeepEqual(sqliteBefore, shadowSQLSnapshot(t, f.source.DB, []string{"events", "pull_state", "pull_receipts", "pull_metrics", "delivery_failures", "delivery_status", "pull_recovery_retention"})) {
		t.Fatal("DR RPC changed source state")
	}
	businessAfter := shadowBusinessSnapshot(t, f.store)
	for table, before := range businessBefore {
		if migrationTargetExcluded(table) {
			continue
		}
		if !reflect.DeepEqual(businessAfter[table], before) {
			t.Fatal("read phase modified live business", table)
		}
	}
	cacheReport, e := f.store.ReplayMigrationRecoveryMetrics(ctx, f.config, generation)
	if e != nil || cacheReport.MetricGaps != 0 || cacheReport.Nodes[0].Metrics.State != "verified" || cacheReport.MetricsVerified {
		t.Fatal("actual dual VM cache replay or independent restore evidence", cacheReport, e)
	}
	floors, e := f.store.MigrationRecoveryEpochFloors(ctx, generation)
	if e != nil || floors[f.node.Shard] != 7 {
		t.Fatal(floors, e)
	}
	if e = f.store.SuppressMigrationRecoveryNotifications(ctx, generation, "viewer"); !errors.Is(e, ErrMigrationRecovery) {
		t.Fatal("viewer resolved notices", e)
	}
	handoff := func() error {
		tx, e := f.store.DB.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if e = MigrationRecoveryHandoffTx(ctx, tx, generation); e != nil {
			return e
		}
		return tx.Commit()
	}
	if e = handoff(); !errors.Is(e, ErrMigrationRecovery) {
		t.Fatal("proof-free handoff", e)
	}
	if e = f.store.SuppressMigrationRecoveryNotifications(ctx, generation, "recovery-admin"); e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.DB.Exec("UPDATE v3_migration_recovery_state SET phase='ready',metrics_sha256=$1,isolation_sha256=$2", digest([]byte("independently-verified-metric-restore")), digest([]byte("independently-verified-old-host-isolation"))); e != nil {
		t.Fatal(e)
	}
	if e = handoff(); !errors.Is(e, ErrMigrationRecovery) {
		t.Fatal("lease epoch not advanced", e)
	}
	if _, e = f.store.DB.Exec("INSERT INTO v3_leases(resource,owner,epoch,expires_at) VALUES($1,'recovery-host',8,clock_timestamp())", shardResource(f.node.Shard)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.DB.Exec("UPDATE v3_migration_recovery_events SET notification_state='verified_unsent' WHERE generation=$1", generation); e != nil {
		t.Fatal(e)
	}
	if e = handoff(); !errors.Is(e, ErrMigrationRecovery) {
		t.Fatal("unsent recovered event consumed without an outbox", e)
	}
	if unresolved, e := f.store.MigrationRecoveryReport(ctx, generation); e != nil || unresolved.Ready || unresolved.UnknownNotifications != 2 {
		t.Fatal("unsent recovery notice reported ready", unresolved, e)
	}
	if _, e = f.store.DB.Exec("UPDATE v3_migration_recovery_events SET notification_state='suppressed' WHERE generation=$1", generation); e != nil {
		t.Fatal(e)
	}
	if e = handoff(); e != nil {
		t.Fatal(e)
	}
	final, e := f.store.MigrationRecoveryReport(ctx, generation)
	if e != nil || final.Phase != "complete" || final.UnknownNotifications != 0 {
		t.Fatal(final, e)
	}
	var events, keys, notifications, published int
	for table, dest := range map[string]*int{"v3_events": &events, "v3_event_keys": &keys, "v3_notifications": &notifications} {
		if e = f.store.DB.QueryRow("SELECT count(*) FROM " + table).Scan(dest); e != nil {
			t.Fatal(e)
		}
	}
	f.store.DB.QueryRow("SELECT count(*) FROM v3_migration_recovery_events WHERE published").Scan(&published)
	if events != 2 || keys != 2 || notifications != 1 || published != 2 {
		t.Fatal(events, keys, notifications, published)
	}
	var done bool
	var result string
	if e = f.store.DB.QueryRow("SELECT done_at IS NOT NULL,result FROM v3_notifications").Scan(&done, &result); e != nil || done || result != "" {
		t.Fatal("suppression fabricated delivery", done, result, e)
	}
	if !reflect.DeepEqual(sqliteBefore, shadowSQLSnapshot(t, f.source.DB, []string{"events", "pull_state", "pull_receipts", "pull_metrics", "delivery_failures", "delivery_status", "pull_recovery_retention"})) {
		t.Fatal("handoff acknowledged agent before ordinary collector")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, method := range f.methods {
		if method != "/webscan.agent.v1.AgentService/Capabilities" && method != "/webscan.agent.v1.AgentService/RecoveryState" && method != "/webscan.agent.v1.AgentService/ReadRecoveryEvents" && method != "/webscan.agent.v1.AgentService/ReadMetrics" {
			t.Fatal("recovery invoked state mutation", method)
		}
	}
}
func TestMigrationRecoveryRetentionUnknownAndActualDeletionKeepGateHeld(t *testing.T) {
	for _, mode := range []string{"old-backup", "unknown-time", "deleted-after-backup"} {
		t.Run(mode, func(t *testing.T) {
			f, generation, backupAt := recoveryCoordinatorFixture(t)
			ctx := context.Background()
			if mode == "old-backup" {
				if _, e := f.store.DB.Exec("UPDATE v3_migration_recovery_state SET backup_at=$1", backupAt.Add(-24*time.Hour)); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "unknown-time" {
				if _, e := f.store.DB.Exec("UPDATE v3_migration_recovery_state SET backup_at=NULL"); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "deleted-after-backup" {
				if _, e := f.source.DB.Exec("DELETE FROM events WHERE id='accepted-after-backup'"); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := f.store.BeginMigrationRecovery(ctx, generation); e != nil {
				t.Fatal(e)
			}
			report, e := f.store.RunMigrationRecovery(ctx, f.config, generation)
			if e != nil || report.Nodes[0].State != "complete" || report.Nodes[0].RetentionComplete || report.EventGaps != 1 || report.Ready {
				t.Fatal(report, e)
			}
			if _, e = f.store.MigrationRecoveryEpochFloors(ctx, generation); !errors.Is(e, ErrMigrationRecovery) {
				t.Fatal("missing retention accepted", e)
			}
		})
	}
}
func TestMigrationRecoveryChangedSavedConfigurationCannotReadRemote(t *testing.T) {
	f, generation, _ := recoveryCoordinatorFixture(t)
	ctx := context.Background()
	if _, e := f.store.BeginMigrationRecovery(ctx, generation); e != nil {
		t.Fatal(e)
	}
	var config common.Map
	if e := json.Unmarshal(f.node.Config, &config); e != nil {
		t.Fatal(e)
	}
	config["changed"] = true
	if _, e := f.store.DB.Exec("UPDATE v3_nodes SET config=$2,version=version+1 WHERE id=$1", f.node.ID, common.JSON(config)); e != nil {
		t.Fatal(e)
	}
	report, e := f.store.RunMigrationRecovery(ctx, f.config, generation)
	if e != nil || report.Nodes[0].State != "failed" || report.Ready {
		t.Fatal(report, e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.methods) != 0 {
		t.Fatal("stale target made remote request", f.methods)
	}
}

func TestMigrationRecoveryMetricCacheGapStopsBeforeAnyVMRequest(t *testing.T) {
	for _, mode := range []string{"outside-one-hour", "missing-start", "middle-gap"} {
		t.Run(mode, func(t *testing.T) {
			f, generation, _ := recoveryCoordinatorFixture(t)
			ctx := context.Background()
			if _, e := f.store.BeginMigrationRecovery(ctx, generation); e != nil {
				t.Fatal(e)
			}
			at := time.Now().Add(-4 * time.Minute)
			if mode == "outside-one-hour" {
				at = time.Now().Add(-2 * time.Hour)
			}
			if _, e := f.store.DB.Exec("UPDATE v3_migration_recovery_state SET backup_at=$1", at); e != nil {
				t.Fatal(e)
			}
			if mode == "middle-gap" {
				if e := f.source.RecordMetrics(ctx, at.Add(-time.Second), []byte("node_memory_MemTotal_bytes 123456\n")); e != nil {
					t.Fatal(e)
				}
			}
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
			defer server.Close()
			f.config.Metrics.QueryURL, f.config.Metrics.WriteURL = server.URL, server.URL
			before := shadowBusinessSnapshot(t, f.store)
			report, e := f.store.ReplayMigrationRecoveryMetrics(ctx, f.config, generation)
			if e != nil || report.MetricGaps != 1 || report.Nodes[0].Metrics.State != "gap" || report.Nodes[0].Metrics.Gaps < 1 || requests.Load() != 0 || report.Ready {
				t.Fatal(report, e, requests.Load())
			}
			after := shadowBusinessSnapshot(t, f.store)
			for table, rows := range before {
				if migrationTargetExcluded(table) {
					continue
				}
				if !reflect.DeepEqual(rows, after[table]) {
					t.Fatal("gap changed normal data", table)
				}
			}
		})
	}
}

func TestMigrationRecoveryNotificationQuarantineDoesNotBlockNewOrReusedIDs(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	notificationSettings(t, s)
	enqueueNotification(t, s, "recovery-node", "ambiguous-old", "email", "synthetic@example.test")
	if _, e := s.DB.Exec(`INSERT INTO v3_migration_recovery_notices(generation,notification,identity_sha256,resolution,proof) SELECT $1,id,encode(sha256(convert_to(jsonb_build_array(node,event_id,channel,recipient,delivery_key,payload)::text,'UTF8')),'hex'),'suppressed',$2 FROM v3_notifications`, token(), digest([]byte("explicit-synthetic-suppression"))); e != nil {
		t.Fatal(e)
	}
	enqueueNotification(t, s, "recovery-node", "new-after-recovery", "email", "synthetic@example.test")
	claimed, e := s.claimNotification(ctx, "email", "recovery-notice-worker")
	if e != nil || claimed == nil || claimed.EventID != "new-after-recovery" {
		t.Fatal("quarantine sent old or blocked FIFO", claimed, e)
	}
	// Identity sequences in old snapshots can be reused. A quarantined integer ID
	// must never suppress a different future message with that same ID.
	if _, e := s.DB.Exec("UPDATE v3_notifications SET event_id='new-identity-reused-id',delivery_key='new-fixed-delivery-key' WHERE event_id='ambiguous-old'"); e != nil {
		t.Fatal(e)
	}
	reused, e := s.claimNotification(ctx, "email", "replacement-notice-worker")
	if e != nil || reused == nil || reused.EventID != "new-identity-reused-id" {
		t.Fatal("old suppression matched reused integer ID", reused, e)
	}
	var attempts int
	if e = s.DB.QueryRow("SELECT count(*) FROM v3_notification_attempts").Scan(&attempts); e != nil || attempts != 0 {
		t.Fatal("claim sent external notification", attempts, e)
	}
}

func TestMigrationRecoveryMetricLostVMAcknowledgementResumesOriginalCacheAndRejectsDrift(t *testing.T) {
	vm, rawVM := os.Getenv("WEBSCAN_V3_TEST_VM"), os.Getenv("WEBSCAN_V3_TEST_RAW_VM")
	if vm == "" || rawVM == "" {
		t.Skip("actual dual VM fixtures required")
	}
	f, generation, _ := recoveryCoordinatorFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, e := f.store.BeginMigrationRecovery(ctx, generation); e != nil {
		t.Fatal(e)
	}
	target, e := f.store.migrationRecoverySaved(ctx, generation, f.node.ID)
	if e != nil {
		t.Fatal(e)
	}
	m := &Metrics{WriteURL: vm, QueryURL: vm, RawURL: rawVM, HTTP: &http.Client{Timeout: 10 * time.Second}}
	fail := true
	var writes atomic.Int64
	m.HTTP.Transport = migrationPrometheusRoundTrip(func(request *http.Request) (*http.Response, error) {
		response, e := http.DefaultTransport.RoundTrip(request)
		if e != nil {
			return nil, e
		}
		if request.Method == "POST" {
			writes.Add(1)
			if fail {
				fail = false
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				return nil, errors.New("synthetic-ack-lost-after-real-VM-write")
			}
		}
		return response, nil
	})
	before := shadowBusinessSnapshot(t, f.store)
	if e = f.store.migrationRecoveryReplayMetricNode(ctx, f.config, generation, target, m); !errors.Is(e, ErrMigrationRecovery) || writes.Load() != 1 {
		t.Fatal("lost real ack accepted", e, writes.Load())
	}
	var sha string
	if e = f.store.DB.QueryRow("SELECT metrics_sha256 FROM v3_migration_recovery_nodes WHERE generation=$1", generation).Scan(&sha); e != nil || !releaseDigest(sha) {
		t.Fatal("original cache not checkpointed", sha, e)
	}
	if e = f.store.migrationRecoveryReplayMetricNode(ctx, f.config, generation, target, m); e != nil {
		t.Fatal("exact cache did not resume", e)
	}
	var unchanged string
	if e = f.store.DB.QueryRow("SELECT metrics_sha256 FROM v3_migration_recovery_nodes WHERE generation=$1", generation).Scan(&unchanged); e != nil || unchanged != sha {
		t.Fatal("resume re-read changed cache", e)
	}
	after := shadowBusinessSnapshot(t, f.store)
	for table, rows := range before {
		if migrationTargetExcluded(table) {
			continue
		}
		if !reflect.DeepEqual(rows, after[table]) {
			t.Fatal("VM replay changed live cursors/health/notifications", table)
		}
	}
	previous := writes.Load()
	drift := *m
	drift.RawURL = "http://127.0.0.1:9"
	if e = f.store.migrationRecoveryReplayMetricNode(ctx, f.config, generation, target, &drift); !errors.Is(e, ErrMigrationRecovery) || writes.Load() != previous {
		t.Fatal("endpoint drift wrote", e)
	}
	if _, e = f.store.DB.Exec("UPDATE v3_migration_recovery_nodes SET metrics_cache=jsonb_set(metrics_cache,'{0,prometheus_text}',to_jsonb('Y2hhbmdlZA=='::text)) WHERE generation=$1", generation); e != nil {
		t.Fatal(e)
	}
	if e = f.store.migrationRecoveryReplayMetricNode(ctx, f.config, generation, target, m); !errors.Is(e, ErrMigrationRecovery) || writes.Load() != previous {
		t.Fatal("checkpoint tamper wrote", e)
	}
}
