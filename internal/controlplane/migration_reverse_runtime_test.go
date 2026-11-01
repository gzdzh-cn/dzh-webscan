package controlplane

import (
	"context"
	"encoding/json"
	"testing"

	"webscan/internal/common"
	"webscan/internal/telemetry"
)

func TestMigrationReverseRuntimeWritesRealLegacySamplesAndBaseline(t *testing.T) {
	ctx := context.Background()
	directory := privateTestDir(t)
	health, e := telemetry.Open(directory, nil, common.Map{})
	if e != nil {
		t.Fatal(e)
	}
	health.DB.Close()
	session := digest([]byte(t.Name()))
	sink, e := openMigrationLegacySink(ctx, directory, migrationLegacySinkManifest{Session: session, Snapshots: map[string]string{"health": digest([]byte("synthetic-metrics"))}})
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	apply := func(label, table, op string, data common.Map) {
		t.Helper()
		row := migrationLegacyTestRow(table, op, nil, data)
		if op == "DELETE" {
			row = migrationLegacyTestRow(table, op, data, nil)
		}
		if _, e := sink.ApplyMigrationJournal(ctx, migrationLegacyTestBatch(session, label, row)); e != nil {
			t.Fatal(e)
		}
	}
	at := int64(1793498400)
	apply("status", "v3_node_status", "ADD", common.Map{"node": "old-node", "sampled_at": at * 1000, "metrics": common.Map{"cpu_percent": 12.5, "memory_percent": 40}, "info": common.Map{"agent_version": "isolated"}, "error": "", "updated_at": "2026-11-01T10:00:00Z"})
	apply("window", "v3_health_samples", "ADD", common.Map{"node": "old-node", "time": at, "cpu": 12.5})
	apply("gap", "v3_health_samples", "ADD", common.Map{"node": "old-node", "time": at + 30, "cpu": nil})
	apply("baseline", "v3_metric_cursors", "ADD", common.Map{"node": "old-node", "sampled_at": at * 1000, "baseline": telemetry.Baseline{Time: at, Values: map[string]float64{"counter": 34}}})
	var payload string
	if e = sink.db.QueryRow(`SELECT payload FROM health.samples WHERE node='old-node' AND time=?`, at).Scan(&payload); e != nil {
		t.Fatal(e)
	}
	var snapshot telemetry.Snapshot
	if e = json.Unmarshal([]byte(payload), &snapshot); e != nil || !snapshot.OK || snapshot.Values["memory_percent"] != 40 || snapshot.Values["cpu_percent"] != 12.5 {
		t.Fatal("lost real sample fields", snapshot, e)
	}
	if e = sink.db.QueryRow(`SELECT payload FROM health.samples WHERE node='old-node' AND time=?`, at+30).Scan(&payload); e != nil {
		t.Fatal(e)
	}
	snapshot = telemetry.Snapshot{}
	if json.Unmarshal([]byte(payload), &snapshot) != nil || snapshot.OK || len(snapshot.Values) != 0 {
		t.Fatal("gap forged as healthy/zero", snapshot)
	}
	if e = sink.db.QueryRow(`SELECT payload FROM health.baselines WHERE node='old-node'`).Scan(&payload); e != nil {
		t.Fatal(e)
	}
	var baseline telemetry.Baseline
	if json.Unmarshal([]byte(payload), &baseline) != nil || baseline.Time != at || baseline.Values["counter"] != 34 {
		t.Fatal("baseline lost", baseline)
	}
	apply("conflict", "v3_node_status", "UPDATE", common.Map{"node": "old-node", "sampled_at": at * 1000, "metrics": common.Map{"cpu_percent": 99}, "info": common.Map{}, "error": "", "updated_at": "2026-11-01T10:00:00Z"})
	var count int
	if e = sink.db.QueryRow(`SELECT count(*) FROM migration_pending WHERE reason='reverse_runtime_sample_conflict'`).Scan(&count); e != nil || count != 1 {
		t.Fatal("silent historical rewrite", count, e)
	}
	apply("retention", "v3_health_samples", "DELETE", common.Map{"node": "old-node", "time": at, "cpu": 12.5})
	if e = sink.db.QueryRow(`SELECT count(*) FROM health.samples WHERE node='old-node'`).Scan(&count); e != nil || count != 2 {
		t.Fatal("window expiry erased retained history", count, e)
	}

	target := migrationNodeActivationTarget{Version: 1, ConfigSHA: digest([]byte("config")), Endpoint: "example:19100", ServerName: "old-node"}
	if _, e = sink.db.Exec(`INSERT INTO migration_node_activation_targets VALUES(?,?)`, "old-node", string(common.JSON(target))); e != nil {
		t.Fatal(e)
	}
	apply("health-cache-init", "v3_health_cursors", "ADD", common.Map{"node": "old-node", "observed": int64(0), "node_version": int64(0), "settings_version": int64(0)})
	apply("health-cache-update", "v3_health_cursors", "UPDATE", common.Map{"node": "old-node", "observed": at * 1000, "node_version": int64(1), "settings_version": int64(2)})
	apply("known-readiness", "v3_node_readiness", "ADD", common.Map{"node": "old-node", "kind": "metrics", "node_version": int64(1), "config_digest": target.ConfigSHA, "endpoint": target.Endpoint, "server_name": target.ServerName, "epoch": int64(1)})
	if e = sink.db.QueryRow(`SELECT count(*) FROM migration_pending WHERE table_name IN ('v3_node_readiness','v3_health_cursors')`).Scan(&count); e != nil || count != 0 {
		t.Fatal("known reconstructible caches blocked", count, e)
	}
	apply("unknown-readiness", "v3_node_readiness", "ADD", common.Map{"node": "foreign", "kind": "metrics", "node_version": 1, "config_digest": digest([]byte("config")), "endpoint": "example:19100", "server_name": "foreign", "epoch": 1})
	if e = sink.db.QueryRow(`SELECT count(*) FROM migration_pending WHERE reason='reverse_runtime_node_identity_unmapped'`).Scan(&count); e != nil || count != 1 {
		t.Fatal("unowned cache ignored", count, e)
	}
}
