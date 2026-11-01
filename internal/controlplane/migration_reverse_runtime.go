package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"strings"
	"time"

	"webscan/internal/common"
	"webscan/internal/telemetry"
)

// Explicitly reconstruct v2's real metric samples and rate baseline. Only the
// two v3 protocol caches below are rebuilt by v2, after their node/configuration
// ownership is established; business events and health rules are mapped apart.
func (s *MigrationLegacySink) migrationLegacyRuntimeTx(ctx context.Context, tx *sql.Tx, row MigrationTargetReplayRow, data common.Map) (bool, error) {
	switch row.Table {
	case "v3_node_status", "v3_metric_cursors", "v3_health_samples", "v3_health_cursors", "v3_node_readiness":
	default:
		return false, nil
	}
	if !s.roles["health"] {
		return true, migrationLegacyPendingError("reverse_required_legacy_database_missing")
	}
	node := common.S(data["node"])
	if !identifier.MatchString(node) {
		return true, ErrMigrationSession
	}
	if row.Table == "v3_health_cursors" || row.Table == "v3_node_readiness" {
		// Both classes are local progress/lease caches, not event ACKs or decisions.
		// A v2 process starts these protocols afresh; require an authenticated
		// imported node rather than ignoring arbitrary cache rows globally.
		var targetRaw string
		var target migrationNodeActivationTarget
		e := tx.QueryRowContext(ctx, `SELECT payload FROM migration_node_activation_targets WHERE node=?`, node).Scan(&targetRaw)
		if e == sql.ErrNoRows {
			return true, migrationLegacyPendingError("reverse_runtime_node_identity_unmapped")
		}
		if e != nil {
			return true, e
		}
		if json.Unmarshal([]byte(targetRaw), &target) != nil {
			return true, ErrMigrationSession
		}

		if row.Table == "v3_health_cursors" {
			initialized := migrationRuntimeInt(data["observed"]) == 0 && migrationRuntimeInt(data["node_version"]) == 0 && migrationRuntimeInt(data["settings_version"]) == 0
			if migrationRuntimeInt(data["observed"]) < 0 || !initialized && migrationRuntimeInt(data["node_version"]) != target.Version || migrationRuntimeInt(data["settings_version"]) < 0 {
				return true, ErrMigrationSession
			}
		} else {
			if common.S(data["kind"]) != "metrics" && common.S(data["kind"]) != "events" || migrationRuntimeInt(data["node_version"]) != target.Version || common.S(data["config_digest"]) != target.ConfigSHA || common.S(data["endpoint"]) != target.Endpoint || common.S(data["server_name"]) != target.ServerName || migrationRuntimeInt(data["epoch"]) < 1 {
				return true, ErrMigrationSession
			}
		}
		return true, nil
	}
	if row.Operation == "DELETE" {
		// Expiring a cache/window must not erase an already retained v2 sample.
		// Removing a baseline does have v2 meaning: restart rate derivation.
		if row.Table == "v3_metric_cursors" {
			_, e := tx.ExecContext(ctx, `DELETE FROM health.baselines WHERE node=?`, node)
			return true, e
		}
		return true, nil
	}
	if row.Table == "v3_metric_cursors" {
		raw := common.JSON(data["baseline"])
		var baseline telemetry.Baseline
		if json.Unmarshal(raw, &baseline) != nil || baseline.Time < 0 {
			return true, ErrMigrationSession
		}
		for _, value := range baseline.Values {
			if math.IsNaN(value) || math.IsInf(value, 0) {
				return true, ErrMigrationSession
			}
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO health.baselines(node,payload) VALUES(?,?) ON CONFLICT(node) DO UPDATE SET payload=excluded.payload`, node, string(raw))
		return true, e
	}
	sample := telemetry.Snapshot{Values: map[string]float64{}, Info: map[string]string{}}
	if row.Table == "v3_node_status" {
		sample.Time = migrationRuntimeInt(data["sampled_at"]) / 1000
		if sample.Time <= 0 {
			stamp, e := time.Parse(time.RFC3339Nano, common.S(data["updated_at"]))
			if e != nil {
				return true, ErrMigrationSession
			}
			sample.Time = stamp.Unix()
		}
		if json.Unmarshal(common.JSON(data["metrics"]), &sample.Values) != nil || json.Unmarshal(common.JSON(data["info"]), &sample.Info) != nil {
			return true, ErrMigrationSession
		}
		sample.Error = strings.TrimSpace(common.S(data["error"]))
		sample.OK = data["sampled_at"] != nil && sample.Error == ""
	} else {
		sample.Time = migrationRuntimeInt(data["time"])
		sample.OK = data["cpu"] != nil
		if sample.OK {
			number, e := json.Marshal(data["cpu"])
			if e != nil {
				return true, e
			}
			var cpu float64
			if json.Unmarshal(number, &cpu) != nil || math.IsNaN(cpu) || math.IsInf(cpu, 0) {
				return true, ErrMigrationSession
			}
			sample.Values["cpu_percent"] = cpu
		}
	}
	if sample.Time <= 0 {
		return true, ErrMigrationSession
	}
	for _, value := range sample.Values {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return true, ErrMigrationSession
		}
	}
	var prior string
	e := tx.QueryRowContext(ctx, `SELECT payload FROM health.samples WHERE node=? AND time=? AND resolution=0`, node, sample.Time).Scan(&prior)
	if e != nil && e != sql.ErrNoRows {
		return true, e
	}
	if e == nil {
		var previous telemetry.Snapshot
		if json.Unmarshal([]byte(prior), &previous) != nil {
			return true, ErrMigrationSession
		}
		// Preserve independently retained facts at the same real timestamp.
		// A different value cannot be silently rewritten during rollback.
		if row.Table == "v3_node_status" {
			for key, value := range previous.Values {
				if actual, ok := sample.Values[key]; ok && actual != value {
					return true, ErrConflict
				}
				sample.Values[key] = value
			}
			for key, value := range previous.Info {
				if _, ok := sample.Info[key]; !ok {
					sample.Info[key] = value
				}
			}
		}
		// The CPU window carries a subset; retain all independently stored fields.
		if row.Table == "v3_health_samples" {
			if previous.Values == nil {
				previous.Values = map[string]float64{}
			}
			for key, value := range sample.Values {
				if old, ok := previous.Values[key]; ok && old != value {
					return true, ErrConflict
				}
				previous.Values[key] = value
			}
			sample = previous
		}
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO health.samples(node,time,resolution,payload,source) VALUES(?,?,0,?,'native') ON CONFLICT(node,time,resolution) DO UPDATE SET payload=excluded.payload`, node, sample.Time, string(common.JSON(sample)))
	return true, e
}

func migrationRuntimeInt(value any) int64 {
	n, e := migrationLegacyInt(value)
	if e != nil {
		return -1
	}
	return n
}
