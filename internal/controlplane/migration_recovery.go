package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

var ErrMigrationRecovery = errors.New("灾备恢复的身份、事件保留、通知、代次或指标证据尚未完整；恢复保护保持启用")

type MigrationRecoveryNode struct {
	Metrics           MigrationRecoveryMetricEvidence `json:"metrics"`
	Node              string                          `json:"node"`
	State             string                          `json:"state"`
	Reason            string                          `json:"reason,omitempty"`
	Shard             int                             `json:"shard"`
	RemoteEpoch       int64                           `json:"remote_epoch"`
	RestoredEpoch     int64                           `json:"restored_epoch"`
	RetainedEvents    int64                           `json:"retained_events"`
	ReadEvents        int64                           `json:"read_events"`
	RetentionComplete bool                            `json:"retention_complete"`
	SnapshotSHA256    string                          `json:"snapshot_sha256"`
}
type MigrationRecoveryMetricEvidence struct {
	State   string `json:"state"`
	Samples int64  `json:"samples"`
	First   int64  `json:"first_unix_millis"`
	Last    int64  `json:"last_unix_millis"`
	Gaps    int    `json:"gaps"`
}

type MigrationRecoveryReport struct {
	MetricGaps           int                     `json:"metric_gaps"`
	Generation           string                  `json:"generation"`
	BackupSHA256         string                  `json:"backup_sha256"`
	BackupAt             *time.Time              `json:"backup_at,omitempty"`
	Phase                string                  `json:"phase"`
	Nodes                []MigrationRecoveryNode `json:"nodes"`
	UnknownNotifications int64                   `json:"unknown_notifications"`
	EventGaps            int                     `json:"event_gaps"`
	MetricsVerified      bool                    `json:"metrics_verified"`
	OldWriterIsolated    bool                    `json:"old_writer_isolated"`
	Ready                bool                    `json:"ready"`
}
type migrationRecoveryTarget struct {
	migrationShadowTarget
	Shard   int  `json:"shard"`
	Enabled bool `json:"enabled"`
}

// Called by restore inside its transaction, after backup integrity validation.
// A missing trustworthy backup timestamp remains SQL NULL and blocks coverage.
// Restoring an older recovery table never reuses its completed generation.
func HoldMigrationRecoveryTx(ctx context.Context, tx *sql.Tx, backupSHA string, backupAt time.Time) error {
	if !releaseDigest(backupSHA) || !backupAt.IsZero() && backupAt.After(time.Now().Add(time.Minute)) {
		return ErrMigrationRecovery
	}
	var at any
	if !backupAt.IsZero() {
		at = backupAt.UTC()
	}
	generation := token()
	_, err := tx.ExecContext(ctx, `INSERT INTO v3_migration_recovery_state(id,generation,backup_sha256,backup_at) VALUES(1,$1,$2,$3) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,backup_sha256=excluded.backup_sha256,backup_at=excluded.backup_at,phase='held',restored_at=clock_timestamp(),metrics_sha256='',isolation_sha256=''`, generation, backupSHA, at)
	if err != nil {
		return ErrMigrationRecovery
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_migration_domains(domain,source,pending) VALUES('disaster-recovery',$1,true) ON CONFLICT(domain) DO UPDATE SET source=excluded.source,pending=true`, generation); err != nil {
		return ErrMigrationRecovery
	}
	return nil
}
func migrationRecoveryLock(ctx context.Context, tx *sql.Tx, generation string) (*time.Time, error) {
	if !validArchiveSource(generation) {
		return nil, ErrMigrationRecovery
	}
	var current, phase string
	var at sql.NullTime
	if tx.QueryRowContext(ctx, "SELECT generation,phase,backup_at FROM v3_migration_recovery_state WHERE id=1 FOR UPDATE").Scan(&current, &phase, &at) != nil || current != generation || phase == "complete" {
		return nil, ErrMigrationRecovery
	}
	var fenced bool
	if tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_migration_domains WHERE domain='disaster-recovery' AND source=$1 AND pending)", generation).Scan(&fenced) != nil || !fenced {
		return nil, ErrMigrationRecovery
	}
	if at.Valid {
		return &at.Time, nil
	}
	return nil, nil
}
func migrationRecoveryTargetTx(ctx context.Context, tx *sql.Tx, id string) (migrationRecoveryTarget, error) {
	var target migrationRecoveryTarget
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR SHARE`, id))
	if err != nil || n.Validate() != nil || n.Version < 1 {
		return target, ErrMigrationRecovery
	}
	target.migrationShadowTarget = migrationShadowTarget{Node: n.ID, Version: n.Version, ConfigSHA: digest(n.Config), Endpoint: n.Endpoint, ServerName: n.ServerName, Mode: n.Mode}
	target.Shard, target.Enabled = n.Shard, n.Enabled
	return target, nil
}
func (s *Store) BeginMigrationRecovery(ctx context.Context, generation string) (MigrationRecoveryReport, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return MigrationRecoveryReport{}, ErrMigrationRecovery
	}
	defer tx.Rollback()
	if _, err = migrationRecoveryLock(ctx, tx, generation); err != nil {
		return MigrationRecoveryReport{}, err
	}
	var existing int
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM v3_migration_recovery_nodes WHERE generation=$1", generation).Scan(&existing) != nil {
		return MigrationRecoveryReport{}, ErrMigrationRecovery
	}
	if existing == 0 {
		rows, err := tx.QueryContext(ctx, "SELECT id FROM v3_nodes WHERE removed_at IS NULL ORDER BY id COLLATE \"C\"")
		if err != nil {
			return MigrationRecoveryReport{}, ErrMigrationRecovery
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil {
				rows.Close()
				return MigrationRecoveryReport{}, ErrMigrationRecovery
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil || len(ids) > 20000 {
			return MigrationRecoveryReport{}, ErrMigrationRecovery
		}
		for _, id := range ids {
			target, err := migrationRecoveryTargetTx(ctx, tx, id)
			if err != nil {
				return MigrationRecoveryReport{}, err
			}
			raw, _ := json.Marshal(target)
			var epoch int64
			if err := tx.QueryRowContext(ctx, "SELECT coalesce((SELECT epoch FROM v3_leases WHERE resource=$1),0)", shardResource(target.Shard)).Scan(&epoch); err != nil {
				return MigrationRecoveryReport{}, ErrMigrationRecovery
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO v3_migration_recovery_nodes(generation,node,target,target_sha256,restored_epoch) VALUES($1,$2,$3,$4,$5)", generation, id, raw, digest(raw), epoch); err != nil {
				return MigrationRecoveryReport{}, ErrMigrationRecovery
			}
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO v3_migration_recovery_notices(generation,notification,identity_sha256) SELECT $1,id,encode(sha256(convert_to(jsonb_build_array(node,event_id,channel,recipient,delivery_key,payload)::text,'UTF8')),'hex') FROM v3_notifications WHERE done_at IS NULL ON CONFLICT DO NOTHING", generation); err != nil {
		return MigrationRecoveryReport{}, ErrMigrationRecovery
	}
	if _, err := tx.ExecContext(ctx, "UPDATE v3_migration_recovery_state SET phase='reconciling' WHERE id=1"); err != nil {
		return MigrationRecoveryReport{}, ErrMigrationRecovery
	}
	if err = tx.Commit(); err != nil {
		return MigrationRecoveryReport{}, ErrMigrationRecovery
	}
	return s.MigrationRecoveryReport(ctx, generation)
}
func (s *Store) MigrationRecoveryReport(ctx context.Context, generation string) (MigrationRecoveryReport, error) {
	out := MigrationRecoveryReport{Generation: generation}
	var at sql.NullTime
	var metrics, isolation string
	if s.DB.QueryRowContext(ctx, "SELECT backup_sha256,backup_at,phase,metrics_sha256,isolation_sha256 FROM v3_migration_recovery_state WHERE id=1 AND generation=$1", generation).Scan(&out.BackupSHA256, &at, &out.Phase, &metrics, &isolation) != nil {
		return out, ErrMigrationRecovery
	}
	if at.Valid {
		out.BackupAt = &at.Time
	}
	out.MetricsVerified = releaseDigest(metrics)
	out.OldWriterIsolated = releaseDigest(isolation)
	rows, err := s.DB.QueryContext(ctx, "SELECT node,state,reason,target,remote_epoch,restored_epoch,retained_events,read_events,retention_complete,snapshot_sha256,metrics_state,metrics_samples,metrics_first,metrics_last,metrics_gaps FROM v3_migration_recovery_nodes WHERE generation=$1 ORDER BY node COLLATE \"C\"", generation)
	if err != nil {
		return out, ErrMigrationRecovery
	}
	defer rows.Close()
	for rows.Next() {
		var node MigrationRecoveryNode
		var raw []byte
		var target migrationRecoveryTarget
		if rows.Scan(&node.Node, &node.State, &node.Reason, &raw, &node.RemoteEpoch, &node.RestoredEpoch, &node.RetainedEvents, &node.ReadEvents, &node.RetentionComplete, &node.SnapshotSHA256, &node.Metrics.State, &node.Metrics.Samples, &node.Metrics.First, &node.Metrics.Last, &node.Metrics.Gaps) != nil || json.Unmarshal(raw, &target) != nil {
			return out, ErrMigrationRecovery
		}
		node.Shard = target.Shard
		out.Nodes = append(out.Nodes, node)
		if node.Metrics.State != "verified" || node.Metrics.Gaps > 0 {
			out.MetricGaps++
		}
		if node.State != "complete" || !node.RetentionComplete {
			out.EventGaps++
		}
	}
	if rows.Err() != nil {
		return out, ErrMigrationRecovery
	}
	if s.DB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM v3_migration_recovery_notices WHERE generation=$1 AND resolution='unknown')+(SELECT count(*) FROM v3_migration_recovery_events WHERE generation=$1 AND notification_state IN ('unknown','verified_unsent'))`, generation).Scan(&out.UnknownNotifications) != nil {
		return out, ErrMigrationRecovery
	}
	out.Ready = out.EventGaps == 0 && out.MetricGaps == 0 && out.UnknownNotifications == 0 && out.MetricsVerified && out.OldWriterIsolated && out.Phase != "held"
	return out, nil
}

// Returns floors only after every saved target has a complete actual read.
// A caller still combines these with independent durable host floors and must
// prove old-writer isolation before advancing leases above every returned value.
func (s *Store) MigrationRecoveryEpochFloors(ctx context.Context, generation string) (map[int]int64, error) {
	report, err := s.MigrationRecoveryReport(ctx, generation)
	if err != nil || report.EventGaps != 0 {
		return nil, ErrMigrationRecovery
	}
	out := map[int]int64{}
	for _, node := range report.Nodes {
		out[node.Shard] = max(out[node.Shard], node.RemoteEpoch, node.RestoredEpoch)
	}
	return out, nil
}
func migrationRecoverySortedNodes(report MigrationRecoveryReport) []string {
	out := []string{}
	for _, node := range report.Nodes {
		out = append(out, node.Node)
	}
	sort.Strings(out)
	return out
}
