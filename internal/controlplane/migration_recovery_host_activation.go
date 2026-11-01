package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"sort"
	"time"

	"webscan/internal/telemetry"
	agentv1 "webscan/sdk/agent/v1"
)

type migrationRecoveryHostNode struct {
	target           migrationRecoveryTarget
	remote, restored int64
	evidence         *agentv1.RecoveryStateResponse
	cache            []*agentv1.MetricsSample
}

func migrationRecoveryHostStateTx(ctx context.Context, tx *sql.Tx, p migrationRecoveryHostPlan) ([]migrationRecoveryHostNode, time.Time, error) {
	at, err := migrationRecoveryLock(ctx, tx, p.request.Generation)
	if err != nil || at == nil || !at.Equal(p.header.SnapshotAt) {
		return nil, time.Time{}, ErrMigrationRecovery
	}
	var backup string
	var restored time.Time
	var phase string
	if tx.QueryRowContext(ctx, `SELECT backup_sha256,restored_at,phase FROM v3_migration_recovery_state WHERE id=1`).Scan(&backup, &restored, &phase) != nil || backup != p.header.SHA256 || (phase != "reconciling" && phase != "ready") {
		return nil, restored, ErrMigrationRecovery
	}
	var blocked bool
	if tx.QueryRowContext(ctx, `SELECT
EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending AND domain<>'disaster-recovery') OR
EXISTS(SELECT 1 FROM v3_migration_recovery_nodes WHERE generation=$1 AND (state<>'complete' OR NOT retention_complete OR metrics_state<>'verified' OR metrics_gaps>0)) OR
EXISTS(SELECT 1 FROM v3_migration_recovery_events WHERE generation=$1 AND notification_state IN ('unknown','verified_unsent')) OR
EXISTS(SELECT 1 FROM v3_migration_recovery_notices WHERE generation=$1 AND resolution='unknown') OR
EXISTS(SELECT 1 FROM v3_nodes n WHERE removed_at IS NULL AND NOT EXISTS(SELECT 1 FROM v3_migration_recovery_nodes r WHERE r.generation=$1 AND r.node=n.id))`, p.request.Generation).Scan(&blocked) != nil || blocked {
		return nil, restored, ErrMigrationRecovery
	}
	m := migrationRecoveryHostMetrics(p.target)
	metricTarget, err := migrationRecoveryMetricsTarget(m)
	if err != nil {
		return nil, restored, ErrMigrationRecovery
	}
	rows, err := tx.QueryContext(ctx, `SELECT target,target_sha256,remote_epoch,restored_epoch,evidence,metrics_target_sha256,metrics_sha256,metrics_cache FROM v3_migration_recovery_nodes WHERE generation=$1 ORDER BY node COLLATE "C"`, p.request.Generation)
	if err != nil {
		return nil, restored, ErrMigrationRecovery
	}
	defer rows.Close()
	nodes := []migrationRecoveryHostNode{}
	for rows.Next() {
		var n migrationRecoveryHostNode
		var targetRaw, evidenceRaw, cacheRaw []byte
		var targetHash, metricsHash, cacheHash string
		if rows.Scan(&targetRaw, &targetHash, &n.remote, &n.restored, &evidenceRaw, &metricsHash, &cacheHash, &cacheRaw) != nil || json.Unmarshal(targetRaw, &n.target) != nil || json.Unmarshal(evidenceRaw, &n.evidence) != nil || json.Unmarshal(cacheRaw, &n.cache) != nil || metricsHash != metricTarget || len(n.cache) == 0 || len(n.cache) > 1920 || n.remote < 0 || n.restored < 0 || n.remote == math.MaxInt64 || n.restored == math.MaxInt64 {
			return nil, restored, ErrMigrationRecovery
		}
		targetCanonical, _ := json.Marshal(n.target)
		cacheCanonical, _ := json.Marshal(n.cache)
		if digest(targetCanonical) != targetHash || digest(cacheCanonical) != cacheHash || n.evidence == nil || n.evidence.NodeId != n.target.Node {
			return nil, restored, ErrMigrationRecovery
		}
		nodes = append(nodes, n)
		if len(nodes) > 20000 {
			return nil, restored, ErrMigrationRecovery
		}
	}
	if rows.Err() != nil {
		return nil, restored, ErrMigrationRecovery
	}
	return nodes, restored, nil
}

func migrationRecoveryHostVerifyCacheTx(ctx context.Context, tx *sql.Tx, p migrationRecoveryHostPlan, n migrationRecoveryHostNode, restored time.Time) (string, error) {
	current, err := migrationRecoveryTargetTx(ctx, tx, n.target.Node)
	if err != nil || !migrationRecoveryTargetEqual(current, n.target) {
		return "", ErrMigrationRecovery
	}
	var baseline telemetry.Baseline
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT baseline FROM v3_metric_cursors WHERE node=$1`, n.target.Node).Scan(&raw)
	if err != nil && err != sql.ErrNoRows || err == nil && json.Unmarshal(raw, &baseline) != nil {
		return "", ErrMigrationRecovery
	}
	if baseline.Time > n.cache[0].UnixMillis/1000 {
		baseline.Time = 0
		baseline.Values = nil
	}
	derived, err := derivedSamples(n.cache, baseline)
	if err != nil {
		return "", ErrMigrationRecovery
	}
	selected := derived[:0]
	for _, sample := range derived {
		if sample.UnixMillis > p.header.SnapshotAt.UnixMilli() && sample.UnixMillis <= restored.UnixMilli() {
			selected = append(selected, sample)
		}
	}
	payload, err := migrationRecoveryBuildMetrics(n.target.Node, selected)
	if err != nil {
		return "", ErrMigrationRecovery
	}
	m := migrationRecoveryHostMetrics(p.target)
	history, original := payload, []byte(nil)
	if m.RawURL != "" {
		history, original, err = splitMetricLayers(payload)
		if err != nil {
			return "", ErrMigrationRecovery
		}
	}
	rawLayer := *m
	if m.RawURL != "" {
		rawLayer.QueryURL, rawLayer.WriteURL = m.RawURL, m.RawURL
	}
	op, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	first, last := n.cache[0].UnixMillis, n.cache[len(n.cache)-1].UnixMillis
	if migrationRecoveryVerifyLayer(op, m, n.target.Node, history, first, last, false) != nil || migrationRecoveryVerifyLayer(op, &rawLayer, n.target.Node, original, first, last, false) != nil {
		return "", ErrMigrationRecovery
	}
	raw, _ = json.Marshal([]any{n.target, history, original})
	return digest(raw), nil
}

func migrationRecoveryHostObserveNode(ctx context.Context, c Config, n migrationRecoveryHostNode, backup time.Time) (int64, string, error) {
	op, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	connection, client, err := migrationRecoveryClient(op, c, n.target)
	if err != nil {
		return 0, "", ErrMigrationRecovery
	}
	defer connection.Close()
	state, err := client.RecoveryState(op, &agentv1.RecoveryStateRequest{NodeId: n.target.Node})
	if err != nil || state == nil || state.NodeId != n.target.Node || state.ConfigurationVersion != n.target.Version || state.ConfigurationSha256 != n.target.ConfigSHA || state.Epoch >= math.MaxInt64 || int64(state.Epoch) < n.remote || !releaseDigest(state.SnapshotSha256) || state.RetentionSinceUnixMillis < 1 || state.RetentionSinceUnixMillis > backup.UnixMilli() || state.LastDeletedUnixMillis > backup.UnixMilli() || state.DeletedEvents < n.evidence.DeletedEvents || state.AcceptedEvents != n.evidence.AcceptedEvents || state.RetainedEvents < n.evidence.RetainedEvents || state.RetainedEvents != state.AcceptedEvents+state.PendingEvents || state.PendingEvents < 0 {
		return 0, "", ErrMigrationRecovery
	}
	// New unacknowledged events may have arrived while recovery ran. They stay
	// on the Agent for the normal collector. No old writer may have accepted an
	// additional event, deleted the recovery interval, or changed configuration.
	raw, _ := json.Marshal(state)
	return int64(state.Epoch), digest(raw), nil
}

func migrationRecoveryHostAdvanceTx(ctx context.Context, tx, old *sql.Tx, generation string, nodes []migrationRecoveryHostNode, floors map[int]int64) error {
	for _, n := range nodes {
		floors[n.target.Shard] = max(floors[n.target.Shard], n.remote, n.restored)
	}
	shards := make([]int, 0, len(floors))
	for shard := range floors {
		shards = append(shards, shard)
	}
	sort.Ints(shards)
	owner := "dr-" + generation + "-" + token()
	for _, shard := range shards {
		var source, current int64
		if old.QueryRowContext(ctx, `SELECT COALESCE((SELECT epoch FROM v3_leases WHERE resource=$1),0)`, shardResource(shard)).Scan(&source) != nil || tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT epoch FROM v3_leases WHERE resource=$1),0)`, shardResource(shard)).Scan(&current) != nil {
			return ErrMigrationRecovery
		}
		floor := max(floors[shard], source, current)
		if floor < 0 || floor >= math.MaxInt64 {
			return ErrMigrationRecovery
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_leases(resource,owner,epoch,expires_at) VALUES($1,$2,$3,clock_timestamp()) ON CONFLICT(resource) DO UPDATE SET owner=excluded.owner,epoch=excluded.epoch,expires_at=excluded.expires_at`, shardResource(shard), owner, floor+1); err != nil {
			return ErrMigrationRecovery
		}
	}
	return nil
}

func (s *Store) migrationRecoveryHost(ctx context.Context, p migrationRecoveryHostPlan, activate bool, r migrationRecoveryHostRuntime) (MigrationRecoveryHostReport, error) {
	report := MigrationRecoveryHostReport{State: "held", Generation: p.request.Generation, BackupSHA256: p.request.ManifestSHA256, PostgresSHA256: p.header.SHA256}
	if r.metrics == nil || r.localSource == nil {
		return report, ErrMigrationRecovery
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
	defer cancel()
	old, err := Open(ctx, p.original.config)
	if err != nil {
		return report, ErrMigrationRecovery
	}
	defer old.DB.Close()
	source, err := old.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return report, ErrMigrationRecovery
	}
	defer source.Rollback()
	target, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return report, ErrMigrationRecovery
	}
	defer target.Rollback()
	a, err := migrationRecoveryHostDatabaseID(ctx, source)
	if err != nil {
		return report, err
	}
	b, err := migrationRecoveryHostDatabaseID(ctx, target)
	if err != nil || a == b {
		return report, ErrMigrationRecovery
	}
	var guarded bool
	if target.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,773376049))`, p.request.Generation).Scan(&guarded) != nil || !guarded {
		return report, ErrMigrationRecovery
	}
	oldTables, err := migrationRecoveryHostFence(ctx, source, false)
	if err != nil {
		return report, err
	}
	nextTables, err := migrationRecoveryHostFence(ctx, target, true)
	if err != nil {
		return report, err
	}
	localSource, err := r.localSource(ctx, p.original, source)
	if err != nil || !releaseDigest(localSource) {
		return report, ErrMigrationRecovery
	}
	nodes, restored, err := migrationRecoveryHostStateTx(ctx, target, p)
	if err != nil {
		return report, err
	}
	if err := migrationRecoveryHostVerifyStage(ctx, p); err != nil {
		return report, err
	}
	if report.IsolationSHA256, err = r.isolation(ctx, p.original); err != nil {
		return report, err
	}
	if report.AuthoritySHA256, err = migrationRecoveryHostAuthorityTx(ctx, source, target, oldTables, nextTables, p.original.config, p.target); err != nil {
		return report, err
	}
	if report.MetricsSHA256, report.Samples, err = r.metrics(ctx, p); err != nil || !releaseDigest(report.MetricsSHA256) {
		return report, ErrMigrationRecovery
	}
	cacheProofs := []string{}
	floors := map[int]int64{}
	for _, n := range nodes {
		proof, err := migrationRecoveryHostVerifyCacheTx(ctx, target, p, n, restored)
		if err != nil {
			return report, err
		}
		cacheProofs = append(cacheProofs, proof)
		epoch, remote, err := migrationRecoveryHostObserveNode(ctx, p.target, n, p.header.SnapshotAt)
		if err != nil {
			return report, err
		}
		cacheProofs = append(cacheProofs, remote)
		floors[n.target.Shard] = max(floors[n.target.Shard], epoch)
	}
	// Re-read the actual target after initial VM/RPC observations. External VM
	// writers are outside the SQL fence; conflicting restored samples must
	// still fail even if the first export was correct.
	metricsProof, sampleCount, err := r.metrics(ctx, p)
	if err != nil || metricsProof != report.MetricsSHA256 || sampleCount != report.Samples {
		return report, ErrMigrationRecovery
	}
	if err := migrationRecoveryHostVerifyBinding(ctx, p); err != nil {
		return report, err
	}
	for _, n := range nodes {
		if _, err := migrationRecoveryHostVerifyCacheTx(ctx, target, p, n, restored); err != nil {
			return report, err
		}
		epoch, remote, err := migrationRecoveryHostObserveNode(ctx, p.target, n, p.header.SnapshotAt)
		if err != nil {
			return report, err
		}
		cacheProofs = append(cacheProofs, remote)
		floors[n.target.Shard] = max(floors[n.target.Shard], epoch)
	}
	// Isolation, files and current authority are re-observed after slow VM/RPC
	// work, under the same source and target table/generation fences.
	isolation, err := r.isolation(ctx, p.original)
	if err != nil || isolation != report.IsolationSHA256 {
		return report, ErrMigrationRecovery
	}
	authority, err := migrationRecoveryHostAuthorityTx(ctx, source, target, oldTables, nextTables, p.original.config, p.target)
	if err != nil || authority != report.AuthoritySHA256 {
		return report, ErrMigrationRecovery
	}
	latestLocalSource, err := r.localSource(ctx, p.original, source)
	if err != nil || latestLocalSource != localSource {
		return report, ErrMigrationRecovery
	}
	cacheRaw, _ := json.Marshal(cacheProofs)
	report.MetricsSHA256 = digest([]byte(report.MetricsSHA256 + ":" + digest(cacheRaw) + ":" + authority))
	report.IsolationSHA256 = digest([]byte(isolation + ":" + a + ":" + b + ":" + localSource))
	report.State = "verified"
	if !activate {
		return report, nil
	}
	if err := migrationRecoveryHostAdvanceTx(ctx, target, source, p.request.Generation, nodes, floors); err != nil {
		return report, err
	}
	if _, err := target.ExecContext(ctx, `UPDATE v3_migration_recovery_state SET metrics_sha256=$2,isolation_sha256=$3,phase='ready' WHERE id=1 AND generation=$1`, p.request.Generation, report.MetricsSHA256, report.IsolationSHA256); err != nil {
		return report, ErrMigrationRecovery
	}
	if err := MigrationRecoveryHandoffTx(ctx, target, p.request.Generation); err != nil {
		return report, err
	}
	if err := advanceConfigurationOperationTx(ctx, target); err != nil {
		return report, ErrMigrationRecovery
	}
	if err := target.Commit(); err != nil {
		return report, ErrMigrationRecovery
	}
	report.State, report.CutoverAuthorized = "complete", true
	return report, nil
}
