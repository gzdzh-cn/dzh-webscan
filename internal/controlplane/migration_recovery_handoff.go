package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"time"
	"webscan/internal/common"
)

// This transaction hook is called only after the host has independently
// verified isolation/metric-restore evidence and advanced durable lease floors.
// It does not turn a checksum string or an administrator's belief into proof.
// Pending notices are never sent by this hook.
func MigrationRecoveryHandoffTx(ctx context.Context, tx *sql.Tx, generation string) error {
	if _, err := migrationRecoveryLock(ctx, tx, generation); err != nil {
		return err
	}
	var metrics, isolation string
	var phase string
	if tx.QueryRowContext(ctx, "SELECT phase,metrics_sha256,isolation_sha256 FROM v3_migration_recovery_state WHERE id=1").Scan(&phase, &metrics, &isolation) != nil || phase != "ready" || !releaseDigest(metrics) || !releaseDigest(isolation) {
		return ErrMigrationRecovery
	}
	var blocked bool
	// A recovered new event cannot be marked "verified_unsent" until a future
	// verified-resolution path can create its exact outbox transactionally.
	// Consuming its receipt here would otherwise silently discard that send.
	if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_migration_recovery_nodes WHERE generation=$1 AND (state<>'complete' OR NOT retention_complete OR metrics_state<>'verified' OR metrics_gaps>0)) OR EXISTS(SELECT 1 FROM v3_migration_recovery_events WHERE generation=$1 AND notification_state IN ('unknown','verified_unsent')) OR EXISTS(SELECT 1 FROM v3_migration_recovery_notices WHERE generation=$1 AND resolution='unknown')`, generation).Scan(&blocked) != nil || blocked {
		return ErrMigrationRecovery
	}
	rows, err := tx.QueryContext(ctx, "SELECT target,remote_epoch,restored_epoch FROM v3_migration_recovery_nodes WHERE generation=$1 ORDER BY node COLLATE \"C\"", generation)
	if err != nil {
		return ErrMigrationRecovery
	}
	type member struct {
		target migrationRecoveryTarget
		floor  int64
	}
	members := []member{}
	for rows.Next() {
		var raw []byte
		var remote, restored int64
		var m member
		if rows.Scan(&raw, &remote, &restored) != nil || json.Unmarshal(raw, &m.target) != nil || remote >= math.MaxInt64 || restored >= math.MaxInt64 {
			rows.Close()
			return ErrMigrationRecovery
		}
		m.floor = max(remote, restored)
		members = append(members, m)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ErrMigrationRecovery
	}
	for _, member := range members {
		current, err := migrationRecoveryTargetTx(ctx, tx, member.target.Node)
		if err != nil || !migrationRecoveryTargetEqual(current, member.target) {
			return ErrMigrationRecovery
		}
		var epoch int64
		if tx.QueryRowContext(ctx, "SELECT epoch FROM v3_leases WHERE resource=$1 FOR UPDATE", shardResource(current.Shard)).Scan(&epoch) != nil || epoch <= member.floor {
			return ErrMigrationRecovery
		}
	}
	// No target may have been inserted outside the frozen recovery inventory.
	if tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_nodes n WHERE removed_at IS NULL AND NOT EXISTS(SELECT 1 FROM v3_migration_recovery_nodes r WHERE r.generation=$1 AND r.node=n.id))", generation).Scan(&blocked) != nil || blocked {
		return ErrMigrationRecovery
	}
	events, err := tx.QueryContext(ctx, "SELECT node,id,payload,canonical_sha256,notification_state FROM v3_migration_recovery_events WHERE generation=$1 AND NOT published ORDER BY node COLLATE \"C\",id COLLATE \"C\"", generation)
	if err != nil {
		return ErrMigrationRecovery
	}
	type event struct {
		node, id, sha, state string
		payload              []byte
	}
	pending := []event{}
	for events.Next() {
		var item event
		if events.Scan(&item.node, &item.id, &item.payload, &item.sha, &item.state) != nil {
			events.Close()
			return ErrMigrationRecovery
		}
		pending = append(pending, item)
		if len(pending) > 1000000 {
			events.Close()
			return ErrMigrationRecovery
		}
	}
	err = events.Err()
	events.Close()
	if err != nil {
		return ErrMigrationRecovery
	}
	for _, item := range pending {
		var p common.Map
		if json.Unmarshal(item.payload, &p) != nil {
			return ErrMigrationRecovery
		}
		canonical, sha, err := canonicalEvent(p)
		if err != nil || sha != item.sha || common.S(p["node_id"]) != item.node || common.S(p["event_id"]) != item.id {
			return ErrMigrationRecovery
		}
		if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,773376010))", item.node); err != nil {
			return ErrMigrationRecovery
		}
		var old string
		err = tx.QueryRowContext(ctx, "SELECT digest FROM v3_event_keys WHERE node=$1 AND id=$2", item.node, item.id).Scan(&old)
		if err != nil && err != sql.ErrNoRows || err == nil && old != sha {
			return ErrMigrationRecovery
		}
		if err == sql.ErrNoRows {
			// New recovered events receive canonical receipts before any later normal
			// Agent replay. This prevents replay from generating duplicate notices.
			if _, err = tx.ExecContext(ctx, "INSERT INTO v3_event_keys(node,id,digest,received_at,digest_format) VALUES($1,$2,$3,clock_timestamp(),'canonical-v1')", item.node, item.id, sha); err != nil {
				return ErrMigrationRecovery
			}
			var removed bool
			if tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_event_history_tombstones WHERE node=$1 AND event_id=$2 AND digest=$3)", item.node, item.id, sha).Scan(&removed) != nil {
				return ErrMigrationRecovery
			}
			if !removed {
				security := common.S(canonical["operation"]) == "scan" && common.S(common.M(canonical["scan"])["status"]) == "matched"
				if _, err = tx.ExecContext(ctx, "INSERT INTO v3_events SELECT node,id,received_at,$3,$4,$5 FROM v3_event_keys WHERE node=$1 AND id=$2", item.node, item.id, common.S(canonical["operation"]), security, common.JSON(canonical)); err != nil {
					return ErrMigrationRecovery
				}
			}
		}
		if _, err = tx.ExecContext(ctx, "UPDATE v3_migration_recovery_events SET published=true WHERE generation=$1 AND node=$2 AND id=$3", generation, item.node, item.id); err != nil {
			return ErrMigrationRecovery
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_migration_recovery_state SET phase='complete' WHERE id=1 AND generation=$1", generation); err != nil {
		return ErrMigrationRecovery
	}
	result, err := tx.ExecContext(ctx, "UPDATE v3_migration_domains SET pending=false WHERE domain='disaster-recovery' AND source=$1 AND pending", generation)
	if err != nil {
		return ErrMigrationRecovery
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrMigrationRecovery
	}
	return nil
}

// Explicit administrator suppression is a truthful resolution for ambiguous
// delivery. It never marks a message delivered or initiates an external send.
// No HTTP endpoint exposes this private host-maintenance action.
func (s *Store) SuppressMigrationRecoveryNotifications(ctx context.Context, generation, actor string) error {
	if !identifier.MatchString(actor) {
		return ErrMigrationRecovery
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrMigrationRecovery
	}
	defer tx.Rollback()
	if _, err = migrationRecoveryLock(ctx, tx, generation); err != nil {
		return err
	}
	var role string
	if tx.QueryRowContext(ctx, "SELECT role FROM v3_accounts WHERE username=$1 FOR SHARE", actor).Scan(&role) != nil || role != "admin" {
		return ErrMigrationRecovery
	}
	proof := digest([]byte("explicit-admin-suppression:" + generation + ":" + actor + ":" + time.Now().UTC().Format(time.RFC3339Nano)))
	if _, err = tx.ExecContext(ctx, "UPDATE v3_migration_recovery_events SET notification_state='suppressed',notification_proof=$2 WHERE generation=$1 AND notification_state='unknown'", generation, proof); err != nil {
		return ErrMigrationRecovery
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_migration_recovery_notices SET resolution='suppressed',proof=$2 WHERE generation=$1 AND resolution='unknown'", generation, proof); err != nil {
		return ErrMigrationRecovery
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,$2,$3,$4)", actor, "migration-recovery-notification-suppression", generation, common.JSON(common.Map{"proof_sha256": proof, "delivery_status": "not_claimed"})); err != nil {
		return ErrMigrationRecovery
	}
	if err = tx.Commit(); err != nil {
		return ErrMigrationRecovery
	}
	return nil
}
