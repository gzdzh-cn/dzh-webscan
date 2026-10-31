package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"webscan/internal/nodepki"
)

func checkRootTaskBindingsTx(ctx context.Context, tx *sql.Tx, c Config, v *Vault, j rootRotationTask) error {
	if j.Configuration != rootConfigDigest(c) || !time.Now().Before(j.ExpiresAt) {
		return errRootRotationTask
	}
	actor, err := deploymentPreviewAccount(ctx, tx, j.User)
	if err != nil || actor != j.ActorRevision {
		return errRootRotationTask
	}
	if held, err := migrationHeld(ctx, tx); err != nil {
		return err
	} else if held {
		return ErrMigrationPending
	}
	anchor, err := readTrustData(c.Collector.CAFile, false, 64<<10)
	if err != nil || !bytes.Equal(j.Anchor, anchor) {
		return errRootRotationTask
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_node_runtime`).Scan(&count); err != nil {
		return err
	}
	expected := 0
	for _, m := range j.Members {
		if m.Role == nodepki.Collector {
			continue
		}
		if m.Role != nodepki.Node {
			return errRootRotationTask
		}
		expected++
		var snapshot string
		var epoch int64
		var raw, config []byte
		var same bool
		err := tx.QueryRowContext(ctx, `SELECT r.snapshot,r.epoch,to_jsonb(c),c.config,r.epoch=n.runtime_generation AND r.delivered_version=n.version AND n.applied_version=n.version AND ROW(n.version,n.name,n.endpoint,n.server_name,n.enabled,n.mode,n.shard,n.config)=ROW(c.version,c.name,c.endpoint,c.server_name,c.enabled,c.mode,c.shard,c.config) FROM v3_node_runtime r JOIN v3_nodes n ON n.id=r.node JOIN v3_node_configurations c ON c.node=r.node AND c.id=r.snapshot WHERE r.node=$1 AND n.removed_at IS NULL FOR SHARE OF n,c`, m.ID).Scan(&snapshot, &epoch, &raw, &config, &same)
		if err != nil || !same || snapshot != m.Snapshot || epoch != m.RuntimeEpoch || digest(raw) != m.NodeDigest || digest(config) != m.Configuration {
			return errRootRotationTask
		}
		proof, err := provisioningCredentialTx(ctx, tx, v, m.Credential, m.ID)
		if err != nil || proof != m.CredentialProof {
			return errRootRotationTask
		}
		if err := requireNodeSnapshotAvailableTx(ctx, tx, m.ID, m.Snapshot); err != nil {
			return err
		}
	}
	if expected != count {
		return errRootRotationTask
	}
	return nil
}

// All checkpoints are authenticated as a complete document, including public
// requests, certificates and observations. SQL state alone cannot authorize a
// new target, fake confirmation or replacement issuance after response loss.
func (s *Store) rootTaskCheckpoint(ctx context.Context, c Config, v *Vault, l Lease, prior rootRotationTask, change func(*rootRotationTask, *sql.Tx) error) (rootRotationTask, error) {
	var empty rootRotationTask
	if l.Resource != "pki-root-rotation" || change == nil {
		return empty, errRootRotationTask
	}
	ctx = rootTaskContext(ctx, prior.ID)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := lockConfigurationOperationTx(ctx, tx, true); err != nil {
		return empty, err
	}
	j, hold, err := scanRootTask(tx.QueryRowContext(ctx, `SELECT `+rootTaskColumns+` FROM v3_root_rotations WHERE id=$1 FOR UPDATE`, prior.ID), v)
	if err != nil || hold || j.Revision != prior.Revision || j.Status == "completed" || j.Status == "canceled" {
		return empty, errRootRotationTask
	}
	if err := checkRootTaskBindingsTx(ctx, tx, c, v, j); err != nil {
		return empty, err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return empty, err
	}
	if err := change(&j, tx); err != nil {
		return empty, err
	}
	j.Revision++
	raw, err := json.Marshal(j)
	if err != nil || len(raw) > 32<<20 {
		return empty, errRootRotationTask
	}
	proof, err := rootTaskMAC(v, v.active, raw)
	if err != nil {
		return empty, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v3_root_rotations SET revision=$2,document=$3,key_id=$4,proof=$5,status=$6,updated_at=clock_timestamp() WHERE id=$1`, j.ID, j.Revision, raw, v.active, proof, j.Status); err != nil {
		return empty, err
	}
	metadata, _ := json.Marshal(map[string]any{"id": j.ID, "revision": j.Revision, "status": j.Status})
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'root-rotation-checkpoint',$2,$3)`, j.User, j.ID, metadata); err != nil {
		return empty, err
	}
	if err := advanceConfigurationOperationTx(ctx, tx); err != nil {
		return empty, err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return empty, err
	}
	return j, tx.Commit()
}

func (s *Store) checkRootTask(ctx context.Context, c Config, v *Vault, l Lease, id string) (rootRotationTask, error) {
	var empty rootRotationTask
	ctx = rootTaskContext(ctx, id)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := lockConfigurationOperationTx(ctx, tx, false); err != nil {
		return empty, err
	}
	j, err := s.authorizedRootTaskTx(ctx, tx, c, v, l, id, false)
	if err != nil {
		return empty, err
	}
	return j, tx.Commit()
}

func (s *Store) authorizedRootTaskTx(ctx context.Context, tx *sql.Tx, c Config, v *Vault, l Lease, id string, completedHeartbeat bool) (rootRotationTask, error) {
	j, hold, err := scanRootTask(tx.QueryRowContext(ctx, `SELECT `+rootTaskColumns+` FROM v3_root_rotations WHERE id=$1 FOR SHARE`, id), v)
	if err != nil || hold || j.Status == "canceled" || j.Status == "completed" && !completedHeartbeat || l.Resource != "pki-root-rotation" {
		return rootRotationTask{}, errRootRotationTask
	}
	if err := checkRootTaskBindingsTx(ctx, tx, c, v, j); err != nil {
		return rootRotationTask{}, err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return rootRotationTask{}, err
	}
	return j, nil
}

func (s *Store) renewRootTaskLease(ctx context.Context, c Config, v *Vault, l Lease, id string) error {
	ctx = rootTaskContext(ctx, id)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockConfigurationOperationTx(ctx, tx, false); err != nil {
		return err
	}
	// Completion can commit just before the last heartbeat. Keep its exact
	// live fence until the runner exits, without allowing further host work.
	j, err := s.authorizedRootTaskTx(ctx, tx, c, v, l, id, true)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE v3_leases SET expires_at=LEAST(clock_timestamp()+interval '30 seconds',$4) WHERE resource=$1 AND owner=$2 AND epoch=$3 AND expires_at>clock_timestamp()`, l.Resource, l.Owner, l.Epoch, j.ExpiresAt)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrLeaseLost
	}
	return tx.Commit()
}
