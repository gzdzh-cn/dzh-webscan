package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

const activeNodeColumns = nodeColumns + ",runtime_epoch"

type NodeConfigurationState struct {
	RegisteredVersion int64  `json:"registered_version"`
	DeliveredVersion  int64  `json:"delivered_version"`
	RuntimeEnabled    *bool  `json:"runtime_enabled"`
	RuntimeMode       string `json:"runtime_mode"`
	RuntimeEndpoint   string `json:"runtime_endpoint"`
}

const managedNodeRelations = `(SELECT * FROM v3_nodes WHERE removed_at IS NULL) n LEFT JOIN v3_node_runtime r ON r.node=n.id LEFT JOIN v3_node_configurations c ON c.node=r.node AND c.id=r.snapshot`

var managedNodeColumns = "n." + strings.ReplaceAll(nodeColumns, ",", ",n.") + ",COALESCE(c.version,0),COALESCE(r.delivered_version,0),c.enabled,COALESCE(c.mode,''),COALESCE(c.endpoint,''),(" + nodeRemovalReasonSQL + "='')," + nodeRemovalReasonSQL

func scanManagedNode(row interface{ Scan(...any) error }) (n Node, err error) {
	state := &NodeConfigurationState{}
	var enabled sql.NullBool
	err = row.Scan(&n.ID, &n.Name, &n.Endpoint, &n.ServerName, &n.Enabled, &n.Mode, &n.Version, &n.AppliedVersion, &n.Shard, &n.Config, &state.RegisteredVersion, &state.DeliveredVersion, &enabled, &state.RuntimeMode, &state.RuntimeEndpoint, &n.CanRemove, &n.RemoveReason)
	if enabled.Valid {
		state.RuntimeEnabled = &enabled.Bool
	}
	n.Configuration = state
	return
}

func scanActiveNode(row interface{ Scan(...any) error }) (n Node, err error) {
	err = row.Scan(&n.ID, &n.Name, &n.Endpoint, &n.ServerName, &n.Enabled, &n.Mode, &n.Version, &n.AppliedVersion, &n.Shard, &n.Config, &n.RuntimeEpoch)
	return
}

// Immutable snapshot IDs preserve a previous registration even when a trusted
// legacy setup changed a row without advancing its configuration version.
func captureSavedNodeTx(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	var snapshot string
	err := tx.QueryRowContext(ctx, `SELECT c.id FROM v3_node_configurations c JOIN v3_nodes n ON n.id=c.node
 WHERE n.id=$1 AND ROW(n.version,n.name,n.endpoint,n.server_name,n.enabled,n.mode,n.shard,n.config)=ROW(c.version,c.name,c.endpoint,c.server_name,c.enabled,c.mode,c.shard,c.config) ORDER BY c.id LIMIT 1`, id).Scan(&snapshot)
	if err == nil {
		return snapshot, nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	snapshot = token()
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_node_configurations(id,node,version,name,endpoint,server_name,enabled,mode,shard,config)
 SELECT $2,id,version,name,endpoint,server_name,enabled,mode,shard,config FROM v3_nodes WHERE id=$1`, id, snapshot)
	return snapshot, err
}

// Publishing is internal and transactional with an explicit registration or a
// verified deployment checkpoint. Saving public form input never calls it.
func publishNodeRuntimeTx(ctx context.Context, tx *sql.Tx, id, snapshot string, delivered int64) error {
	var epoch int64
	if err := tx.QueryRowContext(ctx, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1 WHERE id=$1 AND removed_at IS NULL RETURNING runtime_generation`, id).Scan(&epoch); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO v3_node_runtime(node,snapshot,epoch,delivered_version) VALUES($1,$2,$4,$3)
 ON CONFLICT(node) DO UPDATE SET snapshot=excluded.snapshot,epoch=excluded.epoch,delivered_version=excluded.delivered_version,updated_at=clock_timestamp()`, id, snapshot, delivered, epoch)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM v3_node_readiness WHERE node=$1`, id)
	if err != nil {
		return err
	}
	// An old endpoint's observation must not certify the newly published target.
	// Cursors and historical metrics remain intact; fresh collection repopulates
	// this current-status cache under the new runtime fence.
	if _, err = tx.ExecContext(ctx, `UPDATE v3_node_status SET sampled_at=NULL,metrics='{}',info='{}',error='',metrics_error='',events_error='',protocol_error='',updated_at=clock_timestamp() WHERE node=$1`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM v3_health_samples WHERE node=$1`, id); err != nil {
		return err
	}
	return disableRuntimeHealthTx(ctx, tx, id)
}

func disableRuntimeHealthTx(ctx context.Context, tx *sql.Tx, id string) error {
	var enabled bool
	if err := tx.QueryRowContext(ctx, `SELECT enabled FROM v3_active_nodes WHERE id=$1`, id).Scan(&enabled); err != nil {
		return err
	}
	if enabled {
		return nil
	}
	return disableNodeHealthTx(ctx, tx, id)
}

func disableNodeHealthTx(ctx context.Context, tx *sql.Tx, id string) error {
	for _, q := range []string{
		`UPDATE v3_health_rules SET phase='disabled' WHERE node=$1`,
		`UPDATE v3_health_outbox SET done_at=clock_timestamp(),result='监控已停用，取消待入队通知' WHERE node=$1 AND done_at IS NULL`,
		`UPDATE v3_health_batches SET done_at=clock_timestamp() WHERE node=$1 AND done_at IS NULL`,
		`DELETE FROM v3_health_samples WHERE node=$1`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return nil
}

type deploymentRuntimeBaseline struct {
	Snapshot  string `json:"snapshot"`
	Version   int64  `json:"version"`
	Delivered int64  `json:"delivered_version"`
	Digest    string `json:"digest"`
	Epoch     int64  `json:"epoch"`
}

// Only a version and private digest enter the task, never configuration text.
func runtimeBaselineTx(ctx context.Context, tx *sql.Tx, id string) (*deploymentRuntimeBaseline, error) {
	var b deploymentRuntimeBaseline
	var raw []byte
	var coherent bool
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(c.id,''),COALESCE(c.version,0),COALESCE(r.delivered_version,0),n.runtime_generation,COALESCE(to_jsonb(c),'null'::jsonb),r.node IS NULL OR r.epoch=n.runtime_generation FROM v3_nodes n LEFT JOIN v3_node_runtime r ON r.node=n.id LEFT JOIN v3_node_configurations c ON c.node=r.node AND c.id=r.snapshot WHERE n.id=$1 FOR SHARE OF n`, id).Scan(&b.Snapshot, &b.Version, &b.Delivered, &b.Epoch, &raw, &coherent)
	if err != nil {
		return nil, err
	}
	if !coherent {
		return nil, ErrConflict
	}
	if b.Snapshot != "" {
		b.Digest = digest(raw)
	}
	return &b, nil
}

func (s *Store) deploymentRuntimePhaseTx(ctx context.Context, tx *sql.Tx, j DeploymentJob, phase string) error {
	if j.Kind == "recover" || j.Plan.Recovery != nil {
		if err := checkRecoveryRuntimeTx(ctx, tx, j); err != nil {
			return err
		}
		if phase != "restore" {
			return nil
		}
		b := j.Plan.Recovery.Restore
		if b.Snapshot != "" {
			return publishNodeRuntimeTx(ctx, tx, j.Node, b.Snapshot, b.Delivered)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1 WHERE id=$1`, j.Node); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM v3_node_runtime WHERE node=$1`, j.Node); err != nil {
			return err
		}
		for _, q := range []string{
			`DELETE FROM v3_node_readiness WHERE node=$1`,
			`UPDATE v3_node_status SET sampled_at=NULL,metrics='{}',info='{}',error='',metrics_error='',events_error='',protocol_error='',updated_at=clock_timestamp() WHERE node=$1`,
			`DELETE FROM v3_health_samples WHERE node=$1`,
			`UPDATE v3_health_rules SET phase='disabled' WHERE node=$1`,
			`UPDATE v3_health_outbox SET done_at=clock_timestamp(),result='监控已停用，取消待入队通知' WHERE node=$1 AND done_at IS NULL`,
			`UPDATE v3_health_batches SET done_at=clock_timestamp() WHERE node=$1 AND done_at IS NULL`,
		} {
			if _, err := tx.ExecContext(ctx, q, j.Node); err != nil {
				return err
			}
		}
		return nil
	}
	if j.Plan.PreviousRuntime == nil {
		return nil // A legacy plan has no trustworthy earlier runtime snapshot.
	}
	if j.Direction == "forward" && phase == "activate" {
		current, err := runtimeBaselineTx(ctx, tx, j.Node)
		if err != nil {
			return err
		}
		if *current != *j.Plan.PreviousRuntime {
			return ErrConflict
		}
		var same bool
		if err = tx.QueryRowContext(ctx, `SELECT ROW(n.version,n.name,n.endpoint,n.server_name,n.enabled,n.mode,n.shard,n.config)=ROW(c.version,c.name,c.endpoint,c.server_name,c.enabled,c.mode,c.shard,c.config) FROM v3_nodes n JOIN v3_node_configurations c ON c.node=n.id AND c.id=$2 WHERE n.id=$1 FOR SHARE OF c`, j.Node, j.Plan.TargetRuntime).Scan(&same); err != nil {
			return err
		}
		if !same {
			return ErrConflict
		}
		return publishNodeRuntimeTx(ctx, tx, j.Node, j.Plan.TargetRuntime, j.NodeVersion)
	}
	if j.Direction != "rollback" || phase != "restore" {
		return nil
	}
	b := j.Plan.PreviousRuntime
	current, err := runtimeBaselineTx(ctx, tx, j.Node)
	if err != nil {
		return err
	}
	if !(*current == *b || current.Snapshot == j.Plan.TargetRuntime && current.Version == j.NodeVersion && current.Epoch == b.Epoch+1 && current.Delivered == j.NodeVersion) {
		return ErrConflict
	}
	if b.Version == 0 {
		// Failed first install has no original collection registration.
		if _, err = tx.ExecContext(ctx, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1 WHERE id=$1`, j.Node); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM v3_node_runtime WHERE node=$1`, j.Node); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM v3_node_readiness WHERE node=$1`, j.Node)
		return err
	}
	var raw json.RawMessage
	if err := tx.QueryRowContext(ctx, `SELECT to_jsonb(c) FROM v3_node_configurations c WHERE node=$1 AND id=$2 FOR SHARE`, j.Node, b.Snapshot).Scan(&raw); err != nil {
		return err
	}
	if digest(raw) != b.Digest {
		return ErrConflict
	}
	return publishNodeRuntimeTx(ctx, tx, j.Node, b.Snapshot, b.Delivered)
}

// Reconcile registration before remote work as well as in the checkpoint
// transaction. Response loss may leave the remote ahead, never the PG pointer.
func checkDeploymentRuntimeTx(ctx context.Context, tx *sql.Tx, j DeploymentJob) error {
	if j.Kind == "recover" || j.Plan.Recovery != nil {
		return checkRecoveryRuntimeTx(ctx, tx, j)
	}
	b := j.Plan.PreviousRuntime
	if b == nil {
		return nil
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT to_jsonb(c) FROM v3_node_configurations c WHERE node=$1 AND id=$2 FOR SHARE`, j.Node, j.Plan.TargetRuntime).Scan(&raw); err != nil {
		return err
	}
	if digest(raw) != j.Plan.TargetRuntimeDigest {
		return ErrConflict
	}
	if b.Snapshot != "" {
		if err := tx.QueryRowContext(ctx, `SELECT to_jsonb(c) FROM v3_node_configurations c WHERE node=$1 AND id=$2 FOR SHARE`, j.Node, b.Snapshot).Scan(&raw); err != nil {
			return err
		}
		if digest(raw) != b.Digest {
			return ErrConflict
		}
	}
	current, err := runtimeBaselineTx(ctx, tx, j.Node)
	if err != nil {
		return err
	}
	baseline := *current == *b
	target := current.Snapshot == j.Plan.TargetRuntime && current.Digest == j.Plan.TargetRuntimeDigest && current.Version == j.NodeVersion && current.Delivered == j.NodeVersion && current.Epoch == b.Epoch+1
	if j.Direction == "forward" {
		if j.Step < 4 && baseline || j.Step >= 4 && target {
			return nil
		}
		return ErrConflict
	}
	if j.RollbackStep == 0 {
		if baseline || target {
			return nil
		}
		return ErrConflict
	}
	if (current.Digest == b.Digest || b.Snapshot == "" && current.Digest == "") && current.Snapshot == b.Snapshot && current.Version == b.Version && current.Delivered == b.Delivered && (current.Epoch == b.Epoch+1 || current.Epoch == b.Epoch+2) {
		return nil
	}
	return ErrConflict
}
