package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"

	"webscan/internal/common"
)

func migrationNodeActivationImagesTx(ctx context.Context, tx *sql.Tx, session string, v *Vault) (map[string]string, error) {
	rows, e := tx.QueryContext(ctx, `SELECT node,source,key_id,nonce,ciphertext FROM v3_migration_node_activations WHERE session=$1 ORDER BY node`, session)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var node, source, key string
		var nonce, sealed []byte
		if e = rows.Scan(&node, &source, &key, &nonce, &sealed); e != nil {
			return nil, e
		}
		raw, e := migrationNodesOpen(v, key, "activation:"+session+":"+node, nonce, sealed)
		if e != nil {
			return nil, e
		}
		var proof migrationNodeActivation
		e = singleDecode(raw, &proof)
		clear(raw)
		if e != nil || proof.Node != node || proof.Source != source || proof.Before.ID != node || proof.After.ID != node || proof.Before.Enabled || !proof.After.Enabled || !proof.Evidence.MatchesSaved || proof.Evidence.Status != "observed" || len(proof.Images) != 4 {
			return nil, ErrMigrationSession
		}
		before, after := proof.Before, proof.After
		after.Enabled = before.Enabled
		after.AppliedVersion = before.AppliedVersion
		if !migrationNodeSame(before, after) {
			return nil, ErrMigrationSession
		}
		for identity, table := range proof.Images {
			if len(identity) != 129 || identity[64] != ':' || !releaseDigest(identity[:64]) || !releaseDigest(identity[65:]) {
				return nil, ErrMigrationSession
			}
			switch table {
			case "v3_nodes", "v3_node_configurations", "v3_node_runtime":
			default:
				return nil, ErrMigrationSession
			}
			if previous, ok := out[identity]; ok && previous != table {
				return nil, ErrMigrationSession
			}
			out[identity] = table
		}
	}
	return out, rows.Err()
}

type migrationNodeActivationTarget struct {
	Version    int64  `json:"version"`
	ConfigSHA  string `json:"config_sha256"`
	Endpoint   string `json:"endpoint"`
	ServerName string `json:"server_name"`
}

func migrationNodeActivationTargetsTx(ctx context.Context, tx *sql.Tx, session string, v *Vault) (map[string]migrationNodeActivationTarget, error) {
	rows, e := tx.QueryContext(ctx, `SELECT node,key_id,nonce,ciphertext FROM v3_migration_node_activations WHERE session=$1`, session)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]migrationNodeActivationTarget{}
	for rows.Next() {
		var node, key string
		var nonce, sealed []byte
		if e = rows.Scan(&node, &key, &nonce, &sealed); e != nil {
			return nil, e
		}
		raw, e := migrationNodesOpen(v, key, "activation:"+session+":"+node, nonce, sealed)
		if e != nil {
			return nil, e
		}
		var proof migrationNodeActivation
		e = singleDecode(raw, &proof)
		clear(raw)
		if e != nil || proof.Node != node {
			return nil, ErrMigrationSession
		}
		n := proof.After
		out[node] = migrationNodeActivationTarget{n.Version, digest(n.Config), n.Endpoint, n.ServerName}
	}
	return out, rows.Err()
}

// Authorization is an explicit private host operation before target replay. It
// only imports encrypted mechanically generated images, never arbitrary keys.
func (s *Store) AuthorizeMigrationLegacyNodeActivations(ctx context.Context, session string, sink *MigrationLegacySink, v *Vault) error {
	if sink == nil || sink.session != session || v == nil {
		return ErrMigrationSession
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = migrationSessionLock(ctx, tx, session); e != nil {
		return e
	}
	images, e := migrationNodeActivationImagesTx(ctx, tx, session, v)
	if e != nil {
		return e
	}
	targets, e := migrationNodeActivationTargetsTx(ctx, tx, session, v)
	if e != nil {
		return e
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	local, e := sink.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer local.Rollback()
	if _, e = local.ExecContext(ctx, `DELETE FROM migration_node_activation_images`); e != nil {
		return e
	}
	for key, table := range images {
		if _, e = local.ExecContext(ctx, `INSERT INTO migration_node_activation_images(identity,table_name) VALUES(?,?)`, key, table); e != nil {
			return e
		}
	}
	if _, e = local.ExecContext(ctx, `DELETE FROM migration_node_activation_targets`); e != nil {
		return e
	}
	for node, target := range targets {
		if _, e = local.ExecContext(ctx, `INSERT INTO migration_node_activation_targets(node,payload) VALUES(?,?)`, node, string(common.JSON(target))); e != nil {
			return e
		}
	}
	if e = local.Commit(); e != nil {
		return e
	}
	return tx.Commit()
}
func VerifyMigrationLegacyNodeActivationsTx(ctx context.Context, tx *sql.Tx, session string, sink *MigrationLegacySink, v *Vault) error {
	if sink == nil || sink.session != session {
		return ErrMigrationSession
	}
	expected, e := migrationNodeActivationImagesTx(ctx, tx, session, v)
	if e != nil {
		return e
	}
	targets, e := migrationNodeActivationTargetsTx(ctx, tx, session, v)
	if e != nil {
		return e
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	rows, e := sink.db.QueryContext(ctx, `SELECT identity,table_name FROM migration_node_activation_images`)
	if e != nil {
		return e
	}
	defer rows.Close()
	actual := map[string]string{}
	for rows.Next() {
		var key, table string
		if e = rows.Scan(&key, &table); e != nil {
			return e
		}
		actual[key] = table
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if !reflect.DeepEqual(expected, actual) {
		return ErrMigrationCutoverProtected
	}
	rows.Close()
	targetRows, e := sink.db.QueryContext(ctx, `SELECT node,payload FROM migration_node_activation_targets`)
	if e != nil {
		return e
	}
	defer targetRows.Close()
	actualTargets := map[string]migrationNodeActivationTarget{}
	for targetRows.Next() {
		var node, payload string
		var target migrationNodeActivationTarget
		if e = targetRows.Scan(&node, &payload); e != nil {
			return e
		}
		if json.Unmarshal([]byte(payload), &target) != nil {
			return ErrMigrationSession
		}
		actualTargets[node] = target
	}
	if e = targetRows.Err(); e != nil {
		return e
	}
	if !reflect.DeepEqual(targets, actualTargets) {
		return ErrMigrationCutoverProtected
	}
	return nil
}
func migrationLegacyActivationImageTx(ctx context.Context, tx *sql.Tx, row MigrationTargetReplayRow, data common.Map) (bool, error) {
	switch row.Table {
	case "v3_nodes", "v3_node_configurations", "v3_node_runtime":
	default:
		return false, nil
	}
	if row.Operation == "DELETE" {
		return false, nil
	}
	parsed, e := common.Decode(row.AfterKey)
	if e != nil {
		return false, e
	}
	key := migrationLegacySourceKey(row.Table, common.M(parsed)) + ":" + digest(common.JSON(data))
	var table string
	e = tx.QueryRowContext(ctx, `SELECT table_name FROM migration_node_activation_images WHERE identity=?`, key).Scan(&table)
	if e == sql.ErrNoRows {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	return strings.EqualFold(table, row.Table), nil
}
