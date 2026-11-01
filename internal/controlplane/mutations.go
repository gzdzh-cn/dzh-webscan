package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

var ErrRequestConflict = errors.New("幂等键已用于其他请求，请重新发起操作")

// SaveNode binds optimistic concurrency, idempotency and the audit record to
// one transaction. A retry gets the original response, even after later edits.
func (s *Store) SaveNode(ctx context.Context, username, key string, n Node, expected int64, shards int) (json.RawMessage, error) {
	// Trusted callers supply the complete private configuration themselves.
	// Monitoring is a decorated public read model on scanned nodes; replaying
	// it here must not overwrite an internal caller's new scan/resource config.
	n.Monitoring = nil
	return s.saveNode(ctx, username, key, n, expected, shards, nil)
}

func (s *Store) saveNode(ctx context.Context, username, key string, n Node, expected int64, shards int, before *configurationEditBackup) (json.RawMessage, error) {
	// None of these read-model fields grant write or runtime authority.
	n.Configuration = nil
	n.CanRemove = false
	n.RemoveReason = ""
	n.CanUninstall = false
	n.UninstallReason = ""
	n.Lifecycle = ""
	n.RuntimeEpoch = 0
	n.Version = 0
	n.AppliedVersion = 0
	n.Shard = 0
	if !identifier.MatchString(username) || !identifier.MatchString(key) || expected < 0 {
		return nil, errors.New("操作账号、幂等键或配置版本不正确")
	}
	if err := n.Validate(); err != nil {
		return nil, err
	}
	// Include only accepted request fields, not server-generated state or secrets.
	raw, err := json.Marshal(struct {
		Kind         string `json:"kind"`
		Node         Node   `json:"node"`
		Expected     int64  `json:"expected"`
		ConfigDigest string `json:"config_digest"`
	}{"save-node", n, expected, digest(n.Config)})
	if err != nil {
		return nil, err
	}
	hash := digest(raw)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return nil, err
	} else if held {
		return nil, ErrMigrationPending
	}
	if err = before.lock(ctx, tx, username); err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, "INSERT INTO v3_requests(username,key,request_hash,response) VALUES($1,$2,$3,'{}') ON CONFLICT DO NOTHING", username, key, hash)
	if err != nil {
		return nil, err
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if inserted == 0 {
		var old string
		var response json.RawMessage
		if err = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM v3_requests WHERE username=$1 AND key=$2", username, key).Scan(&old, &response); err != nil {
			return nil, err
		}
		if old != hash {
			return nil, ErrRequestConflict
		}
		return response, tx.Commit()
	}
	if expected > 0 {
		var version int64
		if err = tx.QueryRowContext(ctx, "SELECT version FROM v3_nodes WHERE id=$1 FOR UPDATE", n.ID).Scan(&version); err != nil {
			if err == sql.ErrNoRows {
				return nil, ErrConflict
			}
			return nil, err
		}
		if version != expected {
			return nil, ErrConflict
		}
		if err = checkMonitoringNodeReservationTx(ctx, tx, n.ID); err != nil {
			return nil, err
		}
		var busy bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND status NOT IN ('succeeded','rolled_back') AND (status IN ('queued','running') OR recovery_required)) OR EXISTS(SELECT 1 FROM v3_node_identity_recoveries WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_changes WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_prunings WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp())", n.ID).Scan(&busy); err != nil {
			return nil, err
		}
		if busy {
			return nil, ErrDeploymentBusy
		}
	}
	if err = before.capture(ctx, tx, username, "save-node", n.ID); err != nil {
		return nil, err
	}
	if before != nil || n.Monitoring != nil {
		var vault *Vault
		if before != nil {
			vault = before.vault
		}
		if err = prepareMonitoringNodeTx(ctx, tx, &n, expected, vault); err != nil {
			return nil, err
		}
	}
	if err = putNode(ctx, tx, n, expected, shards); err != nil {
		return nil, err
	}
	if _, err = captureSavedNodeTx(ctx, tx, n.ID); err != nil {
		return nil, err
	}

	var version int64
	if err = tx.QueryRowContext(ctx, "SELECT version FROM v3_nodes WHERE id=$1", n.ID).Scan(&version); err != nil {
		return nil, err
	}
	response, err := json.Marshal(map[string]any{"id": n.ID, "version": version, "message": "配置已保存，尚未部署"})
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_requests SET response=$3 WHERE username=$1 AND key=$2", username, key, []byte(response)); err != nil {
		return nil, err
	}
	// Auditing deliberately excludes node endpoint/configuration and credentials.
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'save-node',$2,$3)", username, n.ID, []byte(response)); err != nil {
		return nil, err
	}
	return response, tx.Commit()
}

// BindCluster prevents a changed shard count from silently changing lease
// resources. Topology transitions require a dedicated, backed-up migration.
func (s *Store) BindCluster(ctx context.Context, c Config) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(773376002)"); err != nil {
		return err
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT payload FROM v3_cluster WHERE id=1 FOR UPDATE").Scan(&raw)
	var saved struct {
		Topology string `json:"topology"`
		Shards   int    `json:"shards"`
	}
	if err == sql.ErrNoRows {
		saved.Topology, saved.Shards = c.Central.Topology, c.Collector.Shards
		raw, err = json.Marshal(saved)
		if err == nil {
			_, err = tx.ExecContext(ctx, "INSERT INTO v3_cluster VALUES(1,$1)", raw)
		}
	} else if err == nil {
		err = json.Unmarshal(raw, &saved)
	}
	if err != nil {
		return err
	}
	if saved.Topology != c.Central.Topology || saved.Shards != c.Collector.Shards {
		return errors.New("拓扑或分片数与已保存的集群不一致，请先执行专门迁移")
	}
	return tx.Commit()
}
