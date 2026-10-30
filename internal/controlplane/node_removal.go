package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
)

var errNodeRemovalInput = errors.New("请选择当前页 1～200 台不重复的服务器，并确认仅移除记录")

// Shared by the console and the committing transaction. Offline nodes do not
// require SSH; an unfinished remote operation still owns its recovery record.
const nodeRemovalReasonSQL = `CASE
 WHEN n.id='central' THEN '中心节点不能从服务器列表移除'
 WHEN EXISTS(SELECT 1 FROM v3_websites WHERE node=n.id AND NOT deleted) THEN '仍有关联网站，请先调整网站的服务器关联'
 WHEN EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=n.id AND (status IN ('queued','running') OR recovery_required)) THEN '存在未完成部署，请先继续或回退原任务'
 WHEN EXISTS(SELECT 1 FROM v3_deployment_preparations WHERE node=n.id AND status IN ('queued','running') AND expires_at>clock_timestamp()) THEN '部署准备正在进行，请等待完成或过期'
 WHEN EXISTS(SELECT 1 FROM v3_node_identity_recoveries WHERE node=n.id AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp())
   OR EXISTS(SELECT 1 FROM v3_node_name_changes WHERE node=n.id AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp())
   OR EXISTS(SELECT 1 FROM v3_node_name_prunings WHERE node=n.id AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) THEN '证书维护任务未完成，请先完成或取消原任务'
 ELSE '' END`

type nodeRemovalRecord struct {
	ID      string `json:"id"`
	Version int64  `json:"expected_version"`
}

type nodeRemovalBlocked struct{ Reason string }

func (e *nodeRemovalBlocked) Error() string { return e.Reason }

func (s *Store) removeNodes(ctx context.Context, user, key string, records []nodeRemovalRecord, confirm bool, before *configurationEditBackup) (json.RawMessage, error) {
	if !confirm || len(records) < 1 || len(records) > 200 {
		return nil, errNodeRemovalInput
	}
	records = append([]nodeRemovalRecord(nil), records...)
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	for i, r := range records {
		if !identifier.MatchString(r.ID) || r.ID == "central" || r.Version < 1 || i > 0 && records[i-1].ID == r.ID {
			return nil, errNodeRemovalInput
		}
	}
	return s.guardedMutation(ctx, user, key, "remove-node-records", "servers", records, func(tx *sql.Tx) error {
		if err := lockWebsiteConfiguration(ctx, tx); err != nil {
			return err
		}
		if before == nil {
			if err := lockConfigurationRestoreStateTx(ctx, tx); err != nil {
				return err
			}
		} else if err := before.lock(ctx, tx, user); err != nil {
			return err
		}
		return configurationBackupAdmin(ctx, tx, user)
	}, func(tx *sql.Tx) (any, error) {
		// The website gate was acquired before node/configuration locks. Keep
		// associations stable through the final reference check and commit.
		if _, err := tx.ExecContext(ctx, `LOCK TABLE v3_websites IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return nil, err
		}
		for _, r := range records {
			var version int64
			if err := tx.QueryRowContext(ctx, `SELECT version FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR UPDATE`, r.ID).Scan(&version); err == sql.ErrNoRows {
				return nil, ErrConflict
			} else if err != nil {
				return nil, err
			}
			if version != r.Version {
				return nil, ErrConflict
			}
			var reason string
			if err := tx.QueryRowContext(ctx, `SELECT `+nodeRemovalReasonSQL+` FROM v3_nodes n WHERE n.id=$1`, r.ID).Scan(&reason); err != nil {
				return nil, err
			}
			if reason != "" {
				return nil, &nodeRemovalBlocked{Reason: reason}
			}
		}
		if err := before.capture(ctx, tx, user, "remove-node-records", "servers"); err != nil {
			return nil, err
		}
		for _, r := range records {
			if _, err := tx.ExecContext(ctx, `UPDATE v3_nodes SET enabled=false,version=version+1,runtime_generation=runtime_generation+1,removed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1`, r.ID); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM v3_node_runtime WHERE node=$1`, r.ID); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM v3_node_readiness WHERE node=$1`, r.ID); err != nil {
				return nil, err
			}
			if err := disableNodeHealthTx(ctx, tx, r.ID); err != nil {
				return nil, err
			}
		}
		return map[string]any{"removed": len(records), "records": records, "message": "服务器记录已移除，已停止采集；未远程卸载程序，历史数据已保留"}, nil
	})
}
