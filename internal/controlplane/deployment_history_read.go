package controlplane

import (
	"context"
	"database/sql"
	"time"
)

type deploymentHistoryRecord struct {
	DeploymentJob
	RecordKey    string `json:"record_key"`
	CanDelete    bool   `json:"can_delete"`
	DeleteReason string `json:"delete_reason"`
}

type deploymentHistoryDeleteState struct {
	ID, Node, Digest, Reason string
}

// Evaluate the entire selected page in one bounded query. Raw SQL flags are
// deliberate: scanDeployment normalizes a legacy terminal recovery flag for
// display, which cannot authorize destructive history cleanup.
const deploymentHistoryProtectionSQL = `CASE
 WHEN d.id IS NULL THEN '任务不存在'
 WHEN EXISTS(SELECT 1 FROM v3_deployment_history_archives a WHERE a.deployment=d.id) THEN '页面历史已删除'
 WHEN d.status NOT IN ('succeeded','rolled_back') THEN '任务尚未完成，请先继续或回退'
 WHEN d.recovery_required THEN '任务仍保留恢复责任'
 WHEN d.lease_until>clock_timestamp() THEN '任务仍有有效执行租约'
 WHEN d.finished_at IS NULL OR d.finished_at>clock_timestamp()-interval '24 hours' THEN '最近24小时或完成时间未知的任务受保护'
 WHEN EXISTS(SELECT 1 FROM v3_root_rotations WHERE status NOT IN ('completed','canceled')) THEN '证书换根尚未完成'
 WHEN EXISTS(SELECT 1 FROM v3_configuration_applications WHERE status IN ('queued','running') OR recovery_required OR recovery_hold AND status NOT IN ('succeeded','rolled_back','cancelled')) THEN '配置应用或恢复尚未完成'
 WHEN EXISTS(SELECT 1 FROM v3_configuration_restore_stages WHERE status IN ('pending_validation','pending_application')) THEN '配置恢复尚未完成'
 WHEN d.id=(SELECT h.id FROM v3_deployment_jobs h WHERE h.node=d.node ORDER BY h.created_at DESC,h.id DESC LIMIT 1) THEN '该节点最新部署任务受保护'
 WHEN d.id=(SELECT h.id FROM v3_deployment_jobs h WHERE h.node=d.node AND h.status='succeeded' ORDER BY h.created_at DESC,h.id DESC LIMIT 1) THEN '该任务仍为当前升级基线'
 WHEN EXISTS(SELECT 1 FROM v3_node_runtime r WHERE r.node=d.node AND r.snapshot=d.plan->>'target_runtime') THEN '该任务仍关联当前运行配置'
 WHEN EXISTS(SELECT 1 FROM v3_deployment_recoveries r WHERE r.job=d.id OR r.source=d.id OR r.head=d.id) THEN '历史恢复链引用该任务'
 WHEN EXISTS(SELECT 1 FROM v3_deployment_uninstalls u WHERE u.job=d.id OR u.source=d.id) THEN '卸载或恢复流程引用该任务'
 WHEN EXISTS(SELECT 1 FROM v3_deployment_lifecycle_receipts r WHERE r.job=d.id) THEN '卸载或恢复回执引用该任务'
 WHEN EXISTS(SELECT 1 FROM v3_deployment_lifecycle_authorizations a WHERE a.job=d.id OR a.source=d.id) THEN '生命周期恢复授权引用该任务'
 WHEN EXISTS(SELECT 1 FROM v3_node_lifecycle l WHERE l.job=d.id) THEN '节点生命周期状态引用该任务'
 WHEN EXISTS(SELECT 1 FROM v3_web_uninstall_credentials c WHERE c.source=d.id) THEN '卸载恢复凭据引用该任务'
 WHEN EXISTS(SELECT 1 FROM v3_configuration_application_nodes c WHERE c.child=d.id) THEN '配置应用任务引用该记录'
 WHEN EXISTS(SELECT 1 FROM v3_monitoring_application_nodes m WHERE m.child=d.id) THEN '公共监控规则任务引用该记录'
 WHEN EXISTS(SELECT 1 FROM v3_monitoring_application_nodes m WHERE m.node=d.node AND m.reserved) THEN '公共监控规则正在保留该节点'
 WHEN EXISTS(SELECT 1 FROM v3_deployment_jobs h WHERE h.node=d.node AND (h.status NOT IN ('succeeded','rolled_back') OR h.recovery_required OR h.lease_until>clock_timestamp())) THEN '节点存在未结算部署'
 WHEN EXISTS(SELECT 1 FROM v3_configuration_backup_pins p WHERE p.reference='job:'||d.id AND p.kind IN ('deployment','rollback') AND (p.expires_at IS NULL OR p.expires_at>clock_timestamp())) THEN '部署恢复备份仍引用该任务'
 WHEN EXISTS(SELECT 1 FROM v3_deployment_previews p WHERE p.expires_at>clock_timestamp() AND (p.job=d.id OR p.node=d.node AND p.job IS NULL)) THEN '有效部署预览仍引用该节点或任务'
 WHEN EXISTS(SELECT 1 FROM v3_deployment_preparations p WHERE p.node=d.node AND (p.status IN ('queued','running') OR p.status='succeeded' AND p.kind IN ('prepare','confirm') AND p.expires_at>clock_timestamp())) THEN '节点部署准备尚未结算'
 WHEN EXISTS(SELECT 1 FROM v3_node_renewal_jobs r WHERE r.node=d.node AND r.activated_at IS NULL) THEN '节点证书续期尚未完成'
 WHEN EXISTS(SELECT 1 FROM v3_node_identity_recoveries r WHERE r.node=d.node AND r.status NOT IN ('completed','canceled')) THEN '节点身份恢复尚未结算'
 WHEN EXISTS(SELECT 1 FROM v3_node_name_changes r WHERE r.node=d.node AND r.status NOT IN ('completed','canceled')) THEN '节点名称变更尚未结算'
 WHEN EXISTS(SELECT 1 FROM v3_node_name_prunings r WHERE r.node=d.node AND r.status NOT IN ('completed','canceled')) THEN '节点旧名称裁剪尚未结算'
 WHEN EXISTS(SELECT 1 FROM v3_deployment_history_delete_items i WHERE i.deployment=d.id AND i.status='pending' AND i.job<>$2) THEN '另一个历史删除任务处理中'
 ELSE '' END`

func deploymentHistoryDeleteStatesTx(ctx context.Context, tx *sql.Tx, ids []string, except string) (map[string]deploymentHistoryDeleteState, error) {
	rows, err := tx.QueryContext(ctx, `SELECT selected.id,coalesce(d.node,''),coalesce(to_jsonb(d),'null'::jsonb),`+deploymentHistoryProtectionSQL+`
 FROM unnest($1::text[]) selected(id) LEFT JOIN v3_deployment_jobs d ON d.id=selected.id ORDER BY selected.id`, ids, except)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]deploymentHistoryDeleteState, len(ids))
	for rows.Next() {
		var v deploymentHistoryDeleteState
		var raw []byte
		if err = rows.Scan(&v.ID, &v.Node, &raw, &v.Reason); err != nil {
			return nil, err
		}
		v.Digest = digest(raw)
		out[v.ID] = v
	}
	return out, rows.Err()
}

func deploymentHistoryDeleteStateTx(ctx context.Context, tx *sql.Tx, id string) (deploymentHistoryDeleteState, error) {
	states, err := deploymentHistoryDeleteStatesTx(ctx, tx, []string{id}, "")
	return states[id], err
}

func deploymentHistoryDeleteProtectionTx(ctx context.Context, tx *sql.Tx, j DeploymentJob) (string, error) {
	state, err := deploymentHistoryDeleteStateTx(ctx, tx, j.ID)
	return state.Reason, err
}

func decorateDeploymentHistoryTx(ctx context.Context, tx *sql.Tx, jobs []DeploymentJob, administrator bool) ([]deploymentHistoryRecord, error) {
	out := make([]deploymentHistoryRecord, len(jobs))
	ids := make([]string, len(jobs))
	for i, job := range jobs {
		ids[i] = job.ID
		out[i] = deploymentHistoryRecord{DeploymentJob: job, RecordKey: "deployment-job:" + job.ID, DeleteReason: "需要管理员权限"}
	}
	if !administrator || len(jobs) == 0 {
		return out, nil
	}
	states, err := deploymentHistoryDeleteStatesTx(ctx, tx, ids, "")
	if err != nil {
		return nil, err
	}
	var held bool
	if held, err = migrationHeld(ctx, tx); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].DeleteReason = states[out[i].ID].Reason
		if held {
			out[i].DeleteReason = "数据迁移尚未完成"
		}
		out[i].CanDelete = out[i].DeleteReason == ""
	}
	return out, nil
}

// Public wrappers never alter the executor's unfiltered journal access.
func (s *Store) publicDeployments(ctx context.Context, before time.Time, beforeID, node string, limit int, administrator bool) ([]deploymentHistoryRecord, error) {
	if limit < 1 || limit > 200 || node != "" && !identifier.MatchString(node) || beforeID != "" && !identifier.MatchString(beforeID) {
		return nil, errDeploymentHistoryDeleteInput
	}
	if before.IsZero() {
		before = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs d WHERE (created_at,id)<($1,$2) AND ($3='' OR node=$3) AND NOT EXISTS(SELECT 1 FROM v3_deployment_history_archives a WHERE a.deployment=d.id) ORDER BY created_at DESC,id DESC LIMIT $4`, before, beforeID, node, limit)
	if err != nil {
		return nil, err
	}
	jobs := []DeploymentJob{}
	for rows.Next() {
		job, e := scanDeployment(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		jobs = append(jobs, job)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out, err := decorateDeploymentHistoryTx(ctx, tx, jobs, administrator)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func publicDeploymentTx(ctx context.Context, tx *sql.Tx, id string, administrator bool) (deploymentHistoryRecord, error) {
	j, err := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs d WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM v3_deployment_history_archives a WHERE a.deployment=d.id)`, id))
	if err != nil {
		return deploymentHistoryRecord{}, err
	}
	items, err := decorateDeploymentHistoryTx(ctx, tx, []DeploymentJob{j}, administrator)
	if err != nil {
		return deploymentHistoryRecord{}, err
	}
	return items[0], nil
}

func (s *Store) publicDeployment(ctx context.Context, id string, administrator bool) (deploymentHistoryRecord, error) {
	job, _, err := s.publicDeploymentLogs(ctx, id, 0, 0, administrator)
	return job, err
}

func (s *Store) publicDeploymentLogs(ctx context.Context, id string, after int64, limit int, administrator bool) (deploymentHistoryRecord, []DeploymentLog, error) {
	var empty deploymentHistoryRecord
	if !identifier.MatchString(id) || after < 0 || limit < 0 || limit > 200 {
		return empty, nil, errDeploymentHistoryDeleteInput
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return empty, nil, err
	}
	defer tx.Rollback()
	job, err := publicDeploymentTx(ctx, tx, id, administrator)
	if err != nil {
		return empty, nil, err
	}
	logs := []DeploymentLog{}
	if limit > 0 {
		rows, e := tx.QueryContext(ctx, `SELECT cursor,phase,code,created_at FROM v3_deployment_logs WHERE job=$1 AND cursor>$2 ORDER BY cursor LIMIT $3`, id, after, limit)
		if e != nil {
			return empty, nil, e
		}
		for rows.Next() {
			var line DeploymentLog
			if e = rows.Scan(&line.Cursor, &line.Phase, &line.Code, &line.CreatedAt); e != nil {
				rows.Close()
				return empty, nil, e
			}
			logs = append(logs, line)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return empty, nil, e
		}
	}
	return job, logs, tx.Commit()
}
