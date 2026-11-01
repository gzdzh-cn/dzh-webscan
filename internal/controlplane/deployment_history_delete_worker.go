package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"webscan/internal/common"
)

// One item per transaction: the tombstone, removed logs, item outcome, job
// counts and audit are atomic. Original task rows are never updated.
func (s *Store) deploymentHistoryDeleteBatch(ctx context.Context, lease Lease, id string) (deploymentHistoryDeleteJob, error) {
	var empty deploymentHistoryDeleteJob
	if lease.Resource != "retention" || !identifier.MatchString(id) {
		return empty, ErrLeaseLost
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err = deploymentHistoryDeleteGuardTx(ctx, tx); err != nil {
		return empty, err
	}
	if err = s.Fence(ctx, tx, lease); err != nil {
		return empty, err
	}
	j, err := scanDeploymentHistoryDeleteJob(tx.QueryRowContext(ctx, `SELECT `+deploymentHistoryDeleteColumns+` FROM v3_deployment_history_delete_jobs WHERE id=$1`, id))
	if err != nil {
		return j, err
	}
	if j.Status != "queued" && j.Status != "running" {
		return j, tx.Commit()
	}
	account, err := deploymentPreviewAccount(ctx, tx, j.Username)
	cancelReason := ""
	if errors.Is(err, ErrDeploymentPreview) || err == nil && account != j.Account {
		cancelReason = "账号权限或版本已变化，剩余记录需重新预览"
	} else if err != nil {
		return j, err
	}
	var originalStamp string
	if err = tx.QueryRowContext(ctx, `SELECT p.state_digest FROM v3_deployment_history_delete_previews p JOIN v3_deployment_history_delete_jobs j ON j.preview=p.id WHERE j.id=$1`, id).Scan(&originalStamp); err != nil {
		return j, err
	}
	_, _, currentStamp, err := deploymentHistoryConfigurationStateTx(ctx, tx)
	if err != nil {
		return j, err
	}
	if currentStamp != originalStamp {
		cancelReason = "配置已变化，保留已完成部分；剩余记录需重新预览"
	}
	j, err = scanDeploymentHistoryDeleteJob(tx.QueryRowContext(ctx, `SELECT `+deploymentHistoryDeleteColumns+` FROM v3_deployment_history_delete_jobs WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return j, err
	}
	j.Status = "running"
	if cancelReason != "" {
		res, err := tx.ExecContext(ctx, `UPDATE v3_deployment_history_delete_items SET status='skipped',reason=$2 WHERE job=$1 AND status='pending'`, id, cancelReason)
		if err != nil {
			return j, err
		}
		count, err := res.RowsAffected()
		if err != nil {
			return j, err
		}
		j.Skipped += int(count)
		j.Status, j.Message = "cancelled", cancelReason
	} else {
		var ordinal int
		var deployment, stamp string
		err = tx.QueryRowContext(ctx, `SELECT ordinal,deployment,state_digest FROM v3_deployment_history_delete_items WHERE job=$1 AND status='pending' ORDER BY ordinal LIMIT 1 FOR UPDATE`, id).Scan(&ordinal, &deployment, &stamp)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return j, err
		}
		if err == nil {
			if _, err = tx.ExecContext(ctx, `SAVEPOINT deployment_history_delete_item`); err != nil {
				return j, err
			}
			count, reason, deletionErr := deleteDeploymentHistoryItemTx(ctx, tx, j, deployment, stamp)
			status := "skipped"
			if deletionErr != nil {
				var pg *pgconn.PgError
				if ctx.Err() != nil || !errors.As(deletionErr, &pg) || !strings.HasPrefix(pg.Code, "23") && pg.Code != "P0001" {
					return j, deletionErr
				}
				if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT deployment_history_delete_item`); err != nil {
					return j, err
				}
				status, reason, count = "failed", "删除失败，原记录保留；请检查后重新预览", 0
				j.Failed++
			} else if reason == "" {
				status, reason = "deleted", deploymentHistoryDeleteMessage
				j.Deleted++
			} else {
				j.Skipped++
			}
			if _, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT deployment_history_delete_item`); err != nil {
				return j, err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE v3_deployment_history_delete_items SET status=$3,reason=$4,deleted_logs=$5 WHERE job=$1 AND ordinal=$2`, id, ordinal, status, reason, count); err != nil {
				return j, err
			}
		}
		j.Message = "正在逐条检查引用；已完成部分已保存"
		if j.Deleted+j.Skipped+j.Failed == j.Selected {
			j.Status, j.Message = "succeeded", deploymentHistoryDeleteMessage
			if j.Skipped+j.Failed > 0 {
				j.Status = "partial"
				j.Message = "部分完成，请查看逐项跳过或失败原因；未处理其他任务"
			}
		}
	}
	j, err = scanDeploymentHistoryDeleteJob(tx.QueryRowContext(ctx, `UPDATE v3_deployment_history_delete_jobs SET status=$2,deleted=$3,skipped=$4,failed=$5,message=$6,updated_at=clock_timestamp(),finished_at=CASE WHEN $2 IN ('succeeded','partial','cancelled') THEN clock_timestamp() ELSE NULL END WHERE id=$1 RETURNING `+deploymentHistoryDeleteColumns, id, j.Status, j.Deleted, j.Skipped, j.Failed, j.Message))
	if err != nil {
		return j, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'deployment-history-delete-progress',$2,$3)`, j.Username, id, common.JSON(map[string]any{"selected": j.Selected, "deleted": j.Deleted, "skipped": j.Skipped, "failed": j.Failed, "status": j.Status})); err != nil {
		return j, err
	}
	if err = s.Fence(ctx, tx, lease); err != nil {
		return j, err
	}
	return j, tx.Commit()
}

func deleteDeploymentHistoryItemTx(ctx context.Context, tx *sql.Tx, deletion deploymentHistoryDeleteJob, id, expected string) (int64, string, error) {
	// Lock the node before its journal; every deployment creator and parent
	// checkpoint follows the same operation gate / node / journal order.
	var node string
	err := tx.QueryRowContext(ctx, `SELECT node FROM v3_deployment_jobs WHERE id=$1`, id).Scan(&node)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "任务不存在", nil
	}
	if err != nil {
		return 0, "", err
	}
	var locked string
	if err = tx.QueryRowContext(ctx, `SELECT id FROM v3_nodes WHERE id=$1 FOR UPDATE`, node).Scan(&locked); err != nil {
		return 0, "", err
	}
	j, err := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return 0, "", err
	}
	states, err := deploymentHistoryDeleteStatesTx(ctx, tx, []string{id}, deletion.ID)
	if err != nil {
		return 0, "", err
	}
	state := states[id]
	if state.Reason != "" {
		return 0, state.Reason, nil
	}
	if state.Digest != expected {
		return 0, "任务状态已变化，请重新预览", nil
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM v3_deployment_logs WHERE job=$1`, id)
	if err != nil {
		return 0, "", err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return 0, "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_deployment_history_archives(deployment,deletion,username,actor_revision,plan_digest,log_cursor,deleted_logs) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, deletion.ID, deletion.Username, deletion.Account, j.PlanDigest, j.LogCursor, count)
	return count, "", err
}

func (s *Store) runDeploymentHistoryDeleteRound(ctx context.Context, lease Lease) (resultErr error) {
	var id string
	err := s.DB.QueryRowContext(ctx, `SELECT id FROM v3_deployment_history_delete_jobs WHERE status IN ('queued','running') ORDER BY created_at,id LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		if resultErr == nil || ctx.Err() != nil || errors.Is(resultErr, ErrLeaseLost) || errors.Is(resultErr, ErrMigrationPending) {
			return
		}
		op, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		tx, err := s.DB.BeginTx(op, nil)
		if err != nil {
			return
		}
		defer tx.Rollback()
		if s.Fence(op, tx, lease) == nil {
			if _, err = tx.ExecContext(op, `UPDATE v3_deployment_history_delete_jobs SET message='本轮处理失败，已完成部分保留，等待重试',updated_at=clock_timestamp() WHERE id=$1 AND status IN ('queued','running')`, id); err == nil {
				_ = tx.Commit()
			}
		}
	}()
	for ctx.Err() == nil {
		job, err := s.deploymentHistoryDeleteBatch(ctx, lease, id)
		if err != nil {
			return err
		}
		if job.Status != "queued" && job.Status != "running" {
			return nil
		}
	}
	return ctx.Err()
}
