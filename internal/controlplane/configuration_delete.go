package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"webscan/internal/common"
)

var errConfigurationDeleteInput = errors.New("请选择当前页 1～200 份不重复的部署配置备份，并明确确认永久删除")
var errConfigurationDeleteQuota = errors.New("当前账号待处理删除任务或有效预览已达 100 个，请等待完成或预览过期后重试")
var errConfigurationDeletePreview = errors.New("删除预览已过期、已使用或配置已变化，请重新预览")

type configurationDeleteItem struct {
	ID        string `json:"id"`
	RecordKey string `json:"record_key"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
}

type configurationDeletePreview struct {
	Token     string                    `json:"token"`
	Version   int64                     `json:"settings_version"`
	Eligible  int                       `json:"eligible"`
	Protected int                       `json:"protected"`
	Expires   time.Time                 `json:"expires_at"`
	Items     []configurationDeleteItem `json:"items"`
}

type configurationDeleteJob struct {
	ID       string     `json:"id"`
	Username string     `json:"username"`
	Version  int64      `json:"settings_version"`
	Selected int        `json:"selected"`
	Status   string     `json:"status"`
	Deleted  int        `json:"deleted"`
	Skipped  int        `json:"skipped"`
	Failed   int        `json:"failed"`
	Message  string     `json:"message"`
	Created  time.Time  `json:"created_at"`
	Updated  time.Time  `json:"updated_at"`
	Finished *time.Time `json:"finished_at"`
}

const configurationDeleteColumns = `id,username,settings_version,selected,status,deleted,skipped,failed,message,created_at,updated_at,finished_at`

func scanConfigurationDeleteJob(row interface{ Scan(...any) error }) (j configurationDeleteJob, err error) {
	err = row.Scan(&j.ID, &j.Username, &j.Version, &j.Selected, &j.Status, &j.Deleted, &j.Skipped, &j.Failed, &j.Message, &j.Created, &j.Updated, &j.Finished)
	return
}

func configurationDeleteRecords(records []string) ([]string, error) {
	if len(records) < 1 || len(records) > 200 {
		return nil, errConfigurationDeleteInput
	}
	out := append([]string{}, records...)
	sort.Strings(out)
	for i, key := range out {
		if !strings.HasPrefix(key, "configuration-backup:") || !validArchiveSource(strings.TrimPrefix(key, "configuration-backup:")) || i > 0 && out[i-1] == key {
			return nil, errConfigurationDeleteInput
		}
	}
	return out, nil
}

func (s *Store) previewConfigurationDelete(ctx context.Context, user string, records []string) (configurationDeletePreview, error) {
	var out configurationDeletePreview
	records, err := configurationDeleteRecords(records)
	if err != nil {
		return out, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err = configurationBackupAdmin(ctx, tx, user); err != nil {
		return out, err
	}
	if held, err := migrationHeld(ctx, tx); err != nil {
		return out, err
	} else if held {
		return out, ErrMigrationPending
	}
	// Serialize preview quotas for an account in the same snapshot, including
	// concurrent API replicas. The shared gate is already used by history.
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_history_gates(username,version) VALUES($1,1) ON CONFLICT(username) DO UPDATE SET version=v3_history_gates.version+1`, user); err != nil {
		return out, err
	}
	var active int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_configuration_delete_previews WHERE username=$1 AND NOT used AND expires_at>clock_timestamp()`, user).Scan(&active); err != nil {
		return out, err
	}
	if active >= 100 {
		return out, errConfigurationDeleteQuota
	}
	if err = tx.QueryRowContext(ctx, "SELECT version FROM v3_settings WHERE id=1 FOR SHARE").Scan(&out.Version); err != nil {
		return out, err
	}
	out.Token = token()
	hash := digest([]byte(out.Token))
	if err = tx.QueryRowContext(ctx, `INSERT INTO v3_configuration_delete_previews(id,username,settings_version,records) VALUES($1,$2,$3,$4) RETURNING expires_at`, hash, user, out.Version, common.JSON(records)).Scan(&out.Expires); err != nil {
		return out, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.key,b.id IS NOT NULL,
 COALESCE((SELECT kind FROM v3_configuration_backup_pins p WHERE p.backup=b.id AND (expires_at IS NULL OR expires_at>clock_timestamp()) ORDER BY kind LIMIT 1),''),
 EXISTS(SELECT 1 FROM v3_configuration_delete_items i WHERE i.backup=b.id AND i.status='pending')
 FROM jsonb_array_elements_text($1::jsonb) AS r(key) LEFT JOIN v3_configuration_backups b ON b.id=substring(r.key from 22) ORDER BY r.key`, common.JSON(records))
	if err != nil {
		return out, err
	}
	out.Items = []configurationDeleteItem{}
	for rows.Next() {
		var item configurationDeleteItem
		var found, deleting bool
		var pin string
		if err = rows.Scan(&item.RecordKey, &found, &pin, &deleting); err != nil {
			break
		}
		item.ID = strings.TrimPrefix(item.RecordKey, "configuration-backup:")
		item.Status = "eligible"
		switch {
		case !found:
			item.Reason = "备份不存在"
		case pin != "":
			item.Reason = configurationBackupPinReason(pin)
		case deleting:
			item.Reason = "删除任务处理中"
		}
		if item.Reason != "" {
			item.Status = "protected"
			out.Protected++
		} else {
			out.Eligible++
		}
		out.Items = append(out.Items, item)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return configurationDeletePreview{}, err
	}
	// Preserve the preview's eligibility as well as the fixed identities. An
	// item protected at preview time cannot become an implicit later deletion.
	if _, err = tx.ExecContext(ctx, `UPDATE v3_configuration_delete_previews SET records=$2 WHERE id=$1`, hash, common.JSON(out.Items)); err != nil {
		return configurationDeletePreview{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-backup-delete-preview',$2,$3)`, user, hash, common.JSON(common.Map{"selected": len(records), "eligible": out.Eligible, "protected": out.Protected, "settings_version": out.Version, "operation": "deployment-backup"})); err != nil {
		return configurationDeletePreview{}, err
	}
	return out, tx.Commit()
}

func (s *Store) submitConfigurationDelete(ctx context.Context, user, key, preview string, confirm bool) (json.RawMessage, error) {
	if !validArchiveSource(preview) || !confirm {
		return nil, errConfigurationDeleteInput
	}
	hash := digest([]byte(preview))
	return s.guardedMutation(ctx, user, key, "configuration-backup-delete-queue", "configuration-backups", hash, configurationBackupGuard(ctx, user), func(tx *sql.Tx) (any, error) {
		// Bound outstanding jobs per account without cross-replica races.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,773376015))`, user); err != nil {
			return nil, err
		}
		var version, current int64
		var raw []byte
		err := tx.QueryRowContext(ctx, `SELECT settings_version,records FROM v3_configuration_delete_previews WHERE id=$1 AND username=$2 AND NOT used AND expires_at>clock_timestamp() FOR UPDATE`, hash, user).Scan(&version, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errConfigurationDeletePreview
		}
		if err != nil {
			return nil, err
		}
		if err = tx.QueryRowContext(ctx, "SELECT version FROM v3_settings WHERE id=1 FOR SHARE").Scan(&current); err != nil {
			return nil, err
		}
		if current != version {
			return nil, errConfigurationDeletePreview
		}
		var items []configurationDeleteItem
		if json.Unmarshal(raw, &items) != nil {
			return nil, errConfigurationDeleteInput
		}
		records := []string{}
		for _, item := range items {
			if item.RecordKey != "configuration-backup:"+item.ID || item.Status != "eligible" && item.Status != "protected" || len(item.Reason) > 256 {
				return nil, errConfigurationDeleteInput
			}
			records = append(records, item.RecordKey)
		}
		if _, err = configurationDeleteRecords(records); err != nil {
			return nil, err
		}
		var active int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_configuration_delete_jobs WHERE username=$1 AND status IN ('queued','running')`, user).Scan(&active); err != nil {
			return nil, err
		}
		if active >= 100 {
			return nil, errConfigurationDeleteQuota
		}
		id := token()
		j, err := scanConfigurationDeleteJob(tx.QueryRowContext(ctx, `INSERT INTO v3_configuration_delete_jobs(id,username,preview,settings_version,selected,message) VALUES($1,$2,$3,$4,$5,'已排队；不表示已删除') RETURNING `+configurationDeleteColumns, id, user, hash, version, len(records)))
		if err != nil {
			return nil, err
		}
		for i, item := range items {
			backup := item.ID
			if item.Status == "protected" {
				if _, err = tx.ExecContext(ctx, `INSERT INTO v3_configuration_delete_items(job,ordinal,backup,status,reason) VALUES($1,$2,$3,'skipped',$4)`, id, i+1, backup, "预览时受保护或不存在："+item.Reason); err != nil {
					return nil, err
				}
				j.Skipped++
				continue
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO v3_configuration_delete_items(job,ordinal,backup) VALUES($1,$2,$3) ON CONFLICT(backup) WHERE status='pending' DO NOTHING`, id, i+1, backup)
			if err != nil {
				return nil, err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return nil, err
			}
			if n == 0 {
				if _, err = tx.ExecContext(ctx, `INSERT INTO v3_configuration_delete_items(job,ordinal,backup,status,reason) VALUES($1,$2,$3,'skipped','另一个删除任务处理中')`, id, i+1, backup); err != nil {
					return nil, err
				}
				j.Skipped++
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v3_configuration_delete_jobs SET skipped=$2 WHERE id=$1`, id, j.Skipped); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v3_configuration_delete_previews SET used=true WHERE id=$1`, hash); err != nil {
			return nil, err
		}
		return j, nil
	})
}

func (s *Store) configurationDeleteJobs(ctx context.Context, user string, before retentionCursor, limit int) ([]configurationDeleteJob, error) {
	if limit < 1 || limit > 200 {
		return nil, errConfigurationDeleteInput
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = configurationBackupAdmin(ctx, tx, user); err != nil {
		return nil, err
	}
	stamp := before.Time
	if stamp.IsZero() {
		stamp = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+configurationDeleteColumns+` FROM v3_configuration_delete_jobs WHERE username=$1 AND (created_at,id)<($2,$3) ORDER BY created_at DESC,id DESC LIMIT $4`, user, stamp, before.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []configurationDeleteJob{}
	for rows.Next() {
		j, err := scanConfigurationDeleteJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return out, tx.Commit()
}

func (s *Store) configurationDeleteJob(ctx context.Context, user, id string) (configurationDeleteJob, []configurationDeleteItem, error) {
	if !validArchiveSource(id) {
		return configurationDeleteJob{}, nil, errConfigurationDeleteInput
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return configurationDeleteJob{}, nil, err
	}
	defer tx.Rollback()
	if err = configurationBackupAdmin(ctx, tx, user); err != nil {
		return configurationDeleteJob{}, nil, err
	}
	j, err := scanConfigurationDeleteJob(tx.QueryRowContext(ctx, `SELECT `+configurationDeleteColumns+` FROM v3_configuration_delete_jobs WHERE id=$1 AND username=$2 FOR SHARE`, id, user))
	if err != nil {
		return j, nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT backup,status,reason FROM v3_configuration_delete_items WHERE job=$1 ORDER BY ordinal`, id)
	if err != nil {
		return j, nil, err
	}
	defer rows.Close()
	items := []configurationDeleteItem{}
	for rows.Next() {
		var item configurationDeleteItem
		if err = rows.Scan(&item.ID, &item.Status, &item.Reason); err != nil {
			return j, nil, err
		}
		item.RecordKey = "configuration-backup:" + item.ID
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return j, nil, err
	}
	rows.Close()
	return j, items, tx.Commit()
}

// One backup is one short transaction: ciphertext parts, parent, result,
// checkpoint and audit commit together. The shared retention fencing lease
// excludes automatic/history cleaners and stale owners at both boundaries.
func (s *Store) configurationDeleteBatch(ctx context.Context, l Lease, id string) (configurationDeleteJob, error) {
	if l.Resource != "retention" || !validArchiveSource(id) {
		return configurationDeleteJob{}, ErrLeaseLost
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return configurationDeleteJob{}, err
	}
	defer tx.Rollback()
	if err = s.Fence(ctx, tx, l); err != nil {
		return configurationDeleteJob{}, err
	}
	if held, err := migrationHeld(ctx, tx); err != nil {
		return configurationDeleteJob{}, err
	} else if held {
		return configurationDeleteJob{}, ErrMigrationPending
	}
	j, err := scanConfigurationDeleteJob(tx.QueryRowContext(ctx, `SELECT `+configurationDeleteColumns+` FROM v3_configuration_delete_jobs WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return j, err
	}
	if j.Status != "queued" && j.Status != "running" {
		return j, tx.Commit()
	}
	cancelReason := ""
	if err = configurationBackupAdmin(ctx, tx, j.Username); errors.Is(err, ErrConfigurationBackupPermission) {
		cancelReason = "操作账号已失效或权限变化，剩余记录未删除"
	} else if err != nil {
		return j, err
	}
	var version int64
	if err = tx.QueryRowContext(ctx, "SELECT version FROM v3_settings WHERE id=1 FOR SHARE").Scan(&version); err != nil {
		return j, err
	}
	if version != j.Version {
		cancelReason = "配置已变化，保留已完成部分；剩余记录需重新预览"
	}
	j.Status = "running"
	if cancelReason != "" {
		res, err := tx.ExecContext(ctx, `UPDATE v3_configuration_delete_items SET status='skipped',reason=$2 WHERE job=$1 AND status='pending'`, id, cancelReason)
		if err != nil {
			return j, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return j, err
		}
		j.Skipped += int(n)
		j.Status, j.Message = "cancelled", cancelReason
	} else {
		var ordinal int
		var backup string
		err = tx.QueryRowContext(ctx, `SELECT ordinal,backup FROM v3_configuration_delete_items WHERE job=$1 AND status='pending' ORDER BY ordinal LIMIT 1 FOR UPDATE`, id).Scan(&ordinal, &backup)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return j, err
		}
		if err == nil {
			if _, err = tx.ExecContext(ctx, "SAVEPOINT configuration_delete_item"); err != nil {
				return j, err
			}
			deleted, reason, deletionErr := deleteConfigurationBackupTx(ctx, tx, backup)
			status := "skipped"
			if deletionErr != nil {
				var pg *pgconn.PgError
				if ctx.Err() != nil || !errors.As(deletionErr, &pg) || !strings.HasPrefix(pg.Code, "23") && pg.Code != "P0001" {
					return j, deletionErr
				}
				if _, err = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT configuration_delete_item"); err != nil {
					return j, err
				}
				status, reason = "failed", "删除失败，原记录保留；请检查后重新提交"
				j.Failed++
			} else if deleted {
				status, reason = "deleted", "已永久删除备份存档；未修改运行配置，不保证立即释放磁盘空间"
				j.Deleted++
			} else {
				j.Skipped++
			}
			if _, err = tx.ExecContext(ctx, "RELEASE SAVEPOINT configuration_delete_item"); err != nil {
				return j, err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE v3_configuration_delete_items SET status=$3,reason=$4 WHERE job=$1 AND ordinal=$2`, id, ordinal, status, reason); err != nil {
				return j, err
			}
		}
		j.Message = "正在逐条检查引用并删除；已完成部分已保存"
		if j.Deleted+j.Skipped+j.Failed == j.Selected {
			j.Status, j.Message = "succeeded", "已处理明确选择的备份；未修改运行配置，不保证立即释放磁盘空间"
			if j.Skipped > 0 || j.Failed > 0 {
				j.Status, j.Message = "partial", "部分完成，请查看逐项跳过或失败原因；未处理其他备份"
			}
		}
	}
	j, err = scanConfigurationDeleteJob(tx.QueryRowContext(ctx, `UPDATE v3_configuration_delete_jobs SET status=$2,deleted=$3,skipped=$4,failed=$5,message=$6,updated_at=clock_timestamp(),finished_at=CASE WHEN $2 IN ('succeeded','partial','cancelled') THEN clock_timestamp() ELSE NULL END WHERE id=$1 RETURNING `+configurationDeleteColumns, j.ID, j.Status, j.Deleted, j.Skipped, j.Failed, j.Message))
	if err != nil {
		return j, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-backup-delete-progress',$2,$3)`, j.Username, j.ID, common.JSON(common.Map{"operation": "deployment-backup", "selected": j.Selected, "deleted": j.Deleted, "skipped": j.Skipped, "failed": j.Failed, "status": j.Status})); err != nil {
		return j, err
	}
	if err = s.Fence(ctx, tx, l); err != nil {
		return j, err
	}
	return j, tx.Commit()
}

func (s *Store) runConfigurationDeleteRound(ctx context.Context, l Lease) (resultErr error) {
	var id string
	err := s.DB.QueryRowContext(ctx, `SELECT id FROM v3_configuration_delete_jobs WHERE status IN ('queued','running') ORDER BY created_at,id LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		if resultErr == nil || errors.Is(resultErr, context.Canceled) || errors.Is(resultErr, context.DeadlineExceeded) || errors.Is(resultErr, ErrMigrationPending) || errors.Is(resultErr, ErrLeaseLost) {
			return
		}
		// A failed transaction cannot journal its own error. Persist only a
		// bounded, credential-free retry message under the still-valid fence.
		op, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		tx, err := s.DB.BeginTx(op, nil)
		if err != nil {
			return
		}
		defer tx.Rollback()
		if s.Fence(op, tx, l) != nil {
			return
		}
		if _, err = tx.ExecContext(op, `UPDATE v3_configuration_delete_jobs SET message='本轮处理失败，已完成部分保留，等待重试',updated_at=clock_timestamp() WHERE id=$1 AND status IN ('queued','running')`, id); err == nil {
			_ = tx.Commit()
		}
	}()
	for ctx.Err() == nil {
		j, err := s.configurationDeleteBatch(ctx, l, id)
		if err != nil {
			return err
		}
		if j.Status != "queued" && j.Status != "running" {
			return nil
		}
	}
	return ctx.Err()
}
