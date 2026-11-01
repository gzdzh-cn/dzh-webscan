package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"webscan/internal/common"
)

var errDeploymentHistoryDeleteInput = errors.New("请选择1～200条不重复的部署历史，并明确确认删除")
var errDeploymentHistoryDeletePreview = errors.New("删除预览已失效、已使用或配置已变化，请重新预览")
var errDeploymentHistoryDeleteQuota = errors.New("当前账号待处理历史删除任务或有效预览已达100个")

const deploymentHistoryDeleteMessage = "删除页面历史及日志；防重记录、部署状态和恢复资料保留"

type deploymentHistoryDeleteItem struct {
	ID          string `json:"id"`
	RecordKey   string `json:"record_key"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	DeletedLogs int64  `json:"deleted_logs"`
}

type deploymentHistoryFrozenItem struct {
	deploymentHistoryDeleteItem
	Digest string `json:"state_digest"`
}

type deploymentHistoryDeletePreview struct {
	Token     string                        `json:"token"`
	Eligible  int                           `json:"eligible"`
	Protected int                           `json:"protected"`
	Expires   time.Time                     `json:"expires_at"`
	Items     []deploymentHistoryDeleteItem `json:"items"`
	Message   string                        `json:"message"`
}

type deploymentHistoryDeleteJob struct {
	ID       string                        `json:"id"`
	Username string                        `json:"-"`
	Account  int64                         `json:"-"`
	Selected int                           `json:"selected"`
	Status   string                        `json:"status"`
	Deleted  int                           `json:"deleted"`
	Skipped  int                           `json:"skipped"`
	Failed   int                           `json:"failed"`
	Message  string                        `json:"message"`
	Created  time.Time                     `json:"created_at"`
	Updated  time.Time                     `json:"updated_at"`
	Finished *time.Time                    `json:"finished_at"`
	Items    []deploymentHistoryDeleteItem `json:"items,omitempty"`
}

const deploymentHistoryDeleteColumns = `id,username,account_revision,selected,status,deleted,skipped,failed,message,created_at,updated_at,finished_at`

func scanDeploymentHistoryDeleteJob(row interface{ Scan(...any) error }) (j deploymentHistoryDeleteJob, err error) {
	err = row.Scan(&j.ID, &j.Username, &j.Account, &j.Selected, &j.Status, &j.Deleted, &j.Skipped, &j.Failed, &j.Message, &j.Created, &j.Updated, &j.Finished)
	return
}

func deploymentHistoryDeleteRecords(records []string) ([]string, error) {
	if len(records) < 1 || len(records) > 200 {
		return nil, errDeploymentHistoryDeleteInput
	}
	out := append([]string{}, records...)
	sort.Strings(out)
	for i, key := range out {
		if !strings.HasPrefix(key, "deployment-job:") || !identifier.MatchString(strings.TrimPrefix(key, "deployment-job:")) || i > 0 && out[i-1] == key {
			return nil, errDeploymentHistoryDeleteInput
		}
	}
	return out, nil
}

func deploymentHistoryDeleteGuardTx(ctx context.Context, tx *sql.Tx) error {
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return err
	}
	if held, err := migrationHeld(ctx, tx); err != nil {
		return err
	} else if held {
		return ErrMigrationPending
	}
	var restoring bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_configuration_restore_stages WHERE status IN ('pending_validation','pending_application'))`).Scan(&restoring); err != nil {
		return err
	}
	if restoring {
		return ErrConflict
	}
	return nil
}

func deploymentHistoryConfigurationStateTx(ctx context.Context, tx *sql.Tx) (version, generation int64, stamp string, err error) {
	var draft int64
	// Settings writers lock the live row before changing or creating a draft.
	// Hold that same row through confirmation/deletion, including when no draft
	// exists yet, so the bound configuration cannot change before commit.
	err = tx.QueryRowContext(ctx, `SELECT s.version,g.generation,coalesce(d.generation,0) FROM v3_settings s CROSS JOIN v3_configuration_operation_gate g LEFT JOIN v3_settings_drafts d ON d.id=s.id WHERE s.id=1 AND g.singleton FOR SHARE OF s,g`).Scan(&version, &generation, &draft)
	stamp = digest(common.JSON([]int64{version, generation, draft}))
	return
}

// Capabilities are kept in the private idempotency receipt, never in audit.
// guardedMutation's generic audit serializes its whole result, so preview uses
// the same request protocol with a deliberately reduced audit projection.
func (s *Store) previewDeploymentHistoryDelete(ctx context.Context, user, key string, records []string) (deploymentHistoryDeletePreview, error) {
	var out deploymentHistoryDeletePreview
	records, err := deploymentHistoryDeleteRecords(records)
	if err != nil || !identifier.MatchString(user) || !identifier.MatchString(key) {
		return out, errDeploymentHistoryDeleteInput
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err = deploymentHistoryDeleteGuardTx(ctx, tx); err != nil {
		return out, err
	}
	account, err := deploymentPreviewAccount(ctx, tx, user)
	if err != nil {
		return out, err
	}
	requestHash := digest(common.JSON([]any{"deployment-history-delete-preview", records}))
	res, err := tx.ExecContext(ctx, `INSERT INTO v3_requests(username,key,request_hash,response) VALUES($1,$2,$3,'{}') ON CONFLICT DO NOTHING`, user, key, requestHash)
	if err != nil {
		return out, err
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return out, err
	}
	if inserted == 0 {
		var previous string
		var raw []byte
		if err = tx.QueryRowContext(ctx, `SELECT request_hash,response FROM v3_requests WHERE username=$1 AND key=$2`, user, key).Scan(&previous, &raw); err != nil {
			return out, err
		}
		if previous != requestHash {
			return out, ErrRequestConflict
		}
		if err = json.Unmarshal(raw, &out); err != nil {
			return out, errDeploymentHistoryDeletePreview
		}
		return out, tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,773376040))`, user); err != nil {
		return out, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_deployment_history_delete_previews WHERE username=$1 AND NOT used AND expires_at>clock_timestamp()`, user).Scan(&count); err != nil {
		return out, err
	}
	if count >= 100 {
		return out, errDeploymentHistoryDeleteQuota
	}
	version, generation, configuration, err := deploymentHistoryConfigurationStateTx(ctx, tx)
	if err != nil {
		return out, err
	}
	ids := make([]string, len(records))
	for i, record := range records {
		ids[i] = strings.TrimPrefix(record, "deployment-job:")
	}
	states, err := deploymentHistoryDeleteStatesTx(ctx, tx, ids, "")
	if err != nil {
		return out, err
	}
	frozen := make([]deploymentHistoryFrozenItem, len(records))
	out.Items = make([]deploymentHistoryDeleteItem, len(records))
	for i, id := range ids {
		state := states[id]
		item := deploymentHistoryDeleteItem{ID: id, RecordKey: records[i], Status: "eligible", Reason: state.Reason}
		if item.Reason == "" {
			out.Eligible++
		} else {
			item.Status = "protected"
			out.Protected++
		}
		out.Items[i] = item
		frozen[i] = deploymentHistoryFrozenItem{item, state.Digest}
	}
	out.Token, out.Message = token(), deploymentHistoryDeleteMessage
	hash := digest([]byte(out.Token))
	if err = tx.QueryRowContext(ctx, `INSERT INTO v3_deployment_history_delete_previews(id,username,account_revision,settings_version,operation_generation,state_digest,records) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING expires_at`, hash, user, account, version, generation, configuration, common.JSON(frozen)).Scan(&out.Expires); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v3_requests SET response=$3 WHERE username=$1 AND key=$2`, user, key, common.JSON(out)); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'deployment-history-delete-preview',$2,$3)`, user, hash, common.JSON(map[string]any{"selected": len(records), "eligible": out.Eligible, "protected": out.Protected})); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

func (s *Store) submitDeploymentHistoryDelete(ctx context.Context, user, key, capability string, confirm bool) (json.RawMessage, error) {
	if !validArchiveSource(capability) || !confirm {
		return nil, errDeploymentHistoryDeleteInput
	}
	hash := digest([]byte(capability))
	guard := func(tx *sql.Tx) error {
		if err := deploymentHistoryDeleteGuardTx(ctx, tx); err != nil {
			return err
		}
		_, err := deploymentPreviewAccount(ctx, tx, user)
		return err
	}
	return s.guardedMutation(ctx, user, key, "deployment-history-delete-confirm", hash, hash, guard, func(tx *sql.Tx) (any, error) {
		account, err := deploymentPreviewAccount(ctx, tx, user)
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,773376040))`, user); err != nil {
			return nil, err
		}
		var ownerRevision, version, generation int64
		var stamp string
		var raw []byte
		err = tx.QueryRowContext(ctx, `SELECT account_revision,settings_version,operation_generation,state_digest,records FROM v3_deployment_history_delete_previews WHERE id=$1 AND username=$2 AND NOT used AND expires_at>clock_timestamp() FOR UPDATE`, hash, user).Scan(&ownerRevision, &version, &generation, &stamp, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errDeploymentHistoryDeletePreview
		}
		if err != nil {
			return nil, err
		}
		current, operation, configuration, err := deploymentHistoryConfigurationStateTx(ctx, tx)
		if err != nil {
			return nil, err
		}
		if ownerRevision != account || current != version || operation != generation || stamp != configuration {
			return nil, errDeploymentHistoryDeletePreview
		}
		var items []deploymentHistoryFrozenItem
		if json.Unmarshal(raw, &items) != nil {
			return nil, errDeploymentHistoryDeletePreview
		}
		records := make([]string, len(items))
		for i, item := range items {
			if item.RecordKey != "deployment-job:"+item.ID || item.Status != "eligible" && item.Status != "protected" || !releaseDigest(item.Digest) || len(item.Reason) > 512 {
				return nil, errDeploymentHistoryDeletePreview
			}
			records[i] = item.RecordKey
		}
		if _, err = deploymentHistoryDeleteRecords(records); err != nil {
			return nil, err
		}
		var active int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_deployment_history_delete_jobs WHERE username=$1 AND status IN ('queued','running')`, user).Scan(&active); err != nil {
			return nil, err
		}
		if active >= 100 {
			return nil, errDeploymentHistoryDeleteQuota
		}
		j, err := scanDeploymentHistoryDeleteJob(tx.QueryRowContext(ctx, `INSERT INTO v3_deployment_history_delete_jobs(id,username,account_revision,preview,selected,message) VALUES($1,$2,$3,$4,$5,'历史删除任务已创建；尚未删除') RETURNING `+deploymentHistoryDeleteColumns, token(), user, account, hash, len(items)))
		if err != nil {
			return nil, err
		}
		for i, item := range items {
			status, reason := "pending", ""
			if item.Status == "protected" {
				status, reason = "skipped", "预览时受保护："+item.Reason
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO v3_deployment_history_delete_items(job,ordinal,deployment,state_digest,status,reason) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(deployment) WHERE status='pending' DO NOTHING`, j.ID, i+1, item.ID, item.Digest, status, reason)
			if err != nil {
				return nil, err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return nil, err
			}
			if n == 0 {
				status, reason = "skipped", "另一个历史删除任务处理中"
				if _, err = tx.ExecContext(ctx, `INSERT INTO v3_deployment_history_delete_items(job,ordinal,deployment,state_digest,status,reason) VALUES($1,$2,$3,$4,$5,$6)`, j.ID, i+1, item.ID, item.Digest, status, reason); err != nil {
					return nil, err
				}
			}
			if status == "skipped" {
				j.Skipped++
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v3_deployment_history_delete_jobs SET skipped=$2 WHERE id=$1`, j.ID, j.Skipped); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v3_deployment_history_delete_previews SET used=true WHERE id=$1`, hash); err != nil {
			return nil, err
		}
		return j, nil
	})
}

func (s *Store) deploymentHistoryDeleteJob(ctx context.Context, user, id string) (deploymentHistoryDeleteJob, error) {
	var empty deploymentHistoryDeleteJob
	if !identifier.MatchString(id) {
		return empty, errDeploymentHistoryDeleteInput
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if _, err = deploymentPreviewAccount(ctx, tx, user); err != nil {
		return empty, err
	}
	j, err := scanDeploymentHistoryDeleteJob(tx.QueryRowContext(ctx, `SELECT `+deploymentHistoryDeleteColumns+` FROM v3_deployment_history_delete_jobs WHERE id=$1 AND username=$2`, id, user))
	if err != nil {
		return empty, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT deployment,status,reason,deleted_logs FROM v3_deployment_history_delete_items WHERE job=$1 ORDER BY ordinal`, id)
	if err != nil {
		return empty, err
	}
	j.Items = []deploymentHistoryDeleteItem{}
	for rows.Next() {
		var item deploymentHistoryDeleteItem
		if err = rows.Scan(&item.ID, &item.Status, &item.Reason, &item.DeletedLogs); err != nil {
			rows.Close()
			return empty, err
		}
		item.RecordKey = "deployment-job:" + item.ID
		j.Items = append(j.Items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return empty, err
	}
	return j, tx.Commit()
}
