package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"webscan/internal/common"
	configuration "webscan/internal/config"
	"webscan/internal/notify"
)

var errNotificationTestInput = errors.New("通知测试参数不正确，请使用已应用的邮箱或飞书配置")
var errNotificationTestPreview = errors.New("通知测试预览已失效或实际配置已变化，请重新预览")
var errNotificationTestRate = errors.New("每个通知通道30秒内最多创建一次测试，请稍后重试")
var errNotificationTestUnavailable = errors.New("通知测试服务或共享密钥暂不可用，请稍后重试")
var errNotificationTestQuota = errors.New("待处理通知测试或有效预览已达上限")

const notificationTestSubject = "【网站监控】通知测试"
const notificationTestBody = "通知测试\n这是管理员主动发送的测试通知，不是业务异常。\n已提交不代表收件人已读；请核对实际接收结果。"

type notificationTestPreview struct {
	Token      string    `json:"token"`
	Channel    string    `json:"channel"`
	Runtime    int64     `json:"runtime_version"`
	Expires    time.Time `json:"expires_at"`
	Recipients []string  `json:"recipients"`
	Subject    string    `json:"subject"`
	Body       string    `json:"body"`
}
type notificationTestDelivery struct {
	Ordinal   int    `json:"ordinal"`
	Recipient string `json:"recipient"`
	State     string `json:"state"`
	Outcome   string `json:"outcome"`
	Message   string `json:"message"`
}
type notificationTestJob struct {
	ID       string                     `json:"id"`
	Channel  string                     `json:"channel"`
	Runtime  int64                      `json:"runtime_version"`
	Status   string                     `json:"status"`
	Created  time.Time                  `json:"created_at"`
	Updated  time.Time                  `json:"updated_at"`
	Finished *time.Time                 `json:"finished_at"`
	Message  string                     `json:"message"`
	Items    []notificationTestDelivery `json:"items"`
}
type notificationTestAuthorization struct {
	ID, Username, Channel, Key, Proof string
	Account, Runtime                  int64
	Targets                           []string
	Expires                           time.Time
}

func notificationTestHMAC(v *Vault, key, domain string, a notificationTestAuthorization, settings []byte) (string, error) {
	if v == nil || len(v.receiptKeys[key]) == 0 {
		return "", errNotificationTestUnavailable
	}
	var payload any
	if json.Unmarshal(settings, &payload) != nil {
		return "", errNotificationTestUnavailable
	}
	raw := common.JSON([]any{domain, a.ID, a.Username, a.Account, a.Channel, a.Runtime, a.Targets, a.Expires.UnixMicro(), payload})
	defer clear(raw)
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/notification-test/v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func notificationTestSettingsTx(ctx context.Context, tx *sql.Tx, channel string) (int64, []byte, common.Map, []string, error) {
	if channel != "email" && channel != "feishu" {
		return 0, nil, nil, nil, errNotificationTestInput
	}
	var version int64
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT version,payload FROM v3_settings WHERE id=1 FOR SHARE`).Scan(&version, &raw); err != nil {
		return 0, nil, nil, nil, err
	}
	var root common.Map
	if json.Unmarshal(raw, &root) != nil {
		return 0, nil, nil, nil, errNotificationTestUnavailable
	}
	c := common.M(root[channel])
	if !common.B(c["enabled"]) {
		return 0, nil, nil, nil, errNotificationTestInput
	}
	targets := []string{""}
	if channel == "email" {
		if notify.Validate(c) != nil {
			return 0, nil, nil, nil, errNotificationTestInput
		}
		targets = notify.Recipients(c)
		for _, recipient := range targets {
			if len(recipient) > 320 {
				return 0, nil, nil, nil, errNotificationTestInput
			}
		}
	} else if !configuration.ValidFeishuWebhook(common.S(c["webhook_url"])) || common.B(c["signing_enabled"]) && common.S(c["signing_secret"]) == "" {
		return 0, nil, nil, nil, errNotificationTestInput
	}
	return version, raw, root, targets, nil
}
func notificationTestGuardTx(ctx context.Context, tx *sql.Tx, user string) (int64, error) {
	if held, e := migrationHeld(ctx, tx); e != nil {
		return 0, e
	} else if held {
		return 0, ErrMigrationPending
	}
	return deploymentPreviewAccount(ctx, tx, user)
}

// Private idempotency receipts can contain preview capabilities. Audits cannot.
func notificationTestRequestTx(ctx context.Context, tx *sql.Tx, user, key, hash string) (json.RawMessage, bool, error) {
	res, err := tx.ExecContext(ctx, `INSERT INTO v3_requests(username,key,request_hash,response) VALUES($1,$2,$3,'{}') ON CONFLICT DO NOTHING`, user, key, hash)
	if err != nil {
		return nil, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	if n == 1 {
		return nil, true, nil
	}
	var previous string
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT request_hash,response FROM v3_requests WHERE username=$1 AND key=$2`, user, key).Scan(&previous, &raw)
	if err != nil {
		return nil, false, err
	}
	if previous != hash {
		return nil, false, ErrRequestConflict
	}
	return raw, false, nil
}
func notificationTestReceiptTx(ctx context.Context, tx *sql.Tx, user, key, kind, resource string, response any) error {
	raw := common.JSON(response)
	if _, e := tx.ExecContext(ctx, `UPDATE v3_requests SET response=$3 WHERE username=$1 AND key=$2`, user, key, raw); e != nil {
		return e
	}
	_, e := tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,$2,$3,$4)`, user, kind, resource, common.JSON(map[string]string{"status": "created"}))
	return e
}
func (s *Store) previewNotificationTest(ctx context.Context, v *Vault, user, key, channel string, expected int64) (notificationTestPreview, error) {
	var out notificationTestPreview
	if !identifier.MatchString(user) || !identifier.MatchString(key) || expected < 1 {
		return out, errNotificationTestInput
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	account, e := notificationTestGuardTx(ctx, tx, user)
	if e != nil {
		return out, e
	}
	hash := digest(common.JSON([]any{"notification-test-preview", channel, expected}))
	raw, fresh, e := notificationTestRequestTx(ctx, tx, user, key, hash)
	if e != nil {
		return out, e
	}
	if !fresh {
		if json.Unmarshal(raw, &out) != nil {
			return out, errNotificationTestUnavailable
		}
		return out, tx.Commit()
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,773376042))`, user); e != nil {
		return out, e
	}
	var active int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_notification_test_previews WHERE username=$1 AND NOT used AND expires_at>clock_timestamp()`, user).Scan(&active); e != nil {
		return out, e
	}
	if active >= 100 {
		return out, errNotificationTestQuota
	}
	version, settings, _, targets, e := notificationTestSettingsTx(ctx, tx, channel)
	if e != nil {
		return out, e
	}
	if version != expected {
		return out, errNotificationTestPreview
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	out = notificationTestPreview{Token: token(), Channel: channel, Runtime: version, Expires: now.Add(10 * time.Minute), Recipients: append([]string{}, targets...), Subject: notificationTestSubject, Body: notificationTestBody}
	if channel == "feishu" {
		out.Recipients = []string{"已应用的飞书机器人"}
	}
	a := notificationTestAuthorization{ID: digest([]byte(out.Token)), Username: user, Account: account, Channel: channel, Runtime: version, Targets: targets, Expires: out.Expires}
	if v == nil {
		return out, errNotificationTestUnavailable
	}
	a.Key = v.active
	a.Proof, e = notificationTestHMAC(v, a.Key, "preview", a, settings)
	if e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_notification_test_previews(id,username,account_revision,channel,runtime_version,targets,key_id,proof,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, a.ID, user, account, channel, version, common.JSON(targets), a.Key, a.Proof, now, a.Expires); e != nil {
		return out, e
	}
	if e = notificationTestReceiptTx(ctx, tx, user, key, "notification-test-preview", a.ID, out); e != nil {
		return out, e
	}
	return out, tx.Commit()
}
func (s *Store) submitNotificationTest(ctx context.Context, v *Vault, user, key, capability string, confirm bool) (json.RawMessage, error) {
	if !identifier.MatchString(user) || !identifier.MatchString(key) || !validArchiveSource(capability) || !confirm {
		return nil, errNotificationTestInput
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	account, e := notificationTestGuardTx(ctx, tx, user)
	if e != nil {
		return nil, e
	}
	hash := digest(common.JSON([]any{"notification-test-confirm", digest([]byte(capability)), confirm}))
	receipt, fresh, e := notificationTestRequestTx(ctx, tx, user, key, hash)
	if e != nil {
		return nil, e
	}
	if !fresh {
		return receipt, tx.Commit()
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,773376042))`, user); e != nil {
		return nil, e
	}
	var a notificationTestAuthorization
	var targets []byte
	e = tx.QueryRowContext(ctx, `SELECT id,username,account_revision,channel,runtime_version,targets,key_id,proof,expires_at FROM v3_notification_test_previews WHERE id=$1 AND username=$2 AND NOT used AND expires_at>clock_timestamp() FOR UPDATE`, digest([]byte(capability)), user).Scan(&a.ID, &a.Username, &a.Account, &a.Channel, &a.Runtime, &targets, &a.Key, &a.Proof, &a.Expires)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, errNotificationTestPreview
	}
	if e != nil {
		return nil, e
	}
	if json.Unmarshal(targets, &a.Targets) != nil {
		return nil, errNotificationTestPreview
	}
	version, settings, _, actual, e := notificationTestSettingsTx(ctx, tx, a.Channel)
	if errors.Is(e, errNotificationTestInput) {
		return nil, errNotificationTestPreview
	}
	if e != nil {
		return nil, e
	}
	proof, e := notificationTestHMAC(v, a.Key, "preview", a, settings)
	if e != nil {
		return nil, e
	}
	if account != a.Account || version != a.Runtime || !hmac.Equal([]byte(proof), []byte(a.Proof)) || string(common.JSON(actual)) != string(common.JSON(a.Targets)) {
		return nil, errNotificationTestPreview
	}
	var count int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_notification_test_jobs WHERE username=$1 AND status IN ('queued','running')`, user).Scan(&count); e != nil {
		return nil, e
	}
	if count >= 100 {
		return nil, errNotificationTestQuota
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_notification_test_cooldowns(channel,next_allowed_at) VALUES($1,'epoch') ON CONFLICT DO NOTHING`, a.Channel); e != nil {
		return nil, e
	}
	var allowed bool
	if e = tx.QueryRowContext(ctx, `SELECT next_allowed_at<=clock_timestamp() FROM v3_notification_test_cooldowns WHERE channel=$1 FOR UPDATE`, a.Channel).Scan(&allowed); e != nil {
		return nil, e
	}
	if !allowed {
		return nil, errNotificationTestRate
	}
	previewID := a.ID
	a.ID = token()
	a.Expires = time.Now().UTC().Truncate(time.Microsecond).Add(10 * time.Minute)
	a.Proof, e = notificationTestHMAC(v, a.Key, "job", a, settings)
	if e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_notification_test_jobs(id,preview,username,account_revision,channel,runtime_version,targets,key_id,proof,expires_at,message) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'测试任务已创建，尚未发送')`, a.ID, previewID, user, account, a.Channel, version, targets, a.Key, a.Proof, a.Expires); e != nil {
		return nil, e
	}
	for i, target := range a.Targets {
		if _, e = tx.ExecContext(ctx, `INSERT INTO v3_notification_test_deliveries(job,ordinal,recipient) VALUES($1,$2,$3)`, a.ID, i+1, target); e != nil {
			return nil, e
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_notification_test_previews SET used=true WHERE id=$1`, previewID); e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_notification_test_cooldowns SET next_allowed_at=clock_timestamp()+interval '30 seconds' WHERE channel=$1`, a.Channel); e != nil {
		return nil, e
	}
	out, e := notificationTestJobTx(ctx, tx, user, a.ID)
	if e != nil {
		return nil, e
	}
	if e = notificationTestReceiptTx(ctx, tx, user, key, "notification-test-created", a.ID, out); e != nil {
		return nil, e
	}
	return common.JSON(out), tx.Commit()
}
func notificationTestJobTx(ctx context.Context, tx *sql.Tx, user, id string) (notificationTestJob, error) {
	var j notificationTestJob
	e := tx.QueryRowContext(ctx, `SELECT id,channel,runtime_version,status,created_at,updated_at,finished_at,message FROM v3_notification_test_jobs WHERE id=$1 AND username=$2`, id, user).Scan(&j.ID, &j.Channel, &j.Runtime, &j.Status, &j.Created, &j.Updated, &j.Finished, &j.Message)
	if e != nil {
		return j, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT ordinal,recipient,state,outcome,message FROM v3_notification_test_deliveries WHERE job=$1 ORDER BY ordinal LIMIT 20`, id)
	if e != nil {
		return j, e
	}
	defer rows.Close()
	j.Items = []notificationTestDelivery{}
	for rows.Next() {
		var item notificationTestDelivery
		if e = rows.Scan(&item.Ordinal, &item.Recipient, &item.State, &item.Outcome, &item.Message); e != nil {
			return j, e
		}
		if j.Channel == "feishu" {
			item.Recipient = "已应用的飞书机器人"
		}
		j.Items = append(j.Items, item)
	}
	return j, rows.Err()
}
func (s *Store) notificationTestJob(ctx context.Context, user, id string) (notificationTestJob, error) {
	var j notificationTestJob
	if !identifier.MatchString(id) {
		return j, errNotificationTestInput
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return j, e
	}
	defer tx.Rollback()
	if _, e = deploymentPreviewAccount(ctx, tx, user); e != nil {
		return j, e
	}
	j, e = notificationTestJobTx(ctx, tx, user, id)
	if e != nil {
		return j, e
	}
	return j, tx.Commit()
}

// Every stored error exposed by this feature is a fixed code and message.
func notificationTestOutcome(state string) string {
	switch state {
	case "accepted":
		return "通道已确认接收；请核对实际收件，未表示已读"
	case "unknown":
		return "未获得完整发送确认，可能已送达；不会自动重发"
	case "cancelled":
		return "发送授权已变化或过期，未发送目标已取消"
	}
	return "等待发送"
}
