package controlplane

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"webscan/internal/common"
)

type NotificationTestWorker struct {
	Store    *Store
	Vault    *Vault
	Instance string
	Sender   NotificationSender
}
type notificationTestAttempt struct {
	Job, Owner   string
	Ordinal      int
	Epoch        int64
	Notification *Notification
}

func notificationTestAggregateTx(ctx context.Context, tx *sql.Tx, id string) error {
	var total, queued, sending, accepted, unknown, cancelled int
	e := tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE state='queued'),count(*) FILTER(WHERE state='sending'),count(*) FILTER(WHERE state='accepted'),count(*) FILTER(WHERE state='unknown'),count(*) FILTER(WHERE state='cancelled') FROM v3_notification_test_deliveries WHERE job=$1`, id).Scan(&total, &queued, &sending, &accepted, &unknown, &cancelled)
	if e != nil {
		return e
	}
	status, message := "running", "测试进行中，请核对各目标的实际状态"
	if queued+sending == 0 {
		switch {
		case total > 0 && accepted == total:
			status = "succeeded"
			message = "通道已确认接收；请核对实际收件，未表示已读"
		case total > 0 && cancelled == total:
			status = "cancelled"
			message = "未发送目标已取消；请重新预览已应用配置"
		case total > 0 && unknown == total:
			status = "unknown"
			message = "发送结果不确定，可能已送达；不会自动重发"
		case total == 0:
			status = "failed"
			message = "测试目标资料不可用，未继续发送"
		default:
			status = "partial"
			message = "部分目标已完成，请查看逐项结果；不确定目标不会自动重发"
		}
	} else if sending == 0 && accepted+unknown+cancelled == 0 {
		status = "queued"
		message = "测试任务已创建，等待通道速率额度"
	}
	_, e = tx.ExecContext(ctx, `UPDATE v3_notification_test_jobs SET status=$2,message=$3,updated_at=clock_timestamp(),finished_at=CASE WHEN $2 IN ('queued','running') THEN NULL ELSE COALESCE(finished_at,clock_timestamp()) END WHERE id=$1`, id, status, message)
	return e
}
func (w *NotificationTestWorker) claim(ctx context.Context) (*notificationTestAttempt, error) {
	rows, e := w.Store.DB.QueryContext(ctx, `SELECT id FROM (SELECT DISTINCT ON(channel) id,created_at FROM v3_notification_test_jobs j WHERE status IN ('queued','running') AND EXISTS(SELECT 1 FROM v3_notification_test_deliveries d WHERE d.job=j.id AND (d.state='queued' OR d.state='sending' AND d.lease_until<=clock_timestamp())) ORDER BY channel,created_at,id) candidates ORDER BY created_at,id`)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for _, id := range ids {
		a, e := w.claimJob(ctx, id)
		if e != nil || a != nil {
			return a, e
		}
	}
	return nil, nil
}
func (w *NotificationTestWorker) claimJob(ctx context.Context, id string) (*notificationTestAttempt, error) {
	tx, e := w.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if held, e := migrationHeld(ctx, tx); e != nil {
		return nil, e
	} else if held {
		return nil, nil
	}
	var a notificationTestAuthorization
	var rawTargets []byte
	var status string
	// Immutable owner is read before taking shared account/settings locks. A
	// later locked re-read below verifies all signed fields before execution.
	if e = tx.QueryRowContext(ctx, `SELECT username FROM v3_notification_test_jobs WHERE id=$1`, id).Scan(&a.Username); e != nil {
		return nil, e
	}
	account, accountErr := deploymentPreviewAccount(ctx, tx, a.Username)
	if accountErr != nil && !errors.Is(accountErr, ErrDeploymentPreview) {
		return nil, accountErr
	}
	var runtime int64
	var settings []byte
	if e = tx.QueryRowContext(ctx, `SELECT version,payload FROM v3_settings WHERE id=1 FOR SHARE`).Scan(&runtime, &settings); e != nil {
		return nil, e
	}
	e = tx.QueryRowContext(ctx, `SELECT id,username,account_revision,channel,runtime_version,targets,key_id,proof,expires_at,status FROM v3_notification_test_jobs WHERE id=$1 FOR UPDATE`, id).Scan(&a.ID, &a.Username, &a.Account, &a.Channel, &a.Runtime, &rawTargets, &a.Key, &a.Proof, &a.Expires, &status)
	if e != nil {
		return nil, e
	}
	if status != "queued" && status != "running" {
		return nil, tx.Commit()
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_notification_test_deliveries SET state='unknown',outcome='unconfirmed',message=$2,lease_owner=NULL,lease_until=NULL,finished_at=clock_timestamp() WHERE job=$1 AND state='sending' AND lease_until<=clock_timestamp()`, id, notificationTestOutcome("unknown")); e != nil {
		return nil, e
	}
	cancelled := ""
	if accountErr != nil || account != a.Account || runtime != a.Runtime {
		cancelled = "authorization_changed"
	}
	if time.Now().After(a.Expires) {
		cancelled = "expired"
	}
	var root common.Map
	if json.Unmarshal(settings, &root) != nil {
		return nil, errNotificationTestUnavailable
	}
	c := common.M(root[a.Channel])
	if !common.B(c["enabled"]) {
		cancelled = "authorization_changed"
	}
	if json.Unmarshal(rawTargets, &a.Targets) != nil || len(a.Targets) < 1 || len(a.Targets) > 20 {
		cancelled = "authorization_changed"
	}
	proof, proofErr := notificationTestHMAC(w.Vault, a.Key, "job", a, settings)
	if proofErr != nil {
		return nil, proofErr
	}
	if !hmac.Equal([]byte(proof), []byte(a.Proof)) {
		cancelled = "authorization_changed"
	}
	rows, e := tx.QueryContext(ctx, `SELECT ordinal,recipient FROM v3_notification_test_deliveries WHERE job=$1 ORDER BY ordinal`, id)
	if e != nil {
		return nil, e
	}
	index := 0
	for rows.Next() {
		var ordinal int
		var recipient string
		if e = rows.Scan(&ordinal, &recipient); e != nil {
			rows.Close()
			return nil, e
		}
		if index >= len(a.Targets) || ordinal != index+1 || recipient != a.Targets[index] {
			cancelled = "authorization_changed"
		}
		index++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if index != len(a.Targets) {
		cancelled = "authorization_changed"
	}
	if cancelled != "" {
		if _, e = tx.ExecContext(ctx, `UPDATE v3_notification_test_deliveries SET state='cancelled',outcome=$2,message=$3,finished_at=clock_timestamp() WHERE job=$1 AND state='queued'`, id, cancelled, notificationTestOutcome("cancelled")); e != nil {
			return nil, e
		}
	}
	if e = notificationTestAggregateTx(ctx, tx, id); e != nil {
		return nil, e
	}
	if cancelled != "" {
		return nil, tx.Commit()
	}
	var ordinal int
	var recipient string
	e = tx.QueryRowContext(ctx, `SELECT ordinal,recipient FROM v3_notification_test_deliveries WHERE job=$1 AND state='queued' ORDER BY ordinal LIMIT 1 FOR UPDATE`, id).Scan(&ordinal, &recipient)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, tx.Commit()
	}
	if e != nil {
		return nil, e
	}
	reserved, e := channelRateSlotTx(ctx, tx, a.Channel, root)
	if e != nil {
		return nil, e
	}
	if !reserved {
		return nil, tx.Commit()
	}
	attempt := &notificationTestAttempt{Job: id, Owner: w.Instance, Ordinal: ordinal}
	var quotaExpires time.Time
	if w.Store.HostQuota != nil {
		grant, err := w.Store.HostQuota.Reserve(ctx, a.Channel, "test:"+id+":"+string(common.JSON(ordinal))+":"+token(), runtime)
		if err != nil {
			return nil, err
		}
		if !grant.New || !grant.ExpiresAt.After(time.Now()) {
			return nil, nil
		}
		quotaExpires = grant.ExpiresAt
	}
	if e = tx.QueryRowContext(ctx, `UPDATE v3_notification_test_deliveries SET state='sending',attempts=1,started_at=clock_timestamp(),lease_owner=$3,lease_epoch=lease_epoch+1,lease_until=clock_timestamp()+interval '90 seconds',message='正在发送，等待通道确认' WHERE job=$1 AND ordinal=$2 AND state='queued' RETURNING lease_epoch`, id, ordinal, w.Instance).Scan(&attempt.Epoch); e != nil {
		return nil, e
	}
	if e = notificationTestAggregateTx(ctx, tx, id); e != nil {
		return nil, e
	}
	attempt.Notification = &Notification{Owner: w.Instance, Channel: a.Channel, Node: "central", EventID: "notification-test:" + id, Recipient: recipient, Settings: root, Payload: common.JSON(map[string]string{"message": notificationTestBody, "source": "test"}), DeliveryKey: digest([]byte("notification-test:" + id + ":" + string(common.JSON(ordinal))))}
	attempt.Notification.HostQuotaExpiresAt = quotaExpires
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return attempt, nil
}
func (w *NotificationTestWorker) finish(ctx context.Context, a *notificationTestAttempt, accepted bool) error {
	tx, e := w.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var id string
	if e = tx.QueryRowContext(ctx, `SELECT id FROM v3_notification_test_jobs WHERE id=$1 FOR UPDATE`, a.Job).Scan(&id); e != nil {
		return e
	}
	state, outcome := "unknown", "unconfirmed"
	if accepted {
		state, outcome = "accepted", "accepted"
	}
	res, e := tx.ExecContext(ctx, `UPDATE v3_notification_test_deliveries SET state=$5,outcome=$6,message=$7,lease_owner=NULL,lease_until=NULL,finished_at=clock_timestamp() WHERE job=$1 AND ordinal=$2 AND state='sending' AND lease_owner=$3 AND lease_epoch=$4 AND lease_until>clock_timestamp()`, a.Job, a.Ordinal, a.Owner, a.Epoch, state, outcome, notificationTestOutcome(state))
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrLeaseLost
	}
	if e = notificationTestAggregateTx(ctx, tx, a.Job); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) SELECT username,'notification-test-outcome',id,$2 FROM v3_notification_test_jobs WHERE id=$1`, a.Job, common.JSON(map[string]any{"ordinal": a.Ordinal, "outcome": outcome})); e != nil {
		return e
	}
	return tx.Commit()
}
func (w *NotificationTestWorker) RunRound(ctx context.Context) error {
	if w.Store == nil || w.Vault == nil || !identifier.MatchString(w.Instance) {
		return errNotificationTestUnavailable
	}
	a, e := w.claim(ctx)
	if e != nil || a == nil {
		return e
	}
	sender := w.Sender
	if sender == nil {
		sender = ChannelSender{}
	}
	op, cancel := context.WithTimeout(ctx, 60*time.Second)
	sendErr := sender.Send(op, a.Notification)
	cancel()
	// Persist a known response during graceful shutdown too; on loss or crash the
	// committed sending marker eventually becomes unknown, never a second send.
	finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return w.finish(finish, a, sendErr == nil)
}
func (w *NotificationTestWorker) heartbeat(ctx context.Context, result error) error {
	message := ""
	key := ""
	if w.Vault != nil {
		key = w.Vault.active
	}
	if result != nil {
		message = "通知测试工作器或共享密钥不可用"
	}
	_, e := w.Store.DB.ExecContext(ctx, `INSERT INTO v3_role_status(role,instance,heartbeat,error,details) VALUES('notification-tests',$1,clock_timestamp(),$2,$3) ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error,details=excluded.details`, w.Instance, message, common.JSON(map[string]string{"vault_key_id": key}))
	return e
}
func (w *NotificationTestWorker) Run(ctx context.Context) error {
	if w.Store == nil || w.Vault == nil || !identifier.MatchString(w.Instance) {
		return errNotificationTestUnavailable
	}
	// Prove the independent queue is queryable before announcing readiness.
	var probe bool
	initialErr := w.Store.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_notification_test_jobs)`).Scan(&probe)
	var stateMu sync.Mutex
	lastErr := initialErr
	heartbeatCtx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for heartbeatCtx.Err() == nil {
			op, cancel := context.WithTimeout(heartbeatCtx, 5*time.Second)
			err := w.Store.vaultAvailable(op, w.Vault)
			stateMu.Lock()
			if err == nil {
				err = lastErr
			}
			stateMu.Unlock()
			_ = w.heartbeat(op, err)
			cancel()
			if !waitRetry(heartbeatCtx, 5*time.Second) {
				return
			}
		}
	}()
	defer func() { stop(); wg.Wait() }()
	for ctx.Err() == nil {
		err := w.Store.vaultAvailable(ctx, w.Vault)
		if err == nil {
			err = w.RunRound(ctx)
		}
		stateMu.Lock()
		lastErr = err
		stateMu.Unlock()
		_ = w.heartbeat(ctx, err)
		if !waitRetry(ctx, time.Second) {
			break
		}
	}
	return ctx.Err()
}

// A database copy cannot restore authorization to send real messages.
func quarantineNotificationTestsTx(ctx context.Context, tx *sql.Tx) error {
	if _, e := tx.ExecContext(ctx, `DELETE FROM v3_role_status WHERE role='notification-tests'`); e != nil {
		return e
	}

	if _, e := tx.ExecContext(ctx, `UPDATE v3_notification_test_previews SET used=true,expires_at=GREATEST(created_at+interval '1 microsecond',LEAST(expires_at,clock_timestamp()))`); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, `UPDATE v3_notification_test_deliveries SET state='cancelled',outcome='restored',message='灾备恢复已撤销未执行的测试授权',finished_at=clock_timestamp() WHERE state='queued'`); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, `UPDATE v3_notification_test_deliveries SET state='unknown',outcome='unconfirmed',message='灾备恢复前发送结果不确定，可能已送达；不会自动重发',lease_owner=NULL,lease_until=NULL,finished_at=clock_timestamp() WHERE state='sending'`); e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, `SELECT id FROM v3_notification_test_jobs WHERE status IN ('queued','running') ORDER BY id`)
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		if e = notificationTestAggregateTx(ctx, tx, id); e != nil {
			return e
		}
	}
	return nil
}
