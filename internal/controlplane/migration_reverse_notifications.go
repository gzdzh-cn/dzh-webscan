package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"webscan/internal/common"
)

type migrationLegacyPendingError string

func (e migrationLegacyPendingError) Error() string { return string(e) }
func migrationLegacyInt(v any) (int64, error) {
	var raw string
	switch value := v.(type) {
	case json.Number:
		raw = value.String()
	case int64:
		return value, nil
	case int:
		return int64(value), nil
	case string:
		raw = value
	default:
		return 0, ErrMigrationSession
	}
	n, e := strconv.ParseInt(raw, 10, 64)
	if e != nil {
		return 0, ErrMigrationSession
	}
	return n, nil
}
func migrationLegacyNumericID(v any) string {
	n, e := migrationLegacyInt(v)
	if e != nil || n < 1 {
		return ""
	}
	return strconv.FormatInt(n, 10)
}
func (s *MigrationLegacySink) migrationLegacyNoticeIdentityTx(ctx context.Context, tx *sql.Tx, data common.Map) error {
	if migrationLegacyNumericID(data["id"]) == "" {
		return ErrMigrationSession
	}
	task, e := migrationLegacyInt(data["migration_task"])
	if e != nil || task < 1 {
		return ErrMigrationSession
	}
	if !s.roles["central"] {
		return migrationLegacyPendingError("reverse_required_legacy_database_missing")
	}
	var exists int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM central.tasks WHERE id=?`, task).Scan(&exists); e != nil || exists != 1 {
		return ErrMigrationSession
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO migration_notice_tasks VALUES(?,?,?,?) ON CONFLICT(notification) DO UPDATE SET task=excluded.task,channel=excluded.channel,recipient=excluded.recipient`, migrationLegacyNumericID(data["id"]), task, common.S(data["channel"]), common.S(data["recipient"]))
	return e
}
func (s *MigrationLegacySink) migrationLegacyNotificationTx(ctx context.Context, tx *sql.Tx, operation string, data common.Map) error {
	if migrationLegacyNumericID(data["id"]) == "" {
		return ErrMigrationSession
	}
	if !s.roles["central"] {
		return migrationLegacyPendingError("reverse_required_legacy_database_missing")
	}
	channel, recipient := common.S(data["channel"]), common.S(data["recipient"])
	if channel != "feishu" && channel != "email" {
		return migrationLegacyPendingError("reverse_notification_channel_not_supported")
	}
	var task int64
	err := tx.QueryRowContext(ctx, `SELECT task FROM migration_notice_tasks WHERE notification=?`, migrationLegacyNumericID(data["id"])).Scan(&task)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if operation == "DELETE" {
		if err == sql.ErrNoRows {
			return migrationLegacyPendingError("reverse_notification_origin_missing")
		}
		if channel == "email" && recipient != "" {
			if _, err = tx.ExecContext(ctx, `DELETE FROM central.email_recipients WHERE task_id=? AND recipient=?`, task, recipient); err != nil {
				return err
			}
			var remaining int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM central.email_recipients WHERE task_id=?`, task).Scan(&remaining); err != nil {
				return err
			}
			if remaining > 0 {
				return nil
			}
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM central.tasks WHERE id=?`, task)
		return err
	}
	if err == sql.ErrNoRows && data["migration_task"] != nil {
		task, err = migrationLegacyInt(data["migration_task"])
		if err != nil || task < 1 {
			return ErrMigrationSession
		}
	}
	payload := common.M(data["payload"])
	if len(payload) == 0 {
		return ErrMigrationSession
	}
	node, event := common.S(data["node"]), common.S(data["event_id"])
	if strings.HasPrefix(event, "server-alert:") {
		node = "central"
		event = "native:" + strings.TrimPrefix(event, "server-alert:")
		if common.S(payload["source"]) != "health" {
			return migrationLegacyPendingError("reverse_health_notification_payload_not_legacy")
		}
	}
	created, e := migrationLegacyTime(data["created_at"], false)
	if e != nil {
		return e
	}
	next, e := migrationLegacyTime(data["next_try"], false)
	if e != nil {
		return e
	}
	done, e := migrationLegacyTime(data["done_at"], false)
	if e != nil {
		return e
	}
	attempts, e := migrationLegacyInt(data["attempts"])
	if e != nil {
		return e
	}
	if channel == "email" && done == nil && attempts > 0 {
		legacyKey := digest([]byte(fmt.Sprintf("%d:%s", task, recipient)))
		if task == 0 || common.S(data["delivery_key"]) != legacyKey {
			return migrationLegacyPendingError("reverse_pending_email_delivery_key_not_preserved")
		}
	}
	if task == 0 {
		// Email recipients share one real legacy task; never duplicate the enqueue.
		e = tx.QueryRowContext(ctx, `SELECT id FROM central.tasks WHERE node=? AND event_id=? AND target=?`, node, event, channel).Scan(&task)
		if e == sql.ErrNoRows {
			if e = tx.QueryRowContext(ctx, `SELECT coalesce(max(id),0)+1 FROM central.tasks`).Scan(&task); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
	}
	var oldNode, oldEvent, oldChannel, oldPayload string
	e = tx.QueryRowContext(ctx, `SELECT node,event_id,target,payload FROM central.tasks WHERE id=?`, task).Scan(&oldNode, &oldEvent, &oldChannel, &oldPayload)
	if e == nil {
		if oldNode != node || oldEvent != event || oldChannel != channel || !migrationLegacyValueEqual(oldPayload, string(common.JSON(payload))) {
			return ErrConflict
		}
	} else if e != sql.ErrNoRows {
		return e
	}
	if e == sql.ErrNoRows {
		if _, e = tx.ExecContext(ctx, `INSERT INTO central.tasks(id,node,event_id,target,payload,created,next_try,attempts,lease,done,result,priority) VALUES(?,?,?,?,?,?,?,?,0,?,?,0)`, task, node, event, channel, string(common.JSON(payload)), created, next, attempts, done, common.S(data["result"])); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO migration_notice_tasks VALUES(?,?,?,?) ON CONFLICT(notification) DO UPDATE SET task=excluded.task,channel=excluded.channel,recipient=excluded.recipient`, migrationLegacyNumericID(data["id"]), task, channel, recipient); e != nil {
		return e
	}
	if channel == "feishu" || recipient == "" {
		_, e = tx.ExecContext(ctx, `UPDATE central.tasks SET next_try=?,attempts=?,lease=0,done=?,result=? WHERE id=?`, next, attempts, done, common.S(data["result"]), task)
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO central.email_recipients(task_id,recipient,attempts,next_try,lease,done,result) VALUES(?,?,?,?,0,?,?) ON CONFLICT(task_id,recipient) DO UPDATE SET attempts=excluded.attempts,next_try=excluded.next_try,lease=0,done=excluded.done,result=excluded.result`, task, recipient, attempts, next, done, common.S(data["result"])); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE central.tasks SET lease=0,done=CASE WHEN EXISTS(SELECT 1 FROM central.email_recipients WHERE task_id=? AND done IS NULL) THEN NULL ELSE (SELECT max(done) FROM central.email_recipients WHERE task_id=?) END WHERE id=?`, task, task, task)
	return e
}
func (s *MigrationLegacySink) migrationLegacyAttemptTx(ctx context.Context, tx *sql.Tx, operation string, data common.Map) error {
	if !s.roles["central"] {
		return migrationLegacyPendingError("reverse_required_legacy_database_missing")
	}
	var task int64
	var channel, recipient string
	if e := tx.QueryRowContext(ctx, `SELECT task,channel,recipient FROM migration_notice_tasks WHERE notification=?`, migrationLegacyNumericID(data["notification"])).Scan(&task, &channel, &recipient); e != nil {
		return migrationLegacyPendingError("reverse_attempt_notification_missing")
	}
	table := "delivery_records"
	if channel == "email" {
		table = "email_attempts"
	}
	id := common.S(data["migration_record"])
	if id == "" {
		id = migrationLegacyNumericID(data["id"])
	}
	if _, e := strconv.ParseInt(id, 10, 64); e != nil {
		return ErrMigrationSession
	}
	at, e := migrationLegacyTime(data["created_at"], false)
	if e != nil {
		return e
	}
	values := common.Map{"id": json.Number(id), "task_id": task, "time": at}
	if channel == "email" {
		values["recipient"] = recipient
		values["result"] = common.S(data["result"])
	} else {
		values["target"] = channel
		values["status"] = common.S(data["result"])
	}
	return migrationLegacyWriteTx(ctx, tx, migrationLegacyProjection{"central", table, []string{"id"}, values}, operation)
}
func (s *MigrationLegacySink) migrationLegacyRatesTx(ctx context.Context, tx *sql.Tx, operation string, data common.Map) error {
	if !s.roles["central"] {
		return migrationLegacyPendingError("reverse_required_legacy_database_missing")
	}
	if common.S(data["channel"]) != "feishu" {
		return migrationLegacyPendingError("reverse_rate_channel_not_legacy")
	}
	if operation == "DELETE" {
		_, e := tx.ExecContext(ctx, `DELETE FROM central.kv WHERE key='feishu_rate_history'`)
		return e
	}
	_, e := tx.ExecContext(ctx, `INSERT INTO central.kv VALUES('feishu_rate_history',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(common.JSON(data["history"])))
	return e
}
