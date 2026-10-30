package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"webscan/internal/common"
)

func decodedArchiveRecord(raw []byte, hash string) (archivedRecord, error) {
	var object map[string]any
	if len(raw) > 2<<20 || json.Unmarshal(raw, &object) != nil {
		return nil, errors.New("归档记录格式不正确或超限")
	}
	canonical, _ := json.Marshal(object)
	if digest(canonical) != hash {
		return nil, errors.New("归档记录摘要发生变化")
	}
	var r archivedRecord
	if json.Unmarshal(raw, &r) != nil {
		return nil, errors.New("归档字段格式不正确")
	}
	return r, nil
}
func archiveLinked(ctx context.Context, tx *sql.Tx, source, table, field, value string) ([]archivedRecord, error) {
	// Field/table are private constants selected by the mapper, never API input.
	rows, err := tx.QueryContext(ctx, "SELECT payload,digest FROM v3_legacy_records WHERE source=$1 AND table_name=$2 AND payload->$3->>'value'=$4 ORDER BY record_key::bigint LIMIT 1001", source, table, field, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []archivedRecord{}
	for rows.Next() {
		var raw []byte
		var hash string
		if err = rows.Scan(&raw, &hash); err != nil {
			return nil, err
		}
		r, e := decodedArchiveRecord(raw, hash)
		if e != nil {
			return nil, e
		}
		result = append(result, r)
	}
	if len(result) > 1000 {
		return nil, errors.New("单个旧任务关联记录过多")
	}
	return result, rows.Err()
}

func (s *Store) MapNotificationArchive(ctx context.Context, source string) (DomainImportReport, error) {
	tables := []string{"tasks", "email_recipients", "delivery_records", "email_attempts", "kv"}
	report, err := s.mapArchiveDomain(ctx, source, "", "notifications", tables, []string{"tasks"}, func(ctx context.Context, tx *sql.Tx) error {
		return bindMigrationDomain(ctx, tx, "notifications", source, "", []string{"v3_notifications", "v3_notification_attempts"})
	}, func(ctx context.Context, tx *sql.Tx, table string, r archivedRecord) (bool, error) {
		return mapNotificationRecord(ctx, tx, source, table, r)
	})
	if err == nil {
		err = s.reconcileHealthArchive(ctx)
	}
	if err != nil {
		report.Complete = false
	}
	return report, safeMappingError(err)
}

type archivedNotice struct {
	task                 int64
	node, event, channel string
	payload              common.Map
	created, next        time.Time
	done                 *time.Time
	attempts             int64
}

func parseArchivedNotice(r archivedRecord) (v archivedNotice, err error) {
	if v.task, err = r.integer("id"); err != nil || v.task < 1 {
		return v, errors.New("旧通知任务编号不正确")
	}
	if v.node, err = archiveText(r, "node", 512); err != nil {
		return v, err
	}
	if v.event, err = archiveText(r, "event_id", 1024); err != nil {
		return v, err
	}
	if v.channel, err = archiveText(r, "target", 64); err != nil {
		return v, err
	}
	raw, err := r.text("payload")
	if err != nil || json.Unmarshal([]byte(raw), &v.payload) != nil || v.payload == nil {
		return v, errors.New("旧通知载荷格式不正确")
	}
	created, err := r.timestamp("created", false)
	if err != nil {
		return v, err
	}
	v.created = *created
	next, err := r.timestamp("next_try", false)
	if err != nil {
		return v, err
	}
	v.next = *next
	lease, err := r.timestamp("lease", false)
	if err != nil {
		return v, err
	}
	if lease.After(v.next) {
		v.next = *lease
	}
	if v.done, err = r.timestamp("done", true); err != nil {
		return v, err
	}
	if v.attempts, err = r.integer("attempts"); err != nil || v.attempts < 0 || v.attempts > 2147483647 {
		return v, errors.New("旧通知重试次数不正确")
	}
	if strings.HasPrefix(v.event, "native:") {
		node := common.S(v.payload["node_id"])
		phase := common.S(v.payload["notice_kind"])
		if node == "" || len(node) > 512 || !utf8.ValidString(node) || strings.ContainsRune(node, 0) || strings.TrimPrefix(v.event, "native:") == "" || common.S(v.payload["source"]) != "health" || (phase != "firing" && phase != "resolved" && phase != "reminder") {
			return v, errors.New("旧服务器通知缺少节点身份")
		}
		v.node = node
		v.event = "server-alert:" + strings.TrimPrefix(v.event, "native:")
	}
	return v, nil
}
func insertArchivedNotice(ctx context.Context, tx *sql.Tx, source string, v archivedNotice, recipient string, r archivedRecord) error {
	done, next, attempts := v.done, v.next, v.attempts
	if r != nil {
		var err error
		if done, err = r.timestamp("done", true); err != nil {
			return err
		}
		n, err := r.timestamp("next_try", false)
		if err != nil {
			return err
		}
		next = *n
		lease, err := r.timestamp("lease", false)
		if err != nil {
			return err
		}
		if lease.After(next) {
			next = *lease
		}
		if attempts, err = r.integer("attempts"); err != nil || attempts < 0 || attempts > 2147483647 {
			return errors.New("旧收件人重试次数不正确")
		}
		if v.done != nil && done == nil {
			return errors.New("已完成邮件任务仍有未完成收件人")
		}
	}
	key := ""
	if v.channel == "email" {
		key = digest([]byte(fmt.Sprintf("%d:%s", v.task, recipient)))
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO v3_notifications(node,event_id,channel,recipient,payload,created_at,next_try,attempts,done_at,result,migration_source,migration_task,migration_pending,delivery_key)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'旧版本投递记录，原始结果保存在受控归档',$10,$11,true,$12)`, v.node, v.event, v.channel, recipient, common.JSON(v.payload), v.created, next, attempts, done, source, v.task, key)
	return err
}

func mapNotificationRecord(ctx context.Context, tx *sql.Tx, source, table string, r archivedRecord) (bool, error) {
	switch table {
	case "tasks":
		v, err := parseArchivedNotice(r)
		if err != nil {
			return false, err
		}
		if v.channel != "feishu" && v.channel != "email" {
			if v.channel == "loki" && v.done != nil {
				return false, nil
			}
			return false, errors.New("源队列存在未迁移的投递目标，禁止丢弃待投递任务")
		}
		if v.channel == "feishu" {
			return true, insertArchivedNotice(ctx, tx, source, v, "", nil)
		}
		recipients, err := archiveLinked(ctx, tx, source, "email_recipients", "task_id", strconv.FormatInt(v.task, 10))
		if err != nil {
			return false, err
		}
		if len(recipients) == 0 {
			if v.done == nil {
				return false, errors.New("待投递邮件缺少原收件人，不能按当前设置猜测")
			}
			return true, insertArchivedNotice(ctx, tx, source, v, "", nil)
		}
		for _, rec := range recipients {
			address, err := archiveText(rec, "recipient", 320)
			if err != nil {
				return false, err
			}
			parsed, err := mail.ParseAddress(address)
			if err != nil || parsed.Address != address || strings.ContainsAny(address, "\r\n") {
				return false, errors.New("原收件邮箱格式不正确")
			}
			if err = insertArchivedNotice(ctx, tx, source, v, address, rec); err != nil {
				return false, err
			}
		}
		return true, nil
	case "email_recipients":
		task, err := r.integer("task_id")
		if err != nil {
			return false, err
		}
		recipient, err := r.text("recipient")
		if err != nil {
			return false, err
		}
		var exists bool
		err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_notifications WHERE migration_source=$1 AND migration_task=$2 AND channel='email' AND recipient=$3)", source, task, recipient).Scan(&exists)
		if err != nil {
			return false, err
		}
		if !exists {
			return false, errors.New("原收件人缺少对应任务")
		}
		return true, nil
	case "email_attempts", "delivery_records":
		id, err := r.integer("id")
		if err != nil || id < 1 {
			return false, errors.New("旧投递尝试编号不正确")
		}
		task, err := r.integer("task_id")
		if err != nil {
			return false, err
		}
		channel, recipient, result := "email", "", ""
		if table == "delivery_records" {
			channel, err = r.text("target")
			if err != nil {
				return false, err
			}
			if channel == "loki" {
				return false, nil
			}
			if channel != "feishu" {
				return false, errors.New("旧投递尝试通道不支持")
			}
			result, err = r.text("status")
		} else {
			recipient, err = r.text("recipient")
			if err == nil {
				result, err = r.text("result")
			}
		}
		if err != nil {
			return false, err
		}
		at, err := r.timestamp("time", false)
		if err != nil {
			return false, err
		}
		// Old SQLite history may outlive its completed task. Keep that orphan in
		// the lossless archive; pending tasks and recipients are never guessed.
		var target int64
		err = tx.QueryRowContext(ctx, "SELECT id FROM v3_notifications WHERE migration_source=$1 AND migration_task=$2 AND channel=$3 AND recipient=$4", source, task, channel, recipient).Scan(&target)
		if err == sql.ErrNoRows {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		success := result == "已提交邮件服务器" || strings.HasSuffix(result, ",business=0")
		_, err = tx.ExecContext(ctx, `INSERT INTO v3_notification_attempts(notification,epoch,success,result,created_at,migration_source,migration_table,migration_record) VALUES($1,0,$2,'旧版本投递尝试，原始结果保存在受控归档',$3,$4,$5,$6)`, target, success, at, source, table, id)
		return err == nil, err
	case "kv":
		key, err := r.text("key")
		if err != nil {
			return false, err
		}
		channel := ""
		if key == "feishu_rate_history" {
			channel = "feishu"
		}
		if key == "email_rate_history" {
			channel = "email"
		}
		if channel == "" {
			return false, nil
		}
		raw, err := r.text("value")
		if err != nil {
			return false, err
		}
		var history []float64
		// Legacy Feishu limits could exceed the current 600/minute limit.
		// Preserve their complete bounded source window rather than dropping it.
		if json.Unmarshal([]byte(raw), &history) != nil || len(history) > 100000 {
			return false, errors.New("原通知限流记录不正确")
		}
		for _, at := range history {
			if !(at >= 0 && at < 253402300800) {
				return false, errors.New("原限流时间不正确")
			}
		}
		// The target is empty/fenced, so preserve the source's rate window too.
		_, err = tx.ExecContext(ctx, "INSERT INTO v3_notification_rates(channel,history) VALUES($1,$2) ON CONFLICT(channel) DO UPDATE SET history=excluded.history", channel, raw)
		return err == nil, err
	}
	return false, errors.New("不支持的通知迁移表")
}
