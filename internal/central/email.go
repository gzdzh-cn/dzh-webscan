package central

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/notify"
	"webscan/internal/persist"
)

func ensureEmailSchema(d *sql.DB, config common.Map) error {
	var existing int
	d.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='tasks'").Scan(&existing)
	var migrated int
	d.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='email_recipients'").Scan(&migrated)
	if existing > 0 && migrated == 0 {
		backup := filepath.Join(common.S(config["backup_dir"]), "email-migration-"+common.ID()+".sqlite3")
		if common.S(config["backup_dir"]) == "" {
			backup = filepath.Join(common.S(config["data_dir"]), "migration-backups", "email-"+common.ID()+".sqlite3")
		}
		if e := persist.BackupDB(d, backup); e != nil {
			return fmt.Errorf("邮件数据库迁移前备份失败：%w", e)
		}
	}
	if _, e := d.Exec(Schema + notify.Schema); e != nil {
		return e
	}

	return nil
}

// claimEmail reserves one recipient and a persisted rate slot, shared with the host watchdog.
func (s *Store) claimEmail(ctx context.Context, watchdog bool) (*Task, string, error) {
	c := common.M(s.Snapshot()["email"])
	if !common.B(c["enabled"]) {
		return nil, "", nil
	}
	tx, e := persist.BeginWrite(ctx, s.DB)
	if e != nil {
		return nil, "", e
	}
	defer tx.Rollback()
	now := common.Now()
	var raw string
	history := []float64{}
	e = tx.QueryRowContext(ctx, "SELECT value FROM kv WHERE key='email_rate_history'").Scan(&raw)
	if e != nil && e != sql.ErrNoRows {
		return nil, "", e
	}
	if v, err := common.Decode([]byte(raw)); err == nil {
		for _, n := range common.A(v) {
			if common.F(n) > now-60 {
				history = append(history, common.F(n))
			}
		}
	}
	if len(history) >= max(1, common.I(c["max_per_minute"])) {
		return nil, "", nil
	}
	q := `SELECT t.id,t.node,t.event_id,t.target,t.payload,r.attempts,r.recipient FROM tasks t JOIN email_recipients r ON r.task_id=t.id WHERE t.target='email' AND t.done IS NULL AND r.done IS NULL AND r.next_try<=? AND r.lease<=? AND NOT EXISTS(SELECT 1 FROM tasks earlier JOIN email_recipients er ON er.task_id=earlier.id WHERE earlier.target='email' AND earlier.id<t.id AND earlier.node=t.node AND er.recipient=r.recipient AND er.done IS NULL AND ((t.event_id LIKE 'website:%' AND earlier.event_id LIKE 'website:%') OR (t.event_id LIKE 'native:%' AND earlier.event_id LIKE 'native:%') OR (t.event_id LIKE 'watchdog:%' AND earlier.event_id LIKE 'watchdog:%'))) `
	if watchdog {
		q += " AND t.event_id LIKE 'watchdog:%'"
	}
	q += " ORDER BY t.priority DESC,t.id,r.recipient LIMIT 1"
	t := &Task{}
	recipient := ""
	e = tx.QueryRowContext(ctx, q, now, now).Scan(&t.ID, &t.Node, &t.EventID, &t.Target, &t.Payload, &t.Attempts, &recipient)
	if e == sql.ErrNoRows {
		return nil, "", nil
	}
	if e != nil {
		return nil, "", e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE email_recipients SET lease=? WHERE task_id=? AND recipient=?", now+120, t.ID, recipient); e != nil {
		return nil, "", e
	}
	history = append(history, now)
	if _, e = tx.ExecContext(ctx, "INSERT INTO kv VALUES('email_rate_history',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", string(common.JSON(history))); e != nil {
		return nil, "", e
	}
	return t, recipient, tx.Commit()
}
func emailSubject(message string) string {
	line, _, _ := strings.Cut(message, "\n")
	if len([]rune(line)) > 80 {
		line = string([]rune(line)[:80])
	}
	return "【网站监控】" + line
}
func (s *Store) emailAttempt(ctx context.Context, t *Task, recipient string) error {
	v, e := common.Decode([]byte(t.Payload))
	if e != nil {
		return e
	}
	message := common.S(common.M(v)["message"])
	if message == "" {
		message = eventNotice(common.M(v))
	}
	c := common.M(s.Snapshot()["email"])
	if !common.B(c["enabled"]) {
		_, e = s.DB.ExecContext(ctx, "UPDATE email_recipients SET lease=0 WHERE task_id=? AND recipient=?", t.ID, recipient)
		return e
	}
	send := notify.Send
	if s.emailSend != nil {
		send = s.emailSend
	}
	err := send(ctx, c, recipient, common.Hash([]byte(fmt.Sprintf("%d:%s", t.ID, recipient))), emailSubject(message), message)
	result := "已提交邮件服务器"
	if err != nil {
		result = err.Error()
	}
	tx, e := persist.BeginWrite(ctx, s.DB)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	now := common.Now()
	if _, e = tx.ExecContext(ctx, "INSERT INTO email_attempts(task_id,recipient,time,result) VALUES(?,?,?,?)", t.ID, recipient, now, result); e != nil {
		return e
	}
	if err == nil {
		_, e = tx.ExecContext(ctx, "UPDATE email_recipients SET done=?,attempts=attempts+1,lease=0,result=? WHERE task_id=? AND recipient=?", now, result, t.ID, recipient)
	} else {
		retry := common.M(c["retry"])
		delay := min(max(1, common.I(retry["max_delay_seconds"])), max(1, common.I(retry["initial_delay_seconds"]))*int(int64(1)<<min(t.Attempts, 16)))
		_, e = tx.ExecContext(ctx, "UPDATE email_recipients SET attempts=attempts+1,lease=0,next_try=?,result=? WHERE task_id=? AND recipient=?", now+float64(delay), result, t.ID, recipient)
	}
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE tasks SET attempts=(SELECT sum(attempts) FROM email_recipients WHERE task_id=?),next_try=coalesce((SELECT min(next_try) FROM email_recipients WHERE task_id=? AND done IS NULL),?),result=?,done=CASE WHEN NOT EXISTS(SELECT 1 FROM email_recipients WHERE task_id=? AND done IS NULL) THEN ? ELSE NULL END WHERE id=?", t.ID, t.ID, now, result, t.ID, now, t.ID); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) emailWorker(ctx context.Context) {
	for ctx.Err() == nil {
		t, r, e := s.claimEmail(ctx, false)
		if e != nil {
			fmt.Println("邮箱队列读取失败：" + common.SecretFree(e))
		}
		if t != nil {
			if e = s.emailAttempt(ctx, t, r); e != nil {
				fmt.Println("邮箱投递记录保存失败：" + common.SecretFree(e))
			}
		} else {
			common.Sleep(ctx, time.Second)
		}
	}
}
func (s *Store) emailTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		consoleError(w, 405, "请使用发送测试邮件操作")
		return
	}
	if e := notify.Validate(common.M(s.Snapshot()["email"])); e != nil {
		consoleError(w, 400, e.Error())
		return
	}
	if !common.B(common.M(s.Snapshot()["email"])["enabled"]) {
		consoleError(w, 400, "请先开启并应用邮箱配置")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e == nil {
		defer tx.Rollback()
		var stamp string
		e = tx.QueryRowContext(r.Context(), "SELECT value FROM kv WHERE key='email_test_last'").Scan(&stamp)
		if e == sql.ErrNoRows {
			e = nil
		}
		var last float64
		fmt.Sscan(stamp, &last)
		if e == nil && common.Now()-last < 30 {
			consoleError(w, 429, "测试邮件每 30 秒最多发送一次")
			return
		}
		if e == nil {
			e = notify.Enqueue(r.Context(), tx, common.Map{"email": s.Snapshot()["email"]}, "central", "email-test:"+common.ID(), common.Map{"message": "邮箱通知测试\n这是管理员主动发送的测试邮件，不是业务异常。\n发生时间：" + noticeTime(common.Stamp()), "source": "test"}, "", 100)
		}
		if e == nil {
			_, e = tx.ExecContext(r.Context(), "INSERT INTO kv VALUES('email_test_last',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", fmt.Sprint(common.Now()))
		}
		if e == nil {
			e = tx.Commit()
		}
	}
	if e != nil {
		consoleError(w, 503, "测试邮件入队失败")
		return
	}
	write(w, 200, common.Map{"message": "测试邮件已入队，请查看邮箱通知历史", "recipients": notify.Recipients(common.M(s.Snapshot()["email"]))})
}
