package notify

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"webscan/internal/common"
	"webscan/internal/persist"
)

const Schema = `CREATE TABLE IF NOT EXISTS email_recipients(task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,recipient TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_try REAL NOT NULL,lease REAL NOT NULL DEFAULT 0,done REAL,result TEXT NOT NULL DEFAULT '',PRIMARY KEY(task_id,recipient));
CREATE INDEX IF NOT EXISTS email_ready ON email_recipients(done,next_try,lease);
CREATE TABLE IF NOT EXISTS email_attempts(id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,recipient TEXT NOT NULL,time REAL NOT NULL,result TEXT NOT NULL);`

var Categories = []string{"file_changes", "important_config_changes", "scan_matches", "scan_errors", "health_failures", "health_recoveries"}

func Enabled(c common.Map) bool {
	return common.B(common.M(c["feishu"])["enabled"]) || common.B(common.M(c["email"])["enabled"])
}
func Allows(c common.Map, target, category string) bool {
	f := common.M(c[target])
	return common.B(f["enabled"]) && (category == "" || common.B(common.M(f["notifications"])[category]))
}
func Recipients(c common.Map) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range common.SS(c["recipients"]) {
		v = strings.TrimSpace(v)
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
func Validate(c common.Map) error {
	if !common.B(c["enabled"]) {
		return nil
	}
	for _, k := range []string{"smtp_host", "username", "password", "from_address"} {
		if common.S(c[k]) == "" {
			return fmt.Errorf("email.%s 必须填写", k)
		}
	}
	for _, k := range []string{"smtp_host", "username", "password", "from_address", "from_name"} {
		if strings.ContainsAny(common.S(c[k]), "\r\n\x00") {
			return fmt.Errorf("email.%s 不能包含换行或空字符", k)
		}
	}
	if strings.ContainsAny(common.S(c["smtp_host"]), " /:@") {
		return fmt.Errorf("email.smtp_host 请填写主机名，不带协议或端口")
	}
	if p := common.I(c["smtp_port"]); p < 1 || p > 65535 {
		return fmt.Errorf("email.smtp_port 必须为 1～65535")
	}
	if v := common.S(c["tls_mode"]); v != "tls" && v != "starttls" {
		return fmt.Errorf("email.tls_mode 只能为 tls 或 starttls")
	}
	if v := common.I(c["timeout_seconds"]); v < 1 || v > 60 {
		return fmt.Errorf("email.timeout_seconds 必须为 1～60")
	}
	if v := common.I(c["max_per_minute"]); v < 1 || v > 600 {
		return fmt.Errorf("email.max_per_minute 必须为 1～600")
	}
	retry := common.M(c["retry"])
	if common.I(retry["initial_delay_seconds"]) < 1 || common.I(retry["max_delay_seconds"]) < common.I(retry["initial_delay_seconds"]) || common.I(retry["max_delay_seconds"]) > 86400 {
		return fmt.Errorf("email.retry 重试间隔必须至少 1 秒，最大间隔不得小于初始间隔或超过 86400 秒")
	}
	rs := Recipients(c)
	if len(rs) < 1 || len(rs) > 20 {
		return fmt.Errorf("email.recipients 请填写 1～20 个收件邮箱")
	}
	for _, v := range append(rs, common.S(c["from_address"])) {
		a, e := mail.ParseAddress(v)
		if e != nil || a.Address != v || !strings.Contains(v, "@") || strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("邮箱地址格式不正确：%s", v)
		}
	}
	return nil
}
func Enqueue(ctx context.Context, tx persist.SQLWriter, c common.Map, node, id string, payload common.Map, category string, priority int) error {
	for _, target := range []string{"feishu", "email"} {
		if !Allows(c, target, category) {
			continue
		}
		now := common.Now()
		result, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO tasks(node,event_id,target,payload,created,next_try,priority) VALUES(?,?,?,?,?,?,?)", node, id, target, string(common.JSON(payload)), now, now, priority)
		if e != nil {
			return e
		}
		if target != "email" {
			continue
		}
		inserted, _ := result.RowsAffected()
		if inserted == 0 {
			continue
		}
		var tid int64
		if e = tx.QueryRowContext(ctx, "SELECT id FROM tasks WHERE node=? AND event_id=? AND target='email'", node, id).Scan(&tid); e != nil {
			return e
		}
		for _, r := range Recipients(common.M(c["email"])) {
			if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO email_recipients(task_id,recipient,next_try) VALUES(?,?,?)", tid, r, now); e != nil {
				return e
			}
		}
	}
	return nil
}
