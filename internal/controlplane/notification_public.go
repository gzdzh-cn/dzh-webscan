package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type notificationPublicContent struct {
	Source, Subject, Summary, Body, State, Reason string
	Truncated                                     bool
}

func validNotificationSource(source string) bool {
	switch source {
	case "event", "server_health", "website", "test", "legacy", "unknown":
		return true
	}
	return false
}

// Public fields are a limited business view, not the exact provider message.
// Paths remain potentially sensitive business data; this is not a claim that
// arbitrary file names are secret-free. Unknown fields never leave this view.
func renderNotificationPublic(raw []byte, source string) notificationPublicContent {
	p := notificationPublicContent{Source: source, State: "available"}
	var v map[string]json.RawMessage
	if source == "legacy" || source == "unknown" {
		p.State, p.Subject, p.Summary = "unsupported", "通知记录", "此记录未生成可核验的公共正文。"
		p.Reason = "无法确认通知内容来源。"
		if source == "legacy" {
			p.Subject, p.Reason = "旧版通知", "旧版记录未生成公共正文。"
		}
		return p
	}
	if json.Unmarshal(raw, &v) != nil || v == nil {
		p.State, p.Subject, p.Reason = "unsupported", "通知记录", "通知业务字段不受支持。"
		return p
	}
	text := func(key string) string {
		var s string
		_ = json.Unmarshal(v[key], &s)
		return s
	}
	lines := []string{}
	switch source {
	case "event":
		op := map[string]string{"create": "发现新增文件", "modify": "发现文件被修改", "delete": "发现文件被删除", "move": "发现文件被移动或改名", "scan": "文件安全检查结果", "health": "监控运行异常", "test": "监控通知测试", "probe": "监控链路检查"}[text("operation")]
		if op == "" {
			op = "文件监控事件"
		}
		p.Subject = op
		var important bool
		_ = json.Unmarshal(v["important_config"], &important)
		if important {
			p.Subject = "重要配置提醒：" + p.Subject
		}
		for _, f := range []struct{ key, label string }{{"path", "文件"}, {"old_path", "原位置"}} {
			if s := text(f.key); s != "" {
				clean, cut := notificationPublicText(s, 32768)
				p.Truncated = p.Truncated || cut
				lines = append(lines, f.label+"："+clean)
			}
		}
		if t, err := time.Parse(time.RFC3339Nano, text("time")); err == nil && t.Year() >= 1900 && t.Year() <= 9999 {
			lines = append(lines, "发生时间："+t.UTC().Format(time.RFC3339Nano))
		}
		var scan map[string]json.RawMessage
		var status string
		_ = json.Unmarshal(v["scan"], &scan)
		_ = json.Unmarshal(scan["status"], &status)
		if label := map[string]string{"pending": "等待扫描", "matched": "发现可疑特征", "no_match": "未发现可疑特征", "error": "扫描未完成", "skipped": "本次未扫描", "not_applicable": "无需扫描"}[status]; label != "" {
			lines = append(lines, "安全检查："+label)
		}
		risk := text("risk")
		var scanRisk string
		if json.Unmarshal(scan["risk"], &scanRisk) == nil {
			risk = scanRisk
		}
		if label := map[string]string{"critical": "严重", "high": "高", "medium": "中", "low": "低", "warning": "警告", "unclassified": "未分类", "unknown": "未知"}[risk]; label != "" {
			lines = append(lines, "风险："+label)
		}
	case "server_health":
		p.Subject = "服务器监控通知"
		if label := map[string]string{"firing": "告警发生", "resolved": "告警恢复", "reminder": "告警持续"}[text("phase")]; label != "" {
			p.Subject = "服务器" + label
		}
		if label := notificationHealthKind(text("kind")); label != "" {
			lines = append(lines, "监控项目："+label)
		}
		if count, ok := notificationArrayCount(v["members"]); ok {
			lines = append(lines, fmt.Sprintf("涉及告警：%d 项", count))
		}
	case "website":
		p.Subject = "网站监控通知"
		if label := map[string]string{"outage": "网站访问异常", "recovery": "网站访问恢复", "outage_reminder": "网站访问持续异常", "certificate": "网站证书提醒", "certificate_recovery": "网站证书恢复", "slow": "网站响应缓慢", "slow_recovery": "网站响应恢复"}[text("notice_kind")]; label != "" {
			p.Subject = label
		}
		if count, ok := notificationArrayCount(v["site_ids"]); ok {
			lines = append(lines, fmt.Sprintf("涉及网站：%d 个", count))
		}
	case "test":
		p.Subject = "通知通道测试"
		lines = append(lines, "管理员发起的通知通道测试。")
	default:
		return renderNotificationPublic(nil, "unknown")
	}
	p.Body = strings.Join(append([]string{p.Subject}, lines...), "\n")
	p.Summary = strings.Join(lines, "；")
	if p.Summary == "" {
		p.Summary = p.Subject
	}
	for _, field := range []struct {
		target *string
		limit  int
	}{{&p.Subject, 1024}, {&p.Summary, 4096}, {&p.Body, 32768}} {
		// Generated line breaks are retained, while every untrusted field was
		// cleaned before interpolation. The final cap never splits UTF-8.
		clean, cut := notificationPublicLimit(*field.target, field.limit)
		*field.target, p.Truncated = clean, p.Truncated || cut
	}
	return p
}

func notificationArrayCount(raw []byte) (int, bool) {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil || items == nil {
		return 0, false
	}
	return len(items), true
}

func notificationHealthKind(kind string) string {
	return map[string]string{"host_api": "主控后台", "host_postgres": "业务数据库", "host_metrics": "指标存储", "host_storage": "宿主数据存储", "node_unreachable": "节点连接", "cpu": "CPU", "memory": "内存", "clock": "时钟", "agent": "子控心跳", "local_probe": "本地探针", "central_probe": "中心探针", "event_query": "事件查询", "scanner": "扫描服务", "coverage": "监控覆盖", "vector": "事件传输", "transport_rejected": "事件拒收", "agent_metric_missing": "心跳指标", "inotify_overflow": "监听队列", "dropped": "事件丢弃"}[kind]
}

func notificationPublicText(s string, limit int) (string, bool) {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	return notificationPublicLimit(clean, limit)
}

func notificationPublicLimit(s string, limit int) (string, bool) {
	if len(s) <= limit {
		return s, false
	}
	end := limit
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end], true
}

// The caller supplies provenance from the trusted producer, never from JSON.
// Select PostgreSQL's exact jsonb text, not a Go reserialization, for the hash.
func projectNotificationTx(ctx context.Context, tx *sql.Tx, id int64, source string) error {
	if tx == nil || id < 1 || !validNotificationSource(source) {
		return ErrHistoryInput
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT payload::text FROM v3_notifications WHERE id=$1 FOR UPDATE`, id).Scan(&raw); err != nil {
		return err
	}
	p := renderNotificationPublic(raw, source)
	_, err := tx.ExecContext(ctx, `INSERT INTO v3_notification_public(notification,source,payload_sha256,subject,summary,body,content_state,content_reason,truncated)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(notification) DO NOTHING`, id, source, digest(raw), p.Subject, p.Summary, p.Body, p.State, p.Reason, p.Truncated)
	return err
}

const notificationProjectionValidSQL = `(p.notification IS NOT NULL AND p.projection_version=1 AND p.payload_sha256=encode(sha256(convert_to(t.payload::text,'UTF8')),'hex'))`

// This bounded, safe subquery also serves history exports. It intentionally has
// no raw delivery payload or provider result in its returned columns.
func notificationPublicReadSQL() string {
	return `(SELECT t.id,t.node,t.event_id,t.channel,t.recipient,t.created_at,t.done_at,t.attempts,t.next_try,t.migration_pending,t.lease_owner,t.lease_until,
` + historyDeleteReasonSQL(6, "t") + ` public_delete_reason,CASE WHEN ` + notificationProjectionValidSQL + ` THEN p.source WHEN p.notification IS NULL AND t.migration_source<>'' THEN 'legacy' ELSE 'unknown' END public_source,
 CASE WHEN ` + notificationProjectionValidSQL + ` THEN p.subject ELSE '通知记录' END public_subject,
 CASE WHEN ` + notificationProjectionValidSQL + ` THEN p.summary ELSE '此记录未生成可核验的公共正文。' END public_summary,
 CASE WHEN ` + notificationProjectionValidSQL + ` AND p.content_state='available' THEN p.body ELSE '' END public_body,
 CASE WHEN ` + notificationProjectionValidSQL + ` THEN p.content_state ELSE 'unsupported' END public_content_state,
 CASE WHEN p.notification IS NULL AND t.migration_source<>'' THEN '旧版记录未生成公共正文。' WHEN p.notification IS NULL THEN '缺少公共内容投影。' WHEN NOT ` + notificationProjectionValidSQL + ` THEN '通知内容已变化，原公共投影已停用。' ELSE p.content_reason END public_content_reason,
 CASE WHEN ` + notificationProjectionValidSQL + ` THEN p.truncated ELSE false END public_truncated
 FROM v3_notifications t LEFT JOIN v3_notification_public p ON p.notification=t.id)`
}
