package controlplane

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"webscan/internal/common"
	configuration "webscan/internal/config"
	"webscan/internal/notify"
)

var errSettingsEdit = errors.New("设置字段或参数不正确，请检查类型、范围和通知配置")

type settingsField struct {
	Path    string   `json:"path"`
	Label   string   `json:"label"`
	Kind    string   `json:"kind"`
	Min     int      `json:"min,omitempty"`
	Max     int      `json:"max,omitempty"`
	Choices []string `json:"choices,omitempty"`
}

// Expose only controls consumed by existing runtime workers. Bootstrap, paths,
// legacy selectors, arbitrary JSON and future backup/metrics policies are not
// editable through this projection. Unknown stored fields remain untouched.
func settingsFields() []settingsField {
	f := []settingsField{
		{Path: "collector.interval_seconds", Label: "主控拉取指标间隔（秒）", Kind: "integer", Min: 10, Max: 3600},
		{Path: "backup.enabled", Label: "自动完整备份", Kind: "bool"},
		{Path: "backup.time", Label: "每天备份时间（HH:MM）", Kind: "text", Max: 5},
		{Path: "backup.timezone", Label: "备份时区（IANA，未指定为 UTC）", Kind: "text", Max: 128},
		{Path: "backup.keep_days", Label: "完整备份保留天数", Kind: "integer", Min: 1, Max: 3650},
		{Path: "website_monitor.enabled", Label: "网站检测", Kind: "bool"},
		{Path: "website_monitor.interval_seconds", Label: "网站检测间隔（秒）", Kind: "integer", Min: 10, Max: 3600},
		{Path: "website_monitor.timeout_seconds", Label: "网站请求超时（秒）", Kind: "integer", Min: 1, Max: 60},
		{Path: "website_monitor.max_concurrent", Label: "网站检测并发", Kind: "integer", Min: 1, Max: 256},
		{Path: "monitoring.interval_seconds", Label: "告警判定参考间隔（秒）", Kind: "integer", Min: 10, Max: 3600},
		{Path: "monitoring.repeat_hours", Label: "重复告警间隔（小时）", Kind: "integer", Min: 1, Max: 168},
		{Path: "monitoring.group_wait_seconds", Label: "告警首次合并等待（秒）", Kind: "integer", Min: 15, Max: 3600},
		{Path: "monitoring.group_interval_seconds", Label: "告警合并间隔（秒）", Kind: "integer", Min: 15, Max: 86400},
		{Path: "monitoring.alert_on_inotify_overflow", Label: "监听队列溢出告警", Kind: "bool"},
		{Path: "monitoring.alert_on_dropped_events", Label: "事件丢弃告警", Kind: "bool"},
		{Path: "email.enabled", Label: "邮箱通知", Kind: "bool"},
		{Path: "email.smtp_host", Label: "SMTP 主机", Kind: "text", Max: 253},
		{Path: "email.smtp_port", Label: "SMTP 端口", Kind: "integer", Min: 1, Max: 65535},
		{Path: "email.tls_mode", Label: "SMTP 加密方式", Kind: "choice", Choices: []string{"tls", "starttls"}},
		{Path: "email.username", Label: "SMTP 用户名", Kind: "text", Max: 320},
		{Path: "email.from_address", Label: "发件邮箱", Kind: "text", Max: 320},
		{Path: "email.from_name", Label: "发件名称", Kind: "text", Max: 256},
		{Path: "email.recipients", Label: "收件邮箱", Kind: "addresses", Max: 20},
		{Path: "email.timeout_seconds", Label: "SMTP 超时（秒）", Kind: "integer", Min: 1, Max: 60},
		{Path: "email.max_per_minute", Label: "邮件每分钟上限", Kind: "integer", Min: 1, Max: 600},
		{Path: "email.retry.initial_delay_seconds", Label: "邮件初始重试等待（秒）", Kind: "integer", Min: 1, Max: 86400},
		{Path: "email.retry.max_delay_seconds", Label: "邮件最大重试等待（秒）", Kind: "integer", Min: 1, Max: 86400},
		{Path: "feishu.enabled", Label: "飞书通知", Kind: "bool"},
		{Path: "feishu.signing_enabled", Label: "飞书签名", Kind: "bool"},
		{Path: "feishu.message_prefix", Label: "飞书通知前缀", Kind: "text", Max: 256},
		{Path: "feishu.timeout_seconds", Label: "飞书超时（秒）", Kind: "integer", Min: 1, Max: 60},
		{Path: "feishu.rate_limit.max_per_second", Label: "飞书每秒上限", Kind: "integer", Min: 1, Max: 100},
		{Path: "feishu.rate_limit.max_per_minute", Label: "飞书每分钟上限", Kind: "integer", Min: 1, Max: 600},
		{Path: "feishu.retry.initial_delay_seconds", Label: "飞书初始重试等待（秒）", Kind: "integer", Min: 1, Max: 86400},
		{Path: "feishu.retry.max_delay_seconds", Label: "飞书最大重试等待（秒）", Kind: "integer", Min: 1, Max: 86400},
	}
	for _, channel := range []string{"email", "feishu"} {
		for i, category := range notify.Categories {
			label := []string{"文件变更", "重要配置变更", "扫描命中", "扫描错误", "健康故障", "健康恢复"}[i]
			f = append(f, settingsField{Path: channel + ".notifications." + category, Label: map[string]string{"email": "邮件", "feishu": "飞书"}[channel] + label, Kind: "bool"})
		}
	}
	for _, metric := range []string{"cpu", "memory"} {
		name := map[string]string{"cpu": "CPU", "memory": "内存"}[metric]
		f = append(f, settingsField{Path: "monitoring.alerts." + metric + "_enabled", Label: name + " 告警", Kind: "bool"})
		for _, level := range []string{"warning", "recovery"} {
			f = append(f, settingsField{Path: "monitoring.alerts." + metric + "_" + level + "_percent", Label: name + map[string]string{"warning": "触发阈值（%）", "recovery": "恢复阈值（%）"}[level], Kind: "integer", Min: 1, Max: 100})
		}
		f = append(f, settingsField{Path: "monitoring.alerts." + metric + "_duration_seconds", Label: name + " 持续时间（秒）", Kind: "integer", Min: 1, Max: 86400})
	}
	for _, metric := range []string{"disk", "inode"} {
		for _, level := range []string{"warning", "critical"} {
			f = append(f, settingsField{Path: "monitoring.alerts." + metric + "_" + level + "_percent", Label: metric + map[string]string{"warning": "警告阈值（%）", "critical": "严重阈值（%）"}[level], Kind: "integer", Min: 1, Max: 100})
		}
	}
	for key, label := range map[string]string{"node_unreachable_seconds": "节点不可达等待", "agent_stopped_seconds": "文件监控停止等待", "local_probe_stale_seconds": "本地探针过期", "central_probe_stale_seconds": "中心探针过期", "loki_probe_stale_seconds": "事件查询探针过期", "oldest_pending_task_seconds": "事件积压阈值", "clock_offset_warning_seconds": "时钟偏差阈值", "clock_failure_duration_seconds": "时钟故障等待"} {
		f = append(f, settingsField{Path: "monitoring.alerts." + key, Label: label + "（秒）", Kind: "integer", Min: 1, Max: 86400})
	}
	sort.Slice(f, func(i, j int) bool { return f[i].Path < f[j].Path })
	return f
}

var settingsSecretLabels = map[string]string{"email.password": "SMTP 密码／授权码", "feishu.webhook_url": "飞书 Webhook", "feishu.signing_secret": "飞书签名密钥"}

type settingsSecretEdit struct {
	Action string `json:"action"`
	Value  string `json:"value,omitempty"`
}

func (settingsSecretEdit) String() string   { return "[private credential edit]" }
func (settingsSecretEdit) GoString() string { return "[private credential edit]" }

type settingsEdit struct {
	Values  map[string]json.RawMessage    `json:"values,omitempty"`
	Secrets map[string]settingsSecretEdit `json:"secrets,omitempty"`
}

func (settingsEdit) String() string   { return "[private settings edit]" }
func (settingsEdit) GoString() string { return "[private settings edit]" }

func settingsPath(root configurationValues, path string) (any, bool) {
	parts := strings.Split(path, ".")
	m := common.Map(root)
	for _, part := range parts[:len(parts)-1] {
		child, ok := m[part].(map[string]any)
		if !ok {
			return nil, false
		}
		m = child
	}
	v, ok := m[parts[len(parts)-1]]
	return v, ok
}
func setSettingsPath(root configurationValues, path string, value any) error {
	parts := strings.Split(path, ".")
	m := common.Map(root)
	for _, part := range parts[:len(parts)-1] {
		v, exists := m[part]
		if !exists {
			v = map[string]any{}
			m[part] = v
		}
		child, ok := v.(map[string]any)
		if !ok {
			return errSettingsEdit
		}
		m = child
	}
	m[parts[len(parts)-1]] = value
	return nil
}

func (f settingsField) valid(v any) bool {
	switch f.Kind {
	case "bool":
		_, ok := v.(bool)
		return ok
	case "integer":
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		i, e := strconv.ParseInt(n.String(), 10, 64)
		return e == nil && i >= int64(f.Min) && i <= int64(f.Max)
	case "text", "choice":
		s, ok := v.(string)
		if !ok || !utf8.ValidString(s) || strings.ContainsAny(s, "\x00\r\n") {
			return false
		}
		if f.Kind == "choice" {
			return common.Contains(f.Choices, s)
		}
		return len(s) <= f.Max
	case "addresses":
		a, ok := v.([]any)
		if !ok || len(a) > f.Max {
			return false
		}
		for _, v := range a {
			s, ok := v.(string)
			if !ok || len(s) > 320 || strings.ContainsAny(s, "\x00\r\n") || !utf8.ValidString(s) {
				return false
			}
		}
		return true
	}
	return false
}

func editSettings(current configurationValues, edit settingsEdit) (configurationValues, []string, error) {
	out, e := configurationMap(current)
	if e != nil {
		return nil, nil, e
	}
	fields := map[string]settingsField{}
	for _, f := range settingsFields() {
		fields[f.Path] = f
	}
	for _, f := range metricsRetentionFields() {
		fields[f.Path] = f
	}
	changed := []string{}
	for path, raw := range edit.Values {
		f, ok := fields[path]
		if !ok {
			return nil, nil, errSettingsEdit
		}
		v, e := common.Decode(raw)
		if e != nil || !f.valid(v) {
			return nil, nil, errSettingsEdit
		}
		old, _ := settingsPath(current, path)
		if !configurationRestoreEqual(old, v) {
			changed = append(changed, path)
		}
		if setSettingsPath(out, path, v) != nil {
			return nil, nil, errSettingsEdit
		}
	}
	for path, edit := range edit.Secrets {
		if settingsSecretLabels[path] == "" {
			return nil, nil, errSettingsEdit
		}
		old, _ := settingsPath(current, path)
		switch edit.Action {
		case "keep":
			if edit.Value != "" {
				return nil, nil, errSettingsEdit
			}
			continue
		case "clear":
			if edit.Value != "" {
				return nil, nil, errSettingsEdit
			}
		case "replace":
			if edit.Value == "" || len(edit.Value) > 4096 || !utf8.ValidString(edit.Value) || strings.ContainsAny(edit.Value, "\x00\r\n") {
				return nil, nil, errSettingsEdit
			}
		default:
			return nil, nil, errSettingsEdit
		}
		if !configurationRestoreEqual(old, edit.Value) {
			changed = append(changed, path)
		}
		if setSettingsPath(out, path, edit.Value) != nil {
			return nil, nil, errSettingsEdit
		}
	}
	// Future/unknown values stay lossless; apply only validates known controls.
	for _, f := range settingsFields() {
		if v, ok := settingsPath(out, f.Path); ok && !f.valid(v) {
			return nil, nil, errSettingsEdit
		}
	}
	if e = validateSettingsChannels(out); e != nil {
		return nil, nil, e
	}
	if _, e = singleBackupRuntimePolicyFromSettings(out); e != nil {
		return nil, nil, errSettingsEdit
	}
	return out, changed, nil
}

func validateSettingsChannels(root configurationValues) error {
	if notify.Validate(common.M(root["email"])) != nil {
		return errSettingsEdit
	}
	for _, channel := range []string{"email", "feishu"} {
		c := common.M(root[channel])
		r := common.M(c["retry"])
		if !common.B(c["enabled"]) {
			continue
		}
		if common.I(r["initial_delay_seconds"]) < 1 || common.I(r["max_delay_seconds"]) < common.I(r["initial_delay_seconds"]) {
			return errSettingsEdit
		}
	}
	f := common.M(root["feishu"])
	if common.B(f["enabled"]) {
		if !configuration.ValidFeishuWebhook(common.S(f["webhook_url"])) {
			return errSettingsEdit
		}
		if mode := common.S(f["mode"]); mode != "" && mode != "inline" {
			return errSettingsEdit
		}
		if common.B(f["signing_enabled"]) && common.S(f["signing_secret"]) == "" {
			return errSettingsEdit
		}
	}
	a := common.M(common.M(root["monitoring"])["alerts"])
	for _, metric := range []string{"cpu", "memory"} {
		if common.B(a[metric+"_enabled"]) {
			high, low := common.I(a[metric+"_warning_percent"]), common.I(a[metric+"_recovery_percent"])
			if high == 0 {
				high = 85
				if metric == "memory" {
					high = 90
				}
			}
			if low == 0 {
				low = 80
				if metric == "memory" {
					low = 85
				}
			}
			if low >= high {
				return errSettingsEdit
			}
		}
	}
	for _, metric := range []string{"disk", "inode"} {
		high, low := common.I(a[metric+"_critical_percent"]), common.I(a[metric+"_warning_percent"])
		if high == 0 {
			high = 90
		}
		if low == 0 {
			low = 80
		}
		if low >= high {
			return errSettingsEdit
		}
	}
	return nil
}
