package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
	"webscan/internal/common"
)

func ValidFeishuWebhook(value string) bool {
	u, err := url.Parse(value)
	const prefix = "/open-apis/bot/v2/hook/"
	return err == nil && u.Scheme == "https" && u.Host == "open.feishu.cn" && strings.HasPrefix(u.Path, prefix) && len(strings.TrimPrefix(u.Path, prefix)) > 0 && !strings.ContainsAny(value, " \t\r\n") && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

func validateFeishu(f common.Map) error {
	mode := common.S(f["mode"])
	if !common.Contains([]string{"inline", "existing", "existing_env"}, mode) {
		return WithField(errors.New("invalid_feishu_mode"), "feishu.mode")
	}
	if !common.B(f["enabled"]) {
		return nil
	}
	if mode != "inline" {
		if !strings.HasPrefix(common.S(f["existing_env_file"]), "/") {
			return WithField(errors.New("feishu_env_file_required"), "feishu.existing_env_file")
		}
		return nil
	}
	var problems []string
	code := ""
	if !ValidFeishuWebhook(common.S(f["webhook_url"])) {
		code = "feishu_requires_https_webhook"
		problems = append(problems, "feishu.webhook_url 未填写或格式错误：请从飞书群自定义机器人的设置复制完整 HTTPS Webhook，格式为 https://open.feishu.cn/open-apis/bot/v2/hook/机器人标识")
	}
	if common.B(f["signing_enabled"]) && common.S(f["signing_secret"]) == "" {
		if code == "" {
			code = "feishu_signing_secret_required"
		}
		problems = append(problems, "feishu.signing_secret 未填写：signing_enabled: true 时，请复制机器人安全设置中的加签密钥；两端加签设置应一致")
	}
	if len(problems) > 0 {
		return &Diagnostic{Err: errors.New(code), Field: "feishu", Detail: "飞书已开启，请完成以下填写后重试：\n- " + strings.Join(problems, "\n- ") + "\n凭据请加引号，并将实际 YAML 权限设为 0600。"}
	}
	return nil
}

// Validate scheduling, capacities and thresholds before they can produce silent
// runtime failures or unusable component configuration. Report only field names.
func validateValues(m common.Map, prefix string) error {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		v := m[key]
		field := prefix + key
		bad := func(detail string) error {
			return &Diagnostic{Err: errors.New("invalid_parameter_value"), Field: field, Detail: detail}
		}
		if obj, ok := v.(common.Map); ok {
			if err := validateValues(obj, field+"."); err != nil {
				return err
			}
			continue
		}
		if array, ok := v.([]any); ok && key == "nodes" {
			for i, item := range array {
				if err := validateValues(common.M(item), fmt.Sprintf("nodes[%d].", i)); err != nil {
					return err
				}
			}
			continue
		}
		if key == "timezone" {
			if _, err := time.LoadLocation(common.S(v)); err != nil {
				return bad("时区无效。请填写 IANA 时区，例如 Asia/Shanghai 或 UTC。")
			}
		}
		if key == "time" {
			if _, err := time.Parse("15:04", common.S(v)); err != nil || len(common.S(v)) != 5 {
				return bad("时间必须是 24 小时 HH:MM 字符串，例如 '09:00' 或 '02:30'，请加引号。")
			}
		}
		if strings.HasSuffix(key, "bind_address") && net.ParseIP(common.S(v)) == nil {
			return bad("监听地址必须是 IP，例如 0.0.0.0 或 127.0.0.1，不能带端口。")
		}
		if field == "health.probe_directory" {
			if err := ValidPath(common.S(v)); err != nil {
				return WithField(err, field)
			}
		}
		if key == "nice" && (common.I(v) < -20 || common.I(v) > 19) {
			return bad("Linux nice 必须是 -20～19 的整数，数值越大优先级越低。")
		}
		if key == "ionice_class" && (common.I(v) < 1 || common.I(v) > 3) {
			return bad("I/O 优先级类别必须为 1（实时）、2（尽力）或 3（空闲）。")
		}
		if key == "start_jitter_minutes" && common.I(v) < 0 {
			return bad("随机延迟上限为分钟数，必须是大于或等于 0 的整数。")
		}
		if strings.HasSuffix(key, "_percent") {
			if common.I(v) <= 0 || common.I(v) > 100 {
				return bad("使用率阈值必须是 1～100 的整数，例如 80 表示 80%。")
			}
			if strings.Contains(key, "warning") && common.I(v) >= common.I(m[strings.Replace(key, "warning", "critical", 1)]) {
				return bad("警告阈值必须低于对应的严重告警阈值；建议 warning: 80、critical: 90。")
			}
		}
		if strings.HasSuffix(key, "_seconds") || strings.HasSuffix(key, "_hours") || strings.HasSuffix(key, "_days") || strings.HasSuffix(key, "_mib") || common.Contains([]string{"max_per_second", "max_per_minute", "max_batch_events"}, key) {
			min := 1
			if key == "group_wait_seconds" {
				min = 0
			}
			if common.I(v) < min {
				return bad(fmt.Sprintf("必须填写至少为 %d 的整数；单位按字段名分别为秒、小时、天、MiB 或条数。", min))
			}
		}
		if key == "cpus" && (math.IsNaN(common.F(v)) || math.IsInf(common.F(v), 0) || common.F(v) < .1 || common.F(v) > 16) {
			return bad("CPU 配额必须为 0.1～16 的有限数字，例如 1.0。")
		}
		if key == "max_delay_seconds" && common.I(v) < common.I(m["initial_delay_seconds"]) {
			return bad("最大重试等待时间不得小于 initial_delay_seconds。")
		}
		if field == "deployment.run_acceptance_tests" && !common.B(v) {
			return bad("当前部署必须执行验收，请保持 run_acceptance_tests: true。")
		}
	}
	return nil
}
