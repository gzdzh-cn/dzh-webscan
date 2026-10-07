package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"webscan/internal/common"
)

// Diagnostic preserves machine-readable codes; terminal messages never include
// supplied values, YAML parser excerpts, passwords or webhook addresses.
type Diagnostic struct {
	Err           error
	Field, Detail string
}

func (e *Diagnostic) Error() string { return e.Err.Error() }
func (e *Diagnostic) Unwrap() error { return e.Err }

func WithField(err error, field string) error {
	var d *Diagnostic
	if errors.As(err, &d) {
		return err
	}
	var rule *common.FieldError
	if errors.As(err, &rule) && rule.Field != "" {
		field += "." + rule.Field
	}
	return &Diagnostic{Err: err, Field: field}
}

func syntaxError(err error) error {
	// Only extract line numbers: YAML parser text may contain credential values.
	lines := regexp.MustCompile(`line [0-9]+`).FindAllString(err.Error(), -1)
	return &Diagnostic{Err: errors.New("invalid_yaml_syntax"), Field: "配置文件", Detail: "YAML 语法错误。请检查缩进（使用空格，不能用 Tab）、冒号、引号及重复字段。" + strings.Join(lines, "、")}
}

var instructions = map[string]string{
	"cannot_read_yaml":                          "无法读取 YAML。请确认 --config 指向存在的普通文件，当前用户有读取权限；未指定时读取当前目录的 webscan.yaml。",
	"invalid_yaml_syntax":                       "YAML 语法错误。请检查空格缩进、冒号、引号及重复字段；不要使用 Tab。",
	"yaml_requires_single_document":             "一个配置文件只能包含一份 YAML 文档；请删除多余的 --- 文档或末尾无效内容。",
	"expected_yaml_mapping":                     "配置不能为空，顶层必须是字段映射。请复制完整的 webscan.example.yaml 后修改，不要只使用配置片段。",
	"config_version_must_be_2":                  "请填写整数 2：config_version: 2。",
	"invalid_registry_prefix":                   "填写仓库域名/命名空间，例如 docker.io/gzdzh；不能带 https://、镜像名或 ..。",
	"private_registry_credentials_required":     "registry.auth_required 为 true 时，registry.username 和 registry.password 均必填。Docker Hub 密码字段填写访问令牌；公开拉取可设 auth_required: false。",
	"invalid_registry_credentials":              "仓库账号及密码必须是单行字符串，不能含换行或空字符。",
	"images_require_explicit_version_or_digest": "填写相对镜像名及已发布版本，例如 webscan-central:v2.0.16；或 @sha256: 加 64 位小写十六进制摘要，也可同时填写标签及摘要。不能使用 latest 或省略版本。",
	"central_requires_ip_https_url":             "填写 https://主服务器IP:HTTPS端口，例如 https://192.0.2.10:19443；不能用域名、HTTP、账号、查询参数或额外路径。",
	"central_https_port_mismatch":               "central.public_url 中的端口必须与 central.event_service.https_port 相同，并显式填写端口。",
	"invalid_absolute_path":                     "填写绝对路径，例如 /www/wwwroot 或 /opt/webscan-central；不能包含 ..、换行或空字符。",
	"path_too_broad":                            "目录范围过大。请使用专用子目录；不能直接使用 /、/etc、/usr、/var、/root、/home 或 /www。",
	"central_directories_overlap":               "安装、数据、日志及备份目录必须分别独立，不能相同或互相包含。请检查 central 下的四个目录。",
	"invalid_grafana_username":                  "账号名长度为 1～64 个字符，只允许字母、数字及 _.@-。",
	"invalid_grafana_password":                  "自定义密码应为 8～256 字节且不含换行或空字符；留空时首次随机生成，已有部署沿用保存的密码。",
	"grafana_users_must_differ":                 "管理员账号与 Viewer 只读账号不能相同；分别填写 admin_username 和 viewer_username。",
	"invalid_or_conflicting_central_port":       "HTTP 接收、HTTPS 接收及 Grafana 端口必须在 1024～65535 之间，不能互相重复，也不能占用内部端口 19190、19193、19110、3100。Grafana 默认端口 3000。",
	"internal_service_must_bind_loopback":       "内部 HTTP 接口必须填写 bind_address: 127.0.0.1；节点使用 public_url 的 HTTPS 接口。",
	"invalid_allowed_source_cidr":               "填写 CIDR 列表，例如 ['198.51.100.20/32']；不是 IP:端口。[] 表示自动允许启用节点、主服务器和本机来源。",
	"invalid_or_duplicate_node_id":              "节点 id 必须唯一，长度为 1～64 个字符，只允许字母、数字、下划线和连字符，例如 node-29。",
	"node_requires_ip_address":                  "host 填写子服务器 IP，例如 198.51.100.20；不要填写域名、协议或端口，SSH 端口写在 ssh.port。",
	"invalid_ssh_port":                          "SSH 端口必须是 1～65535 的整数，例如 port: 22。",
	"node_ssh_requires_root":                    "当前部署要求 ssh.username: root。",
	"ssh_key_requires_absolute_path":            "key 认证必须填写主服务器上的私钥绝对路径，例如 /root/.ssh/node-29_id_ed25519；不能使用 Mac 本地路径代替服务器路径。",
	"ssh_password_required":                     "password 认证必须填写 ssh.password；使用单引号包裹，密码内的单引号写成两个单引号。",
	"invalid_ssh_auth_method":                   "ssh.auth_method 只能填写 key（私钥认证）或 password（密码认证）。",
	"ssh_host_fingerprint_invalid":              "host_key_sha256 可删除或留空，首次认证成功后自动保存并持续校验；手动固定值必须以 SHA256: 开头。",
	"invalid_agent_resource_limits":             "agent_memory_mib: 128～8192；go_memory_mib 至少 32 且比容器上限少至少 32；cpus: 0.1～16；gomaxprocs: 1～32。内存单位为 MiB。",
	"invalid_scan_limits":                       "workers 必须为 1～16，timeout_seconds 为 1～600，max_file_mib 至少 1；均填写整数。",
	"invalid_reconciliation_limits":             "interval_hours 和 max_read_mib_per_second 必须是至少为 1 的整数。",
	"metrics_allowed_source_requires_ip":        "metrics.allowed_source_ip 填写主服务器实际采集来源 IP，不带端口或 /32。",
	"metrics_require_tls_nonprivileged_port":    "metrics.port 必须是 1024～65535 的整数，并填写 tls_enabled: true。",
	"nodes_required":                            "nodes 至少填写一台子服务器，参考示例的列表结构；每台可覆盖 node_defaults 的同名参数。",
	"unknown_node_order_id":                     "deployment.node_order 只能填写 nodes 中已定义的 id；请删除不存在的 ID 或补齐节点配置。",
	"enabled_node_missing_from_order":           "请将全部 enabled: true 的节点 id 加入 deployment.node_order 列表；单节点操作仍须保持完整配置。",
	"serial_node_deployment_required":           "当前只支持串行部署，请填写 deployment.max_parallel_nodes: 1。",
	"feishu_requires_https_webhook":             "飞书已开启。feishu.webhook_url 必填，格式为 https://open.feishu.cn/open-apis/bot/v2/hook/机器人标识；在飞书群添加自定义机器人后复制完整 Webhook。signing_enabled: true 时还需填写 signing_secret。",
	"invalid_feishu_webhook":                    "feishu.webhook_url 必须是飞书机器人 HTTPS 地址，格式为 https://open.feishu.cn/open-apis/bot/v2/hook/机器人标识；不能含账号、查询参数或锚点。",
	"feishu_signing_secret_required":            "feishu.signing_enabled 为 true 时必须填写 feishu.signing_secret；在机器人安全设置中获取加签密钥，与飞书端设置保持一致。",
	"missing_feishu_signing_secret":             "feishu.signing_secret 未填写；请复制飞书机器人安全设置中的加签密钥。",
	"invalid_feishu_mode":                       "feishu.mode 只能填写 inline（YAML 中的凭据）、existing_env 或 existing（已有 env 文件中的凭据）。",
	"feishu_env_file_required":                  "existing_env 模式必须填写 feishu.existing_env_file 的绝对路径；文件内填写 FEISHU_WEBHOOK_URL 和 FEISHU_SECRET，不执行 shell 命令。",
	"feishu_env_file_unreadable":                "无法读取 feishu.existing_env_file；请确认文件位于执行工具的机器上且当前用户可读，包含 FEISHU_WEBHOOK_URL 和 FEISHU_SECRET。",
	"feishu_env_invalid_literal":                "飞书 env 文件的引号未成对。请使用 KEY='值' 单行格式；该文件按文本读取，不展开变量、不执行命令。",
	"too_many_registry_mirrors":                 "registry.mirrors 最多填写 8 个加速源；不加速时填写 []。",
	"registry_mirror_requires_https_origin":     "加速源必须是完整 HTTPS 根地址，例如 https://mirror.example.com；不能有路径、账号、查询参数、空列表项。[] 表示禁用。",
	"duplicate_registry_mirror":                 "registry.mirrors 存在重复加速源，请保留一个。",
	"missing_monitor_field":                     "缺少监控规则字段，请保留 roots、extensions、important_filenames、critical_paths、exclude_paths；节点未填写时继承公共配置。",
	"filter_list_too_large":                     "单个规则列表不能超过 10000 条，请缩减列表或使用路径通配规则。",
	"invalid_filter_list":                       "规则必须是 YAML 列表，例如 extensions: [.php, .js]；空列表写 []。",
	"invalid_filter":                            "规则列表项不能是空字符串或含控制字符；请删除空行中的 '-' 或填写有效值。",
	"invalid_extension":                         "扩展名必须包含前导点且只含字母数字，例如 [.php, .js, .html]；不要写 *.php。",
	"invalid_filename":                          "important_filenames 只填写文件名，例如 [.user.ini, .htaccess]，不能包含 /；完整路径请写 critical_paths。",
	"empty_roots":                               "monitor.roots 至少填写一个绝对目录，例如 [/www/wwwroot]；单节点设置列表会替换公共列表，需保留仍要监控的公共目录。",
	"invalid_glob":                              "忽略通配规则无效。* 匹配一个路径段，** 匹配多层目录，例如 /www/wwwroot/*/runtime/**/cache；请检查方括号及范围。",
	"exclude_matches_root":                      "忽略规则不能排除整个监控根目录；请缩小到根目录下的缓存子目录。",
	"exclude_prefix_outside_roots":              "忽略规则的固定前缀必须位于 monitor.roots 内，例如 /www/wwwroot/*/cache。",
	"exclude_matches_critical":                  "忽略规则排除了 critical_paths 中的重要文件；请缩小忽略范围或纠正关键文件路径。",
}

// Explain returns a known configuration diagnostic, otherwise lets the runtime
// reporter handle the error. No untrusted values are interpolated into messages.
func Explain(err error) (string, bool) {
	var d *Diagnostic
	field, detail := "", ""
	if errors.As(err, &d) {
		field, detail = d.Field, d.Detail
	}
	code := err.Error()
	message, ok := instructions[code]
	for _, spec := range []struct{ Prefix, Message string }{
		{"missing_section_", "缺少配置区块，请从完整示例补齐此区块。"},
		{"unknown_field_", "无法识别此字段，请检查名称、层级和拼写；参数列表见 --config-help。"},
		{"expected_mapping_", "此字段应是 YAML 字段映射，不能填写字符串、列表或空值。"},
		{"expected_list_", "此字段应是列表，例如 [.php, .js]；空列表写 []，不能只留一个空的 '-'。"},
		{"expected_string_", "此字段应是字符串；密码、时间及数字形式的字符串请加引号，留空写 ''。"},
		{"expected_boolean_", "此字段应是布尔开关，填写 true 或 false，不要加引号或填 0/1。"},
		{"expected_integer_", "此字段应是整数，不要加引号或填写小数。"},
		{"expected_number_", "此字段应是数字，例如 cpus: 1.0，不要加引号。"},
	} {
		if strings.HasPrefix(code, spec.Prefix) {
			field = strings.TrimSuffix(strings.TrimPrefix(code, spec.Prefix), ".")
			message, ok = spec.Message, true
			break
		}
	}
	if code == "nodes_must_be_list" {
		field, message, ok = "nodes", "nodes 必须是列表，每台子服务器使用一个 '- id: 节点ID' 条目。", true
	}
	if detail != "" {
		message, ok = detail, true
	}
	if !ok {
		return "", false
	}
	field = safeField(field)
	if field != "" {
		message = "字段 " + field + "：" + message
	}
	if strings.HasPrefix(field, "nodes[") {
		message += "（下标从 0 开始；节点未单独填写的参数请检查 node_defaults。）"
	}
	return fmt.Sprintf("%s（%s）", message, safeField(code)), true
}

func safeField(s string) string {
	if len(s) > 250 || strings.ContainsAny(s, "\n\r\x00") {
		return "[字段名已隐藏]"
	}
	// Unknown YAML keys may themselves contain arbitrary sensitive text.
	if !regexp.MustCompile(`^[a-zA-Z0-9_.\[\] /-]*$`).MatchString(s) && s != "配置文件" {
		return "[字段名已隐藏]"
	}
	return s
}
