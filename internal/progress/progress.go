// Package progress reports deployment operations without exposing configuration secrets.
package progress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"webscan/internal/common"
	"webscan/internal/config"
)

type Reporter struct {
	mu       sync.Mutex
	out      io.Writer
	file     *os.File
	secrets  []string
	phase    string
	color    bool
	step     int
	interval time.Duration
}
type key struct{}
type scope struct {
	reporter    *Reporter
	host, title string
	step        int
}

func With(ctx context.Context, r *Reporter) context.Context {
	return context.WithValue(ctx, key{}, scope{reporter: r})
}
func current(ctx context.Context) scope { s, _ := ctx.Value(key{}).(scope); return s }
func Enabled(ctx context.Context) bool  { return current(ctx).reporter != nil }

func Open(raw common.Map, phase, directory string) (*Reporter, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, errors.New("progress_log_directory_failed")
	}
	path := os.Getenv("WEBSCAN_PROGRESS_LOG")
	if path == "" {
		path = filepath.Join(directory, "deploy-"+time.Now().Format("20060102-150405.000000000")+".log")
	}
	if st, err := os.Lstat(path); err == nil && (!st.Mode().IsRegular() || st.Mode().Perm() != 0600) {
		return nil, errors.New("progress_log_requires_private_regular_file")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, errors.New("progress_log_open_failed")
	}
	r := New(os.Stdout, raw, phase)
	r.file = f
	st, _ := os.Stdout.Stat()
	r.color = st != nil && st.Mode()&os.ModeCharDevice != 0 && os.Getenv("TERM") != "dumb" && os.Getenv("NO_COLOR") == ""
	os.Setenv("WEBSCAN_PROGRESS_LOG", path)
	r.emit(scope{}, "信息", "日志文件："+path)
	return r, nil
}
func New(out io.Writer, raw common.Map, phase string) *Reporter {
	r := &Reporter{out: out, phase: phase, interval: 10 * time.Second}
	var walk func(any)
	walk = func(v any) {
		switch m := v.(type) {
		case map[string]any:
			for k, v := range m {
				if strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.Contains(k, "token") || k == "webhook_url" {
					if s, ok := v.(string); ok && s != "" {
						r.secrets = append(r.secrets, s, url.QueryEscape(s), url.PathEscape(s))
					}
				}
				walk(v)
			}
		case []any:
			for _, v := range m {
				walk(v)
			}
		}
	}
	walk(raw)
	if s := common.S(common.M(raw["registry"])["username"]); s != "" {
		r.secrets = append(r.secrets, s)
	}
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
	return r
}
func (r *Reporter) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file != nil {
		r.file.Close()
		r.file = nil
	}
}
func Protect(ctx context.Context, raw common.Map) {
	s := current(ctx)
	if s.reporter == nil {
		return
	}
	other := New(io.Discard, raw, "")
	s.reporter.mu.Lock()
	defer s.reporter.mu.Unlock()
	s.reporter.secrets = append(s.reporter.secrets, other.secrets...)
	sort.Slice(s.reporter.secrets, func(i, j int) bool { return len(s.reporter.secrets[i]) > len(s.reporter.secrets[j]) })
}

type limited struct {
	target    io.Writer
	remaining int
}

func Limit(target io.Writer, bytes int) io.Writer { return &limited{target, bytes} }
func (l *limited) Write(p []byte) (int, error) {
	n := len(p)
	if l.remaining <= 0 {
		return n, nil
	}
	part := p
	if len(part) > l.remaining {
		part = part[:l.remaining]
	}
	_, err := l.target.Write(part)
	l.remaining -= len(part)
	return n, err
}

var ansi = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
var bearer = regexp.MustCompile(`(?i)(bearer\s+)[^\s]+`)
var credentials = regexp.MustCompile(`(?i)(https?://)[^/\s@]+:[^/\s@]+@`)

func (r *Reporter) clean(s string) string {
	for _, secret := range r.secrets {
		s = strings.ReplaceAll(s, secret, "[已隐藏]")
	}
	s = ansi.ReplaceAllString(s, "")
	s = bearer.ReplaceAllString(s, "${1}[已隐藏]")
	s = credentials.ReplaceAllString(s, "${1}[已隐藏]@")
	return strings.Map(func(c rune) rune {
		if c < 32 && c != '\t' {
			return ' '
		}
		if c == 127 {
			return -1
		}
		return c
	}, s)
}
func (r *Reporter) emit(s scope, status, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	zone := time.FixedZone("Asia/Shanghai", 8*3600)
	label := r.phase
	if s.step > 0 {
		label += fmt.Sprintf("%02d", s.step)
	}
	host := s.host
	if host == "" {
		host = "主服务器"
	}
	line := fmt.Sprintf("[%s][%s][%s][%s] %s\n", time.Now().In(zone).Format("15:04:05"), label, status, r.clean(host), r.clean(message))
	if r.file != nil {
		fmt.Fprint(r.file, line)
	}
	if r.color {
		color := "36"
		if status == "成功" {
			color = "32"
		}
		if status == "失败" {
			color = "31"
		}
		if status == "等待" || status == "重试" {
			color = "33"
		}
		fmt.Fprintf(r.out, "\x1b[%sm%s\x1b[0m", color, line)
	} else {
		fmt.Fprint(r.out, line)
	}
}
func Info(ctx context.Context, message string) {
	s := current(ctx)
	if s.reporter != nil {
		s.reporter.emit(s, "信息", message)
	}
}
func Warn(ctx context.Context, message string) {
	s := current(ctx)
	if s.reporter != nil {
		s.reporter.emit(s, "重试", message)
	}
}
func Stage(ctx context.Context, host, title string, run func(context.Context) error) error {
	s := current(ctx)
	if s.reporter == nil {
		return run(ctx)
	}
	r := s.reporter
	r.mu.Lock()
	r.step++
	step := r.step
	r.mu.Unlock()
	s = scope{r, host, title, step}
	ctx = context.WithValue(ctx, key{}, s)
	start := time.Now()
	r.emit(s, "进行", title)
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				r.emit(s, "等待", fmt.Sprintf("%s；仍在执行，已用时 %.0f 秒", title, time.Since(start).Seconds()))
			}
		}
	}()
	var err error
	func() { defer func() { close(done); <-stopped }(); err = run(ctx) }()
	if err != nil {
		r.emit(s, "失败", fmt.Sprintf("%s；耗时 %.1f 秒；%s", title, time.Since(start).Seconds(), Explain(err)))
	} else {
		r.emit(s, "成功", fmt.Sprintf("%s；耗时 %.1f 秒", title, time.Since(start).Seconds()))
	}
	return err
}

// Stream emits only explicitly selected command output; configuration reads never use it.
func Stream(ctx context.Context, label string) io.WriteCloser { return &stream{ctx: ctx, label: label} }

type stream struct {
	mu      sync.Mutex
	ctx     context.Context
	label   string
	pending []byte
}

func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range p {
		if c == '\n' || c == '\r' {
			s.flush()
		} else if len(s.pending) < 8192 {
			s.pending = append(s.pending, c)
		}
	}
	return len(p), nil
}
func (s *stream) flush() {
	if len(s.pending) > 0 {
		Info(s.ctx, s.label+"｜"+translate(string(s.pending)))
		s.pending = nil
	}
}
func (s *stream) Close() error { s.mu.Lock(); defer s.mu.Unlock(); s.flush(); return nil }

type reader struct {
	ctx               context.Context
	source            io.Reader
	total, read, last int64
	label             string
	stamp             time.Time
}

func Reader(ctx context.Context, source io.Reader, total int64, label string) io.Reader {
	return &reader{ctx: ctx, source: source, total: total, label: label, stamp: time.Now()}
}
func (r *reader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.read += int64(n)
	if r.total > 0 && (time.Since(r.stamp) >= 5*time.Second || r.read == r.total || err == io.EOF) && r.read != r.last {
		Info(r.ctx, fmt.Sprintf("%s：%.1f / %.1f MiB（%.0f%%）", r.label, float64(r.read)/1048576, float64(r.total)/1048576, 100*float64(r.read)/float64(r.total)))
		r.stamp = time.Now()
		r.last = r.read
	}
	return n, err
}
func translate(s string) string {
	return strings.NewReplacer("Pulling fs layer", "准备下载镜像层", "Pulling from", "下载镜像，来源", "Waiting", "等待下载", "Downloading", "下载中", "Verifying Checksum", "校验下载文件", "Download complete", "下载完成", "Extracting", "解压中", "Pull complete", "镜像层已就绪", "Already exists", "镜像层已缓存", "Status: Image is up to date for", "镜像已是目标版本：", "Status: Downloaded newer image for", "镜像下载完成：", "Creating", "创建中", "Created", "已创建", "Starting", "启动中", "Started", "已启动", "Recreated", "已重建", "Recreate", "重建中", "Running", "运行中", "Healthy", "健康", "Error response from daemon", "Docker 报错").Replace(s)
}
func Host(raw common.Map) string {
	u, _ := url.Parse(common.S(common.M(raw["central"])["public_url"]))
	if u != nil {
		return "主服务器 " + u.Hostname()
	}
	return "主服务器"
}
func Node(n common.Map) string {
	name := common.S(n["name"])
	if name == "" {
		name = common.S(n["id"])
	}
	return name + " " + common.S(n["host"])
}
func Role(role string) string {
	if s := map[string]string{"central": "主服务器接收服务", "agent": "子服务器文件监控", "deployer": "部署工具", "prometheus": "Prometheus 指标采集", "alertmanager": "Alertmanager 健康告警", "exporter": "服务器指标采集器", "vector": "Vector 日志传输", "grafana": "Grafana 监控面板", "loki": "Loki 日志存储"}[role]; s != "" {
		return s
	}
	return role
}
func CommandLabel(args []string) string {
	if len(args) == 0 || filepath.Base(args[0]) != "docker" {
		return ""
	}
	i := 1
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		option := args[i]
		i++
		if strings.Contains(option, "=") {
			continue
		}
		switch option {
		case "--host", "-H", "--config", "--context", "-c":
			i++
		case "--debug", "-D", "--tls", "--tlsverify":
		default:
			return ""
		}
	}
	if i >= len(args) {
		return ""
	}
	command := args[i]
	i++
	switch command {
	case "pull":
		return "下载进度"
	case "image":
		if i < len(args) && (args[i] == "save" || args[i] == "load") {
			return "镜像归档"
		}
	case "compose":
		for i < len(args) && strings.HasPrefix(args[i], "-") {
			option := args[i]
			i++
			if strings.Contains(option, "=") {
				continue
			}
			switch option {
			case "-f", "--file", "-p", "--project-name", "--profile", "--env-file", "--project-directory", "--ansi":
				i++
			default:
				return ""
			}
		}
		if i < len(args) && (args[i] == "up" || args[i] == "stop" || args[i] == "down") {
			return "容器状态"
		}
	}
	return ""
}

type Failure struct{ Code, Message string }

func (e *Failure) Error() string { return e.Code }
func Explain(err error) string {
	if err == nil {
		return ""
	}
	if message, ok := config.Explain(err); ok {
		return message
	}
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Message
	}
	if message, ok := explainOperation(err); ok {
		return message
	}
	if errors.Is(err, context.Canceled) {
		return "操作已取消"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "操作超时，请检查网络或服务状态"
	}
	code := common.SecretFree(err)
	for key, message := range map[string]string{
		"website_previous_runtime_unreadable":             "无法读取主服务器已有 runtime.json，不能确认网站后台的内存增量；请检查主服务器安装目录和权限。",
		"add_node_requires_installed_compatible_main":     "增加子服务器需要已安装且协议兼容的主服务器；请先通过菜单 1 安装或升级主服务器，本次未切换服务",
		"rollout_rollback_not_confirmed":                  "合并部署失败且恢复尚未确认；已停止后续节点，请检查恢复日志并使用原参数继续或回退",
		"selected_node_not_configured":                    "YAML 中找不到指定的子服务器，请核对节点 ID",
		"invalid_retained_pki_":                           "保留的 HTTPS 证书备份不完整或路径不安全，已停止恢复",
		"menu_requires_selection_or_non_interactive":      "没有读取到菜单选择；请交互选择 1/2/3/4，或使用明确的操作参数",
		"unsafe_uninstall_path":                           "卸载路径不安全，已停止清理",
		"uninstall_path_overlaps_preserved_data":          "运行目录与部署包、数据或备份目录重叠，已停止清理，请检查 YAML 目录设置",
		"uninstall_node_missing_from_yaml_":               "历史已部署节点不在 YAML 中；请补回节点连接信息后再卸载",
		"incompatible_cli_options":                        "命令参数冲突：请选择一种操作；重装仅支持全项目，卸载可使用 --central-only 或 --node 指定范围",
		"node_vector_config_invalid":                      "Vector 配置校验失败，事件尚未传输；请检查生成配置中的数值类型及 Vector 错误日志",
		"node_sidecars_not_ready":                         "Vector 或指标采集器未正常启动，暂停文件验收，请检查对应容器日志",
		"acceptance_event_timeout_":                       "中央服务未在规定时间收到测试文件事件或预期扫描结果，请核对节点采集、扫描及 Vector 传输",
		"images_require_explicit_version_or_digest":       "镜像版本格式错误：版本号使用 :v2.0.6，摘要使用 @sha256:…",
		"deployment_notification_pending_resume":          "飞书通知或 PHP 修改测试仍待确认；已保留投递队列，请使用原参数加 --resume 继续",
		"deployment_notification_request_failed":          "无法提交部署通知，请检查主服务器接收服务及飞书配置；使用原参数加 --resume 继续",
		"deployment_php_baseline_timeout":                 "测试 PHP 的新增事件未收到，请检查监控根目录、忽略规则和节点传输；使用 --resume 继续",
		"resume_scope_must_match_original_run":            "继续部署时请保留原来的 --node 或 --central-only 参数",
		"insufficient_available_memory_for_fresh_install": "首次安装的可用内存不足，请调整新组件内存预算或释放内存",
		"registry_authentication_failed":                  "私有镜像仓库认证失败，请检查 YAML 中的账号密码",
		"all_image_pull_sources_failed":                   "所有镜像下载来源均失败，请检查网络、镜像版本和加速地址",
		"all_remote_image_pull_sources_failed":            "子服务器镜像下载失败，将尝试 SSH 传输",
		"bootstrap_already_running":                       "已有引导任务正在执行，请等待当前任务结束",
		"bootstrap_container_cleanup_failed":              "临时引导容器清理失败，未继续执行部署，请检查 Docker 状态",
		"bootstrap_stale_cleanup_failed":                  "上次中断的临时引导容器未能清理，请检查 Docker 状态",
		"single_uninstall_pending_use_original_node":      "存在未完成的单节点卸载，请先使用原来的 --uninstall --node 参数继续收尾",
		"single_uninstall_main_cleanup_pending":           "节点已卸载，主服务器配置收尾尚未完成；请再次执行相同卸载命令继续",
		"single_uninstall_main_configuration_changed":     "卸载重试期间主服务器运行配置发生变化，已停止覆盖，请核对卸载备份和当前配置",
		"single_uninstall_main_health_not_ready":          "节点已卸载，但主服务器接收服务或 Prometheus 尚未就绪，请检查容器并重试收尾",
		"uninstall_main_compose_invalid":                  "主服务器 Compose 配置校验失败，尚未卸载节点",
		"uninstall_main_service_missing":                  "主服务器 Compose 缺少接收服务或 Prometheus，尚未卸载节点",
		"uninstall_main_image_not_available_locally":      "主服务器现有服务镜像不在本机，无法保证离线收尾，尚未卸载节点",

		"bootstrap_central_image_pull_failed":               "主服务器镜像下载失败，无法提取部署工具，请检查网络、版本和仓库权限",
		"bootstrap_tool_release_mismatch":                   "主服务器镜像中的部署工具版本与 SH 脚本不一致，请使用同一版本的脚本及 YAML 镜像",
		"deployment_tool_failed":                            "部署工具执行失败，具体阶段和原因见上方失败日志",
		"central_ready_timeout":                             "主服务器服务就绪超时，请检查接收服务容器",
		"node_agent_ready_timeout":                          "子服务器建立文件清单超时，请检查目录规模和 Agent 状态",
		"node_agent_container_not_running":                  "子服务器 Agent 容器未正常运行",
		"node_agent_start_time_unavailable":                 "无法确认子服务器当前监控容器的启动时间，已停止就绪确认",
		"node_staged_exporter_not_ready":                    "文件清单已完成，但主服务器尚未取得节点的最新 HTTPS 指标，请检查指标采集器及连接",
		"deployment_already_running":                        "已有部署程序正在运行，请勿同时执行安装",
		"ssh_host_fingerprint_mismatch":                     "SSH 主机指纹不匹配，请核对服务器身份",
		"ssh_host_fingerprint_invalid":                      "可选 SSH 主机指纹格式无效；自动记录模式请删除该字段或留空",
		"ssh_known_hosts_insecure_permissions":              "SSH 主机密钥记录或锁文件权限不安全，应由当前执行用户持有，文件权限为 0600、目录为 0700",
		"ssh_known_hosts_invalid":                           "SSH 主机密钥记录格式损坏，已停止连接，请恢复原记录",
		"ssh_known_hosts_read_failed":                       "无法读取已记录的 SSH 主机密钥，已停止连接",
		"ssh_known_hosts_write_failed":                      "SSH 认证已完成，但无法保存主机密钥，已停止此节点操作",
		"node_inotify_limit_setup_failed":                   "无法提高并保存子服务器共享目录监听额度，请检查 sysctl 权限和配置目录",
		"unfinished_deployment_requires_resume_or_rollback": "存在未完成的部署，请使用 --resume 继续或 --rollback 回退",
		"changed_release_or_configuration_requires_upgrade": "现有部署的版本或配置有变化，请使用 --upgrade",
	} {
		if strings.Contains(code, key) {
			return message + "（" + code + "）"
		}
	}
	return "操作失败，程序未识别具体原因。请查看上方最近的失败阶段和日志文件，记录操作命令及错误代码后排查；若已有未完成部署，保持原来的配置和 --node 范围，使用 --resume 继续或 --rollback 回退。错误代码：" + code
}
