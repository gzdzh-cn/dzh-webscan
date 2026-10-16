package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"webscan/internal/common"
)

const MinimumSystemdVersion = 231
const NodeReserveKiB = 262144

type CheckItem struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}
type CheckReport struct {
	OK        bool        `json:"ok"`
	Items     []CheckItem `json:"items"`
	CheckedAt int64       `json:"checked_at"`
	Mode      string      `json:"mode"`
}
type NodeExecutor interface {
	Run(context.Context, string) ([]byte, error)
}

// DeploymentRequirements is also used by the UI. Values here are not evidence
// that a route is reachable; only a completed connection check can establish that.
func DeploymentRequirements(c *Config) common.Map {
	defaults := common.M(c.Raw["node_defaults"])
	center := common.M(c.Raw["central"])
	nodes := []any{}
	for _, n := range c.Nodes {
		nodes = append(nodes, common.Map{"id": n["id"], "ssh_port": common.M(n["ssh"])["port"], "metrics_port": common.M(n["metrics"])["port"], "allowed_source_ip": common.M(n["metrics"])["allowed_source_ip"], "clamav_enabled": common.B(common.M(common.M(n["scan"])["clamav"])["enabled"])})
	}
	return common.Map{"platform": "Linux amd64", "ssh_user": "root", "minimum_systemd": MinimumSystemdVersion, "reserve_mib": NodeReserveKiB / 1024, "ssh_port": common.M(defaults["ssh"])["port"], "metrics_port": common.M(defaults["metrics"])["port"], "allowed_source_ip": common.M(defaults["metrics"])["allowed_source_ip"], "event_url": center["public_url"], "clamav_enabled": common.B(common.M(common.M(defaults["scan"])["clamav"])["enabled"]), "nodes": nodes}
}

// CheckNodePrerequisites never installs software or changes running services.
// Missing installable Docker/Compose is a warning, not a fabricated pass.
func CheckNodePrerequisites(ctx context.Context, r NodeExecutor, n common.Map, emit func(CheckItem)) CheckReport {
	report := CheckReport{OK: true, Items: []CheckItem{}, Mode: nodeMode(n)}
	add := func(v CheckItem) {
		report.Items = append(report.Items, v)
		if v.Status == "failed" {
			report.OK = false
		}
		if emit != nil {
			emit(v)
		}
	}
	check := func(name, cmd, reason, advice string) []byte {
		started := time.Now()
		if emit != nil {
			emit(CheckItem{Name: name, Status: "running", Message: "正在检查"})
		}
		b, e := r.Run(ctx, cmd)
		v := CheckItem{Name: name, Status: "passed", Message: "检查通过", DurationMS: time.Since(started).Milliseconds()}
		if e != nil {
			v.Status = "failed"
			v.Message = reason
			v.Suggestion = advice
			if ctx.Err() != nil {
				v.Message = "检查超时或已取消"
			}
		} else if strings.Contains(string(b), "install-on-deploy") {
			v.Status = "warning"
			v.Message = "缺少 Docker 或 Compose，将在正式部署时按受支持流程安装"
			v.Suggestion = "确认允许安装；已有异常引擎不会自动重装或重启"
		}
		if e == nil && name == "磁盘空间、inode 与目录权限" && len(b) > 0 {
			v.Message = strings.TrimSpace(string(b))
		}
		add(v)
		return b
	}
	if _, e := deploymentFixtureRoot(n, "preflight"); e != nil {
		add(CheckItem{Name: "监控规则与验收覆盖", Status: "failed", Message: "监控规则不能覆盖独立 PHP 验收文件", Suggestion: "检查监控根目录、.php 后缀和忽略规则；不会绕过规则或创建测试文件"})
	} else {
		add(CheckItem{Name: "监控规则与验收覆盖", Status: "passed", Message: "监控规则可覆盖独立验收文件；未创建测试文件"})
	}
	check("系统与基础工具", "set -eu; test \"$(id -u)\" = 0; test \"$(uname -s)\" = Linux; test \"$(uname -m)\" = x86_64; test -x /bin/bash; for x in sync sha256sum tar df du awk cut mktemp; do command -v \"$x\" >/dev/null; done", "需要 root、Linux amd64 和必要基础工具", "检查 SSH 用户、系统架构及 Bash、tar、sha256sum 等基础命令")
	check("磁盘空间、inode 与目录权限", fmt.Sprintf("set -eu; test -w /var/lib; test -w /var/tmp; free=$(df -Pk /var/lib | awk 'NR==2 {print $4}'); size=0; if [ -f /var/lib/webscan-v1/agent.sqlite3 ]; then size=$(du -k /var/lib/webscan-v1/agent.sqlite3 | cut -f1); fi; need=$((size * 2 + %d)); printf '可用 %%s KiB，需要至少 %%s KiB（数据库双份备份及程序预留）' \"$free\" \"$need\"; test \"$free\" -ge \"$need\"; df -Pi /var/lib /var/tmp | awk 'NR>1 && $4 != \"-\" && $4 < 64 {exit 1}'", NodeReserveKiB), "空间、inode 不足或部署目录不可写", "释放空间并检查 /var/lib、/var/tmp 的权限；不会删除业务文件")
	if nodeMode(n) == "native" {
		check("systemd 与 CPU／内存限制", fmt.Sprintf("set -eu; test -d /run/systemd/system; command -v systemctl >/dev/null; v=$(systemctl --version | awk 'NR==1 {print $2}'); test \"$v\" -ge %d; if [ -f /sys/fs/cgroup/cgroup.controllers ]; then grep -qw cpu /sys/fs/cgroup/cgroup.controllers; grep -qw memory /sys/fs/cgroup/cgroup.controllers; else test -d /sys/fs/cgroup/cpu; test -d /sys/fs/cgroup/memory; fi", MinimumSystemdVersion), "systemd 版本或 CPU／内存控制器不满足要求", "需要 systemd ≥231 和可用 CPU、内存 cgroup；无需安装 Docker")
	} else {
		b := check("Docker 引擎与 Compose", "set -eu; if command -v docker >/dev/null; then docker info >/dev/null; if docker compose version >/dev/null 2>&1; then docker info --format '{{json .}}'; else echo install-on-deploy; fi; else . /etc/os-release; case \"$ID\" in debian|ubuntu) echo install-on-deploy;; *) exit 1;; esac; fi", "Docker 已安装但不可用，或当前系统不支持自动安装", "检查 Docker 服务；不会重启或重装已有引擎。不支持的系统可选择 native")
		if !strings.Contains(string(b), "install-on-deploy") && report.Items[len(report.Items)-1].Status == "passed" {
			ok, e := dockerCPUQuotaSupported(b)
			var info struct {
				MemoryLimit *bool `json:"MemoryLimit"`
			}
			parse := json.Unmarshal(b, &info)
			if e != nil || !ok || parse != nil || info.MemoryLimit == nil || !*info.MemoryLimit {
				add(CheckItem{Name: "Docker 资源限制", Status: "failed", Message: "无法确认 Docker CPU／内存配额控制能力", Suggestion: "检查 Docker 和 cgroup 配置后重新检查"})
			}
		}
	}
	for _, root := range common.SS(common.M(n["monitor"])["roots"]) {
		check("监控目录", "test -d "+Q(root)+" && test -r "+Q(root)+" && test -x "+Q(root), "目录不存在或不可访问："+root, "确认目录路径及权限，或修改此节点监控目录")
	}
	if common.B(common.M(common.M(n["scan"])["clamav"])["enabled"]) {
		check("ClamAV 服务", "test -S /run/clamav/clamd.ctl", "已启用 ClamAV，但扫描服务套接字不可用", "先配置现有 clamd 服务；部署不会安装守护进程或关闭扫描")
	}
	report.CheckedAt = time.Now().Unix()
	return report
}
