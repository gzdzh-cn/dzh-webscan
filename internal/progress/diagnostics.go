package progress

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"webscan/internal/common"
)

// CommandError reports only exit status, never raw command/error text which can
// contain passwords, environment assignments or private configuration output.
func CommandError(code string, err error) error {
	status := -1
	var remote interface{ ExitStatus() int }
	var local interface{ ExitCode() int }
	if errors.As(err, &remote) {
		status = remote.ExitStatus()
	} else if errors.As(err, &local) {
		status = local.ExitCode()
	}
	message := Explain(errors.New(code))
	if status >= 0 {
		message += fmt.Sprintf("；退出码：%d", status)
		switch status {
		case 126:
			message += "，命令无法执行，请检查执行权限"
		case 127:
			message += "，命令未找到，请检查该阶段依赖是否安装及 PATH"
		case 137:
			message += "，进程被强制终止，可能内存不足，请检查 OOM 及系统日志"
		}
	}
	return &Failure{Code: code, Message: message}
}

func explainOperation(err error) (string, bool) {
	code := common.SecretFree(err)
	if message, ok := operationInstructions[code]; ok {
		return message + "（" + code + "）", true
	}
	switch {
	case errors.Is(err, os.ErrPermission):
		return "文件操作被拒绝。请检查当前执行用户、目录可写权限、文件所有者及磁盘只读状态；包含凭据的文件应为 0600。", true
	case errors.Is(err, os.ErrNotExist):
		return "所需文件或目录不存在。请核对 --config、SSH 私钥及部署包路径，按上方失败阶段补齐文件后重试。", true
	}
	if strings.HasPrefix(code, "image_pull_failed_") {
		return "镜像下载失败。请检查 registry.prefix、images 中版本及摘要、仓库权限和网络；加速源写在 registry.mirrors，[] 表示不用加速。查看同阶段的下载诊断。" + "（" + code + "）", true
	}
	return "", false
}

var operationInstructions = map[string]string{
	"consistent_backup_disk_full":                            "一致性数据库备份失败：备份磁盘空间不足。原服务已保留或恢复；请释放备份空间后按原范围重试，不能跳过备份。",
	"consistent_database_backup_failed":                      "一致性数据库备份失败，未提交迁移；请检查备份目录权限、磁盘空间和数据库状态。原数据保持不变。",
	"native_resource_limits_not_effective":                   "systemd 实际内存、CPU 或文件句柄限制与配置不一致，验收停止；请核对 cgroup 和服务属性后恢复。",
	"node_disk_insufficient_for_bundle_and_database_backups": "节点磁盘不足：需要当前数据库两倍空间用于一致性备份，另加至少 256 MiB 工具包及预留空间。尚未切换服务，请释放空间后重试。",
	"old_node_docker_daemon_unavailable":                     "旧节点 Docker 服务不可用，无法保证原写入者已停止。请先恢复现有引擎；本次不会重装或重启业务容器。",
	"native_systemd_version_unavailable":                     "无法识别 systemd 版本，请检查节点 systemctl --version。",
	"native_requires_systemd_231":                            "直接运行 Go 需要 systemd 231 或更高版本，以落实 MemoryMax。当前版本过旧；请升级系统或选择 Docker 单容器。",

	"native_requires_root_linux_amd64_systemd_and_tools":             "直接运行 Go 需要 root、Linux amd64、systemd、Bash、tar、sha256sum 和 sync。请补齐环境；当前未切换服务。",
	"native_cpu_memory_cgroup_limits_unavailable":                    "宿主机缺少可用的 CPU 或内存 cgroup 控制器，无法落实资源限制。请启用相关控制器后重试。",
	"docker_installed_but_daemon_unavailable_not_reinstalled":        "Docker 已安装但服务不可用。本次不会重装或重启业务容器；请修复 Docker，或选择直接运行 Go。",
	"node_docker_missing_choose_native_or_install":                   "此节点没有 Docker。请选择直接运行 Go，或执行部署让受支持的系统自动安装 Docker。",
	"node_docker_bootstrap_failed_choose_native_or_install_manually": "Docker 自动安装未完成。请查看该阶段输出；可改用直接运行 Go，或手动安装 Docker 后重试。",
	"agent_native_package_missing_upgrade_image":                     "目标 Agent 镜像没有新版 native 工具包。请将镜像更新为 v2.0.35 或更高版本。",
	"native_bundle_transfer_or_verification_failed":                  "native 工具包传输、版本或 SHA256 校验失败。尚未切换节点服务；请检查磁盘、连接与该阶段输出后重试。",
	"native_bundle_not_prepared":                                     "节点 native 工具包尚未准备，请按原部署范围恢复任务。",
	"node_go_transport_not_ready":                                    "Go 投递工作器或指标接口尚未就绪，请检查节点服务日志、19100 端口、来源地址及证书。",
	"node_native_service_not_running":                                "节点 systemd 服务没有正常运行，请查看 systemctl status webscan-agent-native 和对应 journal。",
	"node_native_start_time_unavailable":                             "无法读取节点 systemd 本次启动时间，请检查 systemctl 输出和服务状态。",
	"node_clamav_service_unavailable":                                "已开启 ClamAV，但节点扫描服务或 /run/clamav/clamd.ctl 不可用；请恢复现有服务。本次不会静默关闭扫描。",
	"docker_cpu_limits_unavailable":                                  "Docker 不支持所要求的 CPU 配额，未启动新容器。请修复 cgroup 控制器或选择 native 模式。",
	"node_maintenance_release_failed":                                "节点已验收，但中心维护状态解除失败。请保持原范围恢复部署任务，检查中心管理接口及日志。",

	"bootstrap_tool_image_lock_failed":                        "无法记录 latest 部署工具的实际镜像摘要。请检查 Docker 镜像缓存及仓库响应，修复后重试；未开始部署。",
	"runtime_image_alias_lock_invalid":                        "容器短标签对应的锁定镜像记录无效。请检查 Compose 的 io.webscan.locked-image 记录；不要手动改写摘要，使用部署脚本重新生成。",
	"runtime_locked_image_unavailable":                        "本次启动或回退所需的锁定镜像在本机不存在。请恢复该镜像缓存或按部署记录中的摘要下载；不会改用仓库当前 latest 代替旧版本。",
	"runtime_locked_image_identity_invalid":                   "无法识别锁定镜像的实际 ID。请检查 Docker 镜像缓存，修复后重试；本次未启动容器。",
	"runtime_image_alias_tag_failed":                          "无法为锁定镜像设置简短标签，请检查 Docker 服务和镜像缓存后重试。",
	"runtime_image_alias_identity_mismatch":                   "简短标签与本次锁定镜像的实际 ID 不一致，已停止启动；请排查其他进程是否同时修改镜像标签。",
	"reload_rules_only_allows_filter_changes":                 "规则热更新发现监控根目录、资源、端口或其他非规则配置发生变化。仅 exclude_paths、extensions、important_filenames、critical_paths 和指定的 YARA 内容可热更新；其他设置请用 --upgrade 应用，或恢复后重试。本次未下发规则。镜像版本差异不阻止新版工具热更新。",
	"complete_matching_goframe_deployment_required":           "规则热更新需要一次已完成的 GoFrame 部署。请先完成或恢复当前部署，再执行 --reload-rules；部署工具版本可以高于正在运行的服务版本。",
	"global_rules_change_requires_all_affected_nodes":         "公共规则影响了其他节点，请移除 --node 对全部受影响节点更新；单节点更新时，请仅修改该节点的规则覆盖。",
	"node_nonrule_monitor_configuration_mismatch":             "YAML 与该节点实际运行的监控根目录或其他非规则参数不一致。请先通过 --add-node --node 节点ID 或 --upgrade 应用这些设置，再更新过滤规则。本次未替换该节点规则。",
	"node_docker_cpu_capability_check_failed":                 "无法确认子服务器 Docker 的 CPU 配额能力。请在该节点执行 docker info，检查 Docker 服务及 CPUCfsQuota、CPUCfsPeriod 能力；未确认能力前不会启动监控容器。",
	"compose_fresh_packages_do_not_reuse_external_components": "Compose 生成仅支持独立的新部署包。请将 central.reuse_existing.grafana 和 loki 设为 false；已有 SH 部署的升级与回退继续使用 SH。",
	"compose_packages_require_public_registry":                "Compose 入口使用公开镜像。请填写 registry.auth_required: false；私有仓库自动部署请使用 SH。",
	"compose_requires_enabled_node":                           "没有启用的节点。请在 nodes 中至少配置一台 enabled: true 的子服务器，并将其 id 加入 deployment.node_order。",
	"compose_node_id_collides_with_package_directory":         "nodes[].id 不能使用 central 或 private，它们是部署包保留目录名；请修改 id 及 deployment.node_order。",
	"compose_packages_require_dockerhub_gzdzh":                "Compose 入口当前使用 Docker Hub 公开镜像，请填写 registry.prefix: docker.io/gzdzh。",
	"compose_output_path_invalid":                             "--output 目录路径无效；请指定一个尚不存在的新子目录，例如 --output compose-deploy-new。",
	"compose_output_exists_use_new_directory":                 "--output 指定的目录已经存在，未覆盖原有令牌、证书及配置。另一套全新部署请使用 --output compose-deploy-new；已有部署不要重新生成身份进行升级。",
	"compose_output_parent_unwritable":                        "输出目录的父目录不存在或不可写。请创建父目录并确认权限，或将 --output 设置为当前可写目录下的新子目录。",
	"compose_staging_failed":                                  "无法创建临时部署包目录。请检查 --output 父目录的写权限、剩余磁盘容量及 inode。",
	"compose_output_publish_failed":                           "无法将临时部署包保存为目标目录。请检查目录权限、磁盘及是否有另一生成任务同时使用相同 --output。",
	"compose_file_write_failed":                               "写入部署包配置失败。请检查输出磁盘可用空间、inode 和写权限，修复后使用新输出目录重试。",
	"compose_data_directory_failed":                           "无法创建部署包数据目录。请检查输出目录权限、磁盘容量及 inode。",
	"compose_certificate_generation_failed":                   "HTTPS 或指标证书生成失败。请检查 central.public_url、nodes[].host 的 IP 配置和输出目录写权限。",
	"compose_certificate_read_failed":                         "无法读取刚生成的证书。请检查输出目录权限及是否被其他程序删除。",
	"compose_dashboard_read_failed":                           "程序内置 Grafana 面板缺失。请使用完整源码重新构建生成工具。",
	"compose_certificate_staging_cleanup_failed":              "临时证书目录无法清理，部署包未确认完成。请检查输出目录权限后重试。",
	"compose_yara_read_failed":                                "内置 YARA 规则无法读取。请使用完整源码重新构建生成工具。",
	"compose_launcher_unreadable":                             "无法读取 --launcher 指定的 Compose 入口文件，默认是当前目录的 compose.yaml；请在项目根目录运行，或指定文件路径。",
	"actual_yaml_requires_0600_permissions":                   "实际 YAML 必须是普通文件且权限为 0600；在主服务器执行 chmod 600 webscan.yaml（自定义文件名请替换）。",
	"actual_yaml_requires_root_ownership":                     "实际 YAML 必须属于 root；请在主服务器检查并设置文件所有者。",
	"run_on_linux_amd64_main_server_as_root":                  "SH 部署应在 Linux amd64 主服务器使用 root 执行；Mac 上仅生成 Compose 包或离线检查配置。",
	"ssh_key_missing_or_insecure_permissions":                 "SSH 私钥不存在或权限不安全。请检查所选节点 ssh.private_key_path，文件必须位于主服务器、是普通文件且权限为 0400 或 0600。",
	"ssh_key_owner_mismatch":                                  "SSH 私钥所有者与执行用户不一致；root 部署时私钥必须属于 root。请检查节点 ssh.private_key_path。",
	"ssh_key_parse_failed":                                    "SSH 私钥格式无效或需要交互口令。请填写可用的无口令私钥；不要填写 .pub 公钥文件。",
	"ssh_connect_failed":                                      "无法连接子服务器 SSH。请检查 nodes[].host、ssh.port、SSH 服务，以及云安全组、宝塔和系统防火墙是否允许主服务器访问。",
	"ssh_authentication_or_host_verification_failed":          "SSH 认证或握手失败。请检查 ssh.auth_method、root 账号及对应私钥／密码；确认 SSH 服务允许这种认证，查看节点 SSH 服务日志。",
	"ssh_session_failed":                                      "SSH 已连接但无法创建执行会话。请检查节点 SSH 服务、连接数限制和网络，再执行相同操作。",
	"remote_command_failed":                                   "子服务器命令执行失败。请根据上方节点和阶段检查该节点的 Docker、磁盘、目录权限及服务日志；命令内容和配置值不会输出，防止泄露凭据。",
	"bootstrap_command_failed":                                "主服务器引导命令失败。请根据上方阶段检查 Docker 服务、当前执行权限和网络；下载问题见同阶段诊断。",
	"fresh_docker_installation_failed":                        "Docker／Compose 安装失败。请检查主服务器网络和软件源，执行 docker info 与 docker compose version 确认安装后重试。",
	"selected_node_not_enabled":                               "所选 --node 没有启用或不在部署顺序中。请填写 nodes[].id，设置 enabled: true，并加入 deployment.node_order。",
	"progress_log_directory_failed":                           "无法创建进度日志目录。请检查 /var/lib/webscan-deploy 的写权限、磁盘容量和 inode。",
	"progress_log_open_failed":                                "无法打开进度日志。请检查日志目录可写、磁盘未满及日志文件权限。",
	"progress_log_requires_private_regular_file":              "进度日志必须为权限 0600 的普通文件，不能是符号链接；请检查 WEBSCAN_PROGRESS_LOG 指向的文件。",
}
