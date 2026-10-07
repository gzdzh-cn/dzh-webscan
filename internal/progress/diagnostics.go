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
