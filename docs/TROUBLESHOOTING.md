# 安装与运行问题排查

[返回 README](../README.md) · [SH 安装](INSTALLATION.md) · [网站后台](WEBSITE.md) · [日常维护](OPERATIONS.md)

## 安装入口与全局命令

| 提示或现象 | 处理 |
|---|---|
| 需要交互终端 | 在主服务器的 root SSH 终端执行；向导和菜单从 `/dev/tty` 读取，不能在没有终端的任务中使用一行交互安装命令 |
| 下载超时或失败 | 核对主服务器到 GitHub Release、下载附件域名及 `raw.githubusercontent.com` 的出站连接；已有完整部署包直接使用本地 `webscan` |
| SHA256 校验失败 | 本次校验失败的文件不会覆盖本地包，不执行未验证的下载文件；核对网络及发布附件后重试 |
| 已安装但 YAML 丢失 | 从受保护备份恢复原实际配置，不重新下载示例作为生产配置 |
| 存在未完成部署或卸载 | 保持原脚本、配置、协议与节点范围，按终端日志继续或回退，先处理原任务 |
| 另一个安装或部署正在执行 | 等待原任务结束，不手动删除锁或启动第二次部署 |
| `webscan: command not found` | 已注册时执行 `source /etc/profile.d/webscan.sh` 或重新登录；也可直接执行完整脚本路径 |
| 已有其他软件的同名命令 | 不覆盖它；使用 `bash /root/webscan-deploy/deploy-webscan.sh`，直接运行本地脚本会提示快捷入口注册失败并继续 |
| 部署脚本缺失或路径不安全 | 未完成任务需恢复原版本脚本；其他情况重新获取已校验部署包，不把目标路径改成符号链接 |
| 取消向导后再次打开仍要求填写 | 首次配置尚未保存，重新执行 `webscan` 完成向导；取消不会提交半份配置 |

完整路径调用方式：

```bash
bash /root/webscan-deploy/deploy-webscan.sh
```

帮助、检查、预览和非交互操作不会填写首次向导；配置不完整时按字段提示修正。[一行安装与重复执行规则](INSTALLATION.md) · [未完成任务恢复](OPERATIONS.md#升级中断恢复与回退)。

## 问题排查

### 查看日志和资源

每次执行会显示完整日志路径，日志保存在主服务器：

```text
/var/lib/webscan-deploy/logs/deploy-时间.log
```

另开 SSH 窗口，用 `tail -f` 加上本次显示的完整路径跟踪。阶段日志显示服务器、动作、耗时和失败原因，长任务每 10 秒提示进度。

在要检查的服务器执行：

```bash
# 容器状态
docker ps -a
# 容器 CPU、内存
docker stats --no-stream
```

在**子服务器**查看具体日志：

```bash
docker logs --tail 100 webscan-agent-go
docker logs --tail 100 webscan-vector-v1
docker logs --tail 100 webscan-exporter-v1
```

在**主服务器**从 `docker ps -a` 找到接收服务或 Grafana 容器名称，再执行 `docker logs --tail 100 容器名称`。

### 清单核对一直等待

首次部署要核对现有文件，大型站点最多等待 30 分钟。观察已核对文件数、监听目录数和目录覆盖是否变化。

“启动就绪正常”表示初始清单完成；“目录覆盖等待”表示监听尚未全部建立，两者是不同检查。

v2.0.16 会在 Agent 启动前把 `fs.inotify.max_user_watches` 提高到至少 `262144`，保留已有更高值。监听失败会显示目录及原因，补齐后更新状态。额度由同一用户的程序共享，超大目录树仍可能需要更高上限。配置在 `/etc/sysctl.d/90-webscan-inotify.conf`，卸载时保留。

### 清单正常，但节点指标连接超时

检查主服务器是否能访问节点指标端口，尤其是云安全组是否允许主服务器 IP 访问 TCP `19100`。SSL 开启时指标接口使用双向 TLS，普通 HTTP 请求不能代替正确的健康检查；关闭 SSL 时使用 HTTP，并继续限制来源地址。

失败回退后采集容器可能已停止，应从回退前的日志找原始故障。

### 内存不足

首次安装会显示可用内存和预算明细：组件预算 + 新建 Grafana（192 MiB）+ 新建 Loki（256 MiB）+ 网站后台额外预算 + 安装预留。检查使用实际可用物理内存，不把 Swap 当作可用内存。

`central.new_components_memory_budget_mib` 控制主服务器部分组件的预算。`central.install_memory_reserve_mib` 只控制安装检查的额外预留，默认 128 MiB，可设置 64～4096 MiB，不改变任何容器内存限额。例如组件预算 320、网站后台 128、新建 Grafana 和 Loki 时，默认要求 1024 MiB；预留设为 64 后要求 960 MiB。可用内存低于要求时仍会停止安装。

优先释放闲置资源或扩容；确认实际余量后可调整预留。不要为了通过检查而随意降低组件限额。若失败发生在首次安装环境检查，尚未启动监控容器，修改后重新执行脚本即可，无需 `--resume`；进入部署阶段后中断则按日志提示恢复。

子服务器资源可以公共设置，也可由单节点覆盖：

```yaml
node_defaults:
  resources:
    agent_memory_mib: 256
    go_memory_mib: 64
    cpus: 1.0
    gomaxprocs: 2
```

`agent_memory_mib` 是容器硬上限，不预先分配全部内存；`go_memory_mib` 是 Go 软内存目标，还需为 YARA、缓存及目录监听留空间。不要只为了通过检查而把上限压得过低。修改资源后更新节点服务。

### 容器启动提示 NanoCPUs 不支持

如果 Docker 提示 `NanoCPUs can not be set`，表示节点的内核或 cgroup 没有提供 CPU 配额能力，与网站目录、镜像下载或 SSH 无关。

从 v2.0.17 起，SH 部署会查询子服务器 Docker 的实际能力。支持时应用 `resources.cpus`；不支持时明确提示并跳过 CPU 硬配额，保留容器内存限制、`GOMEMLIMIT` 和 `GOMAXPROCS`。并发限制不能保证 CPU 使用率上限。检查能力失败时停止部署，不静默跳过限制。

直接使用 Compose 部署包时，生成工具无法查询远端 Docker；遇到此错误，可在该节点部署包的 `services.yaml` 中删除 Agent 的 `cpus` 一项后重新执行 `docker compose up -d`，保留其他资源设置。

### 终端报错怎么看

本地新版工具会显示**字段位置、错误原因、填写要求及错误代码**。例如开启飞书却没有填写凭据时，会同时指出：

```text
生成／检查失败：字段 feishu：飞书已开启，请完成以下填写后重试：
- feishu.webhook_url 未填写或格式错误：请复制飞书机器人的完整 HTTPS Webhook
- feishu.signing_secret 未填写：signing_enabled: true 时必须填写加签密钥
```

该段是提示示意，具体措辞以终端输出为准。提示不会回显输入的密码、密钥或 Webhook。YAML 语法错误尽可能给出 `line` 行号；`nodes[0]` 表示第一台节点，`nodes[1]` 表示第二台。节点没有单独填写的参数，请同时检查 `node_defaults`。

生成或检查失败后，先按字段提示修改，再执行：

```bash
# 本地源码目录：只检查，不生成文件、不发送飞书消息
go run ./cmd/compose --config webscan.compose.yaml --check
```

线上部署失败时，先查看最近的 `[失败]` 阶段及同阶段诊断，确认服务器和动作；有未完成部署记录时，按[继续或回退流程](OPERATIONS.md#升级中断恢复与回退)处理，保留原来的配置和节点范围。SSH／命令失败的新版提示可包含退出码；不会输出可能含凭据的完整命令。

| 报错／现象 | 处理方法 |
|---|---|
| Webhook 未填写或格式不正确 | 补齐 `feishu.webhook_url` 的飞书机器人 HTTPS 地址 |
| 加签密钥未填写 | 补齐 `feishu.signing_secret`；核对飞书端与 YAML 的加签设置 |
| YAML 无法读取或语法错误 | 核对 `--config` 文件路径及读权限；根据行号检查缩进、引号、冒号和重复字段 |
| 无法识别字段、类型或取值错误 | 按完整字段路径对照 `--config-help`；不要把整数、布尔值写成带引号的字符串 |
| Compose 输出目录已存在 | 保留原包；另一套全新部署指定 `--output compose-deploy-new`，已有部署升级不要重新生成身份 |
| SSH 连接或认证失败 | 核对节点 IP、端口、root 登录策略、私钥／密码及云安全组；私钥位于主服务器，权限 0400/0600 |
| 镜像下载失败 | 检查仓库、版本及摘要、认证、网络和加速源；查看同阶段下载诊断 |
| `enabled_node_missing_from_order` | 把全部启用节点 ID 补入 `deployment.node_order` |
| `images_require_explicit_version_or_digest` | 默认填写 `webscan-central:latest`、`webscan-agent:latest`；也支持明确版本或完整摘要，不用裸镜像名 |
| `unfinished_deployment_requires_resume_or_rollback` | 原版本及范围下用 `--resume` 或 `--rollback` |
| 热更新提示只能修改过滤规则 | YAML 同时改了目录、资源或端口等，需要先应用那些更新；v2.0.18 起镜像版本差异不阻止热更新 |
| SSH 主机密钥变化 | 先核实服务器身份，再维护密钥记录，不直接绕过校验 |
| 飞书没有收到消息 | 检查机器人开关、Webhook、签名、关键词要求及主服务器投递日志 |

程序尚不能识别具体原因的错误，会提示查看失败阶段和日志，并保留可安全输出的错误代码。更多取值范围和排查步骤见[参数填写与报错说明](PARAMETERS.md)。

## 网站后台无法访问或反代登录失败

先区分无法连接、证书提示和来源校验错误，再检查协议、容器、端口和代理请求头。具体步骤见[后台访问排查](WEBSITE.md#访问与登录问题排查)；网站停止后未立即告警，见[检测与通知判断](WEBSITE.md#检测与通知如何判断)。
