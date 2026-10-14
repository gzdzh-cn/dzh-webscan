# 参数填写与终端报错

完整参数、用途、单位、示例和兼容限制见根目录的 [webscan.example.yaml](../webscan.example.yaml)。该文件使用示例 IP 和空凭据，请填写实际信息后再部署。

## 查看全部参数

本地完整源码目录执行：

```bash
go run ./cmd/compose --config-help
```

帮助内容内嵌于程序，不读取实际 YAML，不显示真实凭据，也不连接服务器。更新源码后编译的引导程序同样支持 `--config-help`；旧版 SH 内嵌程序需要重新打包才支持新增参数，旧版线上镜像的部署工具也需要发布更新。

## 飞书默认开启

示例保留以下开关：

```yaml
feishu:
  enabled: true
  mode: inline
  webhook_url: ''
  signing_enabled: true
  signing_secret: ''
```

这只是填写片段，不能替换完整 YAML。在飞书群添加“自定义机器人”，从机器人设置中复制完整的 HTTPS Webhook 到 `webhook_url`，从安全设置复制加签密钥到 `signing_secret`。加签开关应与飞书端一致；若飞书端没有启用加签，设置 `signing_enabled: false`。

空凭据不是可用默认值。开启飞书却漏填凭据时，工具会同时指出缺少的 Webhook 和签名密钥，停止生成或部署。不会自动关闭飞书，也不会输出你填入的凭据。实际 YAML 权限应为 `0600`。

```bash
chmod 600 webscan.compose.yaml
go run ./cmd/compose --config webscan.compose.yaml --check
```

`--check` 校验配置类型、取值及 Compose 生成要求；不创建部署包、不验证 SSH 连接或网络、不实际发送飞书消息。`existing_env` 模式会读取指定的本地 env 文件检查凭据格式，但不执行文件中的内容。

## 通用填写规则

| 类型或位置 | 怎么填写 |
|---|---|
| 开关 | `true` 或 `false`，不加引号，不用 0/1 |
| 整数 | 端口、秒数、容量、线程数等使用整数，不加引号；具体范围见示例注释 |
| CPU 配额 | 数字，例如 `1.0`；范围 0.1～16 |
| 字符串 | 密码和时间建议使用单引号；字符串中的单引号写成两个单引号 |
| 时间与时区 | 时间写 `'09:00'`；时区写 `Asia/Shanghai` 或 `UTC` |
| 列表 | 使用 `- 值` 或 `[值1, 值2]`；空列表写 `[]`，不能留下空的 `-` |
| 路径 | 绝对路径，例如 `/www/wwwroot`；SSH 私钥必须在执行部署的主服务器上 |
| 主服务器地址 | `https://主服务器IP:端口`；端口与 `central.event_service.https_port` 相同 |
| 子服务器地址 | `nodes[].host` 只写 IP；SSH 端口单独写 `ssh.port` |
| SSH 指纹 | `host_key_sha256` 可留空；首次认证成功后自动记录，后续仍校验 |
| 公开镜像仓库 | `registry.prefix: docker.io/gzdzh`、`auth_required: false`；账号密码可留空 |
| 私有镜像仓库 | `auth_required: true` 时用户名和密码／访问令牌必填；Compose 生成入口只支持公开仓库 |
| 镜像版本 | 默认 `webscan-central:latest`、`webscan-agent:latest`；也支持已发布版本或真实摘要 |
| 忽略规则 | 完整路径通配列表；`*` 匹配一层，`**` 匹配多层；不能排除根目录或关键文件 |

一个 YAML 文件只能有一份文档；使用空格缩进，不能用 Tab，同一层不能重复定义字段。

`node_defaults` 是公共配置，`nodes` 是每台子服务器的设置。映射字段合并，列表整体替换。例如单节点自定义 `monitor.roots` 时，仍需要的公共路径也要写进该列表。报错中的 `nodes[0]` 是第一台，`nodes[1]` 是第二台；节点未单独填写的字段请检查公共设置。

示例中标为“兼容保留”的字段不代表功能已实现，请按注释使用，不要通过这些开关启用 auditd 等尚未接入的功能。

## 常见报错与处理

| 终端提示 | 如何处理 |
|---|---|
| 飞书 Webhook 或签名密钥未填写 | 填写 `feishu.webhook_url`、`signing_secret`，核对两端加签设置 |
| 无法读取 YAML | 核对 `--config` 路径、文件存在和可读权限 |
| YAML 语法错误 | 根据提示的 `line` 行号检查缩进、冒号、引号、重复字段；不会回显该行内容 |
| 无法识别字段或类型错误 | 根据完整字段位置修改名称、层级或类型；用 `--config-help` 对照 |
| 输出目录已经存在 | 原包不会被覆盖。另一套全新部署可指定 `--output compose-deploy-new`；已有系统升级不要重新生成身份 |
| SSH 连接失败 | 检查节点 IP、SSH 端口、服务状态、云安全组及系统防火墙 |
| SSH 认证失败 | 检查 root 登录策略、认证方式以及私钥／密码；私钥须为普通文件且权限 0400/0600 |
| 镜像下载失败 | 查看同阶段的下载诊断，检查版本、摘要、认证、网络和加速源 |
| 子服务器命令执行失败 | 根据上方节点及阶段检查 Docker、目录权限、磁盘和服务日志；不会打印可能含凭据的命令 |
| 未识别的运行错误 | 保留命令、错误代码和最近失败阶段的日志，进一步排查；有未完成部署时保持配置与节点范围，用 `--resume` 或 `--rollback` |

错误提示保留代码供排查。配置错误主要显示字段、原因和填写方法；运行错误主要显示失败阶段及检查方向。离线校验只能判断配置格式和已实现的取值约束，实际端口被其他程序占用、网络断开、SSH 登录权限或飞书拒绝请求仍需在运行时检查。

## 生成部署包

```bash
go run ./cmd/compose --config webscan.compose.yaml --output compose-deploy-new
```

生成后按 [Compose 教程](COMPOSE.md) 将各服务器的独立包上传并启动。修改源 YAML 不会自动更新之前已生成包内的 `runtime.json`；此前关闭飞书的旧包仍维持旧设置。已运行系统应沿用身份并按升级步骤修改配置，不要覆盖旧数据或重新生成整套令牌与证书。

## 首次安装内存检查

`central.install_memory_reserve_mib`：默认 128，允许 64～4096，单位 MiB。只增加首次安装所需的空闲物理内存，不修改容器限额或 Go 内存目标；旧 YAML 未填写时仍按 128 检查。

legacy 模式要求内存 = `central.new_components_memory_budget_mib` + 新建 Grafana 192 + 新建 Loki 256 + 开启网站后台时的 `extra_memory_mib` + 安装预留。复用已有 Grafana/Loki 时不加对应预算。可用内存取 Linux 的 `MemAvailable`，不计 Swap。终端显示各项、差额和配置字段；不足时停止，不启动监控容器。预检阶段失败可修改后重新安装，无需 `--resume`。

## 网站可用性后台参数

`central.website_monitor` 为可选区块；旧 YAML 省略时关闭，新示例开启。`enabled` 开关、`bind_address` 映射地址、`host_port` 管理 HTTPS 端口默认 19444；`admin_username` 和 `admin_password` 为独立后台账号。密码为空首次生成，手动填写为 12～72 字节。v2.0.29 起这两个账号参数仅用于初始化；数据库已有账号不会被 YAML、SH 升级、Compose 或重装覆盖。修改密码使用后台右上角入口，忘记密码使用 root 交互命令；详见 [后台账号管理](WEBSITE.md#修改管理员密码)。`interval_seconds` 默认 60、允许 10～3600；`timeout_seconds` 默认 5、允许 1～30 且小于间隔；`max_concurrent` 默认 128、允许 1～128；`extra_memory_mib` 默认 128、允许 128～2048。开启后检查主服务器内存，并调整接收容器限制。

网站、关键词及暂停状态通过后台配置，保存到数据库，不写入 YAML。修改后台监听、账号或调度参数使用 `--upgrade --central-only`。详细用法见 [网站后台指南](WEBSITE.md)。

## SSL 总开关

`ssl.enabled` 为布尔值，省略默认 true。true 时节点事件、指标和网站后台使用 HTTPS；false 时统一使用 HTTP，保留原端口和令牌，不生成证书。`central.public_url` 的有效协议自动由此开关决定，旧 `metrics.tls_enabled` 由总开关覆盖。飞书、仓库及网站探测自身的 HTTPS 不受影响。SH 交互安装和重装都会引导选择协议（已有安装记录也询问；中断恢复沿用原协议）；菜单 5 或 `--set-ssl on/off` 会保存设置并自动完整安装或升级主服务器和全部启用节点，同时应用 YAML 其他修改和目标镜像，无需另行执行 `--upgrade`。存在未完成部署或卸载时拒绝修改；单节点或仅主服务器操作不能切换协议。Compose 生成工具同样支持此项，HTTP 包不包含证书。面板宝塔反代示例见 [后台宝塔反代说明](WEBSITE.md#宝塔域名反向代理)。

网站配置备份沿用 `central.backup_dir`，其下 `website-config/` 保存 JSON 配置文件，`website-migrations/` 保存首次升级 v2.0.29 前的一致性 SQLite 备份。手动配置备份不自动过期。证书提醒阈值固定为不超过 7 天，展示按天向上取整；详见 [后台指南](WEBSITE.md#证书有效期与网址操作)。

## Go 一体化采集与告警

`central.monitoring.mode`：新示例为 `native`；旧 YAML 未填写时为 `legacy`，兼容运行原组件并影子采集。已有旧系统不能直接修改此值绕过[历史迁移](MIGRATION.md)。

| 参数 | 默认值与含义 |
|---|---|
| `central.monitoring.raw_hours` | 48；原始指标保留小时数 |
| `central.monitoring.history_days` | 15；5 分钟均值／峰值及健康历史保留天数 |
| `central.monitoring.memory_mib` | 384；native 中心容器内存上限，包含网站后台 |
| `central.monitoring.go_memory_mib` | 256；Go 内存回收目标，需要小于容器上限 |
| `health.metrics_scrape_seconds` | 30；Go 指标采集周期，最多并发 4 |
| `health.alerts.cpu_enabled` / `memory_enabled` | false；按需开启资源告警 |
| `health.alerts.cpu_warning_percent` / `cpu_recovery_percent` | 85 / 80；CPU 5 分钟均值超过阈值、恢复低于阈值 |
| `health.alerts.memory_warning_percent` / `memory_recovery_percent` | 90 / 85 |
| `health.alerts.cpu_duration_seconds` / `memory_duration_seconds` | 300；异常持续时间；恢复需连续两次有效采样 |
| `health.alertmanager.group_wait_seconds` | 30；native 保留兼容字段用于 Go 首次分组等待 |
| `health.alertmanager.group_interval_seconds` | 300；同节点及类别下一批通知间隔 |
| `health.alertmanager.repeat_interval_hours` | 4；持续异常重复提醒间隔 |

native 首次安装内存要求 = 中心容器预算 + exporter 32 MiB + 宿主机管理服务 128 MiB + 安装预留；不再加 Grafana、Loki 或第二份网站后台预算。默认合计 672 MiB，仍以实际 MemAvailable 检查。

`central.managed_runtime_dir`、`managed_compose_name` 是 Compose 接管工具写入的内部布局参数，普通 YAML 保持为空，不通过网页修改。可视化配置参数及生效范围见[统一后台](CONSOLE.md#修改-yaml-参数)。

## 邮箱通知（v2.0.34）

顶层 `email` 默认关闭，SH、Compose 和可视化设置共用。[完整示例和教程](EMAIL.md)。

| 参数 | 默认／约束 |
|---|---|
| enabled | false；关闭保留并暂停队列 |
| smtp_host / smtp_port / tls_mode | 主机不带协议和端口；465 / tls；支持 starttls |
| username / password / from_address | 开启时必填；密码只用于 SMTP，后台留空保持 |
| from_name / recipients | 网站监控；去重后 1～20 个有效地址 |
| timeout_seconds / max_per_minute | 15（1～60 秒）/ 30（1～600 次尝试） |
| retry.initial_delay_seconds / max_delay_seconds | 30 / 3600；指数退避，最大不超过 86400 秒 |
| notifications | 六类开关，与飞书独立；旧配置初始继承飞书 |

SMTP TLS 校验始终开启，不受 `ssl.enabled` 影响；仅需主服务器出站连接。邮件历史与任务纳入事件数据库一致性备份。

## 子服务器部署方式与投递（v2.0.35）

```yaml
node_defaults:
  deployment:
    mode: native
nodes:
  - id: node-example
    deployment:
      mode: docker
```

`native` 为 systemd 单服务，`docker` 为 Agent 单容器。节点显式字段优先于公共默认；旧配置未填写且已有部署记录时沿用原方式，否则 native。中心 `monitoring.mode` 不决定节点方式。

`resources.agent_memory_mib`、`cpus`、`go_memory_mib`、`gomaxprocs` 同时用于 systemd 和容器；native 在启动后核对 MemoryMax、CPUQuota 和文件句柄，未生效则验收失败。

`transport.local_event_queue_max_mib` 继续限制事件库队列，`request_timeout_seconds` 控制请求超时，中心请求上限继续约束每批数据。`vector_buffer_mib` 仅兼容旧 YAML，不再控制 Go 投递器。扫描工具随程序发布，ClamAV 启用需已有 `/run/clamav/clamd.ctl` 扫描服务。指标端口与来源 IP、双向 TLS 和统一 SSL 开关保持原规则。

## v2.0.36 历史管理

`retention.security_events_days`、`retention.website_incidents_days`、`retention.server_alerts_days` 新增独立保留期限；与 `sqlite_events_days`、`delivery_records_days` 一样要求 1～3650 天整数。缺失安全期限沿用事件期限，缺失服务器期限沿用原聚合期限，网站缺省 30 天。所有旧值保留，不进行数据重新导入。[清理行为、保护及导出](RETENTION.md)。

文件事件的页面自动刷新间隔是浏览器偏好，不属于 YAML；后台默认不开启，查询后手动开启，范围 10～3600 秒。
