# Grafana 查看与查询指南

这份文档介绍如何判断服务器监控是否正常、查找网站文件变化，以及核对飞书投递结果。日常先看面板，需要定位某台服务器或某个文件时，再进入 Explore（探索）查询。

示例节点使用 `node-29`，查询时替换成自己的 YAML `nodes[].id`，不是服务器名称或 IP。截图来自 `docs/image/1.png`、`2.png`，文档引用的是隐藏服务器地址和头像后的副本；图中的数值只代表截图时刻。

## 1. 登录后先看哪几个页面

浏览器访问 `http://主服务器IP:Grafana端口`，默认端口 `3000`；使用 YAML 配置的账号登录。SH 随机密码见部署结束提示，Compose 随机密码见主服务器包内 `grafana-credentials.json`。账号维护方法见 [Grafana 账号维护](OPERATIONS.md#grafana-账号与节点状态)。

点击左侧 **Dashboards（仪表盘）**，搜索并打开以下面板：

| 面板 | 主要用途 | 数据来源 |
|---|---|---|
| `Webscan servers` | 节点在线、CPU、内存、磁盘、负载、网络、inode | `Webscan Prometheus` |
| `Webscan health` | Agent 心跳、监听覆盖、监控链路测试、积压队列及组件可达性 | `Webscan Prometheus` |
| `Webscan events` | 网站文件变化、扫描结果及投递记录 | `Webscan Loki` |

当前有两个预配置数据源：**Prometheus 查指标，Loki 查日志**。如果搜索不到面板或看不到这两个数据源，先确认 Grafana 配置是否部署成功；复用外部 Grafana 时还需确认对应配置已导入。

## 2. 时间范围、刷新和节点筛选

右上角的 `Last 1 hour` 表示“最近 1 小时”。查看当前状态可选择最近 15 分钟或 1 小时；查历史问题可展开时间选择器，填写具体起止时间，然后点击 **Apply（应用）**。

**Refresh（刷新）** 可立即更新结果，旁边 `30s` 表示每 30 秒自动刷新。查历史固定时段时可以关闭自动刷新，避免查询重复执行。

建议使用 `Asia/Shanghai`（UTC+8）时区，与飞书的北京时间对照。文件事件 JSON 中的 `time` 仍保存原始 UTC 时间，例如末尾的 `Z` 或 `+00:00`；这不表示事件时间错误。

当前源码中顶部输入框的实际作用如下：

| 面板 | `node` | `search` |
|---|---|---|
| `Webscan events` | 已接入查询，可按节点 ID 或正则筛选；`.*` 表示全部节点 | 已接入日志正则搜索，留空显示全部 |
| `Webscan servers` | 当前查询未引用这个变量，填写后不会自动过滤图表 | 当前未接入查询 |
| `Webscan health` | 当前查询未引用这个变量，填写后不会自动过滤图表 | 当前未接入查询 |

因此，**精确查询某台服务器的资源和健康状态，请使用后面的 Explore 查询**。部署版本或自行修改过的面板可能不同，可通过面板菜单的查询检查功能查看实际表达式。

## 3. 服务器资源面板怎么看

![服务器资源面板：在线状态、CPU、内存和磁盘](image/grafana-servers.png)

图中左上角“正常”表示 Prometheus 能采集对应服务器的指标。右侧 CPU 接近 100% 的曲线表示该服务器当时 CPU 使用率很高；即使在线显示正常，也需要结合负载及健康面板继续判断。

| 项目 | 怎么理解 |
|---|---|
| 节点在线 | `1`：采集可达；`0`：采集失败；`-1`：已登记但尚未取得采集数据；无数据：状态未知 |
| CPU % | 整台服务器最近 5 分钟的平均 CPU 使用率，不是仅监控容器的占用 |
| 内存 % | 按系统可用内存计算的使用比例，包含服务器业务程序的影响 |
| 磁盘 % | 每个文件系统分别显示，可能有多个挂载点；排查时确认网站和监控数据所在挂载点 |
| 负载 | 最近 1 分钟的系统负载，需结合 CPU 核数判断；不能把负载数字直接当百分比 |
| 网络接收 | 每秒接收字节数，可查看趋势和突增情况 |
| inode % | 已使用的文件数量额度；容量未满但 inode 接近耗尽，也可能无法创建文件 |

图例中的 `node_id` 区分服务器：`central` 是主服务器，其余是节点 ID。悬停曲线可看某时刻的数值和标签；曲线颜色由图表分配，不代表固定的风险等级。

这个面板不能判断具体哪个进程占用了内存。需要定位进程或容器时，在对应服务器使用 `docker stats --no-stream` 等系统工具检查；Grafana 显示的是主机总量，与容器统计口径不同。

## 4. 监控健康面板怎么看

![监控健康面板：心跳、链路测试、监听覆盖和积压队列](image/grafana-health.png)

“年龄”表示距离最近一次成功更新经过了多久，数值越小表示更新越近。`s` 是秒，`mins` 是分钟；`2.12 mins` 约为 127 秒，并非 2 分 12 秒。

| 项目 | 表示什么 | 默认配置下的判断参考 |
|---|---|---|
| Agent 心跳年龄 | 距文件监控程序最近一次更新心跳的时间 | 通常几十秒；超过 60 秒需观察，告警还取决于采集间隔及持续时间 |
| 本地测试年龄 | 距 Agent 最近一次捕获独立心跳文件变化的时间 | 心跳文件默认每 60 秒修改；持续超过 180 秒检查本地监听 |
| 中央接收测试年龄 | 距主服务器最近一次收到该节点心跳事件的时间 | 持续超过 180 秒检查节点导出、Vector、网络及接收服务 |
| Loki 查询测试年龄 | 距主服务器最近一次确认该节点心跳日志在 Loki 中可查的时间 | 持续超过 180 秒检查 Loki 投递和查询链路 |
| 覆盖 | 配置范围内的目录监听是否完整 | `1` 正常，`0` 不完整；无数据不能当成正常 |
| 待投递任务 | 主服务器待发送到飞书／Loki 的任务数量 | 短暂上升可以正常；持续增长需排查 |
| 最旧任务年龄 | 主服务器最早未完成投递任务等待了多久 | 默认超过 300 秒告警；结合任务数量判断 |
| Vector 缓冲字节 | 节点传输缓冲中积压的数据量 | 允许短暂积压；网络恢复后应逐步减少 |
| 组件可达性 | Prometheus 各采集目标是否可访问 | `1` 可达，`0` 不可达；要看清 `job` 和 `node_id` |
| 最近投递成功年龄 | 主服务器最近一次飞书／Loki 投递成功距今多久 | 无需投递消息时自然增长，不能单独据此判断故障 |

以上是默认参考，不是所有部署的固定阈值。实际值由 YAML 的 `health` 等配置控制。**卡片变绿不等于所有检查通过，应同时看数值、单位、持续时间和队列趋势。**

按顺序排查更容易定位：先确认节点在线 → 再看 Agent 心跳及覆盖 → 再看本地测试 → 中央接收测试 → Loki 查询测试 → 最后核对积压队列与飞书送达。

例如本地测试持续正常，但中央接收年龄持续增加，优先查 Vector、节点到主服务器的网络及接收接口；中央接收正常而 Loki 查询年龄增加，优先查主服务器的 Loki 投递和查询。

## 5. Explore：精确查询指标

1. 点击左侧 **Explore（探索）**。
2. 数据源选择 **Webscan Prometheus**。
3. 切换为 **Code（代码）** 输入模式，粘贴下面的表达式。
4. 设置右上角时间范围，点击 **Run query（执行查询）**。
5. 查当前数值时使用 **Instant（即时查询）**；查变化趋势时使用 **Range（范围查询）**。界面可能显示为查询类型选项。

没有 Explore 菜单或提示权限不足时，使用管理员账号或申请对应查询权限。查看现有面板可使用只读账号；查询操作无需编辑已部署的面板。

### 查询某台子服务器是否在线

```promql
up{job=~"webscan-node-.*", node_id="node-29"}
```

`1` 表示指标接口可达，`0` 表示本次采集失败。没有结果时核对节点 ID、采集登记及时间范围；不要解释为 `0` 或正常。

同时查询所有子服务器：

```promql
up{job=~"webscan-node-.*"}
```

### 查询 Agent 和文件监听是否正常

依次执行以下表达式：

```promql
time() - webscan_agent_heartbeat_seconds{node_id="node-29"}
```

```promql
webscan_coverage_ok{node_id="node-29"}
```

```promql
time() - webscan_local_probe_seconds{node_id="node-29"}
```

心跳和本地测试的结果单位为秒，覆盖应为 `1`。启动清单尚未完成时，结合节点日志和进度判断；指标采集失败时先恢复采集，不要依赖停止更新的旧数值。

### 查询中央接收和 Loki 链路

```promql
time() - webscan_probe_received_seconds{node_id="node-29"}
```

```promql
time() - webscan_probe_loki_seconds{node_id="node-29"}
```

极大的年龄也可能表示尚未成功记录第一次测试；不能仅凭这两个值确认进程已经停了。

### 查询节点本地积压与扫描任务

```promql
webscan_local_pending_events{node_id="node-29"}
```

```promql
webscan_local_oldest_pending_seconds{node_id="node-29"}
```

```promql
webscan_pending_scans{node_id="node-29"}
```

第一项是尚未得到主服务器接收确认的本地事件数，第二项是其中最旧事件的等待秒数，第三项是待扫描任务数。短暂非零并不一定异常，关注是否能排空。

### 查询飞书和 Loki 投递积压

```promql
webscan_pending_tasks{target="feishu"}
```

```promql
webscan_oldest_pending_seconds{target="feishu"}
```

将 `target="feishu"` 改为 `target="loki"` 即可检查 Loki。**这两个指标统计整个主服务器的投递队列，不带 `node_id` 标签**；加上节点过滤会查不到数据。查询某节点的具体投递结果，请使用后面的 Loki 日志。

### 查询某台服务器的 CPU、内存与磁盘

CPU 使用率，单位百分比：

```promql
100 * (1 - avg by (node_id) (rate(node_cpu_seconds_total{node_id="node-29", mode="idle"}[5m])))
```

内存使用率，单位百分比：

```promql
100 * (1 - node_memory_MemAvailable_bytes{node_id="node-29"} / node_memory_MemTotal_bytes{node_id="node-29"})
```

磁盘使用率，排除部分临时及容器文件系统：

```promql
100 * (1 - node_filesystem_avail_bytes{node_id="node-29", fstype!~"tmpfs|overlay|squashfs"} / node_filesystem_size_bytes{node_id="node-29", fstype!~"tmpfs|overlay|squashfs"})
```

磁盘返回多条结果时，按 `mountpoint`、`device` 区分挂载点。查主服务器的资源时，将 `node_id="node-29"` 改为 `node_id="central"`；Agent 专有指标通常不适用于主服务器。

## 6. 查某个网站、文件或操作的日志

### 先使用事件面板

打开 **Webscan events**，选择时间范围，在 `node` 中填写 `node-29`，在 `search` 中填写简单搜索词，例如 `config` 或 `modify`，确认输入后刷新。

`node` 接受正则，`.*` 表示全部，`node-202|node-28` 表示两个节点。`search` 同样是正则搜索，会搜索整条日志，可能匹配多个字段；要精确限定网站、路径、操作或扫描状态，请用 Explore。

### Explore 中选择 Loki

点击 **Explore**，数据源改为 **Webscan Loki**，切换 **Code**，设置时间范围后执行查询。这里使用 LogQL，与 Prometheus 的 PromQL 不同，不要粘贴到错误的数据源。

查看某节点的全部事件：

```logql
{job="webscan-v1", node_id="node-29"} | json
```

按文件路径中的固定文字搜索：

```logql
{job="webscan-v1", node_id="node-29"} |= "config.php" | json
```

按完整路径精确查找：

```logql
{job="webscan-v1", node_id="node-29"} | json | path="/www/wwwroot/example.com/config/config.php"
```

只查某个网站的修改操作：

```logql
{job="webscan-v1", node_id="node-29", operation="modify"} | json | site="example.com"
```

这些路径和网站名都是示例，需按实际目录及事件中的 `site` 替换。站点名通常是监控根目录下的第一级目录名。

### 常见字段和操作怎么读

点击日志行展开详情，查看解析字段或原始 JSON：

| 字段 | 含义 |
|---|---|
| `node_id`、`server_name` | 来源节点 ID、服务器显示名称 |
| `site`、`path` | 所属网站与文件路径 |
| `operation` | 事件类型，见下表 |
| `time` | 事件发生时间，原始值为 UTC |
| `event_id` | 此事件的唯一编号，用于对照飞书或追踪关联结果 |
| `related_event_id` | 扫描及投递结果所关联的原事件编号 |
| `sha256`、`previous_hash` | 文件内容摘要及原摘要，适用时存在 |
| `old_path` | 移动或改名前的位置，适用时存在 |
| `scan`、`risk` | 扫描状态及风险分类 |
| `detection` | `inotify` 为实时监听，`reconciliation` 为清单补查 |
| `rules_version` | 生成事件时使用的规则版本 |

| `operation` 值 | 通俗含义 |
|---|---|
| `create` | 新增文件 |
| `modify` | 修改文件 |
| `delete` | 删除文件 |
| `move` | 移动或改名 |
| `scan` | 文件扫描结果 |
| `probe` | 监控心跳自检，不是业务网站异常 |
| `health` | 节点监控健康异常 |
| `delivery` | 主服务器的飞书投递尝试记录 |
| `test` | 通知测试类事件 |

`risk: unclassified` 表示尚未归类，不等于文件安全。文件变化事件的扫描状态可能是 `pending`，后续扫描结果是另一个关联事件。

### 查询可疑代码和扫描失败

查询扫描命中：

```logql
{job="webscan-v1", node_id="node-29", operation="scan"} | json scan_status="scan.status" | scan_status="matched"
```

将最后的 `matched` 改为 `error` 查询扫描失败，改为 `no_match` 查询未命中特征，改为 `skipped` 查询跳过扫描。未命中只说明本次检查未命中特征，不能证明代码绝对安全。

### 根据事件编号追踪变化、扫描及投递

```logql
{job="webscan-v1", node_id="node-29"} | json | event_id="替换为实际事件编号" or related_event_id="替换为实际事件编号"
```

两处填写同一个原事件编号。结果可能包含原文件变化、后续扫描和飞书投递记录；是否存在飞书任务还取决于通知开关及事件类型。

Loki 列表显示的时间是日志索引写入时间，`time` 字段才是原事件发生时间。断网补传时两者可能相差很久：按原事件时间查不到时，扩大到补传发生的时段，再按路径或事件编号过滤。

## 7. 怎么确认飞书确实发送成功

先在 Prometheus 查飞书队列数量，再用 Loki 查看该节点的投递记录：

```logql
{job="webscan-v1", node_id="node-29", operation="delivery"} | json | target="feishu"
```

展开日志，重点看 `related_event_id`、`attempt` 和 `status`：

- `related_event_id` 用于对应原事件；`attempt` 是第几次投递尝试。
- `status` 为 `http=200,business=0` 等记录，表示飞书 HTTP 请求成功且返回业务成功码；程序不能确认群成员是否已经阅读。
- 非零飞书业务码或错误说明本次失败，任务会按配置等待重试。核对 Webhook、加签、关键词限制及网络。

投递记录本身也通过队列写入 Loki，因此可能稍晚出现。Loki 无法查询时，仅靠查不到投递记录不能断定飞书失败；需结合飞书群实际消息、队列指标及主服务器接收服务日志。

主服务器返回的事件接收回执只说明事件已经落库，不代表飞书已发送；文件在 Loki 中可查也不能代替飞书投递成功。

## 8. 查看当前健康告警

在 Explore 选择 **Webscan Prometheus**，使用即时查询：

```promql
ALERTS{alertstate="firing"}
```

只查看某台节点：

```promql
ALERTS{alertstate="firing", node_id="node-29"}
```

将 `firing` 改为 `pending` 查看已经达到条件但尚未满足持续时间的告警。结果中的 `alertname` 是告警名称；例如 `WebscanCoverageGap` 表示监听覆盖异常，`WebscanNodeUnreachable` 表示节点指标不可达。

本项目告警规则由 **Prometheus 计算、Alertmanager 分组并转发、主服务器投递飞书**。Grafana 左侧的 Alerting（告警）页面可能没有列出这些外部规则，页面为空不表示没有告警。上述即时查询无结果，也仅说明当前没有匹配该筛选条件的告警样本。

## 9. 常见问题与日常检查

| 现象 | 优先检查什么 |
|---|---|
| 所有面板都无数据 | 时间范围、数据源连接、Prometheus／Loki 服务及 Grafana 配置 |
| 一台节点无数据 | 节点 ID、采集目标登记、exporter、双向 TLS、指标端口及云安全组 |
| 顶部填写节点后图表仍显示全部 | 资源和健康面板当前未绑定该变量，改用 Explore 的 `node_id` 标签过滤 |
| 节点在线但本地测试停了 | Agent 心跳、目录覆盖、监听额度和本地日志 |
| 本地测试正常、中央接收不更新 | JSONL 导出、Vector 缓冲、节点到主服务器的 HTTPS 网络及认证 |
| 中央接收正常、Loki 查询不更新 | Loki 待投递任务、最旧任务年龄、Loki 服务及接收服务查询日志 |
| 文件日志查不到 | 节点 ID、查询时间、忽略规则、后缀、实际监控路径和补传时段 |
| 飞书没有消息但 Loki 有日志 | 飞书通知开关、投递队列、投递尝试记录、机器人配置及网络 |
| 点击 Edit 后无法保存 | 面板由部署工具预配置；查询可用 Explore，自定义面板可另存副本 |

日常检查建议：打开 `Webscan servers` 看在线和资源 → 打开 `Webscan health` 看覆盖、心跳及积压 → 打开 `Webscan events` 看异常事件 → 有疑问时用 Explore 按节点、文件及事件编号定位。

如需验证真实文件监控，只在独立测试目录修改 PHP，再核对文件变化、扫描结果、Loki 和飞书；不要修改业务文件做测试，也不要运行测试 PHP 内容。运行故障的服务日志及恢复命令见 [安装与运行问题排查](TROUBLESHOOTING.md)。

[返回项目使用说明](../README.md)

## 网站可用性

v2.0.21 开启网站后台并升级主服务器后，搜索“网站可用性”看板。网站列表通过 [管理后台](WEBSITE.md) 添加，Grafana 用于观察趋势。

| 查询 | 含义 |
|---|---|
| `webscan_website_available` | 1 正常、0 连续失败已告警、-1 尚未确认；暂停网站不导出 |
| `webscan_website_latency_seconds` | 最近一次首页检查耗时 |
| `webscan_website_http_status` | 最近 HTTP 状态；连接失败时为 0 |
| `webscan_website_success_ratio` | 自网站添加或状态重置起的检查成功比例 |
| `(webscan_website_certificate_expiry_seconds - time()) / 86400` | 最近取得证书的剩余天数；证书指标为 0 时不适用 |
| `webscan_website_scheduler_up` | 1 表示调度正常运行，0 表示停滞或读取失败 |
| `webscan_website_backlog_seconds` | 检测积压持续时间 |
| `time() - webscan_website_last_check_seconds` | 距离最近检查的时间 |

可以通过 `site_id`、`website` 和 `node_id` 标签筛选，例如 `webscan_website_available{website="示例官网"}`。没有数据时先确认网站后台已开启、已经添加网站，且主服务器采集目标正常；不要把“没有数据”视为网站正常。

网站故障和恢复由 Go 服务统一发送飞书，Grafana/Alertmanager 默认不重复发送这些网站告警。

网站可用性看板的证书剩余天数使用 `webscan_website_certificate_remaining_days`。负数或零表示已过期；未知、不适用显示无数据，不会被当成过期证书。可用 `webscan_website_certificate_known` 区分是否有已取得的证书。网络失败后保留最近证书信息，检查新鲜度请在网站后台详情查看最近证书检查时间。网站证书告警由 Go 服务发送，不另建 Alertmanager 重复提醒。
