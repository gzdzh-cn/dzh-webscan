# 日常维护与升级

[返回 README](../README.md) · [SH 安装](INSTALLATION.md) · [网站后台](WEBSITE.md) · [日常维护](OPERATIONS.md)

## 增加或更新单个节点

v2.0.30 起可直接输入 `webscan`，选择菜单 **4 → N**，填写节点信息，查看脱敏摘要并保存，随后自动执行该节点安装和验收；无需先编辑 YAML。没有节点时也可使用此入口。未完成任务期间禁止修改节点配置。

下面是仍然支持的手动填写方式：

在现有 YAML 的 `nodes` 列表末尾追加节点，例如：

```yaml
nodes:
  # 原有节点继续保留，追加下面这个条目
  - id: node-29
    name: 子服务器29
    host: 198.51.100.22
    enabled: true
    ssh:
      port: 22
      auth_method: key
      private_key_path: /root/.ssh/node-29_id_ed25519
```

再把 `node-29` 加入 `deployment.node_order`，保留原有 ID：

```yaml
deployment:
  node_order:
    - node-202
    - node-28
    - node-29
```

确认主服务器能用指定私钥登录该节点，并放行节点指标端口，然后执行：

```bash
bash deploy-webscan.sh --add-node --node node-29
```

也可以在菜单中选择 **4 → 对应节点序号**。主服务器尚未安装时，应先选择菜单 1 完成安装。

增加节点的顺序：

1. **主服务器及所选子服务器**：检查环境，准备镜像、证书和回退记录。
2. **所选子服务器**：备份旧状态，启动监听及扫描，建立清单，暂缓传输。
3. **主服务器**：登记节点身份和采集目标，使接收服务及 Prometheus 配置生效。
4. **所选子服务器**：启用 Vector，补传本地事件。
5. **子服务器与主服务器**：验收检测、扫描、投递和健康指标，清理测试文件。

这项操作沿用主服务器当前运行的镜像和设置，仅更新所选节点的登记及采集目标。接收服务和 Prometheus 可能因配置生效而重建，正常流程各最多一次；Grafana、Loki、Alertmanager 和其他节点继续运行。

YAML 中尚未应用的主服务器镜像、端口、账号等修改，不随“增加子服务器”生效。更新主服务器另用 `--upgrade --central-only`。

## 镜像版本与下载加速

现在只有两个自研镜像：

| 镜像 | 用途 |
|---|---|
| `webscan-central` | 主服务器接收服务，同时包含部署工具 |
| `webscan-agent` | 子服务器监听和扫描程序 |

不再需要单独的 `webscan-deployer` 镜像。Grafana、Loki、Prometheus、Alertmanager、Vector 和 exporter 使用固定版本的官方镜像。

“Docker 官方仓库”在这里指 Docker Hub。`gzdzh/webscan-central` 和 `gzdzh/webscan-agent` 是本项目在 Docker Hub 发布的公开镜像；第三方组件使用各上游项目发布的镜像。仓库地址如下：

| 组件 | Docker Hub 仓库 | 默认标签 |
|---|---|---|
| 主服务器程序 | [gzdzh/webscan-central](https://hub.docker.com/r/gzdzh/webscan-central) | `latest` |
| 子服务器程序 | [gzdzh/webscan-agent](https://hub.docker.com/r/gzdzh/webscan-agent) | `latest` |
| Grafana 面板 | [grafana/grafana](https://hub.docker.com/r/grafana/grafana) | `12.0.0` |
| Loki 日志 | [grafana/loki](https://hub.docker.com/r/grafana/loki) | `3.5.0` |
| Prometheus 指标 | [prom/prometheus](https://hub.docker.com/r/prom/prometheus) | `v3.5.0` |
| Alertmanager 告警 | [prom/alertmanager](https://hub.docker.com/r/prom/alertmanager) | `v0.28.1` |
| Vector 传输 | [timberio/vector](https://hub.docker.com/r/timberio/vector) | `0.45.0-alpine` |
| 主机指标 | [prom/node-exporter](https://hub.docker.com/r/prom/node-exporter) | `v1.9.1` |

公开仓库配置示例：

```yaml
registry:
  prefix: docker.io/gzdzh
  auth_required: false
  username: ''
  password: ''
  mirrors: []

images:
  central: webscan-central:latest
  agent: webscan-agent:latest
```

默认保持上面的 `latest` 配置。每次发布会同时推送版本号标签和 `latest`，两者对应同一份镜像；需要指定历史版本时，也可以填写明确版本或真实摘要。

SH 部署拉取 `latest` 后，会记录实际镜像摘要。运行容器显示 `docker.io/gzdzh/webscan-central:latest`、`docker.io/gzdzh/webscan-agent:latest` 这样的简短名称；摘要保存在部署状态和容器标签中，用于校验、恢复和回退。第三方容器显示各自的官方固定版本标签。

已有安装升级时，也会把第三方组件的旧摘要名称改成版本标签，例如 `grafana/grafana:12.0.0`、`prom/prometheus:v3.5.0` 和 `timberio/vector:0.45.0-alpine`。即使没有开启 `upgrade_existing_components`，也能更新显示名称，并保留当前锁定的镜像内容。Docker 的容器镜像名称不能原地修改，因此首次切换名称需要重建对应监控容器，数据目录和账号保留；以后名称未变化时不会为此重复重建。仅增加一个节点时，主服务器其他组件保持运行。

`latest` 更新不会自动替换已经运行的容器。SH 更新执行 `bash deploy-webscan.sh --upgrade`；Compose 更新先执行 `docker compose pull`，再执行 `docker compose up -d`。回退会恢复原来锁定的镜像，不重新选择仓库当前的 `latest`。要看程序实际版本，可在节点执行 `docker exec webscan-agent-go webscan version`。

私有仓库设置 `auth_required: true` 并填写用户名和密码／访问令牌；公开仓库用 `false`，部署匿名拉取。**推送公开镜像仍需认证。** 部署认证使用临时 Docker 配置，完成后清理。

`registry.mirrors` 支持多个 HTTPS 加速地址，失败后依次尝试，最后回到官方源；写 `[]` 关闭脚本配置的加速。需要加速时填写自己的有效地址，不能直接使用文档示例域名。部署程序下载公开 Docker Hub 镜像时，自研 central、agent 和第三方组件都使用这些加速源；需要认证的项目镜像及非 Docker Hub 仓库仍直接下载，不向加速源发送仓库凭据。SH 引导提取部署工具时仍按 `registry.prefix` 下载 central。脚本不修改 Docker 全局设置，因此回到官方引用时，Docker 自身配置的全局加速器仍可能生效。节点直拉失败时，可由主服务器下载后经 SSH 传输并校验摘要。

安装和更新时，脚本从 central 镜像提取部署程序，随即删除临时提取容器，再在主服务器运行程序。**提取程序本身不代表重建主服务器接收服务。卸载使用 SH 内嵌程序，不需要下载镜像或创建临时容器。**

## Grafana 账号与节点状态

面板截图、指标含义、Explore 查询和飞书投递结果的核对方法，见 [Grafana 查看与查询指南](GRAFANA.md)。文档提供可复制的 PromQL／LogQL 示例，并说明各面板当前的节点筛选方式。

浏览器访问 `http://主服务器IP:端口`，默认端口 `3000`。可以先用 IP 访问，之后自行配置域名反向代理；子服务器连接使用 `central.public_url`，协议由 SSL 总开关决定。

账号在 YAML 中设置：

```yaml
central:
  grafana:
    host_port: 3000
    admin_username: admin
    admin_password: ''
    create_viewer: true
    viewer_username: webscan-viewer
    viewer_password: ''
```

首次安装密码留空会随机生成，已安装后留空沿用原密码。自定义密码长度为 8～256 字节。

随机密码可以在**部署结束的终端提示**及本项目 **Grafana 容器日志末尾**查看，也保存在主服务器 `/var/lib/webscan-deploy/credentials.json` 中，由 root 查看。部署进度日志文件不会记录这段密码提示。

修改已有账号密码后执行：

```bash
bash deploy-webscan.sh --sync-grafana-credentials
```

修改 `host_port` 后执行：

```bash
bash deploy-webscan.sh --grafana-only --upgrade
```

复用外部 Grafana 时，账号由该 Grafana 自身管理。

登录后查看：

| 面板名称 | 看什么 |
|---|---|
| `Webscan servers` | 节点在线状态、CPU、内存、磁盘和负载 |
| `Webscan health` | 监听覆盖、Agent 心跳、链路测试、组件可达性和待投递队列 |
| `Webscan events` | 文件变化和扫描事件日志 |

判断节点正常时，重点看：节点在线及覆盖值为 `1`；Agent 心跳通常在 60 秒内；本地、中央接收和 Loki 测试年龄通常在 180 秒内；待投递任务能逐步排空。持续增长的队列、失联或覆盖为 `0` 都需要检查。

没有文件变化时，“最近投递成功年龄”可能变大，应结合心跳、链路测试和队列判断。无数据表示未知，不能当作正常。按面板中的节点标识区分各服务器；需要精确查询时，可在 Grafana Explore 的指标查询中加 `{node_id="node-29"}` 筛选。

## 部署通知与验收

安装或更新成功后，发送主服务器及本次选中子服务器的“监控部署完成”通知，再验证每台选中节点的真实 PHP 修改事件。单独增加节点也会执行。

测试使用独立目录，不修改业务网站文件，不执行测试 PHP 内容，完成后清理。新版接收服务会把已登记的预期验收事件汇总；额外的“部署后的 PHP 修改测试成功”通知确认真实修改消息到达飞书。扫描失败、异常内容或未登记事件仍正常告警。

飞书消息使用北京时间和中文说明。验收会检查飞书业务成功响应及 Loki 可查询记录，仅容器启动不算完整部署成功。

通知失败时保留正常监控服务，用原参数加 `--resume` 继续，已确认通知不会重复入队。`feishu.enabled: false` 会明确跳过飞书完成通知及相关 PHP 通知测试。

## 升级、中断恢复与回退

```bash
# 更新整套项目
bash deploy-webscan.sh --upgrade

# 只更新主服务器
bash deploy-webscan.sh --upgrade --central-only

# 只更新一个子服务器，沿用主服务器当前设置
bash deploy-webscan.sh --add-node --node node-29
```

全新 Go 安装及完整 Go 升级，先准备节点监听和清单，暂缓传输，再统一更新主服务器，最后启用传输并验收。首次从旧 Python 版迁移时，先切换主服务器并验证兼容，再切换节点。

出现“存在未完成的部署”时，保留原版本及原操作范围，选择继续或回退：

```bash
# 完整部署中断后继续
bash deploy-webscan.sh --resume
# 或回退
bash deploy-webscan.sh --rollback

# 增加 node-29 时中断，保留原操作及范围
bash deploy-webscan.sh --add-node --node node-29 --resume
# 或回退该操作
bash deploy-webscan.sh --add-node --node node-29 --rollback
```

每组命令是两个可选操作，按需要执行其中一个。原来仅操作主服务器或指定其他节点时，恢复／回退也要带回对应参数。恢复期间不要更换发布版本或改动目标配置。

失败时停止后续节点，恢复失败阶段的旧服务。回退恢复程序和配置，不用旧数据库覆盖新事件，也不清空队列。切换期间监控服务可能短暂停止，网站继续运行；恢复后会补查清单，但间隙中创建后立即删除的文件可能无法补查。

## 卸载与重装

菜单 3 会继续询问：

```text
0、返回上一级
1、主服务器 + 全部子服务器
2、主服务器
3、单个子服务器
```

选择单个子服务器后，列出 YAML 中全部节点的序号、名称、ID 和 IP，包括停用节点。输入序号卸载，输入 `0` 返回上一级。

也可以直接执行：

```bash
# 卸载主服务器和 YAML 中全部子服务器
bash deploy-webscan.sh --uninstall

# 只卸载主服务器
bash deploy-webscan.sh --uninstall --central-only

# 只卸载 node-29
bash deploy-webscan.sh --uninstall --node node-29

# 仅预览卸载范围
bash deploy-webscan.sh --uninstall --dry-run

# 重装全项目
bash deploy-webscan.sh --reinstall
```

卸载先备份，再删除本项目监控容器、服务入口、运行配置和对应防火墙规则。**部署包、网站、SSH 密钥、数据库、事件队列、监控历史、账号、镜像和 Vector 缓冲保留。** 重装是重建服务，不是清空历史。

单节点卸载还会移除主服务器上的节点身份及采集目标，可能使接收服务和 Prometheus 重建，但不拉取或升级镜像。主服务器收尾失败时，再次执行同一条 `--uninstall --node 节点ID` 继续。

只卸载主服务器时，子服务器继续采集并缓存事件。之后用 `--install --central-only` 恢复主服务器；全项目卸载后选择菜单 1 恢复。重装不支持 `--node` 或 `--central-only`。
