# DZH Webscan · 网站与服务器统一监控

监控多台服务器的网站文件变化、可疑代码、首页访问故障、证书到期和服务器资源，通过飞书和邮箱发送提醒，在自己的中文后台查询状态与历史。

[GitHub · gzdzh-cn/dzh-webscan](https://github.com/gzdzh-cn/dzh-webscan) · [Docker Hub central](https://hub.docker.com/r/gzdzh/webscan-central) · [Docker Hub agent](https://hub.docker.com/r/gzdzh/webscan-agent)

支持 **Linux amd64（x86_64）**。前端 Vue 3 + Vite + TypeScript + Element Plus + ECharts，构建后嵌入 GoFrame；服务器无需 Go、Python、Node.js 或前端容器。默认使用 Docker Hub 公开镜像 `latest`。

## 功能与文档

| 功能 | 用途与详细教程 |
|---|---|
| 统一监控后台 | [总览、服务器切换、17 个图表、链路与中心健康](docs/CONSOLE.md) |
| 服务器资源 | CPU、内存、Swap、负载、磁盘／inode、读写速率、IOPS、网络与丢包；主服务器及子服务器可切换 |
| 文件与安全事件 | [多目录、单节点规则、自定义后缀与忽略路径](docs/MONITOR-RULES.md)；变化后异步 YARA，可选 ClamAV |
| 网站与证书 | [首页、关键词、连续故障／恢复、7 天证书提醒](docs/WEBSITE.md) |
| 告警与通知历史 | 当前异常、网站／服务器历史、飞书与邮箱投递结果；[邮箱配置教程](docs/EMAIL.md) |
| 可视化配置与部署 | [添加子服务器、编辑必要 YAML 参数、预览与应用、任务日志](docs/CONSOLE.md#添加和修改子服务器) |
| 账号与备份 | [修改管理员密码、网站 JSON 备份及合并恢复](docs/WEBSITE.md)；部署 YAML 另有受保护的备份与恢复 |
| Go 一体化 | [中心组件迁移](docs/MIGRATION.md)；[子服务器单服务、无 Docker 安装与方式切换](docs/NODE-DEPLOYMENT.md) |

网站关联节点只用于分类，首页检查由主服务器执行；文件监听与扫描在子服务器执行。目标规模为 **50 台服务器（含主服务器）、1000 个网站**。

## 统一监控面板

![网站配置、证书及网址操作](docs/image/website-console.png)

新系统把服务器资源、文件事件、网站检查和飞书／邮箱记录放在同一个后台。后台左侧选择服务器管理，点击服务器进入详情；顶部切换主／子服务器，保留所选时间范围。[页面和图表说明 →](docs/CONSOLE.md)

### 如何打开，需要什么端口

开启 `central.website_monitor.enabled`，部署完成后按实际 SSL 设置访问：

| 方式 | 地址 | 开放要求 |
|---|---|---|
| HTTPS 直接访问 | `https://主服务器IP:19444/login` | 云安全组与宝塔／系统防火墙放行 TCP 19444，需信任部署 CA |
| HTTP 直接访问 | `http://主服务器IP:19444/login` | 同上，协议使用 HTTP |
| 宝塔 HTTPS 域名反代 | `https://monitor.example.com/login` | 对外开放 443；同机后台绑定 127.0.0.1 时不开放公网 19444 |

端口以 `central.website_monitor.host_port` 为准。反代保留原域名 Host，并设置 `X-Forwarded-Proto $scheme`。[登录及宝塔配置 →](docs/WEBSITE.md#宝塔域名反向代理)

管理员初始凭据见安装结果；修改密码后新密码在升级、重启和保留数据的重装后保持。后台旧配置省略时默认关闭，新示例开启。

## 安装方式

**推荐 SH 自动部署**，统一配置各服务器并完成验收。选择其中一种：

1. **[SH 自动部署（推荐）](#1sh-自动部署推荐)**：首次一行安装，以后输入 `webscan` 管理。
2. **[Docker Compose 手动部署](#2docker-compose-手动部署)**：本地生成包，各服务器执行 Compose。

### 1、SH 自动部署（推荐）

在 Linux amd64 主服务器 root SSH 终端执行：

```bash
bash -o pipefail -c 'curl -fsSL https://github.com/gzdzh-cn/dzh-webscan/releases/latest/download/install.sh | bash'
```

入口自动创建 `/root/webscan-deploy`，下载固定发布版本并校验 SHA256。填写首次向导、保存后选择菜单 **1、安装**。可先不加子服务器，以后从菜单 **4** 或后台添加。

以后在主服务器任意目录输入：

```bash
webscan
```

再次执行一行命令保留已有 YAML、账号和数据；有新版时只更新入口，进入菜单，不自动升级容器。配置丢失或有未完成任务时先恢复原任务。[完整 SH 教程、权限与重复执行处理 →](docs/INSTALLATION.md)

### 2、Docker Compose 手动部署

本地完整源码目录先配置并生成身份、证书和运行配置：

```bash
cp webscan.example.yaml webscan.compose.yaml
chmod 600 webscan.compose.yaml
# 填写真实服务器及飞书信息
go run ./cmd/compose --config webscan.compose.yaml --check
go run ./cmd/compose --config webscan.compose.yaml --output compose-deploy
```

把各服务器对应目录上传。主服务器在包目录执行 `docker compose pull`、`docker compose up -d`；Docker 节点只启动一个 Agent；native 节点生成 systemd 安装包。Go 一体化主服务器只启动 receiver，内部采集宿主机指标。[完整 Compose 教程与可视化接管 →](docs/COMPOSE.md)

## 新架构与旧系统升级

```text
文件变化 → 节点 Agent／扫描／SQLite → Go 批量投递与确认 → 中心 SQLite → 飞书＋邮箱／后台
主机指标 → 共享 Go Linux 采集 → 指标 SQLite／聚合 → Go 告警 → 飞书＋邮箱／资源图表
网站配置 → Go 定时首页与证书检查 → 故障历史 → 飞书＋邮箱／后台
后台设置 → Unix Socket 宿主机管理服务 → YAML 备份／部署引擎 → SSH 与验收
```

**新示例采用 Go 一体化模式**，不启动 Prometheus、Alertmanager、Grafana、Loki；子服务器整合为一个 Agent，主服务器内部采集主机指标。旧 YAML 默认 legacy，先升级主服务器，然后后台迁入项目历史并验收，再停用本项目的四个旧容器；不直接删除旧数据。[迁移与回退教程 →](docs/MIGRATION.md)

这是固定项目指标和事件查询，不提供任意 PromQL／LogQL 或 Grafana 插件。旧系统仍在 legacy 时，可继续使用[Grafana 指南](docs/GRAFANA.md)。[详细执行顺序 →](docs/ARCHITECTURE.md)

## v2.0.37 统一备份与记录删除

“备份管理”统一为 **网站配置／部署配置** 两个页签。部署 YAML 支持手动备份、脱敏导出、age 密码加密导入导出及恢复预览；恢复只保存为待应用配置。网站、历史、通知、部署任务及备份支持明确选择的单条／批量删除；服务器先卸载监控并验收，再移除配置，保留业务与历史数据。

近期历史、当前异常、未完成任务和回退依赖受保护；系统设置不新增删除按钮。[备份、恢复、删除及保护规则 →](docs/BACKUPS.md)

普通升级只更新中心，无需升级子服务器：

```bash
webscan --upgrade --central-only
```

子服务器卸载仅在主动确认“卸载并移除”后执行。同步部署包不会自动切换生产容器。

## v2.0.36 总览与历史管理

监控总览增加 **13 类组件状态**，同时展示资源排名、当前异常、网站与双通道通知摘要。正常、异常、停用和未知分别显示，缺失数据不会当成零。

**文件与安全事件打开后不自动查询**：设置条件后点击“查询”，链路探针默认隐藏。查询成功后可手动开启自动刷新，选择 10／30／60／120／300 秒或自定义 10～3600 秒；筛选未提交或浏览器标签处于后台时暂停。刷新间隔只影响页面查询。

系统设置 → 历史与备份可独立设置事件、安全命中、网站故障、服务器告警及通知的保留天数，并查看存储、预览、导出和手动清理。未完成投递、当前异常与未结束故障受保护。缩短期限会自动删除超期历史，调大无法恢复。

```bash
webscan --upgrade --central-only
```

![v2.0.36 监控总览（隔离演示数据）](docs/image/dashboard-v36.png)

本版只需升级主服务器，现有 v2.0.35 子服务器继续运行。[操作说明与数据保护 →](docs/RETENTION.md)

## v2.0.35 子服务器单服务

新增节点默认 **直接运行 Go（native）**，主服务器通过 SSH 下发校验过的程序、YARA 和扫描客户端，由 systemd 管理，子服务器无需 Docker。也可以选择 **Docker 单容器**；已有三容器节点未明确修改方式时，完整升级后保留 Docker，合并为一个 `webscan-agent` 容器。

后台服务器管理 → 添加／编辑配置 → 选择部署方式 → 预览 → 保存并部署。仅保存会标记待应用。列表和详情显示方式、版本及部署状态。主服务器仍需要 Docker。启用 ClamAV 需节点已有扫描服务，不自动安装扫描守护进程。[部署要求、数据保护与回退 →](docs/NODE-DEPLOYMENT.md)

```bash
webscan --upgrade
```

**本版本需要升级子服务器**：先升级中心，再逐台升级启用节点。`--central-only` 只升级中心，旧节点暂时继续兼容运行。下载更新部署包不会自动切换生产服务。

## 网络与维护

| 服务器 | 默认 TCP 端口 | 谁访问、做什么 |
|---|---|---|
| 主服务器 | 19443 | 子服务器上报文件事件 |
| 子服务器 | 19100 | 仅主服务器采集指标 |
| 子服务器 | SSH 端口，默认 22 | 主服务器部署和维护 |
| 主服务器 | 19444 | 管理后台，限制管理来源；同机反代可绑定回环地址 |
| 宝塔反代 | 443 | HTTPS 域名后台 |
| 旧 legacy 主服务器 | 3000 | Grafana；迁移完成后无需开放 |

云安全组和系统防火墙都要放行；主服务器需出站访问被监控网站、飞书和镜像仓库。SSL 总开关统一控制通信、采集和面板，切换协议需部署所有启用节点。

```bash
webscan --upgrade                        # 完整升级
webscan --upgrade --central-only         # 仅升级主服务器，不切换协议
webscan --add-node --node node-example   # 单节点添加或更新
webscan --reload-rules                   # 支持的过滤规则热更新
```

`latest` 不会自动更新运行容器。恢复／回退要保持原版本、配置及范围，按任务日志操作。[维护与回退](docs/OPERATIONS.md) · [问题排查](docs/TROUBLESHOOTING.md)

## 其他文档

[配置参数](docs/PARAMETERS.md) · [版本记录](docs/CHANGELOG.md) · [v2.0.36 验证记录](docs/ACCEPTANCE-v2.0.36.md) · [本地开发与发布](docs/DEVELOPMENT.md) · [镜像仓库](docs/REGISTRY.md)

文档 IP、域名、凭据均为示例。下载命令以已发布 Release 为准；源码构建中的新功能需发布相应镜像后才在线上可用。发布或同步部署包不自动切换生产容器。
