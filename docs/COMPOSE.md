# 用 Docker Compose 手动安装

本教程用于在全新环境手动部署主服务器和子服务器。镜像从 Docker Hub 下载，服务器只需要 Docker Engine 和 Docker Compose **2.20.0 或更高版本**，不需要安装 Go 或 Python。v2.0.35 的 native 子服务器包由 systemd 运行，无需 Docker；本页 Docker 操作只用于主服务器和选择 docker 的节点。

文中的 `192.0.2.10`、`198.51.100.20` 是保留的文档示例 IP，不是真实服务器地址。实际部署必须填写自己的 IP 和凭据。

> 本页旧 Vector／exporter 和 Grafana 操作仅用于旧版本或 legacy 中心；v2.0.35 节点按文末单服务章节执行，不能同时启动旧 sidecar。

## 一、与 SH 安装有什么区别

| 方式 | 负责什么 |
|---|---|
| SH 自动部署 | SSH 连接所有节点，安装、备份、规则下发、验收、通知及回退 |
| Compose 手动部署 | 本地生成配置和证书，各服务器上传自己的包，手动启动及检查 |

Compose 一次只管理当前服务器，不能替另一台机器启动容器。本教程使用独立的数据目录和项目名；不要与 SH 管理的监控服务同时运行在同一台服务器上，端口和节点容器名会冲突。已有生产服务迁移、数据库接管和回退继续使用 SH 流程。

手动方式运行相同的接收、扫描、投递及健康采集程序，但不会自动发送“部署完成”通知或执行整套验收。普通事件及健康告警按配置工作。新 native 模式通过统一后台查看和管理；旧 legacy 模式仍使用 Grafana。

## 二、安装 Docker 和 Compose

按官方教程安装 Docker Engine 和 Compose 插件：

- [Ubuntu 安装 Docker Engine](https://docs.docker.com/engine/install/ubuntu/)
- [Debian 安装 Docker Engine](https://docs.docker.com/engine/install/debian/)
- [安装 Compose 插件](https://docs.docker.com/compose/install/linux/)

在每台 Linux amd64 服务器确认：

```bash
docker version
docker compose version
```

这里使用带空格的 `docker compose` 命令。

## 三、本地生成部署包

在本地完整源码目录准备 Go 1.26.3，复制并编辑配置：

```bash
cp webscan.example.yaml webscan.compose.yaml
chmod 600 webscan.compose.yaml
# 编辑配置，填写实际 IP、节点、监控目录及飞书信息
```

使用与 SH 相同的 YAML 格式，节点 ID 列入 `deployment.node_order`。SSH 参数仍按配置格式填写，但生成工具不建立 SSH 连接，不把 SSH 密码、私钥或仓库凭据放进包。

仓库使用：

```yaml
registry:
  prefix: docker.io/gzdzh
  auth_required: false
  username: ''
  password: ''
  mirrors: []
```

默认采用 Docker Hub `latest`，也可以固定已发布版本。`central.reuse_existing.grafana`、`loki` 都为 `false`，手动包只支持独立安装，不接管外部组件。

示例默认开启飞书。请填写自己的 `feishu.webhook_url`；默认 `signing_enabled: true`，还需填写 `feishu.signing_secret`。工具会同时提示缺少的 Webhook 和加签密钥，不会生成缺少凭据的通知配置。

生成前可执行 `go run ./cmd/compose --config webscan.compose.yaml --check`，仅校验配置，不创建部署包。执行 `go run ./cmd/compose --config-help` 可查看全部参数及注释；详见 [参数填写与报错说明](PARAMETERS.md)。

执行：

```bash
go run ./cmd/compose --config webscan.compose.yaml --output compose-deploy
```

工具本地生成随机节点令牌、HTTPS 及双向 TLS 指标证书、运行配置、扫描规则和面板，不登录服务器、不拉镜像、不启动容器。

生成目录示意：

```text
compose-deploy/
├── central/              主服务器包
│   ├── compose.yaml      Compose 入口
│   ├── services.yaml     native 两个主服务器组件；legacy 六个
│   ├── .env              指向本包的 services.yaml
│   ├── config/           配置、证书及面板
│   ├── data/             数据目录
│   ├── backups/          自动备份
│   └── grafana-credentials.json
├── node-202/             一个节点包，名称由 YAML 的 ID 决定
│   ├── compose.yaml
│   ├── services.yaml     Agent、Vector、exporter
│   ├── .env
│   ├── config/
│   ├── data/
│   ├── logs/
│   ├── probe/
│   └── vector-data/
└── private/              仅本地保存的 CA 签名密钥
```

每个包只带本机需要的凭据。`private/` 不上传服务器，也不发给别人。包内包含真实运行凭据，文件权限 `0600`、目录 `0700`，默认输出目录已加入 Git 忽略。

输出目录已存在时拒绝覆盖，防止意外换掉令牌和证书。保存原包；试验另一套全新部署时使用新目录，不覆盖已使用的配置。

## 四、上传并启动主服务器

通过 SSH 把整个 `central` 目录上传到主服务器，如 `/root/webscan-compose`。必须包含隐藏的 `.env`、全部配置及数据目录，不要只复制 Compose 文件。

在主服务器执行：

```bash
cd /root/webscan-compose
docker compose config --quiet
docker compose pull
docker compose up -d
docker compose ps
docker compose logs --tail 100 receiver
```

native 主服务器有 receiver 和 host-exporter；legacy 才有 Grafana、Loki、Prometheus、Alertmanager。事件及组件数据在包的 `data/`，自动备份在 `backups/`。容器内路径沿用 YAML，宿主机存储在包目录中。

从主服务器本机检查接收服务，端口以实际 YAML 为准：

```bash
curl --fail http://127.0.0.1:18081/ready
```

新 Go 模式访问 `https://主服务器IP:19444/login`（SSL 关闭时用 HTTP），端口以 `central.website_monitor.host_port` 为准。初始管理员凭据在 `website-credentials.json`，由 root 查看；后台改密后使用新密码。直接访问需放行 TCP 19444，也可使用[宝塔域名反代](WEBSITE.md#宝塔域名反向代理)。

只有旧 legacy 模式提供 `http://主服务器IP:Grafana端口`，凭据在 `grafana-credentials.json`。Compose 不执行 SH 的安装结束提示；已有 Grafana 密码不能通过修改密码文件重置。

## 五、上传并启动每台子服务器

把各节点自己的目录上传到对应服务器，如 `/root/webscan-compose`。**不能把一个节点的包复制给另一节点**，ID、令牌及指标证书都不同。

先确保 YAML 配置的全部监控目录存在，例如 `/www/wwwroot`。缺少目录时 Compose 报错，不会自动创建空目录代替网站。

检查目录监听额度：

```bash
sysctl fs.inotify.max_user_watches
```

低于 `262144` 时在该节点执行以下命令，已有更高值则保留：

```bash
printf 'fs.inotify.max_user_watches=262144\n' > /etc/sysctl.d/90-webscan-inotify.conf
sysctl -p /etc/sysctl.d/90-webscan-inotify.conf
```

手动设置云安全组及系统防火墙：允许主服务器 IP 访问节点指标端口，默认 TCP `19100`；主服务器默认 TCP `19443` 允许节点访问。Compose 不执行 SH 的防火墙管理。

在节点执行：

```bash
cd /root/webscan-compose
docker compose config --quiet
docker compose pull

# 先建立监听和清单
docker compose up -d agent exporter
docker compose logs --tail 100 agent
```

查看就绪文件，确认本次启动的状态为 `applied`，清单及覆盖正常，并结合统一后台（legacy 为 Grafana）检查指标：

```bash
cat data/rules-status.json
```

确认后启用传输：

```bash
docker compose up -d vector
docker compose ps
docker compose logs --tail 100 vector
```

发事件使用生成的 HTTPS 配置，读取指标使用双向 TLS，无需关闭证书校验。

## 六、根目录 Compose 入口

根目录 `compose.yaml` 通过 Compose `include` 加载服务定义，默认选择 `compose-deploy/central/services.yaml`。生成配置后，在根目录执行 `docker compose config --quiet` 可校验主服务器定义。

选择节点包校验：

```bash
WEBSCAN_COMPOSE_FILE=./compose-deploy/node-202/services.yaml docker compose config --quiet
```

`up -d` 必须在对应 Linux 服务器上执行。Mac 可生成及校验配置，不能替远程服务器启动监控，也不能使用 Linux 节点监听及 host 网络功能。

## 七、日常维护

```bash
# 状态和日志
docker compose ps
docker compose logs -f --tail 100

# 停止；恢复时执行 up -d
docker compose stop

# 移除本包容器和网络，绑定目录的数据保留
docker compose down
```

后缀、忽略路径、重要文件名等，编辑节点 `config/runtime.json` 中 `monitor` 对应字段；YARA 编辑 `config/php-webshell.yar`。保存备份，使用原子替换，程序每 5 秒校验后热加载。非法规则保留旧版，在 `data/rules-status.json` 查看是否应用。新增根目录还要调整 `services.yaml` 中 Agent 的只读挂载，再更新 Agent。

Compose 包没有 SH 部署状态，不能对它使用 `--reload-rules`、`--resume` 或 `--rollback`。修改来源 YAML 不会自动更新上传的包。需要批量下发、增加节点、自动验收及回退时，使用 README 的 SH 流程。

更新镜像时，保存当前配置及数据库一致性备份，把目标服务改为已发布的版本及摘要，再执行 `docker compose pull 服务名` 和 `docker compose up -d --no-deps 服务名`。不要重新生成全套身份来升级已有数据。

## 八、如何验收

在统一后台查看采集正常及覆盖值为 `1`，心跳更新，三段链路测试正常，队列能够排空。

手动测试 PHP 时，只在监控目录内建立专用测试目录，新增后修改一个不执行的 PHP 文件，确认飞书和后台事件（legacy 还可查询 Loki），再清理。通知时间应为北京时间。手工测试没有自动验收登记，可能收到新增、修改及删除多条普通通知。

Running 只说明进程在运行，不能代替监听、扫描及投递验收。Compose 不自动执行 YARA 命中、断网恢复及回退等整套测试。

## 网站可用性后台

v2.0.21 的生成工具支持 `central.website_monitor`。开启后主服务器 receiver 额外映射 HTTPS 19444，前端已嵌入 central 镜像，无需增加容器。生成包的 `central/website-credentials.json` 保存访问地址及账号密码，权限 0600。自行放行管理端口并配置证书信任。

更新配置时使用新的输出目录重新生成，先备份已有配置，再替换主服务器 `config` 和 `services.yaml`，保留原来的 `data` 与 `backups`；执行 `docker compose up -d receiver`。重新生成会生成新凭据，若需保留后台密码，请在实际 YAML 明确填写原密码。网站列表保存在数据目录中的事件 SQLite，不会因配置重新生成而清空。详细见 [网站后台指南](WEBSITE.md)。

## SSL 总开关

`ssl.enabled` 为布尔值，省略默认 true。true 时节点事件、指标和网站后台使用 HTTPS；false 时统一使用 HTTP，保留原端口和令牌，不生成证书。`central.public_url` 的有效协议自动由此开关决定，旧 `metrics.tls_enabled` 由总开关覆盖。飞书、仓库及网站探测自身的 HTTPS 不受影响。SH 交互安装和重装都会引导选择协议（已有安装记录也询问；中断恢复沿用原协议）；菜单 5 或 `--set-ssl on/off` 会保存设置并自动完整安装或升级主服务器和全部启用节点，同时应用 YAML 其他修改和目标镜像，无需另行执行 `--upgrade`。存在未完成部署或卸载时拒绝修改；单节点或仅主服务器操作不能切换协议。Compose 生成工具同样支持此项，HTTP 包不包含证书。面板宝塔反代示例见 [后台宝塔反代说明](WEBSITE.md#宝塔域名反向代理)。

## 仅安装主服务器

配置 `nodes: []`、`deployment.node_order: []` 即可生成主服务器独立部署包；无需填写演示节点的 SSH 信息。只启动主服务器组件，网站检查仍由主服务器执行。Compose 用户可继续手动添加，或按下面步骤显式接管宿主机管理。

## 启用可视化部署与配置管理

接管后第一次调整已有节点的监控目录或通信设置前，先执行一次完整升级以记录节点镜像锁。缺少镜像锁时配置应用会明确停止，不会自行替换现有节点镜像。接管失败的回退保留当前数据库及账号，并停用宿主机管理服务，恢复普通 Compose 管理。

普通 `docker compose up -d` 可以使用后台资源／事件／网站查询，但没有宿主机 SSH 和 YAML 写入权限。需要可视化部署时，在 Linux amd64 主服务器包目录执行一次显式接管：

1. 确认主服务器为运行 systemd 的 Linux amd64，且没有另一套 SH 管理部署；备份当前包，确保启用的是 native 模式。
2. 编辑本包 `management.yaml`，配置真实的主服务器宿主机 SSH 私钥路径或密码。生成时 SSH 密码不会导出，原密码认证会改为占位私钥路径，必须完善后再管理节点。
3. HTTPS 模式需将本地生成包的 `private/ca.key` 安全复制到主服务器 `config/pki/ca.key`，root 所有，权限 0600。它必须匹配原 CA，不能生成新 CA。这个签名密钥不上传子服务器，后续由宿主机管理程序使用。
4. 执行 `bash enable-management.sh`。它从已运行的中心镜像提取同版本 Go 程序，记录原包布局、镜像与备份，安装 systemd 管理服务；使用原数据重建 receiver，验证后台与指标。
5. 刷新后台后查看系统设置和部署任务。原包 `services.yaml` 保持与管理生成的 Compose 一致；后续不要并行通过另一个部署包修改同一系统。

接管失败记录为 `compose-adoption-pending`。用提取的工具保持原包路径继续：

```bash
/usr/local/lib/webscan/adoption-tool deploy --config "$PWD/management.yaml" --resume
# 如需退回接管前的独立包布局：
/usr/local/lib/webscan/adoption-tool deploy --config "$PWD/management.yaml" --rollback
```

回退保持当前 SQLite 数据和账号，恢复原运行文件，再启动原 receiver。接管不会改节点容器或防火墙。普通 SSH 节点配置未完善时不能由后台远程更新它们；切换 SSL 前务必确保主服务器持有原 CA 和所有节点认证。

## v2.0.35 混合运行方式

生成前给 Docker 节点显式填写 `deployment.mode: docker`；新示例默认 native。中心 Go 一体化包只启动 receiver。Docker 节点包只启动 agent，不再启动 Vector 或 exporter。节点目录的 `runtime.json` 和证书都带凭据，按 root 专用权限上传。

native 节点目录包含 `install-native.sh`、systemd unit、`config/` 和 `prepare-directories.sh`，不含 Compose 栈。取得同版本发布的 `agent-native.tar.gz` 和 SHA256 清单后，上传该目录，在全新节点运行：

```bash
bash install-native.sh agent-native.tar.gz <发布清单中的SHA256>
```

独立安装包拒绝覆盖已有配置；升级或 Docker/native 切换应通过主服务器部署引擎，避免并行写同一数据库。启用 ClamAV 前准备已有扫描服务。安装后手动核对指标、目录覆盖、扫描和事件上报；自动部署的完整验收请用 SH。[节点部署说明](NODE-DEPLOYMENT.md)。
