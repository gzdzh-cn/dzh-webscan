# 用 Docker Compose 手动安装

本教程用于在全新环境手动部署主服务器和子服务器。镜像从 Docker Hub 下载，服务器只需要 Docker Engine 和 Docker Compose **2.20.0 或更高版本**，不需要安装 Go 或 Python。

文中的 `192.0.2.10`、`198.51.100.20` 是保留的文档示例 IP，不是真实服务器地址。实际部署必须填写自己的 IP 和凭据。

## 一、与 SH 安装有什么区别

| 方式 | 负责什么 |
|---|---|
| SH 自动部署 | SSH 连接所有节点，安装、备份、规则下发、验收、通知及回退 |
| Compose 手动部署 | 本地生成配置和证书，各服务器上传自己的包，手动启动及检查 |

Compose 一次只管理当前服务器，不能替另一台机器启动容器。本教程使用独立的数据目录和项目名；不要与 SH 管理的监控服务同时运行在同一台服务器上，端口和节点容器名会冲突。已有生产服务迁移、数据库接管和回退继续使用 SH 流程。

手动方式运行相同的接收、扫描、投递及健康采集程序，但不会自动发送“部署完成”通知或执行整套验收。普通事件及健康告警按配置工作。Viewer 只读账号需在 Grafana 中手动创建，自动账号管理仍使用 SH。

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

保留示例中的已发布镜像版本和摘要。`central.reuse_existing.grafana`、`loki` 都为 `false`，手动包只支持独立安装，不接管外部组件。

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
│   ├── services.yaml     六个主服务器组件
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

主服务器有 receiver、Grafana、Loki、Prometheus、Alertmanager 和 host-exporter。事件及组件数据在包的 `data/`，自动备份在 `backups/`。容器内路径沿用 YAML，宿主机存储在包目录中。

从主服务器本机检查接收服务，端口以实际 YAML 为准：

```bash
curl --fail http://127.0.0.1:18081/ready
```

浏览器访问 `http://主服务器IP:Grafana端口`。管理员账号密码在当前目录 `grafana-credentials.json`，由 root 查看。Compose 不执行 SH 的安装结束提示和日志密码写入动作。首次留空随机生成；已有 Grafana 数据库的密码不能通过改密码文件直接重置。

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

查看就绪文件，确认本次启动的状态为 `applied`，清单及覆盖正常，并结合 Grafana 检查指标：

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

在 Grafana 查看节点在线及覆盖值为 `1`，心跳更新，三段链路测试正常，队列能够排空。

手动测试 PHP 时，只在监控目录内建立专用测试目录，新增后修改一个不执行的 PHP 文件，确认飞书及 Loki 事件，再清理。通知时间应为北京时间。手工测试没有自动验收登记，可能收到新增、修改及删除多条普通通知。

Running 只说明进程在运行，不能代替监听、扫描及投递验收。Compose 不自动执行 YARA 命中、断网恢复及回退等整套测试。

## 网站可用性后台

v2.0.21 的生成工具支持 `central.website_monitor`。开启后主服务器 receiver 额外映射 HTTPS 19444，前端已嵌入 central 镜像，无需增加容器。生成包的 `central/website-credentials.json` 保存访问地址及账号密码，权限 0600。自行放行管理端口并配置证书信任。

更新配置时使用新的输出目录重新生成，先备份已有配置，再替换主服务器 `config` 和 `services.yaml`，保留原来的 `data` 与 `backups`；执行 `docker compose up -d receiver`。重新生成会生成新凭据，若需保留后台密码，请在实际 YAML 明确填写原密码。网站列表保存在数据目录中的事件 SQLite，不会因配置重新生成而清空。详细见 [网站后台指南](WEBSITE.md)。

## SSL 总开关

`ssl.enabled` 为布尔值，省略默认 true。true 时节点事件、指标和网站后台使用 HTTPS；false 时统一使用 HTTP，保留原端口和令牌，不生成证书。`central.public_url` 的有效协议自动由此开关决定，旧 `metrics.tls_enabled` 由总开关覆盖。飞书、仓库及网站探测自身的 HTTPS 不受影响。SH 交互安装和重装都会引导选择协议（已有安装记录也询问；中断恢复沿用原协议）；菜单 5 或 `--set-ssl on/off` 会保存设置并自动完整安装或升级主服务器和全部启用节点，同时应用 YAML 其他修改和目标镜像，无需另行执行 `--upgrade`。存在未完成部署或卸载时拒绝修改；单节点或仅主服务器操作不能切换协议。Compose 生成工具同样支持此项，HTTP 包不包含证书。面板宝塔反代示例见 [后台宝塔反代说明](WEBSITE.md#宝塔域名反向代理)。

## 仅安装主服务器

配置 `nodes: []`、`deployment.node_order: []` 即可生成主服务器独立部署包；无需填写演示节点的 SSH 信息。只启动主服务器组件，网站检查仍由主服务器执行。后续 SH 交互新增节点只适用于 SH 管理的部署，Compose 用户按原手动维护流程添加。
