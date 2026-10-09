# SH 自动部署教程（推荐）

[返回 README](../README.md) · [SH 安装](INSTALLATION.md) · [网站后台](WEBSITE.md) · [日常维护](OPERATIONS.md)

## 一行安装（推荐）

在 Linux amd64 主服务器的 root SSH 交互终端执行：

```bash
bash -o pipefail -c 'curl -fsSL https://github.com/gzdzh-cn/dzh-webscan/releases/latest/download/install.sh | bash'
```

下载入口使用 `/dev/tty` 连接向导与菜单，下载或执行失败返回非零状态。无交互终端时不启动安装。需要 curl、Bash、flock、sha256sum 等基础工具；不需要 Go、Python 或 jq。

下载文件来自固定的 GitHub 发布版本，示例 YAML 来自对应源码提交，并检查 SHA256。实际配置保存为 `/root/webscan-deploy/webscan.yaml`，权限 0600；目录和部署脚本为 0700，均由 root 持有。

首次执行顺序：

```text
检查 root、系统与交互终端
→ 下载并校验部署脚本和示例 YAML
→ 注册 webscan 管理入口
→ 填写首次配置向导并保存
→ 进入菜单，选择 1 安装
→ 选择范围内的主、子服务器部署及验收
→ 显示实际后台地址、初始账号与后续管理入口
```

向导保存配置后不会立即启动容器。进入菜单选择 **0** 可退出，以后输入 `webscan` 继续；首次向导已选 SSL 时，紧接着安装不会重复询问。

## 首次配置向导

依次填写主服务器名称和 IP、指标采集来源 IP（默认主服务器 IP）、SSL 模式、网站后台和 Grafana 端口与账号、飞书设置、公共监控目录、子服务器。

| 顺序 | 填写内容 | 默认与说明 |
|---|---|---|
| 1 主服务器 | 名称、公网 IPv4、指标采集来源 IP | 采集来源默认主服务器 IP |
| 2 SSL | HTTPS 或 HTTP | 默认 HTTPS，统一控制通信、采集与网站后台 |
| 3 管理入口 | 是否启用网站后台、端口、管理员名称 | 网站后台默认开启、19444；Grafana 3000；账号 admin，初始密码随机生成 |
| 4 飞书 | 是否启用、Webhook、加签开关与密钥 | 默认开启；Webhook、密钥隐藏输入，也可明确关闭 |
| 5 公共目录 | 一个或多个绝对路径 | 默认 `/www/wwwroot` |
| 6 子服务器 | 唯一 ID、名称、IP、SSH 端口、私钥或密码、独立目录 | 可不添加；SSH 用户 root，端口 22，指纹自动记录 |
| 7 保存 | 查看脱敏摘要，选择是否保存 | 取消或输入结束不提交半份配置 |
- 可以不添加节点，生成 `nodes: []` 和空部署顺序，仅安装主服务器和网站面板；以后菜单 4 添加。
- 普通输入填 0 可取消，秘密输入中的 0 不作为取消字符；EOF 或中断不保存半份配置。
- 查看脱敏摘要后选择保存，保留注释与高级默认值，再进入部署菜单；选择 1 开始安装。
- 首次向导已经选择 SSL，紧接着安装不重复询问。之后正常安装和重装保留 SSL 引导。

帮助、检查、预览和非交互操作不启动配置向导。原有手动编辑 YAML 的安装方式继续支持。

## 再次执行安装命令

| 情况 | 处理 |
|---|---|
| 已安装且两个文件都存在 | 保留 YAML，仅有新版时更新脚本；提示系统已安装并进入菜单 |
| 未安装且两个文件存在 | 待初始化模板进入向导，已填写的配置进入菜单 |
| 未安装、只有脚本 | 下载示例 YAML，进入向导 |
| 未安装、只有 YAML | 保留 YAML，下载脚本 |
| 两个文件都没有 | 首次下载并填写 |
| 已安装但 YAML 丢失 | 停止，要求恢复原配置，不重新初始化 |
| 有未完成部署或卸载 | 保留原脚本和配置，按原范围恢复，不换版本 |

已有 YAML 不覆盖，较新的本地脚本不降级；替换脚本前保存受保护的备份。网络失败时可直接使用本地 `webscan`，不必重复下载。更新入口不等于升级容器，仍由用户选择菜单操作。

## 全局 webscan 命令

```bash
webscan
webscan --upgrade --central-only
webscan --add-node --node node-example
```

宿主机 `/usr/local/bin/webscan` 固定调用 `/root/webscan-deploy/deploy-webscan.sh`，保留传入参数。环境配置 `/etc/profile.d/webscan.sh` 导出 `WEBSCAN_DEPLOY_DIR` 并补齐 PATH。常规 root 终端立即可用；当前终端没有 `/usr/local/bin` 时先执行 `source /etc/profile.d/webscan.sh`，重新登录自动生效。

入口只供主服务器 root 管理，容器中的同名 Go 程序不变。其他软件已经占用此名称时不会覆盖，按提示使用完整脚本路径。卸载后保留入口和部署包，方便重新安装。

### 管理入口文件

| 文件 | 用途与权限 |
|---|---|
| `/usr/local/bin/webscan` | root 管理命令，0755；固定执行部署脚本并原样传递参数 |
| `/etc/profile.d/webscan.sh` | 设置 `WEBSCAN_DEPLOY_DIR=/root/webscan-deploy` 并补齐 PATH，0644 |
| `/root/webscan-deploy/.setup-pending.json` | 首次模板的待初始化标记，完成配置后移除 |
| `/var/lib/webscan-deploy/package-backups/` | 入口更新或向导保存前的受保护备份 |
| `/var/lib/webscan-deploy/config-backups/` | SSL 设置修改前的配置备份 |

快捷命令只注册到主服务器宿主机，不在子服务器创建。帮助、预览及检查不注册命令或启动向导。命令不可用、下载失败或名称冲突时见[安装入口与全局命令排查](TROUBLESHOOTING.md#安装入口与全局命令)。

## 部署包与执行位置

使用 **SH 自动部署**时，在主服务器 `/root/webscan-deploy` 中使用以下文件。一行安装自动获取部署脚本及实际 YAML；同步完整部署包时另附 README：

| 文件 | 用途 |
|---|---|
| `deploy-webscan.sh` | 安装、更新、增加节点、卸载和维护的入口 |
| `webscan.yaml` | 实际使用的服务器、规则、镜像和飞书配置 |
| `README.md` | 完整部署包附带的说明；一行安装不单独下载该文件，可在线查看本教程 |

脚本在执行它的主服务器上运行，通过 SSH 操作子服务器。YAML 中的 SSH 私钥路径必须是**主服务器上的路径**，例如 `/root/.ssh/节点私钥`，不能填写 Mac 上的 `/Users/example` 路径。

本地项目保留完整源码、测试、Dockerfile、构建工具和 [配置示例](../webscan.example.yaml)，服务器部署包不用复制这些源码。SH 中大段编码内容是压缩后的 Go 引导程序，由构建工具生成，无需手工编辑。

## 手动配置安装（已有部署包）

一行安装首次填写使用上面的向导；已有部署包或需要调整高级参数时，可按以下步骤手动编辑 YAML。

### 填好 YAML

已有实际配置时，修改 `webscan.yaml`。从零准备时参考 `webscan.example.yaml`，把占位 IP、私钥路径和飞书凭据替换为实际值。

示例默认开启飞书（`feishu.enabled: true`）。生成配置或部署前，请填写机器人 Webhook；默认开启加签，还需填写签名密钥。缺少凭据会明确提示字段及填写方法，不会悄悄关闭通知。完整字段、填写方法和离线检查见 [参数填写与报错说明](PARAMETERS.md)。

| 配置位置 | 填什么 |
|---|---|
| `central.public_url` | 主服务器 IP 和 HTTPS 端口，如 `https://192.0.2.10:19443` |
| `central.event_service.https_port` | 与上述地址一致的 HTTPS 端口 |
| `central.grafana.host_port` | Grafana 的宿主机端口，默认 `3000` |
| `feishu` | 机器人 Webhook、签名开关和签名密钥 |
| `node_defaults.monitor` | 共用的监控目录、后缀和忽略规则 |
| `node_defaults.metrics.allowed_source_ip` | 主服务器访问节点指标时的来源 IP |
| `nodes` | 每台子服务器的 ID、名称、IP、SSH 端口和认证信息 |
| `deployment.node_order` | 所有启用节点的 ID，以及逐台部署顺序 |
| `registry`、`images` | 镜像仓库及已发布版本 |

SSH 当前要求使用 `root` 登录。`host_key_sha256` 可以省略：首次 SSH 认证成功后自动记录主机密钥，以后严格校验。主服务器上的记录文件是 `/var/lib/webscan-deploy/ssh_known_hosts`。

### 飞书怎么填写

1. 在接收告警的飞书群中添加“自定义机器人”，复制机器人的完整 Webhook。
2. 将地址填写到 `feishu.webhook_url`，格式为 `https://open.feishu.cn/open-apis/bot/v2/hook/机器人标识`。
3. 默认 `signing_enabled: true`，还需从机器人安全设置复制加签密钥到 `signing_secret`。两端加签设置应一致；飞书端没有开启加签时，填写 `signing_enabled: false`。
4. 如果机器人开启关键词校验，确保 `message_prefix` 包含机器人要求的关键词。

以下是填写位置示意，合并到完整 YAML 的原有 `feishu` 区块，不要重复新增区块：

```yaml
feishu:
  enabled: true
  mode: inline
  webhook_url: ''       # 填入自己的完整 Webhook，空值不能部署
  signing_enabled: true
  signing_secret: ''    # 填入自己的加签密钥
  message_prefix: '【网站监控】'
```

`mode: inline` 从 YAML 读取凭据；`existing_env`（也接受 `existing`）从 `existing_env_file` 指定的文件读取 `FEISHU_WEBHOOK_URL`、`FEISHU_SECRET`。SH 使用主服务器上的文件，Compose 生成工具使用本地文件。env 文件按文本读取，不执行命令或展开变量。

修改已安装系统的飞书设置后，SH 部署执行 `bash deploy-webscan.sh --upgrade --central-only` 应用。单纯保存 YAML 不会更新运行中的接收服务。

### 参数填写和检查

在**本地完整源码目录**查看全部字段、用途、单位和填写示例：

```bash
go run ./cmd/compose --config-help
```

该命令不读取实际 YAML，不连接服务器，也不会显示你的真实凭据。[webscan.example.yaml](../webscan.example.yaml) 同样提供逐项注释，标为“兼容保留”的字段不会启用注释中说明的未实现功能。

| 填写类型 | 正确写法 |
|---|---|
| 开关 | `true` / `false`，不加引号，不填 0/1 |
| 整数 | 端口、秒数、容量及线程数不加引号，范围按示例注释填写 |
| CPU 配额 | 数字，例如 `cpus: 1.0` |
| 密码与密钥 | 使用单行字符串，建议加单引号；值中单引号写成两个单引号 |
| 每日时间与时区 | `time: '09:00'`、`timezone: Asia/Shanghai` |
| 列表 | `[值1, 值2]` 或逐行 `- 值`；空列表写 `[]`，不要只留下空的 `-` |
| 文件与目录 | 绝对路径；不要用 `~` 或相对路径代替 SSH 私钥及监控目录 |

YAML 使用空格缩进，不能用 Tab；同一层不要重复字段，一个文件只包含一份 YAML 文档。

下面三种检查的用途不同：

| 命令 | 执行位置 | 会做什么 |
|---|---|---|
| `go run ./cmd/compose --config webscan.compose.yaml --check` | 本地源码目录 | 校验配置和 Compose 生成要求，不创建包、不连接服务器、不发送消息 |
| `bash deploy-webscan.sh --dry-run` | 主服务器部署包目录 | 校验配置并预览操作，敏感字段脱敏；不连接子服务器、不切换服务 |
| `bash deploy-webscan.sh --check` | 主服务器部署包目录 | 检查实际部署环境，会连接节点；引导阶段可下载镜像、安装缺失的 Docker，并记录首次成功连接的 SSH 密钥 |

离线检查通过，只表示格式和已实现的取值检查通过；SSH 登录、端口连通、飞书实际送达及目录监听仍需部署时验收。

### 放行网络端口

云安全组和系统防火墙都要允许以下连接，修改过端口时以 YAML 为准：

| 目标 | 默认 TCP 端口 | 允许谁访问 | 用途 |
|---|---|---|---|
| 主服务器 | `19443` | 各子服务器 IP | 发送事件、查询接收确认（HTTP/HTTPS） |
| 每台子服务器 | `19100` | 主服务器 IP | 采集节点健康指标 |
| 每台子服务器 | YAML 中的 SSH 端口 | 主服务器 IP | 部署和维护 |
| 主服务器 | `19444` | 需要管理网站的地址 | 网站监控后台（HTTP/HTTPS，由 SSL 设置决定） |
| 主服务器 | `3000` | 需要查看面板的地址 | 访问 Grafana |

脚本会维护项目通信需要的宿主机防火墙规则，**云安全组需要在云平台设置**；网站后台和 Grafana 的管理入口也应自行核对宝塔／系统防火墙及云安全组。只在宝塔中放行端口，不代表云安全组已放行。

如果网站后台由同机宝塔反代，并绑定 `127.0.0.1`，无需向公网开放 `19444`，对外开放域名使用的 TCP `443`（需要 HTTP 跳转时再开放 `80`）。完整示例见[后台访问与宝塔反代](WEBSITE.md#宝塔域名反向代理)。

### 执行安装

以下命令均在**主服务器**执行：

```bash
cd /root/webscan-deploy
chown root:root webscan.yaml
chmod 600 webscan.yaml

# 校验配置，不连接子服务器、不修改服务
bash deploy-webscan.sh --dry-run

# 检查实际环境，不切换监控服务
bash deploy-webscan.sh --check

# 打开菜单，选择 1 安装
bash deploy-webscan.sh
```

`--check` 不切换监控服务，但包含上表说明的环境准备和 SSH 检查。

也可以直接安装，不进入菜单：

```bash
bash deploy-webscan.sh --install --non-interactive
```

脚本统一部署主服务器和 YAML 中启用的子服务器，不需要逐台登录安装。节点按 `deployment.node_order` 处理。已有 Docker 继续使用；缺少的 Docker／Compose 按支持的系统环境准备，自动安装 Docker 支持 Debian／Ubuntu。

## 菜单与 SSL 设置

执行 `bash deploy-webscan.sh` 会显示：

```text
1、安装（首次安装；已安装时升级或继续）
2、重装（重建监控容器和配置，保留数据及账号）
3、卸载（选择卸载范围，保留数据与部署包）
4、增加子服务器（选择已有节点或交互录入新节点）
5、SSL 设置并自动部署（统一控制主子通信、采集和面板）
0、退出
```

| 选择 | 什么时候用 |
|---|---|
| 1 安装 | 首次部署、完整更新，或恢复缺失的监控容器 |
| 2 重装 | 重新生成配置和容器，保留历史数据及账号；只支持全项目 |
| 3 卸载 | 移除监控程序，下一层选择全部、主服务器或单个节点 |
| 4 增加子服务器 | 选择 N 交互录入并安装新节点，或选择已有节点更新 |
| 5 SSL 设置并自动部署 | 选择 HTTPS 或 HTTP 后，自动安装或完整升级主服务器与全部启用节点 |

`--non-interactive` 表示不询问菜单，适合自动执行。明确写了 `--install`、`--add-node` 等操作时，本来就不会显示主菜单，手动执行不必额外加它。只写 `--non-interactive` 时默认安装。

### SSL 总开关与宝塔反向代理

执行脚本选择 **5**，再选择 **1 使用 SSL** 或 **2 不使用 SSL**；**0 返回上一级**。设置会保存为：

```yaml
ssl:
  enabled: true  # true 使用 HTTPS；false 使用 HTTP
```

旧 YAML 不写此项时默认开启 SSL。该开关统一控制节点事件上报与确认、节点指标采集和网站管理后台。关闭时保留原端口：事件 19443、指标 19100、后台 19444；兼容字段 `https_port` 的名称保持不变。节点的 `metrics.tls_enabled` 兼容读取，但实际协议由总开关决定。飞书、镜像仓库及被检测网站自身的 HTTPS 不受此开关影响。

选择 **1、安装** 或 **2、重装** 后，脚本都会引导选择 HTTPS 或 HTTP；显示当前 YAML 设置，回车沿用，输入 0 返回。旧 YAML 默认 HTTPS。选择后自动保存配置并按所选操作完成主服务器和全部启用节点的安装、升级或重装。已有安装记录也会询问，重装不会变成普通升级。继续未完成部署时沿用原协议，并提示原因；`--non-interactive` 使用 YAML 设置，不弹出引导。

菜单 **5** 选择协议后，会自动完成完整安装或升级及验收，**无需再手动执行 `--upgrade`**。它同时应用 YAML 中其他待更新设置，并使用配置指定的镜像版本；`latest` 会拉取发布版本。即使选择与当前相同的协议，也会继续完整部署。选择前会提示操作范围，选择后不再额外询问确认。

也可使用一条命令完成保存和部署：

```bash
# 关闭 SSL，并自动安装或完整升级
bash deploy-webscan.sh --set-ssl off
# 开启 SSL，并自动安装或完整升级
bash deploy-webscan.sh --set-ssl on
```

脚本在 `/var/lib/webscan-deploy/config-backups/` 保存修改前的 YAML，备份权限 0600。如果部署失败，所选配置和部署记录会保留，终端会显示失败阶段、日志与恢复命令。存在未完成部署或卸载时，不允许通过菜单 5 修改协议，需先完成原任务或回退。

切换协议需要更新全部启用节点及主服务器容器；数据、账号和事件队列保留，旧证书不会删除。SSL 关闭模式无需生成或读取证书；再次开启时校验并复用现有证书。未完成部署时必须先继续或回退原部署，才能改变 SSL 设置。

使用 HTTP 时，节点通信为明文；原有令牌校验、事件来源 IP 限制和指标端口来源限制继续保留。面板可以由宝塔提供对外 HTTPS，再回源 `http://127.0.0.1:19444`。同机反代时可将 `central.website_monitor.bind_address` 设置为 `127.0.0.1`。反代需保留以下请求头，登录 Cookie 会按浏览器 HTTPS 访问保持 Secure：

```nginx
proxy_set_header Host $http_host;
proxy_set_header X-Forwarded-Proto $scheme;
```

Grafana 原本由独立 HTTP 服务提供，此开关不会改变 Grafana 的监听方式。

## 不添加子服务器也能安装

首次向导在“添加一台子服务器”处选择不添加。手动配置时同时清空这两处：

```yaml
nodes: []
deployment:
  node_order: []
```

将上述设置合并到原 YAML，保留 `deployment` 中其他参数。SH 与 Compose 都支持空节点：安装主服务器及已启用组件，网站可用性仍由主服务器检测；验收明确跳过子服务器文件测试。以后输入 `webscan`，选择 **4 → N** 添加节点，具体流程见[增加或更新单个节点](OPERATIONS.md#增加或更新单个节点)。

## 安装完成后看哪里

- 网站后台：按 SSL 模式打开 `https://主服务器IP:19444/login` 或 `http://主服务器IP:19444/login`，使用独立管理员账号。[开启、端口、登录和宝塔反代](WEBSITE.md#开启与登录)。
- Grafana：默认访问 `http://主服务器IP:3000`，使用 Grafana 账号。[看板与查询](GRAFANA.md)。
- 飞书：核对部署完成和独立测试目录的修改通知。[部署通知说明](OPERATIONS.md#部署通知与验收)。

后台与 Grafana 账号独立；端口修改后以实际 YAML 和部署结束提示为准。
