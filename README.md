# Webscan 部署与 Grafana 账号

安装入口是 `deploy-webscan.sh`，内部解包 Python 程序执行部署。请用 **Bash**，不要用 `sh deploy-webscan.sh`。在主服务器以 root 执行，节点 SSH 私钥路径必须是主服务器上的路径。

主服务器 `/root/webscan-deploy` 只需保留这三个文件：`deploy-webscan.sh`（独立部署脚本）、`webscan.yaml`（实际配置，0600）和 `README.md`（操作说明）。其中前两个是执行必需文件；源码和模板已经打包在脚本内部，运行时自动解包到临时目录并清理。

本地 `/Volumes/disk/site/go/监控系统` 同样只保留这三个文件，供编辑配置和上传新版本使用。部署命令在主服务器执行。

运行程序在 `/opt/webscan-central/webscan-v1`，监控数据在 `/var/lib/webscan-central`，部署状态、账号凭据和回退记录在 `/var/lib/webscan-deploy`，数据备份在 `/var/backups/webscan`。这些目录是运行和恢复所需文件，不属于部署目录的临时文件。

```bash
cd /root/webscan-deploy
apt-get install -y python3 python3-yaml openssh-client
# 只有密码认证的节点才需要：apt-get install -y sshpass
chmod 600 webscan.yaml
bash deploy-webscan.sh --config webscan.yaml --dry-run
bash deploy-webscan.sh --config webscan.yaml --check
# 首次安装全部启用节点
bash deploy-webscan.sh --config webscan.yaml --non-interactive
# 同一版本安装中断后继续
bash deploy-webscan.sh --config webscan.yaml --resume --non-interactive
# 更新部署包/配置：中央组件升级，不重新扫描全部节点
bash deploy-webscan.sh --config webscan.yaml --upgrade --central-only --non-interactive
# 需要升级全部节点时：移除 --central-only
```

`--dry-run` 检查配置并显示脱敏计划；`--check` 会连接服务器执行环境检查。正式安装会进行验收，默认发送带测试标记的飞书通知。出错会停止后续节点并保存状态，禁止忽略错误继续切换。

## 本次安装问题与修复

- 主服务器约 2 GB 内存，首次安装仍严格校验预算；重复执行和恢复时只抵扣本项目已运行容器的匿名常驻内存，避免重复预留或把文件缓存重复计入。
- Grafana 数据库初始化晚于事件接收服务：等待数据库与管理员认证就绪，最多 180 秒，然后配置看板。
- 子服务器镜像源下载超时：在主服务器锁定镜像，通过已校验 SSH 指纹的连接传输归档；校验 SHA256、加载后镜像 ID，并按固定 ID 启动。
- 15 秒心跳与 30 秒采集容易在边界误报：规则使用至少两次采集间隔、最低 60 秒的过期阈值，并保留告警持续时间。
- 完成时清理历史失败状态，保留恢复状态、镜像锁定和回退记录。
- 原脚本只在首次安装使用 YAML 密码；现在新增独立的凭据更新命令，支持管理员改名、管理员与只读密码更新和中断后重试。

## 在 YAML 中定义 Grafana 账号

编辑 `central.grafana` 下的这些字段；其他字段保留：

```yaml
central:
  grafana:
    bind_address: 0.0.0.0
    host_port: 3000
    admin_username: admin
    admin_password: ''
    create_viewer: true
    viewer_username: webscan-viewer
    viewer_password: ''
```

首次安装：用户名使用 YAML 值，密码留空则随机生成。自定义密码须 8–256 个字符，不允许控制字符；用户名允许字母、数字、`_.@-`。管理员与只读用户名必须不同。密码值用 YAML 引号包起来，例如 `admin_password: 'Your-Strong-Password'`；单引号内部的单引号写成两个单引号。

已有安装：普通部署/升级保留已保存密码，**修改 YAML 后须专门执行以下命令才更新已有账户**：

```bash
bash deploy-webscan.sh --config webscan.yaml --sync-grafana-credentials
```

该命令调用 Grafana API，验证更新后登录，保存到 root 专属文件；不重新部署节点、不重启监控服务。密码留空保留原值，不重新生成。`admin_username` 可以修改现有管理员登录名；`viewer_username` 指定要更新的现有 Viewer 账号，不负责重命名它。新增只读账号先用中央升级命令建立；已有同名管理员或非 Viewer 账号会被拒绝，不自动改变其权限。复用外部 Grafana 时，管理员密码字段用于认证其现有账户，凭据变更通过其账户管理界面完成。

部署完成和凭据更新后，终端最后会显示访问地址、管理员与只读账户的登录凭据，并把同一提示写入 **Grafana 容器日志**。显示前会验证登录，不会输出未验证的只读密码。日志包含明文 Grafana 凭据；飞书与 SSH 等其他凭据不输出。

```bash
cd /root/webscan-deploy
docker compose -f /opt/webscan-central/webscan-v1/compose.yml logs --tail 50 grafana
```

自动生成的账号信息也保存在主服务器 `/var/lib/webscan-deploy/credentials.json`（0600）；旧版管理员默认为 `admin`，只读用户名见 YAML。密码不会重新随机生成。部署源代码、模板、README 不包含实际 Grafana 密码。首次安装的管理员密码通过文件挂载传入 Grafana，避免 `$`、`#` 和引号被 Compose 插值改变。

## 当前访问方式

默认映射 `0.0.0.0:3000:3000`，浏览器直接访问 `http://156.245.236.154:3000`。修改 `central.grafana.host_port` 可自定义宿主机端口；容器内部固定 3000。`bind_address` 支持 `0.0.0.0`、`127.0.0.1` 或主服务器 IP。

`grafana.public_url` 已取消，新 YAML 无需域名；旧 YAML 中该项会被忽略。仅修改 Grafana 端口或监听地址时执行下列命令，它保留其他服务、现有镜像和账号密码，只重新创建 Grafana 容器；失败会恢复原配置。内存检查只针对这次单独更新（至少 128 MiB 可用），首次部署的完整预算检查仍然保留。

```bash
bash deploy-webscan.sh --config webscan.yaml --upgrade --grafana-only --non-interactive
```

凭据更新等 API 调用也使用新的映射端口。脚本不会建立域名反代；以后自行配置反代和 Grafana 的外部 URL 即可。子服务器连接的事件入口始终是 `central.public_url` 的主服务器 **IP:HTTPS端口**，与 Grafana 端口、域名无关。

选择仅监听 `127.0.0.1` 时，可由本机反代访问，也可在 Mac 建立隧道（右侧端口替换为 `host_port`）：

```bash
ssh -i /Users/lizheng/.ssh/156.245.236.154_id_ed25519 -p 2222 \
  -L 13000:127.0.0.1:3000 root@156.245.236.154
```

保持连接，浏览器打开 `http://127.0.0.1:13000` 登录。

## 后续维护

### 批量忽略网站缓存目录

在主服务器 `webscan.yaml` 的 `node_defaults.monitor.exclude_paths` 下添加规则：

```yaml
node_defaults:
  monitor:
    exclude_paths:
      - '/www/wwwroot/*/runtime/cache'
      - '/www/wwwroot/*/storage/framework/views'
      # 如需任意深度的 cache 目录，使用下面这一条：
      # - '/www/wwwroot/**/cache'
```

`*` 匹配一层目录名，`**` 匹配零层或多层目录，`?` 匹配一个字符，也支持 `[0-9]` 等字符集合。规则区分大小写，匹配目录后自动排除其全部子目录和文件；普通绝对路径排除仍然支持。规则实时匹配，新建网站也适用，不需要重新生成网站列表。YAML 中的通配规则请加引号。

规则必须从监控根目录的固定路径开始，不能排除根目录本身或配置的 `critical_paths`。排除目录内的 PHP 也不再检测。节点自身的 `monitor.exclude_paths` 覆盖全局列表，公共规则需要一并写入。

在主服务器执行 `bash deploy-webscan.sh --config webscan.yaml --upgrade --non-interactive` 下发到全部启用节点；仅更新某节点可加 `--node node-28`。这次不使用 `--central-only` 或 `--grafana-only`。更新会重新执行节点部署和验收。

部署所需的完整程序、配置校验模板和 YARA 规则均内嵌在 `deploy-webscan.sh` 中，不依赖单独的源码目录或构建工具。历史报告、测试目录和临时部署包已清理。

备份源脚本/YAML后再上传新版本。凭据更新不改变运行程序版本；下一次程序部署使用 `--upgrade`。既有回退记录用于运行配置回退，**不回退 Grafana API 修改过的密码**，需要改回时重新设置 YAML 并执行凭据更新命令。

动态 PHP 缓存持续改写可能产生真实读文件/扫描竞态告警；现有文件基线是哈希清单，YARA 扫描的是变更文件。
