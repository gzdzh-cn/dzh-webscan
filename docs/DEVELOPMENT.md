# 目录结构与本地开发

[返回 README](../README.md) · [SH 安装](INSTALLATION.md) · [网站后台](WEBSITE.md) · [日常维护](OPERATIONS.md)

## 目录、源码与本地构建

### 服务器目录

| 所在服务器 | 默认目录 | 用途 |
|---|---|---|
| 主服务器 | `/root/webscan-deploy` | 三文件部署包 |
| 主服务器 | `/opt/webscan-central/webscan-v1` | 运行配置、Compose 和证书，由 `central.install_dir` 决定 |
| 主服务器 | `/var/lib/webscan-central` | 事件数据库及监控组件数据，由 `central.data_dir` 决定 |
| 主服务器 | `/var/backups/webscan` | 日常备份，由 `central.backup_dir` 决定 |
| 主服务器及子服务器 | `/var/lib/webscan-deploy` | 各自的部署／维护备份和回退记录；主服务器另存状态、凭据及部署日志 |
| 子服务器 | `/etc/webscan-v1` | 运行配置、扫描规则和证书 |
| 子服务器 | `/opt/webscan-go` | 编译后的工具及服务辅助文件 |
| 子服务器 | `/var/lib/webscan-v1` | 清单、事件、扫描队列和健康状态 |
| 子服务器 | `/var/log/webscan-v1` | 用于传输的事件日志 |
| 子服务器 | `/var/lib/webscan-vector-v1` | Vector 断网缓冲 |

`install_dir` 和 `data_dir` 仍然有效，分别决定主服务器运行文件和数据的位置，不是部署包目录。已有部署不宜随意修改，需要另外处理路径迁移。

### 本地源码及构建

| 路径 | 负责什么 |
|---|---|
| `internal/common/policy.go` | 后缀、忽略路径和重要文件的过滤判断 |
| `internal/agent` | 子服务器监听、清单核对、扫描和事件导出 |
| `internal/central/central.go` | 主服务器事件接收和投递队列 |
| `internal/central/notice.go` | 飞书中文通知内容 |
| `internal/deploy` | 安装、更新、热加载、卸载和回退 |
| `cmd/bootstrap` | SH 内嵌程序和菜单 |
| `cmd/compose` | 本地 Compose 配置生成、离线检查和参数帮助 |
| `internal/config` | YAML 字段、类型、取值校验和参数诊断 |
| `internal/progress` | 部署阶段日志、中文错误解释及凭据脱敏 |
| `scripts` | 本地打包、构建和发布工具 |

本地构建需要 Go **1.26.3**、Node.js **24 LTS**（至少 24.14.1）、npm 和 Docker。前端使用 Vue 3 + Vite + TypeScript + Element Plus；构建工具自动安装锁定依赖、检查类型、运行前端测试并生成页面，再嵌入 Go 程序。使用新发布版本号，例如：

```bash
# 将版本号替换成尚未发布的新版本，不覆盖已发布标签
VERSION=vX.Y.Z
bash scripts/build-images.sh "$VERSION"
bash scripts/publish-images.sh "$VERSION"
```

构建和推送在本地执行，只发布 central 和 agent。发布工具从指定 YAML 读取仓库及推送凭据，公开仓库也需用户名和访问令牌。可把发布专用配置路径作为第二个参数传入两个脚本，服务器公开拉取配置继续留空凭据。

构建命令自动生成 `webscan-central:版本号`、`webscan-agent:版本号` 及对应的 `latest` 标签；发布命令先推送两个版本标签，再更新两个 `latest`，并校验摘要一致。以后发布新版本时，YAML 可以继续使用 `latest`。

基础镜像及依赖锁定在 `config/base-images.lock`、`go.mod` 和 `go.sum`。生成的脚本和发布摘要在 `dist/版本号/`。正式部署同步 SH、YAML 及 README；只替换部署包不会自动升级运行服务。更新后的 `latest` 部署工具可以由已有的新版 SH 引导，不要求两者的小版本号相同。

配套说明见 [参数填写与报错](PARAMETERS.md)、[Grafana 查看与查询](GRAFANA.md)、[Compose 手动部署](COMPOSE.md) 和 [镜像仓库说明](REGISTRY.md)。本地历史验收记录只说明当时的结果，当前使用方式以[README](../README.md) 和实际代码为准。

## Vue 本地开发与发布

本地需要 Go 1.26.3、Node.js 24 LTS、npm；构建镜像还需要 Docker。

```bash
cd web
npm ci
npm run typecheck
npm test
npm run build
```

Vite 将产物写到 `internal/website/ui`，Go `embed` 将资源打入程序；生产容器不安装 Node.js、不启动 Vite、不依赖外部 CDN。源码保留开发占位页面，纯 Go 开发可直接编译，但正式发布必须构建真实页面。

开发时运行 Go central 服务，启用网站后台 HTTPS 19444，再在 `web` 执行 `npm run dev`。Vite 将 `/api` 代理到 `https://127.0.0.1:19444`；仅本地代理忽略本地开发证书校验并转换 Origin，生产浏览器请求仍校验来源及 CSRF。本地使用 `http://127.0.0.1:5173`。

```bash
# 使用尚未发布的新版本；发布配置不要提交源码
VERSION=vX.Y.Z
bash scripts/build-images.sh "$VERSION"
bash scripts/publish-images.sh "$VERSION" /安全位置/publish.yaml
```

构建工具依次安装锁定前端依赖、检查类型、运行测试、构建页面、测试 Go、编译 Linux amd64 并构建镜像。任何一步失败停止发布。发布同时更新版本和 latest；生产容器不会自动升级。

Dockerfile 源码构建入口也要求先执行 `npm run build`，拒绝只有占位页面的镜像。页面由 GoFrame 提供，Vue 路由刷新不影响 API，带哈希资源长期缓存，入口页面不长期缓存。

## GitHub 一行安装发布附件

镜像发布完成、部署脚本复制到根目录并提交源码后执行：

```bash
bash scripts/package-install.sh "$VERSION" "$(git rev-parse HEAD)"
```

向对应 GitHub Release 上传 `install.sh`、`deploy-webscan.sh`、`install-manifest.txt` 和 `release.json`。清单包含发布版本、源码提交、脚本及示例 YAML 的 SHA256；示例从该提交的仓库下载，不发布实际 `webscan.yaml`。验证匿名下载及文件一致后将 Release 设为最新。
