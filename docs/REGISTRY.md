# Docker Hub 镜像与加速配置

本项目自研镜像在 Docker Hub 公开发布。服务器拉取无需账号密码；实际配置文件可能含飞书及 SSH 凭据，仍应保持 `0600` 权限，不提交到源码仓库。

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

默认使用 `latest`。每次发布同时保留版本标签和 `latest`，两者摘要一致；需要指定历史版本时也可以填写版本号或真实摘要。主服务器镜像同时包含部署工具，无需独立 deployer 镜像。

SH 部署会锁定本次拉取的实际摘要，容器显示简短标签，恢复和回退使用已保存的锁定镜像。仓库更新 `latest` 不会自动升级运行容器，更新时执行 `bash deploy-webscan.sh --upgrade`。

第三方组件使用 Grafana、Loki、Prometheus、Alertmanager、Vector 和 node-exporter 的上游镜像及固定版本，列表见根目录 README。

## 可选加速

```yaml
registry:
  mirrors:
    - https://mirror.example.com
```

这是示例域名，要替换成自己的有效地址。支持多个 HTTPS 源地址，不包含路径、查询参数或账号密码；按顺序尝试，再回到 Docker Hub。`[]` 禁用。

SH 部署的加速配置用于第三方 Docker Hub 组件，自研镜像按 `registry.prefix` 直拉，不修改 Docker 全局设置。手动 Compose 直接使用生成的镜像引用，不执行 SH 的加速回退和 SSH 备用传输。

## 本地构建与发布

```bash
# 下一次发布的示例版本，实际完成构建和推送后才能部署
bash scripts/build-images.sh v2.0.21
bash scripts/publish-images.sh v2.0.21
```

公开仓库的推送仍需认证，发布专用 YAML 中填写 Docker Hub 用户名和具备写入权限的访问令牌，可作为脚本第二个参数传入。凭据不写入文档、镜像或普通日志。服务器使用公开匿名拉取配置，账号密码留空。

构建自动生成版本标签及 `latest`；发布先推送两个版本镜像，再更新两个 `latest`。发布摘要与标签记录在 `dist/版本号/release.json`。正式更新同步 SH、YAML 和 README。Compose 用法见 [安装教程](COMPOSE.md)。
