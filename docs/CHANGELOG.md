# 版本更新说明

[返回 README](../README.md) · [SH 安装教程](INSTALLATION.md) · [日常维护](OPERATIONS.md)

## v2.0.30

[GitHub Release 与下载附件](https://github.com/gzdzh-cn/dzh-webscan/releases/tag/v2.0.30)

本次完善 SH 安装和维护入口：

| 新增功能 | 使用方式 |
|---|---|
| 一行安装 | 下载 `install.sh`，自动创建 `/root/webscan-deploy`，固定版本下载并核对脚本和示例 YAML 的 SHA256 |
| 首次配置向导 | 依次填写主服务器、SSL、管理入口、飞书、多目录和可选子服务器；脱敏摘要确认后保存 |
| 全局管理命令 | 宿主机 root 输入 `webscan` 打开菜单；升级、节点操作与恢复参数原样传递 |
| 重复执行保护 | 保留已有 YAML；有新版脚本时备份后更新，同版跳过重复下载，不自动降级或升级容器 |
| 无节点安装 | 支持 `nodes: []`、`deployment.node_order: []`，先使用主服务器和网站后台 |
| 交互新增节点 | 菜单 **4 → N** 录入并保存节点，随后直接安装所选节点及验收 |
| 权限与任务保护 | 目录和脚本 0700、配置 0600；拒绝不安全路径，锁定并发操作，未完成任务保留原版本及范围 |

### 首次使用

在 Linux amd64 主服务器的 root SSH 交互终端执行：

```bash
bash -o pipefail -c 'curl -fsSL https://github.com/gzdzh-cn/dzh-webscan/releases/latest/download/install.sh | bash'
```

填写向导并保存，进入菜单选择 **1、安装**。首次向导已选 SSL 时，紧接着安装不重复询问。安装成功后按终端提示访问网站后台及 Grafana，并保存初始有效账号凭据。

### 已安装用户

已有配置会保留，不再重复初始化。再次执行一行命令可更新入口；完成后在任意目录输入：

```bash
webscan
```

选择菜单安装、升级或重装才会应用运行配置及目标镜像。单纯下载新脚本、同步部署包、发布镜像或更新 `latest` 都不会自动切换生产容器。已有任务尚未完成时，先按原版本及范围恢复，禁止重置配置。

菜单 1 和 2 继续保留 SSL 引导；菜单 5 选择协议后直接完成主服务器及全部启用节点的完整部署。协议切换不能仅升级主服务器。

### 详细说明

- [配置向导与文件权限](INSTALLATION.md#首次配置向导)
- [第二次执行与配置丢失处理](INSTALLATION.md#再次执行安装命令)
- [全局命令及 PATH 设置](INSTALLATION.md#全局-webscan-命令)
- [先安装主服务器](INSTALLATION.md#不添加子服务器也能安装)
- [交互新增节点](OPERATIONS.md#增加或更新单个节点)
- [下载、终端、锁及名称冲突排查](TROUBLESHOOTING.md#安装入口与全局命令)
- [v2.0.30 验收记录](ACCEPTANCE-v2.0.30.md)

发布提供 Docker Hub `v2.0.30` 及 `latest` 标签，以及 GitHub 的 `install.sh`、`deploy-webscan.sh`、`install-manifest.txt` 和 `release.json`。实际 `webscan.yaml` 含个人配置，不作为公开附件。
