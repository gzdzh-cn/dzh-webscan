# v2.0.23 SSL 总开关验收记录

## 功能

SH 菜单增加“5、SSL 设置”，子菜单 0 返回、1 使用 SSL、2 不使用 SSL。也支持 `--set-ssl on/off`。只保存 YAML，不安装 Docker、不拉取镜像、不创建临时容器或切换生产服务；保存前校验配置和部署状态，使用原子替换及 0600 权限。已有部署必须完整升级，协议改变时拒绝仅主服务器、单节点、规则或 Grafana 的局部操作。

`ssl.enabled` 默认 true，兼容旧 YAML 和历史部署快照。false 统一启用 HTTP 事件入口、HTTP 节点指标及 HTTP 网站后台，原端口不变。HTTP 事件入口保留令牌、来源 IP 和内部接口隔离；指标沿用原有来源 IP 限制。Vector、Agent、Prometheus、exporter 和验收客户端同步移除 TLS 依赖。HTTP 新安装与 Compose 包不生成证书，旧证书保留，再开启 SSL 校验并复用原证书。

后台直接 HTTP 登录保留会话；宝塔 HTTPS 反代保留 Host 与 X-Forwarded-Proto 时使用 Secure Cookie。Origin、CSRF、退出注销和登录限流保持生效。Grafana、飞书 HTTPS、镜像仓库及被检测网站协议独立于此开关。

## 验证

- Go 全量测试、go vet、bootstrap/config/deploy/central/website 竞态检测通过；前端类型检查、6 项测试和 Vite 生产构建通过。
- 菜单返回、错误序号、严格 CLI 参数、旧配置默认开启、一个开关覆盖旧节点 TLS 参数、YAML 评论/权限保留及未完成部署禁止修改通过。
- SSL 模式切换的范围限制、HTTP Compose 包无证书、HTTP 指标读取、HTTPS 旧包兼容通过。
- Linux amd64 central + agent + 固定版 Vector 分别完成 HTTP 和 HTTPS 联调：真实 PHP 创建/修改/删除/移动、YARA、断网积压、进程重启、接收确认、规则热更新和模拟飞书/Loki 投递排空通过。HTTP 用时约 54 秒，HTTPS 约 54 秒；联调容器已删除。
- 独立 HTTP 面板及实际 HTTPS 反代测试通过：真实嵌入资源、直接登录、反代登录 Secure Cookie、会话、CSRF、跨站来源拦截、退出登录、内部接口不对外暴露、关键词连续失败告警及模拟队列排空，容器无重启。测试使用独立数据库及模拟飞书，不发送生产测试消息。
- central 和 agent 均已发布 v2.0.23 和 latest 两种标签，两种标签摘要一致；匿名下载全部镜像层、校验压缩摘要和解压摘要，并重新加载确认镜像身份一致。记录位于 dist/v2.0.23/release.json。
- 主服务器三文件部署包已同步，保留更新前备份。离线升级预览通过；同步前后部署状态及全部容器 ID 相同，未执行线上升级或改变 SSL 设置。临时发布 SSH 转发已关闭。

## 生效

同步主服务器三文件部署包后，默认仍开启 SSL，不切换线上服务。管理员执行脚本选择 5 保存 SSL 设置，再完整执行：

```bash
cd /root/webscan-deploy
bash deploy-webscan.sh --upgrade
```

切换需更新主服务器及全部启用节点。不要加 --central-only 或 --node。网站数据、事件历史、队列和账号保留；业务网站、Nginx 和云安全组不在本次改动范围内。宝塔反代由管理员配置，详见 README 的 SSL 说明。

本地验收日志与私有快照位于 .cache/ssl-v2.0.23/，不可公开上传。
