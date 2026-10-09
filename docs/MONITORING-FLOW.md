# 部署后的监控执行顺序

[返回 README](../README.md)

监控链路与部署顺序已整理到[架构与逻辑执行顺序](ARCHITECTURE.md)，包含：

- 主、子服务器启动与文件变化检测、扫描、传输、通知。
- 节点健康指标、飞书及 Loki 链路自检。
- 网站后台、首页检测和证书告警。
- 完整安装、增加节点及规则热更新。

操作命令分别见 [SH 安装](INSTALLATION.md)、[日常维护](OPERATIONS.md) 和[文件监控规则](MONITOR-RULES.md)。
