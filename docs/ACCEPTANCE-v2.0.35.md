# v2.0.35 验证与发布记录

[返回 README](../README.md) · [节点部署教程](NODE-DEPLOYMENT.md)

## 已完成的验证

| 范围 | 结果 |
|---|---|
| 前端 | TypeScript 检查、21 项测试、Vite 构建通过；真实页面确认新增 native 默认、旧节点 docker、待应用标记及部署表单 |
| Go | 全量 `go test ./...` 通过；Linux amd64 Agent 与采集器测试单独编译并运行，不能用 macOS 测试替代 |
| 主机采集 | PID 1 网卡／挂载、CPU／内存／磁盘累计计数、缺失值；实际中心镜像内部采集及 `/native-verify` 通过 |
| 安全采集接口 | 来源地址、IPv4 映射、路径／方法、缺失指标返回 503；HTTPS 可信客户端证书成功、缺少证书被拒绝 |
| 事件可靠性 | 部分确认、响应丢失 receipts、原 ID 去重、拒绝隔离、容量边界、暂停队列、旧 JSONL 幂等导入及单写入者锁通过 |
| YARA 实际扫描 | native 与 Docker 对仅含注释的规则样本均产生 matched 扫描事件；未执行 PHP |
| Native 真实运行 | 隔离 Debian/systemd 机器无 Docker，工具包清单与版本校验通过；内存 256 MiB、CPUQuota=100%、NOFILE=65536 实际生效 |
| Docker 真实运行 | 单个 Agent；实际内存 256 MiB、1 CPU 限制；宿主 proc/sys/root 指标及测试中心确认通过 |
| 备份失败 | 64 KiB 受限备份盘使一致性备份失败；无完成标记、原服务恢复；新版明确显示磁盘不足原因 |
| 中断与回退 | 备份完成前／后的检查点测试通过；回退不覆盖当前数据库，备份后的新增事件继续补传并归零 |
| 两种方式数据连续性 | 隔离运行方式 native → docker → native，31 个原 ID 全部保留，Docker 后 32 个事件、恢复后至少 32 个；通过 Linux 数据库校验 |
| 发布产物 | 两个镜像包含相同 native 包；外层 SHA256、包内 SHA256SUMS、程序版本、YARA 与 clamdscan 加载器验证通过 |

运行方式切换使用隔离数据库、相同路径和节点身份；部署控制器的顺序、完成标记、恢复及旧配置解析另由测试覆盖。Mac 不直接打开运行中的 Linux SQLite WAL。测试中心关闭飞书和邮件，不向业务群或真实邮箱发送测试告警。

尚需在用户手动生产升级时逐台完成真实 SSH、网络限制、业务目录覆盖和扫描验收。隔离系统没有现成 ClamAV 守护进程；验证了客户端和缺失服务检查，启用后的真实扫描需使用已有扫描服务。未对所有 Linux 发行版进行实机安装测试。

## Docker Hub 发布

v2.0.35 与 latest 已发布；匿名读取核对每个角色两标签摘要一致，manifest 的 config ID 与本地 Linux amd64 镜像一致。保留 v2.0.34 摘要记录用于回退。

| 镜像 | v2.0.35 / latest 摘要 |
|---|---|
| central | `sha256:e5fc2f2a3dabedc97884c1e0424cbfae72dd559fac525de03deabe6e9b6eed9f` |
| agent | `sha256:ccf640479942a64c32d0ee9bd86db7bc503b78bc0aa059f726330bdb43f5fef6` |

native 包发布于两个镜像内，供主服务器提取并通过 SSH 下发；本地 dist 同时提供 `agent-native.tar.gz`、`agent-native.sha256` 和 `release.json`。本次未创建新的 GitHub Release。

Native 包 SHA256：`7db3c1b0eaf562bd27a83758da633206910dfae3c35e7889d8527b2a352b189d`。

## 部署包同步与生产保护

主服务器仅更新 `deploy-webscan.sh` 与 README，三文件包中的实际 YAML 保留；旧包已保存到受保护的 package-backups。同步前后核对 YAML、凭据、运行配置与部署状态校验值、两个生产容器的 ID／镜像／启动时间、宿主管理服务 PID，全部一致。未切换生产容器，未修改业务网站、Nginx、防火墙或协议。

## 用户升级

```bash
webscan --upgrade
```

先升级中心，再逐台升级启用节点；旧 Docker 节点默认合并为单容器，新节点默认 native。之后可从后台选择 native 并应用。`--central-only` 只完成中心升级，不能完成本版本子服务器整合。失败按日志保持原版本、YAML 和范围使用 `--resume` 或 `--rollback`。
