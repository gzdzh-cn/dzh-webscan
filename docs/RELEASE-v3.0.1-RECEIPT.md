# v3.0.1 中心 UI 恢复正式发布回执

2026-10-30（Asia/Shanghai）完成。GitHub Release 已公开，非草稿、非预发布；17 个附件重新下载与签名复核通过，两个镜像 `latest` 与版本摘要一致。**本次未升级生产主控或子控，旧数据保留。**

## 源码与镜像

- 发布标签：`v3.0.1`
- 实际构建提交：`4ad9d79c6d4f021b768bb152c67fa7d898c40fbf`
- 源码摘要：`94fff29840d0d1049a19a94eba71fc9a87811c7cb2b82fbd25536a18906081a1`
- 平台：Linux amd64

| 镜像 | v3.0.1 与 latest 摘要 |
|---|---|
| `gzdzh/webscan-central` | `sha256:00a2226bd89313f143a7db6650142116ffbbe48bdec504b1b509fe338b7e8599` |
| `gzdzh/webscan-agent` | `sha256:4187cb0e982566aefadd8317bf079e22f04071e3796728a1596b3e0506a845aa` |

镜像内置本版程序，实际运行显示 `v3.0.1`；OCI 标签与构建回执绑定上述源码，未使用旧版或试运行包重新打标。

## 产物及验证

| 项目 | 结果 |
|---|---|
| 前端 | 类型检查、220 项测试、构建通过 |
| Go | 全量测试、相关安全与竞争检查通过 |
| native 网页联合生命周期 | 253.28 秒，真实 Linux、SSH、systemd、mTLS；安装／升级／中断续作／回退通过 |
| Docker 29 网页联合生命周期 | 522.26 秒，真实 Linux、containerd；安装／升级／中断续作／回退通过 |
| 单中心安装及 overlay 升级 | 89.67 秒，实际 PostgreSQL 17、VictoriaMetrics、共享 Vault、设置及会话保留通过 |
| 普通节点操作 | 中心容器 ID、进程、启动时间和登录保持不变 |
| UI 对照 | 24 组状态、48 张桌面／手机成对图及真实 Chrome 行为验收 |
| 发布信任 | 原始离线 OCI 包、实际配置摘要、清单签名、文件摘要及公开下载复核通过 |

全部 13 项门禁使用本版证据，生命周期未继承旧版结果。网页联合测试指标写入端模拟，实际 VictoriaMetrics 由单中心测试覆盖。单中心使用 Linux 临时卷、systemd 激活模拟，不代表宿主机断电恢复认证；真实节点服务管理由独立内核联合用例覆盖。高可用和万台认证不在本补丁范围。

## 关键文件 SHA256

- `webscan`：`41ee1e1801aeac3a67f727c91e9043ec1471640bbc13eca6c7538df923165bce`
- `agent-native.tar.gz`：`75254ec13203b3d9381c697f448dd7b8a49e3e534e217406cf50fc23e8e2541f`
- `agent-image.tar`：`8672729d8603d1aff9afaf5bf98f069e52fe530a4499d094d3b9d7734d094cc3`
- `release.json`：`1803e4944fbabdee3a3400481582aabc49f248fc79bf45730dca99be5984bbc7`

发布公钥 DER SHA256：`0ea843c3994b7e904ee1061d5b8159420b90592a348453e7eb857097a8b859af`。先通过独立渠道确认公钥，再验 `SHA256SUMS.sig` 和 `release.sig`。

## 边界与安装

[发布页面](https://github.com/gzdzh-cn/dzh-webscan/releases/tag/v3.0.1) · [本版安装与维护](INSTALL-v3.0.1.md) · [UI 恢复、对照图及实际差异](V3-UI-RESTORATION.md)。

主要页面恢复 v2.0.46 结构与交互，继续使用 `/api/v3`。改密、卸载、设备级历史曲线及公共文件规则编辑等尚无 v3 接口的功能保持禁用／未提供；不宣称完整旧版功能等价。

发布只交付源码、镜像和签名产物。生产上线、子控升级及旧主控数据迁移另行执行。

本次保留直连下载超时、Docker 引擎仓库连接超时、macOS 共享目录 PostgreSQL 初始化及初版离线包配置摘要的失败证据；改用现有代理、Linux 隔离卷及实际归档配置摘要后全部复核通过。未关闭 TLS、摘要、权限或发布门禁。
