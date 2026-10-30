# v3.0.0 单中心正式发布回执

发布完成于 2026-10-30（Asia/Shanghai）。[GitHub Release](https://github.com/gzdzh-cn/dzh-webscan/releases/tag/v3.0.0) 已公开，非草稿、非预发布；中心及子控 `latest` 已核对与 `v3.0.0` 一致。本次未升级线上主控或 229，未迁移或删除旧主控保留数据。

## 固定源码和镜像

- 发布标签：`v3.0.0`
- 实际构建提交：`5756c2bcc02d48b0cb639c98fd216770e6340d14`
- 源码摘要：`64d6e4748d04a3ffc67ddcdbc1bbe6d929f9a5d35842478ce49bc8572003c36c`
- 平台：Linux amd64

| 镜像 | v3.0.0 与 latest 的公开仓库摘要 |
|---|---|
| `gzdzh/webscan-central` | `sha256:b81beb53ce998666444c13e08fb9b1dac498b46c6008a14921d2eae11bff221f` |
| `gzdzh/webscan-agent` | `sha256:59eac4d17bcf2209e8c3c87c7edbef162cb971672b7146a68bd47bca8a18482c` |

安装时使用 `仓库:v3.0.0@sha256:摘要`，不能只凭标签证明实际程序。镜像中的程序均显示 `v3.0.0`，OCI 标签绑定上述提交及源码摘要。

## 下载与验签

16 个发布附件已从公开下载地址重新下载，全部与本地核对一致；`SHA256SUMS.sig` 和 `release.sig` 均使用独立保存的原发布公钥验证。`release.json` 是部署签名清单，不是发布工具生成的本地汇总报告。

| 产物 | SHA256 |
|---|---|
| `webscan` | `0a48137300b98ab15a6fbb692704197ea1fdbfbe2d237af16f191fefb89553e2` |
| `agent-native.tar.gz` | `8f7dbac86192343f923550f2dc5b49561080fe018e337f01775933708e5a563e` |
| `agent-image.tar` | `0e4c0b5a04b20e827ed29f8ca9ee1a80225daa8a53ed30bbfa594d7032eb42cb` |
| 已签名 `release.json` | `b49514a115a7549708d5e1db83ba15c27cd9308afd2ff4941937c50bd7213b7f` |

公钥 DER SHA256：`0ea843c3994b7e904ee1061d5b8159420b90592a348453e7eb857097a8b859af`。先通过独立可信渠道确认公钥，再验清单签名和文件摘要。[正式安装入口](INSTALL-v3.0.0.md) 包含固定镜像请求与命令；不得使用旧 v2 菜单部署 v3。

## 最终正式产物验收

| 验证 | 结果 |
|---|---|
| 真实 Linux native 网页联合部署 | 217.85 秒，通过安装、升级、故障续作和回退 |
| 真实 Linux Docker 29 containerd 网页联合部署 | 477.19 秒，通过安装、升级、故障续作和回退 |
| 单中心实际 CLI、PG17、VictoriaMetrics、中心容器及宿主工作器 | 78.36 秒，通过安装和 overlay 升级；设置、Vault、事务备份、会话和数据保留 |
| 节点操作不重启中心 | 容器 ID、PID、启动时间、重启次数和原登录会话不变 |
| 事件与采集 | mTLS 实际文件事件入库并确认；单中心实际 VictoriaMetrics 覆盖指标写入 |
| 原始离线归档 | OCI 索引、Linux amd64 配置、层内容、完整摘要和签名均通过 |
| 前端与源码 | 类型检查、215 项测试、构建、Go 测试、相关竞争检查、真实 Chrome 桌面及手机页面通过 |

全部 13 项门禁绑定证据文件及摘要。单中心 systemd 激活采用模拟；真实节点 systemd／Docker 服务由独立 Linux 内核联合用例覆盖。网页联合测试指标写入端为模拟，实际时序库由单中心测试另行覆盖。未完成 HA、独立三机故障、万台容量认证及桌面／Android 客户端。

## 保留的失败证据

正式构建曾遇到 Debian 旧版本包不可用，保留错误并更新为明确的可用固定版本。首个本地标签导出的离线包被仓库名检查拒绝，已按正式仓库引用重新导出、完整校验和签名；未放宽身份检查。单中心 Linux volume 测试因不足 2 GiB 被保护检查拦截，改用空间充足的独立测试目录后通过。GitHub 匿名 API 曾返回 403，公开 Release 页面和全部附件实际下载验证均成功。

私有验收目录保存在 `.cache/verification/v3/release-v3.0.0/`，其中含私有测试配置，不作为发布附件上传。源码提交后的本次文档回执不改变既有标签、二进制或镜像。
