# v3.0.0 正式发布验收（2026-10-30）

状态：两项阻塞的本地实现与隔离验收已完成，进入正式构建和产物复核。用户已授权在 `main` 提交、推送并发布。**本记录不证明正式产物已发布，本轮不升级线上主控或 229。** 原版页面、删除保护及旧主控保留数据继续保留。实际发布状态、源码提交与镜像摘要以发布回执为准。

## 两项阻塞的实现

- 运行设置：API 与宿主共用原 Vault。API 只读挂载必要密钥和签名元数据，不挂载 CA 私钥、Docker socket 或宿主程序。`external` 模式禁止 API 重复启动执行器；省略模式沿用旧行为。预览不保存，保存／应用与加密编辑前备份在同一事务提交，密钥或备份错误停止。
- 网页部署：管理员通过 HTTPS、CSRF、幂等键提交；先读取并确认 SSH 指纹，再由持久化宿主工作器准备证书、规则和配置包。预览确认仍返回准备回执，获取真实任务 ID 后进入日志。独立升级只读取已保存配置；未完成任务显示原任务入口，继续／回退核对计划及游标。
- 凭据支持密码、未加密私钥内容和受控宿主路径。浏览器保留拖入、文件选择及粘贴，64 KiB 限制，文件读取完成前不能提交。敏感输入加密保存于限时准备记录，不进入配置、任务日志或审计；指纹改变停止。
- 能力接口核对签名、密钥、新鲜执行器心跳、签发器和规则实际状态。开关开启不能单独证明可用。准备明确失败后允许新请求重试；网络响应丢失时保留原幂等键。

接口及权限见 [网页部署与凭据](V3-WEB-DEPLOYMENT.md) 和 `api/control/v3/openapi.yaml`。

## 安装、升级与版本显示

- 新安装 format 3 使用真正内置 v3 主控的镜像；启动前核对镜像中的程序与签名程序字节一致。独立宿主执行器持有部署权限，Vault 只在全新安装生成一次。
- 升级准备生成独立 overlay，保留原 Vault、旧密钥列表、数据库和不可变安装记录；不因读取不到密文而换密钥。预览、准备均不自动切换服务，维护步骤见 [单中心安装与升级](V3-SINGLE-INSTALL.md)。
- 镜像使用 `仓库:v3.0.0@sha256:摘要`，保留 OCI 版本、源码提交及源码摘要标签。Docker 29 校验同时绑定镜像索引、实际平台镜像及 Linux amd64，不能只比较标签。
- 旧 format 1／2 任务保持原续作资料，不改写其不可变记录。不得把 pilot 镜像重新打标当作正式版。

## 已有验证证据

证据位于本机 `.cache/verification/v3/formal-web-20261030/`，不随发布上传私有测试目录。测试只连接隔离 PostgreSQL、SQLite、模拟通知及测试 SSH，不发送业务通知。

| 验证 | 结果与边界 |
|---|---|
| `go test ./... -count=1` | 全量通过；controlplane 1163 秒、nodeops 337 秒。之后改动另跑定向检查 |
| 变更相关 `-race` | 设置、网页部署、安装／升级模板、镜像身份及发布门禁通过（20.7 秒）；见 `changed-race-final.log` |
| SSH 中断／续作／回退 | 真实 SSH、PG 和远端 SQLite 通过；服务阶段及采集就绪为显式测试替身，不能当成真实内核联合部署 |
| 名称变更／旧名称裁剪 | 真实 mTLS、竞争检查重复 30 次通过，见 `pki-mtls-final.log` |
| 前端 | 类型检查、25 个测试文件／215 项测试、构建通过；移除过时的“部署维护使用受控命令”常驻提示后重新通过，见 `frontend-recheck.log` |
| native 内核 | 完整隔离 x86 Linux、systemd 和资源控制的安装、升级、回退及未确认事件保留通过，见 `kernel-native-run.log` |
| native 网页联合部署 | 真实主控 API 容器、HTTPS、PG、持久化准备工作器、固定 SSH、systemd 服务和 mTLS 采集通过（310.66 秒）；覆盖安装、升级、实际备份响应丢失后的续作及回退。主控容器 ID／PID／启动时间／重启次数不变，会话保留，见 `web-native-kernel-container.log`；指标写入端明确模拟 |
| Docker 29 网页联合部署 | 同一真实主控容器链路通过（902.03 秒），含 Docker 29 containerd、可读版本标签、全新安装、升级、中断续作、回退和 mTLS 事件落库；主控容器身份及登录不变，见 `web-docker-kernel-container.log`。首次 verify／finalize 实际各耗时约 81 秒，保留完整校验后在有界时限内成功；指标写入端明确模拟 |
| Docker 29 内核 | 最新完整复核通过（767.16 秒），见 `kernel-docker29-stream-run.log`：真实 x86 Linux、Docker 29 containerd，全新安装和升级最终确认、全部已完成阶段重放、进程／cgroup 资源限制、mTLS 就绪、响应丢失核对、真实资源限制漂移、原容器 ID 回退及回退后未确认事件保留；隔离 VM 正常退出。此前 22 分钟超时证据仍保留，见下文 |
| format 3 全新单中心 | 实际 CLI、PG17、VictoriaMetrics、镜像内置主控、独立宿主工作器、HTTP 登录和设置保存／应用通过；见 `single-stack-baseline-pass.log` |
| 主控维护与采集 | 上述安装中真实 mTLS 重认证、签名 CRL 分发、两条事件落库确认通过；中心容器、进程及会话保持不变。systemd 激活显式模拟，不证明宿主机重启 |
| 升级 overlay 实际应用 | 已通过（10.58 秒），见 `single-existing-upgrade-final.log`：旧 pilot 挂载程序切换到内置当前程序的本地测试镜像，中心容器替换，PG／时序容器、旧安装资料、Vault、设置、两份加密备份及会话保留，新执行器实际就绪；systemd 显式模拟 |
| 真实浏览器 | 本地 UI 已通过。人工处理测试证书后，用真实 Chrome 验证登录／退出、Docker 默认值、390×844 弹窗滚动及固定反馈、私钥文件换行与超限保留、执行器不可用错误、事件手动查询、运行设置预览／保存／应用；最新构建另行复核并保存截图，见 `browser-recheck/preliminary-result.json`、`browser-final/result.json`。此测试不替代真实部署或签名发布产物复核 |
| 最新定向检查 | 归档流式修改后 nodeops 完整包通过（337.87 秒），此前 release 包通过（0.7 秒），`go vet` 通过；归档流式验证和 SSH 阶段时限竞争检查通过，见 `archive-stream-package.log`、`archive-changed-packages-recheck.log`、`go-vet-final.log`、`archive-stream-race.log`、`node-phase-budget-race.log` |

当前源码 Docker 29 离线包复核发现了嵌套 OCI 索引兼容缺口，已修复：逐层验证元数据摘要，限制深度和子项，要求唯一 Linux amd64 运行清单，匹配已签名配置和层；只跳过明确标记的构建证明，仍校验其 blob 摘要。真实 Docker-save 归档和篡改／重复／错误平台等反例通过，见 `nested-oci-recheck.log`、`node-image-race-final.log`；最终相关 nodeops、release、API 包测试通过，见 `final-changed-packages.log`。

首轮网页内核联合测试在 `finalize` 返回 `remote-unavailable`，第二轮在 `verify` 的 75 秒时限退出，见 `web-docker-kernel.log`、`web-docker-kernel-recheck.log`，失败证据保留。早期独立内核用例也曾在 22 分钟超时，堆栈停在归档重复校验，见 `kernel-docker29-nested-run.log`。现将归档读取、完整摘要校验和元数据／层验证合并为同一次流式读取，不缓存或跳过校验；新增有效层内容篡改、合法零填充变化及取消反例，竞争检查通过。生命周期运行校验、最终确认及回退校验需要重查完整签名归档和实际进程，SSH 时限与 staging 一致为最多 6 分钟；普通预检查仍为 75 秒。最新真实网页联合复测和独立完整生命周期重放均已通过，见上表。

macOS 共享目录上的 PG 初始化曾出现所有权瞬时不一致而失败，失败日志保留在独立测试目录；安装器没有跳过权限、磁盘或数据库检查。浏览器临时数据库随后遇到 Docker 本地磁盘不足，改用仅存测试数据的独立 tmpfs PostgreSQL，不修改生产或清理其他项目。新增 `web-native`／`web-docker` 完整内核验证模式：真实只读主控 API 容器、HTTPS 反代、持久化准备工作器、固定指纹 SSH、实际 systemd／Docker 服务、mTLS 采集及 PostgreSQL；两种网页链路现已通过。指标写入端明确模拟，VictoriaMetrics 另由实际单中心测试覆盖。

## 仍需完成的发布门禁

1. 将本轮源码在 `main` 提交、推送；正式发布必须绑定真实源码提交及相同构建／验收摘要。本次由用户授权代理执行 Git 操作。
2. 从实际 `Dockerfile.release` 构建正式中心和子控，完成最终签名发布产物对应的联合复核。本地桌面和手机浏览器、两种网页联合链路及 Docker 29 独立完整生命周期已通过。已有安装 overlay 的隔离容器应用已通过，真实宿主开机恢复仍不能由模拟 systemd 证明。
3. 签名、核对仓库摘要及下载产物，完成 Release 附件检查后再更新 `latest`。本机 Docker 存储目前空间不足，正式构建前还需核对可用空间；仅清理可确认归属的临时构建资源，不全局清理或重置 Docker。

## 发布工具保护

本地构建不创建 `latest`。构建回执绑定程序、native 包、安装入口、源码提交和源码摘要。`stage` 仅上传版本镜像，也要求干净且已推送的真实提交及全部验收记录；`publish` 额外核对签名、程序／native 包和镜像身份。缺失门禁、替换证据、不同源码或不同构建均拒绝发布。

验收 JSON 必须包含 `settings`、`security`、`native-lifecycle`、`docker29-lifecycle`、`web-deployment-native`、`web-deployment-docker29`、`collection`、`unchanged-central`、`frontend`、`go-race`、`browser`、`single-install`、`single-upgrade`，每项绑定实际证据文件及 SHA256。网页联合门禁不能由分层接口或内核测试代替。尚未通过的门禁不得生成 `passed: true`。

高可用、独立三机故障和万台容量认证不在本次单中心首发的已验收范围内。正式发布不自动执行生产升级。
