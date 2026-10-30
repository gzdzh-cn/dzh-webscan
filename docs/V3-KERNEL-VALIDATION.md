# v3 真实内核、systemd 与 Docker 验收

此工具仅用于本地隔离验证，不属于安装器或发布镜像。ARM Docker Desktop 中的 amd64 容器通过 Rosetta 执行，不能用来证明严格的 `/proc/<pid>/exe` 归属；本工具使用原生 ARM QEMU TCG 启动完整 x86_64 Debian 内核，保留产品的严格归属校验。

## 准备与运行

需要 ARM64 Docker 环境、Go、Bash、ripgrep，以及足够的临时磁盘空间。各内核模式应串行运行，避免多个完整虚拟机争抢 Docker Desktop 的内存；每个 QEMU 验收容器上限为 4 GiB，guest 内存仍为 1536 MiB。容器上限还需容纳 QEMU 翻译缓存及虚拟磁盘缓存，不能只按 guest RAM 估算。若复用此前缓存的 `webscan-v3-systemd-validation:local`，须先核对其原隔离工具镜像 ID：

```text
sha256:7f15a88821bd3ca458e3d668fe7f399404d15756e3162d20fa221c187ff3582f
```

缓存缺失时，先使用 `scripts/Dockerfile.v3-systemd-validator` 从固定 Agent 摘要重建，另存新镜像 ID、构建日志和实际包清单。重建后的 ID 可以变化，不能将它冒充此前缓存或可复现发行构建。

```bash
docker image inspect webscan-v3-systemd-validation:local --format '{{.Id}}'
docker build --platform linux/amd64 -f scripts/Dockerfile.v3-kernel-guest -t webscan-v3-kernel-guest:local .
docker build --platform linux/arm64 -f scripts/Dockerfile.v3-kernel-tools -t webscan-v3-kernel-tools:local .
bash scripts/verify-v3-kernel-lifecycle.sh
```

Docker 方式另需构建专用虚拟机镜像，再明确选择 `docker`：

```bash
docker build --platform linux/amd64 -f scripts/Dockerfile.v3-docker-kernel-guest -t webscan-v3-docker-kernel-guest:local .
bash scripts/verify-v3-kernel-lifecycle.sh docker

# 同一个隔离内核中验证两种运行方式之间的切换及恢复。
bash scripts/verify-v3-kernel-lifecycle.sh transition

# 固定模板旧 sidecar 的实际活动服务停用与按原 ID 恢复。
bash scripts/verify-v3-kernel-lifecycle.sh sidecars

# 已发布 v2.0.34 Agent 与两个活动包装 sidecar 的整组迁移和回退。
bash scripts/verify-v3-kernel-lifecycle.sh legacy-group

# 同一份 Compose 启动的实际旧三容器；无旧包装服务。
bash scripts/verify-v3-kernel-lifecycle.sh pure-compose
```

默认参数仍为 `native`。Docker 工具来自固定的官方 amd64 子清单 `docker.io/library/docker@sha256:f649ef046008ca7f926a2571c32b0ac22e5c59eb61b959617f9acc2a4c638cf5`；不能用已缓存的 ARM 引擎替代。该隔离工具当前为 Docker 27.5.1、Compose 2.33.0、runc 1.2.4，运行时另存实际版本。虚拟机内部自行启动引擎，使用 vfs、systemd cgroup、宿主网络模式下的 loopback，不连接 Docker Desktop 的 socket，不访问镜像仓库或业务网络。

工作盘空间不足时，可将 `WEBSCAN_V3_KERNEL_OUTPUT_ROOT` 设为已创建的绝对目录；它不能是符号链接，推荐权限 0700。脚本只在其中新建私有的 `kernel-lifecycle.*` 子目录，不移动或删除已有证据。运行结束打印实际证据路径；这仅改变本地验收文件位置，不涉及产品数据目录。

内核、systemd 和 QEMU 主包指定版本，依赖由发行版签名仓库解析；每次运行保存实际包清单、镜像 ID、输入 SHA256 和串口日志，不能将未锁定的依赖描述成可复现发布构建。首次构建需要访问 Debian／Alpine 仓库。内核工具镜像和已有业务容器彼此独立，不清理其他镜像或卷。

## 验收内容

`TestNativeSystemdKernelLifecycleRetainsUnconfirmedEvents` 和 `TestNativeSystemdKernelUpgradeRestoresOriginalAndRetainsEvents` 要求专用标记、root、真实 systemd PID 1、完整虚拟机模式、仅 loopback 网卡，以及不存在任何旧 Agent 安装。它们使用当前静态 Go 程序、实际扫描工具包、SQLite、生成的 systemd 单元和双向 TLS：

- 执行只读检查、准备、备份、激活、验证和完成阶段。
- 核对真实进程、systemd 属性、cgroup CPU／内存和文件句柄限制。
- 临时移除本测试 Agent 的内核 CPU 配额，验证不能仅凭 systemd 配置判定健康；恢复配额后重新核对。
- 重开持久化 Journal 并复查完成阶段，要求 Agent PID 保持不变。
- 创建真实监控文件事件，回退时导出当前未确认事件，保留原 ID、当前 SQLite 和可重试记录，确认进程与写锁已退出。
- 第二项先安装一个真实 v3 native Agent，再以新任务执行升级、验证和完成；回退恢复原安装指针及服务，保留升级后产生的未确认事件。这不代表已验证发布版 v2 Agent 的迁移。

没有服务管理器、进程或内核文件替身；命令观察器记录实际 `systemctl` 返回值，不替换结果。测试日志写入虚拟磁盘，关机后通过只读 debugfs 提取；两项用例通过且有 `WEBSCAN_V3_GUEST_TEST_EXIT=0` 才算通过。缺少标记、超时或用例跳过均不算通过。

Docker 模式只运行 `TestDockerKernelLifecycleFinalizesAndRetainsEvents`，同样要求完整 systemd、仅 loopback 和空的专用引擎。它使用当前静态 Go 程序和工具包，执行真实 Compose 创建、完整安装及已有 v3 Docker 安装的升级；测试目标包括完成阶段、实际内核资源限制、mTLS 与目录覆盖、启动响应丢失后的无重启续作、资源漂移拒绝，以及恢复原容器 ID／指针并保留升级后未确认事件。只有该测试通过且退出标记为 0，才算 Docker 内核验收通过；此处是用例要求，实际运行结果见 [验证记录](V3-VALIDATION.md)。

`transition` 模式运行 `TestKernelNativeDockerTransitionsRetainCurrentData`，分别从全新 v3 native 和 Docker 安装出发，切到另一种方式并回退。两个子场景均须通过，且具有退出标记 0。它核对真实 `/proc` 中仅一个 Agent 写入进程、配置版本变更、内核资源检查、YARA 自检和 mTLS，模拟真实启动成功后响应丢失，再重开 Journal 续作；切换前后产生的事件须由恢复后的原 Agent 按相同 ID 继续读取。就绪只接受本次等待开始后采集的最新样本，不能使用保留的历史样本；恢复后再次核对实际进程和 CPU／内存／句柄限制。它不替代发布版 v2 三容器或中心联合验收。

`sidecars` 模式运行 `TestKernelActiveLegacyWrappersRetainOriginalContainers`，使用固定摘要的原 Vector／node-exporter 镜像，以及精确 v2 systemd 包装模板。引擎自身也由真实 systemd 服务启动，原 `ExecStartPre`、挂载和运行参数均实际执行；Docker 客户端安装在模板要求的 `/usr/bin/docker`，不修改产品进程归属校验。分别验证活动、启用的原服务捕获、停用、禁用、按原容器 ID 恢复，以及下一任务的来源核对；完成恢复的重放不能更换附着客户端 PID 或重建厂商容器。

该模式没有启动旧 Agent，`runtime.json` 只含私有归属身份；Vector 使用空文件源和 blackhole 输出，不配置推送中心或通知。它是活动包装组件的实际管理验收，不能声称已完成 v2 三容器整组数据迁移。两项厂商子场景及主测试通过且退出标记为 0 才算通过；实际结果见验证记录。

`legacy-group` 模式运行 `TestKernelLegacyAgentAndWrappersMigrateAndRollback`，导入固定摘要的正式 v2.0.34 Agent，先核对原镜像的实际版本。旧 Agent 由真实 Compose 启动，Vector／node-exporter 由精确旧 systemd 包装模板管理，三者在同一独立内核与 Docker 中运行。Vector 读取实际旧 JSONL，但输出到 blackhole，不连接业务中心。

两个目标方式分别从干净环境开始，执行整组预检查、捕获、全部停写、一致性 SQLite／JSONL 备份、实际 v3 激活、mTLS／新采样／YARA 检查及完成。旧文件事件必须以原 ID 被新 Agent 读取；新事件产生后，重开 Journal 回退，恢复原三个容器 ID 与原启用状态，核对当前数据库及旧格式 JSONL 保留切换前后事件。恢复后的正式旧 Agent 还须生成并导出另一条真实事件；完成回退的只读重放不能改变原进程 PID。

该模式不包含无包装的纯 Compose 活动 sidecar，也不验证旧 Vector 远程推送成功或中心最终切换。两个目标子场景及主用例必须通过，且虚拟机／宿主完整运行均成功；实际结果与失败诊断见验证记录。测试夹具本身不构成通过证据。

`pure-compose` 模式运行 `TestKernelPureComposeGroupMigrateAndRollback`，使用同一正式 v2.0.34 Agent 和固定摘要的厂商镜像，三者均由真实 Compose 启动；不创建旧 systemd 包装单元。分别切换到 v3 native／Docker 并回退，沿用基线、SQLite、JSONL、新旧事件原 ID、新采样、资源限制和实际恢复进程的完整检查。后续增强用例在首轮 v3 完成后再次执行同方式完整生命周期，使用同一份本地编译程序、配置版本 2 和新的任务身份，产生新文件事件，再回退到精确前驱指针，最后回退至原三容器。它同时检查历史 Agent 重启策略漂移会被拒绝、原 sidecar 不可变 ID、当前数据库及三个阶段事件 ID；不会用旧快照覆盖当前库。这验证同一构建的连续服务替换，不等于跨正式发行版本升级。初轮只捕获后继任务的旧结果与增强用例的实际通过情况分别记录，不能混同。

三容器独立保留原重启策略和运行状态；native 激活后旧 Compose 定义已退役，仅本任务绑定的捕获、快照和 native 激活意图允许该文件缺失，原 Agent 也必须保持停用及其捕获的退役名称。未知变化仍拒绝。损坏的新配置不作为旧组件归属证明的依赖，避免因此阻断回退。此模式仍将 Vector 输出送往 blackhole，不验证业务中心推送。

该模式的两个目标子场景、主测试及虚拟机／宿主退出均须成功，实际完成情况见验证记录；增加入口或用例本身不等于验收通过。

## 隔离与证据边界

QEMU 无外部网卡、共享目录或对外端口；只挂载虚拟磁盘，测试密钥为临时生成。基础生命周期模式不启用 SSH；下述网页联合模式只在 guest loopback 启用测试 SSH。外层容器不使用特权模式或宿主 Docker socket。运行结束按精确名称移除自建容器，私有证据目录保留在 `.cache/verification/v3/kernel-lifecycle.*`，包含可供排查的虚拟磁盘；该磁盘含临时测试身份，仍按私有资料保管。

完成磁盘准备及输入摘要后删除临时解包目录与 rootfs tar，保留虚拟磁盘、镜像 ID、摘要和日志，减少重复验收占用空间。Docker 模式额外保存引擎、镜像加载和 daemon 日志。虚拟机运行期间的磁盘内容并非一致性证据，最终日志在关机后提取。

这是虚拟化 x86_64 内核下的本地生命周期验收，覆盖范围按上述各模式实际结果记录；不代表物理机、真实中心联合切换、万台容量、72 小时稳定性或三台独立机器 HA 已通过。各模式的完成情况以验证记录为准；正式发布仍须满足完整 v3 的其他门槛。

用例的 YARA 规则为无害的恒假规则，ClamAV 关闭，不运行业务扫描或通知。启用 ClamAV 的完整 systemd 安装验收仍需另行验证。

## 连续替换与独立恢复任务

`pure-compose` 模式现对 native、Docker 各执行两次完整替换，第二次采用新任务和新配置版本。核对历史退役对象、生成第二阶段真实事件后，先回退后继，再以新的恢复任务引用原 capture、当前指针和后继回执，恢复原三容器。原任务高代次请求仍被拒绝，完成恢复的检查不能再次启停服务。

2026-10-20 的 `kernel-lifecycle.VQAIxZ` 整组通过：主测试 1069.83 秒，native 473.48 秒，Docker 596.21 秒。两个子场景及主测试无失败或跳过，关机后提取的日志包含 `WEBSCAN_V3_GUEST_TEST_EXIT=0`，虚拟机正常关机，宿主脚本退出 0。该次输入和结果保存在本机私有缓存 `/Users/lizheng/Library/Caches/webscan-v3-kernel-validation/`，不属于发布附件。

新恢复任务仍由测试直接构造。此结果证明子控生命周期，主控的可信恢复任务创建、数据库租约／版本／审计及 SSH 生成尚待接入，不能作为完整主控安装器或公开恢复流程验收。

## 名称目标的应用与保留数据回退

新增两个明确选择的模式，默认模式不变：

```bash
bash scripts/verify-v3-kernel-lifecycle.sh name-change
bash scripts/verify-v3-kernel-lifecycle.sh docker-name-change
```

分别运行 `TestNativeSystemdKernelNameChangeApplicationAndRollback`、`TestDockerKernelNameChangeApplicationAndRollback`。从实际 v3 托管身份安装出发，用本机 CSR 激活重叠名称，在同一服务上以原名称和新名称建立全新 mTLS 连接；核对精确证书、原运行配置及未变化的服务 PID／Docker ID、启动时间和重启次数。随后通过原生命周期应用无私钥的目标配置，核对新名称与新版本，生成未确认事件，再回退并核对原指针、当前重叠证书、原配置和保留事件。

这两个用例使用本地签发夹具，不包含主控 PG 签发账本或固定 SSH 的联合编排。2026-10-20 已实际运行 native 和 Docker 完整用例并通过，Docker 子控使用 Docker 27.5.1；详情见 [验证记录](V3-VALIDATION.md)。native 模式仍需至少 4 GiB 临时可用空间，Docker 模式至少 6 GiB；脚本不会自动启动／重启故障的 Docker Desktop 或清理无关资料。

2026-10-20 在用户明确批准后重启了 Docker Desktop，并恢复 containerd 选项；没有重置或全局清理。原测试镜像不可见，已重新准备隔离工具。新 amd64 构建在生成 initramfs 时停滞，取消后采用独立临时构建：重新安装相同固定内核和工具，逐字节核对内核 SHA256，再复制此前已记录输入摘要、版本完全相同的 initrd，并再次核对 SHA256。新测试程序和 Agent 仍从当前源码构建。该变体的来源与 Dockerfile 摘要见本机 `docker-kernel-initrd-reuse-proof.json`；它不是产品镜像或发布附件，也不改变实际进程、mTLS、资源限制或数据保留验收。

真实 native 初轮停在身份核验：程序／扫描工具、systemd 及内核资源检查均成功，但整段操作 5.540 秒，超过内部五秒发布时限而被拒绝。现在只读宿主核验沿用工具现有的三十秒预算，并把受限 context 传入实际核验；调用超时、取消和授权到期仍优先，信任与身份锁持续保持。固定证书发布操作未改。新增回归包含超过五秒但有效的检查、调用取消、较短期限、真实授权到期和锁等待，身份文件保持不变。失败证据保留，不能改写为初轮已通过。

## Docker 引擎版本复测

隔离 Docker 生命周期脚本默认使用固定摘要的 Docker 27 测试引擎。复测其他版本时，可通过 `WEBSCAN_V3_DIND_IMAGE` 指定包含 `@sha256:` 摘要的 DinD 镜像；脚本拒绝只有可变标签的镜像。测试使用独立临时引擎，不连接宿主 Docker socket。

该参数只允许复用测试入口，不代表 Docker 29 验收已通过；还须记录实际引擎版本、镜像摘要及测试结果，并完成真实服务管理联合验证。

## 网页部署联合模式

`web-native` 和 `web-docker` 在同一无外部网卡的完整 Linux guest 内启动实际 PostgreSQL 17、内置主控的应用容器、HTTPS 代理、宿主准备工作器、部署执行器、固定指纹 SSH 和采集器。主控只读挂载共享 Vault、验签元数据及采集身份，不挂载 CA 私钥、宿主程序或 Docker socket。SSH 接收端执行产品生成的真实命令，不替换服务阶段、安装回执或采集就绪记录。native 使用真实 systemd；Docker 使用 guest 内独立引擎。指标写入端明确模拟，实际 VictoriaMetrics 存储另由单中心栈测试覆盖。

```bash
WEBSCAN_V3_DOCKER_KERNEL_IMAGE='本地已核对的Docker29内核工具镜像' \
WEBSCAN_V3_DOCKER_CONTAINERD=1 \
WEBSCAN_V3_AGENT_KERNEL_IMAGE='仓库/webscan-agent:本次测试版本@sha256:<摘要>' \
WEBSCAN_V3_WEB_KERNEL_CENTRAL_IMAGE='仓库/webscan-central:本次测试版本@sha256:<摘要>' \
WEBSCAN_V3_WEB_KERNEL_PG_IMAGE='docker.io/library/postgres@sha256:<摘要>' \
bash scripts/verify-v3-kernel-lifecycle.sh web-docker
# 同样参数，选择 web-native 验证 systemd 子控。
```

测试先读取并确认指纹、加密保存凭据、异步准备和确认安装，再通过 mTLS 采集验证真实文件事件进入 PostgreSQL。之后保存新配置并升级，在真实备份完成后故意丢弃响应，分别从公开接口继续及回退，核对任务状态、可操作标记、原登录，以及主控容器 ID、PID、启动时间和重启次数保持不变。两个模式的结果须分别记录；新增入口或用例不等于通过，也不能据此宣称物理主机已做完整重启验收。
