# v3 全新单中心安装与已有试运行中心升级

证书维护程序升级说明见本文末尾“独立升级证书维护程序”。原安装资料及 CA/Vault 必须保留，不能用覆盖旧程序或重新生成密钥处理数据库版本不一致。

全新安装流程只创建独立单中心，不接管 v2 或迁移拓扑；已有试运行中心使用本文末尾的专用升级模板。v3.0.3 单中心已发布，先阅读 [正式安装入口](INSTALL-v3.0.3.md) 和 [发布回执](RELEASE-v3.0.3-RECEIPT.md)，不要在现有数据目录执行全新安装。

一台中心机器运行三个容器：中心 Go 程序（合并 API、采集、通知和网站检测）、PostgreSQL 17、VictoriaMetrics。systemd 管理整套服务的开机启动，Docker 保持容器重启策略。本机 API、数据库和时序库均只监听回环地址；外部 HTTPS 入口必须预先准备，此工具不修改 Nginx、防火墙或业务网站。

## 输入和命令

在 root 所有、`0700` 的父目录中准备 `0600` 请求 JSON。所有镜像都必须使用明确的官方仓库及 `@sha256:` 摘要，并对应 Linux amd64；示意中的占位摘要不能执行：

```json
{
  "format": 3,
  "root": "/var/lib/webscan-v3-isolated/single",
  "instance": "central-1",
  "username": "admin",
  "public_url": "https://monitor.example.test",
  "api_port": 19444,
  "postgres_port": 5432,
  "metrics_port": 8428,
  "runtime_image": "docker.io/gzdzh/webscan-central:v3.0.3@sha256:<已核验摘要>",
  "postgres_image": "docker.io/library/postgres@sha256:<已核验摘要>",
  "metrics_image": "docker.io/victoriametrics/victoria-metrics@sha256:<已核验摘要>",
  "rules_file": "/opt/webscan-v3/release/rules.yar",
  "deployment_trust": {
    "vault_key_file": "/var/lib/webscan-v3-isolated/single/vault.key",
    "release_public_key_file": "/opt/webscan-v3/trust/signing.pub",
    "release_manifest_file": "/opt/webscan-v3/release/release.json",
    "release_signature_file": "/opt/webscan-v3/release/release.sig",
    "helper_file": "/opt/webscan-v3/release/webscan",
    "native_bundle_file": "/opt/webscan-v3/release/agent-native.tar.gz"
  }
}
```

上例中的占位摘要不可执行；v3.0.3 的实际摘要及可修改请求见 Release 附件。镜像可同时包含版本标签和摘要，生成的 Compose 保留完整引用，便于识别版本；仅有标签、没有摘要的请求仍拒绝。旧的仅摘要请求保持兼容。

目录须为尚不存在的绝对规范路径，只接受 ASCII 字母、数字、`_`、`-`、`.` 和 `/`。三个本机端口须互不相同，范围 `1024～65535`；缺省使用上例值。请求不含数据库密码或管理员密码。

```bash
# 只检查请求格式和生成概要，不写文件、不访问 Docker、不证明环境已通过。
webscan control-v3 --action preview-single-install --source /受控目录/install.json

# 在独立 Linux amd64 主机以 root 执行，首次密码从 0600 文件读取。
webscan control-v3 --action install-single --source /受控目录/install.json \
  --password-file /受控目录/first-password

# 失败后仍用原请求及同一程序继续，不重新生成密码、证书或数据库。
webscan control-v3 --action resume-single-install --source /受控目录/install.json
```

默认单中心语义与 `configure` 的拓扑选择一致。本入口显式拒绝 `--topology ha`；还没有接入正式安装菜单，不代表高可用安装已经完成。

## 实际安装和保护

先检查 root、Linux amd64、Docker／Compose、systemd、本机端口、至少 2 GiB 可用空间和 1024 个空闲 inode。空间是安装最低预留，镜像和长期业务数据需要额外容量。Docker 异常不会触发重装或重启。

当前执行程序、配置、随机数据库凭据、管理员 bcrypt 摘要、独立 CA 和采集器身份、Compose 及 unit 一次性原子发布；目录 `0700`，凭据 `0600`，程序 `0700`。中心容器只挂载需要的资料，不挂载 CA 私钥、首次密码摘要或 Docker socket。format 3 使用镜像内置的 Go 程序；启动前提取并核对其字节与本次签名安装程序完全一致，不再挂载程序覆盖镜像。format 1／2 的旧安装资料保留原执行方式，只用于原任务续作。

安装分六步持久化进度：镜像核验、数据库／时序库启动、空库初始化、首次管理员、服务启动、联合验收。首次管理员明文不写入安装资料；数据库密码仅保存在私有文件，不进入 Compose 环境参数。VictoriaMetrics 初始保留 15 天，不把新建安装当作已有历史期限迁移。

新安装请求使用 `format: 3`，沿用 format 2 对不可变安装资料和可更新证书目录的分离。旧 format 1／2 仅保留按原资料和原程序继续的兼容入口，不自动迁移。续作绑定原请求和程序摘要，核对每个固定文件，拒绝符号链接、硬链接、公开凭据或漂移。账户创建与核对在事务中完成，重复提交不能覆盖后来修改的密码。systemd unit 完整写入后以不覆盖方式发布，已有不同内容的 unit 拒绝操作。

容器核验包含安装归属、项目、服务、固定镜像 ID、Compose 配置摘要、host 网络及运行状态。启动使用 `--no-recreate --pull never`，不重建其他项目。完成后的继续命令仅重新验收，不重置账号、数据库或会话。失败保留原资料和已完成的数据，不自动清空或降级回退。

工具输出区分阶段进行、完成及失败；第三方命令原始输出不进入错误或进度。镜像不可用与平台不符提供明确代码，不能通过更换为 latest 跳过核验。

## 当前边界

format 3 已配置发布信任、共享 Vault 和独立宿主 SSH 执行器；网页操作仍须由能力接口确认执行器、签发器和准备工作器的真实心跳。旧 format 1／2 的原始禁用状态不会被改写。新格式接入本机采集器续签及 CRL 维护，但安装返回不等于全部节点生命周期已经验收。本版使用受控 CLI，尚未接入旧式公开安装菜单。最终签名产物及真实隔离 Linux/systemd 整机重启恢复已通过，普通容器测试不能替代该门禁；实际范围见 [发布回执](RELEASE-v3.0.3-RECEIPT.md)。

## 本机证书维护

宿主机安装独立 oneshot 服务和 timer：每小时检查，开机后一分钟触发，随机延迟最多五分钟，并补执行错过的日历任务。中心 stack 启动依赖维护服务成功；中心容器只读挂载整个 `collector-pki/` 目录，原子替换文件后无需重建容器。CA 私钥和维护工具运行于宿主机，不挂载给中心。

采集器叶证书为 30 天，剩余不超过七天时更新；CRL 有效期 24 小时，剩余不超过 12 小时时更新。保留全部吊销和私有旧身份；已吊销的证书拒绝续签。离线超过叶证书期限后，仍须核对原身份、有效 CA 和吊销历史才能恢复，不能生成新 CA 绕过问题。维护失败向 systemd 返回失败；取得维护锁后的失败还尝试持久化安全状态 `state/pki-maintenance.json`，不输出私钥。

不可变根目录资料用于安装续作；`authority/` 为可更新的签发资料，`collector-pki/` 为可更新的活动身份，`state/collector-trust/` 为跨重启吊销下限。初始化先建立下限再发布运行目录；已存在的运行目录遇到丢失或损坏下限时停止，不从种子资料自动重建。备份须一致保留这些目录及私有历史，不能只恢复旧种子或手工删除下限。本地文件保护不涵盖整盘同时回放。

可在原主机手动运行已安装的同一私有程序进行检查和维护：

```bash
/var/lib/webscan-v3-isolated/single/webscan control-v3 \
  --action maintain-single-pki \
  --source /var/lib/webscan-v3-isolated/single/install.json
```

不传首次密码，不操作 Docker 或直连远端节点。工具核对自身和安装包摘要，安装器之外的其他二进制不能代替。数据库初始化完成后，宿主命令还使用独立凭据连接本机 PostgreSQL，限时处理公开节点续期队列；未完成初始化时只维护本机信任，数据库版本不匹配时停止节点签发，不在定时任务内迁移。节点私钥不进入主控或宿主签发器。

节点证书剩余不超过七天时，由主控采集器准备和提交公开 CSR；宿主每轮最多签发 500 条、预算 45 秒，采集器再交付并确认实际激活。失败记录和退避持久化，单节点失败不阻断同批其他节点。本机信任状态与节点签发状态分别记录：数据库暂不可用时，`node_renewals.state` 为 `deferred`，部分签发失败为 `failed`；保留队列并等待重试，不让数据库启动顺序阻止中心启动。本机 CA／吊销／身份损坏仍停止本机证书维护。真实宿主 timer 调度、离线过期 SSH 恢复和 CA 换根仍须单独演练，不能由容器测试推断全部长期证书运维场景通过；本次正式产物的真实网页联合部署已经验收。

## 容器验证

`scripts/verify-v3-single-install.sh` 在独立测试存储中运行实际 Linux CLI、PostgreSQL、VictoriaMetrics、内置主控镜像和宿主执行器，systemd 明确使用模拟适配器；它不能证明真实主机开机自启。必须显式提供已缓存的 PostgreSQL 17、VictoriaMetrics、当前中心和子控的 **amd64 不可变摘要**：

```bash
WEBSCAN_V3_TEST_SINGLE_PG_IMAGE='docker.io/library/postgres@sha256:<amd64 摘要>' \
WEBSCAN_V3_TEST_SINGLE_VM_IMAGE='docker.io/victoriametrics/victoria-metrics@sha256:<amd64 摘要>' \
WEBSCAN_V3_TEST_SINGLE_CENTRAL_IMAGE='仓库/webscan-central:本次测试版本@sha256:<amd64 摘要>' \
WEBSCAN_V3_TEST_SINGLE_AGENT_IMAGE='仓库/webscan-agent:本次测试版本@sha256:<amd64 摘要>' \
bash scripts/verify-v3-single-install.sh
```

脚本验证安装中断继续、账户与登录会话保留、采集器续签、CRL 发布和向独立子控状态自动下发、实际 HTTP/2 重认证及事件确认；仅删除本次创建的容器和 volume，保留脱敏检查点、清单和测试日志。真实 systemd 重启、HTTPS 入口、主控与节点联合安装及 HA 验收仍须单独完成；测试失败不能算作通过。

## 旧版退役与数据保留

卸载旧主控程序必须先停止旧数据写入者，对旧 SQLite 使用一致性备份和完整性检查，并完整归档配置、部署状态、通知、PKI、SSH 资料、独立解密密钥及旧备份。数据库原目录与验证过的归档均保留，卸载不等于迁移到 PostgreSQL。

清除子控数据属于独立的管理员维护操作，不能复用默认保留数据的普通卸载。逐台固定 SSH 身份、容器 ID、项目镜像、挂载和服务定义后才能清理项目专属目录；业务网站、其他容器、Docker 引擎及云安全服务均保留。失联或身份不符记为未完成。清除后须退役旧运行登记，并创建新安装任务和新证书；不得继续旧任务或声称旧队列可恢复。本操作不开放公网清理接口。


## format 3 的信任与挂载

新安装必须使用 format 3，直接运行镜像内置的本版程序，不再把宿主程序挂载覆盖到旧镜像。安装器在启动前从固定摘要镜像提取实际程序并与签名清单及当前安装工具核对。API 采用 `executor.mode: external`，只读挂载 Vault、验签资料及采集身份；宿主执行器单独使用 CA 私钥、已验签程序及配置包目录。

新安装只生成一次 Vault 密钥。中断继续核对原始文件摘要，禁止通过重新生成密钥或重写安装记录修复失败。format 1／2 只接受原参数 `resume-single-install`，不能冒充全新格式。数据库升级使用一致性备份，失败停止。

## 已有单中心升级模板

升级使用独立目录叠加配置，保留原 install.json、journal.json、Vault、CA、采集身份、PG 及指标数据。以下命令只准备模板，不停止服务，不执行数据库迁移，也不修改线上。

在 0600 的 `upgrade-request.json` 中提供 `format: 1`、原 `api_config`、原宿主 `executor_config`、当前 `compose_file`、原 Compose `project`、带版本和摘要的新 `runtime_image`、`rules_file` 和新发布的 `deployment_trust`。`vault_key_file` 必须为原宿主路径或省略；旧密钥清单沿用原宿主，不接受替换。

```bash
webscan control-v3 --action preview-single-web-upgrade \
  --source /私有目录/upgrade-request.json --output /私有目录/upgrade-v3.0.3
webscan control-v3 --action prepare-single-web-upgrade \
  --source /私有目录/upgrade-request.json --output /私有目录/upgrade-v3.0.3
```

输出包括新的 API／宿主配置、Compose、宿主 unit 及文件摘要。原 PG 和指标服务定义保持不变，中心只挂载明确的状态目录、现有密钥和必要只读文件，不挂载 CA 私钥或 Docker socket。新目录已有内容则拒绝覆盖。

正式维护时须先核对 upgrade.json 的源摘要和文件摘要，确认不存在冲突任务；用新程序的 `migrate-db --output <0700备份目录>` 先执行备份及增量迁移。停止原宿主执行器，使用原 Compose 项目和新 Compose 的 `up -d --no-deps --pull never central` 仅重建中心应用，再安装新宿主 unit。同步更新开机启动 unit 所引用的 Compose 路径，并按下节更新证书维护程序。不要执行 `compose down`，不要替换 Vault、PG 或时序库。

启动后核对 `/healthz`、能力、运行设置及实际执行器心跳，并核对 PG／时序容器 ID、密钥 ID 和登录保持。模板生成不能代替该完整升级演练；失败保留全部检查点及备份，数据库已经迁移时不能直接使用不兼容旧程序冒充恢复成功。本轮不在生产应用这些命令。

Docker 29 的 containerd 镜像库可能分别返回索引和平台镜像摘要。安装器同时核对不可变引用、Linux amd64 平台、实际平台镜像及 Compose 配置；不通过放宽摘要判断来兼容。隔离验收脚本默认使用匹配的 Docker 29 客户端，避免旧客户端无法选择多平台缓存。

## 独立升级证书维护程序

旧安装记录固定了安装时的程序摘要。数据库升级后，继续用旧程序签发节点证书会因结构版本不一致而延后；直接覆盖原 `webscan` 会破坏安装与恢复校验。应使用独立维护升级包，绑定现有安装及新版签名工具，保留原程序、CA、Vault、安装记录和全部运行数据。

在私有父目录内准备权限 `0600` 的请求文件：

```json
{
  "format": 1,
  "installation_file": "/var/lib/webscan-v3/single/install.json",
  "release_public_key_file": "/opt/webscan/trust/signing.pub",
  "release_manifest_file": "/opt/webscan/release/release.json",
  "release_signature_file": "/opt/webscan/release/release.sig",
  "helper_file": "/opt/webscan/release/webscan"
}
```

公钥必须来自独立可信配置；不能仅相信下载包自带的公钥。使用本次已验证的新版工具执行：

```bash
/opt/webscan/release/webscan control-v3 --action preview-single-pki-upgrade \
  --source /私有目录/pki-upgrade.json --output /私有目录/pki-maintenance-new
/opt/webscan/release/webscan control-v3 --action prepare-single-pki-upgrade \
  --source /私有目录/pki-upgrade.json --output /私有目录/pki-maintenance-new
/私有目录/pki-maintenance-new/webscan control-v3 --action check-single-pki-upgrade \
  --source /私有目录/pki-maintenance-new/maintenance.json
```

预览和准备不连接数据库、不激活服务。检查确认签名、摘要、权限、原安装及维护绑定，并要求维护包的结构版本与检查程序一致；`database_checked: false` 明确表示尚未检查实际数据库。实际维护还会核对正在执行的程序路径、文件摘要及内置版本与受签名发布清单一致。输出目录已存在即停止，不能覆盖旧包。包中不包含 CA 私钥或 Vault，仍使用原受限路径。维护时数据库版本必须准确匹配，不自动迁移。

实际激活仅在维护窗口由管理员执行：记录现有 unit 及定时器状态，暂停该项目的 PKI **timer**，等待正在运行的 oneshot 结束；将新包的 service/timer 安装到原项目的同名 unit，执行 `systemctl daemon-reload`。随后以新包程序执行 `maintain-single-pki-upgrade`，核对 `state`、`identity` 及 `node_renewals`（后者为 `deferred`/`failed` 时节点维护并未成功），再恢复 timer 的原启用状态。

**不要 stop/restart PKI service 或整套 stack。** 原 stack 可能依赖 PKI service，停止它可能连带停止数据库和时序库。维护只更新身份文件和 CRL；主控通过文件刷新继续采集，无需重建应用容器。资料检查失败时原包和身份仍保留；数据库已升级时不能恢复不兼容旧签发程序并宣称维护正常。

隔离验证入口为 `bash scripts/verify-v3-pki-maintenance-upgrade.sh`。必须显式提供已缓存、固定摘要的 PostgreSQL 17 与 Linux amd64 测试镜像（`WEBSCAN_V3_PKI_TEST_PG_IMAGE`、`WEBSCAN_V3_PKI_TEST_RUNNER_IMAGE`）。脚本构建本次程序并在临时签名夹具中验证，数据库位于 tmpfs，使用禁外网网络；证据保存在 `.cache/verification/v3/pki-maintenance.*`，只清理本次创建的容器。该测试覆盖真实签名程序、版本校验及结构不匹配时不迁移，不能替代磁盘持久化、完整备份恢复或 systemd 联合验收。
