# v3 完整备份与隔离恢复

v3.0.3 已正式发布，实际签名产物的完整备份／隔离恢复、全新安装默认每日备份及真实整机重启恢复已通过，结果和限制见 [发布回执](RELEASE-v3.0.3-RECEIPT.md)。本文保留分阶段实施与测试记录；早期“待验收”“尚未完成”等状态以最终回执为准。备份恢复不等同生产灾备切换或恢复后执行全部远端任务，以下命令未对生产执行。

## 当前覆盖范围

| 组件 | 当前状态 | 恢复边界 |
|---|---|---|
| PostgreSQL 业务数据 | 已有可校验的重复读快照与空库恢复 | 不覆盖运行中数据库；恢复后仍需协调节点代次及任务 |
| VictoriaMetrics 单机数据 | 新增快照复制、摘要清单、离线恢复暂存；真实单机进程通过 | 只写全新目录，不启动服务、不切换现有存储 |
| 当前配置、Vault、PKI、部署及身份恢复资料 | 新增单中心宿主编排、逐文件摘要和离线展开，真实签名 Linux 程序联合验证通过 | 只暂存私有恢复目录；额外历史恢复目录需明确列入，不启动原路径服务 |
| 每日执行、最近七份及总览完整备份状态 | 实际签名命令、新安装 systemd 激活及整机重启恢复已联合验收 | 升级不覆盖现有策略；归档与完整恢复证据分开，不显示无证据的恢复成功 |

## 单中心组合备份

新增 `backup-single`、`verify-single-backup` 和 `restore-single-offline`，仅供宿主维护命令使用，没有新增公网备份接口。组合备份包含应用 PostgreSQL 逻辑导出、VictoriaMetrics 独立快照、原不可变安装、当前 API／执行器配置、Compose、当前及旧 Vault、CA、CRL 历史与下限、采集器身份历史、当前签名物料、配置包及恢复目录。

在 0600 普通文件中明确本机资料位置。安装需已完成，支持格式 2 的既有安装加已接通的网页部署资料，以及格式 3 安装；不为通过校验改写原安装记录：

```json
{
  "format": 1,
  "installation": "/var/lib/webscan-v3/install.json",
  "host_config": "/var/lib/webscan-v3/executor.yaml",
  "api_config": "/var/lib/webscan-v3/config.yaml",
  "compose_file": "/var/lib/webscan-v3/compose.yaml",
  "pki_maintenance": "/var/lib/webscan-v3-pki-maintenance/maintenance.json",
  "recovery_directories": ["/var/lib/webscan-v3-release-history"]
}
```

`pki_maintenance` 和 `recovery_directories` 可省略。已升级机器必须填写实际生效的配置与 Compose 路径；有独立证书维护包时一并填写，保留其独立验签公钥。额外目录用于当前配置之外仍须保留的历史版本／恢复物料，最多 32 个私有目录。工具不根据数据库中的任意文本猜测宿主路径；相关目录未纳入时，不能承诺历史任务可以离线恢复。

```sh
webscan control-v3 --action backup-single \
  --source /root/webscan-single-backup.json \
  --output /var/lib/webscan-v3-backups/single-20261031
```

输出不可位于来源安装或任何恢复依赖目录内，父目录需预先存在、属于运行账号且为 0700。原始 PostgreSQL／VictoriaMetrics 活动目录不直接拷贝；锁文件不进入恢复材料。宿主文件不允许硬链接、符号链接、设备、FIFO、其他账号所有或可被其他账号写入。归档全部为目录 0700、文件 0600，原可执行权限单独记入私有清单，展开时不自动恢复执行权限。

编排按已有签发及身份更新顺序固定 PKI 锁，随后锁定应用数据库表、导出业务记录、取得时序快照并复制宿主资料。复制后再次读取宿主清单，发现越过维护锁的修改即失败。数据库使用五秒取锁预算，整个命令五分钟预算；**复制期间业务数据库写入会等待，PKI 下限更新也可能等待或超时；恢复时丢弃的 API 进程心跳表不参与写入冻结，真实 heartbeat 仍可更新**，可能导致短暂采集延迟，但不会重建主控。大数据量性能、正常请求及采集延迟影响尚待验收，不能宣称无影响的在线备份；本地实现的默认定时任务尚未对生产启用。

命令检查所有应用表中 `key_id`／`*_key_id` 引用的 Vault 密钥是否存在，缺失时停止。原始安装、配置、信任及物料摘要与实际捕获文件再次绑定。备份根 `backup.json` 记录数据库结构版本、业务归档、时序清单摘要、宿主映射、每个文件摘要及真实起止时间。数据库与宿主在检查点内固定；时序是该时间段内的独立快照，**不是跨引擎原子事务**。

成功只返回 `state: captured`、目录、外部清单摘要和数量，`isolated_restore_validated` 仍为 false；未做隔离恢复的每份归档不能自动显示“可恢复”。时序清理失败则退出非零、不发布组合归档，并返回已确认的临时快照名；创建回执不明时不猜测名称、不清理其他快照。

将可信回执写入 0600 校验请求，格式与下方时序请求相同，但 `directory` 指向组合备份、`manifest_sha256` 为组合根清单摘要：

```sh
webscan control-v3 --action verify-single-backup \
  --source /root/webscan-single-restore.json

webscan control-v3 --action restore-single-offline \
  --source /root/webscan-single-restore.json \
  --output /var/lib/webscan-v3-restore/isolated-single
```

校验无数据库／网络连接；恢复只向全新独立目录复制 `host`、`postgres`、时序存储和恢复说明，不读取归档 DSN 发起连接、不向归档原路径写回、不执行服务文件。随后由管理员在隔离数据库显式执行 `restore-db`、以原固定 VM 版本启动隔离实例并核对。数据库结构升级仍需独立一致性备份及显式迁移。

展开报告始终标记 `cutover_authorized: false`。生产灾备切换仍需协调节点代次，并核对归档后新增的历史退役证据；旧归档不能凭自身证明不存在更晚的退役。已验证恢复后的实际 API 登录、进程再次启动及会话保持，测试使用明确的隔离路径／数据库覆盖资料，关闭执行器和业务通知。隔离恢复新增验证未完成部署的固定计划／步骤／日志游标保留，以及真实通知出箱的领取／完成回执：只用模拟发送器处理待发项，不重放已完成项，保留原投递键或 ID／收件人派生键。此验证不执行归档中的 SSH 部署，也不替代所有恢复任务、节点代次协调或受控生产切换。

## 每日策略与持久任务（本地实现）

新增 `prepare-single-backup-schedule`、`configure-single-backup-schedule`、`enable-single-backup-schedule`、`run-single-backup`。前者生成不可覆盖的策略和 systemd 文件，不激活；其余命令要求实际执行路径、编译版本和安装信任资料中的签名程序一致，数据库须已显式升级到当前结构。`enable` 只允许重新启用完全相同摘要的原策略，不替换配置、不启动 timer；恢复后需由管理员显式执行。策略请求示例：

```json
{
  "format": 1,
  "backup_directory": "/var/lib/webscan-v3-backups",
  "keep": 7,
  "backup": {
    "format": 1,
    "installation": "/var/lib/webscan-v3/install.json",
    "host_config": "/var/lib/webscan-v3/executor.yaml",
    "api_config": "/var/lib/webscan-v3/config.yaml",
    "compose_file": "/var/lib/webscan-v3/compose.yaml"
  }
}
```

`keep` 省略时为 7，允许 1～365。备份父目录预先建立为 0700；策略输出目录必须在安装和备份目录之外。生成的 timer 默认每天宿主时间 03:00，加最多十五分钟随机延时，持久补触发。数据库记录完整策略摘要及每次任务的运行、失败、中断、归档和过期状态；24 小时内已有同策略成功归档时不重复执行，跨进程及宿主互斥。

保留策略只处理该策略已提交清单摘要、再次通过全量校验的已成功目录，不枚举或清理未知目录。清理中断保留持久检查点；失败、未提交的归档不冒充成功，也不被自动删除。升级不会改写已有策略或不可变安装记录；冲突会停止。数据库灾备恢复后禁用策略，并将未完成任务置为待核对，不能用归档中的旧授权删除新宿主文件。

全新 format 3 命令安装默认生成每日／七份策略，原请求的继续操作从不可变清单恢复这一默认值；旧安装继续保持原有策略或不配置。实际 Linux systemd 激活、启用状态、下次运行时间、签名服务执行和 timer／service 重启去重已在隔离虚拟机通过；完整全新安装及整机重启仍是独立门禁。总览只公开任务状态和数量，不公开目录、Vault 或恢复凭据；没有完整隔离恢复证据的归档继续显示未知恢复状态。

## 时序备份宿主命令

`backup-metrics` 在 Linux amd64 主控宿主以 root 执行。来源必须是已完成的受管理单中心安装，校验原不可变安装资料；时序目录固定为原安装的 `metrics-data`。当前配置的数据库凭据路径、回环时序地址必须与该安装一致。不会连接 SSH、迁移 PostgreSQL、重建中心或发送通知。

输出目录必须尚不存在，其父目录属于运行账号、权限 0700 且路径无符号链接；不可放在时序数据目录内。示例中的目录需事先由管理员准备：

```sh
webscan control-v3 \
  --action backup-metrics \
  --config /var/lib/webscan-v3/config.yaml \
  --source /var/lib/webscan-v3/install.json \
  --output /var/lib/webscan-v3-backups/metrics-20261031
```

当前 API 配置可能位于独立升级目录，应使用实际配置路径，不覆盖原 `install.json`、CA 或 Vault。来源校验不通过时停止，不能重新生成密钥或修改不可变安装记录来使校验通过。

成功回执包含 `directory`、`manifest_sha256`、本次 `snapshot`、`snapshot_cleaned`、文件数及字节数。保存回执供后续备份根清单引用。原始服务错误响应不进入回执及日志。

清理失败时退出非零并返回 `metrics_snapshot_cleanup_pending`；若独立备份已校验，其路径和摘要仍保留。备份未完成时回执只包含已知快照及清理状态，不能当作有效备份。创建回执不明返回 `metrics_snapshot_create_unconfirmed`，可能有未知临时快照，需要宿主管理员核对；不会猜测名称、重复创建或清空其他快照。

## 校验及隔离恢复

把可信备份回执中的目录、摘要写入属于运行账号的 0600 普通文件：

```json
{
  "format": 1,
  "directory": "/var/lib/webscan-v3-backups/metrics-20261031",
  "manifest_sha256": "从可信回执或已验证的完整备份根清单复制64位SHA256"
}
```

```sh
webscan control-v3 --action verify-metrics-backup \
  --source /root/webscan-metrics-restore.json

webscan control-v3 --action restore-metrics-offline \
  --source /root/webscan-metrics-restore.json \
  --output /var/lib/webscan-v3-restore/metrics-data
```

校验不加载运行配置、不访问数据库或时序服务。恢复命令同样要求 Linux amd64 root；重新核对每个复制文件的摘要，全部通过后以不可覆盖的原子发布方式暂存到全新目录。不会停止、启动容器或改动原目录；现有目录即使为空也拒绝覆盖。应使用原安装记录的固定时序镜像版本与摘要，在隔离环境启动新实例核对结果；服务切换另行执行。

摘要必须来自可信外部回执，不能从同一待验证目录生成一个新摘要来“修复”损坏。该组件的摘要清单提供完整性核验，不单独提供完整备份根清单的签名、凭据解密或业务灾备协调。

## 存储及失败约束

- 使用配置中的回环单机地址访问固定 `/snapshot/list`、`/snapshot/create`、`/snapshot/delete`，拒绝 URL 凭据、查询参数、其他地址及 HTTP 跳转。不关闭 HTTPS 证书验证。
- 只清理本次确认创建的快照，保留操作前已存在的快照。取消后用独立五秒清理预算；清理不明按失败报告。
- 适配 VictoriaMetrics v1.128.0 单机快照布局。仅解析 `data/big`、`data/small` 和 `indexdb` 指向该次快照的三个已知相对链接；从已固定的存储描述符逐级打开预期目录。拒绝指向活动存储、外部目录或任意深层符号链接。
- 源快照允许 VictoriaMetrics 创建的不可变硬链接；备份与恢复输出全部为独立普通文件。拒绝设备、FIFO、可被其他账号写入的源和非私有备份文件。输出权限为目录 0700、文件 0600。
- 清单记录快照 ID、起止时间、全部目录、每个文件字节数及 SHA256；校验拒绝缺失、附加、截断、内容改变、权限变化及链接替换。空目录和零字节文件也保留。
- 单次上限为一 TiB、200,000 个文件／目录、64 MiB 清单；不表示已经完成大规模容量认证。组件快照不是跨 PostgreSQL、文件系统及时序库的原子事务。

## 可复现的隔离验证

组合备份的实际程序与引擎验证：

```sh
WEBSCAN_V3_BACKUP_TEST_PG_IMAGE=sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b \
WEBSCAN_V3_BACKUP_TEST_VM_IMAGE=sha256:c27e736a8aff888cf30c4f20ec648b767358694993d87e89afc6bf80f28991da \
WEBSCAN_V3_BACKUP_TEST_RUNNER_IMAGE=sha256:ea8d6e779b965a76961caecb42e57e2eec6fcf9f621fcb398d79cfa28572cce5 \
bash scripts/verify-v3-single-backup.sh
```

实际编译的 Linux amd64 程序及测试物料独立签名，PG17 在一次性 tmpfs，VM 及归档在本次专用 bind。没有外网路由、Docker socket、生产配置或通知目标。验证组合捕获、校验、展开、空数据库导入、原凭据解密、CA 与采集器私钥连续性，以及真实 VM 恢复后仍能查询原样本、查不到备份后新增样本。成功不代表已自动启用定时备份或批准生产切换。

时序组件独立验证：

```sh
WEBSCAN_V3_SNAPSHOT_TEST_VM_IMAGE=sha256:c27e736a8aff888cf30c4f20ec648b767358694993d87e89afc6bf80f28991da \
WEBSCAN_V3_SNAPSHOT_TEST_RUNNER_IMAGE=sha256:ea8d6e779b965a76961caecb42e57e2eec6fcf9f621fcb398d79cfa28572cce5 \
bash scripts/verify-v3-metrics-snapshot.sh
```

脚本只使用本机已有的固定镜像 ID，不拉取镜像。默认在本次独立证据目录的专用 bind 目录运行真实 VictoriaMetrics 和恢复实例，网络为 `none`，只使用容器回环连接；可显式设置 `WEBSCAN_V3_SNAPSHOT_TEST_STORAGE=tmpfs`。没有 Docker socket、生产配置、SSH 或业务通知。

验证快照中指标可恢复、备份后新增指标不会混入、并发发布只有一个成功结果、历史快照保留、损坏和取消不会发布不完整恢复目录。宿主命令的校验与恢复也在 Linux 进程内执行。脚本只移除本次有明确名称和标签的测试容器，不清理已有镜像、卷或其他数据。

即使 bind 验证通过，也不能替代真实 Linux 磁盘掉电恢复、完整主控恢复、systemd 或 native／Docker 29 生命周期联合验收。

### 实际 Linux 定时服务验证

```sh
WEBSCAN_V3_WEB_KERNEL_PG_IMAGE=docker.io/library/postgres@sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b \
WEBSCAN_V3_BACKUP_TIMER_VM_IMAGE=sha256:c27e736a8aff888cf30c4f20ec648b767358694993d87e89afc6bf80f28991da \
bash scripts/verify-v3-kernel-lifecycle.sh backup-timer
```

2026-10-31 无网卡 Linux 6.1／systemd 252 虚拟机通过该用例：生产激活路径启用默认每日／七份 timer，实际签名服务完成 PG17＋VictoriaMetrics 捕获、验证、隔离展开、凭据解密、指标查询和恢复 API 登录／第二次启动会话保留。timer／service 再次运行未重复生成每日归档。证据位于 `.cache/verification/v3/kernel-lifecycle.EZEOfJ/guest-test.log`，完整测试约 162.1 秒，56 个文件、117,063,855 字节。

测试程序为当前源码的本地签名版本，不是 v3.0.3 正式签名产物；虚拟机内 Docker 27.5.1 不作为 Docker 29 门禁。测试未完成完整全新安装、整机重启、全部部署任务／通知恢复或灾备切换，没有修改生产服务。完整备份已扩展锁定原 authority 中存在的固定后继 CA，避免捕获期间其签发历史变化；全部节点的换根编排仍按证书维护独立门禁验收。
