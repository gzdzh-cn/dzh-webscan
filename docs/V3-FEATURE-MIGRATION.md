# v2.0.46 功能补齐：本地实施记录

开始日期：2026-11-01。基于 main 的 v3.0.3 继续开发。仅本地实现和隔离验证；不提交、不发布、不操作生产、不导入线上旧数据。保留原 UI、Docker 默认方式、native 可选、事件首次手动查询及删除保护。

## 阶段状态

| 阶段 | 当前状态 | 完成门槛 |
|---|---|---|
| 一：公共规则及本人改密 | 本地实现及隔离验收通过 | 完整批量应用／恢复、真实 native 与 Docker 29、浏览器检查 |
| 二：远程卸载及部署历史管理 | 本地实现及隔离验收通过 | 保留数据卸载、任务续作、固定版本重装及历史保护 |
| 三：通知详情及测试通知 | 本地实现及隔离验收通过 | 正文／逐次结果、筛选、安全投影和模拟通道测试 |
| 四：设备历史、设置及看门狗 | 实施中 | 受限设备曲线、剩余设置、独立故障告警及真实健康证据 |
| 五：旧数据迁移及隔离演练 | 实施中 | 最终增量、冻结／切换／核对、中断恢复及保留新数据回退 |

本轮范围不包含桌面／移动客户端、VPN、中继、HA 和容量认证。没有把局部测试结果当成全部迁移完成。

## 阶段一：实际实现

- 账号菜单开放修改本人密码。当前密码验证、持久限流、密码修改、账号版本递增、撤销该账号所有会话和审计原子提交；其他账号保持登录。新密码为 12～72 个 UTF-8 字节。当前密码错误返回 400，数据库异常返回 503。
- 新增公共目录、文件后缀、重要文件名、重要路径、忽略路径及核对间隔的读取、校验预览和仅保存。保存前加密备份，与配置、幂等回执同事务提交；不下发、不连接子控、不改变实际运行配置。
- 新增节点默认继承公共配置。旧节点没有继承元数据时，按已保存实际规则展示为独立配置；省略规则编辑时保留原有私有配置。合并规则保留扫描、资源及高级核对参数；自定义探针仍需通过完整配置校验。
- 公共规则与节点继承信息加入配置归档的校验和公开投影。拒绝重复字段、未知字段、大小写别名、不完整规则和 null；无效归档不进入恢复。
- 显式批量应用使用独立父任务及现有签名 SSH 部署子任务，每批最多 20 台、最多五个并发；首错停止启动新节点，等待已启动操作结算后暂停。可继续或回退整批及指定节点；回退保留已保存目标为待应用状态。
- 数据库结构升级为 39。不可变计划、成员清单、父子关系及节点检查点均校验；持久节点预留覆盖尚未创建子任务的节点，与编辑、记录移除、普通部署、全量恢复、换根及历史身份退役互斥。
- 账号密码或权限变化使任务暂停；管理员需单独预览并确认重新授权，再明确继续或回退。授权确认本身不启动 SSH。数据库灾备恢复保留任务和恢复资料，但撤销旧授权、维护心跳并保持恢复保护，不自动执行远程任务。

## 已取得的验证证据

证据根目录：`.cache/verification/v3/feature-migration-20261101/`。集成测试只使用本机 PostgreSQL 17 的独立随机 schema，不连接业务通知渠道。

| 检查 | 结果 | 证据 |
|---|---|---|
| 本人改密 PostgreSQL 17 竞争测试 | 通过；49.075 秒 | `password-backend-race.log` |
| 公共规则／继承／配置归档／内部配置保存／全量恢复互斥的 PostgreSQL 17 竞争测试 | 通过；23.882 秒 | `monitoring-main-race.log` |
| nodeconfig 完整竞争测试 | 通过；1.704 秒 | 子任务验证结果；不等同真实服务联合测试 |
| nodeops 配置与恢复定向竞争测试 | 通过；5.154 秒 | 服务管理夹具及本地 SQLite，不等同 SSH／Docker 29 |
| 批量应用 PostgreSQL 17 竞争测试 | 通过；67.407 秒 | `monitoring-applications-race.log` |
| 检查点篡改／旧快照竞争回归 | 通过；9.644 秒，保留修复前失败证据 | `monitoring-security-green.log` |
| 备份恢复及 38→39 迁移竞争测试 | 通过；15.120 秒，包含恢复后直接调用拒绝 | `monitoring-backup-green.log` |
| 换根／历史退役互斥竞争测试 | 通过；6.775 秒 | `monitoring-interlocks-race.log` |
| 公共规则与完整配置恢复兼容回归 | 通过；7.190 秒 | `monitoring-compatibility-final.log` |
| 单节点 preparing 检查点续作 | 通过；5.053 秒，保留修复前失败证据 | `monitoring-preparing-green.log` |
| 能力接口真实状态检查 | 通过；2.880 秒 | `monitoring-capabilities.log` |
| 前端全部组件测试 | 29 文件、256 项通过 | `frontend-final-tests.log` |
| 前端类型检查 | 通过 | `frontend-main-typecheck.log` |
| 前端构建 | 通过；包含预览异步响应修复 | `frontend-final-build.log` |
| OpenAPI 本地引用解析 | 通过 | `openapi-final.log` |
| nodeops／nodeconfig／pull 全包竞争测试 | 通过；483.852／1.721／4.277 秒 | `node-packages-final-race.log` |
| 主控完整测试包 | 807 个顶层测试通过，16 项专用环境检查跳过；2115.091 秒；最后的 preparing 修复另有定向竞争验证 | `controlplane-final-suite.log` |
| 真实 native 主控／SSH／systemd／子控联合测试 | 通过；924.79 秒 | `kernel-native.log`，内核输出 `kernel-lifecycle.KF57Lv` |
| 真实 Docker 29 联合测试首轮 | 未完成；隔离机约 30 分钟触发 systemd 总时限 | `kernel-docker29.log`，内核输出 `kernel-lifecycle.IFHj0y` |
| 真实 Docker 29 联合测试重跑 | 通过；1903.89 秒；整轮退出 0 | `kernel-docker29-final.log` |

真实 native 用例还验证了公共规则新增目录后文件事件进入子控 SQLite 和主控 PostgreSQL、响应丢失后的暂停及回退，以及主控容器 ID、进程、启动时间、登录和 CSRF 保持不变。隔离内核的指标存储端使用测试接收器；本阶段不据此宣称 VictoriaMetrics 端到端或容量认证。

桌面及 390×844 浏览器检查覆盖公共规则保存、批量差异、任务暂停、单独重新授权及改密表单校验；截图为 `monitoring-reauthorized-desktop.png`、`monitoring-reauthorized-mobile.png`、`monitoring-task-mobile.png` 和 `password-dialog-validation.png`。真实密码提交和会话撤销由隔离 PostgreSQL 接口测试验证。

## 集成中发现并修正的问题

- 公共规则读取使用只读事务，同时请求账号共享行锁，被 PostgreSQL 拒绝。已改为可持锁的一致性读取事务。
- 内部调用扫描节点后会携带公开规则投影；若再保存完整私有配置，错误地重新合并旧规则可能覆盖内部新值。可信 `Store.SaveNode` 现在忽略装饰投影，公开规则编辑继续走带备份的专用保存路径，并有实际 PG 回归验证。
- 已选但未执行的节点同样需要互斥，不能只保护已经创建的子部署。保存、移除、普通部署和全量恢复都检查持久预留。
- 备份恢复须先建表、按父子依赖导入，再应用恢复保护；旧版本迁移夹具须先移除授权子表。新增针对完整恢复的直接调用回归，拒绝跳过恢复保护继续远程任务。
- 早期完整竞争回归超过 18 分钟限制，且使用修复前的备份实现；该轮不是通过证据。修复后相关竞争测试及完整包回归分别记录，仍在运行的检查不提前记为通过。
- 页面公共规则版本变化时，迟到的旧预览可能重新显示；显式取消后也曾复用旧准备凭据。已用延迟响应回归验证修复，网络异常重试仍沿用原幂等凭据。
- Docker 29 首轮已执行公共规则实际下发、新目录事件、响应丢失后回退和中心不重启检查，但组合用例未结束便触发测试机的 30 分钟 systemd 时限，没有最终退出标记，不记为整轮通过。调整的仅是隔离组合测试总预算（Go 上下文 45 分钟、测试进程 50 分钟、systemd 55 分钟、模拟器 60 分钟），保留原单次操作时限，重新验收。

未完成的门禁不得记为通过；后续阶段在阶段一正式验收后继续。

## 阶段二：已确认实施约束

- 远程卸载与移除中心记录分开。仅处理具有完整归属及固定安装证明的 v3 native 服务或单容器，默认保留 SQLite、基线、证书、配置和恢复物料；不删除 Docker 数据卷或镜像。
- 卸载前保存实际运行及自启动状态，暂停采集并推进代次；禁用节点可以卸载，恢复不得自动启用。必须取得远端移除、保留清单和墓碑证据后才展示“已卸载”，响应不明保持待确认。
- 删除对象前持久写入精确意图，后续凭意图及墓碑续作，不能仅凭程序不存在推定成功。Docker 恢复允许生成新容器 ID，但必须由原固定配置、镜像及受绑定的重建回执证明归属。
- 部署历史遵循旧版归档语义：隐藏公开历史及删除日志，保留原任务、幂等回执、安装证明和恢复链；原任务 `updated_at`、`log_cursor` 和计划不得改写。
- 仅成功或已回退、超过 24 小时且无恢复／维护／配置／公共规则引用的记录可以归档。最新任务、最新成功基线、当前运行目标和公共规则尚未创建 child 的预留均受保护；预览受保护项不得在确认时自动变成可删除。
- 部署日志参与激活时间和采集就绪验证，不能对任何仍可重开的任务清日志。数据库恢复保留已完成归档，撤销未执行的删除授权；普通进程重启允许持久任务续作。

阶段一于 2026-11-01 完成本地验收。Docker 29 重跑完成自动续期、过期 SSH 恢复、名称变更／裁剪、CA 双根分发及独立换根确认；旧根采集身份被拒绝，新身份继续保存事件。整轮 `TestWebDeploymentKernelPublicAPIAndActualServices` 通过，保留首轮未完成的证据，不删除或掩盖失败。此后进入第二阶段；尚未完成的后续功能不属于阶段一完成结论。

## 阶段二：集成及验证记录

- 增加与安装分离的保留数据卸载任务。预览、SSH 凭据和指纹绑定实际安装目标，编辑弹窗草稿不能改变卸载地址、端口或运行方式；已禁用节点也可卸载，不要求原监控目录、扫描器或证书仍可运行。
- API 容器不需要 CA 私钥或签发能力即可准备卸载，但仍要求可用执行器、可信发布资料和 Vault。来源、远端证据、恢复引用及固定重装墓碑分别认证，数据库 JSONB 字段重排不会使有效回执失效。
- 远端操作前暂停本节点登记并推进代次；原已保存配置和启用意图不变。只有真实远端移除回执完成后展示已卸载。恢复原登记不会应用尚未部署的草稿；失败重装回退后，旧卸载任务不能跨越新的代次直接恢复，仍可使用墓碑创建新的重装任务。
- 历史删除只归档公开记录及删除日志，保留私有任务和恢复依赖。管理员预览与确认、逐项结果及刷新后续读已接入原版 UI；普通读者没有删除入口。
- 当前数据库结构为 41，覆盖 39→40→41 升级及完整备份恢复。历史删除恢复后撤销未执行授权，保留已完成归档。

| 检查 | 当前结果 | 证据 |
|---|---|---|
| 卸载来源、安全边界、权限和保存草稿隔离的实际 PostgreSQL 竞争测试 | 通过；19.494 秒 | `phase2-uninstall-security-race.log` |
| 卸载完成、显式恢复、重复卸载、回执认证和代次隔离 | 通过；17.971 秒；远端回执为显式测试夹具 | `phase2-reinstall-controller-final-race.log` |
| 历史删除及恢复保护的实际 PostgreSQL 竞争测试 | 通过；81.933 秒＋补充 6.083 秒 | `history-delete-race.log`、`history-delete-continuation-race.log` |
| 前端组件测试、类型检查和构建 | 31 文件、272 项通过 | `phase2-frontend-full-tests.log`、`phase2-frontend-integration-typecheck.log`、`phase2-frontend-build.log` |
| OpenAPI 检查 | 通过，4 项 | `phase2-openapi-tests.log` |
| Chrome 桌面及 390×844 窄屏 | 合成接口验收通过；169 条请求均使用 `/api/v3` | `phase2-browser-evidence.json` 及 `phase2-*.png` |
| native 真实 Linux 联合测试首轮 | 失败；卸载续作完成，显式恢复在远端 restore 阶段失败，不能计为通过 | `phase2-kernel-native-run.log`、内核输出 `kernel-lifecycle.TyGGnR` |
| 主控安装／恢复／网页准备／卸载／历史保护竞争回归 | 通过；238.546 秒 | `phase2-controller-final-regression-race.log` |
| nodeops 全包竞争回归（启动过渡修复前） | 通过；531.678 秒；不替代修复后验证 | `phase2-nodeops-final-race.log` |
| native 启动过渡确定性回归及保护条件 | 修复前两项失败；修复后通过，5.401 秒＋2.222 秒 | `phase2-native-exec-transition-red.log`、`phase2-native-exec-transition-race.log`、`phase2-native-exec-guards-race.log` |
| native 真实联合测试诊断轮 | 整轮失败；恢复已完成，按路径恰好一条的补采断言错误 | `phase2-kernel-native-diagnostic.log`、内核输出 `kernel-lifecycle.r0fvp0` |
| nodeops 修复后完整竞争回归 | 通过；559.612 秒 | `phase2-nodeops-after-exec-fix-race.log` |
| native 真实 Linux 最终联合测试 | 通过；478.15 秒，整轮退出 0；三次恢复及保留数据重装 | `phase2-kernel-native-final.log`、内核输出 `kernel-lifecycle.hyhauX` |
| Docker 29 真实 Linux 最终联合测试 | 通过；855.32 秒，整轮退出 0；Docker 29.8.2、containerd snapshotter、cgroup v2 | `phase2-kernel-docker29-final.log`、内核输出 `kernel-lifecycle.qTsKkG/guest-engine.txt` |
| 公共规则备份恢复及 38→当前版本迁移的补充竞争回归 | 通过；17.880 秒；修正旧夹具的硬编码版本和遗漏的后续表 | `phase2-backup-schema-regression-red.log`、`phase2-backup-schema-regression-green.log` |

第二阶段于 2026-11-01 完成本地验收。浏览器使用合成数据，不代替 PostgreSQL、SSH、systemd 或 Docker 29 的真实验证；真实内核失败的原始证据保留。随后进入第三阶段。

诊断轮的只读 SQLite 取证确认：同一路径正常产生独立的 create 与 scan 事件，两条均已被主控确认，完整性检查为 `ok`。测试已改为冻结卸载时未确认的事件 ID 集合，逐 ID 核对主控记录和子控确认，不把合法的扫描结果误判为重复事件。证据位于 `native-restored-event-evidence/`。

另有确定性测试证明，native `Type=simple` 服务在本次 start 成功后可能短暂仍暴露 systemd 的 exe／参数。修复仅允许本次从已证明停止状态启动后的有限只读复验；重试窗口两秒，命令仍受原阶段上下文约束。不重复启动，不放宽单元、程序、参数、运行和自启动归属校验，不给原已运行的进程此宽限。首轮现场的具体错误未被诊断文件捕获，因此不能仅凭这项修复断言首轮唯一根因已证实。最终内核用例增加重复卸载／恢复循环，继续验证。

已结束且保留的内核磁盘使用 zstd 无损压缩，经格式校验及解压 SHA256 对比后才移除未压缩副本；原日志、摘要、测试产物和取证资料保留。没有清理其他项目或 Docker 全局存储。

后续核查发现 Docker Desktop 的虚拟机仍持有已删除测试文件的句柄，导致空间不能回收。沿用用户此前明确允许重启本机 Docker Desktop 的授权，待所有测试结束后重启引擎；保留存储模式、镜像和容器，释放句柄后本机可用空间由约 3 GiB 恢复至约 28 GiB。测试用 PostgreSQL 17 的数据目录为 tmpfs，重新启动后按原测试配置初始化，只用于独立合成 schema；既有验证报告及归档不受影响。未操作生产或其他项目服务。

## 阶段三：开始实施

通知列表与详情仅公开绑定原始载荷摘要的受控文字投影，不返回原始供应商响应或任意 message。测试通知使用独立持久队列，绑定已应用设置、账号及 Vault；结果不明不自动重发。主 Agent 负责结构版本 42、生产者事务、路由、共享客户端及备份恢复；三个独立工作包分别负责投影查询、测试通知、原版风格页面。此处记录开始实施，不代表阶段三验收完成。

### 阶段三：完成记录

- 通知公开投影由可信生产者在事件／通知原事务写入，绑定 PostgreSQL `payload::text` SHA256，不根据载荷自报来源。无全量启动回填、不改写已有投影；缺失或摘要变化只展示受控未知原因。投影写入失败时事件事务回滚，不提前确认子控事件。
- 列表支持来源、精确收件人、状态及受控摘要关键词过滤，先过滤后分页。详情和逐次结果不返回私密原始载荷／供应商回执；失败尝试显示结果未知，ID及代次保留字符串精度。
- 管理员测试使用已应用配置，独立预览／队列及每通道冷却，参与原业务全局限速。每目标仅一次自动尝试；失去响应或发送租约时显示未知，不重发。配置和账号变更撤销未发送项，已获真实回执保留。无密钥仅关闭测试能力，业务通知继续运行。
- 数据库结构 42；升级前一致性备份、失败回滚和旧版快照恢复均验证。完整恢复撤销未使用预览、取消排队项、将发送中标为未知、保留已接受结果并清除旧工作器心跳。
- 原版风格详情与测试弹窗支持内部滚动及固定底部反馈；账号＋渠道范围仅持久化最后任务 ID，刷新查询原任务。文件事件手动首次查询不变。

| 检查 | 结果 | 证据 |
|---|---|---|
| 通知投影、详情、筛选及既有 stats 路由 PostgreSQL 竞争测试 | 通过；11.070 秒 | 通知投影独立工作包专项结果 |
| 新通知生产者事务及 41→42 迁移门禁 | 通过；7.803 秒 | `phase3-producers-migration-race.log` |
| 测试队列、授权、并发、持久限速和心跳 | 通过；70.446 秒 | `notification-tests-final-race.log` |
| 真实整库备份恢复、撤权、投影不变和维护清理保护 | 通过；24.397 秒 | `notification-restore-race.log` |
| 授权及配置最终定向回归 | 通过；6.829 秒 | `notification-final-validation.log` |
| 真实主控 all 角色启动、缺少可选测试密钥及退出 | 通过；4.645 秒 | `phase3-actual-runtime-race.log` |
| 通知／健康／迁移／历史／网站及备份综合回归 | 90 项通过；随后7项受测试PG磁盘满中断，原轮不计整轮通过；7项恢复后全部通过11.720秒 | `phase3-integration-regression-race.log`、`phase3-interrupted-regressions-retry.log` |
| ChannelSender → 本机TLS飞书模拟服务 | 成功及供应商拒绝均通过，不外发 | `notification-tests-final-race.log` |
| ChannelSender → 本机 SMTP | implicit TLS、STARTTLS各验证成功、错证书拒绝和响应丢失；6项竞争测试通过17.877秒 | `notification-smtp-race-recovered.log` |
| 前端类型、全部组件、构建及 OpenAPI/vet | 通过；33文件283项；嵌入前端已重建 | 主Agent集成运行结果、`phase3-frontend-validation.json` |
| Chrome桌面、390×844窄屏及刷新任务恢复 | 合成接口通过；35个v3请求，无旧接口、设置写入或请求失败；主Agent复核手机截图 | `phase3-browser-evidence.json`、`phase3-browser-requests.json`及10张`phase3-notification-*.png` |

综合回归中的 Linux 专用低空间测试在 macOS 上按平台条件跳过，不算该用例通过。测试 PG 的 1GiB tmpfs 在持续迁移压力下写满，已保留原失败日志。仅重建本任务合成 PG 环境，改用 3GiB tmpfs、128MiB WAL 和30秒检查点；未清理 Docker 全局数据，未操作生产。SMTP受环境中断的两次日志也保留，完成恢复后才记通过。

阶段三于 2026-11-01 完成本地验收。随后进入第四阶段；后续阶段仍未验收。


## 阶段四／五：历史续作检查点

- 独立宿主看门狗已完成真实 networkless Linux/systemd 验收：`phase4-kernel-watchdog-sixth.log`，`kernel-lifecycle.KNroRN`，446.03 秒，完整退出 0。覆盖跨进程 Unix 身份认证、实际 API、PostgreSQL／VictoriaMetrics 故障、本机 SMTP／飞书模拟通道、启动宽限／防抖、配置事务冻结与响应丢失、跨进程限速，以及 WAL 一致性备份／冻结恢复。前五轮失败记录保留；不以此次通过替代其他阶段验收。
- 双时序库写入、设备清单、应用后的采集周期与保留协调器已分别完成实际 PG／VM 定向竞争测试。保留协调器的 Docker 操作此前仍为受控夹具；真实 Docker 29 物理保留和主机重启覆盖正在补齐，不能计为已经通过。
- 设置页区分“期望保留”和“实际引擎保留”；没有已认证新鲜宿主证据时不开放修改。保存不生效；应用反馈明确等待宿主备份及引擎确认。相关十项页面测试通过：`phase4-retention-ui-tests-final.log`；错误启动路径首轮失败日志另存。
- 阶段五已实际开始：稳定源身份、多次 SQLite 一致性快照、完整键集差量、真实写入者冻结、YAML 节点映射、只读影子采集与目标变更日志已实施。影子采集仅使用 Capabilities／ReadMetrics，不 Fetch／ACK 事件，不推进运行游标；实际 PG＋mTLS 测试通过 17.577 秒：`migration-shadow-race.log`。
- 新迁移会话接入数据库迁移保护，不能仅靠报告里的 protected=true。目标变更日志核验基线、全部变更摘要、触发器、分区与真实当前行收敛；密钥、路径和业务明文不进入公开报告。
- 数据库结构 46／47 的本地增量包括迁移日志、节点映射、影子证据、最终业务映射和历史指标重放。备份恢复重新设置迁移恢复保护；存在变更日志时安装数据库层不可绕过的写保护。恢复 JSON 非空列中的 JSON null 时保留原标量，不转换为 SQL NULL。
- **尚未完成：**旧单库到双库的显式升级、实际双库保留／重启验收、备份新维护程序的真实 systemd 升级验收，以及最终业务域映射／无损反向回补／切换和灾备协调。阶段四、五均不记为完成。

本检查点没有 Git 暂存、提交、推送、发布、生产连接或线上数据导入。


## 阶段四／五：进一步验收记录（2026-11-01）

本段更新上方历史检查点；阶段四、五仍在隔离验收中，不据此宣布整轮完成。

| 检查 | 当前结果 | 证据 |
|---|---|---|
| 真实 systemd 签名备份维护程序升级及完整恢复 | 通过，137.03 秒 | `phase4-kernel-backup-upgrade-first.log`、`kernel-lifecycle.8GwNH4` |
| 真实旧写入者冻结 | 通过，实际 systemd 与 Docker | `phase5-kernel-freeze-fifth.log`、`kernel-lifecycle.AT5XxE` |
| Prometheus 实际查询、缺失样本与 VM 重放 | 通过，35.443 秒；37 次查询、42 有值、6 缺失、48 健康记录 | `migration-prometheus-actual-race.log` |
| 最终映射对实际目标 VM 再核对 | 通过，26.580 秒；目标更换、投影篡改或实际删样本均拒绝切换 | `migration-cutover-metric-race.log` |
| 非空旧节点、实际 mTLS、激活机械行像和 v2 SQLite 反向映射 | 通过；集成 66.188 秒，最终节点 17.865 秒 | `phase6-cutover-integrated-race.log`、`phase6-cutover-nodes-final-race.log` |
| 新结构 52 的封存时间、旧结构升级、真实 PG 恢复保护与日志回放 | 通过，37.225 秒 | `phase6-schema52-journal-restore-race.log` |
| 前端类型、组件与构建 | 通过；38 文件 326 项，构建 5.21 秒 | `phase6-frontend-typecheck-final.log`、`phase6-frontend-tests-final.log`、`phase6-frontend-build-final.log` |
| 单库显式升级为双库的真实内核检查 | 第二轮总测试预算超时；第三轮运行中，不计通过 | `phase4-kernel-metrics-upgrade-second.log`、`phase4-kernel-metrics-upgrade-third.log` |
| 双库主机实际两次启动 | 第二轮因测试在默认备份时间前要求已生成备份而失败；经正常设置接口使备份到期后待重跑 | `phase4-kernel-dual-boot-second.log` |

切换新增严格核对：导入的加密旧 YAML 必须与最终冻结的同源配置原字节一致；只读影子结果不足以替代激活时新鲜的 mTLS 验证。整批结束仍重新检查样本新鲜度，缺少或过期保持保护。已认证机械行像仅允许导入节点由禁用暂存变为其原启用状态，不允许借此忽略任意配置、凭据或节点变化。

灾备恢复的非空 Agent／代次协调和真实宿主隔离仍在补充最终组合验收。完整 VM 回退归档正在实现和实际双库验证；业务 SQLite 投影本身不能授权最终回退。恢复与操作顺序见 [V3-LEGACY-MIGRATION-RUNBOOK.md](V3-LEGACY-MIGRATION-RUNBOOK.md)。

存储维护只处理本任务归属明确、已结束的测试证据：失败的合成 guest 磁盘回收前保留 SHA256、大小及原因；本机系统盘上的一份已完成压缩证据无损搬到外置任务目录并校验 SHA256，原位置留存 `guest.ext4.archive-location.json`。没有全局清理或重启 Docker，没有生产连接。
