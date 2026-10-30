# v3 本地基础验证记录

最近验证日期：2026-10-20（此前基础验证于 2026-10-17 完成）。状态：基础重构已进行本地验证，完整 v3 尚未完成。本记录不代表发布、生产升级或万台容量认证。

## 环境和方法

- macOS arm64 开发环境，Go 1.26；Docker Desktop 运行隔离 PostgreSQL 17 和 VictoriaMetrics v1.128.0，仅绑定回环地址。
- PostgreSQL 每项测试创建随机 schema，结束时删除，连接配置为临时测试库。VictoriaMetrics 使用随机节点标识。
- Linux amd64 Agent 和子控持久记录工具的测试在已有扫描工具镜像内运行，网络禁用；主控集成测试仅连接独立 PG／VM 测试网络。这是跨架构容器验证，不等同于独立 Linux 物理机性能测试。
- 飞书及邮件工作器使用模拟发送器。既有 SMTP 协议测试使用隔离服务器，不连接业务飞书或真实邮箱。
- 可复现脚本为 `scripts/verify-v3-foundation.sh`，自行创建并清理测试容器和匿名卷。已实际运行成功；现已把 Linux 主控测试纳入同一脚本。

测试镜像摘要：

| 镜像 | SHA256 |
|---|---|
| postgres:17-alpine | `b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24` |
| victoriametrics/victoria-metrics:v1.128.0 | `c27e736a8aff888cf30c4f20ec648b767358694993d87e89afc6bf80f28991da` |

这些摘要用于本地测试复现，生产版本与资源配置尚未选型和验收。

## 已执行项目

| 项目 | 结果 | 说明 |
|---|---|---|
| Go 全量测试 | 通过 | 覆盖现有 v2 包；无测试数据库环境变量时，外部存储集成用例会明确跳过 |
| 真实 PostgreSQL／VictoriaMetrics 集成与 `-race` | 通过 | 最近完整运行 207 项通过；4 项上传脚本仅在显式 Linux 容器执行，另 2 项 Compose 验证单独显式执行，均已实际通过；末次事务锁顺序及并发补充检查另有记录 |
| PostgreSQL 事务出箱及去重 | 通过 | 通知插入失败则事件和去重键回滚；中心确认仅在事务提交后发送 |
| 确认丢失和事件永久拒绝 | 通过 | Agent SQLite 重读不重复存事件；错误身份事件单独记录，正常事件继续 |
| 分片与代次 | 通过 | 竞争租约、续租、过期接管、旧代次和错误分片写入被拒绝 |
| 部署验收即时采集 | 通过 | 正常间隔一小时仍能通过实际调度及时采集；只唤醒持有分片的对应节点版本，重复唤醒合并、慢请求不积压；450 个有效目标跨分页无遗漏 |
| 10,000 条登记调度 | 通过 | 单工作器加载全部登记，增加第二工作器后分配 5,000 条；未建立 10,000 条真实节点连接 |
| 节点变更保护 | 通过 | 停用或修改节点后旧任务不能写入；公开字段编辑保留私有配置 |
| 写操作防重和审计 | 通过 | 12 个并发相同幂等请求只产生一次保存及一条审计，版本冲突回滚 |
| 指标写入与回放 | 通过 | VM 失败不推进游标，成功后提交；真实时序库导入与查询核对 |
| 指标缺失和故障分区 | 通过 | 首样本和 CPU 计数重置不写零速率；指标恢复不清除事件故障 |
| 双通道通知 | 通过 | 独立发送、失败重试、关闭暂停、持久限流、工作器替换及顺序保护 |
| 会话与密码重置 | 通过 | 跨 API 实例复用会话；退出／重置撤销；数据库故障返回 503 而非 401 |
| mTLS、HTTP/2 和旧路由 | 通过 | 错误证书角色被拒绝；Linux 实际监听器共用 gRPC 与 `/metrics`，无证书连接失败 |
| SQLite 一致性归档与续作 | 通过 | 原库只读；中途失败从原快照继续；保留中文、BLOB、大整数及负数／零主键 |
| 网站领域 PostgreSQL 持久化 | 通过 | 与 v2 共用状态机，验证连续失败、恢复、持久通知顺序及出箱失败整笔回滚 |
| 网站任务与批量软删除 | 通过 | 多工作器领取、全局并发上限、代次接管、旧结果保护、显式选择及版本冲突整批拒绝 |
| PostgreSQL 版本与备份恢复 | 通过 | schema 1／2／3／4→5 迁移前快照；备份失败不升级；校验、私有权限、符号链接、空库恢复及自增序列 |
| 部署任务与恢复协议 | 通过 | 同节点并发互斥、请求防重、过期租约、确认丢失补交检查点、失败恢复、回退、新事件保留及检查失败不锁死节点；远端操作使用模拟运行器 |
| SSH 凭据与密钥轮换 | 通过 | AES-GCM、节点及修订号绑定、篡改拒绝、独立密钥文件、替换与轮换、备份恢复、不在日志和审计留明文 |
| 隔离 SSH 连接 | 通过 | 有效任务解密凭据连接本机测试 SSH 服务；固定指纹校验、错误指纹及失效任务拒绝；不执行真实安装 |
| 子控持久操作记录 | 通过 | SQLite WAL／FULL 意图、跨连接操作锁、先写新代次、旧代次／退役任务拒绝；强制退出后从持久记录核对，未重复执行模拟动作 |
| SSH 回包丢失与恢复 | 通过 | 实际 SSH 协议连接真实子控 SQLite；模拟备份动作完成后丢弃响应，继续任务只补交 PG 检查点，不重复动作；安装处理器仍为测试替身 |
| 签名发布清单 | 通过 | Ed25519、大小限制、平台／协议、重复键／未知字段拒绝、不可变镜像摘要；任务绑定清单及 native／Docker 目标摘要，换工具或清单拒绝 |
| 工具文件准备 | 通过 | 受租约和指纹保护的 SSH 传输；本地文件大小／摘要／权限校验；Linux 实际脚本验证截断拒绝、相同文件重用、符号链接拒绝和临时文件清理；未启动 Agent 服务 |
| Native 工具包准备 | 通过 | 有界解包、路径／链接拒绝、完整清单、版本／ELF／规则验证和原子发布；实际 v2 扫描工具包仅作为包验证夹具，未安装 v3 服务 |
| Docker 镜像与归档证明 | 通过 | 固定摘要及 Linux amd64，签名归档／配置摘要绑定，模拟断网回退和无 RepoDigests 导入；真实 Docker-save 导出包解析通过，未执行真实 Docker load／服务切换 |
| SSH 工具包与镜像归档传输 | 通过 | 带签名摘要的私有文件；截断／篡改拒绝、缓存复用及 Linux 实际上传脚本；不改变运行配置 |
| 私有运行配置包 | 通过 | PG 源版本／摘要绑定、私有证书与规则、任务摘要绑定、SSH 传输及全部生成文件重放校验；不把主控凭据放入包 |
| systemd／Compose 定义 | 通过 | 绑定资源、程序及配置路径；宿主机只读挂载、独立可写探针、固定镜像与离线配置 ID；真实 systemd 252、Compose 解析，以及停止状态隔离容器的路径检查 |
| 生成配置的真实 Agent 启动 | 通过 | Linux 实际 Agent 使用准备配置与真实扫描工具，核对 mTLS、加载回执、就绪、目录覆盖及文件事件；重启后原 ID 未确认事件继续读取和确认；新增真实写入锁、停写快照、保留新事件及确认状态的回退补发验证；未执行服务管理切换 |
| 原服务归属及停写控制 | 通过 | native 单元、加载状态、可执行路径；Docker 不可变 ID、项目及完整 v3 挂载；整组先证明再操作，保留原启用／运行／重启策略；实际服务控制使用测试替身，未开放安装切换 |
| 实际采集器部署验收 | 通过 | 实际 mTLS／HTTP2 读取配置回执、指标及事件确认；PG 事务门禁拒绝不匹配、旧观测、旧样本、租约失效和链路失败；取消等待可恢复；尚未启用正式安装运行器 |
| 目录覆盖和扫描就绪门禁 | 通过 | 检查根监听数量、规则绑定、进程／扫描心跳和启用引擎实际自检；拒绝重复、带标签和无效标量；真实 Agent／YARA／inotify／PG 验证目录丢失阻止 finalize，不推进生效版本 |
| 扫描自检隔离和实际 clamd | 通过 | 私有目录排除实时与补扫，自检后清除快照；链接／权限失败拒绝；真实私有 clamd 和无害签名验证扫描及停服失效，不创建业务事件；未验收生产病毒库或跨部署方式安装 |
| schema 3→4 及证据恢复 | 通过 | 先一致性备份再新增验收表，旧库可恢复；备份恢复不沿用瞬时健康证据 |
| 停写前失败的无变更恢复 | 通过 | 持久尝试和独立停写意图证明未改动服务；外部改动导致 capture 前失败可结束任务，不运行主机命令；停写后丢失 capture、损坏或换绑定拒绝 |
| 已删除进程的健康判定 | 通过 | 恢复仍可识别并停止损坏目标；激活及回退完成核对不能接受已删除程序 |
| native 私有阶段编排 | 通过 | 实际子控 SQLite Journal 贯通正向及恢复阶段；响应丢失续作、不重复启动、备份中断与资源验收失败回退、完成回执重验及活动客户端锁；服务管理为替身，正式命令仍只支持预检查／准备 |
| native 私有激活与恢复 | 通过 | 原子单元／指针、精确启动参数、响应丢失续作、原启动状态、相同程序／配置不同任务、损坏目标可回退；服务管理为替身，未接入公开执行器 |
| Docker → native 私有切换 | 通过 | 单 Agent Docker／旧 v3 原容器保留、Journal 续作、原对象／策略／指针恢复、移出并恢复旧 Compose、当前事件保留；systemd／Docker 服务管理与内核为替身，未作真实跨方式服务验收 |
| 原配置原子恢复 | 通过 | 缺失配置先私有暂存、校验后无覆盖发布；取消、损坏源、残留暂存、已有文件和链接拒绝；不将失败拷贝作为活动文件 |
| 快照发布前的中断恢复 | 通过 | 停服前记录原数据库存在性；未激活时可按持久配置恢复原服务，原库丢失则拒绝；激活后缺失快照、损坏已发布快照及无存在性证据不能绕过 |
| 补发回执重验 | 通过 | 原服务未运行时仍核对当前待确认事件，缺失 JSONL 可重建，损坏则禁止启动；已恢复运行不重复停止 |
| 服务操作锁继承 | 通过 | 父进程超时／退出后子进程仍持锁；真实 systemctl 对隔离测试总线的调用验证 FD 继承，不代表完整管理器验收 |
| native → Docker 私有切换 | 通过 | 原单元停用／移出及管理器重载、Journal 续作、原 v2／v3 单元及指针恢复、新增数据保留；服务管理及内核为替身，未作真实跨方式验收 |
| native 内核资源核对 | 通过 | v1／v2／混合挂载、加载值、PID 重用、软／硬句柄及 CPU／内存失败用例；独立 Docker 容器验证真实 256 MiB、1.25 CPU、65536 句柄读取，未验收实际 native 资源落地 |
| Docker 本机只读验收 | 通过 | 精确容器身份／挂载、配置绑定的引擎资源及隔离策略、进程稳定性与共享内核证据；真实隔离容器加载值及内存修改拒绝通过，完整 Agent 在宿主机的身份／内核联合验收及安装恢复仍待完成 |
| 内部 Docker 激活／恢复方法 | 通过 | 持久意图、独立任务项目、保留原对象、丢失响应续作、原 v3 对象恢复、当前事件／基线／任务及吊销状态保留；引擎替身用例及嵌套引擎实际切换分别验证，内部已接入 Journal；正式运行器仍关闭 |
| Docker 私有阶段与真实切换 | 通过 | SQLite Journal 重开／代次／回执重验、响应丢失、锁与损坏拒绝；嵌套引擎实际运行 Agent、mTLS 配置回执、文件事件及资源异常后的原容器／当前数据恢复；预检查为替身，完整内核成功验收未覆盖 |
| 当前 CLI 子进程生命周期 | 转译环境通过 | 执行本次编译的 CLI、真实 mTLS、文件事件、SIGTERM 及保留未确认数据回退；Rosetta 路径只在测试替身适配，严格原生进程归属测试明确跳过 |
| 子控一致性快照及续作 | 通过 | 私有恢复意图先于停止，SQLite 基线／扫描／待确认事件，JSONL、权限、链接、空间不足、损坏清单及重试复用；原数据库与已发布快照不覆盖 |
| 回退待确认事件补发 | 通过 | 原事件 ID、大整数、新增事件、已确认状态、永久拒绝记录、100 条／4 MiB 分批；文件落盘后事务失败可复用，部分完成准确报告；未连接正式服务恢复 |
| 证书签发与吊销 | 通过 | 独立 Node／Collector 身份、用途／SAN、CA 与叶证书往返、签名 CRL／版本／过期拒绝；真实 HTTP/2 已连接会话吊销、重新签发及并发读写 |
| 离线证书工具及持久策略 | 通过 | 12 项 Linux 证书测试，初始化／签发／吊销／续发、0600／0700、链接拒绝、文件锁与中断续作；新增跨重启版本下限、过期下限续发、多进程共享及状态损坏拒绝；实际 Linux CLI 冒烟通过 |
| 只读子控预检查 | 通过 | 缺失目录、空间估算、TCP 监听表缺失／IPv6 情况及结构化错误；未知不伪报端口空闲，不修改防火墙或安装 Docker |
| 部署日志接口 | 通过 | 登录、CSRF、只读权限、任务及日志游标；隐藏私有计划与凭据，未接通执行器的写操作不创建空任务 |
| 网站／账号领域映射 | 通过 | 保留 ID、状态及有效会话；中断后续作；坏摘要及非空目标拒绝；迁入网站不检测、不发通知 |
| 过期认证数据和审计 | 通过 | 每批最多 500 条、两秒预算；有效会话和最近 365 天审计保留 |
| OpenAPI 合约 | 通过 | YAML 解析和已实现接口清单测试；文档由登录后的 API 直接提供 |
| 前端类型检查 | 通过 | `npm run typecheck` |
| 前端单元测试 | 通过 | 12 个文件、56 项；含网站版本写入、明确选中软删除及 v3 传输模型测试 |
| Vite 构建 | 通过 | 输出到现有 Go 嵌入资源目录；现有页面仍使用 v2 API |
| Linux amd64 | 通过 | 中心程序静态编译和 20 项 Agent 测试运行，含真实监听器重读吊销列表后拒绝现有采集连接，以及新监听器拒绝旧列表 |
| Linux 主控业务补充运行 | 通过 | 最新在独立测试网络连接临时 PG／VM，实际运行 81 项主控测试，无跳过；不包含万台性能验收 |
| Linux 子控工具与断线冒烟 | 通过 | 最新 Linux 子控 100 项通过；5 项专用用例在 systemd（2）、Compose（2）、内核限制（1）阶段分别通过；另 1 项严格原生进程用例因 Rosetta 明确未验。实际 CLI 在 SIGHUP 后保留结果并持久化，未支持的切换阶段明确拒绝 |
| Linux 备份恢复 CLI 与网站角色 | 通过 | 两个全新隔离数据库，实际初始化、创建测试管理员、备份、空库恢复、改密及网站工作器启动／退出 |
| Linux CLI 冒烟 | 通过 | 禁网容器内初始化并读取隔离配置，非交互默认 single，明确输出尚未安装 |
| 原未提交修复 | 保留 | 六个相关文件 SHA256 与本轮开始时一致 |

前端已有历史清理测试会输出 Element Plus 分页用法弃用提示，测试通过；本轮未因此修改无关页面逻辑。

## 验证日志

本地原始日志在 `.cache/verification/v3/`，未加入 Git：

- `reproducible.log` 和 `run.5MrKVD/`：可复现脚本实际执行记录，含 Linux Agent 运行和前端输出。
- `race-final.log`：补齐故障分区、派生历史和私有配置保留后的最终真实存储及竞争检查。
- `go-all-final.log`：最终 Go 全量测试。
- `deployment-final.log` 和对应的 `run.*/`：部署任务／SSH 凭据及恢复保护补充后的 66 项竞争测试、全量 Go、Linux 主控／Agent 运行与前端最终验证。
- `node-runtime-final.log`／`run.Pn4d9w/`：子控持久记录和 SSH 断线恢复的初次完整验证。
- `node-runtime-release-final.log`／`run.rPAokJ/`：加入签名清单、任务绑定、工具文件传输及监听表缺失保护后的最终完整验证；含 89 项竞争测试通过、Linux 主控 69 项、子控工具 15 项、Agent 18 项、实际 CLI 断线冒烟，以及全量 Go／前端检查与构建。
- `archive-pki-final.log`／`run.bIVCBx/`：native 包与 Docker 归档证明、签名传输、离线证书工具及在线吊销校验后的完整验证：115 项竞争测试通过、3 项仅 Linux 用例在 Linux 全部通过；Linux 主控 76 项、子控工具 29 项、证书 8 项、Agent 19 项均无跳过；实际 CLI、全量 Go、前端 56 项测试及构建通过。
- `node-config-final.log`／`run.Ngmc34/`：私有节点配置包和精确整数版本回执验证，124 项竞争测试通过；Linux 主控 80 项、子控 32 项、证书 8 项、Agent 20 项，以及前端检查、56 项测试和构建通过。
- `service-persistent-final.log`／`run.sA9ONk/`：服务定义与持久吊销下限的完整回归，134 项竞争测试通过；Linux 主控 81 项、子控 38 项、证书 12 项、Agent 20 项。4 个仅 Linux 上传脚本、2 个 Compose 用例和 1 个 systemd 用例均在对应环境通过；实际 CLI、全量 Go、前端 56 项测试及构建通过。`service-config-unit-final.log` 记录配置校验用例改为自包含夹具后的补充竞争验证。
- `service-systemd-linux.log`、`service-validator-build.log`、`service-agent-linux.log`：systemd 252.39 校验工具构建／解析及实际 Agent 启动补采的独立验证；验证镜像仅保存在本机，未发布。最新全套运行也包含这些检查。
- `transition-foundation.log`／`run.nGpu70/`：停写、快照及回退数据保护的完整回归，158 项竞争／真实存储测试，Linux 主控 81 项、子控 62 项、证书 12 项、Agent 20 项；外部 systemd 1 项／Compose 2 项、CLI、全量 Go、前端 56 项、类型检查及构建通过。
- `transition-final-race.log`、`transition-nodeops-linux-final.log`、`transition-go-all-final.log`、`transition-vet-final.log`：末次补充活动旧包装服务／sidecar 拒绝及 Docker 转 native 归属保护后，子控竞争检查 62 项、Linux 子控 65 项，以及全量 Go 和 vet 检查通过。旧包装服务和活动 sidecar 的实际接管尚未实现，测试验证明确拒绝而非完成迁移。
- `native-resources-foundation.log`／`run.cPi0XC/`：本轮完整回归，181 项竞争／真实存储测试；Linux 主控 81、子控 86、证书 12、Agent 20；外部 systemd 2、Compose 2、真实内核限制 1 项，前端 56 项、类型检查、构建和 CLI 通过。amd64 原生进程用例在 Rosetta 环境明确跳过，另设转译生命周期用例通过。
- `native-recovery-final-race.log`、`native-recovery-nodeops-linux-final.log`、`native-recovery-go-all-final.log`、`native-recovery-vet-final.log`：随后补齐快照发布前中断恢复、原数据库存在性保护及补发回执重验；子控 87 项竞争检查、Linux 91 项、全量 Go 和 vet 通过。前端及外部工具逻辑未变，沿用完整回归证据。
- `native-journal-final-race.log`、`native-journal-nodeops-linux-final.log`、`native-journal-go-all-final.log`、`native-journal-vet-final.log`：将私有 native 方法接到真实子控 Journal，并补齐已完成回执重验、预检查归属拒绝、快照与停写状态区分；子控 96 项竞争检查、Linux 100 项、全量 Go 和 vet 通过。默认命令、SSH 运行器与公开执行器保持关闭。
- `readiness-recovery-foundation-final.log`／`run.Y1UqEq/`：补齐实际采集器证据门禁、schema 4、停写前无变更恢复及已删除程序健康拒绝后的完整回归：207 项竞争／真实存储测试；Linux 主控 88、子控 105、证书 12、Agent 20；外部 systemd 2、Compose 2、实际内核读取 1 项。Go 全量、前端 56 项、类型检查、构建及 CLI 通过。子控 6 项跳过为外部专用检查及 Rosetta 下无法证明的原生进程用例，外部检查另行实际通过；原生 systemd 服务安装仍未验收。
- `readiness-recovery-final-race.log`、`readiness-recovery-locks-final.log`、`readiness-controlplane-linux-final.log`、`readiness-recovery-vet-final.log`：末次锁顺序修正后主控／子控 184 项竞争检查、2 项迁移及并发补充检查、Linux 8 项针对性检查和全量 vet 通过。补充竞争检查的额外跳过项是没有指定 VM 地址的真实 VM 用例，完整回归中已运行。`readiness-recovery-result.json` 汇总日志摘要、原有六项修复保留核对及未发布边界。
- `readiness-recovery-foundation.log` 为已定位的旧通知断言误判记录：时间中的“28（北京时间）”触发了节点名匹配；仅将测试断言限定到服务器名称行后，末次完整回归通过，通知实现未改动。
- `collection-wake-final.log`／`collection-wake-controlplane-linux.log`：即时采集专项 7 项在 macOS 竞争检查及 Linux amd64 均通过，包含真实 mTLS、事件确认、PostgreSQL 和跨页目标查询。正常间隔设为一小时；没有执行真实节点安装。
- `collection-wake-controlplane-race.log`／`docker-readiness-nodeops-race.log`：本轮主控 89 项、子控 106 项竞争检查通过；前者 5 项外部存储／Linux 专用用例跳过，后者 2 项 Compose 外部用例跳过。最后新增的配置绑定及分页用例另由末次专项检查覆盖。
- `collection-docker-focused-final.log`／`collection-docker-nodeops-linux.log`／`collection-docker-kernel-linux.log`：最终 Docker／native 资源专项 15 项通过；Linux 子控 105 项通过、11 项专用环境用例明确跳过；独立受限容器的共享内核读取器实际通过。专用用例的旧完整运行结果仍见 `run.Y1UqEq/`，本轮没有重复执行全部工具包与 systemd 外部检查。真实 Docker 测试只启动短时 sleep，不挂载业务数据、不运行 Agent。
- `collection-docker-go-all.log`／`collection-docker-vet.log`：本轮全量 Go 测试和 vet 通过；本轮未修改前端，沿用前次前端检查结果。六个原有修复文件 SHA256 与 `preserved.json` 一致。结果汇总见 `collection-docker-result.json`，仍未发布或操作生产。
- `docker-transition-nodeops-race-final.log`：内部 Docker 激活／恢复方法及共用配置恢复方法的子控竞争检查 113 项通过，3 项外部专用检查明确跳过；其后的任务对象查找加固由 `docker-transition-ownership-final.log` 的 9 项竞争检查及 `docker-task-orphans-final.log` 的 1 项专项检查覆盖。
- `docker-transition-nodeops-linux-final.log`：最新 Linux amd64 子控 115 项通过、11 项外部环境检查明确跳过；包含原 v3 同配置不同任务的精确对象恢复及未记录改名／重复项目拒绝。Docker 命令是服务管理替身，不能当作真实 Docker 引擎切换验收。
- `docker-transition-go-all-final.log`／`docker-transition-vet-final.log`：末次全量 Go 测试和 vet 通过。`docker-transition-result.json` 记录日志摘要及六个原有文件保护核对；公开部署接口仍关闭，未发布、未提交 Git、未修改生产。
- `native-process-cli.log`、`native-kernel-resources.log`、`native-systemctl-fd.log`：本轮独立故障定位及定向运行；最终结果以完整回归和上述补充日志为准。
- `preserved.json`：原有六个未提交修复文件的摘要基线。
- `completion-race.log`、`completion-go-all.log`、`completion-agent-linux.log`：本轮网站领域、迁移、备份恢复、全量 Go 与 Linux Agent 补充验证。
- `completion-control-linux.log`、`completion-cli-linux.log`：Linux 主控业务测试和完整命令入口的隔离数据库冒烟验证。

可手动指定自己的**隔离库**运行专项集成测试：

```bash
WEBSCAN_V3_TEST_DSN='postgres://测试账号@127.0.0.1:测试端口/测试库?sslmode=disable' \
WEBSCAN_V3_TEST_VM='http://127.0.0.1:测试端口' \
go test -race ./internal/controlplane ./internal/nodeops ./internal/nodeconfig ./internal/nodepki ./internal/pull ./api/control/v3 -count=1 -v
```

## 尚未实施或验收

以下内容不能据现有测试宣称完成：

- 旧网站通知依赖和合并策略，以及服务器告警、部署任务、配置备份和清理的完整 PostgreSQL 迁入；网站／账号领域映射不能替代全部业务迁移。
- 现有完整 Vue 后台切换到 v3；当前只交付传输模型，不包含新版页面端到端交互验收。
- 单中心安装编排、证书完整生命周期与跨机发行记录、SSH 密钥初始化及管理接口，以及 native／Docker 实际运行器。配置包、服务定义、独立数据中的吊销下限和实际 Agent 启动已完成隔离验证；正式信任密钥交付、证书自动分发／轮换、完整旧部署归属兼容、Docker 完整内核成功验收及正式 SSH／主控编排仍未完成；内部激活／恢复、资源核对、停写、快照及补发方法不等于正式安装运行器；还需原生 amd64 systemd 运行环境验收。
- 全部旧节点影子采集、配置版本下发、生效确认、停写增量迁移及保留新增数据的回退。
- Patroni＋etcd 故障转移、同步复制、防脑裂、高可用入口、VictoriaMetrics 集群双副本及拓扑转换。
- 10,000／20,000 实际节点、每节点 200 活跃时序、100 活跃用户、持续和突发事件负载、72 小时稳定性与资源报告。
- 三台独立机器单机故障后 60 秒内接管、磁盘不足和跨机网络分区的完整故障演练。

用户确认暂时没有三台独立隔离测试机，当前只进行本地实现和容器验证。生产环境未用于测试，也未操作发布、生产升级或子控迁移。

本轮网站及数据库备份边界见 [网站迁移说明](V3-WEBSITE-MIGRATION.md)，任务和加密凭据边界见 [部署任务说明](V3-DEPLOYMENT-STATE.md)，证书工具及未连接的生命周期见 [证书说明](V3-PKI.md)。发布版本仍保持 v2.0.46；完整 v3 的发布条件尚未满足。

本轮创建的临时数据库容器和匿名卷已清理；其他已有开发容器保持原样。

## Docker 阶段编排与隔离引擎复现

运行 `scripts/verify-v3-docker-lifecycle.sh`，需要本地 Go、Python 3、Docker，以及缓存的 Linux amd64 Agent 测试镜像。脚本编译当前本地测试程序、复用既有扫描工具，启动固定摘要的短时 Docker-in-Docker；无业务目录／宿主 Docker socket 挂载、无对外端口、无网络。只按本次创建的容器 ID 清理。输出资料位于 `.cache/verification/v3/docker-lifecycle.*/`。

该测试实际验证内部准备、创建、启动、mTLS 配置回执、文件事件、启动响应丢失后的 PID／启动时间保持，以及真实资源参数漂移后的原对象回退和当前事件保留。预检查使用替身；并未通过成功的完整本机内核验收、推进中心生效版本或开启生产执行器。ARM／Rosetta 环境不能替代原生 amd64 验收。

本轮结果：

- `docker-lifecycle-nodeops-race.log`：子控 125 项竞争检查通过、3 项专用环境用例跳过；后续挂载顺序修复由 `docker-lifecycle-focused-race-final.log` 的 19 项竞争检查覆盖。
- `docker-lifecycle-nodeops-linux-final.log`：最终 Linux amd64 子控 126 项通过、12 项专用环境用例明确跳过。
- `docker-lifecycle.OALp9c/lifecycle.log`：复现脚本完成真实嵌套引擎切换、mTLS、实际事件、响应丢失和数据保留回退。
- `docker-lifecycle-go-all-final.log`、`docker-lifecycle-vet-final.log`：全量 Go 测试与 vet 通过。
- `docker-lifecycle-result.json`：测试日志摘要、保留文件摘要及未完成边界。

## Docker → native 与配置恢复补充

- `docker-to-native-nodeops-race-final.log`：子控 137 项竞争检查通过、3 项专用环境用例跳过；配置恢复后续变更另由最终 `docker-to-native-recovery-race-final.log` 的 38 项竞争检查覆盖。
- `docker-to-native-linux-after-atomic.log`：最终 Linux amd64 子控 138 项通过、12 项外部环境用例明确跳过，包含配置原子恢复和全部 Docker → native 用例。
- `docker-to-native-go-all-after-atomic.log`、`docker-to-native-vet-after-atomic.log`：最终全量 Go 测试和 vet 通过。
- `docker-to-native-result.json`：日志和变更文件摘要、原保留文件核对及未完成边界。

切换覆盖旧单容器、旧 v3 原容器、停止状态与重启策略、捕获后快照前中断、资源失败、响应丢失、精确指针与对象恢复、当前待确认事件，以及旧 Compose 退役／恢复。未记录改名、丢失对象、外部配置修改、名称冲突及原容器误启用均拒绝。恢复配置改用私有暂存、完整校验和无覆盖原子发布，取消或损坏源不产生半个活动文件。

本组服务管理与内核证据均为替身，使用真实 SQLite、文件和操作锁。它不代表真实跨方式安装验收，不开启生产处理器；native → Docker 的后续私有实现及验证见下节；活动旧 sidecar／包装服务接管、实际 systemd 与正式 SSH／中心编排仍需完成。

## native → Docker 补充

- `native-to-docker-focused.log`：8 项专项测试通过，涵盖完整 Journal 阶段、单元停用／移出、管理器重载、丢失响应继续、旧服务启停状态、原 v3 指针、捕获后快照前恢复、目标损坏、资源失败及新增事件保留。
- `native-to-docker-race.log`：子控竞争检查 146 项通过、3 项仅 Linux 用例跳过，无失败。
- `native-to-docker-linux.log`：Linux amd64 子控 146 项通过，12 项需要专用外部环境的用例明确跳过，无失败。
- `native-to-docker-go-all.log`、`native-to-docker-vet.log`：最终全量 Go 回归及 `go vet ./...` 通过。本轮未改前端，未重复运行前端验证。
- `native-to-docker-result.json`：记录源码及日志 SHA256、六个受保护文件的基线与未发布边界。
- `native-to-docker-engine.log` 与 `docker-lifecycle.t8SOKw/`：共享 Docker 分支再次通过真实隔离嵌套引擎回归，包括实际 mTLS 配置确认、文件事件、启动响应丢失续作，以及原容器 ID 和当前数据恢复。结束后删除本轮测试引擎及其匿名卷，不操作其他容器。

native → Docker 的服务管理和内核证据仍为替身，SQLite、Journal、配置、捕获及补发文件为真实操作。真实引擎用例仍只证明 Docker → Docker；没有将其当作 systemd 跨方式成功验收。正式运行器、旧三容器接管、网页切换、完整迁移、高可用及容量验收仍未完成，本轮不发布。

## 目录覆盖与扫描就绪补充

中心验收复用 schema 4 和现有指标，不更改 RPC 合约。期望启用的引擎须有实际私有快照扫描证明，证据绑定当前规则并且只在本进程内有效。关键指标缺失、重复、带标签、过期或计数不合法时不能完成部署；verify 之后出现目录或扫描故障，finalize 仍会拒绝。

- `health-pg.nFOr9L/integration.log`：临时 PostgreSQL 中针对事务门禁、并发、旧样本、健康失败及实际 mTLS 采集的竞争检查通过。
- `run.cUEcfa/integration.log`：264 项竞争／集成测试通过，7 项 Linux 或外部环境用例明确跳过。该轮 Go 全量、Linux 子控 150 项、证书、实际资源读取及 Compose 等检查通过。
- `health-agent-scratch-all.log`：最终 Linux Agent 28 项通过，无跳过，包括真实 YARA、私有 clamd、超时／错误／禁用、规则变化、覆盖计数与临时文件隔离。监控上层包含数据目录时，业务 PHP 仍被记录，扫描自检及其快照不会进入实时或补扫事件；链接和不安全权限拒绝。
- `health-linux-final/run.9nS3fW/controlplane-linux.log`：最终 Linux 主控 101 项通过，无跳过；连接独立临时 PG／VM，实际 Agent、inotify、YARA、双向 TLS、探针入库及 receipt 确认通过。移动真实测试根目录后，任务不能完成 finalize，生效版本保持未推进。相邻 `node-cli-linux.log` 的离线 PKI 与 CLI 冒烟通过。
- `health-go-all-final.log`、`health-vet-final.log`、`health-linux-vet-final.log`：最终全量 Go 测试、全量 vet 和 Linux Agent／主控 vet 通过，Linux amd64 工具重新构建。
- `health-frontend.log`：前端类型检查、56 项测试和 Vite 构建通过；页面仍是现有 v2 API，并非新版网页已经完成。
- `health-result.json`：记录本轮源码及日志摘要、六个保留文件核对、未发布和未操作生产的边界。

首次 `health-foundation.log` 在 Linux 联调中发现测试夹具未续租，超过 30 秒后错误地碰到租约失效。仅补齐直接调用阶段的测试续租；生产协调器的续租逻辑未改。该失败记录保留，后续 `health-linux-final-scratch.log` 完整主控回归及 CLI 验证已通过。主脚本增加真实 YARA／Agent 联调，以及通过 `WEBSCAN_V3_SCANNER_TEST_IMAGE` 选择私有 clamd 镜像的可复现入口；该轮 clamd 另行专项执行。

私有 clamd 只加载无害测试签名、使用独立 Unix socket，不下载病毒库、不连接宿主机扫描服务；命中与服务停止后的失效均通过，不生成业务事件。指标写入的联合健康用例使用受控 HTTP sink；同轮另有真实 VM 导入查询用例，不能将二者表述成完整安装或 VM 灾备验收。

本轮未启用正式安装执行器，没有实际 systemd／跨方式安装、生产病毒库效果、HA 或容量验收。完整 v3 仍未交付，不发布、不提交 Git、不操作生产。

## 服务器告警与事务分组补充

业务 schema 升至 **5**。新增 PostgreSQL 服务器告警观察游标、规则、历史、批次、待入队记录和仅供平均值计算的短期 CPU 样本。复用原有规则，接入实际主动采集的指标成功及指标／协议失败路径；告警状态、历史和出箱在采集租约保护下原子提交。采集器实际周期用于新鲜度、缺口和持续时间判断；观察时间与分组等待使用 PostgreSQL 时钟。

- `server-alerts-foundation-final.log`／`run.vh9bsP/`：完整基础回归通过；275 项竞争／真实存储测试通过、7 项平台或外部环境检查明确跳过。Go 全量、Linux Agent、子控、实际内核资源读取、Compose、CLI、前端类型检查、57 项前端测试和 Vite 构建通过。该轮 Linux 主控 113 项通过，无跳过。
- `server-alerts-go-final.log`：在补齐实际采集周期传递后，主控、共享遥测和 OpenAPI 的竞争回归 126 项通过，5 项需要 VM 或 Linux 专用环境的用例明确跳过。覆盖相同观察的并发去重、恢复迟滞、缺失／重置、维护／停用、旧指标回放、原子回滚、分组等待与间隔、双通道独立失败、租约和备份恢复。
- `server-alerts-linux-final/controlplane-linux.log`：最终 Linux 主控 114 项通过，无跳过；使用隔离 PG／VM，包含实际采集周期、真实 mTLS、Agent／YARA、配置／事件确认和部署健康门禁。相邻 `webscan-linux-amd64` 为最终源码的 Linux 构建。
- 500 条被不可达状态抑制的旧通知不会堵住同节点不可达通知或其他节点通知；解除抑制后旧记录继续分组入队。通知入队失败回滚批次和完成状态，不丢记录；模拟飞书失败不阻止模拟邮箱完成。
- 新只读接口要求登录，支持当前异常及历史筛选／游标分页；同一时间记录不重复或遗漏。返回保护原因，数据库故障不伪装成空列表或退出登录；v3 清理未接通时不提供删除能力。
- schema 4 升级仍要求先备份；无备份不修改版本。新增告警表及批次依赖完成一致性备份／空库恢复核对。
- `server-alerts-vet-final.log`、`server-alerts-linux-vet.log`：全量 Go vet 及 Linux 主控／遥测 vet 通过。
- `server-alerts-result.json`：记录最终源码、日志、构建摘要、六个保留文件校验和发布边界。

首次完整回归 `server-alerts-foundation-first.log` 发现旧迁移测试将目标版本写死为 4；已改为验证当前 `SchemaVersion`，保留原失败日志。迁移前版本与备份内容仍严格验证，没有降低备份门禁。

本轮没有重新执行可选私有 clamd 或真实 systemd 验收；本轮 Agent clamd 用例明确跳过，前轮专项结果仍见上节。通知发送器使用替身，不连接业务飞书或真实邮箱。测试容器、匿名卷及网络已清理。

已完成能力及边界见 [服务器告警接入状态](V3-SERVER-ALERTS.md)。旧健康状态／历史／批次与通知依赖的领域迁移、策略编辑、网页接入、清理、正式安装执行器、完整切换回退、高可用与容量验收仍未完成，完整 v3 不发布，不提交 Git，不操作生产。

## 旧告警与通知领域迁移补充

本批将业务 schema 推进至 **6**，完成两份旧 SQLite 归档的规则、告警历史、批次成员和通知队列领域映射。历史节点身份与当前登记分开；旧收件人、完成／重试状态、租约等待和邮件 Message-ID 种子保留。迁移领域持久冻结，不因映射完成、重启或恢复备份而发送通知或确认新事件。

- `history-migration-foundation.log`／`run.iXc6iU/`：完整基础回归通过，竞争／真实存储测试 288 项通过，7 项平台或外部检查明确跳过；Go 全量测试通过。Linux 主控 125 项通过，无跳过；包括本批全部 11 项迁移测试。
- `history-migration-race-final.log`：最后补齐待入队原批次和新分组共用 500 条限额后，相关健康、历史、节点和数据库备份测试 36 项通过，无跳过；维护暂停及原批次身份保持。
- `history-migration-reconciliation-batch.log`：503 个批次关联时第二批故障，第一批 500 个成员保留完成状态；重试补齐余下成员，不复制通知。错误不包含模拟的私密数据库 DETAIL。
- `history-migration-fixtures-final.log`：双向迁移顺序、每收件人部分完成、601 条旧限流窗口、失效来源绑定、运行数据拒绝、损坏归档、缺少成员／收件人、未支持的待发目标，以及并发写入初始化隔离通过。最后增加的关联限额和共享工作预算用例亦在 Linux 主控和最终竞争测试运行。
- `run.iXc6iU/agent-linux.log`：27 项通过；嵌入套件的专用 clamd 用例明确跳过后，`scanner-clamd-linux.log` 独立实际运行并通过。YARA、目录监听、真实 mTLS、接收和确认流程通过。
- `run.iXc6iU/nodeops-linux.log`：150 项通过，8 项专用／外部环境检查明确跳过；另行通过真实内核限制读取、systemd 单元解析、Compose 定义及停止状态隔离容器验证。单元解析不等于完整 systemd 安装验收。
- `history-migration-cli.log`／`history-migration-cli-db-check.log`：实际 Linux CLI 在独立测试数据库执行初始化、两库归档、配对映射、重复续作和备份；核对一条历史身份、原批次已入队且通知仍受保护，没有伪造活动节点。
- 前端类型检查、57 项测试和 Vite 构建通过；现有页面仍使用 v2。全量及 Linux Go vet 通过，最后源码重新静态构建为 `history-migration-linux/webscan-linux-amd64`，版本标记仅为 `v3.0.0-local-test`。

六个指定保留文件的 SHA256 未变。源码、日志和构建摘要记录于 `history-migration-result.json`；仅清理本轮创建的临时容器、匿名卷和网络，不操作其他容器。

本节取代上一节关于旧告警与通知领域尚未映射的描述。正式冻结和增量切换、旧网站未完成合并出箱、看门狗调度交接、其余业务领域、完整网页、部署执行器、保留新增数据的回退、HA 与容量验收仍未完成。没有发布 v3、更新 latest、提交 Git 或操作生产。详见 [迁移说明](V3-HISTORY-MIGRATION.md)。

## 文件与安全事件迁移补充

本批将业务 schema 推进至 **7**，补齐原生事件回执及旧 Loki 展示历史的冻结映射。v3 接收改用与 v2 相同的规范摘要，排除中心补充字段，并保留 JSON 大整数。旧日志本身不生成原生确认；实际重读事件先事务持久化再确认，同一历史观察不重新扩展通道或收件人。

- `event-migration-foundation.log`／`run.0LnDxc/`：完整基础回归通过；296 项竞争／真实存储测试通过，7 项平台或外部检查明确跳过。Go 全量测试通过。
- `run.0LnDxc/controlplane-linux.log`：132 项 Linux amd64 主控测试通过，无跳过；包含真实 mTLS、Agent／YARA、部署健康门禁，以及本批事件映射和确认兼容用例。
- `event-migration-race-final.log`、`event-migration-linux-final.log`：最后补齐冲突拒绝持久化后，12 项相关事件、历史、告警迁移及事务确认用例分别通过竞争检查与 Linux amd64 验证，无跳过。最终 Linux 工具和测试程序位于 `event-migration-linux/`。
- 使用实际 v2 接收器生成旧事件并备份迁移，核对 `9007199254740993`、`18446744073709551615`、原接收时间和扫描命中分类；重复确认不生成新通知，身份冲突不阻断新事件且保留拒绝记录。
- 503 条记录在第二批故障后保留前 500 条；七条大载荷在 8 MiB 工作预算边界中断后保留前五条，重试完成余下部分。损坏摘要、身份／类型错误、非对象载荷、运行目标和不配套通知源均拒绝；错误不返回模拟私密 DETAIL。
- 原生及迁移记录同时间／节点／ID 时，包含来源的游标不漏页；默认隐藏探针，显式查询须开启包含探针。移除原生展示后旧日志不会重新出现；尚未接通清理的 v3 记录不会宣称可删除。
- `event-migration-cli.log`、`event-migration-cli-final.log`、`event-migration-cli-db-check.log`：实际 Linux CLI 完成独立库初始化、SQLite 归档、事件及通知映射、重复续作和备份；最后源码构建再次续作通过。核对 schema 7、精确数值、历史身份和持久迁移保护，未伪造活动节点。
- `run.0LnDxc/agent-linux.log`：27 项通过；套件中专用 clamd 用例跳过后，由 `scanner-clamd-linux.log` 实际运行并通过。子控 150 项通过、8 项外部／专用环境用例明确跳过；实际内核限制、systemd 单元解析、Compose 定义及隔离停止容器检查另行通过。
- 前端类型检查、57 项测试和 Vite 构建通过；完整及 Linux Go vet 通过。现有页面仍使用 v2，未进行页面架构切换。

首次专项测试暴露测试设置未开启“文件变更通知”，已补齐双通道开关并重测，保留初次日志。新接收还覆盖 NUL 文本、超出 PostgreSQL 数值范围及无法规范化的数字：单条永久拒绝不阻断同批正常事件。

六个指定保留文件 SHA256 未变；源码、文档、日志和最终构建摘要记录于 `event-migration-result.json`。仅清理本轮自建容器、匿名卷和网络，不操作其他开发容器。未连接业务通知、未提交 Git、未发布或切换生产。

此阶段仍无正式激活命令；完整部署编排、配置／备份／清理领域、旧网站未完成合并出箱、看门狗交接、完整网页、最终增量、保留新增数据的回退、HA 和容量验收仍需继续。详见 [文件事件迁移](V3-EVENT-MIGRATION.md)。

## 2026-10-18：网站通知出箱与迁移验证（schema 8）

网站状态转换与待发送记录在同一 PostgreSQL 事务保存，通知工作器按原有 15 秒规则分组并独立送入飞书及邮件队列。旧记录保留原编号，同一 SQLite 快照中的通知队列必须配套归档。导入保持冻结，完成映射仍不代表正式切换。

- `website-outbox-foundation.log`／`run.dvoPuL/`：完整基础回归通过；308 项竞争／真实存储测试通过，7 项明确跳过；Go 全量测试通过。
- Linux amd64 主控 146 项通过；Agent 27 项通过，专用 clamd 用例由独立镜像实际运行补验；nodeops 150 项通过、8 项外部环境用例明确跳过。实际内核限制、systemd 单元解析、Compose 及隔离停止容器检查通过。
- `website-outbox-policy-final.log`、`website-outbox-linux-final.log`：最终通道配置并发保护和完整任务身份核对通过竞争检查及 Linux 运行。配置更新必须等待整批双通道入队完成。
- 覆盖 500 条／8 MiB 批次边界、重启续作、原通知身份、时钟回拨下的故障／恢复顺序、软删除网站积压保留、租约接管及过期写入拒绝。测试发送器为本地替身。
- `website-outbox-cli.log`、`website-outbox-cli-db-check.log`：最终静态 Linux 工具完成初始化、v2 SQLite 归档、网站及通知映射、重复续作和一致性备份。核对 3 个网站、1 个账号、1 个有效会话、3 条原待发送网站记录和 1 个原飞书任务；未生成邮件任务，活动节点为 0，迁移保护生效。
- 前端类型检查、57 项测试和构建通过；Go 全量及 Linux vet 通过。

源码、文档、构建及日志摘要见 `.cache/verification/v3/website-outbox-result.json`。六个指定保留文件未改；没有提交 Git、发布或操作生产。

完整 v3 仍待配置与备份领域、历史清理、正式部署编排及信任配置、现有网页接入、影子／增量切换、保留新增数据的回退、HA 与容量验收。

## 2026-10-18：PostgreSQL 自动历史清理（schema 9）

完成五类独立期限、每小时持久任务、共享租约、两秒工作预算和每批 500 条清理。游标、主记录、关联记录和审计事务提交；受保护历史保留。仅开放期限编辑及状态／任务查询，手动预览、导出和删除尚未接入。

- `retention-foundation-final.log`／`run.QxWJ5f/`：完整基础回归通过；326 项竞争／真实存储测试通过、7 项明确跳过；Go 全量测试通过。Linux amd64 主控 162 项通过，无跳过。
- Agent 27 项通过；套件中专用 clamd 用例明确跳过后，由独立私有 clamd 实测补验。nodeops 150 项通过、8 项外部环境用例明确跳过；离线证书、实际内核资源限制、systemd 单元解析、Compose 定义及隔离停止容器验证通过。前端类型检查、57 项测试和构建通过，网页仍使用 v2。
- `retention-graphs-final.log`、`retention-affected-final.log`、`retention-linux-final.log`：覆盖 1503 条投递尝试及重复展示依赖分批续作、第二批失败回滚、策略变更、租约失效、暂停／重试收件人、活动异常和未结束故障保护。主记录和关联删除分别计数，重复访问次数不宣称为唯一记录数。
- 清理与实际 Agent 接收共用节点锁；原生回执保留，旧展示删除身份不冒充 Agent 确认。真实重传先持久化规范回执，不重新生成展示或通知；竞争测试验证并发顺序。
- `retention-cli-migration.log`、`retention-cli-db-check.log`：最终 Linux CLI 完成 schema 8→9 升级，生成升级前 schema 8 一致性备份；3 个网站、1 个账号、1 个会话、3 条网站出箱和1个通知任务保持不变。迁移冻结时不建立清理任务，API 健康正常，业务登录返回迁移保护 503。
- `retention-cli-restore.log`、`retention-restore-final.log`、`retention-restore-linux-final.log`：最终 CLI 将 schema 9 备份恢复到独立空库，原数量和迁移冻结保留；归档的清理工作器心跳被清除，等待新实例提供存活证据。最后恢复调整另以竞争检查及 Linux 专项验证，不冒充先前全量构建已覆盖该调整。
- `retention-vet-final.log`、`retention-linux-vet-final.log`及最终主控 vet 通过；最终静态 Linux 程序位于 `retention-linux/webscan-linux-amd64`，仅标记 `v3.0.0-local-test`。

首轮完整验证遇到操作锁测试固定 100ms 超时，在冷启动／转译环境中子进程尚未写入启动标记。只修改测试为启动／释放握手，保留父进程退出后锁仍有效的断言；实际 Linux 连续 10 次通过，再完成全套回归。原失败日志 `retention-foundation.log` 保留，生产操作锁实现未改。

详情及边界见 [历史保留](V3-RETENTION.md)。旧 YAML 参数导入、手动清理／导出、完整扫描任务与审计依赖迁移、备份策略、部署执行器、网页切换、最终增量、回退、HA 和容量验收仍待完成。记录删除不等于归还磁盘，不执行在线 VACUUM。未发送业务通知、未提交 Git、未发布或操作生产。

## 2026-10-18：旧 YAML 运行参数冻结导入（schema 9）

新增 `preview-settings-v2` 和 `map-settings-v2`，将通过原配置校验的保留期限、网站检测、告警及通知参数初始化到 PostgreSQL。已有实际账号和会话不受 YAML 初始化字段影响；SSH、注册表和管理员密码不混入运行设置。导入先备份，再原子保存设置、迁移冻结和审计，没有增加 schema 版本。

- `settings-pg-second.log`：12 项相关竞争检查通过，无跳过；包含七项参数迁移用例，以及原期限、迁移备份门禁和原配置解析回归。
- `settings-regression-final.log`：主控、配置、部署及 OpenAPI 竞争回归 278 项通过、9 项外部／专用环境检查明确跳过；没有失败。原 v2 配置加载改为复用同一字节解析器，现有配置和部署测试通过。
- `settings-linux.log`：13 项 Linux 专项通过，无跳过；`settings-controlplane-linux-final.log`：163 项 Linux 主控测试通过、6 项需要 VM、真实 Agent 夹具或外部命令行环境的用例明确跳过。本批未把这些跳过计入通过；前节完整基础回归的相应结果仍是独立历史证据。
- 覆盖 2 MiB 限额、空文件、公开权限、符号链接、重复键、多文档、外部飞书环境文件和脱敏错误；不自动读取外部凭据或联系通知通道。只读预览可在无数据库、容器禁网条件下执行。
- 实际 PostgreSQL 验证：备份失败不写设置；审计写入失败整批回滚且隐藏数据库私密 DETAIL；独占迁移门禁等待实际并发写入，禁止旧 YAML 覆盖新版本。原命令重试不递增版本、不重复审计；相同公开策略指纹不能绕过内部通知凭据变化检查。
- 双向顺序验证先迁网站或先迁参数均保留实际账号、会话及网站状态，不启用网站检测、不生成通知，历史清理仍受迁移冻结保护。
- `settings-cli-preview.log`、`settings-cli-import.log`、`settings-cli-repeat.log`、`settings-cli-restore.log` 及相邻数据库核对日志：实际静态 Linux CLI 完成禁网预览、导入、重复续作、一致性备份及空库恢复。核对事件／安全期限 87 天、告警期限 47 天，设置版本为 2；3 个网站、1 个实际账号、1 个有效会话、3 条网站出箱及 1 个原通知任务保留，三个迁移领域仍冻结。恢复后不保留旧清理心跳，不建立清理任务。
- `settings-affected.log`、`settings-vet.log`：配置、部署、主控及 CLI 测试和相关 Go vet 通过；最终 Linux 程序及测试构建位于 `settings-linux/`。没有修改前端，本批未重复前端构建；前节 57 项前端测试和构建为独立结果。

源码、文档、日志、构建及六个保留文件摘要记录于 `.cache/verification/v3/settings-result.json`。前一批 `retention-result.json` 保留当时摘要；后续源码、文档及开发构建变化不追写成旧验证已经覆盖。本批只清理自己的测试容器和卷，不操作其他本地容器。

本节补齐上一节的运行参数导入缺口。完整部署 YAML、配置备份、旧任务及审计承接、手动清理／导出、网页接入、正式安装及信任配置、最终增量与保留新增数据的回退、HA 和容量验收仍未完成。通知参数中的凭据仅保存在内部数据库及受保护备份，未新增通知凭据独立密钥加密。完整 v3 不发布，生产和 Git 均未操作。详见 [参数迁移](V3-SETTINGS-MIGRATION.md)。

## 2026-10-18：网站配置备份与旧备份冻结迁移（schema 10）

已增加网站快照、JSON 导入／导出、账号绑定的十分钟恢复预览、合并恢复、恢复前快照及单条／批量删除 API，附 OpenAPI 和 TypeScript SDK。恢复保留网站身份、故障历史和原待投递通知，规则变化使旧检测租约失效；跨批次失败整次回滚。schema 10 升级仍要求先备份；灾备恢复清除旧预览授权。相关说明见 [网站配置备份](V3-WEBSITE-BACKUPS.md)。

本地记录位于 `.cache/verification/v3/`：

- `run.WLJy0X/`、`website-backup-foundation.log`：网站备份第一阶段完整基础回归通过。竞争检查 341 项通过、7 项外部条件跳过；Linux 主控 177 项通过、无跳过；Agent 27 项通过、1 项跳过；nodeops 150 项通过、8 项跳过，另有实际 clamd、systemd 单元解析、内核限制、Compose 和独立 Docker 对象专项验证。全量 Go、前端类型检查、58 项测试及构建通过。严格原生进程测试在 Rosetta 环境的跳过不代表真实 systemd 完整安装已验收。
- `website-backup-foundation-source.json`：上述基础回归的源码快照摘要。后续增加旧备份映射及 UTF-8 拒绝检查，没有将这些后续改动冒充为前述全量测试已覆盖。
- `website-backup-affected-final.log`：恢复保留原网站 ID、原故障和未完成通知，大于 8 MiB 的合法快照可实际备份恢复；503 个网站第二批失败后整次合并回滚，通过后再续作。
- `website-backup-cli-*`：实际静态 Linux CLI 将旧 schema 9 备份恢复到隔离库，先备份升级至 10，再备份恢复至另一空库。原 3 个网站、1 个账号、1 个有效会话、3 条网站出箱和 1 个通知保持；设置版本、期限和三类迁移冻结保持，预览和归档清理心跳均为零。
- `website-backup-migration-regression.log`：增加旧备份映射和单文档事务后，主控全量竞争检查及 API／CLI 包测试共 177 项通过、5 项明确外部条件跳过。5 项为 VictoriaMetrics 与仅隔离 Linux 容器可运行的工具上传；对应基础能力已由前述完整基础回归覆盖。
- `website-backup-parser-final.log`：最终 UTF-8 检查及受控文件读取两项专项通过，拒绝 NUL、无效 UTF-8、重复键、无效格式、符号链接、FIFO、公开权限、路径穿越和超限文件。
- `website-backup-migration-linux-final.log`：最终 Linux 程序执行备份、旧网站／通知依赖、参数迁移、数据库灾备及旧网站备份映射共 44 项测试通过、无跳过。缺失第二份文件保留第一份进度，补回后续作不重复；旧删除任务未结束时不绑定新迁移领域。
- `website-backup-migration-cli-*`：实际 Linux CLI 从旧 SQLite 归档，核对外部快照摘要，保留备份原来源、时间、恢复结果和旧 ID；重复操作仍只有一份备份。最终程序再次完成重复执行和空库恢复核对，原网站、账号、会话和待投递任务保留，增加的网站备份领域继续冻结，未授权恢复或发送通知。
- `website-backup-final-vet.log`：相关 Go 静态检查通过；`website-backup-result.json` 保存分阶段源码、二进制、日志摘要和适用边界。原先要求保留的六个文件摘要全部一致。

本节补齐网站配置备份 API 与旧快照文件／元数据的冻结承接。部署配置备份、旧任务和审计的业务承接、手动历史预览／导出／清理、完整 Vue 页面、正式部署及信任配置、最终增量切换与保留新增数据的回退、HA 和万台／72 小时验收仍未完成。发布版本保持 v2.0.46，没有发布 v3、更新 latest、操作生产或提交 Git。

## 2026-10-18：手动历史预览、JSONL 导出与选择清理（schema 11）

补齐六类历史的固定范围预览、账号绑定凭据、导出／清理任务、持久化文件意图、下载、实际计数及列表删除保护。自动与手动共用清理租约及业务保护，手动部分限制预算，避免持续导出阻塞自动保留策略。增加飞书／邮件历史元数据接口，不返回通知载荷和提供商响应。

本地结果位于 `.cache/verification/v3/`：

- `manual-history-full-race.log`：主控全量竞争检查 194 项通过、5 项明确跳过，无失败。跳过为 VictoriaMetrics 及只允许隔离 Linux 运行的四项工具上传／安装；本节不把它们计入通过。后续仅增加空选择拒绝与导出到期／小磁盘专项，未将其冒充为此前全量竞争检查已覆盖。
- `manual-history-final-race.log`：最终手动历史与通知元数据竞争检查 20 项通过，1 项需小容量 tmpfs 的用例明确跳过；此用例由下列 Linux 容器实际补验。覆盖账号、CSRF、预览配额竞争、固定选择、空选择不得扩大范围、配置过期、延迟保护、500 条分批、部分事务失败、重启续作、迁移重复展示处理、通知大依赖图与超大通知 ID 精度。
- `manual-history-linux/integration.log`：最终 Linux amd64 专项 44 项通过、无跳过。通过容器 16 MiB 私有 tmpfs 实测空间不足，导出失败、原历史保留、没有错误进入清理。另覆盖 schema 10→11 备份门禁、备份失败、空库恢复、自动／手动互斥、文件损坏及过期、符号链接、权限和摘要验证。
- `manual-history-api.log`、`manual-history-regression.log`、`manual-history-fairness.log`：API 登录与 CSRF、账号隔离、幂等、分页、预览到期、排队任务保护及调度预算专项。真实 HTTP 下载在后续分片缺失时返回不完整数据，客户端检测 `unexpected EOF`，审计记录未完成，不把部分 JSONL 当作完整成功。
- `manual-history-cli.log`、`manual-history-cli-db-check.log`：最终静态 Linux CLI 将旧 schema 10 一致性备份恢复到隔离库，先备份再升级至 11，再备份恢复到另一空库。两库均保留 3 个网站、1 个账号、1 个会话、3 条网站出箱、1 个原通知任务、1 个网站配置备份，设置版本 2、原事件期限 87 天及 4 个迁移冻结不变，没有创建手动任务。
- `manual-history-go-all.log`、`manual-history-vet.log`：Go 全量测试及相关静态检查通过；实际 PostgreSQL 检查由前述专用套件运行，不将缺少显式测试环境的跳过算作数据库验收。
- `manual-history-typecheck.log`、`manual-history-frontend.log`、`manual-history-build.log`：前端类型检查、61 项测试及构建通过。新增 SDK 验证明确选择、预览凭据、幂等键、手动任务分页及完整 JSONL 下载；现有 Vue 页面仍走 v2 接口。

数据库普通重启继续任务，灾备恢复取消未完成手动任务、使预览失效并撤销外部文件证据；保留文件意图供清理，不自动恢复旧破坏性授权。导出文件不包含在数据库备份中。操作元数据及审计保留 365 天，文件完成后 24 小时过期，不在线 VACUUM。

`.cache/verification/v3/manual-history-result.json` 保存源码、二进制、日志摘要、通过数量和适用边界。六个指定保留文件摘要一致。没有提交 Git、发布或更新 latest，也未操作生产及真实通知渠道。

本节补齐手动历史业务接口；完整 Vue 接入、部署配置备份、旧任务和审计承接、正式部署及信任初始化、影子／增量切换和保留新增数据的回退、HA、万台规模及 72 小时验收仍未完成。当前不能发布完整 v3。

## 2026-10-18：已结束操作审计承接与只读查询（沿用 schema 11）

新增 `map-operation-audit-v2`，按完整来源摘要承接中央及宿主管理 SQLite 中已结束的 `record_operations`／`retention_jobs`，不复用原请求键、预览、执行游标或下载授权。新增 `/api/v3/audit` 与 OpenAPI／SDK，只读、账号权限过滤、稳定字符串 ID 及受控结果摘要。迁移冻结期间暂停过期审计删除。

- `operation-audit-race-final.log`：7 项主测试及其子场景通过竞争检查，无跳过。覆盖未结束任务在绑定前拒绝、旧时间／选择／完成数量校验、503 条第二批失败及续作、未处理批次摘要变化、不同 SQLite 中相同旧编号、多来源身份及备份恢复、365 天期限、账号隔离、只读限制、分页、大整数身份、私密字段过滤与数据库故障。
- `operation-audit-linux/integration.log`：相同 7 项主测试在最终 Linux amd64 程序中运行通过，无跳过。未修改数据库版本，继续遵守 schema 11 的备份与恢复门禁。
- `operation-audit-cli-archive.log`、`operation-audit-cli.log`、`operation-audit-cli-db-check.log`：最终静态 Linux CLI 实际创建一致性旧快照、归档、映射、重复续作及 PostgreSQL 备份。只生成 1 条旧操作审计，私密文本泄漏数量为 0，新增来源冻结仍有效，没有创建可执行清理任务；原 3 个网站、1 个会话及 1 个通知任务保留。
- `operation-audit-typecheck.log`、`operation-audit-frontend.log`、`operation-audit-build.log`：前端类型检查、62 项测试及构建通过，网页仍走 v2；新增 SDK 仅提供审计读取。
- `operation-audit-package.log`、`operation-audit-vet.log`：相关 Go 包测试及静态检查通过。此前手动历史阶段的主控全量竞争／Go 全量结果是独立证据，没有将本节后续新增代码写成已由前节全量测试覆盖。

首轮测试的失败日志保留。续作摘要用例修正为损坏尚未处理的第 501 条，验证保留首批并拒绝后续批次；不把已提交的数据库管理操作当作普通快照续作。保留期限用例复用同一清理实例身份，遵守已有持久化租约，未放宽生产租约规则。

`.cache/verification/v3/operation-audit-result.json` 保存本阶段源码、构建和日志摘要。六个原指定文件保持不变，没有提交、发布或操作生产。完整部署配置备份、旧部署任务及配置恢复审计、网页切换、正式安装与信任初始化、最终增量与回退、HA 和容量验收仍需继续。

## 2026-10-18：离线发布签名、凭据密钥初始化及信任配置检查

新增 `release-v3 init-key/sign/verify`、`vault-v3 init-key/check` 与 `control-v3 --action check-deployment-trust`。参数全部使用受控文件；签名密钥为标准 Ed25519 PKCS8／PKIX PEM，发布清单沿用严格规范 JSON 和分离签名。新密钥及发布目录通过不可覆盖的原子重命名发布。读取逐层禁止符号链接、不安全父目录和额外硬链接；已有 `OpenVault` 同步应用限制，最多加载 8 个旧密钥，拒绝重复密钥。没有修改 schema、业务 API 或网页。

本地证据仍位于 `.cache/verification/v3/`：

- `release-trust-full-race.log`：隔离 PostgreSQL 17 上的主控竞争检查 207 项主测试通过，6 项外部条件跳过。跳过为旧手动历史小磁盘测试、VictoriaMetrics 和 4 项需要显式隔离 Linux 的上传测试。本节未重跑这些旧外部专项，也未将跳过算作通过。
- `release-trust-final-race.log`：最终离线工具专项竞争检查 10 项通过，新增小磁盘用例因未指定 tmpfs 明确跳过；由下一项真实容器补验。全量竞争检查开始后仅补充重复密钥和信任资料写满用例，没有将新增测试冒充为之前的全量测试已覆盖。
- `release-trust.JvMWXw/integration.log`：最终 Linux amd64 专项 11 项全部通过，无跳过。只读根目录、无网络、私有 tmpfs 中验证签名往返、错误公钥、清单／签名／程序篡改、FIFO、硬链接、符号链接、超限、权限、取消、并发初始化和配置绑定；1 MiB tmpfs 实测写满失败后没有发布半份密钥或遗留暂存目录。
- `release-trust.JvMWXw/cli.log`：最终静态 Linux CLI 真正执行密钥初始化、签名、独立验签、凭据密钥检查和完整 YAML 信任检查。数据库 DSN 文件不存在，容器无网络，检查仍通过；已有密钥不被覆盖，程序被修改后检查失败，输出明确 `executor_enabled=false`。native 归档为签名用测试夹具，不宣称可部署扫描工具包已经验收。
- `release-trust-go-all.log`、`release-trust-vet.log`：Go 全量测试及相关静态检查通过；没有将未提供环境的数据库／外部测试计入实际服务验收。本节未改动前端，前端证据仍为前一阶段类型检查、62 项测试与构建。

首轮测试日志 `release-trust-race.log` 保留：Mac 测试临时目录经过 `/var` 符号链接，被新安全检查正确拒绝。测试目录改为 `EvalSymlinks` 得到的真实路径，未放宽生产路径规则。新增脚本 `scripts/verify-v3-release-trust.sh` 可复现无网络 Linux 专项，所有测试私钥仅存在于临时测试目录或容器内，未生成生产密钥。

`.cache/verification/v3/release-trust-result.json` 保存本阶段源码、二进制和日志摘要。指定保留的六个文件摘要一致；本轮临时 PostgreSQL、Linux 容器及其匿名卷已清理。另修正忽略规则，使前阶段的操作审计文档和新增信任文档正常显示为待提交文件。没有提交 Git、发布、更新 latest、发送业务通知或操作生产。

这补齐离线信任资料工具，不等于完整正式部署链。仍需完成部署配置备份和旧部署任务承接、全阶段安装器与证书分发轮换、完整 Vue 页面、最终迁移／回退、可选 HA 及万台／72 小时验收。完整 v3 尚不满足发布条件。

## 2026-10-18：显式执行器、完整 SSH 阶段入口与迁移暂停

新增默认关闭的 `executor` 配置及角色。`all` 仅在显式启用时启动执行器；领取任务前核对独立密钥、签名发布文件和私有配置包目录。完整 SSH 路径通过固定 `--lifecycle` 开关选择真实 native／Docker 阶段处理器；默认准备命令仍不能停止或切换服务。每个任务读取 `<配置目录>/<绑定 SHA256>/node.json`，不再依赖多工作器共享的可变文件。详见 [内部执行器](V3-EXECUTOR.md)。

复核后补上迁移冻结：任务领取、阶段前核对及阶段提交受已有迁移锁保护。冻结不制造失败或丢失检查点，解除冻结后按租约接管；已经发出的远端操作仍须核对稳定状态，不能把此检查当作正式迁移停写完成。

证据位于 `.cache/verification/v3/`：

- `executor-wiring-final-race.log`：最终主控部署／执行器相关竞争检查 34 项主测试通过，无跳过。覆盖任务租约、防重、配置版本、实际采集门禁、关闭／中断、SSH 回包丢失、继续与回退、配置包并发分离、篡改及链接拒绝、启动验签、默认关闭和迁移暂停。SSH 测试使用真实 PostgreSQL 与远端 SQLite 记录，服务操作和采集就绪明确采用测试证据，没有据此宣称实际安装成功。
- `executor-wiring-nodeops-race.log`：子控阶段模块竞争检查 147 项通过，3 项需要明确外部 Docker 环境的用例跳过。真实处理器选择、阶段协调、SQLite、备份／补发文件与原生／容器切换保护均回归；本轮没有重新执行嵌套 Docker 引擎专项，也未替代原生 amd64 和 systemd 成功验收。
- `executor-wiring-linux/final-integration.log`：最终 Linux amd64 二进制的执行器、SSH、回包丢失、回退和迁移暂停共 9 项通过，无跳过。
- `executor-wiring-linux/cli-proof.log`、`cli-result.json`、`cli-processes-after-exit.log`：前一阶段静态 Linux CLI 在只读根目录和内部测试网络中实际初始化独立 schema、启动 executor 角色，PostgreSQL 显示活动 0、并发 2、心跳有效、错误为空；终止后正常退出且无残留 Go 主控进程。业务表任务、凭据、节点、账号和会话均保持为零。真实 `node-v3 --lifecycle` 在没有 systemd 的容器中返回明确 `preflight-failed`，没有切换服务。该 CLI 角色证据先于后续迁移保护改动；最终保护由上述最终 Go／Linux 专项补验，未混淆二进制摘要。签名 native 文件仅为测试夹具，不是可部署的扫描工具包。
- `executor-wiring-final-go-all.log`、`executor-wiring-final-vet.log`：最终 Go 全量测试及相关静态检查通过。前端未修改，仍沿用前阶段验证记录。

首次创建的内部网络不提供宿主机端口映射，因此为宿主机竞争测试重建了自己的空测试 PostgreSQL；CLI 仍通过独立内部网络访问它。第一次 detached 容器没有接收到 stdin 脚本，检查确认没有创建测试资料后，改为在同一个容器执行脚本；没有重启业务服务或将空等待当成安装成功。临时测试容器、匿名卷及网络均按明确名称清理。

`.cache/verification/v3/executor-wiring-result.json` 保存最终源码、不同阶段程序及日志摘要，指定保留的六个文件未改变。未提交 Git、发布、改动生产或调用真实通知。完整 systemd／Docker 端到端验收、旧三容器接管、PKI 分发轮换和业务预览／提交尚待完成；公开部署写接口继续关闭。部署配置备份、完整 Vue、最终迁移与回退、HA 和容量验收仍未完成，不能发布完整 v3。

## 2026-10-18：本地凭据登记、节点配置准备及任务提交

新增本地管理员操作 `store-ssh-credential`、`prepare-deployment`、`queue-deployment`。SSH 凭据加密入库，私有节点包按摘要保存，正式任务只存引用。准备及提交核对当前采集器 CA、证书／私钥、允许身份、当前吊销列表和持久吊销版本下限。提交还重新核对发布清单、目标摘要、完整节点配置及版本；节点行锁内检查账号及配置，复用迁移冻结、任务互斥和幂等审计。详见 [配置包](V3-NODE-CONFIGURATION.md#本地管理员准备与提交)。

本阶段没有变更 schema 或开放 HTTP 写入，也不会通过准备／排队命令自动启动执行器。明确选择 `executor.enabled: true` 并另行启动角色后，任务才可能被消费。CLI 输入中的本机路径只用于本地管理员文件，不接受来自浏览器的路径。

证据位于 `.cache/verification/v3/`：

- `provisioning-full-race.log`：隔离 PostgreSQL 17 上主控全量竞争检查 220 项主测试通过，121 个子场景通过，7 项外部条件明确跳过。跳过为两项小磁盘专项、VictoriaMetrics 和四项专用 Linux 上传脚本；这些旧专项本轮没有重跑，不计为已通过。本次新逻辑的 8 项主测试及 20 个子场景均实际运行。
- `provisioning-linux/integration.log`：最终 Linux amd64 测试程序在只读根目录、私有 tmpfs 和内部测试网络中完成同样 8 项主测试、20 个子场景，无跳过。覆盖普通及 Docker 任务摘要绑定、错误 CA／节点／采集器、证书吊销及 CRL 回退、文件和设置篡改、旧配置、管理员权限、迁移冻结、并发 12 次防重及敏感信息不进入任务／审计。测试准备的程序归档是签名用夹具，不作为实际可安装包。
- `provisioning.sxRny0/integration.log`、`provisioning-script.log`：新增 `scripts/verify-v3-provisioning.sh` 重建最终程序，并使用全新、无宿主机端口的 PostgreSQL、独立内部网络再运行同样专项。测试中的实际 Linux CLI 读取 YAML、私有 JSON、数据库 DSN 和严格注册的参数，重放排队请求得到同一任务；没有启动部署工作器或连接任何 SSH 节点。私钥只存在测试临时目录／容器 tmpfs 内。
- `provisioning-go-all.log`、`provisioning-vet.log`：Go 全量测试及相关静态检查通过。前端未改动，本轮没有重复构建网页，也没有用之前的网页验证证明 v3 已完成接入。

首轮日志 `provisioning-initial.log` 保留。首轮凭据重放比较因 PostgreSQL JSONB 改变字段顺序而失败，断言改为比较解码后的响应；没有修改幂等生产语义或放宽校验。最终测试全部使用修改后的断言。所有测试临时 schema、容器及匿名卷按归属清理，六个原指定文件摘要一致。

`.cache/verification/v3/provisioning-result.json` 保存源码、二进制及日志摘要。尚需公开账号绑定预览、自动 PKI 签发／分发与轮换、正式安装菜单、实际 systemd／Docker 全流程及旧节点接管；部署配置备份、完整网页、最终迁移回退、可选 HA、万台／72 小时验收亦未完成。保持 v2.0.46 发布状态，不提交 Git、不更新 latest、不操作生产。

## 2026-10-18：受控节点签发、加密发行登记与执行前信任复查

新增默认关闭的 `node_pki` 配置、本地 `issue-node-certificate` 操作，以及准备阶段使用 `identity_id` 或自动签发的能力。只为已经保存的节点 ID／TLS 名称签发；不接受浏览器提交 CA、角色或路径。节点私钥使用独立 Vault 加密，发行记录、请求防重和审计同事务提交。共享 CA／CRL 下限拒绝其他实例的旧资料及隐式换根；备份可恢复加密叶密钥，仍需要外部 Vault 密钥和受管理 CA。详见 [证书工具](V3-PKI.md)。

schema 从 11 增量到 12。已有数据库必须一致性备份成功后才创建登记表，失败不推进版本；备份恢复按节点、CA、证书依赖排序。已经排队的任务在各远程阶段前重新检查当前采集信任与共享下限。联调还发现远程请求未复用稀疏配置默认值，造成已准备的默认监控目录被请求端丢弃；现统一采用 `nodeRuntimeSettings`，合法默认配置可以通过阶段请求校验。

证据位于 `.cache/verification/v3/`：

- `pki-registry-verified-race.log`：最终主控及证书模块全量竞争检查共 244 项主测试、140 个子场景通过，7 项外部条件跳过。跳过仍为两个小磁盘专项、VictoriaMetrics 和四个专用 Linux 上传脚本；未将其计为本轮实际通过。
- `provisioning.H3PEE9/integration.log`、`pki.log`、`pki-registry-verified-script.log`：最终脚本在独立内部网络 PostgreSQL、只读 Linux 根目录及私有 tmpfs 中完成 20 项主控／部署／迁移主测试、33 个子场景，以及 2 项底层证书测试，全部通过、无跳过。实际 Linux amd64 CLI 验证显式签发、防重、自动复用证书及配置包；没有启动工作器或 SSH。额外验证 schema 9／10／11 的升级前备份和灾备保护。签名程序包仍是测试夹具，不宣称可实际安装的完整扫描工具包已验收。
- 新测试覆盖并发签发仅落一条记录、错误账号／节点／版本／CA／私钥、过期 CRL、数据库写入失败、迁移冻结、独立过时签发目录、共享下限、隐式换根、密文身份绑定、Vault 换钥及旧备份所需密钥、备份恢复、已经排队后信任更新和默认监控范围。
- `pki-registry-verified-go-all.log`、`pki-registry-verified-vet.log`：最终 Go 全量测试及相关静态检查通过；`git diff --check` 无空白错误。前端未修改，没有用既有网页测试宣称完成 v3 页面接入。

初轮日志保留：`pki-registry-initial.log` 的过期 CRL 夹具原本在 CA 生效前调用受约束签发函数，夹具改为直接生成具有真实签名的过期列表；拒绝逻辑未放宽。`pki-registry-script.log` 与 `pki-registry-full-race.log` 暴露了远程请求默认目录不一致的问题；`pki-registry-executor-fix.log` 验证修复。旧历史迁移测试模拟 schema 9／10 时遗漏新的 schema 12 表和版本，另有最终恢复版本硬编码为 11；夹具改为完整移除后继表／版本并断言当前 `SchemaVersion`，仍保留原有备份失败、旧数据和恢复任务保护断言。`pki-registry-regression-fixes-final.log` 及上述最终全量／Linux 记录均通过，没有把旧失败日志算作通过。

`.cache/verification/v3/pki-registry-result.json` 保存本阶段源码、最终程序和日志摘要；六个原指定文件摘要保持一致。没有提交、推送、发布或操作生产，测试容器及匿名卷按归属清理。

当前完成的是受控签发和准备链路，不等于完整 PKI 运维。定时证书／CRL 续期、逐节点分发、交叠轮换、CA 迁移、正式部署菜单与账号绑定预览、实际 systemd／Docker 全流程及旧节点接管仍未完成。完整网页、部署配置备份、最终迁移回退、真实可选 HA 和容量／72 小时验收仍须继续；不能发布完整 v3。


## 2026-10-18：部署预览、事务确认与升级判断

新增本地 `preview-deployment`、`confirm-deployment`，详见 [部署预览与确认](V3-DEPLOYMENT-PREVIEWS.md)。预览绑定管理员账号版本、节点配置与已生效版本、不可变发布／配置包摘要、SSH 凭据版本及最近部署状态，有效十分钟。数据库仅保存 token 摘要；预览消费、任务、日志、请求回执和审计同事务提交。账号重置或撤权后，连旧成功回执的重放也拒绝。节点锁等待不能延长有效期，普通采集与其他节点编辑不会使预览失效。

schema 12→13 增加预览表和按节点查询部署历史的索引；迁移仍要求一致性备份，备份失败停止。灾备覆盖已消费／未消费预览、任务和防重回执。明确的相同版本／摘要／已生效配置返回无需升级；可比较的降级或方式变化拒绝，旧基线缺失返回未知。升级判断测试中的成功记录是显式合成的数据库夹具，不是远端安装成功证据。

证据位于 `.cache/verification/v3/`：

- `deployment-preview-full-race.log`：隔离 PostgreSQL 17 上主控完整 `-race` 测试 241 项主测试、163 个子场景通过，7 项外部条件跳过。跳过为两个小磁盘专项、VictoriaMetrics 和四个专用 Linux 上传脚本，没有计为通过。
- `deployment-preview-targeted-race.log`：相关部署、备份及迁移专项 40 项主测试、62 个子场景通过，无跳过。覆盖十分钟过期、锁等待跨期、账号／节点／凭据变更、任务插入期间状态变化、旧材料和 CRL、并发确认、每账号预览上限、过期回收、审计失败原子回滚及重试。
- `deployment-preview-linux-script.log`、`provisioning.5RhJvW/integration.log`：脚本重新构建 Linux amd64 工具，在独立内部网络 PostgreSQL、只读容器根目录和私有 tmpfs 完成 31 项主测试、62 个子场景，无跳过。实际二进制读取私有配置执行预览，并重放确认得到同一任务；没有启动执行器、连接 SSH 或安装服务。`provisioning.5RhJvW/pki.log` 另有 2 项底层证书测试通过。签名程序包是已有测试夹具，不作为可部署正式包。
- `deployment-preview-go-all.log`、`deployment-preview-vet.log`：Go 全量测试和相关静态检查通过；无测试数据库环境时的 Go 全量运行不替代上述真实 PostgreSQL 测试。前端本轮未修改，没有重复构建或宣称完成 v3 网页。

首轮 `deployment-preview-initial.log` 即通过；后续补齐并发上限、回收、锁等待过期和真实 CLI 路径后，最终专项、完整竞争和 Linux 脚本均通过。`.cache/verification/v3/deployment-preview-result.json` 保存源码、程序和日志摘要。指定的六个旧文件摘要一致，临时容器、卷和网络按归属清理，没有提交、推送、发布或操作生产。

公开部署写入继续关闭，真实 native／Docker 全流程、旧三容器接管、PKI 定期续期／分发／轮换、公开凭据及预览界面仍未完成。完整 Vue 接入、部署配置备份与旧任务承接、最终增量迁移和回退、可选 HA 安装和万台／72 小时验收也仍须继续。保持完整 v3 目标，不把本地预览完成视为正式版交付。

## 2026-10-18：独立 v3 网页、服务器详情及手动事件查询

新增独立 `v3.html`，与发布版 v2 入口一起由 Vite 构建并嵌入 Go。v3 API 只提供自己的登录、服务器列表／详情、文件事件和部署日志路由，不回退到旧 API。服务器详情用同一个只读数据库快照读取白名单状态、版本和最近任务，不返回私有配置、SSH 凭据或部署计划。未知、真实零值、保存与生效状态分别展示。登录接上持久会话和 CSRF，首次匿名访问不会误报会话过期。

文件事件保留已确认行为：首次、带参数、刷新、导航历史不自动查询；清除或修改条件只更新 URL，翻页使用已提交条件。探针默认隐藏，操作为 probe 时必须明确包含。自动刷新每次关闭，只保留按用户名隔离的下拉间隔偏好，不再增加数字输入框；后台、草稿修改和未完成请求暂停，失败保留数据并按完整间隔重试。手动查询、退出和新页面均保护迟到结果／错误。关键词查路径、原因和消息，原生和迁移记录使用相同查询，`%` 和 `_` 保持字面含义。

事件删除接上已有清理接口和工作器，不改变保护逻辑。当前页明确选择、账号预览、导出先行、幂等重试、部分完成、下载和清理后游标回退均有界处理。部署任务仍只读，日志按游标增量读取。公开部署写入、全部其他业务网页仍未完成。详见 [网页接入与边界](V3-CONSOLE.md)。本阶段没有 schema 增量。

证据位于 `.cache/verification/v3/`：

- `console-events-full-race.log`：真实隔离 PostgreSQL 17 上主控完整竞争检查 244 项主测试、163 个子场景通过，7 项外部条件跳过。跳过为两个小磁盘专项、VictoriaMetrics 和四个专用 Linux 上传脚本；这些既有专项本轮没有重跑，不计为通过。
- `events-go-targeted-final.log`：9 项相关主测试、7 个子场景通过，无跳过，覆盖静态入口、服务器详情权限及敏感字段、关键词字面匹配、清空服务器、原生／迁移探针与游标、迁移防重和历史账号／CSRF。
- `console-events-web-final.log`：前端全量 14 个文件、88 项测试通过；`events-typecheck-final.log`、`console-events-build-final.log`：类型检查和双入口构建通过。Vue 实际挂载覆盖待查询／已提交条件、分页窗口、导航旧请求、间隔修改、用户名隔离、后台暂停、失败后不叠加请求、删除明确选择和部分完成等。原有 v2 删除及事件查询测试仍通过。
- `console-linux-final-script.log`、`console-linux.6utDgW/integration.log`：新增可复用 `scripts/verify-v3-console.sh`，重新编译最终内嵌资源及 Linux amd64 程序，在只读容器根目录、私有 tmpfs、独立内部网络和新的 PostgreSQL 中运行 13 项主测试、7 个子场景，全部通过、无跳过。此项为 Linux HTTP 处理器／数据库验收和 CLI 编译，不是实际远程安装或 Linux 桌面浏览器验收。
- `console-events-go-all.log`、`console-events-vet.log`：Go 全量测试和相关静态检查通过。无 DSN 的 Go 全量测试不替代上述真实 PostgreSQL 竞争测试。
- `console-live-fixture/` 与 `events-browser-database-proof.log`：浏览器连接本机实际 Go HTTP 服务和独立 schema，使用合成的 24 个节点、44 条事件、不可部署凭据和一个明确的失败任务。只启动自己的历史清理工作器，没有采集器、执行器、SSH 或通知工作器。实际完成分页、筛选、详情、保存反馈、日志读取，以及单条旧记录预览／导出／删除；数据库确认事件 44→43，目标旧记录为零，任务成功且导出一条，下载完成审计存在。
- `events-download-final.jsonl`：通过真实页面下载并解析，只有本次选中的一条合成记录。下载目录中的临时文件已移入证据目录。`events-cleanup-final.png` 保存实际结果；`events-initial-final.png`、`events-paused-final.png` 保存首次等待查询及修改条件暂停。最终补充长任务 ID 换行和离开页面中止下载后，重新完成前端全量、构建及 Linux 专项，并启动最后一个独立 schema 验证最终资源的关键词查询及 390×600 事件详情；`events-final-bundle-query.png`、`events-final-mobile.png` 为最终构建截图。浏览器没有运行错误或警告。
- `console-detail-final.png`、`console-save-final.png`、`console-logs-final.png` 为此前同阶段服务器／日志功能验收；`console-dialog-mobile-final.png` 验证 390×600 时表单正文 580px 在 384.5px 内滚动，底部按钮保持可见。这些截图不作为远端服务已安装的证据。

首轮前端 `events-web-initial.log` 有两项测试夹具问题：清除图标需要先触发悬停；第三方组件转场定时器不能用全局零定时器断言。夹具改为真实悬停和离开后不再请求的行为验证，`events-web-recheck.log` 后续通过。`events-go-targeted.log` 保留了关键词仍只查路径时的失败，修复查询后最终专项及完整竞争检查通过。初轮类型检查发现任务状态标签遗漏 queued／running 类型映射，已修正，最终检查通过。全量前端日志中的 v2 Element Plus 分页弃用提醒是既有提示，测试无失败。

`.cache/verification/v3/console-events-result.json` 保存最终源码、资源、程序和日志摘要，指定六个文件保持原摘要。测试 schema、导出目录、临时容器／卷／网络和本轮浏览器标签页均按归属清理，临时视口覆盖已重置。没有提交、推送、发布、改动生产或发送业务通知。

完整 v3 仍缺其余业务网页、公开安装升级、实际 native／Docker 全流程和旧节点接管、完整证书运维、部署配置备份及旧任务承接、最终增量切换回退、真实可选 HA 和万台／72 小时容量验收。继续保持 v2.0.46，不更新 latest，不将本阶段网页完成视为正式版交付。

## 2026-10-18：告警中心网页、网站异常筛选及通知状态

独立 v3 告警页接入当前异常、告警历史、飞书通知、邮箱通知。当前异常禁止直接删除；其他历史复用既有选择、预览及清理保护。网站故障接口增加可选服务器、当前状态和时间范围，保留旧无过滤调用；当前网站异常排除暂停、删除和待迁移网站，不默认截断持续多日的故障。通知白名单元数据增加发送状态和计划时间，不返回载荷、通道结果或租约身份。业务 schema 仍为 13。

证据位于 `.cache/verification/v3/`：

- `alerts-full-race.log`：真实隔离 PostgreSQL 17 上主控完整竞争检查 246 项主测试、163 个子场景通过，7 项外部条件跳过。跳过仍是两个小磁盘专项、VictoriaMetrics 和四个专用 Linux 上传脚本，不计为实际通过。
- `alerts-backend-targeted-final.log`：4 项相关 API／读模型主测试通过，无跳过。覆盖 40 天持续异常、暂停／删除／待迁移排除、旧查询兼容、服务器及时间筛选、游标和非法参数、通知全部派生状态、空设置停用及敏感字段排除。初轮 `alerts-backend-targeted.log` 的 PostgreSQL 夹具把带参数的两条语句放入同一次预编译执行而失败；拆分夹具语句后保留全部断言，最终完整测试通过。
- `alerts-web-final.log`：15 个文件共 100 项前端测试通过，其中告警页面 12 项。覆盖来源切换、时间窗、迟到错误、后台暂停、不重叠刷新、退出取消、失败保留、空旧结果及游标回退、只读权限和精确大整数删除身份。
- `alerts-linux-final.log`、`console-linux.cXzA6x/integration.log`：最终 Linux amd64 程序在独立内部网络、只读根目录和私有 tmpfs 内完成 17 项主测试、7 个子场景，无跳过。`alerts-typecheck-final.log`、`alerts-build-final.log`、`alerts-go-all.log`、`alerts-vet.log` 分别记录类型检查、双网页构建、Go 全量和静态检查通过。
- 实际浏览器使用独立 schema、24 个合成节点、2 个合成网站及 26 条合成通知；只启动本 schema 历史清理工作器，不启动通知、采集、部署执行器或 SSH。验证 40 天持续网站异常、暂停网站排除、邮件历史切页、单条删除预览、关闭通道暂停状态及字符串大整数详情。删除仅预览，没有通过浏览器提交清理。390×600 下详情和按钮位于可视范围，浏览器无错误／警告。截图为 `alerts-current-website.png`、`alerts-email-paged.png`、`alerts-delete-preview.png`、`alerts-mobile-detail.png`。

`alerts-console-result.json` 保存此阶段源码和日志摘要；后续阶段修改同文件时不能用旧摘要代替新验证。指定六个原有文件摘要一致，测试 schema、导出目录和浏览器按归属清理。完整通知尝试明细与正文、其他完整业务页面、实际 native／Docker 安装迁移、证书运维、最终切换回退、可选 HA 和容量／72 小时验收仍须继续。没有提交 Git、推送、发布、更新 latest 或操作生产。

## 2026-10-18：网站管理网页、软删除及统计一致性

新增独立 v3 网站列表和详情，支持服务端筛选／游标分页、添加编辑、暂停、按版本提交手动检测、明确选择的单条／批量软删除，以及绑定单网站的故障历史入口。写入保留既有版本、防重、旧结果隔离及通知保护，不改变网站检测协议或访问范围。待迁移网站保持禁止操作；只读账号无写按钮。表单正文可滚动，底部反馈和按钮固定可见。

浏览器初验发现旧统计及状态筛选会把待迁移网站的旧 normal 状态当作当前正常。现以迁移中、暂停、正常／故障／待检查／未知的顺序分类，数据库汇总与列表筛选保持互斥一致；增加 unknown 及 migration_pending 筛选，保留已有字段并补充 unknown 统计。没有添加数据库表或改变 schema 13。

证据位于 `.cache/verification/v3/`：

- `websites-full-race-final.log`：最终代码在真实隔离 PostgreSQL 上全量竞争测试 247 项主测试、163 个子场景通过，7 项外部条件跳过。两个小磁盘、VictoriaMetrics 和四项 Linux 专用上传测试未在此次运行，不计为已通过。
- `websites-linux-final.log`、`console-linux.ITYsl0/integration.log`：脚本重新编译最终内嵌网页及 Linux amd64 程序，独立内部网络测试完成 18 项主测试、7 个子场景，无跳过。新增统计专项验证六类互斥、正常和暂停旧证据不掩盖迁移状态、列表筛选与汇总一致；网站原有事务防重、旧检查代次、软删除及权限继续由全量测试覆盖。
- `websites-web-final.log`：16 个文件共 113 项前端测试通过，其中网站 12 项、告警 13 项。覆盖查询与草稿隔离、清空及分页、固定版本保存、表单错误、幂等重试、手动检测排队、不允许迁移中操作、当前页批量选择、只读权限、后台／弹窗暂停、空页回退、统计失败保留和单网站历史入口。
- `websites-typecheck-final.log`、`websites-build-final.log` 记录最终类型检查与双网页构建通过；`websites-vet-final.log` 记录相关 Go 静态检查；`websites-go-all-final.log` 记录最终 Go 全量测试通过。初轮批量测试遗漏 Element Plus 全选的防抖时间，`websites-selection-diagnostic.log` 保留排查；测试推进这段计时后仍严格断言明确选择的两个网站版本，没有放宽产品选择或删除逻辑。
- 实际浏览器使用独立 schema、24 个合成网站和 24 个合成节点；没有启动网站检测、通知、采集、部署执行器或 SSH。验证两页列表及迁移保护，实际保存第 25 个暂停网站并核对反馈、版本、缺失检查结果；手动检测仅提交队列，不连接示例网站；软删除只打开确认，没有通过浏览器执行。`websites-browser-database-proof.log` 核对新增记录、保存审计及检测排队审计。最终截图为 `websites-paged-final.png`、`websites-save-final.png`、`websites-mobile-form-final.png`、`websites-check-queued-final.png`、`websites-delete-confirm-final.png`。390×600 下正文内容高 496 px，在约 385 px 区域滚动；底部按钮位于可视范围，浏览器无错误／警告。

`websites-console-result.json` 保存最终源码、构建及证据摘要。六个原指定文件保持一致，浏览器、测试 schema、导出目录、容器与匿名卷按归属清理。网站历史曲线和完整详情、通知尝试明细、总览、设置、统一备份、公开安装部署与实际 native／Docker 生命周期、证书运维、最终迁移回退、可选 HA 和万台／72 小时验收仍须继续。没有提交、推送、发布或操作生产。


## 2026-10-18：历史设置、范围清理、只读审计及网站备份网页

独立 v3 `/settings` 接入既有保留期限、范围预览、导出／清理及审计接口；没有新增单条或批量删除按钮。五项期限校验、缩短确认、固定版本、幂等重试和新草稿清除旧成功反馈均有保护。任务及审计列表只读，部分完成报告实际数量；后台暂停和页面退出取消读取。`/backups` 接入网站配置快照、原始 JSON 导入／导出、账号绑定合并预览／恢复、保护原因和当前页明确选择的删除。旧 `/config-backups` 转到部署配置页签，该页仍明确标注待接入。保留业务删除规则，schema 仍为 13。

证据位于 `.cache/verification/v3/`：

- `settings-web-final.log`：18 个文件、142 项前端测试通过。新增历史设置 15 项、网站备份 12 项，传输契约增加原始 JSON／UTF-8 字节上限及自动／手动任务响应区分。覆盖期限范围、缩短确认、保留草稿、版本冲突、重试键、迟到错误、明确不导出确认、预览过期、后台暂停与非重叠轮询、部分结果、只读权限、提交条件与分页、文件读取竞争、恢复预览、保护选择、明确批量 ID 和空页回退。
- `settings-typecheck-final.log`、`settings-build-final.log`：类型检查和现有 v2／独立 v3 双入口构建通过，最终网页重新嵌入 Go。
- `settings-full-race-final.log`：本轮真实独立 PostgreSQL 上完整主控竞争检查 247 项主测试、163 个子场景通过，7 项外部条件跳过。两个小磁盘、VictoriaMetrics 和四项 Linux 专用上传条件未在该次测试具备，不计为通过。该次执行之后只追加了网页新草稿反馈清除和相关测试，Go 业务源码未变化；最终内嵌资源另由下列 Linux 专项覆盖。
- `settings-linux-final.log`、`console-linux.B7cUl6/integration.log`：最终 Linux amd64 编译，独立内部网络、只读根目录及私有 tmpfs 中完成 25 项主测试、7 个子场景，无跳过。脚本补入保留 API／工作器、网站备份严格格式及权限、只读审计角色隔离的专项。`settings-go-all-final.log` 和 `settings-vet-final.log` 记录最终 Go 全量及相关静态检查通过；无 DSN 的全量不替代真实数据库检查。
- `settings-live-fixture/`：独立 schema、24 个合成节点、24 个合成网站、24 份初始配置快照及两条普通／探针事件，只启动本 schema 历史清理工作器；不启动网站检测、通知、采集、执行器或 SSH。浏览器实际修改保留期限，范围预览排除探针，仅导出并下载一条旧事件；`settings-download-final.jsonl` 已解析核对。`settings-browser-database-proof.log` 确认原事件和探针均仍存在、导出任务成功且 deleted=0、下载完成审计存在。
- 同一浏览器实际创建第 25 份手动快照；重复 JSON 字段被服务器拒绝；合法导入只增加快照，之后经恢复预览新增一个暂停网站并清除不存在的节点关联，自动生成恢复前快照。数据库核对网站 24→25、单条恢复网站 paused=true/node=''、导入／恢复审计和恢复前快照存在。没有通过浏览器执行永久清理或备份删除，删除行为由前端测试和真实 PostgreSQL 事务测试验证。
- `settings-retention-save.png`、`settings-export-completed.png`、`backups-created-final.png`、`backups-restored-final.png` 保存实际操作结果。`backups-mobile-preview-final.png`、`backups-mobile-import-final.png` 验证 390×600 下恢复提示、长正文滚动及固定按钮；导入正文 422px 在 385px 可视正文内滚动，页脚底部约 559px。浏览器未发现警告或错误。
- 最后微调新草稿反馈后重新构建并启动全新的独立 schema，`settings-final-bundle-draft.png` 和 `settings-final-browser-database-proof.log` 验证最终资源保存 60 天后编辑为 90 天，只显示“尚未保存”，数据库仍为 60 天。截图中的非生产账号、网址及记录均为本次合成数据。

`settings-console-result.json` 保存最终源码、构建和证据摘要。指定六个文件摘要不变。本轮临时 schema、导出目录、容器／卷／内部网络和浏览器按归属清理，视口恢复。没有提交 Git、推送、发布或操作生产。

完整运行设置、各类存储数量／最早时间、任意历史审计时间窗口、部署配置备份与迁移、总览和其他业务细节、公开部署及真实 native／Docker 全流程、证书运维、最终切换回退、真实可选 HA 和万台／72 小时验收仍需继续；保持 v2.0.46，不更新 latest。

## 2026-10-18：部署配置备份内部格式与只读一致性快照

新增 `configuration_document.go`，将启动配置快照、数据库运行设置及节点期望配置整理为私有版本化文档。相同规则使用文档内顺序编号去重；脱敏采用白名单及显式省略路径，不公开敏感配置摘要。按节点 ID 合并缺失字段，避免共用脱敏 profile 时串用凭据。官方 age 密码加密、损坏检测、scrypt 工作量上限及大小限制均已实现。大整数、小数和未知 JSON 数字保留十进制文本，不经过有损浮点转换。

当前是内部基础模块，未新增数据库表，schema 仍为 13；没有开放部署配置备份 API、网页按钮或恢复写入。设置／节点来自单个只读 repeatable-read 事务；启动配置由调用者提供，不代表已经读取磁盘待应用 YAML。完整持久化、预览、待应用与实际恢复链仍需继续，见 [范围与边界](V3-CONFIGURATION-BACKUPS.md)。

证据位于 `.cache/verification/v3/`：

- `configuration-document-full-race-final.jsonl`：最终源码在独立 PostgreSQL 17 上完整竞争检查通过，共 256 个主测试／种子组、188 个子场景，7 项外部条件跳过。新增 8 项配置文档主测试全部通过；只读测试核对版本、节点、部署任务及审计未被修改；并发测试在捕获已读设置后阻塞节点读取，提交新的设置及节点，再确认捕获仍为同一旧快照，后续捕获才读取新值。跳过仍为两个小磁盘专项、VictoriaMetrics 和四项专用 Linux 上传测试，不计为本轮通过。
- 同一完整检查覆盖版本、重复 YAML／JSON 键、多文档、别名／锚点／合并键、未知字段、非法节点参数、无效保留期限、凭据遮罩、非法／重复省略路径、丢失 profile、节点 ID 匹配、未知私有字段及公共投影可变别名隔离。错误密码、截断、篡改、加密包超限和恶意 scrypt 工作因子均被拒绝；没有调用业务通知渠道。
- 两万节点的合成文档完整往返，私有 YAML 为 4,301,457 字节、脱敏 YAML 为 3,861,109 字节，重复规则只有一份。最终 Linux 容器中该编码场景约 6 秒，竞争检查中约 32 秒。它只是格式／体积检查，不是万台采集、事件吞吐或资源容量验收。合并文档 32 MiB／age 包 34 MiB 是原生 v3 的独立上限，原 v2 的 2 MiB／4 MiB 规则未变。
- `configuration-document-console-linux-final.log` 和 `console-linux.LqViDq/integration.log`：更新可复用 `scripts/verify-v3-console.sh`，只读挂载示例配置和测试源码路径供夹具读取；最终 Linux amd64 程序在只读根目录、私有 tmpfs、独立内部网络及新 PostgreSQL 中完成 33 项主测试、27 个子场景，无跳过。原有网页／权限／历史／网站备份专项与新增文档专项同时通过；不是实际安装子控或恢复生产验收。
- `configuration-document-linux-final.log` 单独记录同版本 Linux 程序 8 项配置专项通过。首次运行缺少示例配置只读挂载而失败，保留 `configuration-document-linux-fixture-missing.log`；补齐夹具挂载后保留原断言并通过。没有为通过测试而降低文档校验。
- `configuration-document-numbers.log`、`configuration-document-numbers-final.log` 保留无损数字改造时的失败及最终通过：修正数字检查器默认浮点解码、自定义映射的遮罩检查，并按 YAML 节点保存数值类型。`configuration-document-fuzz.log` 为短时解析烟测，5 份初始样本、11 次执行通过，不声称充分模糊覆盖。
- `configuration-document-go-all-final.log`、`configuration-document-vet-final.log`、`configuration-document-linux-build-final.log` 记录最终 Go 全量、相关静态检查及 Linux amd64 CLI 编译通过。本轮没有修改网页源码或重新构建前端资源；Linux 编译继续使用之前已验证的内嵌网页。无 DSN 的全量不替代真实数据库竞争检查。

`configuration-document-result.json` 保存最终源码、程序及证据摘要。测试库确认自建 schema 全部清除，容器／卷／两张自建网络均按归属移除。六个指定保留文件摘要一致；没有提交 Git、推送、发布、更新 latest、操作生产或连接 229。完整备份应用链、其余业务功能、实际部署迁移、证书运维、最终切换回退、可选真实 HA 和容量／72 小时验收仍未完成，正式发布版本保持 v2.0.46。

## 2026-10-18：部署配置加密存档、引用保护及 schema 14

配置备份增加内部 PostgreSQL 存储：独立 Vault 密钥 AES-GCM 加密、最多 1 MiB 的密文分块、随机身份和绑定元数据的认证。手动捕获与回执在同一个 repeatable-read 事务中提交，重放跳过捕获；导入仅存档。列表为固定元数据白名单，导出有持久临时引用、准备审计及取消清理；恢复／部署／回退引用可阻止底层删除。新增密钥重新加密及旧库升级／灾备承接。没有新增公开 API、CLI 或网页按钮，持久化删除任务、自动引用接入和恢复应用仍待完成。

schema 增至 14。原版本库必须先完成既有一致性备份；失败不迁移。PostgreSQL 归档表顺序保证备份主记录早于分块及引用，保持原 64 MiB JSONL 行上限。灾备恢复清除中断导出引用，保留持久回退引用；读取时再校验分块长度／连续性、AEAD、文档及元数据。独立密钥不进入存档；这没有改变运行设置当前在原表中的存放方式。

证据位于 `.cache/verification/v3/`：

- `configuration-store-full-race-final.jsonl`：最终 Go 源码在独立 PostgreSQL 17 上完整竞争检查通过，265 个主测试／种子组、194 个子场景，7 项外部条件跳过。新增 9 项存储主测试全部通过，包括重复手动请求、配置后来变为非法时仍重放原回执、并发同键序列化重试只创建一份、降权后不能重放、导入不影响原设置／节点／部署／通知，以及 viewer／operator 拒绝读取或导出。跳过仍为两个小磁盘、VictoriaMetrics 和四项专用 Linux 上传测试，不计为本轮通过。
- 同一检查覆盖真实 age 导入／导出、脱敏导入可再次导出、重复脱敏幂等；存储密文及回执／审计无配置正文。大于单分块的文档验证密文篡改、丢块、计数／来源／密钥／nonce 篡改均被拒绝；模拟写入失败后元数据、回执和审计全部回滚，原键可重试。完整多分块文档经 PostgreSQL 备份、空库恢复后字节一致。
- 导出回调被阻塞时，另一连接确认列表保护和删除拒绝；结束、错误及取消后引用解除。过期导出引用不再保护，永久恢复／部署／回退引用保护，独立的新备份可删除且父记录／分块／引用不残留。分页游标无重复，迁移期间保护生效。此处验证的是内部事务函数，**不是用户可提交的批量删除任务或 HTTP 下载完成**。
- 新旧独立密钥共同打开旧存档后可原子重新加密，ID 和文档保留、revision 增加；新密钥可读，单独旧密钥不可读，重复同钥操作不再增加 revision。schema 13 无备份和备份失败时均停止，成功升级留下可恢复的原 schema 13 归档；旧 schema 9／11／12 的既有升级与灾备测试也继续通过。
- `configuration-store-console-linux-final.log`、`console-linux.ZpH7an/integration.log`：更新复用脚本，最终静态 Linux amd64 CLI 及测试程序在只读根目录、私有 tmpfs、独立内部网络和新 PostgreSQL 中完成 45 项主测试、37 个子场景，无跳过；含既有网页／权限／历史／网站备份、配置文档、存储及旧版本升级专项。没有实际安装、卸载或连接生产子控。
- `configuration-store-targeted.jsonl` 保留首轮三项回执断言失败：PostgreSQL JSONB 改变对象字段顺序，字节比较不适合语义回执。测试改用既有规范化比较，并保留数量、身份、权限及防重断言；最终专项 `configuration-store-targeted-final.jsonl` 和完整竞争检查通过。没有修改产品回执或放宽防重逻辑。
- `configuration-store-go-all-final.log`、`configuration-store-vet-final.log` 分别记录 Go 全量及相关静态检查通过。网页源码未变化，未重复构建前端；Linux 编译使用之前已验证的内嵌网页。旧升级测试仅补齐移除新增 schema 14 表的夹具步骤，原门禁／数据／灾备断言全部保留。

`configuration-store-result.json` 保存当前源码、Linux 程序和证据摘要。临时库确认无剩余自建 schema，临时容器、匿名卷及网络按归属清理；六个指定文件摘要不变。未提交 Git、推送、发布或操作生产。接下来仍需受信 HTTPS 与解密限流、公开接口及网页、持久化删除任务、恢复预览与待应用模型，其他 v3 部署迁移／HA／容量门禁也未完成，保持 v2.0.46。


## 配置存档 API 与网页接入（本地，未发布）

在 schema 14 内新增管理员专用配置存档路由，未新增数据库结构。手动存档使用与随机运行实例 ID 分离的原始启动快照，加同一 PostgreSQL 快照内的已保存设置与节点。它不捕获后来编辑的磁盘 YAML，也不代表已部署。

- 配置列表、创建、严格 YAML 导入、age 导入、脱敏导出及 age 导出已经接通；导入只存档。所有写入沿用登录、CSRF，创建／导入沿用幂等键，存储层再次检查管理员权限。
- 传输校验覆盖原生 TLS、显式代理 IP／CIDR、IPv6、映射 IPv4、伪造转发头、重复头、错误协议及不允许信任所有地址。没有隐式信任回环地址，也不把 PublicURL 当作传输证明。
- 真实 age 往返覆盖错误密码、短密码和确认不一致、导入不改节点／设置／部署／通知，以及密码和正文不进入回执或审计。multipart 拒绝重复／缺失／未知字段及过长密码；不将上传包落入临时文件。源文件名不能指定服务器路径。
- PostgreSQL 计数验证账号与全库窗口、失败计数、窗口到期、API 重建后仍限流，以及非管理员在计数／KDF 前被拒绝。事务 advisory lock 验证跨实例两个工作位、第三次拒绝、请求取消后同步计算尚未返回时仍占用工作位、操作退出后释放；两连接池只允许一个加密工作位，备份业务读写继续完成。
- 网页配置页签已支持存档、独立游标、文件／文本导入与下载；恢复和持久化删除明确显示待接入，不影响网站备份及系统设置范围。前端测试覆盖不确定结果重试复用键、原始 YAML 重复字段不被前端吞掉、导入不应用、文件读取竞争／取消、过大文件保留输入、密码清除、离开页面中止请求、分页及刷新失败保留结果、非管理员不读取配置存档。
- `configuration-api-frontend-typecheck-final.log`、`configuration-api-frontend-tests-final.log`、`configuration-api-frontend-build-final.log` 记录类型检查、151 项前端测试和两套页面构建通过。传输测试额外核对 multipart 自动边界、密码仅在请求体、UTF-8 字节长度、下载类型／长度和截断拒绝。前端已重新嵌入 Go，原 v2 版本标识未改为正式 v3。
- `configuration-api-desktop.png`、`configuration-api-mobile.png` 为内嵌构建页在本地布局夹具上的观察：1280 与 390 像素窗口均无根页面横向溢出，窄屏表格自身可滚动，HTTP 下禁用敏感导入／导出。夹具仅提供合成元数据，不是浏览器经真实 PostgreSQL 完成的端到端验收，也不替代 Linux API 测试。测试页和本地服务已关闭，视口覆盖已恢复。
- 首次 Linux 接口测试发现新夹具只替换 Vault 路径、没有配齐其余 DeploymentTrust 必填字段，因此备份按预期拒绝非法 bootstrap。补齐合成路径并在夹具中先执行完整配置校验后重跑通过；没有放宽产品参数校验。首轮诊断保留于 `configuration-api-console-linux.log`。

恢复预览、待应用／实际生效模型、自动备份引用、持久化备份删除与旧 YAML 映射仍需继续。更完整的生产迁移、部署生命周期、证书管理、HA 安装和万台／72 小时容量门禁没有据此通过；本轮不发布、不推送、不操作生产。


最终 Linux amd64 证据 `configuration-api-console-linux-final.log`、`console-linux.NtnSHx/integration.log`：静态 CLI／测试程序包含本轮重建的前端，在只读根目录、私有 tmpfs、新建 PostgreSQL 17 和无出站内部网络中完成 **51 项主测试、49 个子场景，零跳过**。新工作位门禁与请求取消分离后已重新编译和重跑；不是只沿用修改前证据。`configuration-api-targeted-final.jsonl` 另记录最终配置存档专项竞争检查通过；完整竞争检查另记在本轮结果清单。

最终 `configuration-api-full-race-final.jsonl` 在独立 PostgreSQL 17 上完整竞争检查通过：271 项主测试／种子组、206 个子场景，另有 7 项外部条件跳过，耗时 306.573 秒。跳过仍为两个小磁盘、VictoriaMetrics 和四项专用 Linux 上传检查，不计为通过。取消工作位保护修复前的已通过回归单独保存在 `configuration-api-full-race-before-cancellation-fix.jsonl`；最终结果不沿用修改前二进制。Go 全量检查及相关 vet 通过。

## 2026-10-18：配置存档持久化删除、导出期间保护及 schema 15

配置备份接入固定范围单条／批量预览、确认、持久化任务及本账号任务列表／详情。预览绑定账号和设置版本，十分钟有效；预览时保护项保持排除，实际执行时再次检查引用。与历史清理共用持久租约、代次及两秒总预算；一份备份一笔事务，主记录、密文分块、检查点、计数和审计原子提交。永久单条失败保留原记录并继续后续项，基础设施失败重试且不饿死独立历史清理。无引用的配置备份不套用普通历史二十四小时限制，其他删除规则和系统设置范围保持不变。

schema 15 的已有库升级仍要求先完成一致性备份。普通进程重启续作；灾备恢复取消未完成删除，并保留完成检查点及去重回执。终态任务及其逐项结果保留 365 天，回收分批不超过五百行，运行任务和引用预览不回收。导出引用延长至实际 HTTP 写入返回，下载失败后解除，不将“准备完成”或 Write 结果当作用户已保存。

本轮本地证据位于 `.cache/verification/v3/`：

- `configuration-delete-target.log`：11 项数据库专项测试在独立 PostgreSQL 17 下以 `-race` 通过，无跳过。覆盖固定／缺失／新增引用、重启接管、降权、设置变化、同键并发、不同预览竞争同一备份、单条错误隔离、审计失败全事务回滚、共享工作器、配额、维护回收、灾备取消、CSRF／Origin、HTTP 导出保护。
- `configuration-delete-race.jsonl`：完整 controlplane 竞态测试 282 项主测试／种子组通过、206 个子用例通过，耗时 349.048 秒；7 项专用环境用例明确跳过，没有失败。这不是全平台、真实 HA 或容量验收。
- `configuration-delete-vault-independent.log`：在上述回归后补充不可用 Vault 路径的接口检查；管理员删除和任务查询无需解密配置，专项竞态测试通过。
- `configuration-delete-linux-console.log`：扩充后的隔离 Linux amd64 验收 62 项主测试、49 个子用例通过，零跳过；测试网络无公网。证据子目录 `console-linux.c5NUSu` 保留静态程序、编译测试程序和日志。
- `configuration-delete-ui-all.log`：20 个前端测试文件、158 项通过；`configuration-delete-typecheck.log`、`configuration-delete-build.log` 为类型检查及构建。实际网页已重新嵌入 Go。
- `configuration-delete-go-all.log`、`configuration-delete-vet.log`、`configuration-delete-openapi.log`：Go 全量、相关静态检查和 API 文档合约通过。全量 Go 未启用外部数据库，仅上列专用日志代表实际 PostgreSQL 验证。
- `configuration-delete-desktop.png`、`configuration-delete-preview.png`、`configuration-delete-mobile-preview.png`、`configuration-delete-mobile-progress.png`、`configuration-delete-desktop-progress.png`：真实构建在回环地址的合成元数据页面，覆盖禁选引用备份、确认预览及部分完成结果；窄屏详情改成逐项卡片，直接可读保护原因。仅布局夹具，不代表生产写操作验收。浏览器视口已复原、临时标签已关闭。

早期前端完整运行发现两项旧“删除待接入”文案断言未更新；保留原分页与旧请求断言，仅同步已实现能力的文案后，最终完整测试通过。没有放宽业务保护或删除测试。独立测试库确认无遗留自建 schema，临时服务、容器、匿名卷和网络按归属清理；六份指定原文件摘要不变。

`configuration-delete-result.json` 保存源码与证据摘要。未提交或推送 Git，未发布、未修改 latest、未访问生产。配置恢复／待应用、自动部署引用、完整迁移切换、HA 安装及容量稳定性门禁仍未完成，`complete_v3` 仍为 false。

## 2026-10-18：恢复规划、持久化预览基础及 schema 16

本轮补齐内部恢复文档规划及账号绑定十分钟预览，未开放恢复 API、CLI 或网页写入。默认保留整个通知通道及私有身份，未知分支保守保留；脱敏省略按同一节点 ID 补全。拓扑、部署方式和节点移除要求专用流程；版本不倒退，纯比较始终要求后续本地验证。相同源／当前 profile 只展开一次，扩展体积提前限制，避免万节点共享大规则时逐台复制。

schema 16 将随机令牌摘要、账号版本、恢复选项、分域 HMAC 和安全摘要持久化，绑定原备份 ID／逻辑内容、完整已保存配置及部署证据。源备份引用和审计同事务提交。重新捕获时间不误判配置变化，密文重新加密不误判逻辑内容变化；未知／缺失旧密钥拒绝旧预览。数据库普通重启可复核；灾备取消所有旧恢复预览，只解除它们自己的临时引用，保留真正的持久回退引用。

本轮证据位于 `.cache/verification/v3/`：

- `configuration-restore-full-race.jsonl`：最终源码在独立 PostgreSQL 17 上完整 `controlplane` 竞态回归通过，**299 项主测试／种子组、226 个子场景通过，7 项专用环境跳过，零失败，377.290 秒**。跳过为两个小磁盘、VictoriaMetrics 和四项 Linux 专用上传／安装外部测试，不把它们计作本轮通过。
- `configuration-restore-linux-console.log`、`console-linux.o7dIwV/integration.log`：最终静态 CLI 和测试二进制在新建内部 Docker 网络、独立 PostgreSQL、只读 Linux amd64 容器中通过 **79 项主测试、69 个子场景，零跳过**。脚本已将恢复规划与预览加入常规隔离验证范围。
- 新增预览测试覆盖账号／权限／选项／源身份、设置及节点正文／版本、节点增删、启动配置、部署任务、令牌与引用过期、迁移冻结、配额并发、审计失败原子回滚、密钥轮换、维护回收及 schema 15 一致性备份／灾备恢复。存储的展示摘要不是执行配置，重查时重新规划；先前生成的删除预览不能绕过新建的恢复引用。
- 纯文档专项覆盖默认凭据身份、明确替换、省略与未知分支、数组身份、输入隔离、敏感输出保护、版本归一化、专用迁移阻止项、独立信任与吊销引用、一万节点共享 64 KiB 配置，以及扩展后超过 32 MiB 的提前拒绝。合成配置测试**不代表万台采集容量或 72 小时稳定性验收**。
- `configuration-restore-go-all.log`、`configuration-restore-vet.log`：Go 全量及相关 vet 通过。全量 Go 未连接外部数据库；实际 PostgreSQL 验证以上述专用竞争和容器结果为准。本轮未修改前端，不重复前端构建或沿用旧前端结果声称新增网页恢复能力。

`configuration-restore-result.json` 记录最终源码、程序和证据摘要。原有六个指定文件摘要不变，独立测试库已无自建 schema，临时容器、匿名卷及内部网络按归属清理。没有提交／推送 Git、发布、修改 latest 或访问生产。

下一步仍须统一配置写入与部署创建互斥、完成本地路径／凭据检查、恢复前自动备份、待应用及实际生效，再接公开恢复操作。完整部署／PKI 生命周期、旧版迁移及增量回退、单中心／HA 安装、实际容量和稳定性门禁仍未完成，保持 `complete_v3: false`，正式版本不变。


## 2026-10-18：恢复前存档、待验证意图及 schema 17

内部恢复提交增加数据库关系锁门禁，覆盖设置、节点与部署任务的全部增删改入口，包括直接 SQL；正常查询和事件接收继续执行。事务只允许 READ COMMITTED，等待锁后重新读取最新状态，拒绝可能沿用旧快照的隔离级别。恢复前加密存档、两份持久引用、预览消费、意图、回执与审计原子提交，失败保留原预览供重试。当前状态仅为“待本地验证”，不修改运行配置，不表示已保存／已应用。

取消只删除本意图的两个引用；原备份、业务记录及真实回退引用保留。其他现任管理员可取消已失联／降权账号留下的意图，但不能以其身份继续。继续前重新认证来源、恢复前存档、账号版本、选项和完整当前配置／部署证据，不信任展示摘要。灾备恢复取消旧意图，普通进程重启保留意图；原去重回执不能复活已取消工作。

证据位于 `.cache/verification/v3/`：

- `configuration-stage-full-race.jsonl`：独立 PostgreSQL 17 完整竞态回归 **309 项主测试／种子组、256 个子场景通过，零失败，396.400 秒**。另有 7 项专用环境检查跳过（两个小磁盘、VictoriaMetrics 和四项 Linux 上传／安装），没有计作通过。
- `configuration-stage-target.log`：新增 10 项主测试、30 个子场景专项竞态通过，覆盖存档／引用／审计失败原子回滚、同键并发、权限及过期、取消回滚、365 天回收、关系锁阻止实际写入口且事件接收可用、锁等待后的新状态检查、取消释放锁、旧库备份门禁和灾备保护。
- `configuration-stage-linux-console.log`、`console-linux.CH1I22/integration.log`：最终静态 Linux amd64 CLI 和测试程序在独立内部网络、PostgreSQL、只读根目录容器中通过 **89 项主测试、99 个子场景，零跳过**。没有连接真实子控或通知渠道。
- `configuration-stage-go-all.log`、`configuration-stage-vet.log`：Go 全量和相关静态检查通过。前端未修改，没有新增公开恢复按钮或接口。

`configuration-stage-result.json` 保存本阶段源码、程序和证据摘要。六份指定文件摘要不变；测试 schema 已清除，专用 PostgreSQL 容器继续用于后续本机验证测试，最终按归属清理。未提交／推送 Git、发布、修改 latest 或访问生产。后续仍需本机资料检查、完整保存／应用模型、公开恢复、迁移回退、单中心／HA 安装和实际容量稳定性验收。


## 2026-10-18：恢复配置本机资料只读诊断（schema 17）

新增内部诊断，先在 READ COMMITTED 关系锁门禁下重新认证待验证意图，再读取候选配置中的本机资料。没有公开恢复接口、CLI 或按钮，不写入待应用／实际生效配置，不改变意图状态。所有结果只有固定组件及原因，不包含路径、DSN、证书身份、密钥身份或底层错误。

已配置的检查覆盖 DSN 私有文件、后台证书／私钥／域名／有效期、采集身份及信任、吊销单调历史、签名工具摘要、Vault 全部当前读取密钥延续、启用的 CA 签发资料、私有目录及 HA 本机 SSH 私钥。缺失资料不自动生成；不使用会初始化或推进 CRL 状态的运行时方法。DSN 仅检查文件受控且非空，不隐式解析环境或连接数据库；目录只读检查权限、inode 与超过 64 MiB 的余量，不写探针。不把这些检查当作网络、数据库权限、完整容量或 HA 入口验收。

新增专项覆盖同一路径文件改变后的重新读取、多项错误独立保留、缺失／空／超限／权限错误文件、符号链接祖先与叶、硬链接及 FIFO，证书角色／主机名／密钥／有效期、实际已吊销身份、丢失／损坏／不同根／回退／签名撤销历史、过期真实历史加有效续期的只读验证，签名／工具／归档篡改，缺少独立密钥及安全轮换保留旧密钥。真实待验证意图的 PostgreSQL 测试核对存档、引用、回执、审计、文件未改变，另一管理员或配置变化不能沿用原意图；本地 TCP tripwire 未收到连接。

`configuration-local-linux-console.log`、`console-linux.6HqC8n/integration.log`：最终静态 Linux amd64 CLI／测试程序在独立内部网络、PostgreSQL、只读根目录及受限 tmpfs 中通过 **99 项主测试、143 个子场景，零失败、零跳过**。可复用脚本增加专用 1 MiB tmpfs，磁盘余量不足检查真实执行；没有填满宿主机磁盘，也没有连接业务通知、真实 SSH 或生产。

`configuration-local-go-all.log`、`configuration-local-vet.log`：Go 全量及相关静态检查通过；无外部 DSN 的全量不替代真实数据库测试。网页未修改，不重复构建前端。首轮专项夹具用了不存在的回执表名，编译阶段也修正了计数类型；诊断日志保留，改用实际 `v3_requests` 后，`configuration-local-target-final2.log` 中原数量与只读断言全部通过，没有更改产品表名或放宽保护。

`local_checks_passed` 只表示这次已配置的本机检查结果；未配置的可选项单独说明。`requires_apply_checks` 始终为 true，报告不能作为应用凭据或跳过最终复核。仍须完成统一保存／下发／生效模型、独立凭据引用与数据库权限复核、公开恢复、完整配置及总览、部署／PKI／旧版迁移、单中心／HA 安装与容量稳定性门禁，不能发布完整 v3。


最终完整数据库竞态证据 `configuration-local-full-race.jsonl`：独立 PostgreSQL 17 下 **318 项主测试／种子组、300 个子场景通过，零失败，389.476 秒**。8 项专用环境检查在这轮跳过：新增本机余量检查、原两个小磁盘、VictoriaMetrics 和四项 Linux 上传／安装；新增余量检查已在上述最终 Linux 容器中独立通过，其余跳过没有被计作本轮通过。标准错误为空。

`configuration-local-result.json` 保存最终源码、程序及证据摘要。六个指定文件摘要未改变；两阶段共用的专用 PostgreSQL 确认无自建 schema 后删除容器与匿名卷，最终 Linux 检查的容器／卷／内部网络也已清理。Git 仍在 main，没有提交或推送、发布、更新 latest 或访问生产。`complete_v3` 仍为 false。
## 2026-10-18：schema 18 与总览最终回归

此项记录独立加密待应用恢复版本和总览分区缓存／网页的检查点；不代表完整 v3 或生产验收。证据为 `.cache/verification/v3/dashboard-result.json`，源码清单为同目录 `dashboard-final-source.json`。后续编辑前备份实现使用独立验证记录。

- 真实隔离 PostgreSQL 的 `go test -race -json ./internal/controlplane -count=1`：333 个主测试、327 个子用例通过，8 个主测试按环境跳过，494.208 秒；跳过项逐项保存在结果文件。
- Linux amd64 隔离后台：114 个主测试、170 个子用例通过；目录 `console-linux.kx2u50`，该脚本创建的容器及网络已自动删除。
- 全仓 `go test ./...`、`go vet ./...` 通过；前端类型检查、21 个文件的 163 个测试及构建通过，内嵌资源已重建。
- 本地合成数据浏览器验收：六组摘要、十三张组件卡、资源图表；桌面及 390px 手机视口，无整页水平溢出，无浏览器错误。截图为 `dashboard-desktop.png` 和 `dashboard-mobile.png`。
- 早先一次完整回归在事件迁移租约测试失败，单独复查及上述最终完整竞态回归均通过；早先全仓测试中的旧中心就绪请求竞态也已独立复查并通过最终全仓回归。保留失败日志，不将其算作通过记录，未放宽产品门禁或用例。

原有六份未提交修复的 SHA256 全部保持；未提交／推送 Git、更新标签、访问生产或发送业务通知。剩余完整设置／应用、安装与 PKI、迁移切换／回退、独立机器 HA 和容量稳定性门禁不变。

## 2026-10-18：公开配置编辑前原子备份

服务器登记及保留期限保存入口增加 `before_edit` 加密存档，与原变更、回执和审计同事务提交。专项覆盖并发同键重试、连续编辑前的完整私有快照、备份头／分块／两类审计写入失败及同键恢复、版本冲突、未完成部署、管理员降权、CSRF、Vault 缺失、重复新增、无原始启动快照、取消等待、损坏已保存配置，以及锁等待结束后的最新已提交状态。

- `before-edit-target-final.jsonl`：9 项主测试、14 个子用例通过，使用隔离 PostgreSQL 和竞态检测。
- `before-edit-full-race.jsonl`：最终源码完整数据库竞态回归 339 项主测试、341 个子用例通过，8 项按专用环境条件跳过，495.066 秒；跳过项见 `before-edit-result.json`，测试期间源码摘要未改变。
- `before-edit-linux-console.log`、`console-linux.Jv8Mz2/integration.log`：Linux amd64 独立内部网络、只读根目录及测试 PostgreSQL 下 120 项主测试、184 个子用例通过，零失败、零跳过；脚本已清理自己创建的容器与网络。
- `before-edit-go-all.log`、`before-edit-vet.log`：全仓 Go 测试、`go vet ./...` 通过。前端没有修改，沿用上一检查点的类型检查、163 项测试、构建与浏览器证据。

首次专项编译发现一个未使用的测试导入，已删除后重新编译并执行上述测试，初始失败日志保留为 `before-edit-target.log`。未放宽备份保护或测试断言。原有六份修复摘要保持，未发布、推送或操作生产；普通设置统一生命周期、部署前存档、实际恢复应用及其余完整 v3 门禁仍须继续。


## 2026-10-18：部署前存档、回退引用及解密认证

可信本地排队与预览确认已原子创建 `before_deploy` 加密全配置存档及精确任务引用，绑定不可变计划摘要。测试覆盖存档头／分块／引用／审计／任务日志失败全部回滚、同键重试、有界序列化重试、普通执行器并发与恢复快照门禁、租约接管、恢复责任及引用原子切换、只释放本任务引用。执行器还实际认证解密存档，在首次远端调用及备份／恢复前核对目标和 PostgreSQL 规范化配置；密钥缺失／错误、密文／nonce／元数据损坏及可解密的错误目标均不得连接远端，密钥轮换和大整数／小数保持有效。

- `before-deploy-final-race.jsonl`：最终源码、真实独立 PostgreSQL 17 下完整竞态回归 **350 项主测试、374 个子用例通过，零失败，505.101 秒**。8 项专用环境测试跳过，逐项见 `before-deploy-result.json`；没有计为通过。
- `before-deploy-final-linux-console.log`、`console-linux.UEAXcQ/integration.log`：静态 Linux amd64 CLI 和测试程序，在独立内部网络、只读根目录及受限 tmpfs 下通过 **149 项主测试、264 个子用例，零失败、零跳过**。新增实际 CLI 的账号绑定预览／确认、幂等重放与本地部署专项；执行器远端操作使用明确的进程内测试替身，没有连接真实 SSH。
- `before-deploy-final-go-all.log`、`before-deploy-final-vet.log`：全仓 Go 测试及 `go vet ./...` 通过。前端及内嵌资源的 36 份摘要与总览验收源码一致，沿用此前类型检查、163 项测试、构建和浏览器记录，不重复声称新增前端验收。
- `before-deploy-auth-target2.jsonl`：新增解密校验的 3 项主测试、13 个子用例先行通过。首次编译使用了错误的测试字段名，修正后执行；失败记录保留在 `before-deploy-auth-target.jsonl`。更早的 `before-deploy-full-race.jsonl` 与 Linux 记录编译于解密校验加入前，仅作中间回归，不替代最终源码结果。

`before-deploy-final-source.json` 与 `before-deploy-result.json` 绑定最终源码、Linux 程序和证据摘要。原有六份修复保持；测试库确认无自建 schema 后，删除本轮 PostgreSQL 容器和匿名卷，Linux 脚本自建容器及内部网络也已清理。补充总览文档的 Git 忽略例外，防止专题文档在后续人工提交时遗漏。

schema 保持 18，公开部署写入仍关闭，旧无备份绑定任务不伪造历史存档。没有提交／推送、发布或更新 latest，没有访问生产或发送业务通知。普通配置保存／下发／生效、实际恢复应用、完整安装与 PKI、旧版本增量切换／回退、单中心／HA 和容量稳定性验收仍未完成，不能发布完整 v3。

## 2026-10-18：节点保存、运行登记与生效分离（schema 19）

本轮修正“仅保存节点就立即改变采集、停用告警”的问题。配置快照、运行登记及递增代次分别持久化；部署激活与登记同事务提交，验收完成后才推进生效版本。仅保存的新节点不采集，回退恢复原登记，首次安装回退撤销登记；旧请求即使遇到相同配置版本仍被运行代次隔离。总览、告警与运行状态按实际登记读取。

| 检查 | 结果 |
|---|---|
| 完整真实 PostgreSQL `-race` | 360 项主测试、381 项子用例通过，508.125 秒；8 项专用环境用例明确跳过，无失败 |
| Linux amd64 隔离控制台 | 160 项主测试、271 项子用例通过，无跳过 |
| 前端类型检查、测试与构建 | 通过；21 个文件、165 项测试通过，产物已嵌入 Go |
| Go 全量测试与 `go vet ./...` | 通过；未配置外部存储环境的全量运行不替代上述真实 PostgreSQL 回归 |
| 本地浏览器 | 通过合成只读列表及详情核对保存／下发／生效、运行开关与未登记状态；不是生产或后端集成验收 |
| 源码及既有修复 | 最终回归期间源码冻结；六个受保护文件 SHA256 保持一致；`git diff --check` 通过 |

新增验证涵盖目标／原快照摘要损坏、代次不一致、首次安装回退与重新安装、发布失败原子性、采集与发布的真实行锁竞争、验收先租约后节点的锁顺序，以及 schema 18 备份门禁和灾备恢复后的代次续增。发布登记同时清除旧目标的当前状态缓存和短期观测，不清除历史事件或指标游标。

PostgreSQL 中跳过的 8 项为：两个 Linux 小 tmpfs 用例、VictoriaMetrics 联调、四个显式 Linux 工具上传／安装脚本用例，以及发布信任工具低磁盘用例。两个控制台低磁盘用例已在本轮 Linux 容器覆盖；其余独立环境检查未因本轮节点登记变更而重复运行，旧证据仍保留，不将跳过计为通过。

最终证据为 `.cache/verification/v3/node-runtime-releasegate-pg.jsonl`、`node-runtime-releasegate-linux.log`、`node-runtime-result.json` 及其源码／产物摘要。此前诊断失败和被后续源码取代而中断的运行保留原始日志，不计入最终通过结果。中断产生的一个临时 schema 已在确认无客户端后清理；自建 PostgreSQL 容器及其卷在测试 schema 数为零后移除。未操作其他数据库或容器。

没有提交／推送 Git，没有发布或更新 latest，没有连接生产及业务通知渠道。完整 v3 仍未完成：普通设置完整生命周期、实际配置恢复应用、公开安装／升级与 PKI 生命周期、旧部署增量切换及无损回退、单中心／高可用与容量稳定性验收等门禁继续保留。节点模块详见 [运行登记说明](V3-NODE-RUNTIME.md)。


## 2026-10-18：设置草稿、运行基准与保留期限隔离（schema 20）

本轮补入独立设置草稿和内部显式应用事务。普通保存不改变运行设置；编辑前加密存档、草稿／应用标记、回执及审计原子提交。证明绑定 PostgreSQL 实际存储正文、独立代次及运行版本／正文摘要，拒绝篡改、过期基准、缺失密钥和降权账号。保留期限只更新五项天数，并合并草稿中的相同字段，不应用待确认的 SMTP、告警等修改。

新增测试覆盖：保存后现有工作器仍读旧策略、应用失败全部回滚、丢失响应重放、八个并发同键保存、已应用草稿及同值期限更新、超出安全整数范围的参数、PostgreSQL 科学计数法／负零规范化、存档捕获保存态与独立代次、证明损坏／运行基准漂移、Vault 轮换／缺失旧密钥、旧 YAML 初始化不能覆盖草稿、schema 19 备份门禁及灾备后草稿和代次延续。全部使用隔离库与虚构通知地址，不启动外部通知或连接子服务器。

| 最终检查 | 结果 | 本地证据 |
|---|---|---|
| 主控完整 PostgreSQL 竞态回归 | 372 项主测试、391 项子场景通过，512.007 秒；8 项依赖外部测试环境的场景明确跳过 | `.cache/verification/v3/settings-draft-final-pg.jsonl` |
| Linux amd64 后台验证 | 172 项主测试、281 项子场景通过，0 跳过；包含私有低磁盘 tmpfs 场景 | `.cache/verification/v3/console-linux.Ca84I4/integration.log` |
| 节点工具完整竞态回归 | 147 项主测试、413 项子场景通过，118.582 秒；3 项需额外 Docker 验证环境的场景明确跳过 | `.cache/verification/v3/settings-draft-final-nodeops.jsonl` |
| Linux 空间不足测试 | 128 MiB tmpfs 中确认备份不足时不停止原服务 | `.cache/verification/v3/settings-draft-final-nodeops-linux.log` |
| Go 全包测试与静态检查 | 通过；测试夹具修正后另跑完整节点工具竞态回归及静态检查 | `.cache/verification/v3/settings-draft-final-go-all.log`、`settings-draft-final-vet.log`、`settings-draft-final-nodeops-vet.log` |
| 网页及嵌入资源 | 86 个文件与上一轮验证摘要一致，复用上轮 165 项前端测试、检查及构建证据 | `.cache/verification/v3/node-runtime-result.json` |
| 保护及清理 | 六个受保护文件摘要一致；源码冻结后仅追加本验证文档；临时数据库零测试 schema 后移除，最终 Linux 容器及网络已清理 | `.cache/verification/v3/settings-draft-result.json` |

早先扩展回归发现节点工具的空间测试夹具依赖瞬时可用容量，其他测试释放文件后，预期的空间不足可能已不成立，导致测试失败并复制巨大稀疏文件。已改为构造逻辑尺寸超过整个文件系统容量的稀疏文件，并加五秒超时；部署空间判断及停服逻辑未改。最终节点工具全量竞态和独立 Linux 测试均通过。早先运行保留为诊断日志，不记作最终通过证据。

科学计数法边界在首次广域回归运行期间补齐；最终主控竞态与 Linux 后台均使用修正后的实现。冻结清单、后续仅文档变更及各日志摘要见 `settings-draft-result.json`，不能把旧编译结果当作最终实现的唯一证据。

普通设置的公开预览／编辑／应用、恢复候选到真实保存态的提交、启动及网络校验、完整安装／PKI 运维、旧版切换与增量回退、单中心／HA 安装与真实容量稳定性验收仍需继续。本轮没有访问生产、发送业务通知、提交或推送 Git、发布正式 v3 或更新 latest。当前范围见 [设置生命周期](V3-SETTINGS-LIFECYCLE.md)。

## 2026-10-19：恢复到真实保存态（schema 21）

内部认证候选可原子提交到待部署节点、设置草稿及本成员启动草稿。已有运行登记、采集代次、已生效版本和工作器策略保持不变，新增节点不自动登记；不写磁盘 YAML、不连接子控或创建通知。提交、状态、安全证明、两份存档的回退保护及审计同事务完成，注入任一步失败均回滚。同键重试不重复变更，历史回执不授权后续编辑。

补测存档身份／内容、回退引用、账号版本和证明损坏，schema 20 备份失败阻止升级，旧格式灾备取消未提交意图，以及新灾备保留保存态、启动草稿、独立代次和证明。数字测试覆盖 JSONB 合并等价 profile、科学计数法、负零、超过安全整数范围的大数和高精度小数。启动草稿验证稳定成员隔离、密钥轮换、缺失旧密钥、运行基准漂移及旧 YAML 初始化保护。

| 最终检查 | 结果 | 本地证据 |
|---|---|---|
| 主控完整 PostgreSQL 竞态回归 | 384 项主测试、435 项子场景通过，629.096 秒；8 项外部条件明确跳过 | `.cache/verification/v3/restore-saved-final-pg.jsonl` |
| Linux amd64 后台验证 | 184 项主测试、325 项子场景通过，0 跳过 | `.cache/verification/v3/console-linux.HVZG4z/integration.log` |
| 两万节点恢复 | 合成配置完整导入、预览、候选、提交及当前状态复核通过；全量竞态中的该用例 67.94 秒，单次提交仍使用 30 秒上下文预算 | `restore-saved-final-pg.jsonl` |
| Go 全包与静态检查 | 全部通过 | `restore-saved-final-go-all.log`、`restore-saved-final-vet.log` |
| 前端与既有修复 | 86 个网页／嵌入文件摘要未变，复用 165 项前端测试及构建证据；六个保护文件一致；节点工具代码及测试未变 | `restore-saved-result.json` |
| 清理 | 自建 PostgreSQL 零测试 schema、零其他连接后移除；Linux 脚本所属容器与网络已清理 | `restore-saved-cleanup.json`、`restore-saved-linux-cleanup.json` |

早期两万节点竞态测试暴露恢复准备和提交超时，诊断日志保留，不计作通过。定位并移除 YAML 库对大型映射的逐对重复键检查，改为按键索引和逐条严格解码；复用已经校验的树，避免配置克隆重新解析，复用同事务认证版本，并缓存同次捕获中相同规则的校验。重复键、未知字段、别名、类型、体积和事务预算门禁保持有效。最终冻结实现完成上述全量验证，没有靠延长事务时限通过。

八项跳过为本机缺少专用小磁盘、VictoriaMetrics 或 Linux 上传条件；Linux 后台脚本覆盖其中本机资料低磁盘场景，其余项目未计为本轮通过。源清单为 `restore-saved-final-source.json`，最终交付仅追加本验证文档，汇总见 `restore-saved-result.json`。

两万节点测试只证明合成配置处理能力，不代表一万／两万台真实采集吞吐、HA 或 72 小时稳定性验收。公开设置／恢复工作流、实际运行应用和重启协调、完整安装与 PKI、旧版本增量切换／回退、单中心／HA 安装及容量门禁仍未完成。没有提交或推送 Git、访问生产、发送业务通知、发布完整 v3 或更新 latest。

## 2026-10-19：运行设置公开预览、保存及独立应用（schema 21）

本轮将普通运行设置接入管理员 API 和网页：只返回可编辑字段、保存／运行版本及凭据配置标记；部分编辑保留未知参数和大数精度。凭据采用保留／替换／清除，预览仅显示变更字段和风险。十分钟签名绑定账号版本、完整配置、目标设置与最新部署证据，确认时重新校验并原子写入编辑前加密备份、变更、回执及审计。仅保存不激活工作器；应用只接受已保存且受支持的运行字段，不启动测试通知或远端部署。

新增用例覆盖严格 JSON 类型、重复键、大小写别名、null／超限、未知路径、遮罩凭据、账号与配置变化、已结束或未完成部署、签名与有效期、缺失密钥、密钥轮换、取消请求、同键并发确认、回滚后的重试，以及应用包含未支持策略时拒绝。前端覆盖未设置值、凭据不回显及关闭清理、明确预览、保存／应用分离、过期预览、冲突、模糊结果同键重试、草稿保留、权限和离页迟到响应。测试发现并修复保存成功后复制 Vue 响应式对象的错误，避免成功操作被显示成失败。

| 最终检查 | 结果 | 本地证据 |
|---|---|---|
| 主控完整 PostgreSQL 竞态回归 | 391 项主测试、449 项子场景通过，607.703 秒；8 项专用环境用例明确跳过，无失败 | `.cache/verification/v3/settings-editor-final-pg.jsonl` |
| Linux amd64 隔离后台 | 191 项主测试、339 项子场景通过，0 跳过 | `settings-editor-final-linux.log`、`console-linux.3JXGrv/integration.log` |
| 前端检查、测试和构建 | 全部通过，22 个测试文件、174 项测试；产物已嵌入 Go | `settings-editor-final-typecheck.log`、`settings-editor-final-web.log`、`settings-editor-final-build.log` |
| Go 全包与静态检查 | 全部通过 | `settings-editor-final-go-all.log`、`settings-editor-final-vet.log` |
| 本地浏览器 | 合成资料验证预览确认及 390px 窄屏，无横向溢出、无控制台错误；不是生产或真实后台浏览器联调 | `settings-editor-preview.jpg`、`settings-editor-mobile.jpg` |
| 保护与清理 | 六个受保护文件摘要一致，节点工具实现／测试未变；临时 PostgreSQL 零 schema、零其他客户端后移除，Linux 容器及网络已清理 | `settings-editor-result.json`、`settings-editor-cleanup.json`、`settings-editor-linux-cleanup.json` |

最初完整竞态运行漏设整套测试时限，触发 Go 默认十分钟上限，保留为 `settings-editor-default-timeout-*` 诊断，不计作通过。确认无客户端后清理其唯一残留测试 schema。最终运行设置整套上限三十分钟，业务操作原有三十秒事务预算保持不变。最终实现补齐大小写精确字段检查后，重新完成全部 PostgreSQL 竞态、Linux 后台、Go 全包和静态检查。

八项跳过仍为两个本机低磁盘、VictoriaMetrics 联调、四个 Linux 上传／安装工具及发布信任低磁盘用例。Linux 后台覆盖两个本机低磁盘场景；其余项目未记为本轮通过。最终冻结清单为 `settings-editor-final-source.json`，后续仅修改后台说明和本验证文档，交付清单及日志摘要见 `settings-editor-result.json`。没有提交／推送 Git、访问生产、发送业务通知、发布部分 v3 或更新 latest。

配置恢复公开流程、启动应用协调、完整 native／Docker 安装与 PKI 生命周期、旧版增量切换及无损回退、单中心／HA 安装与真实万台／两万台容量及 72 小时稳定性门禁仍未完成。当前版本和生产维持 v2.0.46；不能用本轮设置功能或合成配置测试代替完整 v3 发布验收。

## 2026-10-19：公开保存态恢复接口与网页

本轮将既有 schema 21 恢复事务接入公开 API 和备份管理页：安全预览、持久恢复记录／详情、本机只读检查、加密候选准备、明确提交到保存配置及取消。不会应用运行配置、重启中心、部署子控或发送业务通知。完整 v3 仍未完成，不发布或更新 latest。

- 本地真实 PostgreSQL 全包 `go test -json -race ./internal/controlplane -count=1 -timeout 30m`：**395 个主测试、449 个子场景通过**，609.348 秒，8 项明确环境跳过，0 失败；stderr 为空。30 分钟只是包测试预算，业务请求和事务保持 30 秒。
- 隔离 Linux amd64 控制台验证：**195 个主测试、339 个子场景通过，无跳过**。目录 `.cache/verification/v3/console-linux.H3eYe1/`，包含四项新增真实恢复 API 测试。测试脚本清理自己的容器和内部网络；不访问业务通知、远端 SSH 或生产配置。
- 新增 API 验证覆盖全流程及进程实例重建后续作、严格字段／重复键／超限／代次字符串、HTTP／CSRF／角色保护、其他管理员只可取消、配置冲突、资料缺失、安全诊断、篡改展示摘要及本机密钥缺失仍可取消。保存后运行设置版本、节点已生效版本保持原值，不新增部署或通知。
- 前端 **23 文件／182 项通过**，类型检查、构建及 Go 嵌入完成。覆盖预览默认保留凭据、选项变化失效、确认及过期、未知结果同键重试、账号归属、断点查看、明确冲突、页面退出和两万差异仅渲染一百行。
- `go test ./...`、`go vet ./...` 通过。最终 Linux amd64 CLI 在最终前端构建嵌入后重新编译。Linux API测试二进制早于最终的确认框换行及一百行展示限制；这些仅为前端修改，Go 实现及测试源码保持一致。
- 真实浏览器只打开本地 GET-only 合成夹具：1280×720 桌面及 390×844 窄屏详情，确认文字可换行、底部操作可见，无整页横向溢出或控制台错误；HTTP 写按钮禁用。HTTPS 真实写入边界由上述 PostgreSQL API 测试覆盖，不将合成截图当作真实浏览器端到端写入证明。截图保存在 `.cache/verification/v3/restore-desktop.jpg`、`restore-mobile.jpg`。
- 六份先前未提交修复保护哈希均未变化；`internal/nodeops` 实现及测试相对上个完整检查点不变，沿用其既有竞态验证证据。不提交 Git、不创建分支、不连接生产。独立本地 PostgreSQL `webscan-v3-restore-api-lab-20261019` 删除前确认剩余测试 schema 和其他数据库连接均为零，测试页面／服务也已关闭。

完整结果和 SHA256 在 `.cache/verification/v3/restore-result.json`；原始数据为 `restore-final-pg-race.jsonl`、`restore-final-linux.log`、`restore-final-frontend.log`、`restore-final-build.log`、`restore-typecheck.log`、`restore-final-go-all.log`、`restore-final-vet.log`。本轮交付源文件快照为 `restore-final-delivery-source.json`，最终文档快照另存。尚需完成运行应用与重启协调、正式安装和 PKI、旧版最终增量切换与无损回退、单中心／HA 安装及实际容量稳定性验收。

## 2026-10-19：保存态应用前真实环境诊断

新增本地管理员命令 `check-configuration-apply`，只接受已提交保存态恢复 ID。它在配套资料有效后检查原 PostgreSQL 业务库身份、默认 schema／业务表、版本、只读状态、逐项表及序列权限、RLS，以及 VictoriaMetrics 当前 `vector(1)` 查询和空导入接口。不改运行配置、不写指标、不创建部署任务或发送通知。诊断始终要求后续实际运行回执，不能当作应用授权；网页原 `/check` 仍保持完全不连接外部依赖的本机检查。

新增测试覆盖另一个数据库／schema、改变建表默认 schema 的搜索路径、只读账号、单项权限缺失、RLS、版本变化、取消／超时、TLS 拒绝、重定向、损坏／超限／过期查询、空导入失败和集群路径；检查过程中账号、配置、回退引用、私钥或 DSN 内容变化均不能沿用通过结果。网络阶段不占用配置关系门禁。还验证私有输入大小、重复键、大小写别名、符号链接及权限，报告不泄露目标和凭据，实际 CLI 失败返回非零退出码。

| 最终检查 | 结果 | 证据 |
|---|---|---|
| PostgreSQL 全包竞态回归 | **406 项主测试、475 个子场景通过**，611.035 秒，7 项环境跳过，无失败，stderr 为空 | `environment-final-pg-race.jsonl`、`environment-final-pg-race.stderr` |
| Linux amd64 隔离后台及实际 CLI | **204 项主测试、365 个子场景通过**；时序专用用例在本组明确跳过 | `environment-final-linux.log`、`console-linux.dekQvY/integration.log` |
| 真实 VictoriaMetrics | 固定摘要的本地独立容器，当前查询及空导入通过；未将空导入当作持久化证明 | `environment-final-pg-race.jsonl` 中 `TestConfigurationEnvironmentVictoriaMetrics` |
| Go 全包及静态检查 | `go test ./...`、`go vet ./...` 均通过 | `environment-final-go-all.log`、`environment-final-vet.log` |
| 前端及既有修复 | 本轮无前端改动，90 份前端源／嵌入文件、22 份嵌入摘要及六份保护哈希均未变化；沿用上一检查点 182 项前端测试与构建证据 | `environment-result.json`、`restore-result.json` |
| 资源清理 | 独立 PostgreSQL 零测试 schema、零遗留测试角色、零其他客户端后，与独立时序容器一并移除；Linux 容器和内部网络由脚本清理 | `environment-cleanup.json` |

七项 PostgreSQL 环境跳过为两个专用低磁盘、四个 Linux 工具上传／安装、发布信任低磁盘测试；Linux 后台覆盖其中的本机资料及导出低磁盘场景。Linux 这一组没有时序容器，因此其唯一跳过由另一组真实时序容器验证补充。没有将未运行的专用场景计为本轮通过。

初次调试的编译／测试失败记录保留在本地，不计为验收通过。最终 747 份源码清单为 `environment-final-source.json`，验证后只追加本段文档，交付清单和汇总见 `environment-result.json`。本轮没有修改 schema，仍为 21；节点工具 65 份文件相对上一检查点不变。

实际运行应用协调、中心启动参数落地与重启、完整安装及 PKI、旧版最终增量切换／无损回退、单中心／HA 安装、万台／两万台实际采集及 72 小时稳定性仍未完成。这一诊断只补齐其中的前置门禁。完整 v3 未完成，不发布、不更新 latest、不访问生产或提交 Git。

## 2026-10-19：持久化应用日志与阶段协调基础（schema 22）

新增内部应用任务、签名计划及检查点、全局冲突门禁、45 秒租约和递增代次、固定代码日志、幂等用户控制及灾备冻结。任务绑定已提交的保存态恢复、原账号修订号、中心成员、保存代次和原提交证明；数据库迁移仍先完成一致性备份。原管理员有效才可继续前向应用，当前其他管理员可明确请求回退；取消不能丢弃已开始切换的恢复责任。网络检查不占用配置门禁。

本轮真实运行适配器只执行环境诊断，未安装到 `Serve`、未开放公开排队／执行接口。完整前向和回退测试使用合成适配器，只证明状态机和权限，不能证明节点已下发、中心已重启、设置已应用或完整运行验收。切换前要求所有剩余前向阶段和回退阶段均受支持，回退开始前同样要求全部剩余回退阶段受支持。

| 验证 | 结果 | 证据 |
|---|---|---|
| PostgreSQL 全包竞态基线 | **416 项主测试、488 个子场景通过**，618.216 秒，9 项明确环境跳过，无失败，stderr 为空 | `application-verified-pg-race.jsonl`、`application-verified-source.json` |
| 最终应用协调器竞态 | 在上述基线之后补齐“部分回退适配器不能先恢复子集”门禁；最终全部 **13 项主测试、13 个子场景通过**，24.189 秒，无跳过 | `application-final-targeted-race.jsonl`、`application-delivery-source.json` |
| 当前源码 Linux amd64 后台 | **217 项主测试、378 个子场景通过**，真实 CLI 编译／调用；时序专用用例明确跳过 | `application-delivery-linux.log`、`console-linux.Ig2mZJ/integration.log` |
| 当前源码 Go 全包及静态检查 | `go test ./...`、`go vet ./...` 通过 | `application-delivery-go-all.log`、`application-delivery-vet.log` |
| 前端及原有修复 | 无前端改动，沿用上一完整前端检查点；22 份嵌入产物、90 份前端源／嵌入文件和六份受保护修复摘要未变，节点工具 65 份文件未变 | `application-result.json`、`restore-result.json` |
| 清理 | 独立 PostgreSQL 零测试 schema、零遗留角色、零其他客户端后移除；所有本轮 Linux 容器和内部网络均已移除 | `application-cleanup.json` |

全包竞态基线与最终实现只相差应用运行器的上述回退支持门禁及对应测试；最终应用测试已全部重跑，最终 Linux 和 Go 全包构建使用当前源码。没有把较早基线冒充为最终运行器的单次全包测试。两次竞态覆盖合并后为 417 个不同主测试和 488 个子场景，重复用例不重复计数。

新增场景还覆盖同键重试、并发领取、过期接管、旧拥有者续租／提交／失败均被拒、真实依赖失败不进入回退、取消网络请求、网络期间直接配置变化、工作器接管、丢失响应后按已完成阶段继续而不重做、原账号失效后的新管理员回退、签名／来源／回退引用篡改、密钥轮换，以及完整 PostgreSQL 灾备后禁止自动执行和必须显式重新授权。

初次回归有一项旧测试仍按锁 SQL 完整文本观察等待；加入应用表后该条件过期。改为查询本测试 schema 内 `v3_nodes` 实际未授予的锁，保留等待和提交后新状态断言，定向竞态通过；该用例在后续完整基线和最终 Linux 中也通过。已知失败的旧进程组停止后，确认零客户端，清理其唯一遗留 schema 及对应合成临时资料。失败／停止记录保留，不计为验收通过。

九项 PostgreSQL 跳过是在先前七项专用环境用例之外，本组没有 VictoriaMetrics 容器而明确跳过两个时序联调用例；本轮时序客户端实现未修改，真实时序接口沿用 `environment-result.json` 的独立容器验证。Linux 同样没有时序容器，其唯一跳过没有算作通过。前端没有重跑或重新截图。

最终源码及文档清单、各日志摘要和验证范围存于 `.cache/verification/v3/application-result.json`。仍需完成真实节点部署协调、中心启动配置及重启交接、设置原子提交和运行回执、回退资料认证及保护引用释放，再接入公开工作流；正式安装／PKI、旧版增量切换／无损回退、单中心／HA 和容量稳定性门禁也仍未完成。本轮未提交 Git、发布、更新 latest 或操作生产。

## 2026-10-19：实际运行设置应用、回退及事务回执（schema 23）

内部设置适配器会真正更新工作器读取的策略，而非仅推进任务状态。实际设置、草稿应用标记、加密前后回执和安全审计同事务提交；回退恢复原运行策略，版本继续递增，并保留目标保存草稿供复核。执行受当前租约、成员、账号、完整原提交与回退存档约束，迁移冻结或提交前租约过期会撤销整个事务。

| 检查 | 结果 | 证据 |
|---|---|---|
| PostgreSQL 全包竞态基线 | **432 项主测试、518 个子场景通过**，677.569 秒，9 项专用环境跳过，无失败，stderr 为空 | `settings-application-final-pg-race.jsonl`、`settings-application-runtime-source.json` |
| 最终应用协调专项竞态 | 基线后补入从已认证数据库任务重新核对成员；最终全部 **28 项主测试、44 个子场景通过**，84.907 秒，无跳过 | `settings-application-final-targeted-race.jsonl`、`settings-application-final-runtime-source.json` |
| 最终源码 Linux amd64 后台及实际 CLI | **232 项主测试、409 个子场景通过**；时序专用用例明确跳过 | `settings-application-final-linux.log`、`console-linux.Du6x0I/integration.log` |
| 最终源码 Go 全包与静态检查 | `go test ./...`、`go vet ./...` 通过 | `settings-application-final-go-all.log`、`settings-application-final-vet.log` |
| 既有修复及前端 | 六份保护哈希、65 份节点工具文件、90 份前端源／嵌入文件及 22 份嵌入摘要不变；沿用 182 项前端检查、构建和浏览器证据 | `settings-application-result.json`、`restore-result.json` |
| 清理 | 独立 PostgreSQL 零测试 schema、零遗留角色、零其他客户端后移除；两次 Linux 验证的容器及内部网络均已清理 | `settings-application-cleanup.json` |

全包竞态基线之后只改变设置适配器的上述成员复核及对应子场景，最终应用专项、Linux、Go 全包及静态检查均使用最终源码。合并去重后为 **432 个主测试、519 个子场景**；这不是最终源码的单次全包竞态运行。没有重复计算已执行用例，也没有把合成前置节点／启动检查点当作真实部署验收。

新增测试覆盖实际策略读取、只读检查不应用、无变化回执、响应丢失、接管不重复写、并发重试、原账号失效后的新管理员回退、回退前未发生设置副作用、八类前向／回退事务故障注入、证明和回执损坏、缺失引用、配置漂移、迁移冻结、执行中租约到期、灾备冻结与显式重新授权、密钥轮换、成员提示不能替代真实任务身份，以及设置适配器不能绕过完整应用门禁。schema 22 升级验证备份失败停止、成功迁移及含加密回执的灾备往返。

九项 PostgreSQL 跳过与上一应用检查点相同，本轮没有 VictoriaMetrics 容器；时序客户端未改动，沿用既有独立容器证据。Linux 补充本机资料和导出低磁盘用例，唯一时序跳过不计为通过。前端没有重跑或重新截图，节点工具未改动。

首次启动完整竞态时漏设三十分钟包测试预算，发现仍为十分钟默认值后，精确中止自己的进程组，确认零数据库客户端并清理唯一遗留测试 schema 和对应合成临时目录，然后以 `-timeout 30m` 重跑完成。被中止运行未计为通过；原日志与清理范围保存在 `settings-application-stopped-run-cleanup.json`。包测试时限不改变十秒设置事务及现有业务请求预算。

加密回执证明运行设置已事务提交，不能证明中心已重启、节点已安装或外部通知送达。实际节点协调、中心启动参数及重启交接、完整运行验收、保护引用释放和公开应用入口仍未完成；正式安装／PKI、旧版最终增量与无损回退、单中心／HA 及真实容量稳定性门禁也仍需继续。本轮未提交或推送 Git、访问生产、发送业务通知、发布部分 v3 或更新 latest。


## 2026-10-19：中心启动交接及进程证明（schema 24）

本轮增加内部 `bootstrap`／`restore-bootstrap` 适配器，实际启动解析、初始化记录及排空后签署结束状态已接入 `Serve`；完整应用运行器与正式安装器仍未接入。详细行为见 [设置生命周期](V3-SETTINGS-LIFECYCLE.md#中心启动交接schema-24)。版本、镜像标签和生产服务保持原状。

| 验证范围 | 结果 | 边界 |
|---|---|---|
| PostgreSQL 广覆盖竞态基线 | 448 项主测试、546 个子用例通过；9 项环境跳过 | 810.525 秒；早于最终批准时间认证、结束标记复核和旧进程等待超时修正 |
| 最终启动交接竞态测试 | 17 项主测试、29 个子用例通过，无跳过 | 142.867 秒，覆盖最终三个差异文件；不是全部包在最终源码上的单次竞态运行 |
| 最终 Linux amd64 | 249 项主测试、438 个子用例通过；1 项 VM 环境跳过 | 只读容器、私有 tmpfs、隔离 PG 网络；实际编译并运行当前 CLI |
| 最终 Go 全量测试及静态检查 | `go test ./...`、`go vet ./...` 通过 | PostgreSQL 专项以独立竞态测试补充 |
| 原修改与前端 | 六份保护文件、65 份 nodeops 文件、90 份前端及嵌入文件哈希未变 | 复用最近前端验证，不声称重新截图或构建前端 |

广覆盖基线与最终专项合并，覆盖 449 项独立主测试、548 个子用例。九项 PG 环境跳过分别为实际 VictoriaMetrics 诊断／读写、两项受限磁盘及五项显式启用的 Linux 工具上传／安装／信任发布；其中本轮 Linux 覆盖自己的受限磁盘场景，VM 保持明确未跑。不能把这些跳过或文档编解码的两万节点测试算作容量验收。

实际 HTTPS 服务测试检查 HTTP/2、监听绑定、重启后原会话及 CSRF；`all` 测试使用空节点／空网站、关闭通知、禁用执行器，等待其余全部角色真实初始化。另用隔离 PG 登录角色和数据库触发器验证新进程实际使用批准的目标凭据。前序环境／节点应用检查点明确为合成，重启由测试管理器执行，不能代替正式安装器或真实子控完整部署验收。

故障测试覆盖确认前／后回退、新管理员恢复权限、租约接管、事务失败及到期回滚、失效来源／保护存档、交接密文／批准时间／进程签名／结束状态损坏、启动基准漂移、等待超时、丢失已确认交接、占用监听地址、无变更不重启及灾备清除心跳与显式恢复。第一次目标凭据测试因默认恢复保留当前引用而失败，已改成明确选择备份凭据并检查保存引用；纠正后的单项和完整最终专项通过，原始失败记录仍保留。

验证证据位于 `.cache/verification/v3/bootstrap-runtime-result.json`，最终源码清单为 `bootstrap-runtime-final-delivery-source.json`，清理记录为 `bootstrap-runtime-cleanup.json`。两个独立回环 PG 及四组 Linux 网络／容器均只清理本轮创建的对象；删除前核对测试 schema、其他客户端和测试角色全部为零。没有连接业务飞书、真实邮箱、生产 PG 或服务器 229，也没有提交或推送 Git。

完整 v3 仍需父应用与子部署任务协调、组合运行器及最终生效验收、公开应用入口、正式 native／Docker 安装和 PKI 生命周期、旧版最终增量切换及无损回退、单中心／可选 HA 安装与容量稳定性验证。保持 v2.0.46，不发布部分 v3，不更新 latest。

## 2026-10-19：父子部署协调与内部节点适配器（schema 25）

增加配置应用的持久操作门禁、签名父子绑定和统一发布目标；启用节点的内部阶段适配器会按顺序调用现有部署执行器，失败后停止后续节点，继续时重用原任务，回退按逆序使用原计划及备份。未完成子任务不能推进父节点阶段，子成功后仍保留父应用的回退备份引用，最终父结果与解除引用原子提交。修正独立部署终态恢复标记及回退后的已生效版本。迁移前一致性备份和灾备后的显式授权继续生效。

本轮证据均保存在 `.cache/verification/v3/`：

- `coordination-result.json`、`coordination-race-partitions.json`：逐项发现 481 个本机测试入口。首轮 `coordination-full-race.jsonl` 触发 Go 默认十分钟**整包**时限，正在运行的子用例不到一秒，没有断言失败；保留已完成的 216 个主测试。`coordination-remaining-race.jsonl` 用三十分钟时限跑完其他全部入口，实际耗时 255.050 秒；合并去重后为 **472 个主测试、565 个子用例通过，9 个主测试明确跳过**。不能把超时首轮描述为完整单次通过。
- 新增节点阶段适配器在首轮竞态编译后加入，原有产品 Go 源码未再变化，见 `coordination-core-source-proof.json`。最终源码的适配器已纳入上述续测；`coordination-runtime-final-race.jsonl` 另外验证本轮全部新增的 **24 个主测试、22 个子用例**，51.274 秒，无失败或跳过。
- 九项跳过需要单独启用的容器传输测试、实际 VictoriaMetrics 服务或低磁盘环境；具体名称写入结果文件。这些跳过不等于功能已验证，也没有使用生产补测。
- `coordination-linux-console.log`、`console-linux.Z703XG/integration.log`：Linux amd64 控制台完整既定回归，**270 个主测试、460 个子用例通过**，仅实际 VictoriaMetrics 环境检查明确跳过；构建并执行本轮 CLI。此轮编译早于追加的内部节点适配器，不能宣称单次涵盖后来新增代码。
- `coordination-final-linux-retry.log`、`coordination-linux.NYu1HM/integration.log`：最终代码在内网隔离 Linux amd64 容器中定向验证，**24 个主测试、22 个子用例通过**，无跳过。完整控制台与最终定向结果的入口并集为 273 个主测试通过；重叠项不重复计数。
- `coordination-final-go-all.log`、`coordination-final-vet.log`：最终代码 `go test ./...`、`go vet ./...` 通过。未提供 PostgreSQL 测试地址的普通全包测试会明确跳过数据库用例，数据库证据以竞态及 Linux 隔离记录为准。
- 首次适配器定向测试 `coordination-node-runtime-race.jsonl` 揭示两台模拟节点共用阶段回执，已将夹具按任务 ID 隔离，未放宽实际任务、代次或验收条件，最终竞态及 Linux 重测通过。首次最终 Linux 脚本 `coordination-linux.jk66YY/integration.log` 缺少只读示例 YAML 和源码工作目录挂载，夹具初始化失败；补齐与既有控制台验证脚本相同的只读挂载后通过。失败记录保留，不计作通过。

覆盖真实 PostgreSQL 的并发、重复读旧快照、源配置及签名篡改、原子备份与任务绑定、当前管理员权限及灾备冻结、父接管隔离旧子执行器、成功子任务再次回退、失败回退保留备份、未变更服务的明确审计、保留新增事件及中断检查点。节点阶段检查不触发准备或远端动作，重复完成不会再次执行；缺失实际 SQL 采集确认时拒绝完成。

这里的远端服务安装动作与采集观察仍为明确的合成夹具，部分环境／设置／启动父检查点也为合成；没有连接真实 SSH 节点、执行生产部署或发送业务通知。禁用节点变更尚需独立前后回执，当前适配器拒绝伪报完成；自动准备提供器、组合验收器及公开完整应用运行器仍未装配。

本轮自建 PostgreSQL 的测试 schema、其他客户端及额外角色均为零，测试容器和专属网络已清理；相关证明见 `coordination-final-database-cleanup-proof.log` 和 `coordination-cleanup.json`。首轮总超时留下的唯一测试 schema 在确认无其他客户端后清理，单独记录为 `coordination-timeout-resource-proof.log` 和 `coordination-timeout-schema-cleanup.log`。没有删除其他应用的容器、网络或镜像。

本轮未更改先前六份修复的保护哈希、65 份 nodeops 文件及 90 份前端／嵌入文件，最终交付源码清单见 `coordination-final-delivery-source.json`。完整安装、PKI 运维、旧版最终增量切换／无损回退、单中心／可选 HA 安装和真实容量稳定性验收仍未完成。正式版本维持 v2.0.46；没有发布部分 v3、更新 latest、提交 Git 或访问生产。

## 2026-10-19：停用节点登记与回退（schema 26）

内部节点适配器新增停用登记及回退：登记快照、代次、缓存失效、待发送健康通知取消、加密前后回执和审计原子提交。保留远端下发／生效版本，不创建 SSH 部署任务。回退保留目标草稿、新增事件、历史及已取消通知的完成状态，使用新代次重新采集。

本轮证据位于 `.cache/verification/v3/registration-result.json`。`registration-race.jsonl` 验证关联配置／部署／恢复模块的竞态，`registration-final-targeted-race.jsonl` 验证最终新增专项；Linux 完整后台回归在 `console-linux.AcpxOe/integration.log`，最终专项在 `registration-linux.xsYNzJ/integration.log`。较大范围回归开始后只增加一个混合场景测试及其夹具，产品 Go 代码未变，证明见 `registration-core-source-proof.json`。最终专项覆盖这项增量，不将两次运行声称为一次最终源码全包测试。

新增专项覆盖已安装／未安装节点、只读检查、响应丢失与重复提交、事务故障、并发、租约接管、写入中到期、账号撤销、源配置或快照漂移、回执损坏和错向复用、密钥轮换、迁移冻结、灾备显式恢复、混合远端失败及逆序恢复。直接验证旧采集请求失效，回退后新登记可采集，取消通知不复活，新增事件不丢失。schema 25 升级验证备份缺失／失败停止及成功迁移；含加密回执的 PostgreSQL 备份恢复另有实际往返。

测试使用隔离 PostgreSQL；环境／启动／设置的前序检查点及混合场景远端动作仍为合成，不构成完整安装验收。Go 全包、静态检查与差异检查结果见上述结果文件；前端与节点工具未改动，不重跑界面验收。原六份保护文件、65 份节点工具及 90 份前端／嵌入文件哈希不变。清理仅移除本轮创建的容器、网络及测试 schema。

完整 v3 仍缺自动准备提供器、组合验收和公开完整应用、正式安装／PKI 生命周期、旧版最终增量切换及无损回退、单中心／HA 安装及真实容量稳定性验收。本轮没有提交 Git、发布镜像或修改 latest，没有连接生产 PG、服务器 229或业务通知渠道。


结果统计：关联竞态主测试 193 项、子用例 319 项通过，仅低磁盘专用场景明确跳过；最终增量专项 10 项主测试、20 个子用例通过，合并去重为 194 项主测试、319 个子用例。Linux 完整后台为 282 项主测试、480 个子用例，时序环境场景明确跳过；最终 Linux 专项为 34 项主测试、42 个子用例，合并为 283 项独立主测试。Linux 的受限 tmpfs 补充实际低磁盘场景，VictoriaMetrics 未补跑。上述配置批量用例不是万台实时采集压测。

最终 `go test ./...`、`go vet ./...` 和 `git diff --check` 通过。清理前临时 PostgreSQL 的测试 schema、其他客户端和额外角色全部为零，两个 Linux 验证网络／容器及回环测试库均已移除，见 `registration-database-cleanup-proof.log` 与 `registration-cleanup.json`。最终源码清单见 `registration-final-delivery-source.json`。

## 2026-10-19：内部联合验收及恢复记录的应用状态

schema 保持 26。本轮增加内部组合运行器和原子联合验收，串联环境、节点、中心启动交接及运行设置。最终验收先检查实际 PG 和 VictoriaMetrics，再在同一事务核对任务权限、来源、设置、进程与节点观测，并提交检查点及解除精确回退引用。缺失任一证据、日志／审计失败或最后写入时租约过期，状态与引用一起回滚。

另给恢复列表和详情增加只读的关联应用状态，原始保存回执保持不变。列表按页批量查任务，与恢复记录及候选版本共用数据库快照；计划或状态签名异常、密钥缺失时返回服务错误。页面显示历史应用／回退结果、阶段和更新时间，区分首次读取失败与保留上次结果的刷新失败。不提供尚未完成的公开应用提交或控制按钮。

证据保存在 `.cache/verification/v3/`：

| 范围 | 结果 | 边界 |
|---|---|---|
| `verification-full-race.jsonl` | 494 项主测试、606 个子用例通过，7 项明确跳过；另一个 Fuzz 入口及五个固定种子通过 | 全 controlplane 竞态，1002.680 秒；编译早于后来追加的只读状态展示 |
| `verification-final-targeted.jsonl` | 10 项主测试、21 个子用例通过，无跳过 | 内部组合、真实中心重启／回退及实际 VM 依赖，83.535 秒 |
| `projection-final-race.jsonl` | 18 项主测试、23 个子用例通过，无跳过 | 最终产品 Go 源码的联合验收、恢复 API 与新增状态读取，96.770 秒 |
| `projection-final-freeze-race.jsonl` | 1 项主测试通过，无跳过 | 后来只追加一个灾备冻结断言，3.156 秒；产品源码未再改动 |
| `console-linux.EUc6nE/integration.log` | 294 项主测试、501 个子用例通过，无跳过 | Linux amd64、只读容器、受限 tmpfs、内部 PG／VM 网络；早于只读状态展示 |
| `projection-linux.LTwGAs/integration.log` | 18 项主测试、23 个子用例通过，无跳过 | 最终产品 Go 代码的关联增量在 Linux 验证，后续冻结断言以上述专项补充 |
| 前端 | TypeScript 检查、23 个测试文件内 191 项测试及 Vite 构建通过 | 包括所有应用状态、刷新失败保留旧结果、首次失败、旧接口兼容及只读操作边界；没有声称完成浏览器截图验收 |

竞态基线与最终专项合并去重为 498 项主测试、608 个子用例通过，Fuzz 固定种子另列；Linux 并集为 298 项主测试、503 个子用例。不是两次“最终源码全包单次通过”。源码差异与各分区明细见 `projection-source-delta.json`、`verification-race-partitions.json` 和 `verification-linux-partitions.json`。

七项跳过分别是三项专用低磁盘场景和四项显式启用的 Linux 工具传输／安装场景，名称完整保存在结果文件。Linux 回归补跑了 `TestConfigurationRestoreLocalLowDisk`；其余跳过不能算作本轮已验证。本轮为控制台脚本加入真实隔离 VictoriaMetrics，因此环境检查及空导入测试不再因缺少 VM 跳过。空导入不写测试时序，也不触发业务通知。

组合测试实际使用空节点配置、真实 PostgreSQL、真实 `Serve(all)` 进程及受控服务重启；部分测试使用合成 VM HTTP 端点，实际 VM 用例另有证明。涉及节点状态及远端动作的专项明确使用合成观测，证明无变化节点和回退后重新启用节点不能绕过健康验收，不能代替 native／Docker 完整安装验收。第一次夹具把不存在的 retention map 当作已有对象修改，导致目标设置未变化；已修正夹具赋值，未放宽产品条件。早期失败与局部运行日志保留，不计作完整通过。

最终重新构建的 Linux amd64 CLI 包含最终前端 HTML，见 `projection-final-linux-embed-proof.json`。Go 全包测试、静态检查、差异检查及最终源码／保留证明见 `verification-result.json`。六份原修复和 65 份 nodeops 文件不变；前端改动限于恢复状态类型、恢复面板及其测试，并重新生成 v3 嵌入资源，v2 入口保持不变。

清理前临时 PostgreSQL 的测试 schema、其他客户端及额外角色均为零。两份隔离 Linux 脚本已清理自己的容器与网络，随后核对并精确移除本轮自建的回环 PG／VM；未修改其他容器或网络，见 `verification-cleanup.json`。

自动可信准备、公开应用提交与调度、正式安装及 PKI 生命周期、旧版最终增量和无损回退、默认单中心／可选 HA 安装、联合验收批量优化及真实容量稳定性仍待完成。20,000 节点配置编码／批量保存不是万台实时采集压测。没有访问生产、服务器 229 或真实通知渠道，没有提交／推送 Git、发布镜像或更新 latest；正式版本仍为 v2.0.46。


## 2026-10-19：持久部署资料与自动准备（schema 27）

新增本地管理员资料绑定、加密规则快照及具体自动准备器。绑定、幂等回执和审计同事务；环境阶段先校验需要部署的节点资料，缺失／损坏不会武装恢复或创建子任务。准备时实际父任务的租约、来源和配置，以及绑定、凭据语义、已登记证书和吊销状态都在文件 I/O 前后复核。原子任务的继续／回退不重新选择绑定资料。

已通过的最终新增专项：

- `preparation-final-targeted-race.jsonl`：11 项主测试、40 个子用例，53.782 秒，无跳过；真实隔离 PostgreSQL，启用 Go 竞态检查。
- `console-linux.qFIllj/integration.log`：同样 11 项主测试、40 个子用例通过；静态 Linux amd64 CLI、只读容器、内部 PG／VM 网络。没有 SSH 到业务节点或发送业务通知。
- `preparation-go-all.log`、`preparation-go-vet.log`：最终 Go 全包测试及静态检查通过。全包测试没有注入 PG DSN，SQL 场景的证明来自上述专项及独立完整竞态回归，不能把跳过的 SQL 用例算作全包已执行。
- Linux CLI 的完整当前 v3 HTML 嵌入核对通过，见 `preparation-linux-embed-proof.json`。前端 90 个源／嵌入文件及 65 个 nodeops 文件与上一轮保持一致，复用此前前端测试／构建证明，不重新声称执行浏览器验收。

专项覆盖 native／Docker 安装与升级配置包、删除原规则文件后的准备、同包重试、私有权限、无通知／子任务副作用、凭据变化／重新加密、证书损坏／吊销、材料篡改、账号和来源变更、租约到期／接管、取消、配置迁移冻结、并发代次、事务失败，以及 schema 26 备份要求与实际 PG 灾备往返。

初期编译发现未使用 import，修正后保留原失败日志。早期绑定测试错误地将其他种类历史审计中的非机密记录 ID 计入泄漏断言，且使用了错误的迁移冻结表；已精确修正夹具。后续停用节点夹具试图取消仍持有效租约的任务，被产品正确拒绝，现改为直接建立真实的停用配置来源。较大范围回归在修正夹具前编译，原失败日志保留；最终新增专项编译的是修正后的测试，未放宽产品保护。

测试使用实际 SQL、Vault、签发登记及私有包文件；远端动作和部分父阶段／采集观察明确为合成夹具。单轮资料检查十秒预算、环境阶段节点清单批量读取及单次来源认证并不等于万台采集容量验收。公开应用提交／调度、正式安装与 PKI 运维、旧版最终增量与无损回退、单中心／HA 安装和真实容量稳定性仍未完成，不能发布部分 v3。


最终较大范围结果：

| 范围 | 结果 | 说明 |
|---|---|---|
| `preparation-full-race.jsonl` | 505 项主测试、647 个子用例及 6 个 Fuzz 入口／固定种子记录通过；10 项明确跳过；1 项主测试及其停用子用例失败 | 1039.689 秒；编译时仍含后来修正的停用夹具，整个基线包返回失败，不能表述为全包单次通过 |
| `preparation-final-targeted-race.jsonl` | 11 项主测试、40 个子用例通过，无跳过 | 覆盖修正后的停用夹具和全部新增准备能力；产品 Go 源码没有继续修改 |
| `console-linux.iusQzu/integration.log` | 308 项主测试、542 个子用例通过，无跳过；同一个旧停用夹具失败 | 实际隔离 PG／VM、Linux amd64；原始失败证据保留 |
| `console-linux.qFIllj/integration.log` | 11 项主测试、40 个子用例通过，无跳过 | 最终测试源码的全部新增专项 |

按测试标识将最终专项替换旧夹具结果后，竞态覆盖并集为 506 项主测试、648 个子用例通过，另有一个 Fuzz 入口及五个固定种子；Linux 并集为 309 项主测试、543 个子用例。没有未被最终验证修正的失败。这是分区证据合并，不能解释为一次最终源码全包绿色运行，详细逐项结果见 `preparation-race-test-results.json`、`preparation-linux-test-results.json` 与 `preparation-result.json`。

竞态跳过项为三项需要实际 VM 的场景、三项专用低磁盘场景、四项显式启用的 Linux 工具传输／安装场景。Linux 回归覆盖其中应用依赖及环境的两个 VM 用例和配置恢复的低磁盘用例；`TestVictoriaMetricsImportAndQuery` 及其余专用跳过项不因此算作本轮执行通过。此前相同未修改模块的证明保留，不冒充本轮实跑。

最终源码及保留证明见 `preparation-final-delivery-source.json`、`preparation-core-source-proof.json` 与 `preparation-preserved-proof.json`。清理前自建 PostgreSQL 的测试 schema、其他客户端和额外角色均为零；精确核对容器 ID 后移除，两个 Linux 脚本自己的网络／容器也已清理，见 `preparation-database-cleanup-proof.json` 与 `preparation-cleanup.json`。没有修改生产 PG、服务器 229、其他容器或真实通知渠道，也没有 Git 提交／推送、发布镜像或更新 latest。已发布版本仍为 v2.0.46。


## 2026-10-19：本地配置应用工作器、命令与只读日志

本轮完成 schema 27 上的显式应用工作器，不增加数据库迁移。默认关闭，只有 `executor.enabled` 和 `executor.applications_enabled` 同时开启时由 `Serve(all|executor)` 装配真实组合；公开 HTTP 写入口仍明确返回 503。补入本地私有排队／控制命令、管理员分页查询与连续日志，以及“部署任务”和恢复记录到应用日志页的入口。修复排队回执漏填实际 `created_at` 的问题。

验证证据位于 `.cache/verification/v3/`：

| 范围 | 结果与限制 |
|---|---|
| `workflow-final-targeted-race.jsonl` | 42 项主测试、84 个子用例通过，无失败／跳过，229.478 秒。覆盖应用工作器、查询、命令、启动交接、配置文档与准备门禁；编译时尚未包含最后的规范游标补充及新增工作器权限场景 |
| `workflow-cursor-final-race.jsonl` | 最终规范游标专项通过，替换上表同名用例的旧源码证明；拒绝前导零、正号、小数和越界游标 |
| `workflow-authority-final-race.jsonl` | 最终新增工作器授权测试：1 项主测试、5 个子用例通过，无失败／跳过 |
| `console-linux.w8d2op/integration.log` | 隔离 Linux amd64、实际 PostgreSQL／VictoriaMetrics，较大范围专项通过；测试内工作器指标 HTTP 仍用模拟服务，不等于远端节点安装验收 |
| `console-linux.hLTIWY/integration.log` | 最终 API／命令／游标测试通过，静态 CLI 包含新网页构建 |
| `console-linux.Uo3ZW4/integration.log` | 最终规范游标和新增工作器授权专项通过，静态 CLI 包含当前完整网页 |
| `workflow-final-go-all.log`、`workflow-final-go-vet.log` | Go 全包测试及静态检查通过。全包测试不注入 PG DSN；SQL 用例的实际执行证明来自以上竞态与 Linux 专项 |
| `workflow-frontend-full.log` | 24 个测试文件、200 项测试通过；另有前端类型检查及构建通过 |

上述最终专项按测试标识合并后，竞态与 Linux 分别为 **43 项主测试、89 个子用例通过，无未解决失败及跳过**，逐项结果见 `workflow-race-test-results.json` 和 `workflow-linux-test-results.json`。这是选择范围的证据，不是一次最终源码全包 SQL 竞态基线。其余未修改模块的前序证明仍保留。

本轮覆盖实际 `Serve` 自动应用、默认关闭时不领取、真实中心重启后等待原 45 秒租约自然到期接续、两个工作器竞争、活动 HTTP 检查取消排空、迁移冻结、账号撤权、损坏签名、其他成员及灾备冻结。没有手工 SQL 调短重启接续的租约。自动应用测试使用空节点；之前部分适配器测试的合成检查点仍不能代替正式远端安装。运行中退出不改写成功检查点；没有确认的重启不能释放回退引用。

查询与本地命令覆盖管理员／其他管理员／操作员／只读／未登录、CSRF、分页、固定恢复筛选、字符串大游标、缺失密钥、数据库故障、日志缺行及非法代码、确认和请求键、重复提交、私有文件权限、符号链接、重复 JSON 键、错误类型／字段、留存恢复职责、配置文件入口。首次新增 API 测试揭示回执创建时间缺失，现已修正。原始失败证据保留；最终测试没有放宽保护。

前端新增八项页面场景和一项传输契约测试，覆盖完成停止、失败重试、隐藏暂停、请求不重叠、旧任务迟到响应、日志断层、已提交分页和非管理员不查询。早期两个页面测试因模拟对象的一次性响应队列未重置而失败，已修正测试夹具并完成最终 200 项全量测试。浏览器实际检查为回环地址上的构建产物与明确合成接口数据：默认桌面及 390×844 窄屏的阶段、错误、长任务 ID 和日志均可读；没有连接生产后台，也不声称这是生产数据联调。检查后恢复浏览器尺寸、关闭测试页及本地预览服务。

`workflow-linux-embed-proof.json` 核对最终静态 Linux CLI 内含当前 v3 HTML 及全部构建资源。六个保护文件、65 个 nodeops 文件与上一轮完全一致，见 `workflow-preserved-proof.json`。前端原实现保留并增加新只读任务页及入口，已重新测试、构建，没有复用旧前端结论冒充本轮验收。

自建 PostgreSQL 精确 ID 为 `44f941583b1e2f48023e69db2edc924906cc3e5d25e1fdf432f07f11581720ee`。确认测试 schema、其他客户端、额外角色均为零后移除；三组 Linux 容器及内部网络均由脚本清理并复核，见 `workflow-database-cleanup-proof.json`、`workflow-cleanup.json`。没有改动生产 PG、229 或业务通知，没有 Git 提交／推送、发布镜像或更新 latest。正式版本仍为 v2.0.46。

v3 仍需完成公开应用写入及完整网页执行工作流、真实 native／Docker 安装和 PKI 运维、最终增量迁移和切换后无损回退、单中心／HA 安装及拓扑迁移，以及实际万台／两万台和 72 小时稳定性验收。本轮不发布部分 v3。

## 2026-10-19：管理员 HTTPS 配置应用与控制（schema 27）

本轮在现有显式工作器开关下接入网页排队和原任务继续／回退／取消，不增加 schema。默认仍关闭；要求管理员、CSRF、幂等键及可信 HTTPS。排队只接受已提交恢复 ID、字符串保存代次和明确确认；控制绑定精确任务日志上界和稳定中心成员。读取的操作提示与签名任务处于同一快照，执行时重新检查账号、租约、恢复保护及来源。旧本地命令防重格式保留。

恢复详情单独确认“应用已保存配置”，创建任务立即跳转日志。确认原任务操作时固定游标和请求键，暂停轮询；响应丢失手动重试沿用原请求，冲突后需重新确认。读取失败禁止依据旧提示新建操作，路由／账号变化或退出撤销本页请求，保留连续日志的字符串精度。HTTP 下说明原因并禁用控制。

验证证据位于 `.cache/verification/v3/public-application-*`：

- Host 选定 SQL 竞态范围分批覆盖 **160 项主测试＋301 个子场景**，完整清单见 `public-application-race-coverage.json`。首次扩大范围运行触及默认十分钟总超时，未出现断言失败或竞态警告；未完成的主测试以十五分钟预算补跑通过，两个未配置 VM 的用例使用本轮独立 VM 补跑通过。不能将首次超时记录写成完整通过，也不声称全包 SQL 竞态基线。
- Linux amd64 在独立 PostgreSQL／VictoriaMetrics 容器及内部网络中运行相同 **160＋301** 范围，全部通过，没有失败或跳过；最终源码的公开应用用例再次运行，**6＋11** 全通过。两次容器运行目录分别为 `console-linux.AyK2Xy`、`console-linux.VKg6r6`。
- 实际 API 排队经 PostgreSQL 交由 `Serve(all)` 的组合工作器处理，空节点应用与设置验收通过。另覆盖依赖故障、工作器不自动重放失败、管理员明确继续、同键并发、回执重试、陈旧／超过 JavaScript 安全整数的游标、成员冲突、原账号限制、活动租约、灾备冻结、恢复保护、撤销会话、跨站及非可信代理。恢复控制授权的前序检查点有明确合成边界，不能当作真实节点安装成功。
- 前端 **24 个测试文件／206 项测试**、TypeScript 检查、构建、`go test ./...`、`go vet ./...`、格式、差异及脚本语法检查通过。常规 Go 全包测试未配置 SQL；SQL 证据来自上述隔离选定范围。当前 **22 个 HTML／静态资源**逐个核对嵌入最终静态 Linux amd64 程序。
- 浏览器以回环地址及合成接口数据检查桌面和 **390×844** 布局、任务／日志换行及 HTTP 控制禁用，窄屏正文与滚动宽度均为 390。HTTPS 浏览器预览因自签名证书被拒绝，没有绕过警告或改变系统信任；HTTPS 交互由前端测试与接口运输边界测试覆盖，不声称真实浏览器 HTTPS 联调通过。截图为 `public-application-desktop.png`、`public-application-mobile.png`；临时页面服务已停止并恢复浏览器尺寸。
- 六份既有修复哈希、65 份 `internal/nodeops` 文件保持不变。首次总超时遗留的单个自有测试 schema 在所有测试退出后清除；删除本轮精确 ID 的 PG／VM 容器前确认零测试 schema、零其他客户端及额外角色。两轮 Linux 容器及网络均已移除，未执行全局清理。

正式版本保持 **v2.0.46**。独立节点安装／升级的公开管理流程、正式 native／Docker 安装和 PKI 运维、旧版最终增量切换及切换后无损回退、默认单中心／可选 HA 安装与拓扑迁移、实际万台／两万台及 72 小时稳定性仍未完成。不发布部分 v3，不更新 latest，不操作生产、服务器 229 或真实通知渠道，不提交或推送 Git。

## 2026-10-19：旧 JSONL 启动前对账与中断续作

本轮补齐 v2 JSONL 向当前 Agent SQLite 的内部数据交接，接到 native 和 Docker 激活前的双锁保护区。仅从已校验快照读取顶层 `events-*.jsonl`，不处理 Vector 私有缓冲。原数据库已知 ID 保持原记录；日志独有事件按原 ID 补入，已补入 ID 的不同日志正文冲突阻止启动。事务字节游标与事件同步提交，最终私有完成凭据绑定原任务、计划、配置和快照。中心 schema 保持 27，公开独立部署写入口仍关闭，活动旧 sidecar／包装单元仍明确拒绝。

本轮证据位于 `.cache/verification/v3/legacy-reconciliation-*`：

- `legacy-reconciliation.ceLn2a/integration.log` 是最终 Linux amd64 专项：**11 项主测试、24 个子场景通过，无失败／跳过**。验证原 ID、大整数精度、原 SQLite 确认／拒绝／扫描保护、重复正文、坏 JSON／身份／UTF-8／超限、100 条分批事务失败续作、完成回执丢失重建、冲突正文、坏快照／游标／链接／数据库缺失，以及部分成功后的无损回退。当前真实 Linux `Agent.New` 从对账数据库重开，确认响应未发出时重开后仍可读原 ID；实际 pull 队列确认后不再返回这些事件。
- Linux 专项没有启动服务管理器、通知工作器或网络。服务管理为替身，程序包的 unit／资源证据没有因此算作实际安装成功；真实 Agent 构造和队列调用不等于 mTLS 网络或旧三容器验收。容器禁用网络、根文件系统只读，只用私有临时目录；测试后容器已移除。
- `legacy-reconciliation-final-race.json` 记录最终源码的整个 `internal/nodeops` 竞态回归：**157 项主测试、437 个子场景通过，199.083 秒，无失败**；三项需要显式外部 Docker／Compose 的测试跳过，未计为成功，清单见 `legacy-reconciliation-final-race-results.json`。`legacy-reconciliation-final-go-all.log` 和 `legacy-reconciliation-final-vet.log` 分别记录通过的 Go 全包测试与静态检查。Go 全包未注入 PostgreSQL DSN，不将跳过的 SQL 测试写为本轮 SQL 验收。更早两次 host 回归和 Linux 中间结果按原范围保留，最终判断以带 `final` 的结果及上述最终 Linux 目录为准。
- 最早的 `legacy-reconciliation.vFiWIm/integration.log` 未通过：隔离脚本的 tmpfs 默认不可执行，导致测试用扫描脚本运行失败。脚本现明确允许自己临时目录内的执行；最终 Linux 专项完整重跑通过，未更改产品程序或放宽扫描检查来绕过失败。
- Linux amd64 静态 CLI 为 `legacy-reconciliation-webscan-linux-amd64`，版本标记 `v3.0.0-local-test`；`legacy-reconciliation-embed-proof.json` 核对前序已验证的全部 **22 个 HTML／静态资源**未改变且仍逐个嵌入该程序。本轮没有修改网页，不声称重跑了前端或浏览器验收。

`legacy-reconciliation-preserved-proof.json` 与最终源码清单记录相对前轮的修改，既有六份修复保持原哈希；nodeops 仅修改两个激活器并增加三个对账文件。没有改动生产配置、PG、服务器 229、真实通知渠道、镜像标签或 Git 提交。该数据交接是旧部署迁移的前置能力，完整 systemd／Docker 安装、旧 sidecar 接管、PKI 运维、最终迁移、HA 与容量验证仍需继续，**本轮不发布**。

## 旧 systemd 包装模板与公开 unit 读取

本轮仅补齐旧 Vector／node-exporter 包装服务的只读归属识别，不启用旧三容器自动接管。以独立夹具保存 v2 实际模板，逐字核对启动、停止、挂载、依赖及镜像别名；支持 HTTP／HTTPS、旧指标端口和源镜像。`0644` unit 由单独读取器验证，凭据和备份继续使用原私有读取器。已停止且禁用的已知残留保持原样；活动或启用的包装服务、未知模板、额外钩子及不确定状态均拒绝。

证据目录为 `.cache/verification/v3/legacy-wrappers-*`：

- `legacy-wrappers.6emcEy/integration.log`：最终 Linux amd64 专项 **6 项主测试、73 个子场景通过，无失败／跳过**，包括真实 root 所有权、0644、符号链接、硬链接、FIFO、权限及模板修改检查；服务管理响应使用替身。此前 `legacy-wrappers.ePBI9T` 的同范围通过记录保留，最终判断以上述目录为准。
- 同目录的 `systemd-parser.log`：**1 项主测试、4 个 HTTP／HTTPS 模板子场景通过，无失败／跳过**，实际调用 `systemd-analyze verify --root`，使用私有惰性依赖定义及 Docker 占位程序。它验证语法，不启动真实服务管理器或 Docker，不作为停服、启动、cgroup 或三容器回退验收。脚本均禁用网络、根文件系统只读、不挂载宿主 socket，容器用后移除。
- `legacy-wrappers-race.json`：整个 `internal/nodeops` 竞态回归通过，**162 项 Test 主测试、1 项 Fuzz 种子主测试、513 个子场景通过，204.298 秒，无失败**。跳过三项外部 Docker／Compose 依赖测试，以及桌面无法执行的 root 换所有者子场景；后者已在上述隔离 Linux root 专项实际通过。逐项清单见 `legacy-wrappers-race-results.json`。
- `legacy-wrappers-fuzz.log`：独立模糊测试运行约 21 秒、51,367 次输入，无失败。`legacy-wrappers-go-all.log` 与 `legacy-wrappers-vet.log` 分别记录通过的 Go 全包测试与静态检查；没有注入 PostgreSQL DSN，不能据此声称 SQL 集成已重跑。
- `legacy-wrappers-webscan-linux-amd64` 为最终静态测试 CLI，版本 `v3.0.0-local-test`。`legacy-wrappers-embed-proof.json` 核对前序已验证的全部 22 个 HTML／静态资源未改变且逐个嵌入；网页没有修改，本轮不声称重跑前端或浏览器验收。

`legacy-wrappers-preserved-proof.json` 和最终源码清单记录相对 789 文件前序基线的变化，六份既有修复原样保留。原包装模板启动前会删除并重建容器，完整接管仍须补齐持久化停写及不会丢失原对象和新事件的恢复流程。没有改变公开部署的 503 门禁，没有 Git 提交／推送、生产操作或发布，当前正式版本仍为 v2.0.46。

## 2026-10-19：旧包装服务的原容器保留与恢复基础

新增私有包装服务切换组件：先持久化原 unit、运行配置摘要、完整容器和镜像归属，再用只启动／停止原不可变 ID 的 unit 替换含 `docker rm -f` 的旧模板。支持禁用停服、响应丢失后继续、恢复原启用及运行状态，并拒绝完成后外部改动。尚未接入生命周期驱动；公开部署入口及活动旧包装服务的保护保持不变。

最终证据位于 `.cache/verification/v3/`：

- `wrapper-transition-delivery-race.json`：整个 nodeops 竞态范围 **173 项 Test 主测试、1 项 Fuzz 固定种子主测试、576 个子场景通过**，204.615 秒，无失败。跳过三项外部 Docker／Compose 场景及桌面不能换所有者的子场景；后者在 Linux root 专项实际通过。
- `legacy-wrappers.edG31p/integration.log`：Linux amd64 root 权限与切换专项 **17 项主测试、136 个子场景通过**，无失败／跳过；服务管理为替身。同目录 `systemd-parser.log` 实际调用 systemd 语法校验，**1 项主测试、6 个子场景通过**，含四个原模板和两个保留 ID 模板；未运行实际 systemd 管理器。
- `wrapper-objects.cvAJJG/objects.log`：实际 Vector／node-exporter Linux amd64 镜像、隔离 Docker 27 引擎，**1 项主测试、2 个角色子场景通过**。初始对象是未启动容器，捕获／切换使用合成 systemd 状态；随后真实执行生成的 `start --attach`／`stop --time 20`，验证 ID、挂载和安全选项不变。不能作为活动三容器或完整 Agent 迁移验收。外层网络关闭，不挂载宿主 Docker socket 或业务路径，不发布端口。
- 真实 Docker 为 host PID exporter 自动增加 `label=disable`；识别规则现仅允许该特定组合，并仍要求唯一 no-new-privileges，拒绝重复和其他安全覆盖。exporter 显式停止的 143 仅在客户端与容器退出码同时匹配、无 OOM 或引擎错误时接受。早期脚本 Python 兼容错误、测试未持有服务锁和上述兼容失败日志均保留；最终通过来自上列目录。
- `wrapper-transition-delivery-go-all.log`、`wrapper-transition-delivery-vet.log`：Go 全包及静态检查通过；未注入 SQL 测试 DSN，不声称重跑 PostgreSQL 集成。最终静态 Linux amd64 CLI 版本为 `v3.0.0-local-test`，SHA256 为 `941e5b4bc5dbb8c31676306cf051e7f8544ce56d77f783bc4b761d70ab49493b`。`wrapper-transition-embed-proof.json` 逐项验证 22 个前序网页资源未改变且已嵌入；未修改前端，不声称重新构建或浏览器验收。

Vector 固定 amd64 子摘要已成功下载；registry 原始 index 获取失败，空文件不是可用校验依据，不能声称完整原始 manifest 校验通过。五个本轮自建 Docker 引擎已按精确标识移除，见 `wrapper-transition-dind-cleanup.json`。没有全局清理、Git 提交／推送、发布、生产及业务通知操作，正式版本仍为 v2.0.46。全组迁移、完整安装及 PKI 运维、最终无损切换／回退、HA 与容量稳定性验收仍需继续。

## 2026-10-19：Agent 与包装组件的整组备份协调

新增私有 `legacyWrapperGroup`，将旧包装组件的捕获与原 Agent 归属接入现有 `transitionBackup`。capture 通过固定服务名及 SHA256 绑定同任务成员；先证明整组再停服，真实一致性备份保留原服务状态。新增仅限目标尚未激活的恢复边界，拒绝任何激活目录、新 active 指针或损坏完成凭据；恢复不写当前数据库和 JSONL。单 Agent 驱动与普通启停方法显式拒绝忽略包装成员，CLI／公开部署尚未选择整组协调器。

最终证据位于 `.cache/verification/v3/`：

- `wrapper-group-final-race.jsonl`：整个 nodeops 包竞态回归 **181 项 Test 主测试、1 项 Fuzz 固定种子主测试、643 个子场景通过**，196.243 秒，无失败。三项外部 Docker／Compose 测试及桌面不能换所有者的子场景跳过；后者在 Linux root 专项实际通过。逐项汇总见 `wrapper-group-final-race-results.json`。
- `legacy-wrappers.0yMTSG/integration.log`：隔离 Linux amd64 root 专项 **25 项主测试、203 个子场景通过**，无失败／跳过。同目录 `systemd-parser.log` 为 **1 项主测试、6 个语法子场景通过**。本轮新增 **8 项主测试、67 个子场景**，覆盖两种原 Agent 方式、完整捕获后才允许变更、后续成员冲突、未知新监督单元、部分停服继续或恢复、独立启用／运行状态、错误归属／成员摘要、恢复响应丢失及已完成外部变化拒绝。
- 分组测试使用真实 SQLite、文件及持久化锁，服务管理器和 Docker 命令为状态替身；不把这些用例计为真实活动三容器迁移，也未重复运行上一轮真实厂商镜像对象用例。语法检查调用实际 systemd 工具，但没有真实 systemd 管理器运行与内核安装验收。容器网络关闭、根文件系统只读，不挂载宿主 socket 或业务目录。
- `wrapper-group-final-go-all.log` 和 `wrapper-group-final-vet.log` 记录 Go 全包测试及静态检查通过；全包未注入 PostgreSQL DSN，不将跳过的 SQL 场景写为本轮集成验收。脚本语法、Go 格式及 `git diff --check` 均通过。
- 最终静态 Linux amd64 CLI 实际输出 `v3.0.0-local-test`，SHA256 为 `1996fc50f37f824ee77914f98bc7e1ded8468306ed4d53e93d782639aa8bdc3d`；`wrapper-group-embed-proof.json` 核对全部 22 个前序网页资源保持不变且逐个嵌入。未修改网页，不声称本轮重做前端或浏览器验收。最初新增测试误用不存在的版本字段，编译失败日志保留；改用真实 Release 字段后最终专项和回归通过。

目标激活及切换后的整组回退、下一任务对保留 ID unit 的归属识别、真实 native／Docker 安装与 PKI 运维、最终增量切换、单中心／HA 安装和真实容量稳定性仍需继续。正式版本保持 v2.0.46，不发布部分 v3；没有生产 PG、服务器 229、业务通知、Git 提交／推送或 latest 变更。自建 Linux 验证及版本核对容器按固定名称确认移除，见 `wrapper-group-cleanup-proof.json`。

## 2026-10-19：保留 ID unit 的跨任务来源与清单复查

新增节点私有首次来源记录，在替换 unit 前发布，绑定首次任务、Spec、节点和意图摘要。后续任务直接核对首次原模板、不可变容器／镜像、运行配置及实际状态，拒绝引用链和错节点；来源保持原样，新任务记录自己开始时的启停状态。已接入私有整组备份和普通只读安装清单，普通路径仍拒绝活动组件。清单返回前复查已停组件，防止 Agent 检查期间状态或来源变化后返回旧证据。目标激活及切换后的整组回退仍待接通，公开部署保持关闭。

证据位于 `.cache/verification/v3/`：

- `legacy-wrappers.H4FI9p/integration.log`：最终源码的隔离 Linux amd64 root 专项 **33 项主测试、269 个子场景通过，无失败／跳过**；同目录真实 systemd 语法检查 **1 项主测试、6 个场景通过**。服务管理器与 Agent 动作仍为替身，SQLite、私有文件、权限和锁使用实际实现。此前 `legacy-wrappers.uww2TF` 为加最终清单复查前的中间通过记录，不能冒充最终源码范围。
- `wrapper-objects.q1ta0l/objects.log`：实际厂商 Linux amd64 镜像和隔离 Docker 27 引擎，**1 项主测试、2 个角色子场景通过**。两个 idle 容器经下一任务重新捕获、停用及恢复，首次来源未改写；随后实际执行按原 ID 的启动／停止，容器身份和挂载保留。systemd 仍为合成状态，不等于真实活动包装服务、三容器或内核安装验收。测试未启动 Agent 或通知；外层网络关闭，无宿主 socket、业务挂载或端口发布。后续仅修改了不在该用例调用范围的安装清单复查，未将该记录写成完整最终安装器证明。
- `retained-wrapper-version.log` 为最终静态 Linux amd64 CLI 实际执行结果 `v3.0.0-local-test`，SHA256 为 `14338d395f958f8567990ca2362fa55337c0ed058f8047683b6c6a7f80f21f87`。`retained-wrapper-embed-proof.json` 核对全部 **22 个**前序 HTML／网页资源未改变且逐个嵌入。未修改网页，不声称重新做前端或浏览器验收。

最初扩大镜像查询测试范围时，两角色夹具误用了相同 config ID，且一角色来源恰好等于该 ID，测试路由错误返回另一镜像。失败日志保留为 `retained-wrapper-initial.log`；现为夹具分配不同 config ID，仍严格校验入口、镜像和对象归属，最终专项通过。另由源码复核发现停用组件可能在 Agent 检查期间变化，已补入最终复查及实际时点注入场景；加此保护前的竞态记录单独保留为 `retained-wrapper-pre-guard-race.jsonl`。

首次来源目录及所有被引用的原任务捕获需要持续保留。缺少来源、凭据配置改变、来源或 unit 删除、权限／所有者异常、引用链、额外命令、同名对象替换和意外运行／启用均拒绝，不用旧快照覆盖当前数据库。六个既有修复保持原哈希。六个自建验证容器（含隔离引擎）按固定名称或精确 ID 确认移除，见 `retained-wrapper-cleanup-proof.json`；没有全局清理、生产、服务器 229、业务通知或 Git／发布操作，正式版本仍为 v2.0.46。

最终 Go 回归：`retained-wrapper-final-race.jsonl` 为 **189 项 Test 主测试、1 项 Fuzz 固定种子主测试、708 个子场景通过**，250.738 秒，无失败；三项外部 Docker／Compose 主测试与两项桌面不能更换所有者的场景跳过，后两者已在上述 Linux root 专项通过。`retained-wrapper-final-go-all.log`、`retained-wrapper-final-vet.log` 分别记录 Go 全包与静态检查通过；没有注入 PostgreSQL DSN，不将 SQL 跳过场景计为本轮集成通过。

## 2026-10-19：整组目标激活、恢复与显式生命周期

整组协调器已接入显式 native／Docker 生命周期。预检查使用只读观察，完整捕获后才停服务；目标驱动保存完整 capture，只对已授权的原 Agent 使用独立视图。每次请求复制驱动并按绑定捕获选择协调器，不改写共享处理器。目标启动前及确认时复查包装成员停用；回退先停止目标并导出当前未确认事件，再恢复原配置及服务。恢复第一个成员前发布任务绑定的恢复边界，响应丢失后不再停止已恢复投递的成员或重导出数据库。

本轮证据位于 `.cache/verification/v3/`：

- `legacy-wrappers.3gQPLN/integration.log`：Linux amd64 root 专项 **46 项主测试、365 个子场景通过，无失败／跳过**；同目录实际 systemd 语法检查 **1 项主测试、6 个子场景通过**。覆盖四种原／目标方式组合、启用与运行状态独立恢复、旧组件变化拒绝、启动及恢复响应丢失、当前新增事件保留与导出、恢复回执损坏、原库缺失和只读预检查。
- 随后仅扩展测试夹具，增加完整本地 verify／finalize 的四种组合验证；产品源码未改变。`group-lifecycle-complete-phase-race.jsonl` 为扩展后的生命周期专项竞态：**5 项主测试、22 个子场景通过**，39.350 秒，无失败／跳过。`group-local-phases.I1NpP5/integration.log` 在 Linux amd64 同范围 **5 项主测试、22 个子场景通过**。文件、SQLite 和 Journal 为真实实现；systemd、Docker、进程和 cgroup／资源数据为替身，不能当作实际安装、内核限制或完整中心采集验收。
- `wrapper-objects.Es18Cz/objects.log`：实际厂商镜像、隔离 Docker 27／vfs 引擎，**1 项主测试、2 个角色子场景通过**。复查本轮拆分后的捕获、跨任务来源及生成的不可变 ID 启停；对象初始未运行，systemd 状态为替身，不等于活动三容器切换。无 Agent、真实通知、宿主 socket、业务路径或端口发布，外层网络关闭。
- `group-lifecycle-final-go-all.log`、`group-lifecycle-final-vet.log` 记录通过的 Go 全包测试和静态检查；扩展纯测试后另用 `group-lifecycle-supplement-vet.log` 检查 nodeops。没有注入 PostgreSQL DSN，不将跳过的 SQL 场景计作本轮 PostgreSQL 验收。
- `group-lifecycle-final-race.jsonl`：整个 nodeops 包 **202 项 Test 主测试、1 项 Fuzz 固定种子主测试、804 个子场景通过**，338.051 秒，无失败。三项外部 Docker／Compose 主测试及两项桌面不能换所有者的子场景跳过；后两者在上述 Linux root 专项通过。全包集合编译后仅扩展纯测试夹具和增加本地 verify／finalize 用例，新增范围由前述 5 项／22 场景竞态及 Linux 补充验证，不把补充测试伪写进该全包记录。
- 静态 Linux amd64 CLI 的 `version` 实际输出 `v3.0.0-local-test`，SHA256 为 `9cceb72a6d64565e02a2eb1ce61fdfe8f15f50b2741fc1cc57138c5bda6efcfa`；`group-lifecycle-embed-proof.json` 核对全部 **22 个**前序网页资源未改变且逐个嵌入。未修改前端，不声称重新构建网页或浏览器验收。最初误用 `--version` 得到帮助，原输出保留为 `group-lifecycle-version-option.log`，版本判断仅使用正确子命令结果。

最初 group 目标夹具把不存在的 native 服务标成运行，及最终 capture 核对误用 `inspect` 操作，分别导致失败；均修正夹具，未放宽程序归属检查。新增异常测试最初误用不存在的 Result 字段导致编译失败，已改用实际 State；日志保留。最终通过记录以上述专项为准。五个自建验证容器（含嵌套引擎）已按精确名称或 ID 确认移除，见 `group-lifecycle-cleanup-proof.json`。六份既有修复保持原哈希。

完整 systemd／Docker 安装与真实中心联合验收、无监督活跃 sidecar、证书自动续期及轮换、单中心／HA 安装与拓扑迁移、最终数据增量切换及万台容量／72 小时稳定性仍未完成。正式版本仍为 **v2.0.46**，没有生产、服务器 229、业务通知、Git 提交／推送或镜像标签变更，不发布部分 v3。

## 2026-10-19：真实 x86_64 内核、systemd native 安装与升级

新增[隔离内核验收工具](V3-KERNEL-VALIDATION.md)：原生 ARM QEMU TCG 启动完整 Debian x86_64 内核，systemd 为 PID 1，虚拟机只有 loopback，无共享目录、SSH、外网和业务资料。外层容器无特权或宿主 socket。正式 v3 仍未完成，本轮没有发布。

真实验收发现 systemd 252 的空闲状态返回 `Job=`，旧解析器只接受 `Job=0`，导致 native 激活在启动服务前失败。现兼容明确存在的空值及原有 `0` 表示；非零任务、模糊值、缺失和重复属性仍拒绝。没有替换 `/proc` 证明或绕过进程、配置、资源限制检查。

最终证据位于 `.cache/verification/v3/`：

- `kernel-lifecycle.G8Z4Po/guest-test.log`：**2 项真实内核主测试通过，无失败／跳过**。新装／回退为 106.70 秒，已有 v3 native 安装的升级／回退为 140.71 秒，最终 `WEBSCAN_V3_GUEST_TEST_EXIT=0`。实际 systemd 命令、进程归属、cgroup CPU／内存及文件句柄、mTLS 指标与配置身份、文件事件、持久化 Journal、恢复原指针与当前未确认事件均使用真实实现。临时移除内核 CPU 配额时复查明确失败，恢复后通过；完成阶段复查不重启 Agent。ClamAV 关闭，YARA 为无害恒假规则，没有业务通知。
- 同目录 `images.json`、包清单、`inputs.sha256`、`serial.log` 记录实际工具及启动输入。内核为 Debian `6.1.0-54-amd64`／包版本 `6.1.190-1`，systemd `252.39-1~deb12u2`，QEMU `9.1.2`。依赖由发行版签名仓库解析并记录实际版本，不将其描述为已锁定全部依赖的发布构建。
- `kernel-final-nodeops-race.jsonl`：整个 nodeops 包 **205 项 Test 主测试、1 项 Fuzz 固定种子主测试及 818 个子场景通过**，377.807 秒，无失败。三项需要外部 Docker／Compose 的主测试及两项桌面不能换所有者的场景跳过，逐项见 `kernel-final-nodeops-race-results.json`；本轮不将这些跳过计为真实 Docker 或 Linux root 专项通过。随后只扩展 Linux 专用真实升级测试，由上述虚拟机直接运行，不改写桌面竞态统计。
- `kernel-final-go-all.log`、`kernel-final-go-vet.log`、`kernel-final-linux-vet.log` 记录 Go 全包与静态检查通过；新增升级测试另见 `kernel-upgrade-linux-vet.log`。未注入 PostgreSQL DSN，不声称本轮重跑 SQL 集成。
- `kernel-binary-version.log` 实际输出 `v3.0.0-local-test`，当前静态 Linux amd64 程序 SHA256 为 `40127e3e7cf8b2abbbad50c5e0db939f36552baa63c26bc01685d3757447a21c`。`kernel-embed-proof.json` 核对全部 22 个前序网页资源未改变且已嵌入。没有修改前端，不声称本轮重做网页构建或浏览器验收；六份既有修复保持原哈希，见 `kernel-preserved-proof.json`。

中间失败完整保留：首次构建错误地把本地镜像 ID 用作 Dockerfile 来源名；根目录准备遇到只读 `machine-id`；导出的 Docker 标记导致 systemd 进入容器模式；串口登录服务干扰输出；debugfs 路径最初填写错误。现移除临时容器标记并强制核对完整虚拟机模式，日志落入虚拟磁盘后只读提取。真正的 native 激活失败及实际 `Job=` 返回见 `kernel-lifecycle.DcEZeh/guest-test.log`；修复后的单项中间通过见 `kernel-lifecycle.Ibb0rt`，最终两项以上述 `G8Z4Po` 为准。

本轮证明新装及已有 **v3 native** 安装的本地服务生命周期，不代表发布版 v2、真实活动三容器、Docker 完整内核安装、ClamAV 启用场景或中心联合验收已通过。单中心／HA 安装、证书运维、完整增量迁移与回退、容量／72 小时稳定性仍需继续；没有生产、服务器 229、Git 提交／推送或 latest 变更。

## 2026-10-19：Docker 真实内核生命周期与启动探针竞争修复

扩展隔离内核工具，增加 Docker 方式。完整 x86_64 虚拟机内运行 Docker 27.5.1、Compose 2.33.0、runc 1.2.4，使用 vfs 和真实 systemd cgroup；引擎来源固定为官方 amd64 子清单，外层无特权或宿主 socket，虚拟机仅 loopback。当前 Go 程序和工具包进入实际生成的 Compose，不以容器配置字段替代内核限制证明。

首次实际运行在激活失败。`kernel-lifecycle.cTrXNq/guest-test.log`、`docker-kernel-first-container.log` 保留 `content_changed_before_commit` 启动错误：Agent 在初始核对尚未结束时就启动心跳探针写入，可能使核对读取的探针文件在提交前变化。现将自己的探针写入延至初始核对完成后；文件内容／元数据复查保持不变。新增测试阻塞真实初始核对，分别验证首次启动和重启不得提前写探针，放行后必须产生正常事件。旧顺序的独立 overlay 二进制两个子场景均失败，修复后二者通过，见 `docker-kernel-startup-probe-original.log`、`docker-kernel-startup-probe-exec.log`；overlay 不改工作区源码。随后增加真实文件并发改写、原子替换和符号链接替换三个场景，确认快照后的变化仍被拒绝，原基线及事件表不被过期事务改写。

本轮证据位于 `.cache/verification/v3/`：

- `kernel-lifecycle.jviuwc/guest-test.log`：`TestDockerKernelLifecycleFinalizesAndRetainsEvents` **298.85 秒通过，无失败／跳过，退出标记 0**。新装及已有 v3 Docker 升级均完成 verify／finalize，验证实际 256 MiB 内存、1.25 CPU 和 65536 文件句柄；真实 mTLS／覆盖、文件事件、启动响应丢失后的无重启续作、全部完成阶段复查、内存限制漂移拒绝、原容器 ID／指针恢复和当前未确认事件保留均通过。恢复后再次核对原容器的实际内核限制。同目录保留实际引擎、daemon、镜像加载、输入摘要和串口日志。
- 该运行的虚拟机测试成功，但宿主脚本退出 **127**：在 QEMU 运行期间修改脚本，导致 Bash 恢复读取时落入错误的行偏移，未执行自动提取。已在正常关机后独立只读提取并校验测试名、PASS 和退出标记，见 `docker-kernel-guest-result.json`。不将宿主退出码伪写为 0。脚本现用完整函数先解析后执行，并在磁盘准备后清理派生解包副本；修订后的脚本已通过 native 的完整运行（宿主和虚拟机退出均为 0），见 `docker-kernel-native-regression-harness.log`。早期在线磁盘读取遇到文件系统校验错误，仅作为失败诊断保留，未用作验收证据。
- `kernel-lifecycle.rnepPN/guest-test.log`：相同 CLI 的 native 新装及已有 v3 native 升级／回退两项复测通过，分别 106.77 和 136.18 秒，无失败／跳过，虚拟机及宿主脚本退出均为 0。仍核对真实 systemd、进程、cgroup、mTLS、文件事件和当前未确认事件；与 Docker 验收的 CLI 摘要一致。
- `docker-kernel-agent-linux-final.log`：Linux amd64 Agent **29 项主测试及 14 个子场景通过**，其中真实 YARA 已运行；私有 clamd 另见 `docker-kernel-agent-clamd.log`，**1 项通过**。自动测试使用无害规则／私有签名、无业务通知。最初测试 tmpfs 不可执行，以及共享测试夹具的等待组引发停机等待，分别保留在初始日志；修正测试运行环境及恢复独立等待组后全包通过，没有改变生产停机语义。
- `docker-kernel-nodeops-race.jsonl`：Docker 及服务状态相关竞态专项 **46 项主测试、177 个子场景通过**，72.769 秒，无失败；需要外部运行时的 `TestDockerLoadedRuntimeOnDisposableContainer` 跳过，不计作实际通过。
- `docker-kernel-go-all.log`、`docker-kernel-go-vet.log` 和 `docker-kernel-final-linux-vet.log` 为 Go 全包测试、静态检查及 Linux Agent／nodeops 静态检查记录。未注入 PostgreSQL DSN，不声称本轮重跑 SQL 集成。
- `docker-kernel-binary-version.log` 实际输出 `v3.0.0-local-test`；CLI SHA256 为 `e889beb9df69b2f051e10e772b268f4ef387fdd4f435708225fc29001d09a2fd`，22 个既有网页资源保持原样且已嵌入，见 `docker-kernel-embed-proof.json`。没有修改前端，不将旧网页验证当成本轮重新构建或浏览器验收。

本轮源码快照为 `docker-kernel-final-delivery-source.json`，共 817 个文件；相对前轮仅 7 个文件变更、2 个新增，差异见 `docker-kernel-source-delta.json`。六份先前未提交修复保持原哈希，17 个自建验证容器均按精确名称确认不存在，见 `docker-kernel-preserved-proof.json`、`docker-kernel-cleanup-proof.json`。测试磁盘及临时身份仍保存在私有证据目录。

这证明当前 v3 Docker 的同方式本地生命周期；尚未证明活动 v2 三容器迁移、native↔Docker 完整内核切换、ClamAV 启用的完整安装或中心联合验收。完整单中心／HA 安装、证书续期／分发／轮换、最终增量切换与回退、万台容量及 72 小时稳定性仍需继续。正式版本保持 v2.0.46，没有 Git 提交／推送、生产、服务器 229 或镜像发布操作。

## 2026-10-19：双向方式切换与活动旧包装服务恢复

新增真实内核 `transition` 和 `sidecars` 模式。内核证据保存在 `WEBSCAN_V3_KERNEL_OUTPUT_ROOT` 指定的私有目录，以避免占满工作盘；索引、源码摘要、常规测试及结果 JSON 仍在 `.cache/verification/v3/`。没有增加公网接口、开放部署写入或操作生产服务。

### v3 native↔Docker 与当前数据保留

`TestKernelNativeDockerTransitionsRetainCurrentData` 分别安装 v3 native 和 Docker，完整切换到另一方式再回退。它执行真实 systemd／Docker、实际 CPU／内存／句柄限制、YARA、mTLS、配置版本 1→2→1，并扫描真实 `/proc` 验证仅一个 Agent 写入进程；在实际启动成功后丢弃响应，重开 Journal 核对，禁止再次启动。切换前后真实文件事件必须以原 ID 留在当前数据库，恢复后的原 Agent 仍可读取，不从旧快照覆盖新数据。

- `kernel-lifecycle.bGwXvx/guest-test.log` 首轮 **359.62 秒通过**，两个子场景分别 187.12／172.43 秒；虚拟机和宿主脚本退出均为 0。结果索引 `cross-mode-first-result.json`。
- 复查发现保留的历史指标可能被首轮测试当作新进程的就绪证据。现仅请求本次等待开始后的样本，并要求最新样本就绪；额外核对恢复后实际进程的内核资源限制。Linux 补充测试覆盖历史样本拒绝、最新失败覆盖旧成功、乱序／空样本及时间边界，见 `cross-mode-fresh-readiness.log`。
- 加强后的 `kernel-lifecycle.cIoNMs/guest-test.log` **433.50 秒通过**，两个子场景分别 221.27／212.14 秒，无失败／跳过，虚拟机退出标记 0。运行时修改过宿主脚本，宿主最终退出 **127**，不能将该项写成宿主脚本成功；自动提取的关机后原始日志及 `cross-mode-strengthened-result.json` 保留实际结果。脚本现于已解析的 `main` 内部退出，防止返回后继续读取变化的源码；后述 sidecar 完整运行的宿主退出为 0。

上述两次 CLI 摘要均为 `e889beb9df69b2f051e10e772b268f4ef387fdd4f435708225fc29001d09a2fd`。它们证明 v3 安装之间的方式切换，不代表发布版 v2 三容器或中心联合迁移。

### 活动 Vector／node-exporter 与恢复确认竞态

`sidecars` 模式使用原厂固定摘要镜像、精确 v2 包装 unit、真实 systemd PID 1 和由 systemd 管理的独立 Docker daemon。Vector 只读取空测试文件源并输出到 blackhole；没有旧 Agent、中心推送目标或通知渠道。

首次 `kernel-lifecycle.K5VQog` 的两个厂商子场景均失败，错误为 `legacy-wrapper-restore-not-confirmed`。第二次 `kernel-lifecycle.QY5HWS` 保留进一步诊断：失败后原 unit 已 active/running、enabled、无排队 Job，原容器也正常运行。独立延迟启动回归在旧实现下两个子场景均失败，见 `active-sidecars-readiness-original.log`。问题在于 `Type=simple` 先确认 Docker 附着客户端启动，程序立即检查时原容器可能尚未运行。

现在恢复仅在精确客户端、已捕获容器和全部归属证明有效时最多等待 15 秒，每次只读复查，不重新发起启动。unit、对象或启用状态变更立即拒绝；取消／超时不写完成回执。修复及取消、归属变更回归见 `active-sidecars-readiness-fixed.log` 和最终竞态专项。

最终 `kernel-lifecycle.bzP5jq/guest-test.log` **75.29 秒通过**，Vector／exporter 分别 36.63／31.91 秒，无失败／跳过，虚拟机及宿主脚本退出均为 0。两种厂商服务各做两轮实际捕获、停用、禁用和恢复，下一任务重新证明首次来源并保留原容器 ID；完成恢复的重放保持附着客户端 PID 不变。结果索引 `active-sidecars-fixed-result.json`。这属于活动旧包装组件管理，不能作为旧 Agent 与全部组件联合数据迁移的证明。

### 回归、产物及边界

- `active-sidecars-final-race.jsonl`：相关竞态专项 **60 项主测试、371 个子场景通过**，247.760 秒，无失败；`wrong-owner` 子场景因宿主非 root 跳过，未计为通过。它使用测试替身覆盖组合及故障分支，真实系统服务证明以上述内核运行单独记载。
- `active-sidecars-final-go-all.log`、`active-sidecars-final-go-vet.log`、`active-sidecars-final-linux-vet.log`：Go 全量测试、静态检查及 Linux nodeops 静态检查通过；没有注入 PG DSN，不声称本轮重跑数据库集成。
- 最终 Linux amd64 CLI 为 `v3.0.0-local-test`，SHA256 `749105c4c9cb8a1f14855da27cc9b1b2cd1fb7692d8b855b6b13c180dd2b09ea`。22 个既有网页资源保持原哈希并已嵌入，见 `cross-mode-final-embed-proof.json`；本轮没有前端改动或重新进行页面验收。
- 最终源码摘要 `cross-mode-final-delivery-source.json` 共 820 个文件，变更索引 `cross-mode-source-delta.json`；六份既有未提交修复保持原哈希，34 个自建验证容器按精确名称确认不存在，见 `cross-mode-preserved-proof.json`、`cross-mode-cleanup-proof.json`。私有虚拟磁盘与临时身份保留供排查。

仍需完成旧 Agent／sidecar 联合迁移、无包装的活动 Compose sidecar、单中心及可选 HA 安装器、证书自动续期／分发／交叠轮换、公开部署提交、最终增量切换及无损回退。10,000／20,000 节点、100 用户、72 小时稳定性及三台独立机器 HA 接管尚未验收。正式版本保持 v2.0.46；本轮没有 Git 提交／推送、服务器 229、生产 PG、业务通知或发布操作。

## 2026-10-19：已发布旧 Agent 与活动包装 sidecar 的联合内核验收

新增 `legacy-group` 模式，导入实际已发布的 `v2.0.34` Agent（摘要 `sha256:453ec55733ec73457e4ddf3ea6a6d23b2d6e4e55c044ec77cd2194aac5c6ee27`），启动真实 Compose Agent 和两个活动 systemd 包装 sidecar；分别测试切到 v3 native／Docker 以及整组回退。Vector 读取实际测试 JSONL，但使用 blackhole 输出，没有业务推送或通知。

首轮 `kernel-lifecycle.p4ZZnF/guest-test.log` **失败**，318.22 秒，两个场景分别 153.71／164.42 秒，虚拟机及宿主退出均为 1。测试夹具漏掉旧部署原有的独立可写探针目录挂载，旧 Agent 在启动时退出，未进入迁移；不能将该轮算成迁移验证通过。独立无网络容器诊断复现原 `*fs.PathError`；补齐相同的探针目录挂载后，同一正式旧镜像实际运行并输出 `webscan_coverage_ok 1` 和已完成基线。实际诊断日志保存在私有 `legacy-agent-diagnostic.2r6w3ei7` 目录，索引见 `.cache/verification/v3/legacy-agent-diagnostic-root.txt`。

第二轮补齐挂载并增加真实基线 hash／stat 保留检查。虚拟机测试输出同时写串口和私有日志，便于长测试期间查看真实阶段，最终证据仍在正常关机后提取。实际结果以后述完整结果为准，不以新增测试代码或独立诊断代替联合验收。

最终 `kernel-lifecycle.DoeUTB/guest-test.log` **474.88 秒通过**，native／Docker 子场景分别 201.21／273.56 秒，无失败或跳过，虚拟机与宿主脚本退出均为 0，见 `legacy-group-fixed-result.json`。两个场景均完整执行检查、准备、整组备份、激活、验证、完成、重开 Journal、回退及回退验证；核对实际 CPU／内存／句柄限制、新采样／mTLS／YARA、原基线 hash／stat、当前数据库和旧 JSONL 中的原事件 ID。全部三个原容器 ID 恢复为运行态，包装服务恢复原启用状态，旧 Agent 再产生并导出新事件；回退的只读重放保持三个进程 PID 不变。

- `legacy-group-go-test.log`：nodeops 回归通过，207.554 秒；`legacy-group-go-all.log`：Go 全包测试通过（部分使用缓存）。没有注入 PG DSN，不声称本轮重跑 SQL 集成。
- `legacy-group-final-go-vet.log`、`legacy-group-final-linux-vet.log`：全包及 Linux amd64 nodeops 静态检查通过；测试与脚本通过编译、`bash -n` 及 `git diff --check`。
- 当前 Linux amd64 CLI 仍为 `v3.0.0-local-test`，SHA256 `749105c4c9cb8a1f14855da27cc9b1b2cd1fb7692d8b855b6b13c180dd2b09ea`，与前轮一致：本轮只新增真实内核验收、修正测试夹具并改进验收脚本输出，没有修改生产 Go 逻辑。22 个既有 UI 资源保持原哈希且已嵌入，见 `legacy-group-embed-proof.json`；没有前端修改或新的页面验收。

该组合不是纯 Compose 三容器：旧 Agent 用 Compose，两个 sidecar 用实际旧 systemd 包装。没有远端中心推送，ClamAV 关闭，测试规则无害。仍需补齐纯 Compose 活动 sidecar、正式单中心／HA 安装、证书自动续期与轮换、公开部署流程、中心最终增量切换和无损回退，以及真实万台／两万台、100 用户、72 小时与独立机器 HA 验收。完整 v3 未完成，正式版本保持 v2.0.46，没有发布、推送 Git、操作生产或服务器 229。

## 2026-10-19：纯 Compose 三容器整组迁移与后继捕获

新增私有纯 Compose 成员捕获和恢复逻辑，原 Agent、Vector、node-exporter 均由同一份真实 Compose 启动，不创建旧包装 unit。普通单服务入口继续拒绝接管活动 sidecar，未知混合管理方式不放行。成员证据绑定原 Compose／运行配置、实际镜像、完整容器设置、原运行状态及重启策略；停用、恢复和丢失响应续作只操作原不可变 ID。

最初本地回归发现 Docker→native 激活会按原设计退役旧 Compose 文件，而新增成员状态核对仍要求该文件存在。现仅在本任务完整捕获、快照和 native 激活意图一致，且原 Agent 仍停止并保持退役名称时允许其缺失；存在但变化的文件仍拒绝。证明不依赖损坏的新配置或过期叶证书。还补入沿已捕获前驱指针查找停用成员的能力，防止后继任务丢失原证明；本轮只验证下一任务捕获，没有执行第二次完整升级。

- 首轮 `kernel-lifecycle.aemzRE` 被 Docker OOM 终止，宿主退出 **137**，没有完整关机后的退出标记，**不计为通过**。原串口保留迁移进度；`compose-group-initial-engine-events.jsonl` 记录实际 `oom`／`die`，结果索引 `compose-group-initial-result.json`。不能将它当成产品迁移失败或成功的完整证据。
- 随后暂停另一台自建虚拟机，将正式重跑的容器上限提高到 **4 GiB**；guest 仍为 1536 MiB。脚本默认值同步更新，文档要求各模式串行执行。实际运行上限及调整日志保存在 `compose-group-final-runtime-state.log` 等文件；没有调整业务容器。
- 最终 `kernel-lifecycle.sbOs8k/guest-test.log` **611.17 秒通过**，native／Docker 分别 **290.46／320.59 秒**，两个子场景和主用例无失败或跳过，guest／宿主退出均为 0，见 `compose-group-fixed-result.json`。
- 两种目标均执行完整捕获、全部停写、一致性 SQLite／JSONL 备份、实际激活、新采样／mTLS／YARA、内核资源核对、完成、重开 Journal、回退和回退验证。原基线 hash／stat、当前数据库及新旧事件 ID 保留；原三个容器 ID 恢复后，正式旧 Agent 仍可生成并导出另一条事件。只读重放不改变原进程 PID。
- 两个场景还创建真实下一任务捕获，沿配置链核对停用 sidecar 的原 ID，当前 Agent 不重启。这是后继捕获的证明，不能替代后继升级和跨任务最终恢复的联合验收。
- `compose-group-final-go-all.log`：Go 全包通过，其中 nodeops **338.584 秒**；`compose-group-final-race.jsonl`：相关竞态专项 **31 项主测试、191 个子场景通过**，**259.214 秒**，无失败或跳过。覆盖独立状态、响应丢失、证明损坏、取消、外部漂移、后继捕获和新配置损坏后的回退。
- `compose-group-final-go-vet.log`、`compose-group-final-linux-vet.log`：Go 全包及 Linux amd64 nodeops 静态检查通过。没有注入 PG DSN，不声称本轮重跑 SQL 集成。
- 当前 Linux amd64 CLI 实际输出 `v3.0.0-local-test`，SHA256 为 `5d8f22579e0a5d08e45ecb16d0d86baf60012e46ec640ef49955e01a104a57d6`。22 个既有 UI 文件保持原哈希且已嵌入，见 `compose-group-embed-proof.json`；没有前端改动或新的浏览器验收。

纯 Compose 本轮的旧服务为 HTTP，目标采用 mTLS；Vector 读取实际测试 JSONL 后输出 blackhole，ClamAV 关闭，没有业务中心推送或通知。旧 HTTPS Compose、ClamAV 启用的整组安装、多次完整升级及中心联合切换仍需补齐验证。完整单中心／HA 安装、自动证书续期／分发／轮换、公开部署流程、中心最终增量迁移和无损回退，以及 10,000／20,000 节点、100 用户、72 小时和独立机器 HA 仍未交付。正式版本保持 v2.0.46；没有发布、Git 提交／推送或生产变更。

旧包装服务的当前源码回归 `kernel-lifecycle.z7fhaw/guest-test.log` **442.26 秒通过**，native／Docker 分别 **186.00／256.14 秒**，两个子场景及主测试无失败或跳过，guest／宿主退出均为 0，见 `compose-group-wrapper-regression-result.json`。该虚拟机在测试开始前的镜像导入阶段暂停，纯 Compose 验收完成后恢复，并使用相同 4 GiB 容器上限；这是资源协调，不能当成运行中故障接管验收。当前静态 CLI 与纯 Compose 正式重跑摘要相同。

最终源码 `compose-group-final-delivery-source.json` 共 **824** 个文件，相对前轮 15 个变更、3 个新增、无删除；原六份未提交修复保留，52 个自建验证容器按精确名称确认不存在。见 `compose-group-source-delta.json`、`compose-group-preserved-proof.json`、`compose-group-cleanup-proof.json`。583 个 Go／模块输入在最终测试后保持原哈希；验收脚本仅追加默认容器内存 3→4 GiB 的资源修正，正式内核重跑已实际应用相同上限，记录见 `compose-group-final-tested-source-proof.json`。


## 2026-10-19：捕获摘要、历史 Agent 与逐级回退缺口

新活动指针增加私有 `capture_sha256`，绑定整份捕获；只沿捕获中的前驱指针追溯，核对清单、任务、配置／定义、快照及激活资料。每一层原 Docker Agent 均需保持原 ID、指纹、退役名称、停止状态和关闭自启动。新指针缺失首层捕获也拒绝；旧开发态意图恢复保留原编码及原有兼容边界，详见节点切换说明。恢复也核对新增摘要，未改动原数据库、协议或公开部署门禁。

本地通过结果：

- `history-anchor-focused.log`：相关专项通过，37.019 秒；`history-anchor-extra.log`：循环和矛盾恢复摘要拒绝通过，3.441 秒。
- `history-anchor-race.jsonl`：13 项主测试、50 个子场景通过，79.132 秒，无跳过／失败，stderr 为空。包含缺失／变更捕获、损坏快照／激活意图、旧 Agent 漂移、兼容续作及原 Compose 专项。
- `history-anchor-engine-regression.log`、`history-anchor-engine-race.jsonl`：切为 native 后仍需证明承担恢复职责的旧 Docker 对象；引擎不可用拒绝检查，当前 native 不停服；恢复正常证据后仍可回退。首次全量运行暴露旧测试假设不再需要该引擎，修正断言，未放宽生产保护。
- `history-anchor-final-go-all.log`：Go 全包通过，其中 nodeops 277.490 秒；`history-anchor-final-vet.log`、`history-anchor-final-linux-vet.log` 及后续夹具的 Linux vet 通过。
- `history-anchor-retired-fence-race.jsonl`：补充原任务退役后，即便后继已回退，原身份／高代次的执行及查询也不能恢复权限；另重验原栅栏用例。该测试证明保护保持，不代表新增恢复交接已实现。
- 原六处保留修复和 22 个嵌入 UI 资源不变。内核运行程序与当前静态编译程序相同，摘要 `67c7df31696fbd6b8f67dafcba7b2d85b35db24b1c9b0bb01e042e1c9846f2ff`。

真实内核增强验收 **尚未通过**，两轮均保留失败证据：

1. `kernel-lifecycle.0htxZj`：完成 native 第二次替换后，测试主动更改旧容器策略时遗漏服务操作锁，返回 `service-operation-lock-required`。只修正测试夹具显式持锁，未放宽运行器。
2. `kernel-lifecycle.6HAN0H`：完成 native 第二次替换、历史策略漂移拒绝及恢复、生成新事件、后继回退及新鲜配置回执后，继续请求原任务恢复时返回 `remote-conflict`。原任务已被后继永久退役；这是需要独立恢复任务交接的实际缺口，不得通过取消旧请求栅栏解决。

两次均在明确失败后停止精确的自建虚拟机，宿主脚本退出 1，没有正常关机／guest 成功标记，不能计为主测试、native 子场景或 Docker 子场景通过。第二轮已开始 Docker 分支但未完成；串口中完成的中间阶段也不等于联合验收成功。私有根目录为 `/Users/lizheng/Library/Caches/webscan-v3-kernel-validation`，记录见 `history-anchor-kernel-initial-result.json` 和 `history-anchor-kernel-followup-result.json`。

后续应增加绑定历史任务及捕获、当前生效指针和后继已完成回退的独立恢复任务，串联主控租约、审计和子控 Journal；旧任务永久退役规则保留。之后再重跑两种方式的完整逐级恢复，核对当前数据库、全部阶段事件和原三容器。旧 HTTPS、ClamAV 完整安装、中心切换、正式安装器、证书运维和容量／独立机器 HA 门槛仍未完成。正式版本保持 v2.0.46，本轮没有发布、Git 提交／推送或生产变更。

## 2026-10-20：独立恢复任务与真实连续升级回退

子控增加受限恢复引用，绑定新的任务身份、原任务／计划／capture、当前指针，以及已完成回退的后继任务／计划。Journal 在采用新身份前核对原任务退役及完成状态、后继回退和无运行阶段；服务锁内重验实际状态，首次执行先原子发布私有恢复意图。后续由新任务继续，旧身份保持退役；不恢复旧数据库覆盖新增事件，不因重复检查重新启停服务。

本地证据位于 `.cache/verification/v3/`：

- `recovery-handoff-guards-final.log`：恢复／Journal 专项通过，41.644 秒。补充未结束／未退役来源、运行阶段、错误后继摘要及命令分派保护。
- `recovery-handoff-race.log`：恢复、Journal 与命令相关竞态测试通过，69.295 秒。`recovery-handoff-history-race.log` 的历史证据竞态通过，38.448 秒；macOS 的 root 所有者子场景跳过，另由 `recovery-handoff-linux-owner-final.log` 在隔离 Linux root 中通过。
- `recovery-handoff-linux-tests-final.log`：Linux root 下 21 个主测试、27 个子场景通过，无跳过。使用真实 SQLite／文件／锁，服务管理为替身。
- `recovery-handoff-chain-race.log`、`recovery-handoff-chain-linux.log`：连续两级独立恢复通过；恢复任务可作为下一次恢复的后继，中间凭据损坏后外层完成验证拒绝，全部退役身份仍拒绝高代次请求。
- `recovery-handoff-go-all.log`：Go 全量通过，nodeops 311.559 秒；本次未配置外部数据库，条件式 PG／时序集成测试不能因此算作通过验收。macOS 和 Linux amd64 的 `go vet ./...` 均通过。

真实完整内核验收 `kernel-lifecycle.VQAIxZ/guest-test.log` 在正常关机后提取，主测试 **1069.83 秒通过**，native／Docker 分别 **473.48／596.21 秒**。两种方式均实际执行旧 v2.0.34 三容器 → 首次 v3 → 后继 v3 → 首次 v3 → 原三容器；最后一步使用独立新恢复任务。核对原不可变三容器 ID、基线、当前 SQLite、各阶段真实事件和旧 JSONL，恢复后旧 Agent 再次产生事件，完成回放不重启。两个子场景及主测试无失败或跳过，guest 及宿主退出均为 0，虚拟机正常关机。引擎为 Docker 27.5.1、x86_64、vfs、systemd、cgroup v2。

静态 CLI SHA256 为 `92c307f902b65857177af96debf9b4f04bf4416491d16035395aa5d57058f3ad`。`recovery-handoff-source.json` 固定该次内核编译前的 828 文件；之后只新增独立恢复链测试和更新进度文档，未修改此次已编译的产品或内核用例。原六份未提交修复摘要保持不变，22 份已有前端资源未变且嵌入该 CLI，见 `recovery-handoff-embed-proof.json`。

原始失败日志仍保留：保护夹具曾使用不存在的 `capture` 阶段，现改为真实的 `backup` 并断言必须影响一行；首次 Linux 运行缺少只读 testdata 挂载，随后运行的临时目录默认不可执行，现明确使用可执行私有临时文件系统供夹具 YARA 脚本运行。未放宽产品检查。前轮两个内核失败记录也保留，当前通过结果不会覆盖它们。

这仍是子控层面的恢复交接。主控尚未生成可信恢复任务或连接其 PG 租约／版本／审计及 SSH 请求；新恢复任务在内核测试中直接构造。旧 Vector 业务投递、旧 HTTPS、ClamAV 完整安装、中心最终切换、正式安装器、证书运维和容量／独立机器 HA 门槛仍未完成。正式版本和 latest 保持 v2.0.46，没有 Git 提交／推送、生产 PG、服务器 229 或业务通知操作，不能发布完整 v3。

## 2026-10-20：主控持久化安装恢复证据

新增正常完成回执中的 capture／目标指针摘要，子控在 Journal 操作锁内核对不可变捕获、快照及激活资料后返回。SSH 将证据与原请求 Spec 绑定，主控使用任务的不可变配置快照校验，在同一租约事务中提交 HMAC 证据、成功状态、已应用版本和审计。schema 27→28 先一致性备份，不为旧任务补造证据；PG 备份恢复继续依赖独立密钥。

首轮 SSH 联调发现任务中的 `Node.Config` 为避免保存配置正文而刻意省略，证据校验误读默认目录。现从目标配置快照读取原配置并校验完整摘要，真实 SSH 夹具使用自定义目录和启用的 ClamAV 设置防止此问题再现；服务动作及采集就绪仍为明确的合成证据。另调整证据外键锁的顺序，先取得采集租约；终态更新再次检查租约，事务内过期不能提交成功。

已通过的本地结果：

- `central-recovery-evidence-fenced-regression.jsonl`：隔离 PostgreSQL 的部署、配置应用节点、互斥及 SSH 竞态回归 **70 项主测试、159 个子场景通过**，122.689 秒，无跳过。覆盖丢失完成响应后的续作且不重复远端阶段、缺失证明拒绝、native／Docker 目标、证据篡改、事务失败、处理中租约失效、密钥轮换及备份恢复。
- `central-recovery-evidence-lock-order.log`：真实 SQL 锁等待下核对安装证据及原验收路径均先取得采集租约，另一事务仍可锁节点；竞态运行通过，3.090 秒。
- `central-recovery-evidence-node-race.log`：子控证据、Journal、恢复引用及旧组生命周期竞态通过，99.837 秒。SQLite、文件及锁为真实实现，服务动作使用替身。
- `central-recovery-evidence-linux-root-pass.log`：隔离 Linux root 中 native／Docker 两种证据绑定及只读重放通过，0.60 秒。未运行真实服务管理器；新回执尚无本轮完整内核安装验收。
- `central-recovery-evidence-fenced-vet.log`、`central-recovery-evidence-fenced-linux-vet.log`：macOS 及 Linux amd64 相关包静态检查通过；Linux amd64 CLI 已静态构建，标记为 `v3.0.0-local-test`。
- `central-recovery-evidence-fenced-go-all.log`：最终源码的 Go 全包回归通过；本命令未注入 PG／时序服务地址，条件式外部集成不据此计为验收通过，相关数据库证据以上述独立组为准。

本轮曾有测试环境准备失败：只读挂载下缺少嵌套挂载点，随后 Docker 夹具所需 `/var/tmp` 未配置可写临时文件系统。修正为已存在的挂载点及独立可执行 tmpfs 后通过；原失败日志保留，没有放宽产品权限检查。

`central-recovery-evidence-pg-all.jsonl` 的广域数据库回归触及 Go 默认 **10 分钟**测试超时，不能计为全包通过。部署相关用例已在上述当前源码竞态组完成；其余未完成主测试另按明确清单、30 分钟上限续跑，`central-recovery-evidence-pg-remaining.jsonl` **219 项主测试、128 个子场景通过**，161.638 秒，7 项因未提供实际时序服务、Linux 上传工具或低空间权限环境而跳过。三个数据库组并集覆盖列表中的 547 项主测试：537 通过，10 项跳过，没有遗漏；覆盖索引见 `central-recovery-evidence-pg-group-coverage.json`。各组编译于不同源码快照，不能写成“同一最终源码全 PG 包通过”，也不是真实万台连接或稳定性验收。

当前源码及结果索引位于 `.cache/verification/v3/central-recovery-evidence-*`；原六份未提交修复和 22 份前端资源哈希保持不变，资源已嵌入本轮 Linux CLI，SHA256 为 `fb0029e20cc7a141f967f0d111d897df07f376ab12f6996ce4a1ada78b54828a`。主控新恢复任务生成、后继／新代次绑定及 SSH 恢复引用仍未接通；其余完整 v3 门槛继续保留，未发布或操作生产。

## 2026-10-20：主控独立历史恢复任务与 SSH 交接

schema 29 新增来源／后继的分域 HMAC 绑定及外键保护。本地管理员可在明确启用执行器后，创建新的历史恢复任务。创建前认证原安装证据、配置摘要及实际运行代次；当前配置先加密存档，再原子提交新任务、回退引用、防重回执、日志和审计。来源任务保持终态，当前已保存草稿不被覆盖。公开创建接口仍不接受 `recover`，读取模型和网页已正确显示“历史恢复”。

SSH 使用原安装 Spec 与新任务身份，绑定 capture／指针和后继任务摘要；仅下发当前可信辅助程序，不要求旧配置包仍存在，不上传前向部署的镜像、程序包或配置。每个阶段和完成事务重新认证，旧运行快照发布时从当前代次递增。后继可为另一个已完成恢复任务，链深最多 128。恢复到原本未登记的节点时清除运行登记和当前健康状态，历史及子控当前事件库保留。

本轮验证证据位于 `.cache/verification/v3/recovery-task-*`：

- `recovery-task-fenced-race.jsonl`：真实隔离 PostgreSQL、竞态检测下 **11 项主测试、21 个子场景通过**，41.787 秒，无跳过。覆盖同／不同请求键并发、防重、备份失败、证据篡改、新任务接管、处理中租约失效整笔回滚、连续两级恢复及原本未登记节点。SSH 为真实本地服务，远端服务动作和安装摘要为明确合成证据。
- `recovery-task-cli-race.jsonl`：本地管理员命令与重复执行通过，3.035 秒；旧配置目录缺失仍可创建任务，输出不包含私密资料。此用例亦已纳入上述最终恢复专项。
- `recovery-task-regression.jsonl`：部署、配置应用节点、启动交接、运行登记及迁移的竞态广域回归，**122 项主测试、237 个子场景通过，1 项主测试失败**，350.098 秒，无跳过。失败为凭据切换夹具：测试临时角色无密码，而初始隔离数据库启用了密码认证。改用该夹具明确要求的独立 trust 测试库，`recovery-task-bootstrap-trust.jsonl` 同一用例通过，6.596 秒；未修改产品或放宽生产认证。原失败记录保留，不将分组结果写为一次全包通过。
- `recovery-task-web-typecheck.log`、`recovery-task-web-test.log`、`recovery-task-web-build.log`：类型检查、**24 个测试文件／207 项测试**及构建通过。新增页面用例核对列表、路由详情和恢复阶段日志；读取契约新增 `recover` 类型，公开创建门禁保持原样。
- `recovery-task-openapi.log`、`recovery-task-fenced-vet.log`、`recovery-task-fenced-linux-vet.log`：OpenAPI 契约、macOS 及 Linux amd64 相关 Go 静态检查通过。
- `recovery-task-final-go-all.log`：更新后的 Go 全包回归通过，controlplane 10.149 秒、nodeops 282.398 秒。本命令未配置外部 PostgreSQL／时序服务，外部数据库验收以上述独立组为准，不据此计为全 PG 包或万台规模验收通过。
- `recovery-task-final-embed-proof.json`：22 份当前页面资源全部嵌入静态 Linux CLI，仅 v3 入口及其脚本因显示新类型而变化；v2 页面及其余资源保持不变。CLI SHA256 为 `af96d4a77399a39e6a4fdc5365f6ab3232cf8f83598d0396631e557e9a328a62`，在无网络隔离容器中实际运行返回 `v3.0.0-local-test`。原六份未提交修复摘要保持不变。

首次专项发现并修复并发不同请求在重复读事务下返回底层唯一约束错误的问题，现返回节点已有未完成部署。连续恢复夹具曾误将原已登记节点当作未登记节点，已修正预期并单独补齐真正未登记场景。最终补充拒绝未完成激活的普通后继，避免本地未切换结算冒充子控所需激活证据。广域组编译早于此保护和页面标签变更，后续恢复专项、页面检查及最终 Go 回归分开记录，不能宣称同一快照完整 PostgreSQL 包验收通过。

本轮尚无主控联合真实 systemd／Docker 的全流程验收。此前真实内核子控恢复通过记录继续有效，但不能替代新主控调度的联合验收。配置应用父任务的历史恢复协调、完整安装器、证书运维、最终增量切换、容量与多机 HA 门槛仍待完成。临时数据库已移除，未访问生产数据库、服务器 229 或业务通知；未提交 Git、发布镜像或改动 latest。

## 2026-10-20：全新单中心安装与续作（schema 29 不变）

本轮冻结记录为 `.cache/verification/v3/single-install-fenced-source.json`（842 个文件）。新增独立安装器、命令入口、验证脚本及测试、安装说明和文档白名单。六项既有修复哈希不变；没有改动 Vue 或嵌入资源，没有提交 Git、操作生产或发布镜像。

- `single-install-fenced-race.jsonl`：隔离 PostgreSQL、实际 Compose 配置解析和竞态检测，10 个主测试、19 个子项通过，11.597 秒，无失败。跳过 1 个需要专属 Docker runner 的整栈测试，该项在下述 Linux 容器单独执行，不计为这里的通过。覆盖账户重复续作、已改密码及数据库版本保护、原子资料、链接和权限、固定摘要、容器身份、unit 冲突和输出脱敏。
- `single-install-fenced-container-run.log`、`single-install.Wx0erB/integration.log`：实际新构建 Linux amd64 CLI、PostgreSQL 17.11、VictoriaMetrics 和中心容器，42.43 秒通过。在中心激活前故意失败，检查点停在第 4 步；继续后核对原数据库标记、数据库凭据及数据库／时序库容器 ID，实际登录后再次继续，三个容器 ID 与登录会话保持有效。systemd 明确使用模拟适配器，不能计为真实开机自启或完整生产安装验收。
- PostgreSQL amd64 摘要 `aa90e97ee862e558111d34cfb8b2c4bec768c2b039fb791341686928560263b3`，VictoriaMetrics amd64 摘要 `11c82f4778672bd362039e01c15ba349b9f69171ebe6f1b3d4e9f62aa79f4164`；从官方仓库按固定摘要拉取，平台子清单另有记录。没有放宽平台校验或替换本机 ARM64 原标签。
- `single-install-fenced-go-all.log`：冻结源码的 `go test ./...` 通过，controlplane 11.836 秒；nodeops 使用此前本轮通过的缓存（`single-install-go-all.log` 为 258.183 秒）。本命令没有配置外部 PG／VM，条件数据库及扫描器测试不计为额外验收。
- `single-install-fenced-vet.log`、`single-install-fenced-linux-vet.log`：macOS 与 Linux amd64 相关 Go vet 通过；脚本语法及 `git diff --check` 通过。
- `single-install-embed-proof.json`：实际执行的 Linux CLI SHA256 `d642c8b5710ef57e91a16d497918889be54e1579d7e4888f9abdf281d1120349`，22 个前端资源全部嵌入。前端未修改，本轮未重复构建，沿用此前同源资源验收。

首次整栈尝试 `single-install-container-run.log` 因本机 ARM64 PostgreSQL 缓存在镜像校验第 1 步停止，63.83 秒，失败记录保留，没有开始数据库服务。另保留一次镜像尚未下载完成时的前置门禁失败。随后改用明确 amd64 子清单摘要，并在创建资源前检查本地平台，两次整栈通过。较早的 `single-install-final-container-run.log` 是最后数据库版本保护改动之前的 41.70 秒结果，不替代最终 42.43 秒记录。

本轮 runner、三个项目容器、volume 及独立测试 PG 已清理，见各 run 的 `cleanup.log` 和 `single-install-pg-cleanup.log`。保留脱敏安装清单、检查点和日志，没有保留测试凭据／数据卷，没有连接业务通知、线上数据库、生产主控或子服务器。

仍须继续：真实 systemd 及 HTTPS 单中心完整安装、节点执行器与公开安装向导、PKI 自动续期／CRL 分发与换根、可选 HA／拓扑迁移、主控与实际节点联合恢复、最终增量迁移和无损回退，以及万台／两万台、100 用户、72 小时和独立三机 HA 验收。完整 v3 尚未完成，正式版本仍为 v2.0.46，不发布部分 v3。

## 2026-10-20：原子身份、叶证书续期与实际连接轮换（schema 29 不变）

本轮继续补齐证书生命周期，完整 v3 仍未完成。新增受管理的单文件 PEM 身份、显式离线发布／续期、主控和 Linux 子控运行中加载，以及主控连接回收。部署准备、受控签发和恢复资料检查统一读取当前活动身份。旧分文件配置保持兼容；没有自动改写现有节点包或单中心安装包，没有启用定时续期、分发或换根。

冻结记录 `.cache/verification/v3/live-identity-verified-source.json` 包含 848 个文件；此后仅更新三份进度／证书文档。六份原修复摘要保持一致，正式 HEAD、版本和 latest 不变。新增证书操作只返回公开回执，私钥不进入输出。身份文件到期时间的回退保护仅在当前进程内成立；跨重启的持久保护仍是既有 CRL 下限，不能混为一谈。

- `live-identity-nodepki-verified-race.jsonl`：证书包 **20 个主测试、18 个子项**通过，无失败／跳过，5.950 秒。覆盖同身份 CAS 并发、相同候选的响应丢失重试、0600／0700 历史、链接与权限拒绝、错 CA／身份／角色／私钥、损坏内容、过期、旧到期时间回退、错误文件恢复，以及显式续期保留 SAN 和拒绝已吊销身份。真实 TLS 新握手在同一监听器上同时使用新的服务端与客户端叶证书。
- `live-identity-nodepki-verified-linux.log`：相同 **20 个主测试、18 个子项**在禁网 Linux amd64 容器执行通过，无跳过。`live-identity-agent-linux.log` 的 **2 个真实监听器用例**通过：同一 Agent 监听器替换双方身份，旧连接交叠期间仍有效，吊销后拒绝；另核对既有 CRL 热加载及跨重启下限。
- `live-identity-transport-final-pg-race.jsonl`：实际隔离 PostgreSQL、SQLite receipts 与 gRPC/HTTP2 的 **8 个主测试**及竞态检测通过，无跳过，26.208 秒。单个主控 Run 和子控监听器保持运行，本机新身份使旧连接排空；远端旧叶证书吊销后回收工作器并重新连接，三批事件全部确认，中心只有三条记录。另覆盖签发、部署准备和恢复资料检查采用当前身份，以及旧连接返回不能借用新握手身份。万条登记调度用例仅证明登记查询，不能计作万台实时连接验收。
- `live-identity-transport-verified-linux-pg.log`：同组 **8 个主测试**在 Linux amd64 容器连接独立测试 PG 执行通过，无跳过；实际轮换用例 20.38 秒。首次 Linux 组缺少只读示例配置挂载，3 个夹具初始化失败，见 `live-identity-transport-linux-pg.log`；其余 5 项通过。补齐示例与源码夹具挂载后完整重跑，不放宽产品检查。
- `live-identity-cli-final-linux.log`：最终静态 CLI 在禁网 Linux 容器实际完成初始化、签发、原子激活、续期、历史权限检查及已吊销续期拒绝；输出 `LINUX_ATOMIC_IDENTITY_PUBLICATION_RENEWAL_AND_REVOCATION_OK`。续期专项首次发现回调错误未正确返回的问题，已修正并纳入拒绝回归；初始失败日志保留。
- `live-identity-final-go-all.log`：最终源码 `go test ./...` 通过。此前同轮 `live-identity-go-all.log` 的 nodeops 为 279.324 秒，最终命令复用该缓存；最终改动后的 controlplane、nodepki 另在 `live-identity-final-go-packages.log` 通过，分别 11.721／3.831 秒。全包命令没有设置外部 PG／VM，条件用例不计为额外数据库或扫描器验收；本轮证书 PG 专项以上述实际隔离数据库记录为准。
- `live-identity-final-verified-vet.log`、`live-identity-verified-linux-vet.log`：macOS 与 Linux amd64 相关 Go vet 通过；格式、脚本语法及 `git diff --check` 通过。没有前端改动，未重复运行无关页面测试和构建。
- `live-identity-final-embed-proof.json`：最终 Linux CLI SHA256 `1b14219a037b9801cffc4f9308955840aad74ac9866c0d13684dafaac3cbefc0`，22 份现有页面资源全部嵌入；禁网容器实际版本为 `v3.0.0-local-test`，不是正式发布。

`live-identity-pg-cleanup.log` 记录临时 PG 容器及测试网络移除。PG 使用临时内存数据目录，未保留数据库凭据或业务数据；没有连接线上 PG、主控、229、飞书或真实邮箱，没有提交 Git、发布镜像或更新 latest。

仍需完成自动叶证书续期／CRL 更新及逐节点交叠分发、CA 轮换、真实 systemd／HTTPS 单中心与执行器集成、公开节点安装流程、可选 HA／拓扑迁移、完整主控与真实节点联合恢复、最终增量切换与无损回退，以及万台／两万台、100 用户、72 小时和独立三机 HA 验收。本轮专项通过不代表完整 v3 可以发布。

## 2026-10-20：本机采集器定时维护接入单中心安装（schema 29 不变）

全新单中心请求使用 `format: 2`：固定原程序、安装配置与种子资料，分别维护 `authority/`、`collector-pki/` 及独立持久吊销下限。宿主机 oneshot／timer 每小时检查本机采集器叶证书与 CRL；中心只读挂载目录，原子更新后运行中加载。旧格式只保留原资料续作，不隐式转换。远端叶证书和 CRL 自动分发、CA 换根仍未完成。

复查补入了两个失败保护：初始化在运行目录发布前建立持久下限；已有运行目录或最终验收遇到下限丢失时均停止，不能按新安装重建。最终验收也检查私有签发资料可用。维护定时器激活失败不启动中心，修复后可继续。已吊销叶证书即使到期也不能续签；长时间离线恢复保持同一 CA 和身份。

源码冻结在 `.cache/verification/v3/single-pki-verified-source.json`，共 855 个文件。此后只更新进度与验证文档；六份原修复保持原摘要。页面没有改动，22 份现有内嵌资源另按实际最终二进制核对，避免将 Git 忽略的构建资源漏算为源码。

- `single-pki-final-nodepki-race.jsonl`：整个 nodepki 包 **22 个主测试、18 个子项**及竞态检测通过，无失败或跳过，5.634 秒。覆盖原子引入 CA、过期 CRL 续期、历史快照恢复活动源、保持身份／SAN、按期续签、长期离线和已吊销身份拒绝。`single-pki-final-nodepki-linux.log` 在禁网 Linux amd64 容器运行相同完整证书包，通过且无跳过。
- `single-pki-final-race.jsonl`：安装及本机维护的 controlplane **18 个主测试、27 个子项**通过，29.158 秒。三个条件测试明确跳过，分别是实际 Docker 安装、外部 PG 账号及 systemd 校验，另由下述独立专项执行；不能将这些跳过计作通过。
- `single-pki-final-linux-systemd.log`：禁网 Linux amd64 中 **10 个主测试、8 个子项**通过，无跳过，包含真实 systemd 252 的 `systemd-analyze verify`。静态校验使用明确的 Docker stub，不执行 PID 1、timer 或 sandbox，不能代替真实开机验收。
- `single-pki-final-pg-race.jsonl`：独立临时 PostgreSQL 的 **17 个主测试、13 个子项**及竞态检测通过，无跳过，37.850 秒。覆盖受控签发、跨实例版本下限、活动身份准备／检查、真实 gRPC 轮换、重复请求与账号续作不覆盖后来改密。测试 PG 容器和数据已清理，见 `single-pki-final-pg-cleanup.log`。
- `single-pki-process-container-run.log`：实际 Linux CLI、PostgreSQL 17、VictoriaMetrics、安装后的中心及 SQLite／mTLS 节点接口联合通过，62.79 秒。故意中断中心启动后按检查点继续，保留数据库凭据、已提交记录与原登录。运行实际安装的维护命令续签本机身份，再吊销原身份并发布 CRL；两批事件各确认一次。续签及完成后继续验收期间，中心容器 ID、PID、启动时间和重启次数全部不变。systemd 仍明确模拟，节点接口是隔离测试服务，不冒充真实完整 Agent 安装。
- `single-pki-final-packages.log`：最后仅增加中心进程断言后，controlplane／nodepki 普通测试通过，controlplane 19.772 秒。前述数据库、竞态与 Linux 专项的产品实现相同；断言新增部分由最终容器专项执行。
- `single-pki-final-go-all.log`：本轮 `go test ./...` 全包通过，nodeops 实际运行 270.903 秒，controlplane 21.839 秒、nodepki 4.459 秒。该全包命令开始后仅补了最终容器专项的进程断言及两份进度文档；最终 controlplane 另按上一项重跑。全包未配置外部 PG／VM，条件用例不另计为数据库或完整安装验收。
- `single-pki-final-vet.log`、`single-pki-final-linux-vet.log`：macOS 全包和 Linux amd64 的 controlplane／nodepki vet 通过；格式、脚本语法与 `git diff --check` 通过。本轮没有页面修改，不重复前端构建。
- `single-pki-final-embed-proof.json`：实际验收的 Linux CLI 位于 `single-install.8zPcPD/webscan`，SHA256 为 `c9798d5b8be016be737ffa0f9b2823bd9443fd90dcd594b4c945e1c03f8f7d7c`。22 份既有页面资源均保持原字节并嵌入；禁网运行 `version` 为 `v3.0.0-local-test`，不是正式发布。

保留最初测试服务等待连接关闭的日志；修正测试清理顺序后完整重跑，没有放松产品校验。所有本轮单中心临时项目、runner 和 volume 均按归属清理；没有全局 Docker 清理、生产数据库、服务器 229 或真实通知访问。Git、正式 v2.0.46 和 latest 未变。

仍需完成真实 systemd 开机与 HTTPS、节点执行器／公开部署集成、远端证书自动分发及交叠和 CA 换根、可选 HA／拓扑迁移、主控与真实节点联合恢复、最终增量迁移与无损回退，以及万台／两万台、100 用户、72 小时和独立三机 HA 验收。完整 v3 未完成，不发布部分版本。

## 2026-10-20：签名 CRL 主动下发与过期恢复（schema 29 不变）

主控通过现有 mTLS／HTTP2 连接调用可选 `UpdateTrust`，在身份协商前和指标周期下发变化的完整签名 CRL。相同已确认摘要不重传，各节点仍受原并发和超时限制；共享 FileTrust 的一秒缓存避免逐节点重复读盘和验签。仅 `Unimplemented` 作为旧节点能力兼容，其他错误保留失败，不记作更新成功。

新生成运行配置启用 `pull.revocation_updates`，接收端要求 TLS、原允许身份名单及独立持久目录。只在首次从不可变种子初始化，此后活动 CRL 和版本下限共用原子持久文件。签名、CA、角色、调用者当前有效性、历史吊销及单调编号全部校验；回执绑定节点、正文摘要、编号和到期时间。不接收路径、命令、CA 或私钥。正文上限为既有 2 MiB RPC 包络减 4096 字节，更新串行且最多等待五秒。

过期的有效历史可启动受限接收入口，但普通数据 RPC 和旧 `/metrics` 仍拒绝；允许身份必须在新签名列表下有效，且新列表不能删除原持久吊销。普通 RPC 返回前再次检查，因此已经进入长轮询的旧身份在吊销后不会得到事件。叶证书过期或换根不走此入口，远端叶证书定时续签和完整 SSH 恢复仍待完成。

冻结源码 `.cache/verification/v3/trust-distribution-verified-source.json` 共 861 个文件，六份原修复摘要保持不变。没有页面改动，实际构建的 CLI 仍包含原 22 份页面资源。

- `trust-distribution-final-core-race.jsonl`：nodepki **27 个主测试、26 个子项**通过，8.034 秒；pull **9 个主测试**通过，3.953 秒；nodeconfig **3 个主测试、4 个子项**通过，1.465 秒。均无失败或跳过。覆盖过期下限恢复、重启不用旧种子覆盖、错 CA／角色／损坏或链接拒绝、吊销不可删除、并发和锁取消、共享快照不暴露可变内存，以及真实 HTTP2 下允许名单、目标和大小校验、吊销中的长轮询及旧能力兼容。
- `trust-distribution-final-nodepki-linux.log`、`trust-distribution-final-pull-linux.log`：相同两个完整包在禁网、只读 Linux amd64 容器执行通过，无跳过，使用私有临时写目录；不替代实际宿主机服务验收。
- `trust-distribution-final-agent-linux.log`：真实 Linux Agent 监听器 **4 个主测试、4 个子项**通过，无跳过。容器根只读、移除全部 capabilities 后仅加回 DAC_READ_SEARCH，启用 no-new-privileges，临时目录受限。覆盖双方叶证书运行中加载、已吊销旧连接拒绝、新签名 CRL 在原连接恢复过期策略、重启保留接收版本及不完整配置拒绝。此处没有运行完整安装器或 systemd PID 1。
- `trust-distribution-pg-race.jsonl`：最终源码连接独立临时 PostgreSQL，controlplane **20 个主测试、20 个子项**及竞态检查通过，无跳过，41.988 秒。客户端丢响应、错节点／摘要／编号／到期、显式旧能力和重发均有覆盖；真实主控 Run 在叶证书轮换后自动把签名 CRL 写入独立子控状态，三批事件各确认一次。签发、共享下限、备份和账号续作专项继续通过。PG 测试日志及清理记录均只对应本轮临时资源。
- `trust-distribution-final-single.log`：实际 Linux 安装 CLI、PostgreSQL 17、VictoriaMetrics 及安装后中心通过，72.41 秒。中心本机维护完成续签及吊销发布，随后由真实采集器经 gRPC 更新子控独立持久目录；子控不再直接读取中心活动 CRL 文件。两批事件确认，中心容器 ID、PID、启动时间、重启次数及原登录保持不变。systemd 仍明确模拟，节点 RPC 服务为隔离夹具，不计作主控与完整 Agent 联合安装。
- `trust-distribution-final-go-all.log`：最终源码 `go test ./...` 全包通过；未设置外部 PG／VM 的条件用例不计为额外集成验收。`trust-distribution-final-vet.log` 与 `trust-distribution-final-linux-vet.log` 分别记录 macOS 全包及 Linux 相关包 vet 通过。
- `trust-distribution-protocol-proof.json`：两个 Go SDK 文件重新生成与当前源码逐字节一致；RPC 合约仍为 v1，事件和指标消息不变。
- `trust-distribution-final-embed-proof.json`：最终验收 CLI 为 `single-install.esGZSb/webscan`，SHA256 为 `372f3a5a41cddefc469bc4179fd1c6ba3196e5636438c879b74fcae07d106cac`；22 份原页面资源字节未变并已嵌入，不重复无关前端构建。

初次编译的语法和测试 import 错误日志保留，修正后重新构建和执行，没有以失败或跳过冒充通过。临时数据库、独立安装项目和验证 volume 均按归属清理，不做全局 Docker 清理。本轮不访问生产 PG、主控、229、飞书或真实邮箱，不提交 Git、发布镜像或改动 latest。

完整 v3 仍需节点叶证书定时续签及交叠分发、CA 换根、真实 systemd／HTTPS 与执行器／公开安装、真实主控与节点联合恢复、可选 HA／拓扑迁移、最终增量切换及无损回退，以及万台／两万台、100 用户、72 小时和独立三机 HA 验收，不发布部分版本。

## 2026-10-20：子控活动身份播种与切换备份互斥（schema 29 不变）

新准备的私有节点包改用 `format: 2`，运行配置将安装种子与 `/var/lib/webscan-v1/pki-identity/active.pem` 分开；旧 format 1 的运行字段和不可变配置仍兼容。首次启动原子发布 0700／0600 状态目录，后续只校验当前活动身份及固定根，不用过期、缺失或旧安装种子覆盖已续签证书。已有目录不完整、身份／CA 不匹配、文件链接或权限异常均拒绝。

切换备份新增可缺省的 `identity_state`，包含活动身份及私有历史，不改变原数据库结构。空间预算计入证书资料，复制时持有与原子激活相同的锁；不安全资料在停服务前报错。快照上限 32 MiB／4096 文件，超限不截断。native／Docker 回退保留当前活动身份，旧快照只作灾备资料；不覆盖切换后续签的证书。回退到使用旧分文件路径的 format 1 仍需单独处理证书有效性，尚未宣称完整跨架构证书回退通过。

最终产品源码冻结于 `.cache/verification/v3/seeded-identity-locked-verified-source.json`，共 863 文件；此后仅补验证文档。六份原修复摘要和正式 HEAD 保持不变。本轮没有修改页面，仍核对实际二进制内嵌的 22 份原页面资源。

- `seeded-identity-locked-core-race.jsonl`：新身份与快照互斥 **5 个主测试、16 个子项**通过，3.043 秒；nodeconfig **3 个主测试**通过，1.429 秒；备份／native 与 Docker 回退 **13 个主测试、29 个子项**通过，11.162 秒。均无跳过。覆盖多并发初始化、取消、过期及错误种子不发布、初始化后不自动修补、续签后重启和回退、私钥历史、快照阻止并发换证及取消后不执行回调，以及备份校验和保留新增事件。
- `seeded-identity-full-pki-race.jsonl`：补快照锁前的完整 nodepki **31 个主测试、42 个子项**及 nodeconfig **4 个主测试、4 个子项**通过，无跳过；新增快照锁本身由上一项竞态用例和以下最终 Linux 完整包覆盖，不能把此前日志写成最后一次全包竞态。
- `seeded-identity-locked-nodepki-linux.log`、`seeded-identity-nodeconfig-final-linux.log`：最终 Linux amd64 完整 nodepki **32 个主测试、42 个子项**和 nodeconfig **4 个主测试、4 个子项**通过，无跳过；禁网、根只读、移除所有 capabilities、私有 tmpfs。`seeded-identity-locked-nodeops-linux.log` 的 **13 个主测试、29 个子项**通过，无跳过，服务控制仍为隔离夹具。
- `seeded-identity-agent-final-linux.log`：真实 Linux Agent 监听器 **5 个主测试、4 个子项**通过，无跳过。补入安装播种、同一监听器换证和原种子下重启仍提供新叶证书；活动文件丢失不重新播种。既有 CRL 过期恢复和已吊销旧连接拒绝继续通过。最后的快照锁不改变监听器代码。
- `seeded-identity-locked-generated-linux.log`：真实 Agent 读取生成配置，旧格式与新格式 **2 个子项**全部通过。实际 YARA、文件事件、SQLite、mTLS 读取／确认、新叶证书重启和私有备份联合验证；重启前未确认事件 ID 不变，已确认状态和快照后新增事件保留。服务启动由测试直接调用 Agent，systemd／Docker 服务控制仍是夹具，不能计为真实 PID 1 或 Docker 安装验收。
- `seeded-identity-pg-race.jsonl`：独立临时 PostgreSQL 的 **27 个主测试、62 个子项**及竞态检测通过，无跳过，69.977 秒。覆盖新格式配置准备、加密发行登记、相同请求回放、原子准备／配置并发、两种部署方式及恢复绑定；不访问业务数据库。该组通过后仅修改独立备份模块的证书互斥，PG 相关实现未再变化。
- `seeded-identity-locked-go-all.log`：补备份互斥后的最终源码 `go test ./...` 全包通过，nodeops 283.143 秒、nodepki 8.166 秒。`seeded-identity-locked-vet.log` 和 `seeded-identity-locked-linux-vet.log` 记录 macOS 全包及 Linux 相关包 vet 通过。未配置外部 PG／VM 的条件用例不另计为集成验收，实际 PG 和扫描器证据以上述独立专项为准。格式及 `git diff --check` 通过。
- `seeded-identity-locked-embed-proof.json`：最终 Linux CLI SHA256 为 `d10e87466a1a0ee8870f8c2648bf97e2bf57fa275ea272ef06bb9f841c886fbf`，22 份原资源全部嵌入且摘要不变。`seeded-identity-locked-linux-version.log` 记录禁网运行版本 `v3.0.0-local-test`，不是正式发布。

最初生成配置容器把临时程序放在 noexec 目录，另一次回退夹具缺少可写的 `/var/tmp`，因此失败；修正隔离环境并保留初始日志后完整重跑，没有放宽产品安全检查。测试代码最初的局部变量重名及快照数量断言已修正；最终编译和以上专项全部通过。`seeded-identity-cleanup-proof.json` 核对独立 PG 容器已移除，其余容器使用 `--rm`，未创建持久测试卷、未执行全局清理。

远端叶证书的定时签发／分发和配置名称变化下的专用激活尚未接通；仅换安装种子不会隐式替换已有活动身份。完整 v3 仍待 CA 换根、真实 systemd／HTTPS 和执行器／公开安装、真实主控与子控联合恢复、可选 HA／拓扑迁移、最终增量切换与无损回退，以及万台／两万台、100 用户、72 小时和独立三机 HA 验收。本轮不提交 Git、不发布、不操作生产环境。

## 2026-10-20：子控本机 CSR 续期与活动身份激活（schema 29 不变）

子控在私有持久目录生成新的 Ed25519 私钥及 CSR，以原活动私钥对完整请求再次签名；主控只接收公开证书、CSR 和持有证明。签发保持相同节点、角色、根与 SAN，不接收任意证书扩展，不生成或回传子控新私钥。待签请求重试复用同一私钥；缺失或损坏不静默重建。激活绑定原证书及请求摘要，并由必需的策略回调核对当前吊销规则；原子发布继续保留私有历史。

此处只完成可复用的 Go 原语、真实监听器和生成配置联验，尚未接通定时调度、持久化签发回执、公开 RPC／CLI 或独立签发角色，不能称为远端自动续期。普通签发拒绝已过期原证书；SSH 恢复仍待完成。

源码冻结于 `.cache/verification/v3/node-renewal-verified-source.json`，共 865 文件。

- `node-renewal-final-pki-race.jsonl`：完整 nodepki **36 个主测试、60 个子项**及竞态检查通过，无失败或跳过，14.463 秒。覆盖同请求重试与并发、旧私钥持有证明、跨节点／根／SAN／扩展／密钥拒绝、吊销及过期、取消、策略失败和丢响应重放。
- `node-renewal-final-nodepki-linux.log`：相同完整包在禁网只读 Linux amd64 容器通过，**36 个主测试、60 个子项**无跳过，私有 tmpfs、移除全部 capabilities。
- `node-renewal-final-agent-linux.log`：真实 Linux Agent 监听器 **6 个主测试、4 个子项**通过，无跳过。本机 CSR 签发与原子激活后，同一监听器提供新证书，旧采集身份吊销继续生效，重启保留新身份。
- `node-renewal-final-generated-linux.log`：实际 Agent、YARA、SQLite、mTLS、生成配置及一致性备份联验通过，**1 个主测试、旧／新格式 2 个子项**，8.57 秒。新格式使用本机 CSR 私钥续签，备份同时保留活动身份、历史及待签请求，重启前未确认事件 ID 保留。服务控制仍由夹具模拟，不计为真实 systemd／Docker 安装。
- `node-renewal-final-go-all.log`：最终冻结源码 `go test ./...` 全包通过；ok   webscan/internal/nodeops 289.423s。`node-renewal-final-vet.log` 与 `node-renewal-linux-vet.log` 分别记录 macOS 全包及 Linux 相关包 vet 通过。条件 PG 用例未配置数据库，不另计为实际 PG 集成验收。`node-renewal-final-embed-proof.json` 核对实际 Linux CLI SHA256 为 `898acac54292b88a51b64c40523b49b5bb29a5f58570da1f39bf173beafc6d37`，22 份原页面资源保持字节且全部嵌入；实际禁网版本为 `v3.0.0-local-test`。

本轮容器均使用 --rm，无业务数据库、服务器或通知渠道访问；正式 v2.0.46、Git HEAD 和 latest 未变。完整 v3 仍待剩余安装、证书生命周期、HA、迁移和容量验收，不发布部分版本。
## 2026-10-20：节点本机私钥续期的公共签发账本（schema 30）

新增 PostgreSQL 续期账本，以节点、原证书和公开 CSR 摘要去重。签发只使用已生效的运行快照和节点专用持久租约；来源必须为初始登记证书或已提交的续期链。保存中的待应用配置不影响续期。签发、共享吊销下限和审计一起提交，结束时再次校验租约；事务或提交失败均不交付证书。账本没有私钥、加密私钥列或本机私钥路径。

源码冻结于 `.cache/verification/v3/renewal-ledger-verified-source.json`，共 868 文件。当前只有内部宿主签发操作，尚无公开 RPC／CLI、自动续期调度、远端交付及过期 SSH 恢复，不计为完整在线续期。

- `renewal-ledger-final-pg-race.jsonl`：独立临时 PostgreSQL 中 **54 个主测试、33 个子项**及竞态检测通过，无失败或跳过，96.319 秒。其中新续期账本 **8 个主测试、16 个子项**，覆盖并发重放、后继链、本地私钥激活、未应用草稿、快照与租约冲突、已吊销身份、共享 CRL 下限、事务失败、提交时失败、备份恢复及初次签发并发锁序；同时重跑旧版本迁移、灾备恢复及原 PKI 登记专项。
- `renewal-ledger-final-linux-pg.log`：相同 **8 个主测试、16 个子项**在真实 Linux amd64 与独立 PostgreSQL 容器通过，无失败或跳过。测试网络为 internal，没有发布数据库端口；runner 根只读、移除全部 capabilities，只用私有 tmpfs，源码夹具仅挂载公开示例 YAML。
- `renewal-ledger-final-go-all.log`：本轮 `go test ./...` 全包通过，nodeops 285.982 秒。命令在最后补入 schema 30 恢复路径及回执完整性校验前启动；最终 controlplane 由上列 PostgreSQL 竞态和 Linux 专项完整覆盖。`renewal-ledger-final-vet.log` 为当前源码 macOS 全包 vet 通过。
- `renewal-ledger-linux-vet.log`：最终 Linux controlplane vet 通过。`renewal-ledger-final-embed-proof.json` 核对 Linux CLI SHA256 为 `0e0ba4353d67b0b401f44cb5c324e1714d87f5e11c92ea812d1e71f6e5035be0`，原 22 份页面资源均保持字节并已嵌入；禁网实际版本为 `v3.0.0-local-test`，不是正式发布。

初次编译的未使用 import 和测试参数错误、回执时区差异、漏接 schema 30 恢复路径，以及首次 Linux 缺少示例 YAML 的夹具错误均保留原日志。修复后按上列最终源码重跑，没有把失败和跳过计为通过。测试容器、内部网络及临时 PG 按归属清理，没有全局清理、业务数据库或真实通知访问。

完整 v3 仍需自动续期及独立签发角色、CA 换根、真实 systemd／HTTPS 与公开部署、主控和真实子控联合恢复、可选 HA 与拓扑迁移、最终增量切换与无损回退，以及万台／两万台、100 用户、72 小时和独立三机 HA 验收。本轮不提交 Git、不发布、不操作生产。


## 2026-10-20：子控本机私钥续期 RPC（schema 30 不变）

合约 v1 增加可选续期准备／激活方法及真实活动身份回执，事件和指标原字段保持不变。新 format 2 配置启用，format 1 继续关闭。原允许名单与普通逐 RPC 吊销鉴权覆盖新方法；没有普通策略时拒绝，不能借用签名 CRL 更新的过期恢复例外。私钥留在子控，公开请求限 64 KiB，公开叶证书限 16 KiB，本机操作限时 5 秒。规范公开 JSON 拒绝重复、未知字段、超限和替代编码。

源码冻结在 `.cache/verification/v3/renewal-rpc-verified-source.json`，共 872 文件。此阶段接通真实子控 RPC，签发步骤由隔离测试调用受控签发器；主控自动请求队列、宿主签发调度和自动交付尚未连接，不计为完整远端自动轮换。

- `renewal-rpc-final-core-race.jsonl`：pull **11 个主测试**、nodepki **37 个主测试、67 个子项**、nodeconfig **4 个主测试、4 个子项**通过，无失败或跳过。包含真实 HTTP2 的允许名单、已吊销旧连接、缺少普通策略拒绝、错误目标及超限，以及规范公开请求和两种格式的启用差异；nodepki 复用相同源码的成功竞态缓存。
- `renewal-rpc-final-pull-linux.log`：Linux amd64 完整 pull **11 个主测试**通过，无跳过；禁网、根只读、移除全部 capabilities、私有 tmpfs。
- `renewal-rpc-final-agent-linux.log`：真实 Linux Agent 监听器 **7 个主测试、11 个子项**通过，无跳过。通过 RPC 准备并重试同一 CSR，原私钥持有证明及本地新私钥保持一致；拒绝损坏签名叶证书后活动身份不变，正确签名证书经 RPC 原子激活，丢响应重试返回相同结果。原监听器提供新叶证书，重启保持身份，换证前未确认的事件可继续读取及确认。启用要求与吊销旧连接同时覆盖。容器仅加回 DAC_READ_SEARCH，不运行 systemd PID 1。
- `renewal-rpc-final-generated-linux.log`：实际生成配置、Agent、YARA、SQLite、mTLS 及私有备份联验 **1 个主测试、2 个子项**通过，8.36 秒。包含启用新能力的 format 2 及保持原行为的 format 1，服务控制仍为隔离夹具，不计为完整宿主机安装。
- `renewal-rpc-final-pg-race.jsonl`：独立临时 PostgreSQL 的 controlplane **33 个主测试、78 个子项**及竞态检测通过，无失败或跳过，86.902 秒。重跑公开续期账本、初次证书登记、新格式配置准备、native／Docker 准备及配置应用并发绑定，未连接业务数据库。
- `renewal-rpc-protocol-proof.json`：重新生成两个 Go SDK 文件与源码完全相同，并逐字段核对 9 个原事件／指标消息；合约版本仍为 1。
- `renewal-rpc-linux-vet.log`：最终 Linux 相关包 vet 通过。`renewal-rpc-final-embed-proof.json` 核对实际 Linux CLI SHA256 为 `390631ba6f0d4efc8870fddd8a0ef33ae72de4ffabb13b184142dd45f2dfda7e`，22 份既有页面资源保持字节且全部嵌入；禁网实际版本为 `v3.0.0-local-test`。没有页面修改，不重复前端构建。

完整 v3 仍需自动续期队列及独立签发角色、过期 SSH 恢复和 CA 换根、真实 systemd／HTTPS 与公开部署、主控和真实子控联合恢复、可选 HA 与拓扑迁移、最终增量切换及无损回退，以及万台／两万台、100 用户、72 小时和独立三机 HA 验收。测试不访问生产、229、业务通知或真实邮箱；Git、正式 v2.0.46 和 latest 未变。

补充最终全量验证：`renewal-rpc-final-go-all.log` 记录冻结源码 `go test ./...` 全包通过，其中 nodeops 273.034 秒；`renewal-rpc-final-vet.log` 为相同源码全包 vet 通过。未配置 PG 的全包测试不另计为 PG 集成，实际 PG 结果以上述独立容器竞态验收为准。


## 2026-10-20：公开续期任务、独立宿主签发与自动交付（schema 31）

本轮将续期 RPC 连到主控采集周期、公共持久队列、节点专用签发租约和全新单中心宿主维护命令。剩余七天进入续期窗口，子控保留私钥，主控只持久化公开请求与签发回执；签发默认 30 天，宿主每轮最多 500 条、预算 45 秒，单项失败持久退避。部署维护期间暂停续期，不使正常部署验收误报协议故障；失去采集租约的工作器不能准备新 CSR 或提交任务。

配置切换后重新绑定同一公共请求，在当前运行身份、主机名及共享 CRL 下读取原签发回执，不改变原发行审计或重复签名。响应丢失后读取实际活动身份并事务确认，确认审计只记一次。成功后结束旧采集连接，由下一轮协调重新握手；监听器和主控进程不因换证重启。队列和确认的提交时失败均不能返回成功；备份／恢复包含新任务及相关快照。

最终源码冻结在 `.cache/verification/v3/renewal-queue-final-verified-source.json`，共 879 文件（前一冻结为 `renewal-queue-verified-source.json`）。以下验证使用实际 Linux CLI／本地 HTTP2／独立 PostgreSQL；没有访问生产、229、业务数据库、飞书或真实邮箱。

- `renewal-queue-final2-linux-pg.log`：真实 Linux amd64 与独立 PG 的续期专项 **21 个主测试、47 个子项**通过，无失败或跳过。含公共请求并发去重、租约过期与吊销、错误身份和证明、采集／签发租约丢失、快照重绑、未初始化／维护节点、损坏候选不阻塞其他节点、持久退避、提交失败和备份恢复。实际 mTLS 用例通过网络准备、独立签发和激活，同一监听器在新握手中提供新证书。容器根只读、移除所有 capabilities、内部网络不发布数据库端口；该用例使用真实本机身份内核和 RPC 接收器，不等同于完整真实 Agent 安装。
- `renewal-queue-single-install.log` 和 `single-install.zBoFsK/`：实际 Linux CLI、PostgreSQL、VictoriaMetrics、中心与安装后的维护命令联验通过，69.58 秒。包含中断续作、原账号与登录保留、原中心 PID／启动时间／重启次数保持、只读证书目录下的重新认证和事件确认。systemd 明确由适配器模拟，不能计作真实宿主开机／定时器演练。
- `renewal-queue-final2-embed-proof.json`：Linux CLI SHA256 为 `e9c8e1ef12b4440fb208c32a301134e7f181602b5e723e1eb7bbe844d134d13f`，原 22 份页面资源保持字节并全部嵌入；禁网执行 `version` 为 `v3.0.0-local-test`，不是正式发布。Linux 相关包 vet 通过。没有页面改动，不重复前端构建。

首次真实 RPC 夹具的 localhost 证书选择、HTTP2 ALPN 及身份文件一秒刷新缓存问题均修正后重跑；已有凭据切换夹具需要临时免密测试角色，首次临时 PG 的 scram 设置不匹配，按夹具要求改用仅回环发布的独立 trust 测试库重跑，未改变产品认证逻辑。失败证据见 `renewal-queue-fixture-failures.json` 与保留日志，失败不计作通过。

仍需 format 2 在初始种子证书过期后的升级／继续集成、过期叶证书 SSH 恢复、主机名专用身份转换、CA 换根、真实 systemd／HTTPS 与完整联合安装、HA 安装及拓扑迁移、最终增量切换与无损回退，以及万台／两万台、100 用户、72 小时和独立三机 HA 验收。正式 v2.0.46、Git HEAD、latest 与生产服务不变，完整 v3 尚不发布。

最终补充：`renewal-queue-final-trust-pg.jsonl` 的迁移／恢复与 PKI 广泛回归 **110 个主测试、152 个子项**及竞态检测通过，无失败或跳过，290.633 秒。其运行开始于最后启动依赖修正之前；最后源码的 `renewal-queue-final2-pg.jsonl` **30 个主测试、55 个子项**及竞态检测通过，无失败或跳过，60.275 秒，覆盖所有续期及本机 PKI 维护专项。`renewal-queue-final-local-pki-race.log` 另验证全部可在本机运行的维护测试。

数据库依赖与本机信任独立：数据库不可用时节点签发记为 `deferred`，部分失败记为 `failed`，保留脱敏状态及队列；中心开机不被 PostgreSQL／节点签发的启动顺序阻塞。本机信任损坏仍停止。Linux 及本机竞态均覆盖数据库不可用、部分签发、未初始化和本机信任损坏四种场景。

最终安装重跑：`renewal-queue-final2-single-tmpfs.log` 在独立 **3 GiB 临时内存卷**运行最终 Linux CLI、实际 PG／VM／中心，**1 个主测试**通过，94.34 秒；额外校验安装后维护命令确实报告独立节点签发状态。systemd 继续明确模拟。之前 `renewal-queue-final2-single-install.log` 因 Docker VM 实际仅余约 67 MiB，正确触发 2 GiB 安装空间门禁而停止，没有降低产品阈值。临时内存卷在 runner 停止后卸载，脚本最后可选的 `docker cp` 没有取到清单／检查点；不能宣称这些文件已被保留，进程内断言与日志仍完整。此前普通物理卷的清单在 `single-install.zBoFsK/`。只移除本轮归属容器、网络与卷，未做全局清理；环境磁盘压力仍需后续处理。

最终全量验证：`renewal-queue-final2-go-all.log` 的冻结源码 `go test ./...` 全包通过；`renewal-queue-final2-vet.log` 与 `renewal-queue-final2-linux-vet.log` 分别为同源码 macOS 全包、Linux 相关包 vet 通过。未配置数据库的全包测试不另计为实际 PG 集成；实际 PG 成绩按上列独立容器竞态结果计。最终源码除本验证文档补记外保持冻结哈希，六份原修复及 Git HEAD 不变。


## 2026-10-20：种子过期后的升级、配置绑定与旧任务继续

本轮新增 format 3 公开节点配置包。已存在本节点公开续期签发回执时，升级准备不读取／解密初始私钥、不另发初始身份，保存配置绑定可保留过期或被吊销种子的历史 ID／摘要。预览、任务提交及配置应用再核对当前公开继任证书和共享 CRL。签发后响应丢失不会强制回到初始种子路径；子控是否具有有效私钥仍由节点本机在停服务前验证。

节点准备、备份停服务之前及切换均检查当前私钥、CA 固定值、节点 ID、用途、TLS 名称、有效期、当前吊销状态及权限。普通 format 1／2 准备仍严格检查种子；只有存在有效本地身份和持久 CRL 的恢复路径允许读取历史 format 2 资料。原文件、任务摘要、活动密钥和吊销下限均不改写；当前私钥失效仍拒绝，不能以历史读取器恢复在线授权。续期发生在准备与入队之间不改变 format 3 包摘要。

- `keyless-pg.jsonl`：独立临时 PostgreSQL 的 **44 个主测试、110 个子项**及竞态检查通过，无失败／跳过，116.362 秒。覆盖新公开包、凭据绑定、配置应用准备、原证书登记、预览、确认、回执及旧 schema 迁移。测试库仅回环发布且使用独立内存数据目录。
- `keyless-final-managed-pg.jsonl`：最终专项 **5 个主测试、8 个子项**及竞态检查通过，无失败／跳过，11.253 秒。补充真实本地 CSR／签发／激活后再次续期，原升级包、预览及入队持续有效；覆盖未保存初始私钥、历史种子到期和吊销、错误节点／根／摘要／主机名，以及拒绝将公开升级包用于新装。
- `keyless-final-linux-pg.log`：真实 Linux amd64 与独立 PG 的 **24 个主测试、51 个子项**通过，无失败／跳过。含原公开队列、实际 HTTP2 mTLS 续期交付和本轮升级校验；签发／收件采用隔离本机实现，不计作完整真实 Agent 安装。
- `keyless-final2-linux-agent.log`：真实 Linux amd64、实际 Agent／SQLite／YARA／mTLS、私有备份的 **6 个主测试、16 个子项**通过，无失败／跳过。format 1、2、3 均启动并保留事件；另一个实际 Agent 用例的不可变初始证书与 CRL 均已过期、初始证书已吊销，仍以有效活动身份启动、续期、重启并保留未确认及切换后事件，4.32 秒。服务管理使用明确的夹具，不能计作 systemd 或真实 Docker 生命周期安装。
- `keyless-final-local-race.log`：本机公开格式、原格式、错误密钥／权限／链接、最新吊销状态、不可变包恢复及 native／Docker 停服务前复查通过竞态检查。该日志不计作实际数据库或真实服务管理证明。
- `keyless-embed-proof.json`：当前 Linux CLI SHA256 为 `18cf120c695d6466ba2b09a57048bdd91abac5be6ac23c88a2ceb6bddf8a8866`；22 份既有页面资源保持原字节且全部嵌入。实际禁网版本为 `v3.0.0-local-test`，没有前端源码修改，不重复构建页面。

首轮公开包测试的 Docker 服务定义夹具缺少固定镜像和安全监控挂载，补齐后重跑通过；首轮升级预览夹具未标记已有安装版本，正确触发配置冲突，补上与真实升级一致的安装证据后重跑通过。没有放松产品检查。当前公开包验证保持原认证、CSRF、摘要及租约要求。

没有修改数据库 schema、通信端口或原事件／指标消息。六份原修复及 Git HEAD 保持，未访问生产、229、业务 PG、SMTP 或飞书。完整 v3 仍需活动证书过期后的 SSH 恢复、TLS 名称转换、CA 换根、真实 systemd／HTTPS 和完整主子控安装恢复、HA 安装及拓扑迁移、v2 最终增量切换与无损回退，以及万台／两万台、100 用户、72 小时和独立三机 HA 验收。正式版及 latest 暂不发布。

最终全量检查：`keyless-final-go-all.log` 记录当前产品源码 `go test ./...` 全包通过，其中 nodeops 284.081 秒。之后增加的停服务前复查及准备期间再次续期用例已分别由最终本机竞态、Linux Agent 和 PG 专项覆盖；没有后续产品源码修改。`keyless-final-vet.log`、`keyless-final2-vet.log` 和 `keyless-final-linux-vet.log` 分别记录全包、本轮最终相关包及 Linux 相关包 vet 通过。最终源码与原修复校验见 `keyless-final-source.json`；本轮归属临时数据库、容器和网络已清除，未全局清理其他 Docker 资料。

## 2026-10-20：主控继续校验与过期活动身份恢复内核

补齐主控执行器在 SSH 前的任务校验：旧 format 2／3 静态资料过期时，既有任务必须仍持有有效租约、原节点版本及不可变配置摘要，并具有当前有效的公开继任证书、Collector 和共享 CRL 下限。新装及新预览继续拒绝历史资料。远端仍独立校验实际私钥；主控公开回执不替代远端就绪证明。

过期活动身份增加独立十分钟挑战、本机 CSR、原私钥对完整请求的独立域证明、受限签发、已有私有信任目录的单调推进及激活前复核。激活保持信任目录锁直至本地身份 CAS 完成；签发后原证书或新证书被吊销、凭据过期、目录丢失或密钥不匹配均拒绝。普通在线续期及 TLS 不接受过期证书，新私钥不出子控，旧私钥历史保留。

- `runtime-resume-pg.jsonl`：本机实际 PostgreSQL 竞态检查 **10 个主测试、22 个子项**通过，无失败／跳过，21.772 秒。通过生产执行器的校验回调连接实际固定指纹 SSH，并读写节点 Journal；服务管理明确模拟。覆盖租约／节点变更、继任证书缺失或吊销、Collector 吊销、CRL 回退、错误主机名和配置篡改在 SSH 前拒绝。
- `identity-recovery-runtime-linux-pg.log`：实际 Linux amd64 与独立 PostgreSQL 的 **30 个主测试、65 个子项**通过，无失败／跳过，包含上述继续校验及原有本机续期、签发账本、队列和实际 mTLS 交付回归。临时数据库无公网暴露，使用独立内存数据目录。
- `identity-recovery-pki-final2-race.jsonl`：本机证书库 **44 个主测试、118 个子项**及竞态检查通过，无失败／跳过，17.510 秒；`identity-recovery-pki-final2-linux.log` 在禁网、只读 Linux amd64 容器运行同样 **44／118 项**，无失败／跳过。覆盖当前吊销、失效挑战、独立签名域、并发 CSR 复用、旧私钥保留、响应丢失、CRL 单调性、权限／链接及激活前重新校验。
- `identity-recovery-agent-final2-linux.log`：实际 Agent、SQLite、YARA 与 mTLS 的 **3 个主测试、3 个子项**通过，无失败／跳过。三种配置格式、旧种子过期继续及活动身份过期恢复均保留未确认事件；后者构造历史签名的过期活动文件，确认真实 Agent 拒绝启动且不退回仍有效种子，再以本机 CSR 恢复、备份、重启并补采原事件，4.31 秒。新文件和确认状态继续保留。服务管理使用明确夹具，未替代实际 systemd／Docker 或 SSH 恢复任务联测；退出扫描期间仍有原有脱敏错误输出，原始日志保留。
- `identity-recovery-vet.log`、`identity-recovery-final2-vet.log`、`identity-recovery-final-linux-vet.log`：分别为本轮全包 vet、最终相关包 vet 及 Linux 相关包 vet 通过。
- `identity-recovery-embed-proof.json`：Linux CLI SHA256 `64df4611670f85201cddaad30b64805aaa896662e9555227f11dbabcb0ef0e2f`，22 份既有页面资源字节不变且全部嵌入；禁网运行显示 `v3.0.0-local-test`。前端源码未变，本轮不重复构建页面。

恢复原语**尚未接通主控持久恢复任务、账号／版本授权、固定路径 SSH 命令和服务受控启动**，不得据此标记完整 SSH 身份恢复完成。独立签发账本的恢复去重和跨进程任务接管仍待实现。TLS 名称转换、CA 换根、真实 systemd／HTTPS 及完整主子控安装恢复、可选 HA 与拓扑迁移、v2 最终增量切换及无损回退，以及万台／两万台、100 用户、72 小时和独立三机 HA 验收仍为发布门禁。

最终源码清单见 `identity-recovery-final-source.json`；六份原修复与 Git HEAD 保持。所有本轮临时容器和网络均已按归属移除，未做全局 Docker 清理，未访问生产、229、业务 PG、邮件或飞书。正式版仍为 v2.0.46，完整 v3 不发布。

最终全量回归：`identity-recovery-final2-go-all.log` 的 `go test ./...` 全包通过；nodeops 命中本轮前次全量运行的缓存（`identity-recovery-go-all.log`，285.868 秒），其后仅增加 Linux 专用 Agent 联测并已在上述实际 Linux 容器重跑，最终 nodepki 用时 14.805 秒。无数据库配置的全包测试不另计为 PostgreSQL 验收，实际 PG 结果按专项日志计。


## 2026-10-20：持久恢复登记、固定 SSH 工具与真实对端确认

schema 32 新增公开恢复意图／请求记录，绑定管理员权限版本、节点配置与运行快照、已验证指纹的加密凭据引用和节点签发租约。恢复沿用普通续期唯一发行账本；重复签发、丢失响应、原发行回执核对、取消、备份恢复及租约接管都不复制子控新私钥。生产适配器支持校验工具后通过固定 SSH 命令执行本机 CSR 和原子激活，完成须另外经过真实 gRPC mTLS 对端确认；旧接口继续拒绝过期身份。

- `recovery-registry-migrations2-pg.jsonl`：独立内存 PostgreSQL 的广泛竞态回归 **314 个主测试、560 个子项通过，零失败**，832.083 秒。覆盖旧 schema 迁移、一致性备份／恢复、配置应用、任务及 PKI 依赖。2 个明确要求附加隔离环境的测试跳过；随后在 `recovery-helper-additional-linux-pg.log` 使用真实 VictoriaMetrics 与 1 MiB 临时文件系统分别补跑 **2 个主测试**，均通过，无跳过。无数据库环境的本机测试不计作 PG 证明。
- `recovery-registry-complete-pg.jsonl`：最终主控恢复／普通续期／固定指纹 SSH 专项 **34 个主测试、82 个子项**及竞态检查通过，无失败或跳过，83.299 秒。覆盖真实 SSH 连接、校验过的工具及公开请求交付、错误／过期返回、签发账本和真正 mTLS 对端核验。SSH 测试服务模拟远端命令；mTLS 测试服务为隔离 HTTP2／gRPC 实现，不能代替实际宿主服务安装。
- `recovery-helper-final-runtime-linux-pg.log`：相同 **34／82 项**在实际 Linux amd64 测试程序和独立 PG 上通过，无失败／跳过。包括正常 mTLS 确认，以及错误证书、错误能力声明、已吊销节点／本机采集器、RPC 期间失去租约的拒绝；已吊销采集器不会发出远端 RPC。
- `recovery-helper-local-final3.jsonl`：本机最终 helper／私有配置／锁回归 **7 个主测试、31 个子项**及竞态检查通过。覆盖 native／Docker 配置、私钥就地保存、重复响应、配置／目录／权限／吊销下限、未完成部署、失败回退、互斥及规范 JSON；拒绝前不生成待用密钥或改变活动身份。
- `recovery-helper-final2-agent-linux.log`：实际 Linux Agent、SQLite、YARA、mTLS 和固定路径 helper 的 **6 个主测试、21 个子项**通过，无失败／跳过。实际 Agent 拒绝过期活动身份且不回退到有效种子；恢复后保留原未确认事件与新事件并继续确认。服务管理与已完成安装元数据为明确夹具，不能计为真实 systemd／Docker 或完整 SSH 恢复任务联测。
- `recovery-registry-pki-race.jsonl`、`recovery-helper-final-pki-linux.log`：证书库 **45 个主测试、125 个子项**分别通过本机竞态与禁网 Linux 验证。
- `scripts/verify-v3-identity-recovery.sh`：可复跑脚本在 `.cache/verification/v3/identity-recovery.HIgszm/` 实际通过 **34／82、6／21、45／125** 三组分层测试，无失败／跳过。独立内部 PG、网络和临时容器均按归属清除；保留 `postgres.log`，不全局清理 Docker。
- `recovery-helper-go-all-final.log`：本轮 `go test ./...` 全包通过，nodeops 286.010 秒。其后仅做本机采集器吊销检查、helper 规范 JSON 和 CLI 冲突提示的收尾，分别由上述最终专项、可复跑 Linux 脚本和 `recovery-helper-cli-final-test.log` 覆盖；没有把早先全量结果伪称为不同源码的全量运行。全包 vet、最终相关包以及 Linux 相关包 vet 均通过，见 `recovery-registry-vet-final.log`、`recovery-helper-final2-{vet,linux-vet}.log`、`recovery-helper-final3-{vet,linux-vet}.log`。
- `recovery-helper-cli-dispatch.json`：实际禁网 Linux CLI 拒绝无效恢复输入及同时指定两种操作。`recovery-helper-embed-proof.json`：最终 CLI SHA256 为 `d37033e8c0272d8aa59fc180bbd6eead69c5445108bf53b5eae121b2aed34f4f`，版本 `v3.0.0-local-test`；22 份原页面资源字节保持且全部嵌入。本轮没有前端源码修改，不重复构建页面。

首次广泛回归的隔离 PG 中途退出，留下 EOF 和后续连接失败；该次不计通过。随后限制临时库 WAL、捕获服务日志并完整重跑成功。helper 夹具最初缺少工具准备、Docker 挂载范围和 CA 的 CRL 目录；mTLS 夹具最初漏填采集器身份，修正夹具后通过，没有放宽产品检查。CLI 冲突提示改为现有结构化错误类型，避免被全局错误脱敏器隐藏；该处理不修改原 progress 修复。

受控服务启动、公开持久工作器／CLI 完整恢复操作、真实 SSH 与宿主服务管理联合验收仍待完成。TLS 名称转换、CA 换根、真实 systemd／HTTPS 安装恢复、可选 HA 及拓扑迁移、v2 最终增量切换与无损回退、万台／两万台、100 用户、72 小时及独立三机 HA 验收继续作为发布门禁。正式版保持 v2.0.46，完整 v3 不发布，不更新 latest，不操作生产、229、业务 PG 或业务通知。六份原修复与 Git HEAD 保持，最终源码和结果见 `recovery-helper-final-source.json`、`recovery-helper-result.json`。

## 2026-10-20：恢复身份后的精确服务启动

固定恢复工具增加 `start`，只接受与已有十分钟授权及本机 CSR 一致、已经激活的新身份。启动期间持有原信任／身份锁及服务操作锁，核对当前吊销、不可变程序和工具清单、生成配置与服务归属；不激活候选、不启用已禁用服务、不创建或重建容器。native 启动原 unit，Docker 使用已经证明的不可变 ID；已运行对象只复核，启动后再次核对实际状态。主控 SSH 适配器可交付该固定步骤，响应仍不能使恢复任务直接完成。

- `recovery-start-final-layered.log` 与 `identity-recovery.FrTAXP/`：最终源码在实际 Linux amd64 和独立内存 PG 通过 **34 个主控主测试／82 个子项**、实际 Agent／SQLite／YARA 分层 **8 个主测试／48 个子项**、证书库 **47 个主测试／129 个子项**，无失败或跳过。服务管理在分层用例中明确模拟。覆盖已激活与 CSR 绑定、错误归属、停用、损坏程序、启动失败／未运行／启动后漂移、当前吊销、重复响应及锁。独立测试容器和网络已按归属清理。
- `recovery-start-final-local-race.log`：最终本机 helper、恢复、安装归属及证书相关竞态测试通过；`recovery-start-pki-locks.log` 单独验证启动回调持有信任／身份锁，失败后释放锁且不修改身份。最终本机和 Linux 相关包 vet 见 `recovery-start-final-vet.log`、`recovery-start-final-linux-vet.log`。
- `recovery-start-final-native-kernel.log`：真实 x86_64 内核、systemd、cgroup、Agent、SQLite 通过 **1 个主测试**，120.62 秒；恢复已停止服务后，以全新连接的真实 mTLS 对端核对新证书，保留原未确认事件、新事件与旧私钥历史。重复启动请求保持实际 PID；之后原有回退和事件导出继续通过。无外部网卡、无服务管理替身。证书签发和恢复调用由隔离夹具进行，尚未与主控恢复工作器／SSH 联合。
- `recovery-start-go-all.log`：本轮全包 `go test ./...` 通过，nodeops 337.851 秒；运行开始于最后增加启动参数长度／规范路径检查及 Linux 新事件断言之前。最终参数检查已由上述最终本机竞态、Linux 分层和最终 native 内核重跑覆盖，不把较早全包结果算成不同源码的全量运行。
- `recovery-start-embed-proof.json`：最终本地 Linux CLI SHA256 `92f507b69279a3abdc0c873b9069b61ea57e503a4ee85d30a8382f7dabe73b92`，22 份既有页面资源保持字节且全部嵌入。没有前端源码修改，不重复页面构建。

初轮 native 内核测试另通过 121.68 秒，尚未加入新事件断言，不替代最终结果。其独立旧 guest 磁盘在保留 SHA256 及全部日志后删除，只回收本轮重复测试资料。最终两次 guest 也在全部断言通过并关机后保存磁盘 SHA256、日志、输入清单及最终 CLI，再删除本轮磁盘以回收实际紧张的本地空间，详见 `recovery-start-kernel-evidence.json`；其余既有验证资料与无关容器未清理。

本轮仍不构成公开的完整恢复操作。持久工作器／CLI、实际 SSH 与服务管理联合验收、TLS 名称转换、CA 换根、完整主子控 HTTPS／systemd 安装恢复、可选 HA 安装及拓扑迁移、v2 最终增量切换及无损回退、万台／两万台、100 用户、72 小时和独立三机 HA 验收仍为发布门禁。正式 v2.0.46、latest 和生产不变；不访问生产、229、业务 PG、SMTP 或飞书，六份原修复及 Git HEAD 保持。

最终 Docker 内核补验：`recovery-start-final-docker-kernel.log` 的 **1 个主测试**通过，306.95 秒，无失败或跳过。实际专用引擎完成安装、升级、资源与内核检查，恢复后保留原／新事件及私钥历史；重复请求保持原容器 ID、PID、启动时间和重启次数，随后真实回退与事件保留断言通过。初轮未加入新事件断言的同类用例另通过 330.73 秒，不能替代最终结果。最终 native／Docker 日志和输入摘要集中保留于 `.cache/verification/v3/recovery-start-kernel-evidence/`，实际测试容器均已退出并按归属移除；测试签发仍为隔离夹具，未声称完整 SSH 与主控工作器联验。

最终 CLI 已保存到 `.cache/verification/v3/recovery-start-webscan`，真实禁网运行 `version` 为 `v3.0.0-local-test`。最终源码清单见 `recovery-start-final-source.json`，结果与剩余恢复边界见 `recovery-start-result.json`。尚需处理授权在激活后、启动／确认前过期时的新授权接管及完整恢复资源／扫描验收，详见 [PKI 边界](V3-PKI.md)。保持完整 v3 发布门禁。

## 2026-10-20：已换证身份在新授权下继续恢复

固定工具新增 `reconcile`，适配签发后但激活结果未知的中断。未激活时复用原 CSR；已激活时以当前新私钥在独立签名域证明新授权，保持原续期请求及发行回执不变。原 `prepare`、普通 TLS 和在线续期保持严格校验，续作证明不能申请另一张证书。主控接纳、回放、激活及启动均核对原公开回执；原密钥历史、安装种子和 CA 私钥不是续作依赖，不增加数据库 schema。

- `recovery-continuation-layered.log` 与 `identity-recovery.V2PT2r/`：实际 Linux amd64、独立内存 PG 的 **36 个主测试／90 个子项**，Agent／SQLite／YARA 分层 **10／57**，证书库 **50／157**，全部通过，无失败或跳过。新增覆盖新授权下原回执重用、无账本／不同证书／CSR／有效期拒绝、旧授权及租约失效、续作后账本丢失不得补签、真实固定指纹 SSH 传输和无 CA 私钥回放。服务管理仍为明确替身，不能计为完整 SSH＋systemd／Docker 验收。
- `recovery-continuation-race-final.log`：在系统私有临时目录串行完成 nodepki 与 nodeops 相关竞态回归，分别 **13.490 秒、24.528 秒**通过。旧授权实际时间边界由 PKI 测试使用明确传入时间跨越；未声称 PG／SSH 联测等待了十分钟。
- `recovery-continuation-vet.log`、`recovery-continuation-linux-vet.log`：相关三包本机及 Linux amd64 `go vet` 通过；`git diff --check`、内核脚本语法检查通过。
- 真实内核测试已新增等待短期授权实际到期、拒绝旧启动请求、重新授权后继续启动及原／新事件保留断言，但此次准备失败，**未启动 guest，native／Docker 新断言尚未验收通过**。记录见 `recovery-continuation-native-failed-preparation.json`。保留失败阶段文件、构建产物、镜像 ID 和磁盘摘要，仅删除本轮生成的未启动磁盘、解包树及重复输入副本。
- `recovery-continuation-race.log` 留存首次并行回归因临时盘不足而失败；`recovery-continuation-race-retry.log` 留存迁往外置盘后安全路径检查拒绝的失败，原因是挂载点允许组写，不降低生产安全校验。最后在系统目录串行通过，前两次不计为成功。
- Docker 随后报告底层存储只读，创建独立、禁网、只读测试容器也失败。未重启引擎或清理无关容器；唯一未清理干净的本轮准备容器为 `webscan-v3-guest-prepare-kernel-lifecycle.qMRV6K`（dead），删除失败原因已存入该运行的 `cleanup.log`。需恢复本机 Docker 后清理该自有容器并补验。
- 内核脚本新增空间门槛，在构建或创建容器前要求临时卷至少 4 GiB（native）／6 GiB（Docker），以覆盖导出、解包、磁盘填充峰值及预留。`recovery-continuation-kernel-space-guard.log` 验证空间不足时提前退出，无容器操作。不以稀疏盘逻辑大小冒充可用空间。

本轮没有前端修改，不重复构建；未完成本轮全包重跑或新的实际内核验收。公开持久恢复工作器／CLI、实际资源和扫描验收、CA／SAN 转换、完整安装、HA 与迁移、万台容量及 72 小时验收仍未完成，保持完整 v3 发布门禁。正式版、latest、Git HEAD 及六份原修复不变；未连接生产、229、业务 PG、SMTP 或飞书。


## 2026-10-20：宿主恢复执行器、实际资源核验与健康确认

本轮连接了持久恢复任务的宿主 root CLI：准备、执行、取消和只读状态。执行器按准备→激活→原服务启动→实际资源→mTLS 健康确认顺序运行；各阶段复核原账号、节点配置、运行快照、凭据和签发租约。续租仅延长尚未过期的同一 owner／epoch，失败取消正在执行的远端工作，不重新抢租复活。进度只输出阶段及公共任务标识；完成状态必须来自最终事务，不能由 SSH 回执或模拟运行器的 nil 返回替代。

节点新增固定 `verify`：在已有锁及当前身份校验中检查 saved resource policy，复用 systemd／Docker 与 `/proc`、cgroup 的实际 CPU、内存、文件句柄和进程归属校验，不修改服务。主控以新的正常 mTLS 连接核对精确已签证书和能力，再在同一认证连接读取最新健康指标，验证实际文件覆盖、规则、心跳和已启用扫描器。未知、过期、重复或带标签的健康标量不能通过；旧坏样本不会盖过更新的健康样本，旧健康样本也不能掩盖最新异常。

- `recovery-runner-controller-final-race.log`：原生隔离 PostgreSQL 17.6 上 **51 个主测试／181 个子项**通过，启用 Go race，无失败或跳过。覆盖新 CLI 的私有输入／权限／历史状态、完整执行顺序、提交后响应丢失重放、资源失败、输出失败、账号失权、租约失效，以及真实 SSH 和真实 gRPC mTLS 的分层断言；同时回归普通证书续期、部署 SSH 和健康规则。真实 10 秒续租检查会取消阻塞中的模拟远端启动。模拟运行器只证明编排，SSH 测试服务模拟远端命令，测试 gRPC 服务也不是实际运行的 Agent。
- `recovery-runner-nodeops-final-race.log`：本机节点恢复 **8 个主测试／94 个子项**及 race 通过，无失败或跳过。新增 2 种部署方式 × 2 种 cgroup × 10 个实际资源证据场景；使用私有真实配置／PKI／日志，但服务管理器和内核文件明确模拟，不能计为真实 systemd 或 Docker 验收。
- `recovery-runner-local-vet.log`、`recovery-runner-linux-vet.log`：controlplane、nodeops、nodepki 的本机和 Linux amd64 vet 通过。Linux 主控／节点测试程序和 CLI 均编译成功；未执行这些新增 Linux 二进制。`recovery-runner-embed-proof.json` 保存 CLI SHA256 `5b598486b74a29310a64348952d6d9519bc8e6402a21fece58a6629a291ae7fb`；22 个既有页面资源字节保持且全部嵌入，无前端源码变化，不重复构建。
- 内核恢复用例已接上实际 `verify` 及不改变 PID／容器状态断言，**本轮未执行新内核断言**。Docker 存储仍不可写，未获授权重启；原 dead 准备容器保持待清理。现有内核脚本空间前置门槛及两个验证脚本语法通过，不将编译当作运行验收。

本机系统卷仅约 130 MiB 可用，第一轮节点测试因 ENOSPC 失败，保留 `recovery-runner-nodeops-test.log`。为继续隔离验证，在外置盘创建本任务专用 APFS 测试镜像，挂载于 `/private/tmp` 的私有目录，未修改原磁盘／挂载点或放松产品安全校验；镜像使用 noowners 挂载，在当前运行账号下创建 0700／0600 测试资料，不能作为 Linux root 所有权的额外证明。镜像和挂载资料见 `recovery-runner-test-volume.json`。

独立 PostgreSQL 来自官方 17.6 源码及官方 SHA256 校验，编译在本任务缓存，无全局安装，监听仅 127.0.0.1:65279；每个测试创建并移除独立 schema。构建／运行配置及日志保留在 `postgres17-build/`，没有使用业务 PG。初轮控制器测试还因直接运行测试二进制时工作目录错误而读不到仓库夹具；后续改为包目录执行。两处账号字段夹具和一处失权后错误使用受保护查询的断言也已修正，失败日志保留；上述最终日志为修正后的成功结果。未完成本轮全包回归，不把此前全包通过当作新源码全包结果。

剩余门禁：真实 SSH＋主控执行器＋Agent＋systemd／Docker 完整联合恢复，CA／SAN 变更，完整安装及恢复、可选 HA／拓扑迁移、v2 最终增量切换／无损回退、万台／两万台、100 用户、72 小时和独立三机 HA。正式版仍为 v2.0.46，不发布部分 v3、不更新 latest，不访问生产、229、业务通知，不提交 Git。六份原修复和 HEAD 保持；最终源码及阶段结果见 `recovery-runner-source.json`、`recovery-runner-result.json`。


## 2026-10-20：节点名称变更的本机 CSR 与重叠证书

新增独立限时授权、规范公开请求、本机 CSR／私钥持久化、受 CA 锁约束的签发回调，以及当前持久 CRL 下的原子激活。普通续期函数和消息格式未修改，普通续期不能调用名称变更；新能力尚未接入主控任务、签发账本、SSH 工具或配置应用。

- `node-name-change-final2-race.log`：证书库全量 **61 个主测试／225 个子项**及 race 通过，28.285 秒，无失败或跳过。覆盖 DNS／IPv4／IPv6、期限和精确授权、独立签名域、CSR 越权、公有请求无私钥、受管理资料与权限／链接、当前吊销、实际过期 CRL、错误候选范围／主体／用途、并发与丢失响应、锁等待取消及取消提交。旧续期、恢复、吊销和实时身份测试也通过。
- 同一日志的 `TestNodeNameChangeActualMTLSKeepsListenerAndBothNames` 使用实际回环 TCP 和双向 TLS：原身份只能验证旧名称，新身份无需更换监听器即可验证旧名称、新名称及原 IP。检查正常 CA 信任、SPIFFE 身份、用途、CRL 和主机名，不使用跳过 TLS 验证选项。不计为实际 Agent 或主控部署联测。
- `node-name-change-local-vet.log`、`node-name-change-linux-vet.log`：相关三包本机和 Linux amd64 vet 通过；Linux CLI 和 PKI 测试二进制编译成功，未执行新增 Linux 二进制。既有 22 个页面资源保持并嵌入，未修改前端源码。
- 初次构建曾因待补的 TLS 测试导入和错误测试辅助函数名失败，已修正。`node-name-change-initial.log` 和 `node-name-change-race.log` 为阶段成功结果；最后增加候选证书范围用例时，解析证书中的 `RawSubject` 使测试重签时忽略修改后的 Subject，导致该夹具意外签回原主体。修正为清空 `RawSubject` 并按用例隔离后，上述最终全量回归通过；保留该失败的 `node-name-change-final-race.log`，不计为成功。新产品校验未因此放松。

本轮系统卷空间恢复到约 12 GiB，但 Docker 守护程序实际查询仍返回 `Docker Desktop is unable to start`，因此未运行容器／真实内核验收，未擅自启动或重启 Docker。测试在系统私有临时目录运行，未修改外置卷权限或产品安全规则；没有启动数据库、连接生产／229、SMTP 或飞书。

后续必须将本机原语接入保存配置绑定的持久名称变更任务、共享唯一发行账本及普通续期互斥、固定指纹 SSH、授权到期后的重授权核对、配置下发和无损回退，再验证实际 Agent／systemd／Docker。CA 换根、完整安装、HA／拓扑迁移、v2 最终切换及回退、万台／两万台／100 用户／72 小时及独立三机验收保持原发布门禁。本轮未重跑 Go 全包，不把证书库范围扩成整个项目验收。正式版与 latest 保持 v2.0.46，不提交 Git；最终源码与结果见 `node-name-change-source.json`、`node-name-change-result.json`。


## 2026-10-20：名称变更的持久授权、签发去重与确认事务

schema 33 保存独立原运行／已保存目标快照、管理员及节点版本、限时挑战和加密 SSH 凭据引用／内容证明。名称变更与普通续期共用后继唯一账本和节点签发租约，并显式区分请求类别；已提交证书才能交付。配置编辑、部署／预览、绑定、恢复和普通续期加入相同互斥。新增公开证书核对函数用于首次签发、回放和本机激活，避免已保存证书绕过精确 CSR／SAN／用途检查。

- `node-name-change-registry-final2-race.log`：隔离 PostgreSQL 上 **9 个主测试／49 个子项**及 race 通过，35.305 秒，无失败或跳过。覆盖并发重复、同一父证书普通／名称签发互斥、下一次正常续期、凭据封装轮换、目标／原快照漂移、失权／版本／租约／吊销、拒绝未授权公开请求、审计／提交失败及签发等待后实际授权到期。延期触发器通过独立序列证明到期用例确实进入签发路径，失败事务不返回或保留新发行。
- 同一专项包含数据库一致性备份／恢复，schema 32 无备份拒绝、备份失败停止及原普通续期记录升级后精确回放；确认事务覆盖原证书、到期、失权、错误目标、租约、吊销及延迟提交失败。完成只解除证书任务占位，不发布目标配置。此处使用存储层证书对象，**不是实际 Agent 连接证明**。
- `node-name-change-registry-related-race.log`：相关控制器回归 **170 个主测试／381 个子项**通过，304.984 秒，无失败；**1 个低磁盘主测试跳过**，其要求独立限额 tmpfs，禁止填满宿主磁盘。覆盖名称变更基础接入、原恢复／续期、数据库备份迁移、配置恢复、部署运行快照及启动运行配置。该批编译后增加了确认事务及名称分支的输入绑定，最终新增范围由上述 final2 专项单独通过；不将早先编译的测试当成最终新增代码的全量运行。
- `node-name-change-registry-pki-race.log`：证书库全量 **61 个主测试／225 个子项**及 race 通过，28.852 秒，无失败或跳过，包含实际同一回环监听器的正常双向 TLS／名称验证。没有因此声称完成真实 Agent、固定 SSH 或 systemd／Docker 名称切换。
- `node-name-change-registry-local-vet.log`、`node-name-change-registry-linux-vet.log`：相关三个包本机和 Linux amd64 vet 通过。最终 Linux CLI、controlplane 和 nodepki 测试程序编译成功，**未运行新增 Linux 二进制**。22 个既有页面资源保持并嵌入；没有前端源码变更，不重复 Vite 构建。构建与嵌入证据见 `node-name-change-registry-embed-proof.json`。

首轮名称专项通过后，新增互斥夹具误用了自造采集租约名称，得到预期外的“采集租约已失效”；已改用产品既有 `shardResource`，未放松租约校验。失败的 `node-name-change-registry-race2.log` 保留，最终上述专项已通过。初轮编译中临时辅助函数名也已修正。

测试仅使用本任务的原生 PostgreSQL 17.6（127.0.0.1:65279），每项独立 schema。没有使用业务数据库、生产／229、SMTP 或飞书；没有启动或重启 Docker。此前未获批准的 Docker 重启不执行，真实内核／容器新验收仍待环境恢复。

尚需连接固定指纹 SSH 名称变更工具、真实对端确认、配置应用／回退、激活后到期重新授权及旧 SAN 裁剪；CA 换根、完整安装恢复、HA／拓扑迁移、v2 最终增量切换与无损回退、万台／两万台、100 用户、72 小时及独立三机验收继续作为正式发布门禁。本轮未跑 Go 全包。正式版与 latest 仍为 v2.0.46，未提交／推送 Git 或发布；六份原修复保持，最终源及阶段结果见 `node-name-change-registry-source.json`、`node-name-change-registry-result.json`。

## 2026-10-20：名称变更固定 SSH 与宿主执行器

本轮在 schema 33 持久授权之上连接固定 SSH 工具、root CLI、续租编排和实际双名称观察；没有新数据库迁移、前端源码改动或生产操作。

- `name-change-ssh-final-race.log`：名称变更控制器专项 **22 个主测试／111 个子项**，85.194 秒，race 通过，无失败或跳过。覆盖原持久授权／签发去重，以及固定发布 helper 校验、正确主机指纹、命令及公开输入回执、伪造／重复 JSON、丢失响应、拒绝失权／版本／凭据／租约／到期后 SSH、任务续作和实等十秒心跳失锁取消。准备命令不签发；状态受账号限制，过期／取消只读，完成 CLI 重放不访问 SSH。
- 同一专项使用**实际回环 gRPC mTLS 握手**，显式测试 Agent 替身报告配置与指标。成功用例观察原／目标两个 SNI、同一精确签发证书，并断言仍使用原活动配置；目标握手拒绝、第二连接配置漂移、错误实际证书、吊销 Collector／节点、租约中途失效、覆盖缺失及过期／重复指标都不能完成。该服务是测试替身，不能计为实际 Agent 或完整安装验收。
- `name-change-ssh-nodeops-race.log`：子控新名称和既有身份恢复相关 **12 个主测试／151 个子项**，104.284 秒，race 通过，无失败或跳过。真实私有文件、PKI 和部署 journal；native／Docker 及 cgroup v1/v2 使用明确的管理器／内核文件替身。原身份历史、不可变配置及数据标记保持，prepare／activate 可精确重放；错误状态不生成新密钥。此处数据标记不等于真实 Agent 事件数据库保留验收。
- `name-change-ssh-pki-race.log`：证书库全量 **63 个主测试／240 个子项**，44.664 秒，race 通过，无失败或跳过。新增已有信任下限的单调推进和持锁只读核验，覆盖吊销／回滚／缺失／到期／取消及回调互斥。包括既有真实回环 TLS 测试，不表示已完成 CA 换根。
- `name-change-ssh-related-race.log`：控制器原身份恢复／续期／PKI／本地准备相关 **64 个主测试／185 个子项**，111.721 秒，race 通过，无失败或跳过，验证新 CLI 分流及共享夹具扩展不改变原业务边界。没有执行 Go 全包。
- `name-change-ssh-local-vet.log`、`name-change-ssh-linux-vet.log`：四个相关包本机和 Linux amd64 vet 通过。Linux CLI 及三个测试程序编译通过；**未运行本轮 Linux 二进制**。`scripts/verify-v3-identity-recovery.sh` 已加入名称专项并通过 shell 语法检查，Docker 脚本本轮没有运行。

首次固定命令测试夹具误写为 `--name-change`，实际受限命令为 `--identity-name-change`；首次重复 JSON 场景未注入重复字段。这两处夹具均已修正，重复字段生产校验保持严格；失败日志 `name-change-ssh-readiness.log`、`name-change-ssh-transport.log` 留存，最终专项全部通过。资源测试后又加强“不执行 create／rm／run／kill／daemon-reload”的断言，最终独立复验见 `name-change-ssh-resource-final.log`。

所有数据库测试使用本任务的原生 PostgreSQL 17.6（127.0.0.1:65279、每项独立 schema），SSH／gRPC 仅回环；无业务 PG、229、SMTP 或飞书访问。未启动／重启 Docker，既有引擎故障不通过放宽环境或安全检查规避。22 个页面资源保持原样并嵌入新 CLI，证据见 `name-change-ssh-embed-proof.json`；六份受保护修复保持。新源清单及阶段结果见 `name-change-ssh-source.json`、`name-change-ssh-result.json`。

仍需名称配置应用／回退、激活后到期的独立重新授权与旧 SAN 裁剪、CA 换根、真实 SSH＋Agent＋systemd／Docker 联合验收、完整安装、可选 HA／拓扑转换、v2 最终增量及保留新增数据回退，以及万台／两万台、100 用户、72 小时和独立三机 HA 验收。完整 v3 尚未达到发布门槛；正式版和 latest 保持 v2.0.46，不提交 Git、不发布、不切换生产。

## 2026-10-20：名称变更到期后的独立授权续作

已签发的名称变更可以通过新的十分钟授权继续。待激活状态由仍有效的父私钥证明，已激活状态由当前后继私钥证明；两者使用独立签名域，保留原请求、CSR 和唯一签发回执。原授权和父证书过期后，已激活身份仍可重新授权；未激活且父证书过期不能使用该路径。历史发行验证与当前 CRL 检查分开，不能把今天的 CRL 按历史时间验证。

- `name-change-continuation-controller-final.log`：隔离 PG 上 **26 个主测试／125 个子项**，race 通过，80.641 秒。补充的目标配置准备、备份恢复见 `name-change-continuation-final-additions.log`，**2／0**，3.814 秒。覆盖新账号／运行代次授权、实际短期授权到期、原回执重放、无旧私钥／CA 私钥、固定回环 SSH reconcile，以及真实双 SNI mTLS；SSH 命令和 Agent 服务仍为明确夹具，不等同完整主子控联合验收。
- `name-change-continuation-pki-race.log`：证书库 **67／265**，46.031 秒；最终新增反例由 `name-change-continuation-pki-final2-extra.log` **4／28**、5.732 秒覆盖。普通签发拒绝续作证明，错误原请求、签名域、过期叶证书／CRL、吊销及错误后继均被拒绝，不生成新密钥或重复发行。
- `name-change-continuation-nodeops-race.log`：节点相关 **13／155**，97.038 秒；`name-change-continuation-related-race.log`：相关控制器 **65／185**，96.606 秒。全部启用 race，无失败或跳过。服务管理和内核证据使用显式替身，不计真实 systemd／Docker 验收。
- 已完成的名称任务可复用现有升级流程准备、预览和排队下发目标名称，不读取原私钥；排队后活动配置仍保持原名称。任务未完成时部署预览和执行受互斥保护。不可变包准备本身不是执行，不把包准备误当配置应用成功。备份恢复保留原任务、续作任务和唯一发行，旧租约不能复活。
- 本机／Linux 相关 vet 通过，Linux CLI 和三份测试二进制编译通过；本轮未执行新增 Linux 二进制、Go 全包、容器或真实内核验收。22 份既有页面资源未修改并嵌入，详见 `name-change-continuation-embed-proof.json`。

初轮控制器断言未适应普通后继冲突提前拒绝；证书反例夹具曾使用不支持的一分钟 CRL；目标准备夹具误把不可变包准备视为执行。三处均修正夹具，严格产品校验未放宽。对应失败日志保留，以上为最终成功结果。数据库仅使用本任务本机 PG 17.6、逐项独立 schema，验证后已停止；没有访问业务 PG、生产、229、SMTP 或飞书，未启动／重启 Docker。

名称目标的实际配置应用／保留新增数据回退、旧 SAN 裁剪、CA 换根、真实 SSH＋Agent＋systemd／Docker 联验、完整安装、可选 HA／拓扑迁移、v2 最终增量切换及回退、万台／两万台、100 用户、72 小时和独立三机 HA 仍为发布门禁。正式版与 latest 保持 v2.0.46，不提交／推送 Git、不发布。阶段源与结果见 `name-change-continuation-source.json`、`name-change-continuation-result.json`。

## 2026-10-20：名称目标配置应用与数据保留回退

本轮沿用现有托管升级和回退流程补齐名称变更后的分层验收，不增加另一套应用协议，不改变生产安装菜单或发布版本。

- `name-change-application-controller-final-race.log`：隔离 PG 的相关控制器 **49 个主测试／164 个子项**，101.617 秒，race 通过，无失败或跳过。名称目标的最终生产租约／信任验证断言见 `name-change-application-controller-target-final.log`，**2／0**，3.627 秒。覆盖不可读取原种子私钥时的准备／预览／排队、目标名称和配置代次的原子发布、旧采集失效、新名称证据门禁，以及回退后原活动配置、保存态目标、三条事件与去重回执保留。远端阶段完成和采集回执为明确夹具，不是实际部署证明。
- `name-change-application-nodeops-final-race.log`：节点相关 **35／130**，83.302 秒，race 通过，无失败或跳过。新用例两种模式均实际执行私有物料准备、完整前驱安装阶段、本机 CSR／重叠身份激活、目标配置激活、真实 SQLite 写入及回退导出，检查精确原安装指针、当前身份和新增未确认事件保留；重放不重复启动。服务管理器、进程和 cgroup 仍为明确替身，不能计为实际 systemd／Docker 验收。
- 新增两个真实 Linux 名称应用／回退用例及内核脚本模式；Linux 测试程序编译通过，本机与 Linux 相关 vet 通过，脚本和内嵌 shell 语法通过。新模式空间保护在任何容器操作前退出。**没有运行新增 Linux 二进制或真实内核／容器测试**，未启动／重启 Docker。

节点测试初轮的 Docker 夹具使用待创建对象的进程信息，并在复用切片反序列化时意外改写旧对象；随后缺少显式物料准备，与该夹具只校验阶段的约定不符。已修正为观察实际运行夹具对象、独立反序列化目标并调用真实准备函数；失败及诊断日志保留，严格产品归属和安全检查未放宽。上表为最终相关回归结果，不把此前 Go 全包结果移用到新测试源码。

本轮没有修改产品 Go 实现或前端源码；22 份既有页面资源及六份受保护修复保持。复用上一阶段相同产品源码构建的 CLI，未声称重新构建或运行；新增测试二进制另存 SHA256。阶段源与结果见 `name-change-application-source.json`、`name-change-application-result.json`。隔离 PG 测试结束后已停止，无业务 PG、生产、229、SMTP 或飞书访问，不提交／推送 Git、不发布或更新 latest。

真实 SSH＋主控工作器＋Agent＋systemd／Docker 联合应用与回退、旧 SAN 裁剪、CA 换根、完整安装、可选 HA／拓扑迁移、v2 最终增量切换及保留新增数据回退、万台／两万台、100 用户、72 小时和独立三机 HA 仍未完成。完整 v3 继续保持发布门禁，正式版仍为 v2.0.46。


## 2026-10-20：独立名称裁剪原语与历史依赖检查

新增独立的本机裁剪协议，不修改普通续期或名称扩展协议。授权绑定原节点／CA／父证书、已应用配置摘要、运行代次、当前名称及精确必保名称，最多十分钟；只允许非空真子集，不能增加名称或移除当前名称。准备复用原本机密钥／CSR，签发仅交付公开材料，激活保留前驱身份并按原 CRL 下限验证。

- `name-pruning-pki-final-race.log`：证书包完整 **77 个主测试／328 个子项**，51.769 秒，race 通过，无失败或跳过。包括独立签名域、伪造 CSR、DNS／IPv4／IPv6 子集、数量上限、过期／吊销、CA 已签但超出授权的证书、损坏／链接／权限、并发重试、锁等待取消及提交回调取消。真实回环双向 TLS 使用同一监听器，验证新握手拒绝被裁剪名称，其他必保名称继续使用精确新身份。
- `name-pruning-controller-final-race.log`：相关名称变更／裁剪与续期控制器 **41／155**，98.963 秒，race 通过，无失败或跳过。最终完整保存态／运行态字段匹配及新增分片／显示名反例见 `name-pruning-policy-final-race.log`，**3／16**，8.425 秒，同样 race 通过、无失败或跳过。真实独立 PG 验证已保存／下发／应用版本一致性、管理员权限、身份登记、当前 CRL、任务冲突、已发行后继、历史快照完整摘要及无私钥只读计算。名称目标应用完成后仍保护原快照名称，不因任务成功就破坏回退。
- PG 用例的已应用状态和额外 SAN 公开登记为明确存储层夹具，名称目标远端阶段和采集回执也是夹具；不计实际 SSH、Agent 或服务管理验收。只读检查不生成授权或任务，不签名、不改变快照／备份引用；当前保留所有历史快照名称，显式历史退役尚待实现。
- 本机和 Linux amd64 的相关 vet、测试程序交叉编译及 CLI 构建通过；**没有运行新增 Linux 二进制、容器或真实内核测试，也没有重跑 Go 全包／前端测试**。前端未变，重新核对 22 份资源的摘要和构建内嵌字节。阶段源码、程序摘要、测试及保护文件证明见 `name-pruning-source.json`、`name-pruning-result.json` 和 `name-pruning-embed-proof.json`。

本轮还没有接入裁剪的持久授权、唯一共享发行账本、固定 SSH、重新授权续作或公开执行入口，不能据此执行生产裁剪。裁剪不是旧证书吊销，也不证明既有连接关闭。CA 换根、完整 SSH＋主控＋Agent＋服务管理联验、完整安装、可选 HA／拓扑迁移、v2 最终增量和保留新数据回退、10,000／20,000 节点、100 用户、72 小时及独立三机 HA 门禁仍未完成。

测试只使用本任务本机 PG 17.6 的独立 schema，结束后已正常停止；未启动／重启 Docker，未访问生产、229、业务 PG、SMTP 或飞书。六份受保护修复和 Git HEAD 保持不变，schema 仍为 33，未提交／推送、发布或更新 latest，正式版保持 v2.0.46。

## 2026-10-20：名称裁剪持久授权与唯一发行账本

新增 schema 34，将内部裁剪授权与普通续期、名称扩展的唯一父证书后继账本连接。完整历史依赖、当前运行／保存配置、账号修订、SSH 凭据证明、独立 intent 及租约每步重新检查；公开证书、任务状态和审计同事务提交。签发等待后再次读取当前 CRL 并以当前时间验证父身份，避免等待期间过期仍返回发行回执。

- `name-pruning-ledger-final-identity-race.log`：当前源码的控制器 **99 个主测试／348 个子项**、369.963 秒，证书库所选名称／续期相关 **32／196**、50.774 秒，race 全部通过，无失败或跳过。这不是证书库全量运行。覆盖裁剪并发回放、普通后继互斥、权限／凭据／配置漂移、吊销、审计与提交失败、实际 SQL 等待后的父证书到期、灾备撤销执行权、旧 schema 迁移及发行账本保留；包括既有名称变更／身份恢复相关回归。
- `name-pruning-ledger-parent-expiry-race.log`：共享签发器当前时间复核专项 **1／4**，22.128 秒，race 通过。SQL 等待与实际短期父证书到期用于普通续期、裁剪的首次发行及回放；没有人工改写当前时间。
- `name-pruning-ledger-management-race.log`：配置应用／保存／恢复／备份、部署、运行快照、迁移等相关控制器 **282／538**，897.246 秒，race 通过，无失败；真实 VictoriaMetrics 和限额文件系统两个主用例因缺少相应独立环境跳过。该批编译包含当前产品修复，不包含后来新增的父证书到期测试；后者由上述当前源码专项覆盖。不是 Go 全包验收。
- Docker 恢复后分别补测两项环境门槛：`name-pruning-ledger-actual-vm-race.log` 的真实独立 VictoriaMetrics＋PG 用例 **1／0**、4.463 秒，race 通过；`name-pruning-ledger-low-disk-linux-retry.log` 使用实际 Linux 静态测试程序和仅 1 MiB 的独立 tmpfs，低磁盘保护通过，未填充宿主磁盘。原批次的跳过记录保留，不改写为当时已通过。
- 本机和 Linux amd64 的 controlplane、nodepki、nodeops vet 通过；Linux CLI 与 controlplane 测试程序交叉编译通过。22 份既有页面资源保持并嵌入，六份原修复保持。程序摘要及嵌入证明见 `name-pruning-ledger-embed-proof.json`。前端源码未变，没有重复前端构建。

PG 授权测试使用本任务原生 PostgreSQL 17.6 的独立 schema；父证书额外 SAN、已应用状态及确认对端是明确存储层夹具。本轮不把确认方法当作实际 Agent、固定 SSH 或服务管理观察。备份恢复取消未完成裁剪任务，保留已完成历史与唯一发行；schema 迁移要求事先一致性备份。

固定 SSH、运行器续租、实际对端观察、到期独立重新授权及显式历史退役尚待接入。所有保留快照仍保护恢复所需名称；裁剪不等于原证书吊销。完整安装、CA 换根、可选 HA／拓扑迁移、最终增量与无损回退、10,000／20,000 节点、100 用户、72 小时和独立三机 HA 验收仍未完成。正式版及 latest 保持 v2.0.46，不发布部分 v3。

## 2026-10-20：Docker 恢复与名称配置的实际内核验收

用户明确批准后重启本机 Docker Desktop、完成系统授权并启用 containerd 镜像存储。已验证实际新容器创建、启动和文件系统写入；没有重置、全局清理或删除原镜像库。原 267 个镜像和原验收标签仍不可见，不能声称原库已全部恢复。任务所需测试镜像按固定来源重建，内核构建复用已校验的同版本 initrd，详情见 [内核说明](V3-KERNEL-VALIDATION.md)。

- 原 native 验收失败被重复确认：`name-change-native-kernel-cause.log`／`kernel-lifecycle.IYoy0U` 的实际校验为 **5.54010051 秒**，全部系统和资源检查成功后返回 `context deadline exceeded`。根因是只读主机验收错误复用五秒证书发布预算；不是服务未启动或资源限制缺失。`name-change-verification-budget-before.log` 另以真实等待 5.1 秒复现该误判。
- 修复只读验收预算为现有工具的三十秒上限，将有效 context 交给实际核验；较早的请求期限、取消、授权到期及原锁顺序继续生效。外部命令保留固定错误，内部保留取消原因以供诊断。证书发布、服务归属、摘要和内核资源检查没有放宽。
- `name-change-verification-final-pki-race.log`：名称变更／裁剪证书相关 **29 个主测试／176 个子项**，55.635 秒，race 通过，无失败或跳过。新增回归包括五秒以上的有效检查、调用期限／取消、实际授权到期、锁等待及身份不变。独立上下文专项见 `name-change-verification-context-race.log`，**1／5**，5.449 秒，同样通过。
- `name-change-verification-budget-race.log` 中 nodeops 分包 **14／157**，108.343 秒，race 通过，无失败或跳过；包含两种方式的名称应用和身份恢复回归，管理器／内核为明确夹具。该命令的 nodepki 分包因新增到期测试使用了早于新 intent 的夹具时间失败，修正测试时间后由上列最终证书批次完整通过；不把原整条命令描述成成功。
- `name-change-native-kernel-fixed.log`／`kernel-lifecycle.lhsiLu`：**TestNativeSystemdKernelNameChangeApplicationAndRollback**，162.41 秒，实际 Linux／systemd／Agent 完整通过，无失败或跳过；guest 标记和宿主脚本退出均为 0。名称只读验收 **5.50085188 秒**，新旧名称使用正常全新 mTLS 连接，名称切换保持原进程；目标配置应用后实际回退，核对当前重叠身份及未确认事件保留。无网卡虚拟机中的 YARA 为无害测试规则，ClamAV 未启用。
- Docker 初轮 `name-change-docker-kernel-fixed.log`／`kernel-lifecycle.1vExAF` 在准备阶段失败，未计通过。Docker 29/containerd 的 `image.Id` 实际为清单摘要，原测试脚本误用为配置摘要；归档中的真正配置为 `c7b76b…cf3f`，严格产品校验因此正确拒绝。三个验收脚本现共用只读元数据解析器，从归档读取并核对配置 SHA256，不从 `Id` 猜测。`name-change-image-fixture-tests.log` 的两个主用例覆盖经典／OCI 两种布局及九个拒绝情形，通过。
- `name-change-docker-kernel-corrected-fixture.log`／`kernel-lifecycle.7RpzEm`：**TestDockerKernelNameChangeApplicationAndRollback**，385.45 秒，实际 Linux 内核及 Docker 27.5.1 子控通过，guest 标记为 0；核对名称变更、实际资源限制、配置应用、回退和事件保留。此结果不覆盖 Docker 29 子控。
- Docker 29.8.1 的 containerd 镜像库实测不能通过已签名配置摘要 `sha256:c7b76b…cf3f` 执行 `docker image inspect`，而同一镜像的 `Id` 是清单摘要。`TestDockerContainerdManifestIDIsNotTreatedAsSignedConfig` 验证当前代码不会将清单摘要误作配置摘要；完整兼容仍须同时解决归档加载、不可变启动引用、容器归属与回退校验，不能直接放宽校验。
- 本机和 Linux amd64 的相关 vet、shell 语法及格式检查通过；Linux CLI 已在上述 native 内核中执行。22 份页面资源未变并核对嵌入；不重复前端构建。

真实内核用例使用本地签发，不包含 PG 发行账本、固定 SSH 与服务管理的完整联合流程，不代替启用 ClamAV 的安装验收。内层引擎为 Docker 27.5.1；外层 Docker 29 导出材料修复不等于目标节点 Docker 29 身份／离线导入兼容已验收，此项继续列为待验证。schema 保持 34，没有启动业务数据库或接触生产、229、SMTP／飞书；六份原修复保持，未提交／推送 Git 或发布。完整 v3 继续保留裁剪执行器／重新授权／历史退役、CA 换根、完整安装、可选 HA／拓扑迁移、最终 v2 增量切换／无损回退及容量／稳定性发布门禁，正式版和 latest 保持 v2.0.46。

## 2026-10-29：Docker 29 镜像身份兼容准备

本机 Docker 29.8.1 的 containerd 镜像库存量 Agent 镜像中，`image inspect` 的 ID 与归档 OCI 清单摘要一致，配置摘要不同；对同一镜像创建的隔离、未启动容器，其 `.Image` 也记录清单摘要。验证后只删除本次临时容器。此为本机引擎的身份观察，不等同 Linux amd64 子控安装验收。

节点归档解析新增经归档摘要、配置、平台和 OCI 元数据校验后返回清单摘要的内部能力；旧式归档返回空值。错误、损坏归档或尾部异常不会返回摘要，成功后文件回到开头。`TestImageArchiveManifestIdentityRequiresCompleteValidation` 与现有归档及镜像身份测试通过 race；该能力尚未连接镜像加载、Compose、容器归属或回退，Docker 29 部署兼容仍未完成。不能把清单摘要单独视为注册表来源证明，发行签名和归档绑定仍须共同校验。

此前 `/private/tmp/webscan-v3-kernel-20261020/` 下的临时虚拟磁盘当前已不存在；工作区内两项内核测试日志仍在。后续若需复验，须重建隔离测试目录，不将不存在的虚拟磁盘当作现有证据。
