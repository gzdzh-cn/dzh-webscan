# v3 发布签名与独立凭据密钥

本地实现已提供离线密钥初始化、发布清单签名、独立公钥校验和部署信任配置检查。它们不连接 PostgreSQL、SSH 或镜像仓库，不启用安装器，不发布文件，也不修改生产信任配置。完整 v3 的网页、安装、迁移与高可用仍未完成，当前发布版本保持 v2.0.46。

## 三种密钥分工

| 资料 | 用途 | 保管位置 |
|---|---|---|
| Ed25519 发布签名私钥 | 签名工具、native 包及镜像身份清单 | 独立的发布端；不下发主控或子控 |
| 发布验签公钥 | 主控校验发布清单 | 管理员通过独立可信渠道预置；不能采用下载包自带公钥 |
| AES-256 凭据主密钥 | 加密 PostgreSQL 中的 SSH 凭据 | 主控独立私有文件；不放入数据库备份或 YAML 内容 |

节点／采集器的 mTLS 证书由另一套 CA 管理，见 [证书工具](V3-PKI.md)，不能用发布签名密钥替代。

## 本地命令

以下示例适用于独立 Linux 测试环境。父目录必须已存在、属于当前运行账号且为 `0700`；所有路径使用绝对规范路径，拒绝任一层符号链接。Mac 应使用真实路径，例如 `/private/tmp/`，不要使用 `/tmp` 或 `/var` 别名。

```bash
install -d -m 700 /tmp/webscan-v3-trust-lab

# 两种初始化都只接受一个全新的输出目录；已有资料绝不覆盖。
webscan release-v3 --action init-key \
  --output /tmp/webscan-v3-trust-lab/signing
webscan vault-v3 --action init-key \
  --output /tmp/webscan-v3-trust-lab/vault

webscan vault-v3 --action check \
  --key-file /tmp/webscan-v3-trust-lab/vault/vault.key
```

发布私钥为标准 PKCS8 PEM，公钥为 PKIX PEM；分别保存为 `signing.key`、`signing.pub`。凭据主密钥是 32 字节随机数的十六进制文件 `vault.key`。目录 `0700`、文件 `0600`，整个新目录通过同文件系统不可覆盖的原子重命名发布。并发初始化只有一次成功；中断、写入失败或目标已存在不能覆盖旧资料。输出只含算法与公钥摘要／密钥 ID，不含密钥值。

## 生成与签名发布清单

先在受控构建流程完成程序包功能测试，再将工具和 native 包放入私有目录。工具／归档文件需属于运行账号、无额外硬链接且只有所有者有权限；签名前将编译工具权限改为 `0700`、归档改为 `0600`。

```bash
webscan release-v3 --action sign \
  --key-file /tmp/webscan-v3-trust-lab/signing/signing.key \
  --release v3.0.0-local-test \
  --helper /tmp/webscan-v3-trust-lab/artifacts/webscan \
  --native-bundle /tmp/webscan-v3-trust-lab/artifacts/agent-native.tar.gz \
  --agent-image 'docker.io/example/webscan-agent:v3.0.0-local-test@sha256:<64位小写摘要>' \
  --output /tmp/webscan-v3-trust-lab/signed
```

`agent_image` 必须包含不可变镜像摘要，不能仅使用 `latest` 或版本标签。新发布使用 `仓库:版本号@sha256:摘要`，其中版本号必须与 `--release` 完全一致；旧版仅含摘要的清单继续兼容。工具最大 256 MiB，native 包最大 4 GiB；大小及 SHA256 从实际文件分块读取，不信任手填摘要。可选 `--image-archive <绝对路径>` 和 `--image-config-sha256 <64位小写摘要>` 必须同时提供，镜像归档最大 4 GiB。

仓库下载使用版本号加摘要；离线导入使用经过核验的本地版本标签，兼容 Docker 经典镜像库及 Docker 29 containerd 镜像库。标签对应其他镜像时拒绝覆盖。创建容器后、启动前仍核对真实镜像 ID，版本名称不能替代签名、归档、平台或配置摘要校验。已有部署的继续和回退保持原引用，不自动改写历史记录。

镜像构建写入 `org.opencontainers.image.version`；发布结果增加 `versioned_images`，原 `images` 摘要字段保留。正式版与试运行版使用各自真实版本，不能把试运行产物重新标成正式版。

输出 `release.json` 与二进制 `release.sig`。清单采用现有严格规范 JSON 和 Ed25519 分离签名，绑定版本、Linux amd64、内部工具协议、文件大小／SHA256、镜像身份及可选离线镜像归档身份。不会把签名私钥、公钥或凭据放进发布目录；不会下载镜像、自动打标签或上传 GitHub。

签名证明指定字节来自可信发布者，不代表 ELF、规则、病毒扫描能力或镜像语义已验收。安装阶段仍必须验证包结构、平台、扫描工具、镜像配置及实际运行结果。离线归档的配置摘要由发布流水线从已验收镜像取得，节点仍执行归档内容和导入后身份检查。

## 独立校验

```bash
webscan release-v3 --action verify \
  --public-key-file /独立可信渠道预置的路径/signing.pub \
  --manifest /tmp/webscan-v3-trust-lab/signed/release.json \
  --signature /tmp/webscan-v3-trust-lab/signed/release.sig \
  --helper /tmp/webscan-v3-trust-lab/artifacts/webscan \
  --native-bundle /tmp/webscan-v3-trust-lab/artifacts/agent-native.tar.gz
```

只提供公钥、清单、签名时，仅验证清单，结果 `artifacts_verified=false`。同时提供工具和 native 包后才核对两个实际文件；增加 `--image-archive` 才核对该归档，并报告 `image_archive_verified=true`。两种结果均不会声称已安装或启用执行器。信任公钥和已签名元数据可为只读公开文件，但不能让其他账号修改，不能采用符号链接、FIFO 或额外硬链接。

## 主控部署信任配置

`webscan-v3.yaml` 可增加以下段落。未配置时兼容已有本地验证配置；一旦配置，必需字段必须完整。这里保存路径，不保存密钥内容。

```yaml
deployment_trust:
  vault_key_file: /etc/webscan-v3/vault/current/vault.key
  previous_vault_key_files: [] # 最多 8 个，不得重复密钥
  release_public_key_file: /etc/webscan-v3/trust/signing.pub
  release_manifest_file: /opt/webscan-v3/release/release.json
  release_signature_file: /opt/webscan-v3/release/release.sig
  helper_file: /opt/webscan-v3/artifacts/webscan
  native_bundle_file: /opt/webscan-v3/artifacts/agent-native.tar.gz
  # image_archive_file: /opt/webscan-v3/artifacts/agent-image.tar
```

```bash
webscan control-v3 --config /绝对路径/webscan-v3.yaml \
  --action check-deployment-trust
```

检查严格验签、工具／native 包摘要及大小、可选归档、当前和旧凭据密钥权限及格式。没有数据库 DSN 文件或数据库不可达时仍能独立运行；不会生成缺失的公钥或密钥。成功报告明确包含 `executor_enabled=false`，只表示本检查命令没有启动执行器。公开网页流程的实际可用性由能力接口和宿主工作器心跳决定，见 [网页部署与凭据](V3-WEB-DEPLOYMENT.md)，不能从离线检查结果推断在线部署已关闭或已就绪。

## 备份与轮换边界

签名私钥、凭据主密钥、旧凭据密钥和 mTLS CA 私钥均需分别备份，不包含在 PostgreSQL 业务备份里。丢失凭据主密钥后无法解密对应 SSH 凭据。不要在工单、URL、命令参数或 Git 中放密钥值。

轮换先用新目录创建密钥，保留旧文件；内部 `OpenVault` 可同时加载当前和最多 8 个旧密钥，拒绝同一密钥重复配置，内部 `RewrapCredential` 可逐条重新加密。网页、生产初始化向导、完整轮换任务与旧备份依赖清点尚未接入；不能仅删除旧密钥就当作轮换完成。发布公钥的分发、撤销和切换也必须经过独立管理员流程，本工具不会自动信任新公钥。
