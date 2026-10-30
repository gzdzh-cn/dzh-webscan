# v3.0.0 单中心安装与升级

本版交付单中心、主动采集及网页节点维护。Linux amd64、root SSH；主控及子控默认 Docker，native 子控可选。高可用、万台认证、桌面与 Android 客户端不在本次范围。旧 v2 数据不自动迁移，勿使用旧 v2 安装菜单部署 v3。

## 下载与信任

下载本 Release 的 `webscan`、`agent-native.tar.gz`、`agent-image.tar`、`release.json`、`release.sig`、`signing.pub`、`SHA256SUMS`、`SHA256SUMS.sig`、`rules.yar` 及安装请求示例。先执行 `sha256sum -c SHA256SUMS`；只下载部分附件时，单独核对对应的清单行。

发布公钥 DER SHA256：

```
0ea843c3994b7e904ee1061d5b8159420b90592a348453e7eb857097a8b859af
```

通过独立可信渠道确认该指纹后再信任公钥；不能因为公钥与程序放在同一个包中就直接信任。可用 `openssl pkey -pubin -in signing.pub -outform DER | sha256sum` 核对。

确认公钥可信后，先验证清单签名，再核对文件：

```bash
openssl pkeyutl -verify -rawin -pubin -inkey signing.pub \
  -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c SHA256SUMS
```

在主控上以 root 创建 `/opt/webscan-v3/release/`、`/opt/webscan-v3/trust/` 和 `/var/lib/webscan-v3/`，目录权限 0700。将程序、包、清单、签名、规则和示例请求放入 release 目录，公钥放入 trust 目录；文件权限 0600，`webscan` 权限 0700。这些目录和祖先不能是符号链接或允许其他账号写入。

```bash
/opt/webscan-v3/release/webscan release-v3 --action verify \
  --public-key-file /opt/webscan-v3/trust/signing.pub \
  --manifest /opt/webscan-v3/release/release.json \
  --signature /opt/webscan-v3/release/release.sig \
  --helper /opt/webscan-v3/release/webscan \
  --native-bundle /opt/webscan-v3/release/agent-native.tar.gz \
  --image-archive /opt/webscan-v3/release/agent-image.tar
```

必须看到 `artifacts_verified: true`、`image_archive_verified: true`。

## 全新单中心

本机须已有可用 Docker、Compose 和 systemd；配置有效 HTTPS 反代，工具不修改 Nginx 或防火墙。`single-install-request.example.json` 已固定本版中心、PG17、VictoriaMetrics 摘要；修改 `public_url`，确认数据根目录尚不存在以及回环端口 19444、15432、18428 未占用。不要删除占用端口的业务服务。

请求文件保持 0600，保存为 `/opt/webscan-v3/release/install.json`。自行创建 0600 的 `/opt/webscan-v3/release/first-password`，保存初始管理员密码，不把密码放入命令参数、Git 或日志。

```bash
/opt/webscan-v3/release/webscan control-v3 --action preview-single-install \
  --source /opt/webscan-v3/release/install.json

/opt/webscan-v3/release/webscan control-v3 --action install-single \
  --source /opt/webscan-v3/release/install.json \
  --password-file /opt/webscan-v3/release/first-password
```

中断后使用原请求、原程序执行 `resume-single-install`，不能生成新 Vault 或覆盖已有安装资料。安装器检查磁盘、端口和镜像身份；失败保持检查点，不把单纯文件写入当作安装成功。完成后将预先准备的 HTTPS 反代指向回环 API，验收登录、采集及能力接口。

## 添加与升级子控

主控部署执行器须能 SSH 连接子控。主控主动访问子控 TCP 19100（mTLS），不要求新子控向公网主控推送；SSH 使用实际端口。仅允许实际主控采集源访问 19100，同时检查云安全组、系统防火墙和宝塔防火墙。

网页输入节点、凭据，读取并确认首次 SSH 指纹，再保存并部署。已安装节点可独立升级；独立升级使用已保存配置，不保存弹窗草稿。任务创建后进入日志；失败使用原任务继续或回退。普通子控操作不重启主控。

## 已有试运行中心升级

不要直接套用全新安装请求。使用本版 `preview-single-web-upgrade`、`prepare-single-web-upgrade` 生成独立 overlay，保留原 Vault、CA、PG、时序库和不可变安装记录。先一致性备份并完成数据库迁移，再仅替换中心应用与宿主执行器。详细字段和维护顺序见源码 `docs/V3-SINGLE-INSTALL.md` 的“已有单中心升级模板”。不得通过重新生成 Vault 修复已有密文。

## 备份与边界

一致性保存 PostgreSQL、VictoriaMetrics 数据、原安装资料、Vault 及旧密钥、authority、collector-pki、state 与发布信任资料；不能只保存 YAML。发布签名私钥不下发。旧主控保留数据继续保留，后续迁移另行核对。

本次测试不连接业务飞书或邮箱。真实 Linux native/Docker 29 联合生命周期已单独验证；单中心容器安装测试中 systemd 激活为模拟，不能宣称已完成真实主机重启认证。最终产物和验收范围见 `acceptance.json`、`images.json` 和 `build-info.json`。本次发布不自动升级生产环境。
