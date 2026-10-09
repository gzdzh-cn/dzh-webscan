# 文件监控规则

[返回 README](../README.md) · [SH 安装](INSTALLATION.md) · [网站后台](WEBSITE.md) · [日常维护](OPERATIONS.md)

## 目录、后缀与忽略规则

### 公共配置与节点配置的关系

`node_defaults` 是所有子服务器的默认配置。每个 `nodes` 条目可以单独填写 `monitor`，覆盖对应的公共参数。

**没有写的参数继承公共设置；列表一旦单独填写，就整体替换公共列表，不会自动追加。** `roots`、`extensions`、`exclude_paths`、`important_filenames` 和 `critical_paths` 都遵循这个规则。

以下 YAML 都是配置片段，要合并进现有文件，保留其他字段；不能用片段覆盖整个文件，也不要重复创建同名顶层配置块。

### 监控多个目录

所有节点共用：

```yaml
node_defaults:
  monitor:
    roots:
      - /www/wwwroot
```

只有 node-29 需要增加 `/data/sites`，就在该节点原有配置中添加：

```yaml
nodes:
  - id: node-29
    # 保留该节点原有名称、IP、SSH 等配置
    monitor:
      roots:
        - /www/wwwroot
        - /data/sites
```

这里仍要写 `/www/wwwroot`，否则该节点只监控 `/data/sites`。每台服务器可以设置不同的多个目录，路径必须是该子服务器上的绝对路径。

### 自定义文件后缀

在公共配置或单节点的 `monitor.extensions` 中填写，例如：

```yaml
node_defaults:
  monitor:
    extensions:
      - .php
      - .phtml
      - .js
      - .html
      - .css
      - .json
      - .txt
      - .vue
```

后缀以 `.` 开头，后面只能是字母或数字，匹配不区分大小写。按最后一个后缀匹配，例如 `archive.tar.gz` 对应 `.gz`；不支持在后缀列表里写 `*` 或 `.tar.gz`。

列表要包含全部需要保留的后缀。上面的示例没有包含所有默认 PHP 后缀，实际修改时请保留现有需要的条目。文件必须在监控目录内，并且没有被忽略规则排除。

### 忽略缓存目录，支持通配符

```yaml
node_defaults:
  monitor:
    exclude_paths:
      - /www/wwwroot/*/**/runtime/**/cache
      - /www/wwwroot/*/caches/temp
```

| 写法 | 含义 |
|---|---|
| `*` | 匹配一个路径段，例如一个网站目录名 |
| `**` | 匹配零层或多层目录 |
| 匹配到目录 | 该目录及其下全部文件、子目录一并忽略 |

第一条忽略各网站中 `runtime` 下不同层级的 `cache` 目录。忽略目录内的 PHP 也不再发送普通文件变化通知。`exclude_paths: []` 表示没有业务路径忽略规则。

不要直接用示例替换已有缓存规则，先确认哪些需要保留。规则必须在监控根目录范围内，不能排除根目录本身或关键文件。单节点改了根目录后，也要检查继承的忽略规则是否仍适用。

### 忽略隐藏文件与目录

在已有 `exclude_paths` 列表中追加，而不是覆盖原有规则：

```yaml
node_defaults:
  monitor:
    exclude_paths:
      # 原有规则继续保留
      - /www/wwwroot/**/.*
```

这会排除 `/www/wwwroot` 下各层级以点开头的文件与目录，隐藏目录下的内容也不再监控。例如 `.htaccess`、`.user.ini` 和 `.git` 都会被忽略；它们可能包含重要网站配置，按实际需求选择。多个监控根目录需要分别写规则，不能用此规则排除已配置的 `critical_paths`。

修改后用下方 `--reload-rules` 生效。详细通配符规则见[参数说明](PARAMETERS.md)。

### 重要文件与关键路径

```yaml
node_defaults:
  monitor:
    important_filenames:
      - .user.ini
      - .htaccess
    critical_paths:
      - /www/wwwroot/example.com/config/config.php
```

`important_filenames` 只写文件名：在监控目录内，即使后缀没列入 `extensions` 也会监控，但仍受忽略规则影响。

`critical_paths` 写完整文件路径：可以位于根目录外，配置校验不允许忽略规则排除这些关键文件。新增根目录外的文件时，如果父目录还没挂载到容器，先更新节点容器。

### 修改后怎么生效

**只编辑 YAML 不会自动下发到子服务器。** 按改动类型执行命令：

| 改动 | 执行方式 | 是否需要更新容器 |
|---|---|---|
| 后缀、忽略路径、重要文件名 | `--reload-rules` | 不重启、不重建 |
| 关键文件路径 | `--reload-rules`，新增挂载时先更新节点 | 已有挂载范围内无需重建 |
| YARA 规则内容 | `--reload-rules --yara-rules 文件路径` | 不重启、不重建 |
| 根目录 `roots` | `--add-node --node 节点ID` | 更新节点容器及挂载 |
| 节点资源、扫描参数、核对间隔、指标端口 | `--add-node --node 节点ID` | 按改动更新节点服务 |
| 主服务器镜像、飞书设置等 | `--upgrade --central-only` | 按改动更新主服务器服务 |

修改公共过滤规则后：

```bash
bash deploy-webscan.sh --reload-rules
```

只修改 node-29 的过滤规则后：

```bash
bash deploy-webscan.sh --reload-rules --node node-29
```

下发自定义 YARA 文件，文件路径在主服务器上：

```bash
bash deploy-webscan.sh --reload-rules --yara-rules /root/php-webshell.yar
```

节点每 5 秒检查规则，先校验再应用；非法规则保留旧版，多节点下发失败时尝试恢复本次已修改的配置。取消忽略后，先为已有文件建立基线，之后的修改正常告警。

热更新要求 GoFrame 部署已完成，YAML 没有同时混入目录、资源、端口等其他待更新项。从 v2.0.18 起，部署工具可以比运行服务更新；YAML 的镜像版本差异不阻止下发规则，也不会升级镜像。配置比较按节点实际继承的参数进行，兼容新增节点时保存的展开配置及自动 SSH 指纹记录。公共规则影响多个节点时，必须更新全部受影响节点，不能只指定其中一台。
