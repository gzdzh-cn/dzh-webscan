export interface Field { path: string; label: string; group: string; type: 'number' | 'text' | 'secret' | 'boolean' | 'lines'; hint: string }
export const fields: Field[] = [
 { path: 'node_defaults.monitor.roots', label: '公共监控根目录', group: '公共监控', type: 'lines', hint: '每行一个绝对路径；添加目录需要更新节点挂载。' },
 { path: 'node_defaults.monitor.extensions', label: '监控文件后缀', group: '公共监控', type: 'lines', hint: '每行一个，例如 .php；可热更新。' },
 { path: 'node_defaults.monitor.important_filenames', label: '重要文件名', group: '公共监控', type: 'lines', hint: '重要文件独立于后缀规则，例如 .htaccess。' },
 { path: 'node_defaults.monitor.critical_paths', label: '必须监控的文件', group: '公共监控', type: 'lines', hint: '每行一个完整路径；忽略规则不能排除它们。' },
 { path: 'node_defaults.monitor.exclude_paths', label: '忽略路径', group: '公共监控', type: 'lines', hint: '每行一个通配规则；隐藏文件也通过规则排除。' },
 { path: 'node_defaults.monitor.reconciliation.interval_hours', label: '清单核对间隔（小时）', group: '公共监控', type: 'number', hint: '至少 1 小时；此参数需要节点部署应用。' },
 { path: 'feishu.enabled', label: '启用飞书', group: '飞书通知', type: 'boolean', hint: '关闭通知仍保留系统异常记录。' },
 { path: 'feishu.webhook_url', label: '飞书 Webhook', group: '飞书通知', type: 'secret', hint: '已有内容不返回；留空保留。' },
 { path: 'feishu.signing_enabled', label: '启用加签', group: '飞书通知', type: 'boolean', hint: '开启后需填写飞书机器人密钥。' },
 { path: 'feishu.signing_secret', label: '加签密钥', group: '飞书通知', type: 'secret', hint: '留空保留已有密钥。' },
 { path: 'feishu.rate_limit.max_per_second', label: '每秒最多消息', group: '飞书通知', type: 'number', hint: '持久化队列按限流发送。' },
 { path: 'feishu.rate_limit.max_per_minute', label: '每分钟最多消息', group: '飞书通知', type: 'number', hint: '避免机器人频率限制。' },
 { path: 'health.metrics_scrape_seconds', label: '采集周期（秒）', group: '指标与告警', type: 'number', hint: '默认 30 秒。' },
 { path: 'health.alerts.node_unreachable_seconds', label: '采集失联持续时间（秒）', group: '指标与告警', type: 'number', hint: '默认 120 秒。' },
 { path: 'health.alerts.cpu_enabled', label: '启用 CPU 告警', group: '指标与告警', type: 'boolean', hint: '默认关闭，启用后使用下方阈值。' },
 { path: 'health.alerts.cpu_warning_percent', label: 'CPU 告警阈值（%）', group: '指标与告警', type: 'number', hint: '默认 85%。' },
 { path: 'health.alerts.cpu_recovery_percent', label: 'CPU 恢复阈值（%）', group: '指标与告警', type: 'number', hint: '须低于告警阈值，默认 80%。' },
 { path: 'health.alerts.cpu_duration_seconds', label: 'CPU 超限持续时间（秒）', group: '指标与告警', type: 'number', hint: '默认 300 秒。' },
 { path: 'health.alerts.memory_enabled', label: '启用内存告警', group: '指标与告警', type: 'boolean', hint: '默认关闭。' },
 { path: 'health.alerts.memory_warning_percent', label: '内存告警阈值（%）', group: '指标与告警', type: 'number', hint: '默认 90%。' },
 { path: 'health.alerts.memory_recovery_percent', label: '内存恢复阈值（%）', group: '指标与告警', type: 'number', hint: '须低于告警阈值，默认 85%。' },
 { path: 'health.alerts.memory_duration_seconds', label: '内存超限持续时间（秒）', group: '指标与告警', type: 'number', hint: '默认 300 秒。' },
 { path: 'health.alerts.disk_warning_percent', label: '磁盘警告阈值（%）', group: '指标与告警', type: 'number', hint: '现有阈值继续沿用。' },
 { path: 'health.alerts.disk_critical_percent', label: '磁盘严重阈值（%）', group: '指标与告警', type: 'number', hint: '持续 60 秒触发。' },
 { path: 'central.monitoring.raw_hours', label: '原始指标保留（小时）', group: '历史与备份', type: 'number', hint: '1～168 小时，默认 48。' },
 { path: 'central.monitoring.history_days', label: '聚合指标保留（天）', group: '历史与备份', type: 'number', hint: '1～90 天，默认 15；减小后将清理超期数据。' },
 { path: 'retention.sqlite_events_days', label: '事件保留（天）', group: '历史与备份', type: 'number', hint: '1～3650 天；有未完成任务的记录继续保留。' },
 { path: 'retention.security_events_days', label: '安全扫描命中保留（天）', group: '历史与备份', type: 'number', hint: '1～3650 天；删除历史不代表风险已解决。' },
 { path: 'retention.website_incidents_days', label: '网站故障历史保留（天）', group: '历史与备份', type: 'number', hint: '1～3650 天；未结束故障保留。' },
 { path: 'retention.server_alerts_days', label: '服务器告警历史保留（天）', group: '历史与备份', type: 'number', hint: '1～3650 天；与指标期限独立，当前异常受保护。' },
 { path: 'retention.delivery_records_days', label: '通知历史保留（天）', group: '历史与备份', type: 'number', hint: '默认 30 天。' },
 { path: 'backup.enabled', label: '启用每日备份', group: '历史与备份', type: 'boolean', hint: '一致性备份事件库与指标库。' },
 { path: 'backup.time', label: '每日备份时间', group: '历史与备份', type: 'text', hint: '格式 HH:MM。' },
 { path: 'backup.keep_days', label: '自动备份保留（天）', group: '历史与备份', type: 'number', hint: '不清理手工配置备份。' },
 { path: 'central.website_monitor.interval_seconds', label: '网站检查周期（秒）', group: '网站检测', type: 'number', hint: '默认 60 秒。' },
 { path: 'central.website_monitor.timeout_seconds', label: '网站检查超时（秒）', group: '网站检测', type: 'number', hint: '默认 5 秒。' },
 { path: 'central.website_monitor.max_concurrent', label: '网站检查并发数', group: '网站检测', type: 'number', hint: '默认 128。' },
 { path: 'ssl.enabled', label: '统一使用 HTTPS', group: '连接与访问', type: 'boolean', hint: '切换协议需要部署主服务器及全部启用节点。' },
 { path: 'central.website_monitor.bind_address', label: '后台绑定地址', group: '连接与访问', type: 'text', hint: '同机反代可使用 127.0.0.1；改变后重建主服务器。' },
 { path: 'central.website_monitor.host_port', label: '后台端口', group: '连接与访问', type: 'number', hint: '默认 19444；请自行放行端口。' },
]
fields.push(
 { path: 'central.name', label: '主服务器名称', group: '连接与访问', type: 'text', hint: '用于列表和通知展示。' },
 { path: 'central.public_url', label: '节点事件公网地址', group: '连接与访问', type: 'text', hint: '例如 https://192.0.2.10:19443；修改后需要更新全部节点。' },
 { path: 'central.metrics_allowed_source_ip', label: '指标采集来源 IP', group: '连接与访问', type: 'text', hint: '主服务器访问节点时实际使用的公网 IP。' },
 { path: 'central.event_service.allowed_source_cidrs', label: '事件接口允许来源', group: '连接与访问', type: 'lines', hint: '每行一个 CIDR；留空使用启用节点 IP。' },
 { path: 'health.alerts.inode_warning_percent', label: 'inode 警告阈值（%）', group: '指标与告警', type: 'number', hint: '文件数量耗尽也会导致写入失败。' },
 { path: 'health.alerts.inode_critical_percent', label: 'inode 严重阈值（%）', group: '指标与告警', type: 'number', hint: '须高于警告阈值。' },
 { path: 'health.alerts.oldest_pending_task_seconds', label: '事件积压阈值（秒）', group: '指标与告警', type: 'number', hint: '本地与中心队列等待时间。' },
 { path: 'health.alerts.clock_offset_warning_seconds', label: '时钟偏差阈值（秒）', group: '指标与告警', type: 'number', hint: '避免时钟错误影响故障时间。' },
 { path: 'health.alertmanager.group_wait_seconds', label: '服务器告警汇总等待（秒）', group: '指标与告警', type: 'number', hint: '至少等待 15 秒；名称保留用于兼容旧 YAML。' },
 { path: 'health.alertmanager.repeat_interval_hours', label: '持续异常重复提醒（小时）', group: '指标与告警', type: 'number', hint: '默认 4 小时；恢复需连续正常两次。' },
 { path: 'feishu.retry.initial_delay_seconds', label: '首次重试延迟（秒）', group: '飞书通知', type: 'number', hint: '失败后重试，不丢弃消息。' },
 { path: 'feishu.retry.max_delay_seconds', label: '最大重试间隔（秒）', group: '飞书通知', type: 'number', hint: '使用已有指数退避。' }
)
for (const [key,label] of [['file_changes','文件变化'],['important_config_changes','重要配置变化'],['scan_matches','安全扫描命中'],['scan_errors','扫描错误'],['health_failures','监控异常'],['health_recoveries','监控恢复']] as const) fields.push({ path: `feishu.notifications.${key}`, label: `通知：${label}`, group: '飞书通知', type: 'boolean', hint: '切换后即时应用；异常记录继续保留。' })
export function getField(values: Record<string, unknown>, path: string): unknown { let value: unknown = values; for (const key of path.split('.')) value = (value as Record<string, unknown> | undefined)?.[key]; return value }
export function formValue(field: Field, value: unknown) { return field.type === 'lines' ? (Array.isArray(value) ? value.join('\n') : '') : field.type === 'secret' ? '' : value }
export function changedPatch(values: Record<string, unknown>, form: Record<string, unknown>) { const patch: Record<string, unknown> = {}; for (const field of fields) { let value = form[field.path]; if (field.type === 'secret' && !value) continue; if (field.type === 'lines') value = String(value || '').split('\n').map(v => v.trim()).filter(Boolean); if (field.type === 'number') value = Number(value); if (JSON.stringify(value) !== JSON.stringify(getField(values, field.path))) patch[field.path] = value } return patch }

fields.push(
 {path:'email.enabled',label:'启用邮箱通知',group:'邮箱通知',type:'boolean',hint:'与飞书独立；关闭后暂停旧任务，重新开启继续投递。'},
 {path:'email.smtp_host',label:'SMTP 服务器',group:'邮箱通知',type:'text',hint:'例如 smtp.163.com，不带协议和端口。'},
 {path:'email.smtp_port',label:'SMTP 端口',group:'邮箱通知',type:'number',hint:'通常隐式 TLS 为 465，STARTTLS 为 587。'},
 {path:'email.tls_mode',label:'SMTP 加密方式',group:'邮箱通知',type:'text',hint:'tls（隐式 TLS）或 starttls；不允许明文，不受通信 SSL 开关影响。'},
 {path:'email.username',label:'SMTP 登录账号',group:'邮箱通知',type:'text',hint:'通常为完整发件邮箱。'},
 {path:'email.password',label:'SMTP 密码或授权码',group:'邮箱通知',type:'secret',hint:'请使用邮箱服务商的 SMTP 授权码；留空保留，不回显。'},
 {path:'email.from_address',label:'发件邮箱',group:'邮箱通知',type:'text',hint:'须符合邮箱服务商授权的发件地址。'},
 {path:'email.from_name',label:'发件显示名称',group:'邮箱通知',type:'text',hint:'默认网站监控。'},
 {path:'email.recipients',label:'接收邮箱',group:'邮箱通知',type:'lines',hint:'每行一个，去重后最多 20 个；修改不改变旧任务收件人。'},
 {path:'email.timeout_seconds',label:'发送超时（秒）',group:'邮箱通知',type:'number',hint:'默认 15，最大 60。'},
 {path:'email.max_per_minute',label:'每分钟最多投递尝试',group:'邮箱通知',type:'number',hint:'默认 30，失败尝试也计入。'},
 {path:'email.retry.initial_delay_seconds',label:'首次重试延迟（秒）',group:'邮箱通知',type:'number',hint:'默认 30。'},
 {path:'email.retry.max_delay_seconds',label:'最大重试间隔（秒）',group:'邮箱通知',type:'number',hint:'默认 3600，失败任务保留。'}
)
for(const [key,label] of [['file_changes','文件变化'],['important_config_changes','重要配置变化'],['scan_matches','安全扫描命中'],['scan_errors','扫描错误'],['health_failures','监控及网站故障'],['health_recoveries','监控及网站恢复']] as const)fields.push({path:`email.notifications.${key}`,label:`通知：${label}`,group:'邮箱通知',type:'boolean',hint:'与飞书类别独立，异常记录始终保留。'})
