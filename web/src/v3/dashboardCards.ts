import type { V3Dashboard, V3DashboardCounts } from '../controlV3'

export type ComponentStatus = '正常' | '异常' | '未知' | '已停用' | '未接管' | '维护中'
export interface DashboardCard { key: string; title: string; status: ComponentStatus; reason: string; at?: string | null; to: string }
const count = (value?: number | null) => value === null || value === undefined ? '—' : String(value)
const checkNames: Record<string,string> = { api:'API',postgres:'PostgreSQL',metrics:'VictoriaMetrics',storage:'存储' }
const checkReasons: Record<string,string> = { health_endpoint_unavailable:'健康接口不可访问',health_endpoint_responded:'健康接口已响应',database_unavailable:'数据库连接失败',database_responded:'数据库连接已验证',storage_evidence_unavailable:'文件系统容量证据不完整',storage_capacity_available:'文件系统容量已观测',storage_capacity_low:'可用空间或 inode 不足' }
const fresh = (at?: string | null, seconds = 45) => !!at && Number.isFinite(Date.parse(at)) && Date.parse(at) >= Date.now() - seconds * 1000 && Date.parse(at) <= Date.now() + 5000
export function dashboardHost(value: V3Dashboard | null, readFailed = false) {
  const section = value?.summary.sections?.host_watchdog, data = section?.data
  const reason = readFailed || value?.stale || section?.error ? '宿主观测读取失败或已过期，当前状态未知' : !data?.configured ? '尚未配置独立宿主看门狗' : !data.available ? data.reason || '宿主看门狗不可访问，当前状态未知' : !data.fresh || !fresh(data.status?.observed_at) ? data.reason || '宿主观测已过期，当前状态未知' : !data.status ? '尚无宿主观测回执' : ''
  const status = reason ? null : data?.status || null
  const check = (component: string) => {
    const matches = status?.checks.filter(item => item.component === component) || [], item = matches.length === 1 ? matches[0] : undefined
    const state: ComponentStatus = !item || !fresh(item.observed_at) || !['normal', 'abnormal'].includes(item.state) ? '未知' : item.state === 'normal' ? '正常' : '异常'
    return { component, state, reason: !status ? reason : !item ? '尚无唯一检查回执' : !fresh(item.observed_at) ? '检查回执已过期，当前状态未知' : checkReasons[item.reason] || item.reason || (state === '未知' ? '检查未提供健康结论' : '独立宿主检查'), observed_at: item?.observed_at || null, latency_ms: item && fresh(item.observed_at) && Number.isFinite(item.latency_ms) && item.latency_ms >= 0 ? item.latency_ms : null }
  }
  return { status, reason, check }
}

export function dashboardCards(value: V3Dashboard | null, readFailed = false): DashboardCard[] {
  const s = value?.summary.sections
  const cards: DashboardCard[] = []
  const add = (key: string, title: string, status: ComponentStatus, reason: string, to: string, at?: string | null, sectionFailed = false) => {
    const stale = readFailed || value?.stale || sectionFailed
    cards.push({ key, title, status: stale ? '未知' : status, reason: stale ? `数据已过期。${reason}` : reason, at, to })
  }
  const aggregate = (state?: V3DashboardCounts): ComponentStatus => !state ? '未知' : state.abnormal > 0 ? '异常' : state.unknown > 0 ? '未知' : state.applicable > 0 ? '正常' : '未接管'
  const describe = (state?: V3DashboardCounts) => state ? `正常 ${state.normal} · 异常 ${state.abnormal} · 未知 ${state.unknown}` : '尚无适用节点的运行证据'
  const servers = s?.servers?.data, monitoring = s?.monitoring?.data, services = s?.services?.data
  const host = dashboardHost(value, readFailed), api = host.check('api'), postgres = host.check('postgres'), metrics = host.check('metrics'), storage = host.check('storage')
  add('central', '中心接收与后台', s?.host_watchdog?.data?.configured ? api.state : value ? '正常' : '未知', s?.host_watchdog?.data?.configured ? `后台 API ${api.state}；${api.reason}` : value ? `后台 API 可访问 · ${value.version || '版本未知'}` : '尚未读取后台状态', '/', api.observed_at || value?.updated_at)
  add('metrics', '主机指标采集', !servers ? '未知' : servers.abnormal ? '异常' : servers.unknown ? '未知' : servers.enabled ? '正常' : '未接管', servers ? `正常 ${servers.fresh} · 异常 ${servers.abnormal} · 未知 ${servers.unknown}` : '尚无采集汇总', '/servers', s?.servers?.updated_at, Boolean(s?.servers?.error))
  add('files', '文件监控', aggregate(monitoring?.states?.files), describe(monitoring?.states?.files), '/events', s?.monitoring?.updated_at, Boolean(s?.monitoring?.error))
  add('scans', '安全扫描', monitoring && monitoring.yara_nodes === 0 && monitoring.clamav_nodes === 0 ? '已停用' : aggregate(monitoring?.states?.scans), `YARA ${count(monitoring?.yara_nodes)} 台 · ClamAV ${count(monitoring?.clamav_nodes)} 台 · 待扫描 ${count(monitoring?.pending_scans)}；${describe(monitoring?.states?.scans)}`, '/events?operation=scan', s?.monitoring?.updated_at, Boolean(s?.monitoring?.error))
  add('delivery', '事件投递', aggregate(monitoring?.states?.delivery), `已观测积压 ${count(monitoring?.pending_events)} · 最老等待 ${count(monitoring?.oldest_wait_seconds)} 秒；${describe(monitoring?.states?.delivery)}`, '/servers', s?.monitoring?.updated_at, Boolean(s?.monitoring?.error))
  const websites = s?.websites?.data
  add('websites', '网站检测', !websites?.scheduler.heartbeat ? '未知' : websites.scheduler.healthy ? '正常' : '异常', websites ? `待检查 ${websites.due} · 暂停 ${websites.paused} · 等待迁移 ${websites.migration_pending}` : '尚无调度状态', '/websites', websites?.scheduler.heartbeat, Boolean(s?.websites?.error))
  const databaseStatus = [postgres, metrics].some(item => item.state === '异常') ? '异常' : [postgres, metrics].every(item => item.state === '正常') ? '正常' : '未知'
  add('database', '数据库', databaseStatus, `PostgreSQL ${postgres.state}：${postgres.reason}；VictoriaMetrics ${metrics.state}：${metrics.reason}。${services && !s?.services?.error && Number.isFinite(services.database_bytes) && services.database_bytes >= 0 ? `PostgreSQL 业务表与索引 ${(services.database_bytes / 1048576).toFixed(1)} MiB；此值不是磁盘容量。` : '业务表与索引大小未知。'}`, '/settings?tab=storage', host.status?.observed_at, Boolean(s?.host_watchdog?.error))
  for (const [channel, title] of [['feishu', '飞书通知'], ['email', '邮箱通知']] as const) {
    const data = s?.notifications?.data?.[channel]
    const worker = services?.roles[`notify-${channel}`], workerFresh = fresh(worker?.heartbeat), workerState: ComponentStatus = !workerFresh ? '未知' : worker?.has_error || worker?.healthy === false ? '异常' : worker?.healthy === true ? '正常' : '未知'
    const frozen = host.status?.frozen
    const workerReason = !data?.enabled ? '通道未启用，队列保留' : frozen ? `通知配置冻结，发送已暂停${host.status?.reason ? `：${host.status.reason}` : ''}${workerState === '未知' ? '；对应工作器状态未知' : ''}` : !workerFresh ? '尚无新鲜投递工作器心跳；队列为空也不能证明正常' : workerState === '正常' ? '对应投递工作器心跳正常；不代表外部通道始终可达' : '对应投递工作器报告异常，请检查任务与通道配置'
    const channelStatus: ComponentStatus = !data ? '未知' : !data.enabled ? '已停用' : workerState === '异常' || data.retrying > 0 ? '异常' : workerState === '未知' ? '未知' : frozen ? '维护中' : workerState
    add(channel, title, channelStatus, data ? `待投递 ${data.pending} · 重试 ${data.retrying}；${workerReason}` : '尚无通道状态', `/alerts?tab=${channel}`, worker?.heartbeat || s?.notifications?.updated_at, Boolean(s?.notifications?.error || s?.services?.error))
  }
  const executor = services?.roles.executor
  add('host', '宿主管理服务', !executor ? '未知' : executor.healthy ? '正常' : '异常', executor ? '部署执行器心跳；配置应用须通过预览及任务验收' : '尚未观察到部署执行器心跳', '/deployments', executor?.heartbeat, Boolean(s?.services?.error))
  const pki = s?.certificates?.data?.maintenance
  const expiry = (date?: string | null) => date ? Date.parse(date) : NaN
  const collectorExpiry = expiry(pki?.collector_expires_at), caExpiry = expiry(pki?.ca_expires_at)
  const expiryKnown = Number.isFinite(collectorExpiry) && Number.isFinite(caExpiry)
  const certificateStatus: ComponentStatus = !pki || !pki.fresh || !expiryKnown ? '未知' : pki.has_error || Math.min(collectorExpiry, caExpiry) <= Date.now() ? '异常' : Math.min(collectorExpiry, caExpiry) <= Date.now() + 7 * 86400_000 ? '维护中' : '正常'
  add('certificates', '证书维护', certificateStatus, !pki ? '尚无宿主证书维护回执' : !pki.fresh ? '维护心跳已过期，请检查宿主定时任务' : pki.reason || (!expiryKnown ? '缺少已验证的证书期限' : certificateStatus === '维护中' ? '证书将在七天内到期，请检查续期任务' : certificateStatus === '异常' ? '证书已过期，请检查维护任务' : '已验证采集器与 CA 期限；节点证书以实际采集验收为准'), '/servers/central?tab=system', pki?.heartbeat, Boolean(s?.certificates?.error))
  const checks = [api, postgres, metrics, storage], watchdogState: ComponentStatus = !host.status ? '未知' : checks.some(item => item.state === '异常') ? '异常' : checks.some(item => item.state === '未知') ? '未知' : host.status.frozen ? '维护中' : '正常'
  add('watchdog', '看门狗', watchdogState, !host.status ? host.reason : `${checks.map(item => `${checkNames[item.component]} ${item.state}`).join(' · ')}；${host.status.frozen ? `通知配置冻结，发送已暂停${host.status.reason ? `：${host.status.reason}` : ''}` : `待处理宿主通知 ${host.status.pending}`}`, '/servers/central?tab=system', host.status?.observed_at, Boolean(s?.host_watchdog?.error))
  const cleanup = services?.roles.retention
  const backups = s?.full_backups?.data, lastBackup = backups?.latest
  const backupFailed = Boolean(lastBackup?.has_error || lastBackup && ['failed', 'interrupted'].includes(lastBackup.status))
  const backupVerified = Boolean(lastBackup?.status === 'captured' && lastBackup.restore_validated && Date.parse(lastBackup.updated_at) > Date.now() - 48 * 3600_000 && Date.parse(lastBackup.updated_at) <= Date.now() + 5000)
  const backupReason = !backups?.policy ? '尚未配置完整备份' : !backups.policy.enabled ? '备份策略未启用' : !lastBackup ? '已配置每日备份，尚无执行回执' : lastBackup.status === 'running' ? '完整备份执行中' : backupFailed ? '完整备份未完成，请检查宿主任务' : lastBackup.status === 'captured' ? `已归档 ${lastBackup.files} 个文件；${lastBackup.restore_validated ? '隔离恢复已验证' : '尚无完整恢复验收回执'}` : '备份任务等待核验'
  add('cleanup', '备份与历史清理', cleanup && !cleanup.healthy || backupFailed ? '异常' : backups?.policy?.enabled && backupVerified && cleanup?.healthy ? '正常' : '未知', `${services?.last_cleanup ? `最近清理 ${services.last_cleanup.status} · 删除 ${services.last_cleanup.deleted}；` : ''}${backupReason}`, '/settings?tab=storage', lastBackup?.updated_at || cleanup?.heartbeat, Boolean(s?.services?.error || s?.full_backups?.error))
  const deployments = s?.deployments?.data
  add('deployments', '部署任务', !deployments ? '未知' : deployments.recovery_required ? '异常' : '正常', deployments ? `运行 ${deployments.running} · 待恢复 ${deployments.recovery_required}${!deployments.running && !deployments.recovery_required ? ' · 空闲' : ''}` : '尚无部署任务汇总', '/deployments', s?.deployments?.updated_at, Boolean(s?.deployments?.error))
  return cards
}
