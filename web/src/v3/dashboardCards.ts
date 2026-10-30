import type { V3Dashboard, V3DashboardCounts } from '../controlV3'

export type ComponentStatus = '正常' | '异常' | '未知' | '已停用' | '未接管' | '维护中'
export interface DashboardCard { key: string; title: string; status: ComponentStatus; reason: string; at?: string | null; to: string }
const count = (value?: number | null) => value === null || value === undefined ? '—' : String(value)

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
  add('central', '中心接收与后台', value ? '正常' : '未知', value ? `后台 API 可访问 · ${value.version || '版本未知'}` : '尚未读取后台状态', '/', value?.updated_at)
  add('metrics', '主机指标采集', !servers ? '未知' : servers.abnormal ? '异常' : servers.unknown ? '未知' : servers.enabled ? '正常' : '未接管', servers ? `正常 ${servers.fresh} · 异常 ${servers.abnormal} · 未知 ${servers.unknown}` : '尚无采集汇总', '/servers', s?.servers?.updated_at, Boolean(s?.servers?.error))
  add('files', '文件监控', aggregate(monitoring?.states?.files), describe(monitoring?.states?.files), '/events', s?.monitoring?.updated_at, Boolean(s?.monitoring?.error))
  add('scans', '安全扫描', monitoring && monitoring.yara_nodes === 0 && monitoring.clamav_nodes === 0 ? '已停用' : aggregate(monitoring?.states?.scans), `YARA ${count(monitoring?.yara_nodes)} 台 · ClamAV ${count(monitoring?.clamav_nodes)} 台 · 待扫描 ${count(monitoring?.pending_scans)}；${describe(monitoring?.states?.scans)}`, '/events?operation=scan', s?.monitoring?.updated_at, Boolean(s?.monitoring?.error))
  add('delivery', '事件投递', aggregate(monitoring?.states?.delivery), `已观测积压 ${count(monitoring?.pending_events)} · 最老等待 ${count(monitoring?.oldest_wait_seconds)} 秒；${describe(monitoring?.states?.delivery)}`, '/servers', s?.monitoring?.updated_at, Boolean(s?.monitoring?.error))
  const websites = s?.websites?.data
  add('websites', '网站检测', !websites?.scheduler.heartbeat ? '未知' : websites.scheduler.healthy ? '正常' : '异常', websites ? `待检查 ${websites.due} · 暂停 ${websites.paused} · 等待迁移 ${websites.migration_pending}` : '尚无调度状态', '/websites', websites?.scheduler.heartbeat, Boolean(s?.websites?.error))
  add('database', '数据库', '未知', services ? `PostgreSQL 可访问 · ${(services.database_bytes / 1048576).toFixed(1)} MiB（本应用）；时序库状态与大小待接入` : '尚无存储证据', '/settings?tab=storage', s?.services?.updated_at, Boolean(s?.services?.error))
  for (const [channel, title] of [['feishu', '飞书通知'], ['email', '邮箱通知']] as const) {
    const data = s?.notifications?.data?.[channel]
    add(channel, title, !data ? '未知' : !data.enabled ? '已停用' : data.retrying > 0 ? '异常' : '未知', data ? `待投递 ${data.pending} · 重试 ${data.retrying}${data.enabled ? '；投递工作器心跳待接入' : '；通道未启用，队列保留'}` : '尚无通道状态', `/alerts?tab=${channel}`, s?.notifications?.updated_at, Boolean(s?.notifications?.error))
  }
  const executor = services?.roles.executor
  add('host', '宿主管理服务', !executor ? '未知' : executor.healthy ? '正常' : '异常', executor ? '部署执行器心跳；配置应用须通过预览及任务验收' : '尚未观察到部署执行器心跳', '/deployments', executor?.heartbeat, Boolean(s?.services?.error))
  add('watchdog', '看门狗', '未接管', 'v3 尚未接入看门狗运行状态', '/servers')
  const cleanup = services?.roles.retention
  add('cleanup', '备份与历史清理', cleanup && !cleanup.healthy ? '异常' : '未知', services?.last_cleanup ? `最近清理 ${services.last_cleanup.status} · 删除 ${services.last_cleanup.deleted}；自动数据库备份状态待接入` : '尚无清理结果；自动数据库备份状态待接入', '/settings?tab=storage', cleanup?.heartbeat, Boolean(s?.services?.error))
  const deployments = s?.deployments?.data
  add('deployments', '部署任务', !deployments ? '未知' : deployments.recovery_required ? '异常' : '正常', deployments ? `运行 ${deployments.running} · 待恢复 ${deployments.recovery_required}${!deployments.running && !deployments.recovery_required ? ' · 空闲' : ''}` : '尚无部署任务汇总', '/deployments', s?.deployments?.updated_at, Boolean(s?.deployments?.error))
  return cards
}
