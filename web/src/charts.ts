import type { EChartsOption } from 'echarts'
export interface MetricPoint { time: number; ok: boolean; values: Record<string, number>; min?: Record<string, number>; max?: Record<string, number> }
export interface ChartMetric { title: string; keys: string[]; unit: string; bar?: boolean }
export const resourceCharts: ChartMetric[] = [
 { title: 'CPU 使用率', keys: ['cpu_percent', 'cpu_user_percent', 'cpu_system_percent', 'cpu_iowait_percent'], unit: '%' },
 { title: '内存使用情况', keys: ['memory_used', 'memory_available'], unit: 'B' },
 { title: 'Swap 使用情况', keys: ['swap_percent'], unit: '%' },
 { title: '系统负载', keys: ['load1', 'load5', 'load15'], unit: '' },
 { title: '各磁盘空间使用率', keys: ['disk_percent:'], unit: '%', bar: true },
 { title: '各磁盘 inode 使用率', keys: ['inode_percent:'], unit: '%', bar: true },
 { title: '磁盘读写速率', keys: ['disk_read', 'disk_write'], unit: 'B/s' },
 { title: '磁盘 IOPS', keys: ['disk_read_iops', 'disk_write_iops'], unit: '次/s' },
 { title: '网络收发速率', keys: ['net_receive', 'net_transmit'], unit: 'B/s' },
 { title: '网络错误与丢包速率', keys: ['net_receive_errors', 'net_transmit_errors', 'net_receive_drops', 'net_transmit_drops'], unit: '次/s' },
]
export const healthCharts: ChartMetric[] = [
 { title: '待投递 / 待扫描数量', keys: ['webscan_local_pending_events', 'webscan_pending_scans'], unit: '条' },
 { title: '心跳与链路检查延迟', keys: ['webscan_agent_heartbeat_seconds', 'webscan_local_probe_seconds', 'webscan_probe_received_seconds', 'webscan_probe_query_seconds'], unit: 's' },
]
const labels: Record<string, string> = { webscan_transport_up: 'Go 事件投递工作器（1 正常 / 0 异常）', webscan_transport_last_success_seconds: '最近中心确认时间', webscan_transport_last_failure_seconds: '最近投递失败时间', webscan_transport_rejected_events: '被拒绝的事件数', cpu_percent: 'CPU', cpu_user_percent: '用户态', cpu_system_percent: '系统态', cpu_iowait_percent: 'I/O 等待', memory_used: '已用', memory_available: '可用', swap_percent: 'Swap', load1: '1 分钟', load5: '5 分钟', load15: '15 分钟', disk_read: '读取', disk_write: '写入', disk_read_iops: '读取', disk_write_iops: '写入', net_receive: '接收', net_transmit: '发送', net_receive_errors: '接收错误', net_transmit_errors: '发送错误', net_receive_drops: '接收丢弃', net_transmit_drops: '发送丢弃', webscan_local_pending_events: '待投递', webscan_pending_scans: '待扫描', webscan_agent_heartbeat_seconds: 'Agent 心跳', webscan_local_probe_seconds: '本地测试', webscan_probe_received_seconds: '事件接收', webscan_probe_query_seconds: '事件查询', webscan_watches: '监听目录数', webscan_coverage_ok: '目录覆盖正常（1 是 / 0 否）', webscan_vector_metrics_up: '事件投递工作器（兼容旧 Vector）', webscan_scan_heartbeat_seconds: '扫描程序最近心跳时间', webscan_oldest_pending_seconds: '中心最早任务等待秒数', webscan_local_oldest_pending_seconds: '节点最早事件等待秒数', webscan_last_drop_seconds: '最近文件事件丢弃时间', webscan_last_inotify_overflow_seconds: '最近监听溢出时间' }
export function metricLabel(key: string) { return labels[key] || key.split(':').slice(1).join(':') || key }
export function metricValue(value: number | undefined, unit = ''): string {
 if (value === undefined || !Number.isFinite(value)) return '未知'
 if (unit.startsWith('B')) { const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']; let index = 0; while (Math.abs(value) >= 1024 && index < units.length - 1) { value /= 1024; index++ } return `${value.toFixed(index ? 1 : 0)} ${units[index]}${unit.endsWith('/s') ? '/s' : ''}` }
 return `${value.toFixed(1)}${unit}`
}
export function trendOption(points: MetricPoint[], spec: ChartMetric, device = '', snapshot: Record<string, number> = {}): EChartsOption {
 let keys = spec.keys
 if (spec.bar) { keys = Object.keys(snapshot).filter(key => key.startsWith(spec.keys[0]!)).sort(); return { tooltip: { trigger: 'axis' }, grid: { left: 110, right: 30, top: 15, bottom: 35 }, xAxis: { type: 'value', max: 100, axisLabel: { formatter: '{value}%' } }, yAxis: { type: 'category', data: keys.map(metricLabel) }, series: [{ type: 'bar', data: keys.map(key => snapshot[key] ?? null), itemStyle: { color: '#4679ee', borderRadius: [0, 4, 4, 0] } }] } }
 if (device) keys = keys.map(key => `${key}:${device}`)
 return { tooltip: { trigger: 'axis', valueFormatter: value => metricValue(typeof value === 'number' ? value : undefined, spec.unit) }, legend: { type: 'scroll', bottom: 0 }, grid: { left: 65, right: 20, top: 20, bottom: 60 }, xAxis: { type: 'time', axisLabel: { formatter: value => new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', hour: '2-digit', minute: '2-digit' }).format(value) } }, yAxis: { type: 'value', axisLabel: { formatter: value => metricValue(Number(value), spec.unit) } }, series: keys.flatMap(key => [{ name: metricLabel(key), type: 'line', showSymbol: false, connectNulls: false, smooth: false, areaStyle: keys.length === 1 ? { opacity: .08 } : undefined, data: points.map(point => { let value = point.ok ? point.values[key] : undefined; if (value !== undefined && spec === healthCharts[1]) value = Math.max(0, point.time - value); return [point.time * 1000, value ?? null] }) }, ...(points.some(p => p.max?.[key] !== undefined) ? [{ name: metricLabel(key) + ' 峰值', type: 'line' as const, showSymbol: false, connectNulls: false, lineStyle: { type: 'dashed' as const, opacity: .45 }, data: points.map(p => [p.time * 1000, p.ok && p.max?.[key] !== undefined ? spec === healthCharts[1] ? Math.max(0, p.time-p.max[key]!) : p.max[key]! : null]) }] : [])]) }
}
export function rankingOption(items: { name: string; snapshot: { ok: boolean; values: Record<string, number> }; status: string }[], key: string): EChartsOption {
 const rows = items.filter(item => item.status === 'normal' && item.snapshot.values[key] !== undefined).sort((a, b) => b.snapshot.values[key]! - a.snapshot.values[key]!).slice(0, 8).reverse()
 return { tooltip: { trigger: 'axis', valueFormatter: value => typeof value === 'number' ? `${value.toFixed(1)}%` : '未知' }, grid: { left: 100, right: 35, top: 15, bottom: 35 }, xAxis: { type: 'value', max: 100 }, yAxis: { type: 'category', data: rows.map(row => row.name) }, series: [{ type: 'bar', data: rows.map(row => row.snapshot.values[key]!), itemStyle: { color: '#4679ee', borderRadius: [0, 4, 4, 0] } }] }
}
