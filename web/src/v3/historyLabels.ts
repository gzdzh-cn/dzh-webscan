import type { V3HistoryCategory } from '../controlV3'
export const historyCategories: { value: V3HistoryCategory; label: string }[] = [
  { value: 'events', label: '普通文件及运行事件' }, { value: 'security-events', label: '安全扫描命中事件' },
  { value: 'website-incidents', label: '网站故障历史' }, { value: 'server-alerts', label: '服务器告警历史' },
  { value: 'feishu', label: '飞书通知历史' }, { value: 'email', label: '邮箱通知历史' },
]
export const historyStatus = (status: string) => ({ queued: '排队中', running: '执行中', succeeded: '已完成', partial: '部分完成', cancelled: '已取消', failed: '失败' } as Record<string, string>)[status] || '未知'
export const historyCategory = (category: string) => historyCategories.find(value => value.value === category)?.label || '未知类别'
