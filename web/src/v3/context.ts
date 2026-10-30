import { inject, type InjectionKey, type Ref } from 'vue'
import type { ControlV3, V3Session } from '../controlV3'

export interface ConsoleContext { client: ControlV3; session: Ref<V3Session | null> }
export const consoleContext: InjectionKey<ConsoleContext> = Symbol('webscan-v3-console')
export function useConsole() {
  const value = inject(consoleContext)
  if (!value) throw new Error('v3 控制台尚未初始化')
  return value
}
export const timeText = (value?: string | number | null) => {
  if (value === undefined || value === null || value === '') return '—'
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? new Intl.DateTimeFormat('zh-CN', { dateStyle: 'short', timeStyle: 'medium', hour12: false }).format(date) : '—'
}
export function jobLabel(status: string) {
  return ({ queued: '排队中', running: '执行中', failed: '失败', interrupted: '已中断', succeeded: '成功', rolled_back: '已回退' } as Record<string, string>)[status] || '未知'
}
