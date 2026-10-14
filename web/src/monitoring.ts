import { api, type Page } from './api'
import type { MetricPoint } from './charts'
export interface Server { can_remove?:boolean;remove_reason?:string; deployment_state?: string; configured_mode?: string; actual_mode?: string; agent_version?: string; pending_mode?: boolean; id: string; name: string; host: string; central: boolean; active: boolean; status: string; snapshot: { time: number; ok: boolean; error?: string; values: Record<string, number>; info?: Record<string, string> } }
export interface Trend { points: MetricPoint[]; resolution_seconds: number; start: number; end: number }
export interface Alert { site?:number; key: string; node?: string; name?: string; kind: string; phase: string; since: number; ended?: number; message: string; severity?: string; source: string }
export interface Notification { id: number; node: string; time: number; done: number; message: string; status: string; source: string; attempts: number; result: string; next_try: number }
export interface Job { can_delete?:boolean;delete_reason?:string; id: string; kind: string; node: string; status: string; created: number; updated: number; revision: string; message: string }
export interface Settings { revision: string; values: Record<string, unknown>; effective_nodes: Record<string, unknown>[]; running?: Record<string, unknown>; pending_task: boolean }
export interface Preview { revision: string; changes: { field: string; before: unknown; after: unknown; effect: string }[]; scope: string; nodes: string[]; restart: boolean; url?: string }
export const statusLabels: Record<string, string> = { normal: '采集正常', unreachable: '采集异常', stale: '数据已过期', unknown: '尚无数据', disabled: '已停用', pending: '等待', firing: '异常', resolved: '已恢复', reminder: '重复提醒', delivered: '已送达', retrying: '重试中', sending: '发送中', queued: '等待执行', running: '执行中', complete: '已完成', failed: '失败', interrupted: '曾中断' }
export function statusLabel(status: string) { return statusLabels[status] || status }
export function servers() { return api<Page<Server>>('/api/servers') }
export function rangeQuery(hours: number) { const end = Math.floor(Date.now() / 1000); return new URLSearchParams({ start: String(end - hours * 3600), end: String(end) }) }
export function errorMessage(error: unknown) { return error instanceof Error ? error.message : '操作失败，请稍后重试' }

export function requestKey() { const bytes = new Uint8Array(16); crypto.getRandomValues(bytes); return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('') }
