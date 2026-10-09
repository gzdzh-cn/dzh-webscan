export interface Result { time: number; ok: boolean; latency: number; http_status: number; cert_expires: number; cert_host?: string; cert_checked?: number; cert_applicable?: boolean; cert_error?: string; reason: string }
export interface Site { id: number; name: string; url: string; node: string; keyword: string; slow_alert: boolean; paused: boolean; state: { status: string; last: Result; checks: number; passed: number; failures: number; successes: number } }
export interface Incident { id: number; site_id: number; name: string; url: string; kind: string; started: number; ended: number; reason: string }
export interface Node { id: string; name: string }
export interface Session { username: string; csrf_token: string; nodes: Node[] }
export interface Page<T> { items: T[]; total: number }
export interface Overview { total: number; normal: number; down: number; pending: number; paused: number; scheduler_healthy: boolean }
let csrf = ''
export function setCSRF(value: string) { csrf = value }
export class APIError extends Error { constructor(public status: number, message: string, public field = '') { super(message) } }
export async function api<T>(url: string, method = 'GET', body?: unknown): Promise<T> {
 let response: Response
 try { response = await fetch(url, { method, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: body === undefined ? undefined : JSON.stringify(body) }) }
 catch { throw new APIError(0, '无法连接管理后台，请检查主服务器服务及网络') }
 const data = await response.json().catch(() => ({}))
 if (!response.ok) {
  if (response.status === 401 && url !== '/api/login') window.dispatchEvent(new Event('session-expired'))
  throw new APIError(response.status, data.message || `请求失败（${response.status}），请稍后重试`, data.field || '')
 }
 return data as T
}
export function beijingTime(value: number) { return value ? new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(value * 1000) : '尚未检查' }
export function stateLabel(site: Site) { return site.paused ? '已暂停' : ({ normal: '正常', down: '无法访问', pending: '等待检查' }[site.state.status] || '等待检查') }
export function siteInput(site: Site) { return { name: site.name, url: site.url, node: site.node, keyword: site.keyword, slow_alert: site.slow_alert, paused: site.paused } }
