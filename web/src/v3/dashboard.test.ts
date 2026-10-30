// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { ControlV3, type V3Dashboard } from '../controlV3'
import { installElements } from '../elements'
import { consoleContext } from './context'
import Dashboard from './Dashboard.vue'
import { dashboardCards } from './dashboardCards'

vi.mock('../MetricChart.vue', () => ({ default: { props: ['title'], template: '<div class="chart">{{ title }}</div>' } }))
let app: App | undefined, host: HTMLDivElement
const at = '2026-10-18T00:00:00Z'
const section = <T,>(data: T) => ({ data, updated_at: at, error: '' })
const fixture = (): V3Dashboard => ({ version: 'v3.0.0-local-test', started_at: at, updated_at: at, stale: false, error: '', summary: { sections: {
  servers: section({ servers: 5, enabled: 4, fresh: 2, abnormal: 1, unknown: 1 }),
  websites: section({ total: 4, normal: 2, down: 1, paused: 1, pending: 0, unknown: 0, migration_pending: 0, due: 1, notification_outbox: { pending: 0, oldest_wait_seconds: null }, notification_worker: { heartbeat: null, healthy: null }, scheduler: { heartbeat: at, healthy: true } }),
  events: section({ total: 18, security: 2 }), alerts: section({ total: 0, items: [] }),
  deployments: section({ running: 0, recovery_required: 0, latest: null }),
  notifications: section({ feishu: { enabled: false, pending: 2, retrying: 1, oldest_wait_seconds: 90 }, email: { enabled: true, pending: 1, retrying: 0, oldest_wait_seconds: 0 } }),
  resources: section({ items: [{ id: 'node-a', name: '测试节点', mode: 'docker', actual_mode: null, agent_version: null, sampled_at: null, cpu_percent: 0, memory_percent: null, disk_percent: null, has_error: false }], rankings: { cpu_percent: [{ id: 'node-a', name: '测试节点', value: 0 }], memory_percent: [], disk_percent: [] } }),
  services: section({ database_bytes: 1048576, roles: {}, last_cleanup: null }),
  monitoring: section({ states: { files: { applicable: 4, normal: 1, abnormal: 1, unknown: 2 } }, pending_events: null, oldest_wait_seconds: null, pending_scans: 0, yara_nodes: 1, clamav_nodes: 0 }),
} } })
async function settle() { for (let i = 0; i < 18; i++) { await Promise.resolve(); await nextTick() } }
async function mount(client: ControlV3) {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/', component: Dashboard }, { path: '/:pathMatch(.*)*', component: { template: '<div>其他页面</div>' } }] })
  await router.push('/'); await router.isReady()
  app = createApp({ template: '<router-view />' })
  installElements(app); app.use(router); app.provide(consoleContext, { client, session: ref({ username: 'viewer', role: 'viewer' as const, csrf: 'synthetic' }) }); app.mount(host); await settle()
  return router
}
beforeEach(() => { vi.useFakeTimers(); Object.defineProperty(document, 'hidden', { configurable: true, value: false }); host = document.createElement('div'); document.body.append(host) })
afterEach(async () => { app?.unmount(); app = undefined; await settle(); host.remove(); vi.clearAllTimers(); vi.useRealTimers(); vi.restoreAllMocks() })

it('shows six summaries, thirteen evidence based components and real zero without fake missing values', async () => {
  const client = new ControlV3(); vi.spyOn(client, 'dashboard').mockResolvedValue(fixture())
  const events = vi.spyOn(client, 'events')
  await mount(client)
  expect(host.querySelectorAll('.v3-summary-card')).toHaveLength(6)
  expect(host.querySelectorAll('.v3-component-heading')).toHaveLength(13)
  expect(host.textContent).toContain('v3.0.0-local-test')
  expect(host.textContent).toContain('0.0%')
  expect(host.textContent).toContain('当前没有异常')
  expect(host.textContent).toContain('时序库状态与大小待接入')
  expect(host.querySelector('a[href="/events?operation=scan"]')).not.toBeNull()
  expect(events).not.toHaveBeenCalled()
  const cards = dashboardCards(fixture())
  expect(cards.find(card => card.key === 'files')?.status).toBe('异常')
  expect(cards.find(card => card.key === 'feishu')?.status).toBe('已停用')
  expect(cards.find(card => card.key === 'email')?.status).toBe('未知')
})

it('keeps unknown state before the first result and on a failed empty observation', async () => {
  const client = new ControlV3()
  let resolve!: (value: V3Dashboard) => void
  vi.spyOn(client, 'dashboard').mockReturnValueOnce(new Promise(done => { resolve = done })).mockRejectedValue(new Error('汇总读取失败'))
  await mount(client)
  expect(host.textContent).not.toContain('当前没有异常')
  expect(host.querySelector('.v3-summary-card strong')?.textContent).toBe('—')
  resolve(fixture()); await settle()
  await vi.advanceTimersByTimeAsync(30_000); await settle()
  expect(host.textContent).toContain('汇总读取失败')
  expect(host.textContent).toContain('上次观测没有异常，当前状态待确认')
  expect(host.textContent).not.toContain('当前没有异常')
  expect(host.textContent).toContain('18')
})

it('waits a whole interval after completion and never overlaps reads', async () => {
  const client = new ControlV3()
  let resolve!: (value: V3Dashboard) => void
  const read = vi.spyOn(client, 'dashboard').mockReturnValueOnce(new Promise(done => { resolve = done })).mockResolvedValue(fixture())
  await mount(client)
  await vi.advanceTimersByTimeAsync(90_000)
  expect(read).toHaveBeenCalledTimes(1)
  resolve(fixture()); await settle()
  await vi.advanceTimersByTimeAsync(29_999); expect(read).toHaveBeenCalledTimes(1)
  await vi.advanceTimersByTimeAsync(1); await settle(); expect(read).toHaveBeenCalledTimes(2)
  host.querySelector('button')!.click(); await settle(); expect(read).toHaveBeenCalledTimes(3)
  await vi.advanceTimersByTimeAsync(30_000); await settle(); expect(read).toHaveBeenCalledTimes(4)
})

it('pauses in a background tab, rejects late responses and clears timers after navigation', async () => {
  const client = new ControlV3()
  let resolve!: (value: V3Dashboard) => void
  const read = vi.spyOn(client, 'dashboard').mockReturnValueOnce(new Promise(done => { resolve = done })).mockResolvedValue(fixture())
  const router = await mount(client), signal = read.mock.calls[0]![0]!
  Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange')); await settle()
  expect(signal.aborted).toBe(true)
  await vi.advanceTimersByTimeAsync(60_000); expect(read).toHaveBeenCalledTimes(1)
  Object.defineProperty(document, 'hidden', { configurable: true, value: false }); document.dispatchEvent(new Event('visibilitychange')); await settle()
  expect(read).toHaveBeenCalledTimes(2)
  const old = fixture(); old.version = 'obsolete-response'; resolve(old); await settle()
  expect(host.textContent).not.toContain('obsolete-response')
  await router.push('/events'); await settle(); await vi.advanceTimersByTimeAsync(90_000)
  expect(read).toHaveBeenCalledTimes(2)
})

it('marks a failed section stale without hiding successful sections or reporting old data as current', async () => {
  const value = fixture(); value.summary.sections!.alerts!.error = '读取失败'
  const client = new ControlV3(); vi.spyOn(client, 'dashboard').mockResolvedValue(value)
  await mount(client)
  expect(host.textContent).toContain('读取失败')
  expect(host.textContent).toContain('当前状态待确认')
  const cards = dashboardCards(value)
  expect(cards.find(card => card.key === 'websites')?.status).toBe('正常')
  value.stale = true
  expect(dashboardCards(value).every(card => card.status === '未知')).toBe(true)
})
