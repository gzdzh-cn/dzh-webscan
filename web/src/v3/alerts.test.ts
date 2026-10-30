// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { installElements } from '../elements'
import { ControlV3, type V3HealthState, type V3HealthRecord, type V3SiteIncident, type V3Notification } from '../controlV3'
import { cancelReadRequests } from '../connection'
import { consoleContext } from './context'
import Alerts from './Alerts.vue'

vi.mock('../MetricChart.vue', () => ({ default: { props: ['title'], template: '<div class="chart">{{ title }}</div>' } }))

let app: App | undefined, host: HTMLDivElement
const state = (): V3HealthState => ({ key: 'node-a:cpu', node: 'node-a', kind: 'cpu', phase: 'firing', since: 1792200000, last: 1792200030, recovery: 0, reminder: 0, message: 'CPU 持续偏高', severity: 'warning' })
const record = (): V3HealthRecord => ({ id: 'health-old', node: 'node-a', kind: 'cpu', phase: 'resolved', time: 1792200000, message: 'CPU 已恢复', state: state(), record_key: 'server-health:health-old', can_delete: true, delete_reason: '' })
const incident = (): V3SiteIncident => ({ id: 7, site: 2, site_name: '示例网站', node: 'node-a', kind: 'outage', started: 1792200000, ended: null, reason: '网站访问失败', record_key: 'website-incident:7', can_delete: true, delete_reason: '' })
const notification = (done = false): V3Notification => ({ id: '9007199254740993', node: 'node-a', event_id: 'event-one', channel: 'email', recipient: 'test@example.test', created_at: '2026-10-17T00:00:00Z', done_at: done ? '2026-10-17T01:00:00Z' : null, state: done ? 'completed' : 'paused', next_try: done ? null : '2026-10-18T00:00:00Z', attempts: 2, record_key: 'notification:9007199254740993', can_delete: done, delete_reason: done ? '' : '未完成通知受保护' })
async function settle() { for (let i = 0; i < 40; i++) { await Promise.resolve(); await nextTick() } }
function fixture() {
  const client = new ControlV3()
  vi.spyOn(client,'notificationStats').mockResolvedValue({items:[],timezone:'Asia/Shanghai',group_by:'created_at'})
  const reads = { current: vi.spyOn(client, 'currentAlerts').mockResolvedValue({ items: [state()], next_cursor: '' }),
    history: vi.spyOn(client, 'alertHistory').mockResolvedValue({ items: [record()], next_cursor: '', start: 'a', end: 'b' }),
    websites: vi.spyOn(client, 'websiteIncidents').mockResolvedValue({ items: [incident()], next_cursor: '' }),
    notifications: vi.spyOn(client, 'notifications').mockResolvedValue({ items: [notification()], next_cursor: '', start: 'a', end: 'b' }) }
  vi.spyOn(client, 'servers').mockResolvedValue({ items: [{ id: 'node-a', name: '服务器 A', endpoint: '192.0.2.1:19100', server_name: 'a.example.test', enabled: true, mode: 'native', version: 1, applied_version: 1, shard: 1 }], next_cursor: '', limit: 20 })
  return { client, ...reads }
}
async function mount(path = '/alerts', client = fixture().client, role: 'admin' | 'viewer' = 'admin') {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/alerts', component: Alerts }] })
  await router.push(path); await router.isReady()
  host = document.createElement('div'); document.body.append(host)
  app = createApp(Alerts); app.use(router); installElements(app); app.provide(consoleContext, { client, session: ref({ username: 'admin', role, csrf: 'csrf' }) })
  app.mount(host); await settle(); return router
}
function button(text: string, root: ParentNode = host) { const value = Array.from(root.querySelectorAll('button')).find(value => value.textContent?.trim() === text); if (!value) throw new Error(`button missing: ${text}`); return value }
async function select(label: string, value: string) {
  host.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!.click(); await settle()
  const option = Array.from(document.querySelectorAll<HTMLElement>('[role="option"]')).find(valueNode => valueNode.textContent?.trim() === value)
  if (!option) throw new Error(`option missing: ${value}`); option.click(); await settle()
}
beforeEach(() => { vi.useFakeTimers(); Object.defineProperty(document, 'hidden', { configurable: true, value: false }) })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(value => value.remove()); cancelReadRequests(true); vi.useRealTimers(); vi.restoreAllMocks() })

it('automatically loads current server anomalies and never offers their direct deletion', async () => {
  const f = fixture(); await mount('/alerts?node=node-a', f.client)
  expect(f.current.mock.calls[0]?.slice(0, 3)).toEqual(['node-a', '', 20])
  expect(host.textContent).toContain('CPU 持续偏高'); expect(host.textContent).not.toContain('删除已选')
  expect(Array.from(host.querySelectorAll('button')).some(value => value.textContent?.trim() === '删除')).toBe(false)
  button('CPU 持续偏高').click(); await settle()
  const dialog = document.querySelector('.v3-node-dialog')!
  expect(dialog.textContent).toContain('当前异常不能直接删除'); expect(dialog.textContent).not.toContain('1970')
})

it('loads website anomalies without a 24-hour cutoff and forces current rows to remain protected', async () => {
  const f = fixture(); await mount('/alerts?node=node-a&source=website', f.client)
  expect(f.websites.mock.calls[0]?.slice(0, 4)).toEqual([undefined, '', 20, { node: 'node-a', current: true }])
  expect(f.current).not.toHaveBeenCalled(); expect(host.textContent).toContain('示例网站'); expect(host.textContent).toContain('网站访问失败')
  expect(host.textContent).not.toContain('删除已选'); expect(host.querySelector('input[type="checkbox"]')).toBeNull()
})

it('changes sources and tabs with their own server-side queries, never filtering a partial page in the browser', async () => {
  const f = fixture(), router = await mount('/alerts', f.client)
  await select('告警来源', '网站')
  expect(router.currentRoute.value.query.source).toBe('website'); expect(f.websites).toHaveBeenCalledTimes(1)
  button('告警历史').click(); await settle()
  expect(f.websites.mock.calls.at(-1)?.[3]).toMatchObject({ current: false })
  expect(Date.parse(f.websites.mock.calls.at(-1)?.[3]?.end || '') - Date.parse(f.websites.mock.calls.at(-1)?.[3]?.start || '')).toBe(24 * 3600_000)
  button('邮箱通知').click(); await settle()
  expect(f.notifications.mock.calls.at(-1)?.[0]).toMatchObject({ channel: 'email', state: '', limit: 20 })
  expect(host.textContent).toContain('已暂停'); expect(host.textContent).toContain('尝试 2 次'); expect(button('删除').disabled).toBe(true)
  button('飞书通知').click(); await settle(); expect(f.notifications.mock.calls.at(-1)?.[0]?.channel).toBe('feishu')
})

it('starts a new time window when changing the range and preserves it for cursor paging', async () => {
  const f = fixture(); f.history.mockResolvedValue({ items: [record()], next_cursor: 'page-two', start: 'a', end: 'b' })
  await mount('/alerts?tab=history', f.client)
  const first = f.history.mock.calls[0]?.[0]
  await vi.advanceTimersByTimeAsync(29_000); button('下一页').click(); await settle()
  expect(f.history.mock.calls[1]?.[0]).toMatchObject({ cursor: 'page-two', start: first?.start, end: first?.end })
  await select('历史时间范围', '最近 7 天')
  const latest = f.history.mock.calls.at(-1)?.[0]!
  expect(latest.cursor).toBe(''); expect(Date.parse(latest.end!) - Date.parse(latest.start!)).toBe(7 * 24 * 3600_000)
})

it('replaces an old pending tab request and ignores its late error', async () => {
  const f = fixture(); let reject!: (error: Error) => void
  f.current.mockImplementation(() => new Promise((_, no) => { reject = no }))
  await mount('/alerts', f.client); const signal = f.current.mock.calls[0]?.[3]!
  button('告警历史').click(); await settle(); reject(new Error('过期当前异常错误')); await settle()
  expect(signal.aborted).toBe(true); expect(host.textContent).toContain('CPU 已恢复'); expect(host.textContent).not.toContain('过期当前异常错误')
})

it('pauses in background, resumes once and never overlaps scheduled refreshes', async () => {
  const f = fixture(); let resolve!: (value: { items: V3HealthState[]; next_cursor: string }) => void
  f.current.mockResolvedValueOnce({ items: [state()], next_cursor: '' }).mockImplementationOnce(() => new Promise(yes => { resolve = yes })).mockResolvedValue({ items: [state()], next_cursor: '' })
  await mount('/alerts', f.client); await vi.advanceTimersByTimeAsync(30_000); await settle(); await vi.advanceTimersByTimeAsync(90_000)
  expect(f.current).toHaveBeenCalledTimes(2)
  Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange'))
  expect(f.current.mock.calls[1]?.[3]?.aborted).toBe(true)
  resolve({ items: [], next_cursor: '' }); await settle(); await vi.advanceTimersByTimeAsync(60_000); expect(f.current).toHaveBeenCalledTimes(2)
  Object.defineProperty(document, 'hidden', { configurable: true, value: false }); document.dispatchEvent(new Event('visibilitychange')); await settle()
  expect(f.current).toHaveBeenCalledTimes(3); expect(host.textContent).toContain('CPU 持续偏高')
  app!.unmount(); app = undefined; await vi.advanceTimersByTimeAsync(60_000); expect(f.current).toHaveBeenCalledTimes(3)
})

it('never describes a first failed query as no anomalies, and retains old results on later failures', async () => {
  const f = fixture(); f.current.mockRejectedValueOnce(new Error('当前异常服务不可用')).mockResolvedValueOnce({ items: [state()], next_cursor: '' }).mockRejectedValue(new Error('刷新失败'))
  await mount('/alerts', f.client)
  expect(host.textContent).toContain('告警读取失败'); expect(host.textContent).not.toContain('当前筛选下暂无异常')
  button('刷新').click(); await settle(); await vi.advanceTimersByTimeAsync(30_000); await settle()
  expect(host.textContent).toContain('CPU 持续偏高'); expect(host.textContent).toContain('刷新失败；保留上一次结果')
})

it('binds selected notification deletion to the correct channel and exact large record identity', async () => {
  const f = fixture(); f.notifications.mockResolvedValue({ items: [notification(true)], next_cursor: '', start: 'a', end: 'b' })
  const preview = vi.spyOn(f.client, 'previewHistory').mockResolvedValue({ token: 'safe-preview', scope: { categories: ['email'] }, settings_version: 1, eligible: 1, protected: 0, expires_at: '2026-10-18T01:00:00Z' })
  await mount('/alerts?tab=email', f.client); button('删除').click(); await settle()
  expect(preview.mock.calls[0]?.[0]).toEqual({ categories: ['email'], records: ['notification:9007199254740993'], include_probes: true })
  expect(document.querySelector('.v3-node-dialog')?.textContent).toContain('仅处理当前页明确选择的 1 条')
})

it('does not offer deletion to viewers, even for otherwise eligible completed history', async () => {
  const f = fixture(); await mount('/alerts?tab=history', f.client, 'viewer')
  expect(host.textContent).toContain('CPU 已恢复'); expect(host.textContent).not.toContain('删除已选')
  expect(Array.from(host.querySelectorAll('button')).some(value => value.textContent?.trim() === '删除')).toBe(false)
})

it('returns to the first page when cleanup empties the current cursor', async () => {
  const f = fixture(); f.history.mockResolvedValueOnce({ items: [], next_cursor: '', start: 'a', end: 'b' }).mockResolvedValue({ items: [record()], next_cursor: '', start: 'a', end: 'b' })
  const router = await mount('/alerts?tab=history&cursor=empty', f.client)
  expect(router.currentRoute.value.query.cursor).toBeUndefined(); expect(f.history.mock.calls.at(-1)?.[0]?.cursor).toBe('')
  expect(host.textContent).toContain('CPU 已恢复')
})


it('does not present an empty old result as a successful current status after a failed refresh or filter change', async () => {
  const f = fixture(); f.current.mockResolvedValueOnce({ items: [], next_cursor: '' }).mockRejectedValueOnce(new Error('读取中断'))
  const router = await mount('/alerts', f.client)
  expect(host.textContent).toContain('当前筛选下暂无异常')
  button('刷新').click(); await settle()
  expect(host.textContent).toContain('当前状态读取失败，上一次结果为空'); expect(host.textContent).not.toContain('当前筛选下暂无异常')
  f.current.mockImplementationOnce(() => new Promise(() => {}))
  await router.push('/alerts?node=node-b'); await settle()
  expect(host.textContent).toContain('正在读取当前筛选，上一次结果为空'); expect(host.textContent).not.toContain('当前筛选下暂无异常')
})

it('walks back to the last visited nonempty cursor page after cleanup rather than losing the browsing position', async () => {
  const f = fixture(); f.history.mockResolvedValueOnce({ items: [record()], next_cursor: 'page-two', start: 'a', end: 'b' })
    .mockResolvedValueOnce({ items: [record()], next_cursor: 'page-three', start: 'a', end: 'b' })
    .mockResolvedValueOnce({ items: [record()], next_cursor: '', start: 'a', end: 'b' })
    .mockResolvedValueOnce({ items: [], next_cursor: '', start: 'a', end: 'b' })
    .mockResolvedValue({ items: [record()], next_cursor: '', start: 'a', end: 'b' })
  const router = await mount('/alerts?tab=history', f.client)
  button('下一页').click(); await settle(); button('下一页').click(); await settle()
  expect(router.currentRoute.value.query.cursor).toBe('page-three')
  button('刷新').click(); await settle()
  expect(router.currentRoute.value.query.cursor).toBe('page-two'); expect(f.history.mock.calls.at(-1)?.[0]?.cursor).toBe('page-two')
  expect(host.textContent).toContain('CPU 已恢复')
})


it('opens exact website history from a detail link without including other sites on the same server', async () => {
  const f = fixture(); await mount('/alerts?tab=history&source=website&site=2', f.client)
  expect(f.websites.mock.calls[0]?.[0]).toBe(2); expect(host.textContent).toContain('当前网站：示例网站')
  button('清除网站筛选').click(); await settle(); expect(f.websites.mock.calls.at(-1)?.[0]).toBeUndefined()
})
