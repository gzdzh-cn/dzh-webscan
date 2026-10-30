// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { installElements } from '../elements'
import { ControlV3, type V3Event, type V3EventPage, type V3HistoryJob } from '../controlV3'
import { cancelReadRequests } from '../connection'
import { consoleContext } from './context'
import Events from './Events.vue'

let app: App | undefined, host: HTMLDivElement
const event = (id = 'one', canDelete = false): V3Event => ({ node: 'node-a', id, received_at: '2026-10-18T00:00:00Z', payload: { path: `/data/${id}.php`, operation: 'modify' }, source: 'events', record_key: `event:${id}`, can_delete: canDelete, delete_reason: canDelete ? '' : '最近 24 小时受保护' })
const page = (id = 'one', cursor = ''): V3EventPage => ({ items: [event(id)], next_cursor: cursor, start: '2026-10-17T00:00:00Z', end: '2026-10-18T00:00:00Z' })
const historyJob = (status: V3HistoryJob['status'] = 'running'): V3HistoryJob => ({ id: 'cleanup-one', username: 'admin', kind: 'cleanup', export_first: true, settings_version: 1, cutoff: '2026-10-17T00:00:00Z', phase: 'cleanup', status, scanned: 2, deleted: 1, skipped: 1, dependent_deleted: 0, exported: 2, export_bytes: 200, export_ready: true, export_expires_at: '2026-10-19T00:00:00Z', message: '保护条件已变化，部分记录跳过', created_at: '2026-10-18T00:00:00Z', updated_at: '2026-10-18T00:00:00Z', finished_at: null })
async function settle() { for (let i = 0; i < 40; i++) { await Promise.resolve(); await nextTick() } }
async function mount(path = '/events', client = new ControlV3(), username = 'admin', role: 'admin' | 'viewer' = 'admin') {
  const options = vi.spyOn(client, 'servers').mockResolvedValue({ items: [{ id: 'node-a', name: '服务器 A', endpoint: '192.0.2.1:19100', server_name: 'a.example.test', enabled: true, mode: 'native', version: 1, applied_version: 1, shard: 1 }], next_cursor: '', limit: 20 })
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/events', component: Events }, { path: '/servers', component: { render: () => null } }] })
  await router.push(path); await router.isReady()
  host = document.createElement('div'); document.body.append(host)
  app = createApp(Events); app.use(router); installElements(app)
  app.provide(consoleContext, { client, session: ref({ username, role, csrf: 'test-csrf' }) }); app.mount(host); await settle()
  return { router, options }
}
function button(text: string, root: ParentNode = host) { const value = Array.from(root.querySelectorAll('button')).find(value => value.textContent?.trim() === text); if (!value) throw new Error(`button missing: ${text}`); return value }
function keyword(value: string) { const field = host.querySelector<HTMLInputElement>('input[aria-label="事件关键词"]')!; field.value = value; field.dispatchEvent(new Event('input', { bubbles: true })) }
const autoSwitch = () => host.querySelector<HTMLElement>('[role="switch"][aria-label="自动刷新"]')!
beforeEach(() => { vi.useFakeTimers(); localStorage.clear(); Object.defineProperty(document, 'hidden', { configurable: true, value: false }) })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(element => element.remove()); cancelReadRequests(true); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

it('never queries events on first entry, restored URLs or navigation history', async () => {
  const client = new ControlV3(), read = vi.spyOn(client, 'events').mockResolvedValue(page())
  const { router, options } = await mount('/events?node=node-a&q=one&include_probes=true', client)
  expect(options.mock.calls[0]?.slice(0, 3)).toEqual(['', '', 20])
  expect(read).not.toHaveBeenCalled(); expect(host.textContent).toContain('请选择筛选条件')
  await router.push('/events?node=node-a&q=two'); await settle(); router.back(); await settle()
  expect(read).not.toHaveBeenCalled(); expect(autoSwitch().getAttribute('aria-checked')).toBe('false')
  button('查询').click(); await settle()
  expect(read.mock.calls[0]?.[0]).toMatchObject({ node: 'node-a', q: 'one', include_probes: true, limit: 20 })
  expect(read.mock.calls[0]?.[2]).toBe(false)
})

it('preserves submitted filters and time window for paging while draft changes only update the URL', async () => {
  const client = new ControlV3(), read = vi.spyOn(client, 'events').mockResolvedValueOnce(page('first', 'cursor-two')).mockResolvedValue(page('second'))
  const { router } = await mount('/events?q=已提交', client)
  button('查询').click(); await settle(); keyword('待提交'); await settle()
  expect(router.currentRoute.value.query.q).toBe('待提交'); expect(read).toHaveBeenCalledTimes(1)
  expect(host.textContent).toContain('筛选条件已修改'); expect(host.textContent).toContain('/data/first.php')
  button('下一页').click(); await settle()
  expect(read.mock.calls[1]?.[0]).toMatchObject({ q: '已提交', cursor: 'cursor-two', start: '2026-10-17T00:00:00Z', end: '2026-10-18T00:00:00Z' })
  expect(host.textContent).toContain('第 2 页')
  button('查询').click(); await settle()
  expect(read.mock.calls[2]?.[0]).toMatchObject({ q: '待提交', cursor: '' }); expect(host.textContent).toContain('第 1 页')
})

it('clears the selected server without querying and submits the all-server scope explicitly', async () => {
  const client = new ControlV3(), read = vi.spyOn(client, 'events').mockResolvedValue(page())
  await mount('/events?node=node-a', client); button('查询').click(); await settle()
  host.querySelector('.el-select')!.dispatchEvent(new MouseEvent('mouseenter')); await settle()
  host.querySelector<HTMLElement>('.el-select__clear')!.click(); await settle()
  expect(read).toHaveBeenCalledTimes(1); button('查询').click(); await settle()
  expect(read.mock.calls[1]?.[0].node).toBe('')
  expect(read.mock.calls[1]?.[0].include_probes).toBe(false)
})

it('requires explicit probe opt-in and executes a keyword query on enter', async () => {
  const client = new ControlV3(), read = vi.spyOn(client, 'events').mockResolvedValue(page())
  await mount('/events?operation=probe', client); button('查询').click(); await settle()
  expect(read).not.toHaveBeenCalled(); expect(host.textContent).toContain('请先开启包含链路探针')
  host.querySelector<HTMLElement>('[role="switch"][aria-label="包含链路探针"]')!.click(); await settle()
  host.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); await settle()
  expect(read.mock.calls[0]?.[0]).toMatchObject({ operation: 'probe', include_probes: true })
})

it('invalidates old results and errors on a new manual query and aborts reads on exit', async () => {
  const client = new ControlV3(); let reject!: (error: Error) => void, resolve!: (value: V3EventPage) => void
  const read = vi.spyOn(client, 'events').mockImplementationOnce(() => new Promise((_, no) => { reject = no })).mockResolvedValueOnce(page('current')).mockImplementationOnce(() => new Promise(yes => { resolve = yes }))
  await mount('/events', client); button('查询').click(); await settle()
  const oldSignal = read.mock.calls[0]?.[1]!
  keyword('new'); await settle(); button('重新查询').click(); await settle(); reject(new Error('迟到错误')); await settle()
  expect(oldSignal.aborted).toBe(true); expect(host.textContent).toContain('/data/current.php'); expect(host.textContent).not.toContain('迟到错误')
  button('查询').click(); await settle(); const exitSignal = read.mock.calls[2]?.[1]!
  app!.unmount(); app = undefined; resolve(page('late')); await settle()
  expect(exitSignal.aborted).toBe(true); await vi.advanceTimersByTimeAsync(60_000); expect(read).toHaveBeenCalledTimes(3)
})

it('restores only the account interval preference, remains disabled until a successful query and never persists the switch', async () => {
  localStorage.setItem('webscan:v3:event-refresh:admin', '10'); localStorage.setItem('webscan:v3:event-refresh:other', '300')
  const client = new ControlV3(), read = vi.spyOn(client, 'events').mockResolvedValue(page())
  await mount('/events', client)
  expect(autoSwitch().getAttribute('aria-disabled')).toBe('true'); expect(host.textContent).toContain('10 秒')
  expect(host.querySelector('input[type="number"]')).toBeNull()
  button('查询').click(); await settle(); autoSwitch().click(); await settle()
  await vi.advanceTimersByTimeAsync(10_000); await settle(); expect(read).toHaveBeenCalledTimes(2)
  app!.unmount(); app = undefined; host.remove(); await mount('/events', new ControlV3(), 'other')
  expect(autoSwitch().getAttribute('aria-checked')).toBe('false'); expect(host.textContent).toContain('300 秒')
})

it('pauses on draft edits and background tabs, then resumes only the submitted conditions after a successful manual query', async () => {
  localStorage.setItem('webscan:v3:event-refresh:admin', '10')
  const client = new ControlV3(), read = vi.spyOn(client, 'events').mockResolvedValue(page())
  await mount('/events?q=original', client); button('查询').click(); await settle(); autoSwitch().click(); await settle()
  keyword('draft'); await settle(); await vi.advanceTimersByTimeAsync(20_000)
  expect(read).toHaveBeenCalledTimes(1); expect(autoSwitch().getAttribute('aria-checked')).toBe('true'); expect(host.textContent).toContain('已暂停，等待提交筛选')
  Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange'))
  Object.defineProperty(document, 'hidden', { configurable: true, value: false }); document.dispatchEvent(new Event('visibilitychange')); await settle()
  expect(read).toHaveBeenCalledTimes(1)
  button('查询').click(); await settle(); await vi.advanceTimersByTimeAsync(10_000); await settle()
  expect(read.mock.calls.at(-1)?.[0].q).toBe('draft'); expect(read).toHaveBeenCalledTimes(3)
  Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange')); await vi.advanceTimersByTimeAsync(30_000)
  expect(read).toHaveBeenCalledTimes(3)
  Object.defineProperty(document, 'hidden', { configurable: true, value: false }); document.dispatchEvent(new Event('visibilitychange')); await settle()
  expect(read).toHaveBeenCalledTimes(4)
})

it('does not overlap automatic requests, preserves failed data and waits a complete interval after completion', async () => {
  localStorage.setItem('webscan:v3:event-refresh:admin', '10')
  const client = new ControlV3(); let reject!: (error: Error) => void
  const read = vi.spyOn(client, 'events').mockResolvedValueOnce(page('kept')).mockImplementationOnce(() => new Promise((_, no) => { reject = no })).mockResolvedValue(page('recovered'))
  await mount('/events', client); button('查询').click(); await settle(); autoSwitch().click(); await settle()
  await vi.advanceTimersByTimeAsync(10_000); await settle(); await vi.advanceTimersByTimeAsync(60_000)
  expect(read).toHaveBeenCalledTimes(2)
  reject(new Error('自动查询失败')); await settle()
  expect(host.textContent).toContain('/data/kept.php'); expect(host.textContent).toContain('保留上一次查询结果')
  await vi.advanceTimersByTimeAsync(9000); expect(read).toHaveBeenCalledTimes(2)
  await vi.advanceTimersByTimeAsync(1000); await settle(); expect(read).toHaveBeenCalledTimes(3)
  expect(host.textContent).toContain('/data/recovered.php'); expect(host.textContent).not.toContain('自动查询失败')
})

it('keeps the current cursor on rolling refresh and returns to a visited valid page after cleanup', async () => {
  localStorage.setItem('webscan:v3:event-refresh:admin', '10')
  const client = new ControlV3(), read = vi.spyOn(client, 'events').mockResolvedValueOnce(page('first', 'next')).mockResolvedValueOnce(page('second')).mockResolvedValueOnce({ ...page(), items: [] }).mockResolvedValue(page('first-again'))
  await mount('/events', client); button('查询').click(); await settle(); button('下一页').click(); await settle()
  autoSwitch().click(); await settle(); await vi.advanceTimersByTimeAsync(10_000); await settle()
  expect(read.mock.calls[2]?.[0].cursor).toBe('next'); expect(read.mock.calls[2]?.[0].start).not.toBe('2026-10-17T00:00:00Z')
  expect(read.mock.calls[3]?.[0].cursor).toBe(''); expect(host.textContent).toContain('第 1 页'); expect(host.textContent).toContain('/data/first-again.php')
})

it('previews only explicit selected keys, retries one idempotent delete and reports partial completion accurately', async () => {
  const client = new ControlV3(), data = page(); data.items = [event('old', true)]
  vi.spyOn(client, 'events').mockResolvedValue(data)
  const preview = vi.spyOn(client, 'previewHistory').mockResolvedValue({ token: 'account-bound-preview', scope: { categories: ['events', 'security-events'] }, settings_version: 1, eligible: 1, protected: 0, expires_at: '2026-10-18T01:00:00Z' })
  const cleanup = vi.spyOn(client, 'cleanupHistory').mockRejectedValueOnce(new Error('响应中断，可重试')).mockResolvedValue(historyJob())
  vi.spyOn(client, 'historyJob').mockResolvedValue({ job: historyJob('partial'), scope: { categories: ['events'] } })
  await mount('/events', client); button('查询').click(); await settle(); button('删除').click(); await settle()
  const dialog = document.querySelector('.v3-node-dialog')!
  expect(preview.mock.calls[0]?.[0]).toEqual({ categories: ['events', 'security-events'], records: ['event:old'], include_probes: true })
  expect(dialog.textContent).toContain('永久删除不能撤销')
  button('导出并删除', dialog).click(); await settle(); expect(dialog.textContent).toContain('响应中断，可重试')
  button('导出并删除', dialog).click(); await settle()
  expect(cleanup.mock.calls[0]).toEqual(cleanup.mock.calls[1]); expect(cleanup.mock.calls[0]?.[1]).toEqual({ export_first: true, confirm_without_export: false })
  expect(dialog.textContent).toContain('部分完成'); expect(dialog.textContent).toContain('跳过 1 条'); expect(dialog.textContent).not.toContain('全部成功')
})

it('keeps protected rows unselectable and does not offer writes to a viewer', async () => {
  const client = new ControlV3(); vi.spyOn(client, 'events').mockResolvedValue(page())
  await mount('/events', client); button('查询').click(); await settle()
  expect(host.textContent).toContain('最近 24 小时受保护'); expect(button('删除').disabled).toBe(true)
  app!.unmount(); app = undefined; host.remove(); const viewer = new ControlV3(); vi.spyOn(viewer, 'events').mockResolvedValue(page())
  await mount('/events', viewer, 'viewer', 'viewer'); button('查询').click(); await settle()
  expect(host.textContent).not.toContain('删除已选'); expect(Array.from(host.querySelectorAll('button')).some(value => value.textContent?.trim() === '删除')).toBe(false)
})

it('changes the selected interval from the dropdown and stops immediately when switched off', async () => {
  const client = new ControlV3(), read = vi.spyOn(client, 'events').mockResolvedValue(page())
  await mount('/events', client); button('查询').click(); await settle(); autoSwitch().click(); await settle()
  await vi.advanceTimersByTimeAsync(29_000); expect(read).toHaveBeenCalledTimes(1)
  host.querySelector<HTMLInputElement>('input[aria-label="自动刷新间隔"]')!.click(); await settle()
  const option = Array.from(document.querySelectorAll<HTMLElement>('[role="option"]')).find(value => value.textContent?.trim() === '60 秒')!
  option.click(); await settle()
  expect(localStorage.getItem('webscan:v3:event-refresh:admin')).toBe('60')
  await vi.advanceTimersByTimeAsync(59_000); expect(read).toHaveBeenCalledTimes(1)
  await vi.advanceTimersByTimeAsync(1000); await settle(); expect(read).toHaveBeenCalledTimes(2)
  autoSwitch().click(); await settle(); await vi.advanceTimersByTimeAsync(120_000); expect(read).toHaveBeenCalledTimes(2)
})

it('restores only filters after back navigation even if the page was queried and refreshing', async () => {
  const client = new ControlV3(), read = vi.spyOn(client, 'events').mockResolvedValue(page())
  const { router } = await mount('/events?q=first', client)
  button('查询').click(); await settle(); autoSwitch().click(); await settle()
  await router.push('/events?q=second'); await settle(); router.back(); await settle()
  await vi.advanceTimersByTimeAsync(60_000); await settle()
  expect(read).toHaveBeenCalledTimes(1); expect(host.textContent).toContain('请选择筛选条件')
  expect(autoSwitch().getAttribute('aria-checked')).toBe('false')
})

it('pauses refreshing after a failed manual replacement without labeling the old data as a new success', async () => {
  localStorage.setItem('webscan:v3:event-refresh:admin', '10')
  const client = new ControlV3(), read = vi.spyOn(client, 'events').mockResolvedValueOnce(page('old')).mockRejectedValueOnce(new Error('新条件查询失败')).mockResolvedValue(page('new'))
  await mount('/events', client); button('查询').click(); await settle(); autoSwitch().click(); await settle()
  keyword('new-filter'); await settle(); button('查询').click(); await settle(); await vi.advanceTimersByTimeAsync(30_000)
  expect(read).toHaveBeenCalledTimes(2); expect(host.textContent).toContain('/data/old.php'); expect(host.textContent).toContain('已暂停，等待查询成功')
  expect(button('下一页').disabled).toBe(true)
  button('查询').click(); await settle(); await vi.advanceTimersByTimeAsync(10_000); await settle(); expect(read).toHaveBeenCalledTimes(4)
})

it('never submits dirty event filters merely because page size changes', async () => {
 const client=new ControlV3(),read=vi.spyOn(client,'events').mockResolvedValue(page('original'))
 await mount('/events?q=已提交',client);button('查询').click();await settle();keyword('草稿');await settle()
 host.querySelector<HTMLInputElement>('[aria-label="每页条数"]')!.click();await settle()
 Array.from(document.querySelectorAll<HTMLElement>('[role="option"]')).find(el=>el.textContent?.trim()==='50 条／页')!.click();await settle()
 expect(read).toHaveBeenCalledTimes(1);expect(host.textContent).toContain('筛选条件已修改')
 button('查询').click();await settle();expect(read.mock.calls.at(-1)?.[0]).toMatchObject({q:'草稿',limit:50,cursor:''})
})
