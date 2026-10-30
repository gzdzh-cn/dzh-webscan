// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { installElements } from '../elements'
import { ControlV3, type V3Site, type V3WebsiteOverview } from '../controlV3'
import { cancelReadRequests } from '../connection'
import { consoleContext } from './context'
import Websites from './Websites.vue'

let app: App | undefined, host: HTMLDivElement
const site = (id = 1): V3Site => ({ id, name: `业务网站 ${id}`, url: `https://site${id}.example.test/`, node: 'node-a', keyword: '欢迎', slow_alert: true, paused: false, version: 3, state: { status: 'normal', last: { time: 1792200000, ok: true, latency: 0, http_status: 200, cert_expires: 0, reason: '' }, checks: 1, passed: 1, failures: 0, successes: 1 } })
const summary = (): V3WebsiteOverview => ({ total: 1, normal: 1, down: 0, pending: 0, paused: 0, migration_pending: 0, unknown: 0, due: 0, notification_outbox: { pending: 0, oldest_wait_seconds: null }, notification_worker: { heartbeat: null, healthy: null }, scheduler: { heartbeat: null, healthy: null } })
async function settle() { for (let i = 0; i < 40; i++) { await Promise.resolve(); await nextTick() } }
function fixture() {
  const client = new ControlV3(), list = vi.spyOn(client, 'websites').mockResolvedValue({ items: [site()], next_cursor: '', limit: 20 })
  const detail = vi.spyOn(client, 'website').mockImplementation(async id => site(id)), overview = vi.spyOn(client, 'websiteOverview').mockResolvedValue(summary())
  vi.spyOn(client, 'servers').mockResolvedValue({ items: [], next_cursor: '', limit: 20 })
  return { client, list, detail, overview }
}
async function mount(path = '/websites', client = fixture().client, role: 'admin' | 'viewer' = 'admin') {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/websites/:id?', component: Websites }, { path: '/alerts', component: { render: () => null } }] })
  await router.push(path); await router.isReady()
  host = document.createElement('div'); document.body.append(host)
  app = createApp(Websites); app.use(router); installElements(app); app.provide(consoleContext, { client, session: ref({ username: 'admin', role, csrf: 'csrf' }) })
  app.mount(host); await settle(); return router
}
function button(text: string, root: ParentNode = host) { const value = Array.from(root.querySelectorAll('button')).find(value => value.textContent?.trim() === text); if (!value) throw new Error(`button missing: ${text}`); return value }
function input(field: HTMLInputElement, text: string) { field.value = text; field.dispatchEvent(new Event('input', { bubbles: true })) }
function dialog() { return document.querySelector<HTMLElement>('.v3-node-dialog')! }
beforeEach(() => { vi.useFakeTimers(); Object.defineProperty(document, 'hidden', { configurable: true, value: false }) })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(value => value.remove()); cancelReadRequests(true); vi.useRealTimers(); vi.restoreAllMocks() })

it('loads only the requested server-side page and leaves unsent keyword out of pagination', async () => {
  const f = fixture(); f.list.mockResolvedValue({ items: [site()], next_cursor: 'page-two', limit: 20 })
  const router = await mount('/websites?q=已提交&node=node-a&status=normal', f.client)
  expect(f.list.mock.calls[0]?.[0]).toEqual({ q: '已提交', node: 'node-a', status: 'normal', cursor: '', limit: 20 })
  input(host.querySelector('input[aria-label="网站名称或网址"]')!, '未提交')
  button('下一页').click(); await settle()
  expect(f.list.mock.calls.at(-1)?.[0]).toMatchObject({ q: '已提交', cursor: 'page-two' })
  router.back(); await settle(); expect(f.list.mock.calls.at(-1)?.[0]?.cursor).toBe('')
  expect(host.textContent).toContain('0 ms')
})

it('saves a new website with visible error feedback and reuses its key only for the same retried content', async () => {
  const f = fixture(), save = vi.spyOn(f.client, 'saveWebsite').mockRejectedValueOnce(new Error('磁盘暂时不可用')).mockResolvedValue({ id: 2, version: 1, message: '网站配置已保存' })
  await mount('/websites', f.client); button('添加网站').click(); await settle()
  const fields = dialog().querySelectorAll<HTMLInputElement>('input.el-input__inner')
  input(fields[0]!, '新增网站'); input(fields[1]!, 'https://new.example.test/'); await settle()
  button('保存', dialog()).click(); await settle()
  expect(dialog().querySelector('.v3-dialog-feedback')?.textContent).toContain('磁盘暂时不可用')
  expect(fields[0]?.value).toBe('新增网站')
  button('保存', dialog()).click(); await settle()
  expect(save).toHaveBeenCalledTimes(2); expect(save.mock.calls[0]?.[2]).toBe(save.mock.calls[1]?.[2])
  expect(save.mock.calls[0]?.slice(0, 2)).toEqual([{ id: 0, name: '新增网站', url: 'https://new.example.test/', node: '', keyword: '', slow_alert: false, paused: false }, 0])
  expect(host.textContent).toContain('网站配置已保存')
})

it('validates fields before saving and preserves the edited version and paused state', async () => {
  const f = fixture(), paused = { ...site(), paused: true }; f.list.mockResolvedValue({ items: [paused], next_cursor: '', limit: 20 })
  const save = vi.spyOn(f.client, 'saveWebsite').mockResolvedValue({ id: 1, version: 4, message: '已保存暂停状态' })
  await mount('/websites', f.client); button('编辑').click(); await settle()
  const fields = dialog().querySelectorAll<HTMLInputElement>('input.el-input__inner')
  input(fields[1]!, 'https://secret:password@example.test/'); await settle(); button('保存', dialog()).click(); await settle()
  expect(save).not.toHaveBeenCalled(); expect(dialog().textContent).toContain('网址不能包含账号或密码')
  input(fields[1]!, 'https://changed.example.test/'); await settle(); button('保存', dialog()).click(); await settle()
  expect(save.mock.calls[0]?.[0]).toMatchObject({ id: 1, paused: true, url: 'https://changed.example.test/' }); expect(save.mock.calls[0]?.[1]).toBe(3)
})

it('queues an explicit check without claiming that the check has completed', async () => {
  const f = fixture(), check = vi.spyOn(f.client, 'checkWebsite').mockResolvedValue({ id: 1, message: '已加入检测队列' })
  await mount('/websites', f.client); button('检测').click(); await settle()
  expect(check.mock.calls[0]?.slice(0, 2)).toEqual([1, 3]); expect(host.textContent).toContain('当前结果尚未更新')
  expect(host.textContent).not.toContain('检测成功')
})

it('confirms soft deletion of exactly one selected version and keeps the scope stable after a retry', async () => {
  const f = fixture(); f.list.mockResolvedValue({ items: [site(), site(2)], next_cursor: '', limit: 20 })
  const remove = vi.spyOn(f.client, 'deleteWebsites').mockRejectedValueOnce(new Error('网站版本已变更')).mockResolvedValueOnce({ deleted: 1, message: '已软删除；故障历史及排队通知保留' })
  await mount('/websites', f.client); button('删除').click(); await settle()
  expect(dialog().textContent).toContain('明确选择的 1 个网站'); expect(dialog().textContent).toContain('不发送恢复通知')
  button('确认软删除', dialog()).click(); await settle(); expect(dialog().textContent).toContain('网站版本已变更')
  button('确认软删除', dialog()).click(); await settle()
  expect(remove.mock.calls[0]?.[0]).toEqual([{ id: 1, version: 3 }]); expect(remove.mock.calls[0]?.[1]).toBe(remove.mock.calls[1]?.[1])
  expect(host.textContent).toContain('1 个网站')
})

it('allows only explicitly checked current-page rows in a batch', async () => {
  const f = fixture(); f.list.mockResolvedValue({ items: [site(), site(2)], next_cursor: '', limit: 20 })
  const remove = vi.spyOn(f.client, 'deleteWebsites').mockResolvedValue({ deleted: 2, message: '已软删除' })
  await mount('/websites', f.client)
  const boxes = host.querySelectorAll<HTMLInputElement>('input[type="checkbox"]'); boxes[0]!.click(); await vi.advanceTimersByTimeAsync(20); await settle()
  button('删除已选（2）').click(); await settle(); button('确认软删除', dialog()).click(); await settle()
  expect(remove.mock.calls[0]?.[0]).toEqual([{ id: 1, version: 3 }, { id: 2, version: 3 }])
})

it('protects migration-pending sites and disables checks for paused sites', async () => {
  const f = fixture(); f.list.mockResolvedValue({ items: [{ ...site(), migration_pending: true }, { ...site(2), paused: true }], next_cursor: '', limit: 20 })
  await mount('/websites', f.client)
  const editButtons = Array.from(host.querySelectorAll<HTMLButtonElement>('button')).filter(b => b.textContent?.trim() === '编辑')
  const checks = Array.from(host.querySelectorAll<HTMLButtonElement>('button')).filter(b => b.textContent?.trim() === '检测')
  expect(editButtons[0]?.disabled).toBe(true); expect(editButtons[1]?.disabled).toBe(false); expect(checks.every(b => b.disabled)).toBe(true)
  expect(host.textContent).toContain('等待迁移切换'); expect(host.textContent).toContain('已暂停')
})

it('does not offer website changes or selection to a viewer', async () => {
  const f = fixture(); await mount('/websites', f.client, 'viewer')
  expect(host.textContent).not.toContain('添加网站'); expect(host.textContent).not.toContain('删除已选'); expect(host.querySelector('input[type="checkbox"]')).toBeNull()
})

it('cancels earlier query results and errors when navigating, and does not mix detail data', async () => {
  const f = fixture(); let resolve!: (value: V3Site) => void
  f.detail.mockImplementationOnce(() => new Promise(yes => { resolve = yes }))
  const router = await mount('/websites/1', f.client), signal = f.detail.mock.calls[0]?.[1]!
  await router.push('/websites/2'); await settle(); resolve(site(1)); await settle()
  expect(signal.aborted).toBe(true); expect(host.querySelector('h1')?.textContent).toBe('业务网站 2')
  expect(f.list).not.toHaveBeenCalled(); expect(f.overview).not.toHaveBeenCalled()
})

it('pauses refresh while editing and in the background, and stops after unmount', async () => {
  const f = fixture(); await mount('/websites', f.client)
  button('添加网站').click(); await settle(); await vi.advanceTimersByTimeAsync(60_000); expect(f.list).toHaveBeenCalledTimes(1)
  button('取消', dialog()).click(); await settle(); await vi.advanceTimersByTimeAsync(30_000); expect(f.list).toHaveBeenCalledTimes(2)
  Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange')); await vi.advanceTimersByTimeAsync(60_000)
  expect(f.list).toHaveBeenCalledTimes(2)
  Object.defineProperty(document, 'hidden', { configurable: true, value: false }); document.dispatchEvent(new Event('visibilitychange')); await settle(); expect(f.list).toHaveBeenCalledTimes(3)
  app!.unmount(); app = undefined; await vi.advanceTimersByTimeAsync(60_000); expect(f.list).toHaveBeenCalledTimes(3)
})

it('retains old summary and results after failure and displays missing summary as unknown', async () => {
  const f = fixture(); f.overview.mockRejectedValueOnce(new Error('统计不可用')).mockResolvedValueOnce(summary())
  await mount('/websites', f.client)
  expect(Array.from(host.querySelectorAll('.v3-stats strong')).map(el => el.textContent)).toEqual(['—', '—', '—', '—', '—', '—'])
  button('刷新').click(); await settle(); f.overview.mockRejectedValue(new Error('统计暂时失败')); f.list.mockRejectedValue(new Error('网站读取失败'))
  button('刷新').click(); await settle()
  expect(host.textContent).toContain('业务网站 1'); expect(host.textContent).toContain('上一次统计保留')
  expect(host.querySelector('.v3-stats strong')?.textContent).toBe('1')
})

it('returns to a known previous page after deletion leaves the current page empty', async () => {
  const f = fixture(); f.list.mockResolvedValueOnce({ items: [site()], next_cursor: 'two', limit: 20 })
    .mockResolvedValueOnce({ items: [site(2)], next_cursor: 'three', limit: 20 })
    .mockResolvedValueOnce({ items: [site(3)], next_cursor: '', limit: 20 })
    .mockResolvedValueOnce({ items: [], next_cursor: '', limit: 20 }).mockResolvedValue({ items: [site(2)], next_cursor: '', limit: 20 })
  const router = await mount('/websites', f.client); button('下一页').click(); await settle(); button('下一页').click(); await settle(); button('刷新').click(); await settle()
  expect(router.currentRoute.value.query.cursor).toBe('two'); expect(host.textContent).toContain('业务网站 2')
})
