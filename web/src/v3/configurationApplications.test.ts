// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://monitor.example.test/configuration-applications"}
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { createRouter, createMemoryHistory, RouterView } from 'vue-router'
import { installElements } from '../elements'
import { ControlV3, V3Error, type V3ConfigurationApplication, type V3ConfigurationApplicationLog } from '../controlV3'
import { consoleContext } from './context'
import Page from './ConfigurationApplications.vue'

let app: App | undefined, host: HTMLDivElement
const id = 'a'.repeat(64), secondID = 'b'.repeat(64)
async function settle() { for (let i = 0; i < 35; i++) { await Promise.resolve(); await nextTick() } }
function job(status: V3ConfigurationApplication['status'] = 'running', jobID = id): V3ConfigurationApplication {
  return { id: jobID, stage: 'c'.repeat(64), generation: '9007199254740993', username: 'admin', controller: 'admin', status, direction: 'forward', phase: status === 'succeeded' ? 'complete' : 'environment', recovery_required: false, recovery_hold: false, error_code: '', log_cursor: '1', created_at: '', updated_at: '', finished_at: null }
}
function line(cursor = '1'): V3ConfigurationApplicationLog { return { cursor, direction: 'forward', phase: 'environment', code: 'claimed', created_at: '' } }
function fixture() {
  const client = new ControlV3()
  const list = vi.spyOn(client, 'configurationApplications').mockResolvedValue({ items: [job()], next_cursor: 'next-page' })
  const logs = vi.spyOn(client, 'configurationApplicationLogs').mockResolvedValueOnce({ job: job(), items: [line()], next_cursor: '1' }).mockResolvedValue({ job: job(), items: [], next_cursor: '1' })
  return { client, list, logs }
}
async function mount(client: ControlV3, path = `/configuration-applications/${id}`, role: 'admin' | 'operator' | 'viewer' = 'admin') {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/configuration-applications/:id?', component: Page }, { path: '/:pathMatch(.*)*', component: { render: () => null } }] })
  await router.push(path); await router.isReady()
  host = document.createElement('div'); document.body.append(host); app = createApp(RouterView); installElements(app)
  app.provide(consoleContext, { client, session: ref({ username: 'admin', role, csrf: 'csrf' }) }); app.use(router); app.mount(host); await settle()
  return router
}
function button(text: string) { const b = Array.from(host.querySelectorAll('button')).find(b => b.textContent?.trim() === text); if (!b) throw new Error(`missing ${text}`); return b }
beforeEach(() => { vi.useFakeTimers(); Object.defineProperty(document, 'hidden', { value: false, configurable: true }) })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); vi.useRealTimers(); vi.restoreAllMocks(); Object.defineProperty(document, 'hidden', { value: false, configurable: true }) })

it('reads durable application progress from string cursors, stops at completion and exposes no control buttons', async () => {
  const f = fixture(); await mount(f.client)
  expect(host.textContent).toContain('9007199254740993'); expect(host.textContent).toContain('已读至 #1'); expect(host.querySelectorAll('.v3-logs li')).toHaveLength(1)
  f.logs.mockResolvedValue({ job: job('succeeded'), items: [line('2')], next_cursor: '2' })
  await vi.advanceTimersByTimeAsync(3000); await settle()
  expect(f.logs.mock.calls[1]?.slice(0, 3)).toEqual([id, '1', 100]); expect(host.textContent).toContain('本次应用完成')
  expect(host.querySelectorAll('.v3-logs li')).toHaveLength(2)
  await vi.advanceTimersByTimeAsync(30000); expect(f.logs).toHaveBeenCalledTimes(2)
  expect(Array.from(host.querySelectorAll('button')).map(b => b.textContent?.trim())).toEqual(['刷新应用进度'])
})
it('keeps last progress on failure, retries without resetting the cursor, and stops when unmounted', async () => {
  const f = fixture(); await mount(f.client)
  f.logs.mockRejectedValueOnce(new Error('连接暂时中断'))
  await vi.advanceTimersByTimeAsync(3000); await settle()
  expect(host.textContent).toContain('上次读取结果保留'); expect(host.querySelectorAll('.v3-logs li')).toHaveLength(1)
  await vi.advanceTimersByTimeAsync(3000); await settle(); expect(f.logs.mock.calls[2]?.[1]).toBe('1')
  app!.unmount(); app = undefined; await vi.advanceTimersByTimeAsync(30000); expect(f.logs).toHaveBeenCalledTimes(3)
})
it('rejects a gapped log response without changing displayed progress or the resume cursor', async () => {
  const f = fixture(); await mount(f.client)
  f.logs.mockResolvedValueOnce({ job: job('succeeded'), items: [line('3')], next_cursor: '3' })
  await vi.advanceTimersByTimeAsync(3000); await settle()
  expect(host.textContent).toContain('日志游标不连续'); expect(host.textContent).toContain('已读至 #1'); expect(host.textContent).toContain('应用中')
  await vi.advanceTimersByTimeAsync(3000); expect(f.logs.mock.calls[2]?.[1]).toBe('1')
})
it('pauses hidden tabs, aborts the old request and resumes once without overlapping requests', async () => {
  const f = fixture(); let resolve!: (r: Awaited<ReturnType<ControlV3['configurationApplicationLogs']>>) => void
  f.logs.mockReset().mockImplementationOnce(() => new Promise(yes => { resolve = yes })).mockResolvedValue({ job: job(), items: [line()], next_cursor: '1' })
  await mount(f.client)
  button('刷新应用进度').click(); await settle(); await vi.advanceTimersByTimeAsync(3000); expect(f.logs).toHaveBeenCalledTimes(1)
  Object.defineProperty(document, 'hidden', { value: true, configurable: true }); document.dispatchEvent(new Event('visibilitychange'))
  expect(f.logs.mock.calls[0]?.[3]?.aborted).toBe(true)
  resolve({ job: job(), items: [line()], next_cursor: '1' }); await settle(); expect(host.textContent).not.toContain('已读至 #1')
  await vi.advanceTimersByTimeAsync(10000); expect(f.logs).toHaveBeenCalledTimes(1)
  Object.defineProperty(document, 'hidden', { value: false, configurable: true }); document.dispatchEvent(new Event('visibilitychange')); await settle()
  expect(f.logs).toHaveBeenCalledTimes(2); expect(f.logs.mock.calls[1]?.[1]).toBe('0')
})
it('clears old route data and ignores a late previous-task response', async () => {
  const f = fixture(); let resolve!: (r: Awaited<ReturnType<ControlV3['configurationApplicationLogs']>>) => void
  f.logs.mockReset().mockImplementationOnce(() => new Promise(yes => { resolve = yes }))
  const router = await mount(f.client)
  f.logs.mockResolvedValue({ job: job('failed', secondID), items: [line()], next_cursor: '1' })
  await router.push(`/configuration-applications/${secondID}`); await settle()
  expect(f.logs.mock.calls[1]?.slice(0, 2)).toEqual([secondID, '0']); expect(host.textContent).toContain('应用未完成')
  resolve({ job: job('succeeded'), items: [line()], next_cursor: '1' }); await settle()
  expect(host.textContent).not.toContain('本次应用完成 ·'); expect(host.textContent).toContain(secondID)
})
it('lists and pages applications using the committed stage filter', async () => {
  const f = fixture(), stage = 'c'.repeat(64)
  await mount(f.client, `/configuration-applications?stage=${stage}`)
  expect(f.list.mock.calls[0]?.slice(0, 3)).toEqual([stage, '', 20]); expect(f.logs).not.toHaveBeenCalled()
  expect(host.querySelector('a[href*="/configuration-applications/"]')?.getAttribute('href')).toBe(`/configuration-applications/${id}`)
  button('下一页').click(); await settle(); expect(f.list.mock.calls[1]?.slice(0, 3)).toEqual([stage, 'next-page', 20])
})
it.each(['operator', 'viewer'] as const)('does not query admin application history as %s', async role => {
  const f = fixture(); await mount(f.client, `/configuration-applications/${id}`, role)
  expect(f.logs).not.toHaveBeenCalled(); expect(f.list).not.toHaveBeenCalled(); expect(host.textContent).toContain('只有管理员')
})

it('confirms the signed snapshot cursor, freezes polling and retries the same ambiguous control', async () => {
  const f = fixture(), failed = { ...job('failed'), log_cursor: '9007199254740993' }
  f.logs.mockReset().mockResolvedValue({ job: failed, items: [line()], next_cursor: '1', can_resume: true, can_rollback: false, can_cancel: true })
  const write = vi.spyOn(f.client, 'controlConfigurationApplication').mockRejectedValueOnce(new Error('响应丢失')).mockResolvedValue(job('queued'))
  await mount(f.client); button('继续应用').click(); await settle()
  expect(host.textContent).toContain('确认版本 #9007199254740993')
  await vi.advanceTimersByTimeAsync(12000); expect(f.logs).toHaveBeenCalledTimes(1); expect(write).not.toHaveBeenCalled()
  button('确认继续应用').click(); await settle(); expect(host.textContent).toContain('响应丢失')
  button('确认继续应用').click(); await settle()
  expect(write.mock.calls[0]?.slice(0, 4)).toEqual(write.mock.calls[1]?.slice(0, 4))
  expect(write.mock.calls[0]?.slice(0, 3)).toEqual([id, 'resume', '9007199254740993'])
  expect(f.logs).toHaveBeenCalledTimes(2)
})
it('requires a new confirmation after a cursor conflict and hides actions on a stale read', async () => {
  const f = fixture()
  f.logs.mockReset().mockResolvedValue({ job: job('failed'), items: [line()], next_cursor: '1', can_resume: true })
  const write = vi.spyOn(f.client, 'controlConfigurationApplication').mockRejectedValue(new V3Error(409, 'application_conflict', '任务状态已变化，请重新确认'))
  await mount(f.client); button('继续应用').click(); await settle()
  f.logs.mockResolvedValue({ job: { ...job('failed'), log_cursor: '2' }, items: [line('2')], next_cursor: '2', can_resume: true })
  button('确认继续应用').click(); await settle()
  expect(host.textContent).toContain('任务状态已变化'); expect(host.querySelector('[aria-label="配置应用操作确认"]')).toBeNull()
  button('继续应用').click(); await settle(); expect(host.textContent).toContain('确认版本 #2')
  button('返回查看').click(); await settle()
  f.logs.mockRejectedValueOnce(new Error('读取失败')); button('刷新应用进度').click(); await settle()
  expect(button('继续应用').disabled).toBe(true); expect(write).toHaveBeenCalledTimes(1)
})
it('aborts a control on route change and ignores its late response', async () => {
  const f = fixture(); f.logs.mockReset().mockResolvedValue({ job: job('failed'), items: [line()], next_cursor: '1', can_cancel: true })
  let resolve!: (value: V3ConfigurationApplication) => void
  const write = vi.spyOn(f.client, 'controlConfigurationApplication').mockImplementation(() => new Promise(yes => { resolve = yes }))
  const router = await mount(f.client); button('取消应用').click(); await settle(); button('确认取消应用').click(); await settle()
  expect(button('确认取消应用').disabled).toBe(true)
  f.logs.mockResolvedValue({ job: job('failed', secondID), items: [line()], next_cursor: '1' })
  await router.push(`/configuration-applications/${secondID}`); await settle()
  expect(write.mock.calls[0]?.[4]?.aborted).toBe(true); resolve(job('cancelled')); await settle()
  expect(host.textContent).toContain(secondID); expect(host.textContent).not.toContain('应用已取消')
})
