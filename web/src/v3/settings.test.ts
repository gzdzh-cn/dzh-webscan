// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App, type Component } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { installElements } from '../elements'
import { ControlV3, type V3RetentionStatus, type V3HistoryJob, type V3HistoryPreview } from '../controlV3'
import { consoleContext } from './context'
import { cancelReadRequests } from '../connection'
import Settings from './Settings.vue'
import HistoryStorage from './HistoryStorage.vue'
import HistoryTask from './HistoryTask.vue'
import HistoryJobs from './HistoryJobs.vue'
import Audit from './Audit.vue'

let app: App | undefined, host: HTMLDivElement
const policy = () => ({ sqlite_events_days: 30, security_events_days: 30, website_incidents_days: 30, server_alerts_days: 15, delivery_records_days: 30 })
const status = (version = 1): V3RetentionStatus => ({ policy: { version, policy: policy(), updated_at: '2026-10-18T00:00:00Z' }, last_job: null, managed_storage_bytes: 1048576, worker_heartbeat: null, worker_healthy: null, reason: '' })
const job = (state: V3HistoryJob['status'] = 'queued'): V3HistoryJob => ({ id: 'a'.repeat(64), username: 'admin', kind: 'cleanup', export_first: true, settings_version: 1, cutoff: '2026-09-18T00:00:00Z', phase: state === 'queued' ? 'export' : 'finished', status: state, scanned: 2, deleted: 0, skipped: 1, dependent_deleted: 0, exported: 1, export_bytes: 128, export_ready: false, export_expires_at: null, message: '', created_at: '2026-10-18T00:00:00Z', updated_at: '2026-10-18T00:00:00Z', finished_at: null })
const preview = (): V3HistoryPreview => ({ token: 'account-preview', scope: { categories: ['events'], before: '2026-09-18T00:00:00Z', include_probes: false }, settings_version: 1, eligible: 2, protected: 1, expires_at: new Date(Date.now() + 600_000).toISOString() })
async function settle() { for (let i = 0; i < 35; i++) { await Promise.resolve(); await nextTick() } }
function fixture() {
  const client = new ControlV3()
  const reads = { status: vi.spyOn(client, 'retentionStatus').mockResolvedValue(status()), jobs: vi.spyOn(client, 'historyJobs').mockResolvedValue({ items: [], next_cursor: '', kind: 'manual' }), automatic: vi.spyOn(client, 'retentionJobs').mockResolvedValue({ items: [], next_cursor: '', limit: 20 }) }
  vi.spyOn(client, 'servers').mockResolvedValue({ items: [], next_cursor: '', limit: 50 }); return { client, ...reads }
}
async function mount(component: Component, client = fixture().client, role: 'admin' | 'operator' | 'viewer' = 'admin', props = {}) {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/settings', component: Settings }] }); await router.push('/settings?tab=retention'); await router.isReady()
  host = document.createElement('div'); document.body.append(host); app = createApp(component, props); app.use(router); installElements(app); app.provide(consoleContext, { client, session: ref({ username: 'admin', role, csrf: 'csrf' }) }); app.mount(host); await settle(); return router
}
function button(text: string, root: ParentNode = host) { const value = Array.from(root.querySelectorAll('button')).find(value => value.textContent?.trim() === text); if (!value) throw new Error(`button missing: ${text}`); return value }
function input(label: string, value: string) { const field = host.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!; field.value = value; field.dispatchEvent(new Event('input', { bubbles: true })) }
beforeEach(() => { vi.useFakeTimers(); Object.defineProperty(document, 'hidden', { configurable: true, value: false }) })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(value => value.remove()); cancelReadRequests(true); vi.useRealTimers(); vi.restoreAllMocks() })

it('shows five periods and unknown evidence, with no single or batch deletion in settings', async () => {
  await mount(Settings); expect(host.querySelectorAll('input[inputmode="numeric"]').length).toBe(5); expect(host.textContent).toContain('未知，尚无心跳证据'); expect(host.textContent).toContain('1.00 MiB'); expect(host.textContent).not.toContain('删除已选')
  expect(Array.from(host.querySelectorAll('button')).some(value => value.textContent?.trim() === '删除')).toBe(false)
})
it('validates integer days and confirms shortening before any write', async () => {
  const f = fixture(), save = vi.spyOn(f.client, 'saveRetentionPolicy').mockResolvedValue({ version: 2, policy: { ...policy(), sqlite_events_days: 7 }, shortened: true, message: '期限已生效' })
  await mount(Settings, f.client)
  for (const value of ['0', '3651', '1.5', '1e2', '-3', '']) { input('普通文件及运行事件', value); await settle(); button('保存并应用保留期限').click(); await settle(); expect(host.textContent).toContain('请输入 1～3650 天整数') }
  input('普通文件及运行事件', '7'); await settle(); button('保存并应用保留期限').click(); await settle(); expect(save).not.toHaveBeenCalled()
  const dialog = document.querySelector('.v3-node-dialog')!; expect(dialog.textContent).toContain('删除不可逆'); button('确认保存并应用', dialog).click(); await settle()
  expect(save.mock.calls[0]?.slice(0, 2)).toEqual([{ ...policy(), sqlite_events_days: 7 }, 1]); expect(host.textContent).toContain('期限已生效')
})
it('keeps dirty input and old version until explicitly discarding the draft', async () => {
  const f = fixture(); await mount(Settings, f.client); input('普通文件及运行事件', '60'); await settle(); f.status.mockResolvedValue(status(2))
  button('重新读取').click(); await settle(); expect(f.status).toHaveBeenCalledTimes(1); button('保留草稿', document.querySelector('.v3-node-dialog')!).click(); await settle()
  expect(host.querySelector<HTMLInputElement>('input[aria-label="普通文件及运行事件"]')!.value).toBe('60'); expect(host.textContent).toContain('配置版本 1')
  button('重新读取').click(); await settle(); button('放弃草稿并读取', document.querySelector('.v3-node-dialog')!).click(); await settle()
  expect(host.querySelector<HTMLInputElement>('input[aria-label="普通文件及运行事件"]')!.value).toBe('30'); expect(host.textContent).toContain('配置版本 2')
})
it('uses stable retry keys, preserves failed drafts and gives changed requests new keys', async () => {
  const f = fixture(), save = vi.spyOn(f.client, 'saveRetentionPolicy').mockRejectedValue(new Error('配置版本冲突'))
  await mount(Settings, f.client); input('普通文件及运行事件', '60'); await settle(); button('保存并应用保留期限').click(); await settle(); button('保存并应用保留期限').click(); await settle()
  expect(save.mock.calls[0]?.[2]).toBe(save.mock.calls[1]?.[2]); expect(host.textContent).toContain('配置版本冲突'); expect(host.querySelector<HTMLInputElement>('input[aria-label="普通文件及运行事件"]')!.value).toBe('60')
  input('普通文件及运行事件', '61'); await settle(); button('保存并应用保留期限').click(); await settle(); expect(save.mock.calls[2]?.[2]).not.toBe(save.mock.calls[1]?.[2])
})
it('restricts retention edits to administrators', async () => {
  await mount(Settings, fixture().client, 'operator'); expect(host.textContent).toContain('只有管理员'); expect(host.querySelector<HTMLInputElement>('input[aria-label="普通文件及运行事件"]')!.disabled).toBe(true)
  expect(Array.from(host.querySelectorAll('button')).some(value => value.textContent?.trim() === '保存并应用保留期限')).toBe(false)
})
it('aborts a retention read on tab switch and ignores its late failure', async () => {
  const f = fixture(); let reject!: (error: Error) => void; f.status.mockImplementation(() => new Promise((_, no) => { reject = no }))
  const router = await mount(Settings, f.client); const signal = f.status.mock.calls[0]?.[0]!; await router.push('/settings?tab=storage'); await settle(); expect(signal.aborted).toBe(true)
  reject(new Error('旧页面错误')); await settle(); expect(host.textContent).not.toContain('旧页面错误')
})
it('rejects recent cutoffs and invalidates preview when scope changes', async () => {
  const f = fixture(), inspect = vi.spyOn(f.client, 'previewHistory').mockResolvedValue(preview()); await mount(HistoryStorage, f.client)
  input('历史截止时间', new Date(Date.now() + 86400_000).toISOString().slice(0, 16)); await settle(); button('预览范围').click(); await settle(); expect(host.textContent).toContain('不能清理最近 24 小时'); expect(inspect).not.toHaveBeenCalled()
  input('历史截止时间', '2026-09-01T12:00'); await settle(); button('预览范围').click(); await settle(); expect(inspect.mock.calls[0]?.[0]).toMatchObject({ categories: ['events'], include_probes: false }); expect(host.textContent).toContain('可处理 2 条')
  input('历史截止时间', '2026-09-02T12:00'); await settle(); expect(host.textContent).not.toContain('可处理 2 条'); expect(button('清理范围内历史').disabled).toBe(true)
})
it('submits an export-first cleanup bound to preview, displaying queued work', async () => {
  const f = fixture(); vi.spyOn(f.client, 'previewHistory').mockResolvedValue(preview()); const cleanup = vi.spyOn(f.client, 'cleanupHistory').mockResolvedValue(job()); vi.spyOn(f.client, 'historyJob').mockResolvedValue({ job: job(), scope: preview().scope })
  await mount(HistoryStorage, f.client); button('预览范围').click(); await settle(); button('清理范围内历史').click(); await settle(); const dialog = document.querySelector('.v3-node-dialog')!; expect(cleanup).not.toHaveBeenCalled(); button('导出成功后清理', dialog).click(); await settle()
  expect(cleanup.mock.calls[0]?.slice(0, 2)).toEqual(['account-preview', { export_first: true, confirm_without_export: false }]); expect(document.body.textContent).toContain('排队中'); expect(document.body.textContent).not.toContain('清理成功')
})
it('confirms skipping export explicitly and retains a retry key on ambiguous failures', async () => {
  const f = fixture(); vi.spyOn(f.client, 'previewHistory').mockResolvedValue(preview()); const cleanup = vi.spyOn(f.client, 'cleanupHistory').mockRejectedValue(new Error('请求结果暂未确认'))
  await mount(HistoryStorage, f.client); button('预览范围').click(); await settle(); button('清理范围内历史').click(); await settle(); const dialog = document.querySelector('.v3-node-dialog')!; dialog.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click(); await settle()
  button('确认不导出，永久清理', dialog).click(); await settle(); button('确认不导出，永久清理', dialog).click(); await settle()
  expect(cleanup.mock.calls[0]?.[1]).toEqual({ export_first: false, confirm_without_export: true }); expect(cleanup.mock.calls[0]?.[2]).toBe(cleanup.mock.calls[1]?.[2]); expect(dialog.textContent).toContain('请求结果暂未确认')
})
it('refuses an expired preview before submission', async () => {
  const f = fixture(); vi.spyOn(f.client, 'previewHistory').mockResolvedValue(preview()); const cleanup = vi.spyOn(f.client, 'cleanupHistory')
  await mount(HistoryStorage, f.client); button('预览范围').click(); await settle(); await vi.advanceTimersByTimeAsync(600_001); button('清理范围内历史').click(); await settle(); expect(cleanup).not.toHaveBeenCalled(); expect(host.textContent).toContain('预览已过期')
})
it('keeps viewers read-only including range cleanup', async () => {
  await mount(HistoryStorage, fixture().client, 'viewer'); expect(host.textContent).toContain('当前账号只读'); expect(Array.from(host.querySelectorAll('button')).some(value => value.textContent?.trim() === '预览范围')).toBe(false)
})
it('polls without overlap, pauses on background and reports partial completion', async () => {
  const f = fixture(); let resolve!: (value: { job: V3HistoryJob; scope: V3HistoryPreview['scope'] }) => void
  const read = vi.spyOn(f.client, 'historyJob').mockResolvedValueOnce({ job: job(), scope: preview().scope }).mockImplementationOnce(() => new Promise(yes => { resolve = yes })).mockResolvedValue({ job: { ...job('partial'), deleted: 1, message: '部分记录受保护' }, scope: preview().scope })
  await mount(HistoryTask, f.client, 'admin', { id: job().id }); await vi.advanceTimersByTimeAsync(3000); await settle(); await vi.advanceTimersByTimeAsync(30_000); expect(read).toHaveBeenCalledTimes(2)
  Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange')); expect(read.mock.calls[1]?.[1]?.aborted).toBe(true); resolve({ job: job('succeeded'), scope: preview().scope }); await settle()
  Object.defineProperty(document, 'hidden', { configurable: true, value: false }); document.dispatchEvent(new Event('visibilitychange')); await settle(); expect(host.textContent).toContain('部分完成'); expect(host.textContent).toContain('已清理 1'); await vi.advanceTimersByTimeAsync(9000); expect(read).toHaveBeenCalledTimes(3)
  app!.unmount(); app = undefined; await vi.advanceTimersByTimeAsync(9000); expect(read).toHaveBeenCalledTimes(3)
})
it('pages task history and safely switches manual and automatic response types', async () => {
  const f = fixture(); f.jobs.mockResolvedValue({ items: [job('succeeded')], next_cursor: 'next', kind: 'manual' }); await mount(HistoryJobs, f.client)
  button('下一页').click(); await settle(); expect(f.jobs.mock.calls.at(-1)?.slice(0, 2)).toEqual(['next', 20]); button('自动清理记录').click(); await settle(); expect(f.automatic).toHaveBeenCalledTimes(1); expect(host.textContent).not.toContain('任务详情'); expect(host.textContent).not.toContain('删除')
})
it('uses submitted audit filters and frozen windows when paging and has no delete action', async () => {
  const f = fixture(), read = vi.spyOn(f.client, 'audit').mockResolvedValue({ items: [{ id: '9007199254740993', username: 'admin', kind: 'retention-cleanup', resource: 'history', result: { deleted: 2 }, created_at: '2026-10-18T00:00:00Z', record_key: 'audit:9007199254740993', can_delete: false, delete_reason: '审计只读，按 365 天期限保留' }], next_cursor: 'next', start: '', end: '' })
  await mount(Audit, f.client); const first = read.mock.calls[0]?.[0]; input('操作账号', '未提交'); await settle(); button('下一页').click(); await settle(); expect(read.mock.calls.at(-1)?.[0]).toMatchObject({ ...first, cursor: 'next' })
  button('查看摘要').click(); await settle(); expect(document.body.textContent).toContain('"deleted": 2'); expect(host.textContent).not.toContain('删除')
})

it('clears an old saved-success message when editing a new retention draft', async () => {
  const f = fixture(); f.status.mockResolvedValueOnce(status()).mockResolvedValue(status(2))
  vi.spyOn(f.client, 'saveRetentionPolicy').mockResolvedValue({ version: 2, policy: { ...policy(), sqlite_events_days: 60 }, shortened: false, message: '保留期限保存成功' })
  await mount(Settings, f.client); input('普通文件及运行事件', '60'); await settle(); button('保存并应用保留期限').click(); await settle(); expect(host.textContent).toContain('保留期限保存成功')
  input('普通文件及运行事件', '90'); await settle(); expect(host.textContent).not.toContain('保留期限保存成功'); expect(host.textContent).toContain('尚未保存')
})
