// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://monitor.example.test/backups?tab=deployment"}
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { installElements } from '../elements'
import { ControlV3, type V3ConfigurationBackup } from '../controlV3'
import { consoleContext } from './context'
import { cancelReadRequests } from '../connection'
import ConfigurationBackups from './ConfigurationBackups.vue'

let app: App | undefined, host: HTMLDivElement
const row = (id = 'a'.repeat(64)): V3ConfigurationBackup => ({ id, record_key: `configuration-backup:${id}`, created_at: '2026-10-18T00:00:00Z', document_created_at: '2026-10-18T00:00:00Z', source: 'manual', settings_version: 5, node_count: 20, needs_completion: false, can_delete: true, delete_reason: '' })
const page = (items = [row()], next_cursor = '') => ({ items, next_cursor, restore_available: false as const, delete_available: true as const })
async function settle() { for (let i = 0; i < 35; i++) { await Promise.resolve(); await nextTick() } }
function fixture() { const client = new ControlV3(); vi.spyOn(client, 'configurationRestores').mockResolvedValue({ items: [], next_cursor: '' }); vi.spyOn(client, 'configurationDeleteJobs').mockResolvedValue({ items: [], next_cursor: '' }); const read = vi.spyOn(client, 'configurationBackups').mockResolvedValue(page()); return { client, read } }
async function mount(client = fixture().client, role: 'admin' | 'operator' | 'viewer' = 'admin') {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/backups', component: ConfigurationBackups }] }); await router.push('/backups?tab=deployment'); await router.isReady()
  host = document.createElement('div'); document.body.append(host); app = createApp(ConfigurationBackups); app.use(router); installElements(app); app.provide(consoleContext, { client, session: ref({ username: 'user', role, csrf: 'csrf' }) }); app.mount(host); await settle(); return router
}
function button(text: string, root: ParentNode = document) { const value = Array.from(root.querySelectorAll('button')).find(value => value.textContent?.trim() === text); if (!value) throw new Error(`button missing: ${text}`); return value }
function input(label: string, text: string) { const value = document.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[aria-label="${label}"]`)!; value.value = text; value.dispatchEvent(new Event('input', { bubbles: true })) }
beforeEach(() => { vi.useFakeTimers() })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(value => value.remove()); cancelReadRequests(true); vi.useRealTimers(); vi.restoreAllMocks() })

it('creates only an archive and retains the explicit retry key until acknowledged', async () => {
  const f = fixture(), create = vi.spyOn(f.client, 'createConfigurationBackup').mockRejectedValueOnce(new Error('连接中断，结果未知')).mockResolvedValue(row())
  await mount(f.client); button('手动备份部署配置').click(); await settle(); expect(host.textContent).toContain('连接中断，结果未知')
  button('手动备份部署配置').click(); await settle(); expect(create.mock.calls[0]?.[0]).toBe(create.mock.calls[1]?.[0]); expect(host.textContent).toContain('共 20 个子服务器；不代表已部署')
  button('手动备份部署配置').click(); await settle(); expect(create.mock.calls[2]?.[0]).not.toBe(create.mock.calls[1]?.[0]); expect(host.textContent).toContain('可恢复到保存配置')
})
it('preserves raw YAML for strict server parsing and never applies it', async () => {
  const f = fixture(), imported = vi.spyOn(f.client, 'importConfigurationBackup').mockRejectedValueOnce(new Error('重复 YAML 字段')).mockResolvedValue({ ...row(), needs_completion: true })
  await mount(f.client); button('导入配置备份').click(); await settle(); const raw = 'format_version: 3\nformat_version: 3\n'; input('部署配置 YAML', raw); await settle()
  button('校验并存档').click(); await settle(); expect(imported.mock.calls[0]?.[0]).toBe(raw); expect(document.querySelector('.v3-dialog-feedback')?.textContent).toContain('重复 YAML 字段')
  button('校验并存档').click(); await settle(); expect(imported.mock.calls[0]?.[1]).toBe(imported.mock.calls[1]?.[1]); expect(host.textContent).toContain('未覆盖或应用配置'); expect(host.textContent).toContain('需补全')
})
it('ignores late file reads, retains prior input on errors, and clears on cancel', async () => {
  await mount(); button('导入配置备份').click(); await settle(); input('部署配置 YAML', 'original'); await settle()
  let old!: (text: string) => void, recent!: (text: string) => void
  const file = document.querySelector<HTMLInputElement>('input[type=file]')!
  function choose(size: number, text: () => Promise<string>) { Object.defineProperty(file, 'files', { configurable: true, value: [{ size, text }] }); file.dispatchEvent(new Event('change', { bubbles: true })) }
  choose(20, () => new Promise(resolve => { old = resolve })); await settle(); choose(20, () => new Promise(resolve => { recent = resolve })); await settle()
  recent('newest'); await settle(); old('stale'); await settle(); expect(document.querySelector<HTMLTextAreaElement>('textarea')!.value).toBe('newest')
  choose(32 * 1024 * 1024 + 1, vi.fn()); await settle(); expect(document.querySelector<HTMLTextAreaElement>('textarea')!.value).toBe('newest'); expect(document.body.textContent).toContain('原输入已保留')
  choose(20, () => new Promise(resolve => { old = resolve })); await settle(); button('取消').click(); await settle(); old('after close'); await settle(); await vi.advanceTimersByTimeAsync(400)
  button('导入配置备份').click(); await settle(); expect(document.querySelector<HTMLTextAreaElement>('textarea')!.value).toBe('')
})
it('uses independent server cursors and preserves successful results if refresh fails', async () => {
  const f = fixture(); f.read.mockResolvedValueOnce(page([row()], 'next-deployment')).mockResolvedValueOnce(page([row('b'.repeat(64))])).mockRejectedValueOnce(new Error('暂时不可用'))
  const router = await mount(f.client); button('下一页').click(); await settle(); expect(f.read.mock.calls[1]?.slice(0, 2)).toEqual(['next-deployment', 20]); expect(router.currentRoute.value.query.cursor).toBeUndefined()
  button('刷新配置存档').click(); await settle(); expect(host.textContent).toContain('已有结果保留'); expect(host.textContent).toContain('20'); button('上一页').click(); await settle(); expect(router.currentRoute.value.query.deployment_cursor).toBeUndefined()
})
it('clears export passwords on cancel and aborts an unmounted sensitive request', async () => {
  const f = fixture(); let resolve!: (file: Blob) => void
  const exported = vi.spyOn(f.client, 'exportEncryptedConfigurationBackup').mockImplementation(() => new Promise(yes => { resolve = yes }))
  await mount(f.client); button('加密配置包').click(); await settle(); input('导出密码', 'temporary-export-password'); input('确认导出密码', 'temporary-export-password'); await settle()
  button('取消').click(); await settle(); await vi.advanceTimersByTimeAsync(400); button('加密配置包').click(); await settle(); expect(document.querySelector<HTMLInputElement>('[aria-label="导出密码"]')!.value).toBe('')
  input('导出密码', 'new-export-password'); input('确认导出密码', 'new-export-password'); await settle(); button('加密并下载').click(); await settle()
  const signal = exported.mock.calls[0]?.[3]!; expect(exported.mock.calls[0]?.slice(0, 3)).toEqual([row().id, 'new-export-password', 'new-export-password']); app!.unmount(); app = undefined; expect(signal.aborted).toBe(true)
  resolve(new Blob(['synthetic-age'])); await settle(); expect(document.body.textContent).not.toContain('new-export-password')
})
it.each(['viewer', 'operator'] as const)('does not read or expose private archive controls to %s', async role => {
  const f = fixture(); await mount(f.client, role); expect(f.read).not.toHaveBeenCalled(); expect(host.textContent).toContain('仅允许管理员'); expect(host.textContent).not.toContain('手动备份部署配置'); expect(host.textContent).not.toContain('脱敏 YAML')
})

const deletionPreview = (items = [row()]) => ({ token: 'c'.repeat(64), settings_version: 5, eligible: items.length, protected: 0, expires_at: new Date(Date.now() + 600_000).toISOString(), items: items.map(item => ({ id: item.id, record_key: item.record_key, status: 'eligible' as const, reason: '' })) })
const deletionJob = (status: 'queued' | 'partial' | 'succeeded' = 'queued') => ({ id: 'd'.repeat(64), username: 'user', settings_version: 5, selected: 1, status, deleted: status === 'succeeded' ? 1 : 0, skipped: status === 'partial' ? 1 : 0, failed: 0, message: status === 'queued' ? '已排队；不表示已删除' : '逐项检查完成', created_at: '2026-10-18T00:00:00Z', updated_at: '2026-10-18T00:00:00Z', finished_at: status === 'queued' ? null : '2026-10-18T00:01:00Z' })
it('deletes only an explicitly selected current-page row and retains the retry key on uncertain submission', async () => {
  const f = fixture(), preview = vi.spyOn(f.client, 'previewConfigurationDelete').mockResolvedValue(deletionPreview()), submit = vi.spyOn(f.client, 'deleteConfigurationBackups').mockRejectedValueOnce(new Error('结果未知，请重试')).mockResolvedValue(deletionJob())
  vi.spyOn(f.client, 'configurationDeleteJob').mockResolvedValue({ job: deletionJob(), items: [] })
  await mount(f.client); button('删除').click(); await settle()
  expect(preview.mock.calls[0]?.[0]).toEqual([row().record_key]); expect((button('确认创建删除任务') as HTMLButtonElement).disabled).toBe(true)
  const checkbox = Array.from(document.querySelectorAll('.el-dialog input[type=checkbox]'))[0] as HTMLInputElement; checkbox.click(); await settle()
  button('确认创建删除任务').click(); await settle(); expect(document.body.textContent).toContain('结果未知，请重试')
  button('确认创建删除任务').click(); await settle(); expect(submit.mock.calls[0]?.slice(0, 2)).toEqual(submit.mock.calls[1]?.slice(0, 2)); expect(host.textContent).toContain('尚不代表删除完成'); expect(document.body.textContent).toContain('已删除 0')
})
it('disables referenced backups and clears selection after pagination', async () => {
  const f = fixture(); f.read.mockResolvedValueOnce(page([row(), { ...row('b'.repeat(64)), can_delete: false, delete_reason: '导出处理中' }], 'next-page')).mockResolvedValue(page([row('e'.repeat(64))]))
  const preview = vi.spyOn(f.client, 'previewConfigurationDelete').mockResolvedValue(deletionPreview())
  await mount(f.client)
  const rowChecks = Array.from(host.querySelectorAll('.el-table__body-wrapper input[type=checkbox]')) as HTMLInputElement[]
  expect(rowChecks).toHaveLength(2); expect(rowChecks[1]!.disabled).toBe(true); rowChecks[0]!.click(); await settle()
  button('删除已选（1）').click(); await settle(); expect(preview.mock.calls[0]?.[0]).toEqual([row().record_key]); button('取消').click(); await settle()
  button('下一页').click(); await settle(); expect((button('删除已选（0）') as HTMLButtonElement).disabled).toBe(true)
})
it('requires a fresh preview after ten minutes and aborts preview work on unmount', async () => {
  const f = fixture(), preview = vi.spyOn(f.client, 'previewConfigurationDelete').mockResolvedValue(deletionPreview())
  await mount(f.client); button('删除').click(); await settle(); await vi.advanceTimersByTimeAsync(600_001); await settle()
  expect(document.body.textContent).toContain('预览已过期'); expect((button('确认创建删除任务') as HTMLButtonElement).disabled).toBe(true)
  button('取消').click(); await settle(); let resolve!: (p: ReturnType<typeof deletionPreview>) => void
  preview.mockImplementationOnce(() => new Promise(yes => { resolve = yes })); button('删除').click(); await settle(); const signal = preview.mock.calls[1]?.[1]!
  app!.unmount(); app = undefined; expect(signal.aborted).toBe(true); resolve(deletionPreview()); await settle(); expect(host.textContent).not.toContain('可删除 1')
})
it('backs out an empty configuration page after deletion without changing the website cursor', async () => {
  const f = fixture(); f.read.mockResolvedValueOnce(page([row()], 'next-page')).mockResolvedValueOnce(page([row('b'.repeat(64))])).mockResolvedValueOnce(page([])).mockResolvedValue(page([row()]))
  const router = await mount(f.client); await router.replace({ query: { ...router.currentRoute.value.query, cursor: 'website-cursor' } }); await settle()
  button('下一页').click(); await settle(); button('刷新配置存档').click(); await settle()
  expect(router.currentRoute.value.query.deployment_cursor).toBeUndefined(); expect(router.currentRoute.value.query.cursor).toBe('website-cursor'); expect(f.read.mock.calls.at(-1)?.[0]).toBe('')
})
