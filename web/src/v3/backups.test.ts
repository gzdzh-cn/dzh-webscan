// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { installElements } from '../elements'
import { ControlV3, type V3WebsiteBackup, type V3WebsiteBackupPreview } from '../controlV3'
import { consoleContext } from './context'
import { cancelReadRequests } from '../connection'
import Backups from './Backups.vue'
let app: App | undefined, host: HTMLDivElement
const row = (id = 'a'.repeat(64), protectedRow = false): V3WebsiteBackup => ({ id, record_key: `website-backup:${id}`, created_at: '2026-10-18T00:00:00Z', source: 'manual', count: 24, restored_at: null, result: {}, can_delete: !protectedRow, delete_reason: protectedRow ? '恢复预览仍有效' : '' })
const preview = (): V3WebsiteBackupPreview => ({ added: 2, updated: 1, unchanged: 21, unknown_nodes: ['old-node'], token: 'preview-account-token' })
async function settle() { for (let i = 0; i < 35; i++) { await Promise.resolve(); await nextTick() } }
function fixture() { const client = new ControlV3(), read = vi.spyOn(client, 'websiteBackups').mockResolvedValue({ items: [row()], next_cursor: '' }); vi.spyOn(client, 'configurationRestores').mockResolvedValue({ items: [], next_cursor: '' }); vi.spyOn(client, 'configurationDeleteJobs').mockResolvedValue({ items: [], next_cursor: '' }); vi.spyOn(client, 'configurationBackups').mockResolvedValue({ items: [], next_cursor: '', restore_available: false, delete_available: false }); return { client, read } }
async function mount(client = fixture().client, path = '/backups', role: 'admin' | 'viewer' = 'admin') {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/backups', component: Backups }, { path: '/config-backups', redirect: '/backups?tab=deployment' }] }); await router.push(path); await router.isReady()
  host = document.createElement('div'); document.body.append(host); app = createApp(Backups); app.use(router); installElements(app); app.provide(consoleContext, { client, session: ref({ username: 'admin', role, csrf: 'csrf' }) }); app.mount(host); await settle(); return router
}
function button(text: string, root: ParentNode = host) { const value = Array.from(root.querySelectorAll('button')).find(value => value.textContent?.trim() === text); if (!value) throw new Error(`button missing: ${text}`); return value }
function paste(text: string) { const input = document.querySelector<HTMLTextAreaElement>('textarea[aria-label="网站备份 JSON"]')!; input.value = text; input.dispatchEvent(new Event('input', { bubbles: true })) }
beforeEach(() => { vi.useFakeTimers() })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(value => value.remove()); cancelReadRequests(true); vi.useRealTimers(); vi.restoreAllMocks() })

it('paginates website backups at server and retains read-only legacy deployment entry truthfully', async () => {
  const f = fixture(); f.read.mockResolvedValue({ items: [row()], next_cursor: 'next' }); const router = await mount(f.client)
  expect(f.read.mock.calls[0]?.slice(0, 2)).toEqual(['', 20]); button('下一页').click(); await settle(); expect(f.read.mock.calls.at(-1)?.slice(0, 2)).toEqual(['next', 20])
  await router.push('/config-backups'); await settle(); expect(router.currentRoute.value.fullPath).toBe('/backups?tab=deployment'); expect(host.textContent).toContain('可恢复到保存配置'); expect(host.textContent).not.toContain('手动备份网站配置')
})
it('preserves the same explicit retry key for creating a backup and reports stored configuration only', async () => {
  const f = fixture(), save = vi.spyOn(f.client, 'createWebsiteBackup').mockRejectedValueOnce(new Error('请求结果不明确')).mockResolvedValue({ id: row().id, count: 24, source: 'manual' })
  await mount(f.client); button('手动备份网站配置').click(); await settle(); expect(host.textContent).toContain('请求结果不明确'); button('手动备份网站配置').click(); await settle()
  expect(save.mock.calls[0]?.[0]).toBe(save.mock.calls[1]?.[0]); expect(host.textContent).toContain('网站配置已备份，共 24 个网站')
  button('手动备份网站配置').click(); await settle(); expect(save.mock.calls[2]?.[0]).not.toBe(save.mock.calls[1]?.[0])
})
it('submits original JSON text for strict duplicate-key validation, preserves import errors and does not restore', async () => {
  const f = fixture(), imported = vi.spyOn(f.client, 'importWebsiteBackupText').mockRejectedValueOnce(new Error('重复 JSON 字段')).mockResolvedValue({ id: row().id, count: 1, source: 'import' }), restore = vi.spyOn(f.client, 'restoreWebsiteBackup')
  await mount(f.client); button('导入网站备份').click(); await settle(); const text = '{"format_version":1,"format_version":1,"websites":[]}'; paste(text); await settle(); const dialog = document.querySelector('.v3-node-dialog')!
  button('校验并加入备份列表', dialog).click(); await settle(); expect(imported.mock.calls[0]?.[0]).toBe(text); expect(dialog.textContent).toContain('重复 JSON 字段'); expect(document.querySelector<HTMLTextAreaElement>('textarea')!.value).toBe(text)
  button('校验并加入备份列表', dialog).click(); await settle(); expect(imported.mock.calls[0]?.[1]).toBe(imported.mock.calls[1]?.[1]); expect(host.textContent).toContain('尚未恢复'); expect(restore).not.toHaveBeenCalled()
})
it('keeps only the most recent asynchronous file selection and ignores a read after cancelling', async () => {
  const f = fixture(); await mount(f.client); button('导入网站备份').click(); await settle(); paste('原输入'); await settle()
  let resolveOld!: (value: string) => void, resolveNew!: (value: string) => void
  const input = document.querySelector<HTMLInputElement>('input[type="file"]')!
  function choose(text: () => Promise<string>) { Object.defineProperty(input, 'files', { configurable: true, value: [{ size: 20, text }] }); input.dispatchEvent(new Event('change', { bubbles: true })) }
  choose(() => new Promise(yes => { resolveOld = yes })); await settle(); choose(() => new Promise(yes => { resolveNew = yes })); await settle()
  resolveNew('最新文档'); await settle(); resolveOld('过期文档'); await settle(); expect(document.querySelector<HTMLTextAreaElement>('textarea')!.value).toBe('最新文档')
  choose(() => new Promise(yes => { resolveNew = yes })); await settle(); button('取消', document.querySelector('.v3-node-dialog')!).click(); await settle(); resolveNew('关闭后的文档'); await settle(); button('导入网站备份').click(); await settle(); expect(document.querySelector<HTMLTextAreaElement>('textarea')!.value).toBe('')
})
it('retains previous import input on file size errors', async () => {
  await mount(); button('导入网站备份').click(); await settle(); paste('原输入'); await settle(); const input = document.querySelector<HTMLInputElement>('input[type="file"]')!
  Object.defineProperty(input, 'files', { configurable: true, value: [{ size: 2097153, text: vi.fn() }] }); input.dispatchEvent(new Event('change', { bubbles: true })); await settle()
  expect(document.querySelector<HTMLTextAreaElement>('textarea')!.value).toBe('原输入'); expect(document.body.textContent).toContain('不超过 2 MiB')
})
it('restores only after an account-bound merge preview and explains missing node associations', async () => {
  const f = fixture(), inspect = vi.spyOn(f.client, 'previewWebsiteBackup').mockResolvedValue(preview()), restore = vi.spyOn(f.client, 'restoreWebsiteBackup').mockResolvedValue({ ...preview(), before_backup: 'before-id' })
  await mount(f.client); button('恢复预览').click(); await settle(); const dialog = document.querySelector('.v3-node-dialog')!
  expect(inspect).toHaveBeenCalledWith(row().id); expect(restore).not.toHaveBeenCalled(); expect(dialog.textContent).toContain('old-node'); expect(dialog.textContent).toContain('清除关联'); button('备份当前配置并合并恢复', dialog).click(); await settle()
  expect(restore.mock.calls[0]?.slice(0, 2)).toEqual([row().id, 'preview-account-token']); expect(host.textContent).toContain('网站配置已合并恢复：新增 2，更新 1，不变 21')
})
it('rejects locally expired restore previews and retains server conflict errors in the footer', async () => {
  const f = fixture(); vi.spyOn(f.client, 'previewWebsiteBackup').mockResolvedValue(preview()); const restore = vi.spyOn(f.client, 'restoreWebsiteBackup').mockRejectedValue(new Error('配置已变化，请重新预览'))
  await mount(f.client); button('恢复预览').click(); await settle(); const dialog = document.querySelector('.v3-node-dialog')!; button('备份当前配置并合并恢复', dialog).click(); await settle(); expect(dialog.querySelector('.v3-dialog-feedback')?.textContent).toContain('配置已变化')
  await vi.advanceTimersByTimeAsync(600_001); button('备份当前配置并合并恢复', dialog).click(); await settle(); expect(restore).toHaveBeenCalledTimes(1); expect(dialog.textContent).toContain('恢复预览已过期')
})
it('disables protected backup selection and uses exact page identities for partial deletion', async () => {
  const f = fixture(); f.read.mockResolvedValue({ items: [row(), row('b'.repeat(64), true)], next_cursor: '' }); const remove = vi.spyOn(f.client, 'deleteWebsiteBackups').mockResolvedValue({ deleted: 0, skipped: [{ id: row().id, reason: '恢复预览仍有效' }], message: '部分完成' })
  await mount(f.client); expect(host.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')[2]!.disabled).toBe(true); button('删除').click(); await settle(); expect(remove).not.toHaveBeenCalled()
  button('确认永久删除 1 份备份', document.querySelector('.v3-node-dialog')!).click(); await settle(); expect(remove.mock.calls[0]?.[0]).toEqual([row().id]); expect(host.textContent).toContain('已删除 0 份备份，跳过 1 份'); expect(host.textContent).toContain('恢复预览仍有效')
})
it('resets selection when paging and walks back to the last nonempty known page', async () => {
  const f = fixture(); f.read.mockResolvedValueOnce({ items: [row()], next_cursor: 'page-two' }).mockResolvedValueOnce({ items: [row('b'.repeat(64))], next_cursor: '' }).mockResolvedValueOnce({ items: [], next_cursor: '' }).mockResolvedValue({ items: [row()], next_cursor: '' })
  const router = await mount(f.client); host.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')[1]!.click(); await settle(); await vi.advanceTimersByTimeAsync(20); expect(button('删除已选（1）').disabled).toBe(false)
  button('下一页').click(); await settle(); expect(button('删除已选（0）').disabled).toBe(true); button('刷新备份列表').click(); await settle(); expect(router.currentRoute.value.query.cursor).toBeUndefined(); expect(f.read.mock.calls.at(-1)?.[0]).toBe('')
})
it('aborts reads and ignores late results after switching backup tabs', async () => {
  const f = fixture(); let resolve!: (value: { items: V3WebsiteBackup[]; next_cursor: string }) => void; f.read.mockImplementation(() => new Promise(yes => { resolve = yes }))
  await mount(f.client); const signal = f.read.mock.calls[0]?.[2]!; button('部署配置').click(); await settle(); expect(signal.aborted).toBe(true); resolve({ items: [row()], next_cursor: '' }); await settle(); expect(host.textContent).not.toContain('网站数'); expect(host.textContent).toContain('可恢复到保存配置')
})
it('lets viewers export website configuration but exposes no write or selection controls', async () => {
  await mount(fixture().client, '/backups', 'viewer'); expect(host.querySelector('input[type="checkbox"]')).toBeNull(); expect(host.textContent).toContain('导出 JSON'); expect(host.textContent).not.toContain('恢复预览'); expect(host.textContent).not.toContain('删除已选')
})

it('bulk deletion freezes only explicit current-page backup IDs and retains partial results', async () => {
  const f = fixture(); f.read.mockResolvedValue({ items: [row(), row('b'.repeat(64))], next_cursor: 'more' }); const remove = vi.spyOn(f.client, 'deleteWebsiteBackups').mockResolvedValue({ deleted: 1, skipped: [{ id: row().id, reason: '新恢复预览保护' }], message: '部分完成' })
  await mount(f.client); host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click(); await settle(); await vi.advanceTimersByTimeAsync(20); button('删除已选（2）').click(); await settle()
  expect(remove).not.toHaveBeenCalled(); button('确认永久删除 2 份备份', document.querySelector('.v3-node-dialog')!).click(); await settle()
  expect(remove.mock.calls[0]?.[0]).toEqual([row().id, 'b'.repeat(64)]); expect(host.textContent).toContain('已删除 1 份备份，跳过 1 份'); expect(host.textContent).toContain('新恢复预览保护')
})
