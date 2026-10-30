// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://monitor.example.test/backups?tab=deployment"}
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { installElements } from '../elements'
import { ControlV3, V3Error, type V3ConfigurationApplication, type V3ConfigurationRestoreStage, type V3ConfigurationRestoreDetail, type V3ConfigurationRestorePreview, type V3ConfigurationRevision } from '../controlV3'
import { consoleContext } from './context'
import { cancelReadRequests } from '../connection'
import Panel from './ConfigurationRestorePanel.vue'
let app: App | undefined, host: HTMLDivElement, panel: { start(id: string): void }
const id = 'a'.repeat(64), backup = 'b'.repeat(64)
const summary = () => ({ settings_changed: true, bootstrap_changed: false, sections: ['retention'], added: 0, updated: 1, unchanged: 0, removed: 0, nodes: [{ node: 'test-node', action: 'update', fields: ['name'] }], credentials_kept: 2, credentials_replaced: 0, credentials_missing: 0, missing_nodes: [], missing_settings: false, missing_bootstrap: false, requires_center_restart: false, requires_local_validation: true, blocked_reasons: [], can_prepare: true })
const stage = (status: V3ConfigurationRestoreStage['status'] = 'pending_validation'): V3ConfigurationRestoreStage => ({ id, username: 'user', backup, before_backup: 'c'.repeat(64), settings_version: 6, status, message: '运行配置未修改', created_at: '2026-10-18T00:00:00Z', updated_at: '2026-10-18T00:00:00Z', finished_at: null, cancelled_by: '' })
const revision = (): V3ConfigurationRevision => ({ id: 'd'.repeat(64), generation: '9007199254740993', stage: id, username: 'user', base_settings_version: 6, status: 'pending_application', message: '候选已准备', created_at: '', updated_at: '', finished_at: null })
const detail = (status: V3ConfigurationRestoreStage['status'] = 'pending_validation'): V3ConfigurationRestoreDetail => ({ stage: stage(status), summary: summary(), revision: status === 'pending_validation' ? null : revision(), can_continue: status === 'pending_validation' || status === 'pending_application', can_cancel: status === 'pending_validation' || status === 'pending_application' })
const preview = (): V3ConfigurationRestorePreview => ({ token: 'e'.repeat(64), backup, expires_at: new Date(Date.now() + 600_000).toISOString(), summary: summary() })
async function settle() { for (let i = 0; i < 45; i++) { await Promise.resolve(); await nextTick() } }
function fixture() {
 const client = new ControlV3()
 const list = vi.spyOn(client, 'configurationRestores').mockResolvedValue({ items: [stage()], next_cursor: '' })
 const read = vi.spyOn(client, 'configurationRestore').mockResolvedValue(detail())
 const pre = vi.spyOn(client, 'previewConfigurationRestore').mockResolvedValue(preview())
 return { client, list, read, pre }
}
async function mount(client = fixture().client, role: 'admin' | 'operator' | 'viewer' = 'admin') {
 const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:pathMatch(.*)*', component: { render: () => null } }] }); await router.push('/backups'); await router.isReady()
 host = document.createElement('div'); document.body.append(host); app = createApp(Panel); app.use(router); installElements(app); app.provide(consoleContext, { client, session: ref({ username: 'user', role, csrf: 'csrf' }) }); panel = app.mount(host) as unknown as typeof panel; await settle(); return router
}
function button(text: string) { const b = Array.from(document.querySelectorAll('button')).find(b => b.textContent?.trim() === text); if (!b) throw new Error(`missing ${text}`); return b }
function checkbox(text: string) { const label = Array.from(document.querySelectorAll('label')).find(e => e.textContent?.includes(text)); if (!label) throw new Error(`missing checkbox ${text}`); (label.querySelector('input') as HTMLInputElement).click() }
beforeEach(() => { vi.useFakeTimers() })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(e => e.remove()); cancelReadRequests(true); vi.useRealTimers(); vi.restoreAllMocks() })
it('previews with current credentials by default and invalidates preview when option changes', async () => {
 const f = fixture(); await mount(f.client); panel.start(backup); await settle(); button('生成恢复预览').click(); await settle()
 expect(f.pre.mock.calls[0]?.slice(0, 2)).toEqual([backup, false]); expect(button('创建恢复记录').disabled).toBe(true)
 checkbox('我确认本次操作'); await settle(); expect(button('创建恢复记录').disabled).toBe(false)
 checkbox('使用备份中的配置凭据'); await settle(); expect(document.body.textContent).not.toContain('创建恢复记录')
 button('生成恢复预览').click(); await settle(); expect(f.pre.mock.calls[1]?.[1]).toBe(true)
 await vi.advanceTimersByTimeAsync(600_001); await settle(); expect(document.body.textContent).toContain('预览已过期'); expect(button('创建恢复记录').disabled).toBe(true)
})
it('retains ambiguous stage retry keys, resumes durable detail, and never reports runtime applied', async () => {
 const f = fixture(), staged = vi.spyOn(f.client, 'stageConfigurationRestore').mockRejectedValueOnce(new Error('结果未知，请重试')).mockResolvedValue(stage())
 const prepare = vi.spyOn(f.client, 'prepareConfigurationRestore').mockResolvedValue(revision())
 const commit = vi.spyOn(f.client, 'commitConfigurationRestore').mockResolvedValue({ stage: id, revision: revision().id, generation: revision().generation, nodes_changed: 1, requires_center_restart: false, status: 'saved_pending_application', message: '已恢复到保存配置，待应用', created_at: '' })
 await mount(f.client); panel.start(backup); await settle(); button('生成恢复预览').click(); await settle(); checkbox('我确认本次操作'); await settle()
 button('创建恢复记录').click(); await settle(); expect(document.body.textContent).toContain('结果未知，请重试'); button('创建恢复记录').click(); await settle()
 expect(staged.mock.calls[0]?.slice(0, 2)).toEqual(staged.mock.calls[1]?.slice(0, 2)); expect(document.body.textContent).toContain('待本机检查')
 f.read.mockResolvedValue(detail('pending_application')); button('检查并准备候选').click(); await settle(); expect(prepare).toHaveBeenCalledTimes(1); expect(button('提交到保存配置').disabled).toBe(true)
 checkbox('我确认本次操作'); await settle(); f.read.mockResolvedValue(detail('saved')); button('提交到保存配置').click(); await settle()
 expect(commit.mock.calls[0]?.slice(0, 2)).toEqual([id, '9007199254740993']); expect(document.body.textContent).toContain('已保存，待应用'); expect(Array.from(document.querySelectorAll('button')).some(b => b.textContent?.trim() === '提交到保存配置')).toBe(false)
})
it('discovers unfinished stages after reload and permits cancellation without owner continuation', async () => {
 const f = fixture(); f.read.mockResolvedValue({ ...detail(), can_continue: false })
 const cancel = vi.spyOn(f.client, 'cancelConfigurationRestore').mockResolvedValue(stage('cancelled'))
 await mount(f.client); button('查看恢复').click(); await settle(); expect(document.body.textContent).toContain('仅原操作账号'); expect(document.body.textContent).not.toContain('检查并准备候选')
 expect(button('取消此恢复').disabled).toBe(true); checkbox('我确认本次操作'); await settle(); f.read.mockResolvedValue(detail('cancelled')); button('取消此恢复').click(); await settle()
 expect(cancel.mock.calls[0]?.[0]).toBe(id); expect(document.body.textContent).toContain('已取消')
})
it('keeps failed detail and requires re-preview on explicit conflict, ignores late unmounted work', async () => {
 const f = fixture(); vi.spyOn(f.client, 'stageConfigurationRestore').mockRejectedValue(new V3Error(409, 'restore_conflict', '状态已变化，请重新预览'))
 await mount(f.client); panel.start(backup); await settle(); button('生成恢复预览').click(); await settle(); checkbox('我确认本次操作'); await settle(); button('创建恢复记录').click(); await settle()
 expect(document.body.textContent).toContain('状态已变化'); expect(document.body.textContent).not.toContain('创建恢复记录')
 let resolve!: (v: V3ConfigurationRestorePreview) => void; f.pre.mockImplementationOnce(() => new Promise(yes => { resolve = yes }))
 button('生成恢复预览').click(); await settle(); const signal = f.pre.mock.calls.at(-1)?.[2]!
 app!.unmount(); app = undefined; expect(signal.aborted).toBe(true); resolve(preview()); await settle(); expect(host.textContent).toBe('')
})
it.each(['operator', 'viewer'] as const)('hides restore history from %s', async role => {
 const f = fixture(); await mount(f.client, role); expect(f.list).not.toHaveBeenCalled(); expect(host.textContent).not.toContain('配置恢复记录')
})

it('bounds large restore previews to one hundred rendered changes while retaining total scope', async () => {
 const f = fixture(), value = preview()
 value.summary.nodes = Array.from({ length: 20000 }, (_, i) => ({ node: `node-${i}`, action: 'update', fields: ['rules'] }))
 value.summary.updated = 20000; f.pre.mockResolvedValue(value)
 await mount(f.client); panel.start(backup); await settle(); button('生成恢复预览').click(); await settle()
 expect(document.body.textContent).toContain('共 20000 个节点有变化，仅展示前 100 个')
 expect(document.querySelectorAll('.el-dialog .el-table__body-wrapper .el-table__row')).toHaveLength(100)
 expect(document.body.textContent).not.toContain('node-1000')
})

it.each([
 ['queued', 'forward', false, '等待应用'], ['running', 'forward', false, '应用中'],
 ['running', 'rollback', false, '回退中'], ['failed', 'forward', false, '应用未完成'],
 ['succeeded', 'forward', false, '本次应用完成'], ['rolled_back', 'rollback', false, '已回退'],
 ['cancelled', 'forward', false, '应用已取消'], ['running', 'forward', true, '应用已冻结'],
] as const)('reads authenticated %s / %s / frozen=%s history separately from saved status', async (state, direction, hold, label) => {
 const f = fixture(), value = detail('saved')
 const application: V3ConfigurationApplication = { id: 'f'.repeat(64), stage: id, username: 'user', controller: 'user', generation: '9007199254740993', status: state, direction, phase: state === 'succeeded' || state === 'rolled_back' || state === 'cancelled' ? 'complete' : 'verify', recovery_hold: hold, recovery_required: state === 'running' || state === 'failed', error_code: '', log_cursor: '9007199254740995', created_at: '2026-10-19T00:00:00Z', updated_at: '2026-10-19T00:01:00Z', finished_at: null }
 value.stage.application = application; value.stage.message = '历史任务结果不代表当前配置版本'
 f.list.mockResolvedValue({ items: [value.stage], next_cursor: '' }); f.read.mockResolvedValue(value)
 await mount(f.client); expect(host.textContent).toContain(label); expect(host.textContent).not.toContain('已保存，待应用')
 button('查看恢复').click(); await settle()
 expect(document.body.textContent).toContain(label); expect(document.body.textContent).toContain('历史任务结果不代表当前配置版本')
 expect(document.body.textContent).toContain('只读展示历史任务，不执行应用或回退')
 expect(Array.from(document.querySelectorAll('button')).some(b => ['提交到保存配置', '检查并准备候选', '取消此恢复'].includes(b.textContent?.trim() || ''))).toBe(false)
 f.read.mockRejectedValueOnce(new V3Error(503, 'configuration_application_unverified', '状态暂时无法核实'))
 button('刷新恢复状态').click(); await settle()
 expect(document.body.textContent).toContain('以上为上次读取结果，请刷新确认'); expect(document.body.textContent).toContain(label)
 // An older compatible server can omit the optional projection entirely.
 f.read.mockResolvedValue(detail('saved')); button('刷新恢复状态').click(); await settle()
 expect(document.querySelector('.el-dialog')?.textContent).toContain('已保存，待应用')
 expect(document.querySelector('.el-dialog')?.textContent).not.toContain('应用阶段：')
})

it('does not invent an old result when the first detail read is unavailable', async () => {
 const f = fixture(); f.read.mockRejectedValue(new V3Error(503, 'configuration_application_unverified', '应用状态无法核实'))
 await mount(f.client); button('查看恢复').click(); await settle()
 expect(document.querySelector('.el-dialog')?.textContent).toContain('请重试读取恢复状态')
 expect(document.querySelector('.el-dialog')?.textContent).not.toContain('以上为上次读取结果')
 expect(document.querySelector('.el-dialog')?.textContent).not.toContain('本次应用完成')
})

it('requires a separate application confirmation and routes immediately to the durable task', async () => {
 const f = fixture(), saved = { ...detail('saved'), can_apply: true }
 f.read.mockResolvedValue(saved)
 const queued: V3ConfigurationApplication = { id: 'f'.repeat(64), stage: id, username: 'user', controller: 'user', generation: revision().generation, status: 'queued', direction: 'forward', phase: 'environment', recovery_hold: false, recovery_required: false, error_code: '', log_cursor: '1', created_at: '', updated_at: '', finished_at: null }
 const write = vi.spyOn(f.client, 'queueConfigurationApplication').mockRejectedValueOnce(new Error('结果未知')).mockResolvedValue(queued)
 const router = await mount(f.client); button('查看恢复').click(); await settle()
 expect(button('应用已保存配置').disabled).toBe(true)
 checkbox('我确认应用已保存的配置'); await settle(); button('应用已保存配置').click(); await settle()
 expect(document.body.textContent).toContain('结果未知'); button('应用已保存配置').click(); await settle()
 expect(write.mock.calls[0]?.slice(0, 3)).toEqual(write.mock.calls[1]?.slice(0, 3))
 expect(write.mock.calls[0]?.slice(0, 2)).toEqual([id, '9007199254740993'])
 expect(router.currentRoute.value.path).toBe(`/configuration-applications/${queued.id}`)
 expect(document.body.textContent).not.toContain('本次应用完成')
})
it('disables application when the saved-stage read becomes stale', async () => {
 const f = fixture(); f.read.mockResolvedValue({ ...detail('saved'), can_apply: true })
 const write = vi.spyOn(f.client, 'queueConfigurationApplication')
 await mount(f.client); button('查看恢复').click(); await settle(); checkbox('我确认应用已保存的配置'); await settle()
 f.read.mockRejectedValue(new Error('状态读取失败')); button('刷新恢复状态').click(); await settle()
 expect(button('应用已保存配置').disabled).toBe(true); button('应用已保存配置').click(); await settle(); expect(write).not.toHaveBeenCalled()
})
