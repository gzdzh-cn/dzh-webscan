// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { installElements } from '../elements'
import { ControlV3, type V3DeploymentJob, type V3DeploymentHistoryDeleteJob } from '../controlV3'
import { consoleContext } from './context'
import HistoryDelete from './DeploymentHistoryDelete.vue'
import DeleteTask from './DeploymentDeleteTask.vue'
let app: App | undefined, host: HTMLDivElement
async function settle() { for (let i = 0; i < 30; i++) { await Promise.resolve(); await nextTick() } }
const row = (id = 'job-a'): V3DeploymentJob => ({ id, node: 'node-a', username: 'admin', kind: 'install', status: 'succeeded', direction: 'forward', node_version: 1, plan_digest: 'd'.repeat(64), step: 1, rollback_step: 0, recovery_required: false, error_code: '', log_cursor: 20, created_at: '', updated_at: '', finished_at: '', record_key: 'record-' + id, can_delete: true, delete_reason: '' })
const deletion = (status: V3DeploymentHistoryDeleteJob['status'] = 'running'): V3DeploymentHistoryDeleteJob => ({ id: 'delete-a', status, selected: 2, deleted: 1, skipped: status === 'partial' ? 1 : 0, failed: 0, message: '实际处理进度', created_at: '', updated_at: '', finished_at: status === 'partial' ? new Date().toISOString() : null, items: [] })
function button(text: string) { const found = Array.from(document.body.querySelectorAll('button')).find(e => e.textContent?.trim() === text); if (!found) throw new Error('Missing ' + text); return found }
async function mount(client: ControlV3, task = false, role: 'admin' | 'viewer' = 'admin') {
 host = document.createElement('div'); document.body.append(host); const changed = vi.fn(), finished = vi.fn()
 app = task ? createApp(DeleteTask, { id: 'delete-a', onFinished: finished }) : createApp(HistoryDelete, { rows: [row()], onChanged: changed }); installElements(app)
 app.provide(consoleContext, { client, session: ref({ username: 'fixture', role, csrf: 'csrf' }) })
 const instance = app.mount(host) as unknown as { open(rows: V3DeploymentJob[]): Promise<void> }; await settle(); return { instance, changed, finished }
}
beforeEach(() => { sessionStorage.clear(); Object.defineProperty(document, 'hidden', { configurable: true, value: false }) })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(e => e.remove()); vi.restoreAllMocks(); vi.useRealTimers() })
it('limits deletion to explicitly eligible current-page records and requires separate confirmation', async () => {
 const client = new ControlV3(), preview = vi.spyOn(client, 'previewDeploymentHistoryDelete').mockResolvedValue({ token: 'opaque-preview', eligible: 1, protected: 0, expires_at: new Date(Date.now() + 600000).toISOString(), message: '', items: [{ id: 'job-a', record_key: 'record-job-a', status: 'eligible', reason: '' }] })
 const submit = vi.spyOn(client, 'deleteDeploymentHistory').mockResolvedValue(deletion()), read = vi.spyOn(client, 'deploymentHistoryDeleteJob').mockResolvedValue(deletion())
 const { instance } = await mount(client)
 await instance.open([row('other-page')]); await instance.open([{ ...row(), can_delete: undefined }]); expect(preview).not.toHaveBeenCalled()
 await instance.open([row()]); await settle(); expect(preview.mock.calls[0]?.[0]).toEqual(['record-job-a'])
 expect(document.body.textContent).toContain('不会卸载子控'); expect(button('确认并创建删除任务').disabled).toBe(true); expect(submit).not.toHaveBeenCalled()
 const checkbox = document.body.querySelector('input[type=checkbox]') as HTMLInputElement; checkbox.click(); await settle()
 button('确认并创建删除任务').click(); await settle(); expect(submit.mock.calls[0]?.[0]).toBe('opaque-preview'); expect(read).toHaveBeenCalled()
 expect(document.body.textContent).toContain('任务已创建不代表删除完成'); expect(sessionStorage.getItem('webscan.deployment.history.delete.fixture')).toBe('delete-a')
})
it('keeps the same confirm key after a lost response and rejects expired previews', async () => {
 vi.useFakeTimers(); const client = new ControlV3()
 vi.spyOn(client, 'previewDeploymentHistoryDelete').mockResolvedValue({ token: 'preview', eligible: 1, protected: 0, expires_at: new Date(Date.now() + 5000).toISOString(), message: '', items: [] })
 const submit = vi.spyOn(client, 'deleteDeploymentHistory').mockRejectedValue(new Error('响应未确认'))
 const { instance } = await mount(client); await instance.open([row()]); await settle()
 ;(document.body.querySelector('input[type=checkbox]') as HTMLInputElement).click(); await settle()
 button('确认并创建删除任务').click(); await settle(); button('确认并创建删除任务').click(); await settle()
 expect(submit).toHaveBeenCalledTimes(2); expect(submit.mock.calls[0]?.[1]).toBe(submit.mock.calls[1]?.[1])
 await vi.advanceTimersByTimeAsync(5001); await settle(); expect(button('确认并创建删除任务').disabled).toBe(true); expect(document.body.textContent).toContain('预览已过期')
})
it('blocks viewers and ignores a late preview after unmount', async () => {
 const client = new ControlV3(), preview = vi.spyOn(client, 'previewDeploymentHistoryDelete')
 const viewer = await mount(client, false, 'viewer'); await viewer.instance.open([row()]); expect(preview).not.toHaveBeenCalled()
 app?.unmount(); app = undefined; host.remove()
 let finish!: (value: Awaited<ReturnType<ControlV3['previewDeploymentHistoryDelete']>>) => void
 preview.mockImplementation(() => new Promise(resolve => { finish = resolve }))
 const admin = await mount(client); const pending = admin.instance.open([row()]); await settle(); (app as App | undefined)?.unmount(); app = undefined
 finish({ token: 'late', eligible: 1, protected: 0, expires_at: new Date().toISOString(), message: 'stale preview', items: [] }); await pending; await settle(); expect(host.textContent).not.toContain('stale preview')
})
it('polls real per-item outcomes without overlap, pauses in background and retains partial progress', async () => {
 vi.useFakeTimers(); const client = new ControlV3(); let resolve!: (value: V3DeploymentHistoryDeleteJob) => void
 const read = vi.spyOn(client, 'deploymentHistoryDeleteJob').mockImplementationOnce(() => new Promise(done => { resolve = done })).mockResolvedValueOnce({ ...deletion('partial'), items: [{ id: 'job-a', record_key: 'record-job-a', status: 'skipped', reason: '新恢复引用，保持保护', deleted_logs: 0 }] })
 const { finished } = await mount(client, true); await vi.advanceTimersByTimeAsync(30000); expect(read).toHaveBeenCalledTimes(1)
 resolve(deletion()); await settle(); expect(host.textContent).toContain('已删除 1')
 Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange')); await vi.advanceTimersByTimeAsync(30000); expect(read).toHaveBeenCalledTimes(1)
 Object.defineProperty(document, 'hidden', { configurable: true, value: false }); document.dispatchEvent(new Event('visibilitychange')); await settle(); expect(host.textContent).toContain('部分完成'); expect(host.textContent).toContain('跳过 1'); expect(host.textContent).toContain('新恢复引用，保持保护'); expect(finished).toHaveBeenCalledTimes(1)
 await vi.advanceTimersByTimeAsync(30000); expect(read).toHaveBeenCalledTimes(2)
})
it('retains loaded progress during transient failures and stops polling after unmount', async () => {
 vi.useFakeTimers(); const client = new ControlV3(), read = vi.spyOn(client, 'deploymentHistoryDeleteJob').mockResolvedValueOnce(deletion()).mockRejectedValueOnce(new Error('暂时断网')).mockResolvedValue(deletion())
 await mount(client, true); await vi.advanceTimersByTimeAsync(3000); await settle(); expect(host.textContent).toContain('已读取的进度保留'); expect(host.textContent).toContain('已删除 1')
 await vi.advanceTimersByTimeAsync(3000); expect(read).toHaveBeenCalledTimes(3); app?.unmount(); app = undefined; await vi.advanceTimersByTimeAsync(30000); expect(read).toHaveBeenCalledTimes(3)
})

it('retries a lost preview response with the same key and creates a new intent after explicit cancellation', async () => {
 const client = new ControlV3(), value = { token: 'preview', eligible: 1, protected: 0, expires_at: new Date(Date.now() + 600000).toISOString(), message: '', items: [] }
 const preview = vi.spyOn(client, 'previewDeploymentHistoryDelete').mockRejectedValueOnce(new Error('预览响应丢失')).mockResolvedValue(value)
 const { instance } = await mount(client); await instance.open([row()]); await settle()
 button('重试删除预览').click(); await settle(); expect(preview).toHaveBeenCalledTimes(2); expect(preview.mock.calls[0]?.[1]).toBe(preview.mock.calls[1]?.[1])
 button('取消').click(); await settle(); await instance.open([row()]); await settle(); expect(preview.mock.calls[2]?.[1]).not.toBe(preview.mock.calls[1]?.[1])
})
