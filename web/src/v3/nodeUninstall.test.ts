// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { installElements } from '../elements'
import { ControlV3, type V3Node } from '../controlV3'
import { consoleContext } from './context'
import NodeUninstall from './NodeUninstall.vue'
import Deployments from './Deployments.vue'
import { createMemoryHistory, createRouter } from 'vue-router'
let app: App | undefined, host: HTMLDivElement
async function settle() { for (let i = 0; i < 30; i++) { await Promise.resolve(); await nextTick() } }
const node = (): V3Node => ({ id: 'node-a', name: '保留记录的节点', endpoint: '203.0.113.19:19100', server_name: 'draft', mode: 'docker', enabled: false, version: 7, applied_version: 2, shard: 0, can_uninstall: true, lifecycle: 'installed' })
async function mount(client: ControlV3, role: 'admin' | 'viewer' = 'admin') {
 vi.spyOn(client, 'capabilities').mockResolvedValue({ api_version: 3, topology: 'single', features: [], implementation_stage: 'fixture', operations: { uninstall: { available: true, reason: '' } } })
 host = document.createElement('div'); document.body.append(host)
 const job = vi.fn(); app = createApp(NodeUninstall, { onJob: job }); installElements(app)
 app.provide(consoleContext, { client, session: ref({ username: 'fixture', role, csrf: 'csrf' }) })
 const instance = app.mount(host) as unknown as { open(value: V3Node): Promise<void> }; await settle()
 return { instance, job }
}
beforeEach(() => { Object.defineProperty(document, 'hidden', { configurable: true, value: false }) })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(e => e.remove()); vi.restoreAllMocks(); vi.useRealTimers() })
it('opens a separate uninstall flow for a disabled node without saving pending metadata', async () => {
 const client = new ControlV3(), save = vi.spyOn(client, 'saveServer')
 vi.spyOn(client, 'deployments').mockResolvedValue({ items: [], next_cursor: '', limit: 20 })
 const credential = vi.spyOn(client, 'sshCredential').mockResolvedValue({ configured: true, version: 7, ssh_port: 555, fingerprint: 'fp', can_uninstall: false, reason: '证据待核实' })
 const { instance } = await mount(client); await instance.open(node()); await settle()
 expect(document.body.textContent).toContain('不应用尚未下发的新地址或部署方式')
 expect(credential.mock.calls[0]?.[2]).toBe('uninstall'); expect(save).not.toHaveBeenCalled()
 expect(document.body.textContent).toContain('证据待核实')
 expect(document.body.textContent).not.toContain('203.0.113.19')
})
it('keeps unfinished task navigation and never starts a second remote operation', async () => {
 const client = new ControlV3(), credential = vi.spyOn(client, 'sshCredential')
 vi.spyOn(client, 'deployments').mockResolvedValue({ items: [{ id: 'original', node: 'node-a', status: 'interrupted' } as never], next_cursor: '', limit: 20 })
 const { instance, job } = await mount(client); await instance.open(node()); await settle()
 const button = Array.from(document.body.querySelectorAll('button')).find(e => e.textContent?.trim() === '打开未完成任务')!
 button.click(); await settle(); expect(job).toHaveBeenCalledWith('original'); expect(credential).not.toHaveBeenCalled()
})
it('does not open remote operations for a viewer or an unproven node', async () => {
 const client = new ControlV3(), jobs = vi.spyOn(client, 'deployments')
 const { instance } = await mount(client, 'viewer'); await instance.open(node()); await settle(); expect(jobs).not.toHaveBeenCalled()
 app?.unmount(); app = undefined; host.remove()
 const admin = await mount(client); await admin.instance.open({ ...node(), can_uninstall: undefined }); expect(jobs).not.toHaveBeenCalled()
})

it('offers rollback for a successful uninstall when the server permits it, retaining detail after a failed request', async () => {
 vi.useFakeTimers()
 const client = new ControlV3(), job = { id: 'uninstall-success', node: 'node-a', username: 'fixture', kind: 'uninstall' as const, status: 'succeeded' as const, direction: 'forward' as const, node_version: 7, plan_digest: 'd'.repeat(64), step: 6, rollback_step: 0, recovery_required: false, error_code: '', log_cursor: 12, created_at: '', updated_at: '', finished_at: new Date().toISOString() }
 vi.spyOn(client, 'deployment').mockResolvedValue({ job, phase: 'complete', can_resume: false, can_rollback: true, recovery_required: false, recovery_reason: '' })
 vi.spyOn(client, 'deploymentLogs').mockResolvedValue({ items: [], next_cursor: 12, status: 'succeeded' })
 const recover = vi.spyOn(client, 'recoverDeployment').mockRejectedValue(new Error('宿主暂时不可达，原资料保留'))
 const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/deployments/:id', component: Deployments }, { path: '/configuration-applications', component: { template: '<div />' } }, { path: '/servers/:id', component: { template: '<div />' } }, { path: '/deployments', component: Deployments }] })
 await router.push('/deployments/uninstall-success'); await router.isReady()
 host = document.createElement('div'); document.body.append(host); app = createApp(Deployments); installElements(app); app.use(router)
 app.provide(consoleContext, { client, session: ref({ username: 'fixture', role: 'admin' as const, csrf: 'csrf' }) }); app.mount(host); await settle()
 expect(host.textContent).toContain('已确认卸载程序及自启动')
 const rollback = Array.from(host.querySelectorAll('button')).find(e => e.textContent?.trim() === '回退')!
 expect(rollback).toBeTruthy(); expect(host.textContent).not.toContain('继续原任务'); rollback.click(); await vi.advanceTimersByTimeAsync(100); await settle()
 expect(document.body.textContent).toContain('按原固定版本重新安装并复用保留数据')
 const confirm = document.body.querySelector('.el-popconfirm__action .el-button--primary') as HTMLButtonElement
 expect(confirm).toBeTruthy(); confirm.click(); await settle()
 expect(recover.mock.calls[0]?.slice(0, 4)).toEqual(['uninstall-success', 'rollback', job.plan_digest, 12])
 expect(host.textContent).toContain('宿主暂时不可达'); expect(host.textContent).toContain('已确认卸载程序及自启动'); expect(host.textContent).toContain('回退')
})
