// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App, type Component } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { installElements } from '../elements'
import { ControlV3, type V3Node, type V3ServerDetail, type V3DeploymentDetail } from '../controlV3'
import { cancelReadRequests } from '../connection'
import { consoleContext } from './context'
import ConsoleApp from './App.vue'
import Servers from './Servers.vue'
import Deployments from './Deployments.vue'
import Events from './Events.vue'
import Alerts from './Alerts.vue'
import Websites from './Websites.vue'

vi.mock('element-plus/es/components/message/style/css', () => ({}))
vi.mock('../MetricChart.vue', () => ({ default: { props: ['title','option'], template: '<div class="chart" :data-option="JSON.stringify(option)">{{ title }}</div>' } }))

let app: App | undefined, host: HTMLDivElement
const node = (id = 'node-a'): V3Node => ({ id, name: `服务器 ${id}`, endpoint: '192.0.2.10:19100', server_name: 'node-a.example.test', enabled: true, mode: 'native', version: 2, applied_version: 1, shard: 1 })
const detail = (id = 'node-a'): V3ServerDetail => ({ node: node(id), status: null, latest_deployment: null })
const job = (status: 'running' | 'succeeded' = 'running'): V3DeploymentDetail => ({ job: { id: 'job-a', node: 'node-a', username: 'admin', kind: 'install', status, direction: 'forward', node_version: 2, plan_digest: 'a'.repeat(64), step: 0, rollback_step: 0, recovery_required: false, error_code: '', log_cursor: 0, created_at: '2026-10-18T00:00:00Z', updated_at: '2026-10-18T00:00:00Z', finished_at: null }, phase: 'preflight', can_resume: false, can_rollback: false, recovery_required: false, recovery_reason: '' })
const ok = (data: unknown) => new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } })
async function settle() { for (let i = 0; i < 18; i++) { await Promise.resolve(); await nextTick() }; if (!vi.isFakeTimers()) await new Promise(resolve => setTimeout(resolve, 20)) }
async function mount(component: Component, path: string, client = new ControlV3(), role: 'admin' | 'viewer' = 'admin') {
  if (!vi.isMockFunction(client.notificationStats)) vi.spyOn(client, 'notificationStats').mockResolvedValue({items:[],timezone:'Asia/Shanghai',group_by:'created_at'})
  if (!vi.isMockFunction(client.serverMetrics)) vi.spyOn(client, 'serverMetrics').mockResolvedValue({points: [], resolution_seconds: 30, start: 0, end: 0})
  if (!vi.isMockFunction(client.websiteIncidents)) vi.spyOn(client, 'websiteIncidents').mockResolvedValue({items: [], next_cursor: ''})
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/websites/:id?', component: Websites }, { path: '/alerts', component: Alerts }, { path: '/events', component: Events }, { path: '/servers/:id?', component: Servers }, { path: '/deployments/:id?', component: Deployments }, { path: '/login', component: { render: () => null } }] })
  await router.push(path); await router.isReady()
  host = document.createElement('div'); document.body.append(host)
  app = createApp(component); app.use(router); installElements(app)
  app.provide(consoleContext, { client, session: ref({ username: 'admin', role, csrf: 'fixture-csrf' }) })
  app.mount(host); await settle(); return router
}
function button(text: string, root: ParentNode = host) { const value = Array.from(root.querySelectorAll('button')).find(value => value.textContent?.trim() === text); if (!value) throw new Error(`button missing: ${text}`); return value }
function input(value: HTMLInputElement, text: string) { value.value = text; value.dispatchEvent(new Event('input', { bubbles: true })) }
beforeEach(() => { Object.defineProperty(document, 'hidden', { configurable: true, value: false }) })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(element => element.remove()); cancelReadRequests(true); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

it('loads only the requested server cursor, retains the submitted query and supports browser back', async () => {
  const client = new ControlV3()
  const read = vi.spyOn(client, 'servers').mockResolvedValue({ items: [node()], next_cursor: 'next-cursor', limit: 20 })
  const router = await mount(Servers, '/servers?q=生产', client)
  expect(read.mock.calls[0]?.slice(0, 3)).toEqual(['生产', '', 20])
  input(host.querySelector('input')!, '未提交')
  button('下一页').click(); await settle()
  expect(read.mock.calls.at(-1)?.slice(0, 3)).toEqual(['生产', 'next-cursor', 20])
  router.back(); await settle()
  expect(read.mock.calls.at(-1)?.slice(0, 3)).toEqual(['生产', '', 20])
  expect(host.textContent).toContain('待应用')
  expect(host.textContent).not.toContain('已部署成功')
})

it('shows saved intent separately from the registered runtime and excludes runtime metadata from edits', async () => {
  const client = new ControlV3(), saved = node()
  saved.enabled = false
  saved.version = 4
  saved.configuration = { registered_version: 3, delivered_version: 3, runtime_enabled: true, runtime_mode: 'native', runtime_endpoint: '192.0.2.20:19100' }
  vi.spyOn(client, 'servers').mockResolvedValue({ items: [saved], next_cursor: '', limit: 20 })
  const save = vi.spyOn(client, 'saveServer').mockResolvedValue({ id: saved.id, version: 5, message: '配置已保存，尚未部署' })
  await mount(Servers, '/servers', client)
  expect(host.textContent).toContain('保存 4 / 下发 3 / 生效 1')
  expect(host.textContent).toContain('已启用')
  expect(host.textContent).toContain('保存：停用')
  button('编辑配置').click(); await settle()
  const dialog = document.querySelector('.v3-node-dialog')!
  expect(dialog.textContent).toContain('不改变当前采集或告警')
  button('仅保存', dialog).click(); await settle()
  expect(save.mock.calls[0]?.[0]).toEqual({ id: saved.id, name: saved.name, endpoint: saved.endpoint, server_name: saved.server_name, mode: saved.mode, enabled: false })
  expect(save.mock.calls[0]?.[0]).not.toHaveProperty('configuration')
})

it('does not describe a saved unregistered node as running or successfully collected', async () => {
  const client = new ControlV3(), saved = detail()
  saved.node.applied_version = 0
  saved.node.configuration = { registered_version: 0, delivered_version: 0, runtime_enabled: null, runtime_mode: '', runtime_endpoint: '' }
  vi.spyOn(client, 'server').mockResolvedValue(saved)
  await mount(Servers, '/servers/node-a', client)
  expect(host.textContent).toContain('保存 2 / 下发 — / 生效 —')
  expect(host.textContent).toContain('尚未登记，待部署')
  expect(host.textContent).not.toContain('最近一次采集成功')
})

it('aborts navigation reads and ignores late success from an earlier detail', async () => {
  const client = new ControlV3()
  let oldResolve!: (value: V3ServerDetail) => void
  const read = vi.spyOn(client, 'server').mockImplementation(id => id === 'node-a' ? new Promise(resolve => { oldResolve = resolve }) : Promise.resolve(detail('node-b')))
  const router = await mount(Servers, '/servers/node-a', client)
  const signal = read.mock.calls[0]![1]!
  await router.push('/servers/node-b'); await settle()
  expect(signal.aborted).toBe(true)
  oldResolve(detail('node-a')); await settle()
  expect(host.querySelector('h1')?.textContent).toBe('服务器详情'); expect(host.querySelector('[aria-label="选择服务器"]')?.closest('.el-select')?.textContent).toContain('服务器 node-b')
  expect(host.textContent).toContain('未知，尚无采集证据')
})

it('shows real zero metrics while leaving missing values and versions unknown', async () => {
  const client = new ControlV3(), value = detail()
  value.status = { sampled_at: null, updated_at: '2026-10-18T00:00:00Z', error: '', metrics_error: '', events_error: '', protocol_error: '', metrics: { cpu_percent: 0, memory_percent: null, disk_percent: null, uptime: null }, info: { hostname: null, kernel: null, architecture: null, agent_version: null, agent_mode: null } }
  vi.spyOn(client, 'server').mockResolvedValue(value)
  vi.spyOn(client,'serverMetrics').mockResolvedValue({points:[{time:100,ok:true,values:{cpu_percent:0}}],resolution_seconds:30,start:100,end:100})
  await mount(Servers, '/servers/node-a', client)
  const charts=Array.from(host.querySelectorAll('.chart'))
  const cpu=JSON.parse(charts.find(el=>el.textContent==='CPU 使用率')!.getAttribute('data-option')!)
  const memory=JSON.parse(charts.find(el=>el.textContent==='内存使用情况')!.getAttribute('data-option')!)
  expect(cpu.series[0].data).toEqual([[100000,0]])
  expect(memory.series[0].data).toEqual([[100000,null]])
  expect(host.textContent).toContain('未知')
})

it('saves only metadata with a stable retry key and visible persistent failure feedback', async () => {
  const client = new ControlV3()
  vi.spyOn(client, 'servers').mockResolvedValue({ items: [], next_cursor: '', limit: 20 })
  const save = vi.spyOn(client, 'saveServer').mockRejectedValueOnce(new Error('配置版本已变化')).mockResolvedValueOnce({ id: 'new-node', version: 1, message: '配置已保存，尚未部署' })
  await mount(Servers, '/servers', client)
  button('添加子服务器').click(); await settle()
  const dialog = document.querySelector('.v3-node-dialog')!
  const fields = Array.from(dialog.querySelectorAll<HTMLInputElement>('input.el-input__inner'))
  ;['new-node', '测试服务器', '192.0.2.11:19100', 'node.example.test'].forEach((value, index) => input(fields[index]!, value))
  button('仅保存', dialog).click(); await settle()
  expect(dialog.querySelector('.v3-dialog-feedback')?.textContent).toContain('配置版本已变化')
  expect(fields[0]!.value).toBe('new-node')
  button('仅保存', dialog).click(); await settle()
  expect(save).toHaveBeenCalledTimes(2)
  expect(save.mock.calls[0]?.[2]).toBe(save.mock.calls[1]?.[2])
  expect(save.mock.calls[0]?.[0]).toEqual({ id: 'new-node', name: '测试服务器', endpoint: '192.0.2.11:19100', server_name: 'node.example.test', enabled: true, mode: 'docker' })
  expect(save.mock.calls[0]?.[1]).toBe(0)
  expect(host.textContent).toContain('配置已保存，尚未部署')
})

it('does not offer configuration writes to a viewer', async () => {
  const client = new ControlV3()
  vi.spyOn(client, 'servers').mockResolvedValue({ items: [node()], next_cursor: '', limit: 20 })
  await mount(Servers, '/servers', client, 'viewer')
  expect(host.textContent).not.toContain('添加服务器')
  expect(Array.from(host.querySelectorAll('button')).some(value => value.textContent?.trim() === '编辑')).toBe(false)
  expect(Array.from(host.querySelectorAll('button')).some(value => value.textContent?.trim() === '移除记录')).toBe(false)
})

it('removes a stale server only after explicit confirmation and retains its retry key on failure', async () => {
  const client = new ControlV3(), stale = { ...node(), can_remove: true, collection_state: 'disabled' as const }
  const read = vi.spyOn(client, 'servers').mockResolvedValueOnce({ items: [stale], next_cursor: '', limit: 20 }).mockResolvedValue({ items: [], next_cursor: '', limit: 20 })
  const remove = vi.spyOn(client, 'removeServerRecords').mockRejectedValueOnce(new Error('配置备份失败，原记录保留')).mockResolvedValue({ removed: 1, message: '服务器记录已移除，已停止采集；未远程卸载程序，历史数据已保留' })
  await mount(Servers, '/servers', client)
  button('移除记录').click(); await settle()
  const dialog = document.querySelector('.el-dialog[aria-labelledby]') || document.querySelector('.el-dialog')!
  expect(dialog.textContent).toContain('不会连接服务器或卸载远程程序')
  expect(dialog.textContent).toContain(stale.endpoint)
  expect(button('确认移除记录', dialog).disabled).toBe(true)
  expect(remove).not.toHaveBeenCalled()
  ;(dialog.querySelector('input[type="checkbox"]') as HTMLInputElement).click(); await settle()
  button('确认移除记录', dialog).click(); await settle()
  expect(dialog.querySelector('.v3-dialog-feedback')?.textContent).toContain('配置备份失败')
  expect(remove.mock.calls[0]?.[0]).toEqual([{ id: stale.id, expected_version: stale.version }])
  button('确认移除记录', dialog).click(); await settle()
  expect(remove).toHaveBeenCalledTimes(2)
  expect(remove.mock.calls[0]?.[1]).toBe(remove.mock.calls[1]?.[1])
  expect(read).toHaveBeenCalledTimes(2)
  expect(host.textContent).toContain('历史数据已保留')
})

it('explains protected records and fails closed if an older server omits removal capability', async () => {
  const client = new ControlV3()
  vi.spyOn(client, 'servers').mockResolvedValue({ items: [{ ...node(), can_remove: false, remove_reason: '存在未完成部署，请先继续或回退原任务' }, node('older-api')], next_cursor: '', limit: 20 })
  const remove = vi.spyOn(client, 'removeServerRecords')
  await mount(Servers, '/servers', client)
  expect(host.textContent).toContain('存在未完成部署，请先继续或回退原任务')
  const buttons = Array.from(host.querySelectorAll('button')).filter(value => value.textContent?.trim() === '移除记录')
  expect(buttons).toHaveLength(2)
  expect(buttons.every(value => value.disabled)).toBe(true)
  expect(button('移除已选记录（0）').disabled).toBe(true)
  expect(remove).not.toHaveBeenCalled()
})

it('replaces a pending deployment filter read instead of silently ignoring the new query', async () => {
  const client = new ControlV3()
  let reject!: (error: Error) => void
  const read = vi.spyOn(client, 'deployments').mockImplementation(node => node === 'old' ? new Promise((_, no) => { reject = no }) : Promise.resolve({ items: [], next_cursor: '', limit: 20 }))
  const router = await mount(Deployments, '/deployments?node=old', client)
  const signal = read.mock.calls[0]![3]!
  await router.push('/deployments?node=new'); await settle()
  reject(new Error('过期查询失败')); await settle()
  expect(signal.aborted).toBe(true)
  expect(read.mock.calls.at(-1)?.slice(0, 3)).toEqual(['new', '', 20])
  expect(host.textContent).not.toContain('过期查询失败')
})

it('tails logs from their accepted cursor and pauses polling in a background tab', async () => {
  vi.useFakeTimers()
  const client = new ControlV3()
  vi.spyOn(client, 'deployment').mockResolvedValueOnce(job()).mockResolvedValue(job('succeeded'))
  const read = vi.spyOn(client, 'deploymentLogs').mockResolvedValueOnce({ items: [{ cursor: 1, phase: 'preflight', code: 'queued', created_at: '2026-10-18T00:00:00Z' }], next_cursor: 1, status: 'running' }).mockResolvedValue({ items: [{ cursor: 2, phase: 'finalize', code: 'succeeded', created_at: '2026-10-18T00:00:01Z' }], next_cursor: 2, status: 'succeeded' })
  await mount(Deployments, '/deployments/job-a', client)
  expect(read.mock.calls[0]?.slice(0, 3)).toEqual(['job-a', 0, 100])
  Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange'))
  await vi.advanceTimersByTimeAsync(9000); expect(read).toHaveBeenCalledTimes(1)
  Object.defineProperty(document, 'hidden', { configurable: true, value: false }); document.dispatchEvent(new Event('visibilitychange')); await settle()
  expect(read.mock.calls[1]?.slice(0, 3)).toEqual(['job-a', 1, 100])
  expect(host.querySelector('[aria-label="部署进程日志"]')?.textContent?.trim().split('\n')).toHaveLength(2)
  await vi.advanceTimersByTimeAsync(9000); expect(read).toHaveBeenCalledTimes(2)
  expect(host.textContent).toContain('部署成功')
})

it('shows a historical recovery task and its restore phase in the list and log detail', async () => {
  const client = new ControlV3(), value = job('succeeded')
  Object.assign(value.job, { kind: 'recover', direction: 'rollback', status: 'rolled_back', step: 0, rollback_step: 2 })
  value.phase = 'complete'
  vi.spyOn(client, 'deployments').mockResolvedValue({ items: [value.job], next_cursor: '', limit: 20 })
  vi.spyOn(client, 'deployment').mockResolvedValue(value)
  vi.spyOn(client, 'deploymentLogs').mockResolvedValue({ items: [{ cursor: 1, phase: 'verify-rollback', code: 'rolled-back', created_at: '2026-10-18T00:00:00Z' }], next_cursor: 1, status: 'rolled_back' })
  const router = await mount(Deployments, '/deployments', client)
  expect(host.textContent).toContain('历史恢复')
  await router.push('/deployments/job-a'); await settle()
  expect(host.querySelector('h2')?.textContent).toContain('历史恢复')
  expect(host.textContent).toContain('回退验收')
  expect(host.textContent).toContain('回退完成')
})

it('uses only v3 endpoints, restores csrf and revokes the current session on logout', async () => {
  const calls: [string, RequestInit][] = []
  vi.stubGlobal('fetch', vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
    calls.push([url, init])
    if (url === '/api/v3/session') return ok({ username: 'admin', role: 'admin', csrf: 'persistent-csrf' })
    if (url.startsWith('/api/v3/servers?')) return ok({ items: [node()], next_cursor: '', limit: 20 })
    if (url === '/api/v3/logout') return ok({ ok: true })
    throw new Error('unexpected request')
  }))
  const router = await mount(ConsoleApp, '/servers')
  expect(host.textContent).toContain('服务器 node-a')
  button('退出登录').click(); await settle()
  expect(router.currentRoute.value.path).toBe('/login')
  expect((calls.find(([path]) => path === '/api/v3/logout')![1].headers as Record<string, string>)['X-CSRF-Token']).toBe('persistent-csrf')
  expect(calls.every(([path]) => path.startsWith('/api/v3/'))).toBe(true)
})

it('opens a clean login form for an anonymous visitor without claiming an expired session', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ message: '请先登录' }), { status: 401 })))
  const router = await mount(ConsoleApp, '/servers')
  expect(router.currentRoute.value.path).toBe('/login')
  expect(host.textContent).toContain('登录管理后台')
  expect(host.textContent).not.toContain('登录已失效')
})

it('shows session expiration only after an authenticated read actually returns 401', async () => {
  let expired = false
  vi.stubGlobal('fetch', vi.fn().mockImplementation(async (url: string) => {
    if (url === '/api/v3/session') return ok({ username: 'admin', role: 'admin', csrf: 'fixture-csrf' })
    if (expired) return new Response(JSON.stringify({ message: '请先登录' }), { status: 401 })
    return ok({ items: [node()], next_cursor: '', limit: 20 })
  }))
  const router = await mount(ConsoleApp, '/servers')
  expired = true; button('刷新').click(); await settle()
  expect(router.currentRoute.value.path).toBe('/login')
  expect(host.textContent).toContain('登录已失效，请重新登录')
  expect(host.textContent).not.toContain('服务器 node-a')
})

it('keeps the session and existing results on 503, then reconnects with the same request', async () => {
  vi.useFakeTimers()
  let failing = false
  const send = vi.fn().mockImplementation(async (url: string) => {
    if (url === '/api/v3/session') return ok({ username: 'admin', role: 'admin', csrf: 'fixture-csrf' })
    if (failing) return new Response(JSON.stringify({ code: 'query_failed', message: '暂时不可用' }), { status: 503 })
    return ok({ items: [node()], next_cursor: '', limit: 20 })
  })
  vi.stubGlobal('fetch', send)
  const router = await mount(ConsoleApp, '/servers')
  failing = true; button('刷新').click(); await settle()
  expect(host.textContent).toContain('已有内容保留')
  expect(host.textContent).toContain('服务器 node-a')
  expect(router.currentRoute.value.path).toBe('/servers')
  const last = send.mock.calls.at(-1)![0]
  failing = false; await vi.advanceTimersByTimeAsync(3000); await settle()
  expect(send.mock.calls.at(-1)![0]).toBe(last)
  expect(host.textContent).not.toContain('已有内容保留')
})

it('replaces chart requests on range changes and ignores old-node errors', async () => {
  const client = new ControlV3(); vi.spyOn(client,'server').mockImplementation(async id => detail(id))
  let reject!: (e:Error)=>void
  const trends=vi.spyOn(client,'serverMetrics').mockImplementationOnce(()=>new Promise((_,no)=>{reject=no})).mockResolvedValue({points:[],resolution_seconds:30,start:0,end:0})
  const router=await mount(Servers,'/servers/node-a',client)
  const old=trends.mock.calls[0]?.[3]!
  await router.push('/servers/node-b?hours=24');await settle()
  expect(old.aborted).toBe(true);expect(trends.mock.calls.at(-1)?.[0]).toBe('node-b')
  const call=trends.mock.calls.at(-1)!;expect(Date.parse(call[2])-Date.parse(call[1])).toBe(24*3600_000)
  reject(new Error('旧节点曲线错误'));await settle();expect(host.textContent).not.toContain('旧节点曲线错误')
  await router.push('/servers/node-b?hours=0&start=2026-01-01T00:00&end=2026-03-01T00:00');await settle()
  expect(host.textContent).toContain('范围不能超过 31 天');expect(trends).toHaveBeenCalledTimes(2)
})

it('resizes server pages using submitted filters and the first opaque cursor', async () => {
 const client=new ControlV3(),read=vi.spyOn(client,'servers').mockResolvedValue({items:[node()],next_cursor:'second',limit:20})
 const router=await mount(Servers,'/servers?q=已提交&status=stale',client)
 input(host.querySelector('input')!,'草稿');button('下一页').click();await settle()
 host.querySelector<HTMLInputElement>('[aria-label="每页条数"]')!.click();await settle()
 Array.from(document.querySelectorAll<HTMLElement>('[role="option"]')).find(el=>el.textContent?.trim()==='50 条／页')!.click();await settle()
 expect(router.currentRoute.value.query).toMatchObject({q:'已提交',status:'stale',limit:'50'})
 expect(router.currentRoute.value.query.cursor).toBeUndefined()
 expect(read.mock.calls.at(-1)?.slice(0,3)).toEqual(['已提交','',50]);expect(read.mock.calls.at(-1)?.[4]).toBe('stale')
})
