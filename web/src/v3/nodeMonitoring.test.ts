// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest'
import { createApp, h, nextTick, ref, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { installElements } from '../elements'
import { ControlV3, type V3Node, type V3NodeMonitoring, type V3MonitoringRulesView } from '../controlV3'
import { consoleContext } from './context'
import { cancelReadRequests } from '../connection'
import NodeMonitoringFields from './NodeMonitoringFields.vue'
import Servers from './Servers.vue'

let app: App | undefined, host: HTMLDivElement
const defaults = (): V3MonitoringRulesView => ({ version: '4', rules: { roots: ['/srv/public'], extensions: ['.php'], important_filenames: ['.htaccess'], critical_paths: [], exclude_paths: [], reconciliation_interval_hours: 6 } })
const node = (): V3Node => ({ id: 'node-a', name: '原节点', endpoint: '192.0.2.10:19100', server_name: 'node-a', enabled: true, mode: 'docker', version: 3, applied_version: 3, shard: 0 })
async function settle() { for (let i = 0; i < 30; i++) { await Promise.resolve(); await nextTick() } }
function button(text: string) { const found = Array.from(document.querySelectorAll('button')).find(b => b.textContent?.trim() === text); if (!found) throw new Error(`missing ${text}`); return found }
function input(label: string, value: string) { const el = document.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[aria-label="${label}"]`)!; el.value = value; el.dispatchEvent(new Event('input', { bubbles: true })) }
async function mountFields(initial?: V3NodeMonitoring) {
  const value = ref(initial)
  host = document.createElement('div'); document.body.append(host)
  app = createApp({ setup: () => () => h(NodeMonitoringFields, { modelValue: value.value, defaults: defaults(), 'onUpdate:modelValue': (next: V3NodeMonitoring) => { value.value = next } }) }); installElements(app); app.mount(host); await settle(); return value
}
async function mountServers(client: ControlV3) {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/servers/:id?', component: Servers }, { path: '/deployments/:id?', component: { render: () => null } }] }); await router.push('/servers'); await router.isReady()
  host = document.createElement('div'); document.body.append(host); app = createApp(Servers); app.use(router); installElements(app); app.provide(consoleContext, { client, session: ref({ username: 'admin', role: 'admin' as const, csrf: 'fixture-csrf' }) }); app.mount(host); await settle()
}
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(el => el.remove()); cancelReadRequests(true); vi.restoreAllMocks() })

it('keeps unknown legacy rules untouched and inherited fields read only', async () => {
  await mountFields(); expect(host.textContent).toContain('监控规则未知'); expect(host.querySelector('textarea')).toBe(null)
  app!.unmount(); app = undefined; host.remove(); await mountFields({ source: 'inherited', rules: defaults().rules, rules_version: '4' })
  expect(Array.from(host.querySelectorAll('textarea')).every(field => field.disabled)).toBe(true); expect(host.textContent).toContain('跟随公共配置')
})

it('edits independent rules and copies public values only when explicitly requested', async () => {
  const value = await mountFields({ source: 'independent', rules: { ...defaults().rules, roots: ['/srv/private'] }, rules_version: '2' })
  input('忽略路径', '/srv/private/tmp/**\n'); await settle()
  expect(value.value!.rules.roots).toEqual(['/srv/private']); expect(value.value!.rules.exclude_paths).toEqual(['/srv/private/tmp/**']); expect(value.value!.rules.important_filenames).toEqual(['.htaccess'])
  button('复制公共配置').click(); await settle(); expect(value.value).toEqual({ source: 'independent', rules: defaults().rules, rules_version: '4' })
})

it('does not reinterpret legacy nodes as inherited when no rule evidence is available', async () => {
  const client = new ControlV3(); vi.spyOn(client, 'servers').mockResolvedValue({ items: [node()], next_cursor: '', limit: 20 }); vi.spyOn(client, 'server').mockResolvedValue({ node: node(), status: null, latest_deployment: null }); vi.spyOn(client, 'monitoringRules').mockResolvedValue(defaults())
  const save = vi.spyOn(client, 'saveServer').mockResolvedValue({ id: 'node-a', version: 4, message: '配置已保存，尚未部署' })
  await mountServers(client); button('编辑配置').click(); await settle(); expect(document.querySelector('.v3-node-dialog')?.textContent).toContain('监控规则未知')
  button('仅保存').click(); await settle(); expect(save).toHaveBeenCalledTimes(1); expect(save.mock.calls[0]?.[0].monitoring).toBeUndefined()
})

it('defaults new nodes to explicitly loaded public rules and retains independent values on edit', async () => {
  const current = node(); current.monitoring = { source: 'independent', rules: { ...defaults().rules, roots: ['/srv/custom'] }, rules_version: '2' }
  const client = new ControlV3(); vi.spyOn(client, 'servers').mockResolvedValue({ items: [current], next_cursor: '', limit: 20 }); vi.spyOn(client, 'monitoringRules').mockResolvedValue(defaults())
  const save = vi.spyOn(client, 'saveServer').mockResolvedValue({ id: 'node-a', version: 4, message: '配置已保存，尚未部署' })
  await mountServers(client); button('编辑配置').click(); await settle(); expect(document.querySelector<HTMLTextAreaElement>('[aria-label="公共监控根目录"]')!.value).toBe('/srv/custom')
  button('仅保存').click(); await settle(); expect(save.mock.calls[0]?.[0].monitoring).toEqual(current.monitoring)
  button('添加子服务器').click(); await settle(); expect(document.querySelector('.v3-node-dialog')?.textContent).toContain('跟随公共配置'); expect(document.querySelector<HTMLTextAreaElement>('[aria-label="公共监控根目录"]')!.value).toBe('/srv/public')
})

it('blocks creation when public defaults are unavailable instead of guessing rules', async () => {
  const client = new ControlV3(); vi.spyOn(client, 'servers').mockResolvedValue({ items: [], next_cursor: '', limit: 20 }); vi.spyOn(client, 'monitoringRules').mockRejectedValue(new Error('unavailable'))
  const save = vi.spyOn(client, 'saveServer')
  await mountServers(client); button('添加子服务器').click(); await settle()
  const dialog = document.querySelector('.v3-node-dialog')!, fields = dialog.querySelectorAll<HTMLInputElement>('input')
  ;['new-node', '新节点', '192.0.2.10:19100', 'new-node.example.test'].forEach((value, index) => { fields[index]!.value = value; fields[index]!.dispatchEvent(new Event('input', {bubbles:true})) })
  button('仅保存').click(); await settle()
  expect(save).not.toHaveBeenCalled(); expect(dialog.querySelector('.v3-dialog-feedback')?.textContent).toContain('公共规则尚未读取成功')
})

it('ignores defaults from a closed earlier node dialog', async () => {
  const client = new ControlV3(); vi.spyOn(client, 'servers').mockResolvedValue({ items: [], next_cursor: '', limit: 20 })
  let finish!: (value: V3MonitoringRulesView) => void
  const read = vi.spyOn(client, 'monitoringRules').mockImplementationOnce(() => new Promise(resolve => { finish = resolve })).mockResolvedValue(defaults())
  await mountServers(client); button('添加子服务器').click(); await settle(); button('取消').click(); await settle(); button('添加子服务器').click(); await settle()
  finish({version:'old', rules:{...defaults().rules, roots:['/old-dialog-only']}}); await settle()
  expect(read).toHaveBeenCalledTimes(2); expect(document.querySelector<HTMLTextAreaElement>('[aria-label="公共监控根目录"]')!.value).toBe('/srv/public')
})
