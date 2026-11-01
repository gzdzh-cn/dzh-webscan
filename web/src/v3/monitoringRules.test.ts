// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { installElements } from '../elements'
import { ControlV3, V3Error, type V3MonitoringRulesView, type V3Role } from '../controlV3'
import { consoleContext } from './context'
import { cancelReadRequests } from '../connection'
import MonitoringRules from './MonitoringRules.vue'

let app: App | undefined, host: HTMLDivElement
const rules = (): V3MonitoringRulesView => ({ version: '9007199254740993', rules: { roots: ['/srv/site'], extensions: ['.php'], important_filenames: ['.htaccess'], critical_paths: ['/srv/site/config.php'], exclude_paths: ['/srv/site/cache/**'], reconciliation_interval_hours: 6 } })
async function settle() { for (let i = 0; i < 30; i++) { await Promise.resolve(); await nextTick() } }
function fixture() {
  const client = new ControlV3(), load = vi.spyOn(client, 'monitoringRules').mockResolvedValue(rules())
  const preview = vi.spyOn(client, 'previewMonitoringRules').mockResolvedValue({ token: 'rules-preview', expires_at: new Date(Date.now() + 600_000).toISOString(), changed_fields: ['roots'] })
  const save = vi.spyOn(client, 'saveMonitoringRules').mockImplementation(async input => ({ version: '9007199254740994', rules: input.rules }))
  return { client, load, preview, save }
}
async function mount(f = fixture(), role: V3Role = 'admin') {
  host = document.createElement('div'); document.body.append(host); app = createApp(MonitoringRules); installElements(app)
  app.provide(consoleContext, { client: f.client, session: ref({ username: 'admin', role, csrf: 'fixture-csrf' }) }); app.mount(host); await settle(); return f
}
function button(text: string) { const found = Array.from(document.querySelectorAll('button')).find(b => b.textContent?.trim() === text); if (!found) throw new Error(`missing ${text}`); return found }
function input(label: string, value: string) { const el = host.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[aria-label="${label}"]`)!; el.value = value; el.dispatchEvent(new Event('input', { bubbles: true })) }
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(el => el.remove()); cancelReadRequests(true); vi.restoreAllMocks() })

it('previews exact saved-version rules and saves without applying nodes', async () => {
  const f = await mount(); expect(host.textContent).toContain('9007199254740993')
  input('公共监控根目录', '/srv/site\n/srv/second'); await settle(); button('校验并预览公共规则').click(); await settle()
  expect(f.preview).toHaveBeenCalledWith({ expected_version: '9007199254740993', rules: { ...rules().rules, roots: ['/srv/site', '/srv/second'] } })
  expect(f.save).not.toHaveBeenCalled(); button('确认仅保存公共规则').click(); await settle()
  expect(f.save.mock.calls[0]?.[0].preview).toBe('rules-preview'); expect(f.save.mock.calls[0]?.[1]).toMatch(/^[0-9a-f-]{36}$/)
  expect(host.textContent).toContain('公共规则已保存，尚未下发'); expect(host.textContent).toContain('9007199254740994')
})

it('keeps textarea newlines while editing and validates interval before preview', async () => {
  const f = await mount(); input('公共监控根目录', '/srv/site\n'); await settle()
  expect(host.querySelector<HTMLTextAreaElement>('[aria-label="公共监控根目录"]')!.value).toBe('/srv/site\n')
  input('清单核对间隔（小时）', '1e2'); await settle(); button('校验并预览公共规则').click(); await settle()
  expect(host.textContent).toContain('请输入 1～8760 的整数'); expect(f.preview).not.toHaveBeenCalled()
})

it('keeps drafts on a version conflict and requires a fresh preview', async () => {
  const f = fixture(); f.save.mockRejectedValue(new V3Error(409, 'configuration_conflict', '规则版本已变化'))
  await mount(f); input('忽略路径', '/srv/site/tmp/**'); await settle(); button('校验并预览公共规则').click(); await settle(); button('确认仅保存公共规则').click(); await settle()
  expect(host.textContent).toContain('规则版本已变化'); expect(host.querySelector<HTMLTextAreaElement>('[aria-label="忽略路径"]')!.value).toBe('/srv/site/tmp/**')
  expect(f.load).toHaveBeenCalledTimes(1); expect(button('校验并预览公共规则').disabled).toBe(false)
})

it('retries an uncertain save with the original idempotency key and preview', async () => {
  const f = fixture(); f.save.mockRejectedValueOnce(new V3Error(0, 'connection_unavailable', '连接中断'))
  await mount(f); input('公共监控根目录', '/srv/new'); await settle(); button('校验并预览公共规则').click(); await settle(); button('确认仅保存公共规则').click(); await settle()
  expect(document.body.textContent).toContain('连接中断'); button('确认仅保存公共规则').click(); await settle()
  expect(f.save).toHaveBeenCalledTimes(2); expect(f.save.mock.calls[0]).toEqual(f.save.mock.calls[1]); expect(f.preview).toHaveBeenCalledTimes(1)
})

it('does not submit expired previews', async () => {
  const f = fixture(); f.preview.mockResolvedValue({ token: 'old', expires_at: new Date(Date.now() - 1000).toISOString(), changed_fields: ['roots'] })
  await mount(f); input('公共监控根目录', '/srv/new'); await settle(); button('校验并预览公共规则').click(); await settle(); button('确认仅保存公共规则').click(); await settle()
  expect(f.save).not.toHaveBeenCalled(); expect(host.textContent).toContain('预览已过期')
})

it('asks before discarding drafts and restricts reads and writes to administrators', async () => {
  const f = await mount(); input('公共监控根目录', '/srv/new'); await settle(); button('重新读取公共规则').click(); await settle()
  expect(f.load).toHaveBeenCalledTimes(1); button('保留草稿').click(); await settle(); expect(host.querySelector<HTMLTextAreaElement>('[aria-label="公共监控根目录"]')!.value).toBe('/srv/new')
  app!.unmount(); app = undefined; host.remove(); const viewer = fixture(); await mount(viewer, 'viewer')
  expect(viewer.load).not.toHaveBeenCalled(); expect(host.textContent).toContain('只有管理员'); expect(host.querySelector('textarea')).toBe(null)
})

it('ignores a preview response after leaving the page', async () => {
  const f = fixture(); let resolve!: (value: Awaited<ReturnType<ControlV3['previewMonitoringRules']>>) => void
  f.preview.mockImplementation(() => new Promise(yes => { resolve = yes })); await mount(f); input('公共监控根目录', '/srv/new'); await settle(); button('校验并预览公共规则').click(); await settle()
  app!.unmount(); app = undefined; resolve({ token: 'late', expires_at: new Date(Date.now() + 600_000).toISOString(), changed_fields: ['roots'] }); await settle()
  expect(f.save).not.toHaveBeenCalled(); expect(document.body.textContent).not.toContain('确认仅保存公共规则')
})
