// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { ControlV3, V3Error, type V3SettingsView, type V3SettingsPreview } from '../controlV3'
import { installElements } from '../elements'
import { consoleContext } from './context'
import { cancelReadRequests } from '../connection'
import RuntimeSettings from './RuntimeSettings.vue'
let app: App | undefined, host: HTMLDivElement
const view = (pending = false): V3SettingsView => ({ state: { generation: pending ? '2' : '0', applied_generation: '0', runtime_version: 5, pending, updated_at: '2026-10-19T00:00:00Z' }, fields: [
  { path: 'website_monitor.interval_seconds', label: '网站检测间隔（秒）', kind: 'integer', min: 10, max: 3600 },
  { path: 'website_monitor.enabled', label: '网站检测', kind: 'bool' },
  { path: 'email.enabled', label: '邮箱通知', kind: 'bool' },
  { path: 'email.smtp_host', label: 'SMTP 主机', kind: 'text', max: 253 },
  { path: 'email.recipients', label: '收件邮箱', kind: 'addresses', max: 20 },
], values: { 'website_monitor.interval_seconds': 30, 'email.enabled': false }, runtime_values: { 'website_monitor.interval_seconds': pending ? 60 : 30, 'email.enabled': false }, secret_configured: { 'email.password': true }, runtime_secret_configured: { 'email.password': true } })
const preview = (action: 'save' | 'apply' = 'save'): V3SettingsPreview => ({ token: 'private-bound-preview', action, expires_at: new Date(Date.now() + 600_000).toISOString(), changed_fields: ['website_monitor.interval_seconds'], retention_shortened: false, notifications_enabled: false })
async function settle() { for (let i = 0; i < 40; i++) { await Promise.resolve(); await nextTick() } }
function fixture(pending = false) {
  const client = new ControlV3(), load = vi.spyOn(client, 'settings').mockResolvedValue(view(pending))
  const inspect = vi.spyOn(client, 'previewSettings').mockImplementation(async input => preview(input.action))
  const save = vi.spyOn(client, 'confirmSettings').mockResolvedValue({ ...view().state, generation: '3', pending: true })
  return { client, load, inspect, save }
}
async function mount(f = fixture(), role = 'admin') {
  host = document.createElement('div'); document.body.append(host); app = createApp(RuntimeSettings); installElements(app)
  app.provide(consoleContext, { client: f.client, session: ref({ username: 'admin', role: role as 'admin', csrf: 'csrf' }) }); app.mount(host); await settle(); return f
}
function button(text: string, root: ParentNode = document) { const b = Array.from(root.querySelectorAll('button')).find(b => b.textContent?.trim() === text); if (!b) throw new Error(`missing ${text}`); return b }
function input(label: string, value: string) { const field = host.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[aria-label="${label}"]`)!; field.value = value; field.dispatchEvent(new Event('input', { bubbles: true })) }
function select(label: string, value: string) { const field = host.querySelector<HTMLSelectElement>(`select[aria-label="${label}"]`)!; field.value = value; field.dispatchEvent(new Event('change', { bubbles: true })) }
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(e => e.remove()); cancelReadRequests(true); vi.useRealTimers(); vi.restoreAllMocks() })
it('shows safe configured flags and absent fields without pretending they are runtime defaults', async () => {
  await mount(); expect(host.textContent).toContain('已配置，留空保留'); expect(host.textContent).toContain('运行版本 5'); expect(host.querySelector<HTMLSelectElement>('[aria-label="网站检测"]')!.value).toBe('')
  expect(host.querySelector<HTMLInputElement>('[aria-label="SMTP 主机"]')!.value).toBe(''); expect(button('预览并保存设置').disabled).toBe(true); expect(host.textContent).not.toContain('删除')
})
it('validates edits, previews before saving and never applies a saved draft automatically', async () => {
  const f = await mount(); input('网站检测间隔（秒）', '1e2'); await settle(); button('预览并保存设置').click(); await settle(); expect(host.textContent).toContain('请输入 10～3600 的整数'); expect(f.inspect).not.toHaveBeenCalled()
  input('网站检测间隔（秒）', '45'); await settle(); button('预览并保存设置').click(); await settle(); expect(f.inspect.mock.calls[0]?.[0]).toEqual({ action: 'save', expected_generation: '0', expected_runtime_version: 5, edit: { values: { 'website_monitor.interval_seconds': 45 }, secrets: {} } })
  expect(f.save).not.toHaveBeenCalled(); expect(document.body.textContent).toContain('仅保存配置，不立即生效'); button('确认仅保存').click(); await settle(); expect(f.save.mock.calls[0]?.[0].preview).toBe('private-bound-preview'); expect(f.inspect).toHaveBeenCalledTimes(1); expect(host.textContent).toContain('配置已保存，尚未应用')
})
it('uses explicit credential actions, hides entered secrets in preview and clears temporary values on close', async () => {
  const f = await mount(); select('SMTP 密码／授权码操作', 'replace'); await settle(); input('SMTP 密码／授权码', 'private-smtp-secret'); button('预览并保存设置').click(); await settle()
  expect(f.inspect.mock.calls[0]?.[0].edit.secrets).toEqual({ 'email.password': { action: 'replace', value: 'private-smtp-secret' } }); expect(document.querySelector('.v3-node-dialog')!.textContent).not.toContain('private-smtp-secret'); button('返回修改').click(); await settle()
  expect(host.querySelector('[aria-label="SMTP 密码／授权码"]')).toBeNull(); select('SMTP 密码／授权码操作', 'clear'); await settle(); button('预览并保存设置').click(); await settle(); expect(f.inspect.mock.calls[1]?.[0].edit.secrets).toEqual({ 'email.password': { action: 'clear' } })
})
it('applies only saved state and blocks apply while there is unsaved input', async () => {
  const f = await mount(fixture(true)); input('网站检测间隔（秒）', '44'); await settle(); expect(button('预览应用已保存设置').disabled).toBe(true)
  input('网站检测间隔（秒）', '30'); await settle(); button('预览应用已保存设置').click(); await settle(); expect(f.inspect.mock.calls[0]?.[0]).toEqual({ action: 'apply', expected_generation: '2', expected_runtime_version: 5, edit: {} })
  expect(document.body.textContent).toContain('后续检测及通知任务使用新配置'); button('确认应用已保存设置').click(); await settle(); expect(f.save.mock.calls[0]?.[0].action).toBe('apply')
})
it('retains an ambiguous confirmation and retry key; a conflict requires fresh preview', async () => {
  const f = fixture(); f.save.mockRejectedValue(new V3Error(0, 'connection_unavailable', '连接中断')); await mount(f); input('网站检测间隔（秒）', '42'); await settle(); button('预览并保存设置').click(); await settle(); button('确认仅保存').click(); await settle(); button('确认仅保存').click(); await settle()
  expect(f.save.mock.calls[0]?.[1]).toBe(f.save.mock.calls[1]?.[1]); expect(host.querySelector<HTMLInputElement>('[aria-label="网站检测间隔（秒）"]')!.value).toBe('42')
  f.save.mockRejectedValue(new V3Error(409, 'settings_conflict', '预览已变化')); button('确认仅保存').click(); await settle(); expect(host.textContent).toContain('预览已变化'); expect(button('预览并保存设置').disabled).toBe(false)
  button('预览并保存设置').click(); await settle(); button('确认仅保存').click(); await settle(); expect(f.save.mock.calls[3]?.[1]).not.toBe(f.save.mock.calls[0]?.[1])
})
it('displays activation/retention warnings and refuses expired previews', async () => {
  vi.useFakeTimers(); const f = fixture(); f.inspect.mockResolvedValue({ ...preview(), retention_shortened: true, notifications_enabled: true }); await mount(f); input('网站检测间隔（秒）', '42'); await settle(); button('预览并保存设置').click(); await settle()
  expect(document.body.textContent).toContain('已有待投递记录可能继续投递'); expect(document.body.textContent).toContain('永久清理'); await vi.advanceTimersByTimeAsync(600_001); button('确认仅保存').click(); await settle(); expect(f.save).not.toHaveBeenCalled(); expect(host.textContent).toContain('预览已过期')
})
it('requires explicit discard before reload and preserves input when reloading fails', async () => {
  const f = await mount(); input('网站检测间隔（秒）', '44'); await settle(); button('重新读取运行设置').click(); await settle(); expect(f.load).toHaveBeenCalledTimes(1); button('保留草稿').click(); await settle(); expect(f.load).toHaveBeenCalledTimes(1)
  f.load.mockRejectedValue(new Error('数据库不可用')); button('重新读取运行设置').click(); await settle(); button('放弃草稿并读取设置').click(); await settle(); expect(host.querySelector<HTMLInputElement>('[aria-label="网站检测间隔（秒）"]')!.value).toBe('44'); expect(host.textContent).toContain('已有输入保留')
})
it('ignores late preview after unmount and restricts all settings reads to admin', async () => {
  const f = fixture(); let resolve!: (v: V3SettingsPreview) => void; f.inspect.mockImplementation(() => new Promise(yes => { resolve = yes })); await mount(f); input('网站检测间隔（秒）', '44'); await settle(); button('预览并保存设置').click(); await settle(); app!.unmount(); app = undefined; resolve(preview()); await settle(); expect(f.save).not.toHaveBeenCalled(); expect(document.body.textContent).not.toContain('确认仅保存')
  host.remove(); const other = fixture(); await mount(other, 'operator'); expect(other.load).not.toHaveBeenCalled(); expect(host.textContent).toContain('只有管理员')
})
