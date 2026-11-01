// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, h, nextTick, ref, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { installElements } from '../elements'
import { ControlV3, type V3Role } from '../controlV3'
import { consoleContext } from './context'
import { cancelReadRequests } from '../connection'
import PasswordDialog from './PasswordDialog.vue'
import ConsoleApp from './App.vue'

let app: App | undefined, host: HTMLDivElement
async function settle() { for (let i = 0; i < 25; i++) { await Promise.resolve(); await nextTick() } }
function button(text: string, root: ParentNode = document) {
  const found = Array.from(root.querySelectorAll('button')).find(b => b.textContent?.trim() === text)
  if (!found) throw new Error(`button missing: ${text}`)
  return found
}
function field(label: string) { return document.querySelector<HTMLInputElement>(`.v3-password-dialog input[aria-label="${label}"]`)! }
function input(label: string, value: string) { const el = field(label); el.value = value; el.dispatchEvent(new Event('input', { bubbles: true })) }
function enter(next = 'new-test-password') { input('当前密码', 'old-test-password'); input('新密码', next); input('确认新密码', next) }
async function mountDialog(client = new ControlV3(), role: V3Role = 'admin') {
  const opened = ref(true), changed = vi.fn()
  host = document.createElement('div'); document.body.append(host)
  app = createApp({ setup: () => () => h(PasswordDialog, { modelValue: opened.value, 'onUpdate:modelValue': (value: boolean) => { opened.value = value }, onChanged: changed }) })
  installElements(app); app.provide(consoleContext, { client, session: ref({ username: 'account-a', role, csrf: 'fixture-csrf' }) }); app.mount(host)
  await settle(); return { opened, changed }
}
beforeEach(() => { Object.defineProperty(document, 'hidden', { configurable: true, value: false }) })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(el => el.remove()); cancelReadRequests(true); vi.restoreAllMocks(); vi.unstubAllGlobals() })

it('validates byte length and confirmation without sending passwords', async () => {
  const client = new ControlV3(), write = vi.spyOn(client, 'changePassword')
  await mountDialog(client)
  button('修改密码并退出').click(); await settle(); expect(document.body.textContent).toContain('请输入当前密码')
  enter('中文中文中文中文中文中文中文中文中文中文中文中文中文'); button('修改密码并退出').click(); await settle()
  expect(document.body.textContent).toContain('12～72 字节'); expect(write).not.toHaveBeenCalled()
  enter(); input('确认新密码', 'different-password'); button('修改密码并退出').click(); await settle()
  expect(document.body.textContent).toContain('确认密码与新密码不一致'); expect(write).not.toHaveBeenCalled()
})

it('preserves input and visible failure near the buttons until a new operation', async () => {
  const client = new ControlV3(), write = vi.spyOn(client, 'changePassword').mockRejectedValue(new Error('当前密码不正确，请重试'))
  await mountDialog(client); enter(); button('修改密码并退出').click(); await settle()
  expect(write).toHaveBeenCalledWith({ current_password: 'old-test-password', new_password: 'new-test-password', confirm_password: 'new-test-password' })
  expect(field('新密码').value).toBe('new-test-password')
  expect(document.querySelector('.v3-password-dialog .el-dialog__footer [role="status"]')?.textContent).toContain('当前密码不正确')
  button('取消').click(); await settle()
})

it('submits once and allows a viewer to change their own password', async () => {
  const client = new ControlV3(); let finish!: (v: {ok: boolean; reauthenticate: boolean}) => void
  const write = vi.spyOn(client, 'changePassword').mockImplementation(() => new Promise(resolve => { finish = resolve }))
  const { changed, opened } = await mountDialog(client, 'viewer'); enter()
  button('修改密码并退出').click(); button('修改密码并退出').click(); await settle()
  expect(write).toHaveBeenCalledTimes(1); expect(changed).not.toHaveBeenCalled()
  expect(document.querySelector('.v3-password-dialog .el-dialog__footer')?.textContent).toContain('正在校验并修改密码')
  finish({ ok: true, reauthenticate: true }); await settle()
  expect(changed).toHaveBeenCalledTimes(1); expect(opened.value).toBe(false)
})

it('clears secrets on reopen and ignores a response from an earlier opening', async () => {
  const client = new ControlV3(); let finish!: (v: {ok: boolean; reauthenticate: boolean}) => void
  vi.spyOn(client, 'changePassword').mockImplementation(() => new Promise(resolve => { finish = resolve }))
  const { changed, opened } = await mountDialog(client); enter(); button('修改密码并退出').click(); await settle()
  opened.value = false; await settle(); opened.value = true; await settle()
  expect(field('当前密码').value).toBe(''); expect(field('新密码').value).toBe(''); expect(field('确认新密码').value).toBe('')
  finish({ ok: true, reauthenticate: true }); await settle()
  expect(changed).not.toHaveBeenCalled(); expect(opened.value).toBe(true)
})

it('returns to login after the topbar password action without an extra logout request', async () => {
  vi.spyOn(ControlV3.prototype, 'session').mockResolvedValue({ username: 'readonly', role: 'viewer', csrf: 'fixture-csrf' })
  const write = vi.spyOn(ControlV3.prototype, 'changePassword').mockResolvedValue({ ok: true, reauthenticate: true })
  const logout = vi.spyOn(ControlV3.prototype, 'logout')
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/', component: { render: () => h('p', 'home') } }, { path: '/login', component: { render: () => null } }, { path: '/:pathMatch(.*)*', component: { render: () => null } }] })
  await router.push('/'); await router.isReady()
  host = document.createElement('div'); document.body.append(host); app = createApp(ConsoleApp); app.use(router); installElements(app); app.mount(host); await settle()
  expect((button('修改密码') as HTMLButtonElement).disabled).toBe(false)
  button('修改密码').click(); await settle(); enter(); button('修改密码并退出').click(); await settle()
  expect(write).toHaveBeenCalledTimes(1); expect(logout).not.toHaveBeenCalled(); expect(router.currentRoute.value.path).toBe('/login')
  expect(host.textContent).toContain('密码已修改，请使用新密码重新登录'); expect(host.querySelector('.v3-topbar')).toBe(null)
})
