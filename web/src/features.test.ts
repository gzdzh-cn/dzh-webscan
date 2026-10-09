// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick } from 'vue'
import { copyURL } from './clipboard'
import { certificateLabel } from './certificate'
import type { Site } from './api'
import UrlLink from './UrlLink.vue'
vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn() } }))
vi.mock('element-plus/es/components/message/style/css', () => ({}))
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); document.body.innerHTML = '' })
describe('HTTP / HTTPS 完整网址复制', () => {
 const url = 'https://example.com/目录/?key=a%20b&next=2'
 it('使用可用的 Clipboard API 保留路径和参数', async () => { const writeText = vi.fn().mockResolvedValue(undefined); Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } }); expect(await copyURL(url)).toBe(true); expect(writeText).toHaveBeenCalledWith(url) })
 it('HTTP 缺少 Clipboard API 时兼容复制并清理临时元素', async () => { Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined }); const command = vi.fn(() => { expect((document.activeElement as HTMLTextAreaElement).value).toBe(url); return true }); document.execCommand = command; expect(await copyURL(url)).toBe(true); expect(command).toHaveBeenCalledWith('copy'); expect(document.querySelector('textarea')).toBeNull() })
 it('权限拒绝时先尝试兼容复制，最终失败提供手动方案', async () => { Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn().mockRejectedValue(new Error('denied')) } }); document.execCommand = vi.fn().mockReturnValue(false); expect(await copyURL(url)).toBe(false) })
 it('链接新标签安全打开，复制按钮独立点击不触发导航', async () => {
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn().mockResolvedValue(undefined) } })
  const target = document.createElement('div'); document.body.appendChild(target)
  const app = createApp(UrlLink, { url }); app.component('el-dialog', { template: '<div><slot /></div>' }); app.component('el-button', { template: '<button><slot /></button>' }); app.mount(target)
  const link = target.querySelector('a')!, button = target.querySelector('button.copy-url')!
  expect(link.getAttribute('href')).toBe(url); expect(link.target).toBe('_blank'); expect(link.rel).toBe('noopener noreferrer')
  const parentClick = vi.fn(); target.addEventListener('click', parentClick)
  const event = new MouseEvent('click', { bubbles: true, cancelable: true }); button.dispatchEvent(event); await nextTick()
  expect(event.defaultPrevented).toBe(true); expect(parentClick).not.toHaveBeenCalled(); expect(button.getAttribute('aria-label')).toBe('复制完整网址')
  app.unmount()
 })
})
describe('证书剩余时间', () => {
 const site = (expiry: number, url = 'https://example.com/', error = '') => ({ url, state: { last: { time: 1000, cert_expires: expiry, cert_error: error, ok: true } } } as Site)
 it('展示向上取整，边界和过期清楚区分', () => { expect(certificateLabel(site(1001), 1000)).toBe('1 天'); expect(certificateLabel(site(1000 + 7 * 86400), 1000)).toBe('7 天'); expect(certificateLabel(site(999), 1000)).toBe('已过期') })
 it('未知、不适用以及失败后保留的证书可区分', () => { expect(certificateLabel(site(0), 1000)).toBe('未知'); expect(certificateLabel(site(0, 'http://example.com/'), 1000)).toBe('不适用'); expect(certificateLabel(site(999, undefined, '网络失败'), 1000)).toBe('已过期（检查失败）') })
})
