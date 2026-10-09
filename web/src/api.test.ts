// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, APIError, beijingTime, setCSRF, siteInput, stateLabel, type Site } from './api'
afterEach(() => vi.restoreAllMocks())
describe('管理接口', () => {
 it('同源会话与 CSRF 随写入请求发送', async () => { const fetcher = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ id: 1 }) }); vi.stubGlobal('fetch', fetcher); setCSRF('csrf-fixture'); expect(await api('/api/websites', 'POST', { name: '官网' })).toEqual({ id: 1 }); expect(fetcher.mock.calls[0][1]).toMatchObject({ credentials: 'same-origin', headers: { 'X-CSRF-Token': 'csrf-fixture' } }) })
 it('显示后端中文参数提示', async () => { vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 400, json: async () => ({ message: '请填写完整的首页地址', field: 'url' }) })); await expect(api('/api/websites')).rejects.toMatchObject({ message: '请填写完整的首页地址', field: 'url' }) })
 it('会话失效通知页面重新登录', async () => { const listener = vi.fn(); window.addEventListener('session-expired', listener); vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 401, json: async () => ({}) })); await expect(api('/api/session')).rejects.toBeInstanceOf(APIError); expect(listener).toHaveBeenCalledOnce(); window.removeEventListener('session-expired', listener) })
 it('断网提示明确', async () => { vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline'))); await expect(api('/api/session')).rejects.toThrow('无法连接管理后台') })
})
describe('显示和编辑数据', () => {
 it('时间始终显示北京时间', () => { expect(beijingTime(Date.UTC(2026, 9, 9, 0, 0, 0) / 1000)).toContain('08:00:00'); expect(beijingTime(0)).toBe('尚未检查') })
 it('暂停优先于故障，编辑提交不包含服务端状态', () => { const site = { id: 1, name: '官网', url: 'https://example.com/', node: '', keyword: '', slow_alert: false, paused: true, state: { status: 'down' } } as Site; expect(stateLabel(site)).toBe('已暂停'); expect(siteInput(site)).not.toHaveProperty('state'); expect(siteInput(site)).not.toHaveProperty('id') })
})
