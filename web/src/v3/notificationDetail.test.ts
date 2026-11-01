// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { installElements } from '../elements'
import { ControlV3, type V3NotificationDetail } from '../controlV3'
import { consoleContext } from './context'
import NotificationDetail from './NotificationDetail.vue'
import Alerts from './Alerts.vue'
vi.mock('../MetricChart.vue', () => ({ default: { template: '<div />' } }))
let app: App | undefined, host: HTMLDivElement
async function settle() { for (let i = 0; i < 30; i++) { await Promise.resolve(); await nextTick() } }
const record = (id = 'n1'): V3NotificationDetail => ({ notification: { id, node: 'node-a', event_id: 'event-1', channel: 'email', recipient: 'recipient@example.test', created_at: new Date().toISOString(), done_at: null, attempts: 1, state: 'retrying', source: 'event', subject: '安全提醒', summary: '内容摘要', content_state: 'available', truncated: true, record_key: `email:${id}`, can_delete: false, delete_reason: '近期记录' }, body: '<img src=x onerror=alert(1)>\n纯文本正文', outcome: { code: 'unknown', message: '结果尚未确认' } })
function button(text: string) { return Array.from(document.body.querySelectorAll('button')).find(e => e.textContent?.trim() === text)! }
async function mount(client: ControlV3, id = ref('n1')) { host = document.createElement('div'); document.body.append(host); const closed = vi.fn(); app = createApp({ components: { NotificationDetail }, setup: () => ({ id, closed }), template: '<NotificationDetail :id="id" @close="closed" />' }); installElements(app); app.provide(consoleContext, { client, session: ref({ username: 'fixture', role: 'admin' as const, csrf: 'csrf' }) }); app.mount(host); await settle(); return { closed, id } }
beforeEach(() => Object.defineProperty(document, 'hidden', { configurable: true, value: false }))
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-overlay').forEach(e => e.remove()); vi.restoreAllMocks(); vi.useRealTimers() })
it('renders safe text and pages attempts with an independent cursor, retaining results after 503', async () => {
 const client = new ControlV3(); const details = vi.spyOn(client, 'notificationDetail').mockResolvedValue(record())
 const attempts = vi.spyOn(client, 'notificationAttempts').mockResolvedValueOnce({ items: [{ id: 'a1', epoch: '1', success: false, outcome: 'unknown', message: '等待核对', created_at: '' }], next_cursor: 'attempt-next' }).mockResolvedValueOnce({ items: [{ id: 'a2', epoch: '2', success: true, outcome: 'accepted', message: '通道接受', created_at: '' }], next_cursor: '' }).mockRejectedValue(new Error('503 暂时不可用'))
 await mount(client); expect(document.body.textContent).toContain('<img src=x onerror=alert(1)>'); expect(document.querySelector('img[src="x"]')).toBeNull(); expect(document.body.textContent).toContain('仅展示截取部分')
 button('下一页').click(); await settle(); expect(attempts.mock.calls[1]?.slice(0, 3)).toEqual(['n1', 'attempt-next', 20]); expect(details).toHaveBeenCalledTimes(1)
 button('刷新尝试记录').click(); await settle(); expect(document.body.textContent).toContain('503 暂时不可用'); expect(document.body.textContent).toContain('通道接受'); expect(document.body.textContent).toContain('SMTP 接受不代表进入收件箱')
})
it('ignores late detail and attempts after switching records and aborts on close', async () => {
 const client = new ControlV3(); let complete: (v: V3NotificationDetail) => void = () => {}
 const details = vi.spyOn(client, 'notificationDetail').mockImplementationOnce(() => new Promise(resolve => { complete = resolve })).mockResolvedValue(record('n2'))
 const attempts = vi.spyOn(client, 'notificationAttempts').mockResolvedValue({ items: [], next_cursor: '' })
 const { id, closed } = await mount(client); id.value = 'n2'; await settle(); expect(details.mock.calls[0]?.[1]?.aborted).toBe(true); complete(record('stale')); await settle(); expect(document.body.textContent).toContain('n2'); expect(document.body.textContent).not.toContain('stale'); expect(attempts.mock.calls[1]?.slice(0,3)).toEqual(['n2','',20])
 button('关闭').click(); await settle(); expect(closed).toHaveBeenCalled(); expect(details.mock.calls.at(-1)?.[1]?.aborted).toBe(true)
})
it('preserves automatic notification querying with separate exact, coarse, source and text filters', async () => {
 const client = new ControlV3(); vi.spyOn(client, 'servers').mockResolvedValue({ items: [], next_cursor: '', limit: 20 }); vi.spyOn(client, 'notificationStats').mockResolvedValue({ items: [] } as never)
 const notifications = vi.spyOn(client, 'notifications').mockResolvedValue({ items: [record().notification], next_cursor: 'list-next', start: '', end: '' })
 const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/alerts', component: Alerts }, { path: '/settings', component: { template: '<div />' } }] }); await router.push('/alerts?tab=email&state=pending&delivery_state=retrying&source=event&q=needle&recipient=one%40example.test'); await router.isReady()
 host = document.createElement('div'); document.body.append(host); app = createApp(Alerts); installElements(app); app.use(router); app.provide(consoleContext, { client, session: ref({ username: 'fixture', role: 'viewer' as const, csrf: 'csrf' }) }); app.mount(host); await settle()
 expect(notifications.mock.calls[0]?.[0]).toMatchObject({ channel:'email', state:'pending', delivery_state:'retrying', source:'event', q:'needle', recipient:'one@example.test' }); expect(host.textContent).toContain('安全提醒'); expect(host.textContent).not.toContain('已送达'); await router.push('/alerts?tab=feishu&recipient=one%40example.test'); await settle(); expect(notifications.mock.calls.at(-1)?.[0]).toMatchObject({ channel:'feishu',recipient:'' })
})
