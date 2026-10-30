// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { installElements } from '../elements'
import { ControlV3, type V3ConfigurationDeleteJob } from '../controlV3'
import { consoleContext } from './context'
import { cancelReadRequests } from '../connection'
import Task from './ConfigurationDeleteTask.vue'
let app: App | undefined, host: HTMLDivElement
async function settle() { for (let i = 0; i < 25; i++) { await Promise.resolve(); await nextTick() } }
const job = (status: V3ConfigurationDeleteJob['status'] = 'running'): V3ConfigurationDeleteJob => ({ id: 'a'.repeat(64), username: 'user', settings_version: 5, selected: 2, status, deleted: 1, skipped: status === 'partial' ? 1 : 0, failed: 0, message: '已完成部分已保存', created_at: '', updated_at: '', finished_at: null })
async function mount(client: ControlV3, finished = vi.fn()) { host = document.createElement('div'); document.body.append(host); app = createApp(Task, { id: job().id, onFinished: finished }); installElements(app); app.provide(consoleContext, { client, session: ref({ username: 'user', role: 'admin' as const, csrf: 'csrf' }) }); app.mount(host); await settle() }
beforeEach(() => { vi.useFakeTimers(); Object.defineProperty(document, 'hidden', { configurable: true, value: false }) })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); cancelReadRequests(true); vi.useRealTimers(); vi.restoreAllMocks() })
it('polls without overlap, pauses in background, and reports partial results with retained counts', async () => {
  const client = new ControlV3(), finished = vi.fn(); let resolve!: (v: { job: V3ConfigurationDeleteJob; items: [] }) => void
  const read = vi.spyOn(client, 'configurationDeleteJob').mockImplementationOnce(() => new Promise(yes => { resolve = yes })).mockResolvedValue({ job: job('partial'), items: [] })
  await mount(client, finished); await vi.advanceTimersByTimeAsync(30_000); expect(read).toHaveBeenCalledTimes(1)
  resolve({ job: job(), items: [] }); await settle(); expect(host.textContent).toContain('已删除 1'); await vi.advanceTimersByTimeAsync(2999); expect(read).toHaveBeenCalledTimes(1)
  Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange')); await vi.advanceTimersByTimeAsync(30_000); expect(read).toHaveBeenCalledTimes(1)
  Object.defineProperty(document, 'hidden', { configurable: true, value: false }); document.dispatchEvent(new Event('visibilitychange')); await settle(); expect(read).toHaveBeenCalledTimes(2); expect(host.textContent).toContain('部分完成'); expect(host.textContent).toContain('跳过 1'); expect(finished).toHaveBeenCalledTimes(1)
  await vi.advanceTimersByTimeAsync(30_000); expect(read).toHaveBeenCalledTimes(2)
})
it('retains progress on failure, retries, and stops updates when closed', async () => {
  const client = new ControlV3(), read = vi.spyOn(client, 'configurationDeleteJob').mockResolvedValueOnce({ job: job(), items: [] }).mockRejectedValueOnce(new Error('读取失败')).mockResolvedValue({ job: job(), items: [] })
  await mount(client); await vi.advanceTimersByTimeAsync(3000); await settle(); expect(host.textContent).toContain('已读取的进度保留'); expect(host.textContent).toContain('已删除 1'); await vi.advanceTimersByTimeAsync(3000); await settle(); expect(read).toHaveBeenCalledTimes(3)
  app!.unmount(); app = undefined; await vi.advanceTimersByTimeAsync(30_000); expect(read).toHaveBeenCalledTimes(3)
})
