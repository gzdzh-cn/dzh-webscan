// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { installElements } from '../elements'
import { ControlV3 } from '../controlV3'
import { consoleContext } from './context'
import LegacyMigrationHistory from './LegacyMigrationHistory.vue'

const first = 'a'.repeat(64), second = 'b'.repeat(64), cursor = 'c'.repeat(64)
type History = { id: string; role: string; legacy_table: string; record_key: number; summary: Record<string, unknown> }
const record = (id = first, summary: Record<string, unknown> = {}): History => ({ id, role: 'host-manager', legacy_table: 'logs', record_key: 12, summary: { created_at: '2026-11-01T01:00:00Z', message_available: true, original_encrypted: true, ...summary } })
const page = (items: History[] = [record()], next_cursor = '') => ({ items, next_cursor, read_only: true as const })
const sessions = () => ({ items: [{ id: first, phase: 'frozen', created_at: '2026-11-01T00:00:00Z', history_records: 31, generations: [] }, { id: second, phase: 'indexed', created_at: '2026-10-31T00:00:00Z', history_records: 2, generations: [] }] })
let app: App | undefined, host: HTMLDivElement
async function settle() { for (let i = 0; i < 30; i++) { await Promise.resolve(); await nextTick() } }
function fixture() { return Object.assign(new ControlV3(), { migrationHistorySessions: vi.fn(async (_signal?: AbortSignal) => sessions()), legacyHistory: vi.fn(async (_session: string, _role: string, _table: string, _cursor: string, _limit: number, _signal?: AbortSignal) => page()) }) }
async function mount(client: ReturnType<typeof fixture>, role: 'admin' | 'operator' | 'viewer' = 'admin') {
 host = document.createElement('div'); document.body.append(host)
 app = createApp({ components: { LegacyMigrationHistory }, template: '<LegacyMigrationHistory ref="history" />' })
 installElements(app); app.component('router-link', { template: '<a><slot /></a>' }); app.provide(consoleContext, { client, session: ref({ username: role, role, csrf: 'csrf' }) })
 const root = app.mount(host) as unknown as { $refs: { history: { setFilters(values: { session?: string; role?: string; table?: string }): void; search(): Promise<void>; nextPage(): void; previousPage(): void; resize(limit: number): void } } }
 await settle(); return root.$refs.history
}
function button(label: string) { return Array.from(host.querySelectorAll('button')).find(value => value.textContent?.trim() === label)! }
beforeEach(() => Object.defineProperty(document, 'hidden', { configurable: true, value: false }))
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-popper').forEach(value => value.remove()); vi.restoreAllMocks(); vi.useRealTimers() })

it('loads available migration sessions but requires a manual history query for an administrator', async () => {
 const client = fixture(), view = await mount(client)
 expect(client.migrationHistorySessions).toHaveBeenCalledTimes(1); expect(client.legacyHistory).not.toHaveBeenCalled()
 expect(host.textContent).toContain('尚未查询历史'); expect(host.textContent).toContain('此处仅查看历史')
 view.setFilters({ role: 'host-manager', table: 'logs' }); await settle(); await view.search(); await settle()
 expect(client.legacyHistory.mock.calls[0]?.slice(0, 5)).toEqual([first, 'host-manager', 'logs', '', 20])
 expect(host.textContent).toContain('原日志已加密保留'); expect(host.textContent).toContain('已归档历史 31 条')
 for (const label of ['继续', '回退', '删除', '部署']) expect(Array.from(host.querySelectorAll('button')).some(value => value.textContent?.trim() === label)).toBe(false)
})
it('uses real cursors for previous and next pages and resets to the first page when resizing', async () => {
 const client = fixture(); client.legacyHistory.mockResolvedValueOnce(page([record(first)], cursor)).mockResolvedValueOnce(page([record(second)])).mockResolvedValueOnce(page([record(first)], cursor)).mockResolvedValue(page())
 const view = await mount(client); await view.search(); await settle(); expect(button('上一页').disabled).toBe(true)
 view.nextPage(); await settle(); expect(client.legacyHistory.mock.calls[1]?.[3]).toBe(cursor); expect(host.textContent).toContain('第 2 页')
 view.previousPage(); await settle(); expect(client.legacyHistory.mock.calls[2]?.[3]).toBe(''); expect(host.textContent).toContain('第 1 页')
 view.resize(50); await settle(); expect(client.legacyHistory.mock.calls[3]?.slice(3, 5)).toEqual(['', 50])
 expect(host.textContent).not.toContain('共 31 页')
})
it('cancels a pending query and ignores its late response after changing the migration session', async () => {
 const client = fixture(); let complete: (value: ReturnType<typeof page>) => void = () => {}
 client.legacyHistory.mockImplementationOnce(() => new Promise(resolve => { complete = resolve }))
 const view = await mount(client); void view.search(); await settle()
 view.setFilters({ session: second }); await settle(); expect(client.legacyHistory.mock.calls[0]?.[5]?.aborted).toBe(true)
 complete(page([record(first, { kind: 'configuration-backup', artifact_available: true })])); await settle()
 expect(host.textContent).not.toContain('备份文件已保留'); expect(host.textContent).toContain('尚未查询历史')
 await view.search(); await settle(); expect(client.legacyHistory.mock.calls[1]?.[0]).toBe(second)
})
it('preserves prior results after a network failure, retries without overlap and pauses in a hidden tab', async () => {
 vi.useFakeTimers(); const client = fixture(); client.legacyHistory.mockResolvedValueOnce(page()).mockRejectedValueOnce(new Error('503 暂时不可用')).mockResolvedValue(page([record(second)]))
 const view = await mount(client); await view.search(); await settle(); await view.search(); await settle()
 expect(host.textContent).toContain('503 暂时不可用'); expect(host.textContent).toContain('原日志已加密保留')
 Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange')); await vi.advanceTimersByTimeAsync(6000); await settle()
 expect(client.legacyHistory).toHaveBeenCalledTimes(2)
 Object.defineProperty(document, 'hidden', { configurable: true, value: false }); document.dispatchEvent(new Event('visibilitychange')); await settle()
 expect(client.legacyHistory).toHaveBeenCalledTimes(3); expect(host.textContent).not.toContain('503 暂时不可用')
})
it('does not expose raw source text, paths, unknown fields or HTML from a history response', async () => {
 const client = fixture(); client.legacyHistory.mockResolvedValue(page([record(first, { raw_source: 'PRIVATE-source', message: '<img src=x onerror=PRIVATE>', path: '/PRIVATE/config.yaml', password: 'PRIVATE-password', unknown: { credential: 'PRIVATE-secret' }, kind: 'PRIVATE-kind', status: 'PRIVATE-status', created_at: 'PRIVATE-time', parent: 'PRIVATE-parent' })]))
 const view = await mount(client); await view.search(); await settle()
 expect(host.textContent).not.toContain('PRIVATE'); expect(host.querySelector('img')).toBeNull(); expect(host.textContent).toContain('未知')
})
it('does not query an empty session list or fabricate a zero for an unsafe original record number', async () => {
 const client = fixture(); client.migrationHistorySessions.mockResolvedValueOnce({ items: [] })
 const view = await mount(client); await view.search(); await settle(); expect(client.legacyHistory).not.toHaveBeenCalled(); expect(button('查询历史').disabled).toBe(true)
 client.migrationHistorySessions.mockResolvedValue(sessions()); button('刷新迁移会话').click(); await settle()
 const row = record(); row.record_key = Number.MAX_SAFE_INTEGER + 1; client.legacyHistory.mockResolvedValue(page([row])); await view.search(); await settle()
 expect(host.textContent).not.toContain('9007199254740992'); expect(host.textContent).toContain('未知')
})
it('resets an incompatible table filter on source changes and never queries merely from changing filters', async () => {
 const client = fixture(), view = await mount(client)
 view.setFilters({ role: 'host-manager', table: 'logs' }); await settle(); view.setFilters({ role: 'central' }); await settle()
 expect(client.legacyHistory).not.toHaveBeenCalled(); await view.search(); await settle()
 expect(client.legacyHistory.mock.calls[0]?.slice(0, 3)).toEqual([first, 'central', ''])
})

it.each(['viewer', 'operator'] as const)('does not request protected migration history for %s', async role => {
 const client = fixture(), view = await mount(client, role); await view.search(); await settle()
 expect(client.migrationHistorySessions).not.toHaveBeenCalled(); expect(client.legacyHistory).not.toHaveBeenCalled()
 expect(host.textContent).toContain('仅管理员'); expect(host.querySelector('form')).toBeNull()
})
