// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { installElements } from '../elements'
import { ControlV3 } from '../controlV3'
import { consoleContext } from './context'
import LegacyMetricHistory from './LegacyMetricHistory.vue'
vi.mock('../MetricChart.vue', () => ({ default: { props: ['title', 'option'], template: '<pre class="legacy-chart-fixture">{{JSON.stringify(option)}}</pre>' } }))
const first = 'a'.repeat(64), second = 'b'.repeat(64), stamp = Date.parse('2026-11-01T00:00:00Z') / 1000
const generation = () => [{ generation: first, revision: first, state: 'verified' }, { generation: second, revision: second, state: 'preparing' }]
const catalog = () => ({ nodes: [{ id: 'old-node', first_sample: stamp, last_sample: stamp + 1200 }], series: [{ metric: 'cpu_percent', dimension: '' }, { metric: 'disk_percent', dimension: '/data' }], node: 'old-node', read_only: true as const })
const history = () => ({ source: 'legacy-v2' as const, points: [{ time: stamp, resolution_seconds: 300, origin: 'native', ok: true, value: 4, min: 2, max: 6, count: 8 }, { time: stamp + 300, resolution_seconds: 300, origin: 'native', ok: false }, { time: stamp + 600, resolution_seconds: 300, origin: 'native', ok: true }, { time: stamp + 1200, resolution_seconds: 300, origin: 'native', ok: true, value: 9 }], read_only: true as const, interpolated: false as const })
function fixture() { return Object.assign(new ControlV3(), { migrationMetricCatalog: vi.fn(async (_session: string, _generation: string, _node = '', _q = '', _signal?: AbortSignal) => catalog()), migrationMetricHistory: vi.fn(async (_session: string, _generation: string, _node: string, _metric: string, _dimension: string, _start: string, _end: string, _signal?: AbortSignal) => history()) }) }
let app: App | undefined, host: HTMLDivElement
async function settle() { for (let i = 0; i < 30; i++) { await Promise.resolve(); await nextTick() } }
async function mount(client: ReturnType<typeof fixture>, role: 'admin' | 'viewer' | 'operator' = 'admin') {
 const session = ref(first), generations = ref(generation())
 host = document.createElement('div'); document.body.append(host)
 app = createApp({ components: { LegacyMetricHistory }, setup: () => ({ session, generations }), template: '<LegacyMetricHistory ref="history" :session="session" :generations="generations" />' })
 installElements(app); app.provide(consoleContext, { client, session: ref({ username: role, role, csrf: 'csrf' }) })
 const root = app.mount(host) as unknown as { $refs: { history: { loadCatalog(node?: string): Promise<void>; query(): Promise<void>; setSelection(value: { generation?: string; node?: string; filter?: string; series?: string; start?: string; end?: string }): void } } }
 await settle(); return { view: root.$refs.history, session, generations }
}
beforeEach(() => Object.defineProperty(document, 'hidden', { configurable: true, value: false }))
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); document.querySelectorAll('.el-popper').forEach(value => value.remove()); vi.restoreAllMocks() })
it('requires explicit catalog and history queries and uses only a verified batch', async () => {
 const client = fixture(), { view } = await mount(client)
 expect(client.migrationMetricCatalog).not.toHaveBeenCalled(); expect(client.migrationMetricHistory).not.toHaveBeenCalled()
 view.setSelection({ generation: second }); await settle(); await view.loadCatalog(); expect(client.migrationMetricCatalog).not.toHaveBeenCalled()
 view.setSelection({ generation: first }); await settle(); await view.loadCatalog(); await settle()
 expect(client.migrationMetricCatalog.mock.calls[0]?.slice(0, 4)).toEqual([first, first, '', '']); expect(client.migrationMetricHistory).not.toHaveBeenCalled()
 await view.query(); await settle(); expect(client.migrationMetricHistory.mock.calls[0]?.slice(0, 5)).toEqual([first, first, 'old-node', 'cpu_percent', ''])
 expect(host.textContent).toContain('不与当前采集合并'); expect(host.querySelector('.legacy-chart-fixture')).toBeTruthy()
})
it('preserves missing and failed samples, exact min/max and distinct five-minute resolution', async () => {
 const client = fixture(), { view } = await mount(client); await view.loadCatalog(); await settle(); await view.query(); await settle()
 const chart = JSON.parse(host.querySelector('.legacy-chart-fixture')!.textContent!)
 expect(chart.series[0].name).toContain('5分钟汇总'); expect(chart.series[0].connectNulls).toBe(false)
 expect(chart.series[0].data.map((point: unknown[]) => point[1])).toEqual([4, null, null, null, 9])
 expect(chart.series[1].data[0][1]).toBe(2); expect(chart.series[2].data[0][1]).toBe(6)
})
it('rejects arbitrary nodes, metric expressions and invalid or excessive date ranges before requests', async () => {
 const client = fixture(), { view } = await mount(client); await view.loadCatalog(); await settle()
 view.setSelection({ node: 'not-in-catalog' }); await settle(); await view.query(); expect(client.migrationMetricHistory).not.toHaveBeenCalled()
 view.setSelection({ node: 'old-node', series: 'sum(secret)' }); await settle(); await view.query(); expect(client.migrationMetricHistory).not.toHaveBeenCalled()
 view.setSelection({ series: JSON.stringify(['cpu_percent', '']), start: '2026-01-01T00:00:00', end: '2026-11-01T00:00:00' }); await settle(); await view.query(); expect(host.textContent).toContain('最多31天'); expect(client.migrationMetricHistory).not.toHaveBeenCalled()
})
it('retains existing results when verification expires with 409 or the network fails', async () => {
 const client = fixture(), { view } = await mount(client); await view.loadCatalog(); await settle(); await view.query(); await settle()
 client.migrationMetricHistory.mockRejectedValueOnce(new Error('409 批次尚未核对')); await view.query(); await settle()
 expect(host.textContent).toContain('409 批次尚未核对'); expect(host.querySelector('.legacy-chart-fixture')).toBeTruthy()
 client.migrationMetricHistory.mockRejectedValueOnce(new Error('503 网络暂时不可用')); await view.query(); await settle()
 expect(host.textContent).toContain('503 网络暂时不可用'); expect(host.querySelector('.legacy-chart-fixture')).toBeTruthy()
})
it('cancels pending responses when the migration session or batch changes', async () => {
 const client = fixture(), { view, session } = await mount(client); await view.loadCatalog(); await settle()
 let complete: (value: ReturnType<typeof history>) => void = () => {}; client.migrationMetricHistory.mockImplementationOnce(() => new Promise(resolve => { complete = resolve }))
 void view.query(); await settle(); session.value = second; await settle(); expect(client.migrationMetricHistory.mock.calls[0]?.[7]?.aborted).toBe(true)
 complete(history()); await settle(); expect(host.querySelector('.legacy-chart-fixture')).toBeNull()
 await view.loadCatalog(); await settle(); expect(client.migrationMetricCatalog.mock.calls.at(-1)?.[0]).toBe(second)
 view.setSelection({ generation: '' }); await settle(); expect(host.querySelector('form')).toBeNull()
})
it.each(['viewer', 'operator'] as const)('does not request old metrics for %s', async role => {
 const client = fixture(), { view } = await mount(client, role); await view.loadCatalog(); await view.query(); await settle()
 expect(client.migrationMetricCatalog).not.toHaveBeenCalled(); expect(client.migrationMetricHistory).not.toHaveBeenCalled(); expect(host.textContent).toBe('')
})
it('pauses queries in a hidden tab and rejects oversized or interpolated responses', async () => {
 const client = fixture(), { view } = await mount(client); await view.loadCatalog(); await settle()
 Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange')); await view.query(); expect(client.migrationMetricHistory).not.toHaveBeenCalled()
 Object.defineProperty(document, 'hidden', { configurable: true, value: false })
 client.migrationMetricHistory.mockResolvedValueOnce({ ...history(), points: Array.from({ length: 1001 }, () => history().points[0]!) }); await view.query(); await settle(); expect(host.textContent).toContain('超过1000点'); expect(host.querySelector('.legacy-chart-fixture')).toBeNull()
})

it('accepts second precision returned by the history catalog in native date inputs', async () => {
 const client = fixture(), { view } = await mount(client); await view.loadCatalog(); await settle()
 const dates = Array.from(host.querySelectorAll<HTMLInputElement>('input[type="datetime-local"]'))
 expect(dates).toHaveLength(2); expect(dates.every(input => input.step === '1' && input.validity.valid)).toBe(true)
 expect(dates[1]!.value).toMatch(/:01(?:\.000)?$/)
})
