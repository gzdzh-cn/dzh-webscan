import { describe, expect, it } from 'vitest'
import { resourceCharts, healthCharts, trendOption, rankingOption } from './charts'
import { changedPatch, fields } from './settings'
describe('资源曲线和配置', () => {
 it('17 个固定图表位置，失联数据保持未知并保留峰值', () => {
  expect(resourceCharts.length + healthCharts.length + 3 + 2).toBe(17)
  const option = trendOption([{ time: 10, ok: false, values: { cpu_percent: 0 } }, { time: 20, ok: true, values: { cpu_percent: 30 }, max: { cpu_percent: 99 } }], resourceCharts[0]!)
  const series = option.series as { name: string; data: unknown[] }[]
  expect(series[0]!.data[0]).toEqual([10000, null]); expect(series.find(s => s.name.includes('峰值'))?.data[1]).toEqual([20000,99])
  const ranks = rankingOption([{ name:'失联', status:'unreachable', snapshot:{ ok:false, values:{ cpu_percent:0 } } }], 'cpu_percent')
  expect((ranks.yAxis as { data: string[] }).data).toEqual([])
 })
 it('后台表单不会发送空白凭据，数字与数组保持类型', () => {
  const values = { feishu:{ signing_secret:'' }, central:{ website_monitor:{ interval_seconds:60 } }, node_defaults:{ monitor:{ roots:['/www/wwwroot'] } } }
  const form = Object.fromEntries(fields.map(f => [f.path, f.type === 'secret' ? '' : f.type === 'number' ? '60' : f.type === 'lines' ? '/www/wwwroot' : false]))
  const patch = changedPatch(values,form)
  expect(patch['feishu.signing_secret']).toBeUndefined(); expect(patch['central.website_monitor.interval_seconds']).toBeUndefined();expect(patch['node_defaults.monitor.roots']).toBeUndefined()
 })
})
