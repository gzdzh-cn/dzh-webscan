<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import type { EChartsOption } from 'echarts'
import MetricChart from '../MetricChart.vue'
import { metricLabel } from '../charts'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
type Generation = { generation: string; revision: string; state: string }
type Catalog = { nodes: { id: string; first_sample: number; last_sample: number }[]; series: { metric: string; dimension: string }[]; node: string; read_only: true }
type History = { source: 'legacy-v2'; points: { time: number; resolution_seconds: number; origin: string; ok: boolean; value?: number; min?: number; max?: number; count?: number }[]; read_only: true; interpolated: false }
const props = defineProps<{ session: string; generations: Generation[] }>()
const { client, session: account } = useConsole(), catalogRead = useReadScope(), historyRead = useReadScope()
const allowed = computed(() => account.value?.role === 'admin'), generations = computed(() => props.generations.filter(item => item.state === 'verified'))
const generation = ref(''), node = ref(''), filter = ref(''), selectedSeries = ref(''), start = ref(''), end = ref(''), catalog = ref<Catalog>(), result = ref<History>(), error = ref(''), applied = ref('')
const seriesID = (item: { metric: string; dimension: string }) => JSON.stringify([item.metric, item.dimension])
const series = computed(() => catalog.value?.series.find(item => seriesID(item) === selectedSeries.value))
const currentNode = computed(() => catalog.value?.nodes.find(item => item.id === node.value))
const signature = computed(() => JSON.stringify([props.session, generation.value, node.value, selectedSeries.value, start.value, end.value]))
const stale = computed(() => !!result.value && applied.value !== signature.value)
const localInput = (seconds: number) => { const d = new Date(seconds * 1000); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 19) }
const finite = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value)
const chart = computed<EChartsOption>(() => {
 const groups = new Map<string, History['points']>()
 for (const point of result.value?.points || []) { const key = JSON.stringify([point.origin, point.resolution_seconds]); const list = groups.get(key) || []; list.push(point); groups.set(key, list) }
 const lines = [...groups.values()].flatMap(points => {
  points = [...points].sort((a, b) => a.time - b.time)
  const first = points[0]!, prefix = `${first.origin === 'native' ? '原生历史' : '旧指标历史'} · ${first.resolution_seconds === 300 ? '5分钟汇总' : first.resolution_seconds === 0 ? '原始样本' : `${first.resolution_seconds}秒样本`}`
  return (['value', 'min', 'max'] as const).filter(field => field === 'value' || points.some(point => finite(point[field]))).map(field => {
   const data: [number, number | null][] = []
   points.forEach((point, index) => { const previous = points[index - 1]; if (previous && first.resolution_seconds > 0 && point.time - previous.time > first.resolution_seconds) data.push([(previous.time + first.resolution_seconds) * 1000, null]); data.push([point.time * 1000, point.ok && finite(point[field]) ? point[field]! : null]) })
   return { name: `${prefix} · ${{ value: '值', min: '最小值', max: '最大值' }[field]}`, type: 'line' as const, showSymbol: true, symbolSize: 4, connectNulls: false, smooth: false, lineStyle: { type: field === 'value' ? 'solid' as const : 'dashed' as const }, data }
  })
 })
 return { tooltip: { trigger: 'axis' }, legend: { type: 'scroll', bottom: 0 }, grid: { left: 65, right: 20, top: 20, bottom: 70 }, xAxis: { type: 'time', axisLabel: { formatter: value => new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', hour: '2-digit', minute: '2-digit' }).format(value) } }, yAxis: { type: 'value' }, series: lines }
})
let disposed = false
function clearHistory() { historyRead.cancel(); error.value = '' }
function reset() { catalogRead.cancel(); historyRead.cancel(); catalog.value = undefined; result.value = undefined; node.value = ''; selectedSeries.value = ''; start.value = ''; end.value = ''; error.value = ''; applied.value = '' }
async function loadCatalog(selectedNode = '') {
 if (!allowed.value || disposed || document.hidden || catalogRead.loading.value || !generations.value.some(item => item.generation === generation.value)) return
 historyRead.cancel(); error.value = ''
 await catalogRead.run(signal => client.migrationMetricCatalog(props.session, generation.value, selectedNode, filter.value, signal), value => {
  if (value.read_only !== true || value.nodes.length > 100 || value.series.length > 4096 || value.node && !value.nodes.some(item => item.id === value.node)) throw Error('旧指标清单响应不正确')
  catalog.value = value; node.value = value.node; selectedSeries.value = value.series[0] ? seriesID(value.series[0]) : ''
  const target = value.nodes.find(item => item.id === value.node)
  if (target && finite(target.first_sample) && finite(target.last_sample) && target.first_sample <= target.last_sample) { start.value = localInput(Math.max(target.first_sample, target.last_sample - 86400)); end.value = localInput(target.last_sample + 1) }
 })
}
async function query() {
 if (!allowed.value || disposed || document.hidden || historyRead.loading.value || catalogRead.loading.value) return
 const selected = series.value, from = Date.parse(start.value), until = Date.parse(end.value)
 if (!generations.value.some(item => item.generation === generation.value) || !currentNode.value || !selected) { error.value = '请先读取已核对批次的节点与指标清单'; return }
 if (!Number.isFinite(from) || !Number.isFinite(until) || until <= from || until - from > 31 * 86400_000) { error.value = '请选择有效时间范围，最多31天'; return }
 error.value = ''; const key = signature.value
 await historyRead.run(async signal => { const value = await client.migrationMetricHistory(props.session, generation.value, node.value, selected.metric, selected.dimension, new Date(from).toISOString(), new Date(until).toISOString(), signal); if (value.read_only !== true || value.source !== 'legacy-v2' || value.interpolated !== false || value.points.length > 1000 || value.points.some(point => !finite(point.time) || !Number.isSafeInteger(point.resolution_seconds) || point.resolution_seconds < 0 || !['native', 'legacy'].includes(point.origin) || typeof point.ok !== 'boolean')) throw Error('旧指标历史响应不正确或超过1000点'); return value }, value => { result.value = value; applied.value = key })
}
function setSelection(value: { generation?: string; node?: string; filter?: string; series?: string; start?: string; end?: string }) { if (value.generation !== undefined) generation.value = value.generation; if (value.node !== undefined) node.value = value.node; if (value.filter !== undefined) filter.value = value.filter; if (value.series !== undefined) selectedSeries.value = value.series; if (value.start !== undefined) start.value = value.start; if (value.end !== undefined) end.value = value.end }
function visibility() { if (document.hidden) { catalogRead.cancel(); historyRead.cancel() } }
watch(() => [props.session, props.generations], () => { reset(); generation.value = generations.value[0]?.generation || '' }, { immediate: true })
watch(generation, reset)
watch([node, selectedSeries, start, end], clearHistory)
watch(allowed, value => { if (!value) reset() })
onMounted(() => document.addEventListener('visibilitychange', visibility))
onUnmounted(() => { disposed = true; document.removeEventListener('visibilitychange', visibility) })
defineExpose({ loadCatalog, query, setSelection })
</script>
<template>
 <el-card v-if="allowed" shadow="never" class="legacy-metric-history"><div class="card-heading"><h3>旧版指标历史</h3><span class="muted">只读核对，按迁移批次查询</span></div>
  <p class="muted">仅显示已核对批次的原始样本与5分钟汇总；不与当前采集合并，不插值、不补零。先读取清单，再点击查询。</p>
  <el-empty v-if="!generations.length" description="尚无已核对的旧指标批次" />
  <template v-else>
   <div class="filters legacy-metric-filters"><el-select v-model="generation" aria-label="旧指标批次"><el-option v-for="item in generations" :key="item.generation" :value="item.generation" :label="`${item.generation.slice(0,12)}…（已核对）`" /></el-select><el-input v-model="filter" aria-label="旧节点筛选" placeholder="按旧节点 ID 筛选" :maxlength="128" /><el-button :loading="catalogRead.loading.value" @click="loadCatalog()">读取旧指标清单</el-button></div>
   <el-alert v-if="catalogRead.error.value" :title="`${catalogRead.error.value}；保留已有结果。`" type="error" :closable="false" />
   <form v-if="catalog" class="filters legacy-metric-filters" @submit.prevent="query"><el-select :model-value="node" aria-label="旧指标节点" :disabled="catalogRead.loading.value" @update:model-value="loadCatalog($event)"><el-option v-for="item in catalog.nodes" :key="item.id" :value="item.id" :label="item.id" /></el-select><el-select v-model="selectedSeries" aria-label="旧指标类型"><el-option v-for="item in catalog.series" :key="seriesID(item)" :value="seriesID(item)" :label="`${metricLabel(item.metric)}${item.dimension ? ` · ${item.dimension}` : ''}`" /></el-select><label>开始时间（本地）<el-input v-model="start" type="datetime-local" step="1" aria-label="旧指标开始时间" /></label><label>结束时间（本地）<el-input v-model="end" type="datetime-local" step="1" aria-label="旧指标结束时间" /></label><el-button type="primary" native-type="submit" :loading="historyRead.loading.value" :disabled="!currentNode || !series || catalogRead.loading.value">查询旧指标历史</el-button></form>
   <p v-if="currentNode" class="muted">原始记录范围：{{ timeText(currentNode.first_sample * 1000) }} ～ {{ timeText(currentNode.last_sample * 1000) }}。清单最多100个节点；未列出不代表不存在，可按 ID 筛选。</p>
   <el-alert v-if="error || historyRead.error.value" :title="`${error || historyRead.error.value}；保留上一次结果，请核对批次后重试。`" type="error" :closable="false" />
   <el-alert v-if="stale" title="筛选已变化，下方保留上一次查询结果；再次点击查询后更新。" type="info" :closable="false" />
   <template v-if="result"><p class="muted">旧版历史 · 返回 {{ result.points.length }} 个原始记录点；不同来源与精度分别显示，缺失和异常样本留空。</p><MetricChart v-if="result.points.length" title="旧版历史曲线（北京时间）" :option="chart" /><el-empty v-else description="此范围没有旧指标样本" /></template>
  </template>
 </el-card>
</template>
<style scoped>
.legacy-metric-history { margin-top:16px; }.legacy-metric-filters { gap:12px;flex-wrap:wrap;margin-top:12px; }.legacy-metric-filters .el-select,.legacy-metric-filters>.el-input { min-width:180px;flex:1; }.legacy-metric-filters label { display:block;min-width:210px;flex:1;font-size:13px; }.card-heading { display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap; }p { overflow-wrap:anywhere; }
@media(max-width:600px){ .legacy-metric-filters { flex-direction:column;align-items:stretch; }.legacy-metric-filters .el-select,.legacy-metric-filters>.el-input,.legacy-metric-filters label { min-width:0;width:100%; } }
</style>
