<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import type { EChartsOption } from 'echarts'
import type { V3Dashboard } from '../controlV3'
import MetricChart from '../MetricChart.vue'
import { useConsole, timeText } from './context'
import { useReadScope } from './readScope'
import { dashboardCards } from './dashboardCards'

const { client } = useConsole(), read = useReadScope(), value = ref<V3Dashboard | null>(null)
const sections = computed(() => value.value?.summary.sections)
const components = computed(() => dashboardCards(value.value, Boolean(read.error.value)))
let timer: ReturnType<typeof setTimeout> | undefined, disposed = false, generation = 0
function stop() { if (timer) clearTimeout(timer); timer = undefined }
async function refresh() {
  if (disposed || document.hidden || read.loading.value) return
  stop(); const current = ++generation
  await read.run(signal => client.dashboard(signal), data => { value.value = data })
  if (!disposed && current === generation && !document.hidden) timer = setTimeout(() => { void refresh() }, 30_000)
}
function visibility() { stop(); if (document.hidden) { generation++; read.cancel() } else void refresh() }
onMounted(() => { document.addEventListener('visibilitychange', visibility); void refresh() })
onUnmounted(() => { disposed = true; generation++; stop(); document.removeEventListener('visibilitychange', visibility) })
const number = (v?: number | null) => v === undefined || v === null ? '—' : String(v)
const percent = (v?: number | null) => v === undefined || v === null || !Number.isFinite(v) || v < 0 || v > 100 ? '—' : `${v.toFixed(1)}%`
const summaries = computed(() => {
  const s = sections.value
  const notifications = s?.notifications?.data
  return [
    { title: '服务器采集', value: s?.servers?.data ? `${s.servers.data.fresh} / ${s.servers.data.enabled}` : '—', detail: '正常 / 启用', section: s?.servers, to: '/servers' },
    { title: '网站状态', value: s?.websites?.data ? `${s.websites.data.normal} / ${s.websites.data.total}` : '—', detail: `正常 / 全部 · 暂停 ${number(s?.websites?.data?.paused)}`, section: s?.websites, to: '/websites' },
    { title: '当前异常', value: number(s?.alerts?.data?.total), detail: '服务器与网站', section: s?.alerts, to: '/alerts' },
    { title: '24 小时文件／安全事件', value: number(s?.events?.data?.total), detail: `安全命中 ${number(s?.events?.data?.security)} · 排除探针`, section: s?.events, to: '/events' },
    { title: '双通道待投递', value: notifications ? String(notifications.feishu.pending + notifications.email.pending) : '—', detail: notifications ? `飞书 ${notifications.feishu.pending} · 邮箱 ${notifications.email.pending}` : '飞书与邮箱独立统计', section: s?.notifications, to: '/alerts?tab=feishu' },
    { title: '部署任务', value: number(s?.deployments?.data?.running), detail: `待恢复 ${number(s?.deployments?.data?.recovery_required)}`, section: s?.deployments, to: '/deployments' },
  ]
})
const charts = computed(() => (['cpu_percent', 'memory_percent', 'disk_percent'] as const).map((metric, index) => {
  const rows = sections.value?.resources?.data?.rankings[metric] || []
  const option: EChartsOption = { grid: { left: 100, right: 35, top: 15, bottom: 25 }, tooltip: { trigger: 'axis' }, xAxis: { type: 'value', min: 0, max: 100, axisLabel: { formatter: '{value}%' } }, yAxis: { type: 'category', inverse: true, data: rows.map(row => row.name), axisLabel: { width: 85, overflow: 'truncate' } }, series: [{ type: 'bar', data: rows.map(row => row.value), itemStyle: { color: ['#168a80', '#437fa8', '#8c77ab'][index], borderRadius: [0, 3, 3, 0] }, barMaxWidth: 18 }] }
  return { title: `${['CPU', '内存', '磁盘'][index]} 使用率前 10`, option, known: rows.length > 0 }
}))
</script>

<template>
  <section class="v3-dashboard">
    <div class="v3-page-heading"><div><h1>运行概况</h1><p class="v3-muted">{{ value?.version || '版本未知' }} · 最近更新 {{ timeText(value?.updated_at) }} · 每 30 秒刷新</p></div><el-button :loading="read.loading.value" @click="refresh">刷新</el-button></div>
    <el-alert v-if="read.error.value" :title="`${read.error.value}；保留上次数据，等待重试`" type="error" :closable="false" />
    <el-alert v-else-if="value?.stale || value?.error" title="汇总已过期或生成异常；以下为上次观测数据" type="warning" :closable="false" />
    <div class="v3-dashboard-summary"><router-link v-for="item in summaries" :key="item.title" :to="item.to" class="v3-summary-card"><span>{{ item.title }}</span><strong>{{ item.value }}</strong><small>{{ item.detail }}</small><small v-if="item.section?.error" class="v3-expired">分区读取失败 · 上次 {{ timeText(item.section.updated_at) }}</small></router-link></div>
    <el-card shadow="never"><div class="v3-section-heading"><h2>当前异常</h2><router-link to="/alerts">查看全部</router-link></div><p v-if="sections?.alerts?.error" class="v3-expired">{{ sections.alerts.error }} · 上次 {{ timeText(sections.alerts.updated_at) }}</p><p v-if="!sections?.alerts?.data" class="v3-muted">{{ read.loading.value ? '正在读取异常…' : '当前异常未知，尚无可用结果' }}</p><p v-else-if="sections.alerts.data.items.length === 0" class="v3-muted">{{ sections.alerts.error || value?.stale || read.error.value ? '上次观测没有异常，当前状态待确认' : '当前没有异常' }}</p><ul v-else class="v3-dashboard-alerts"><li v-for="item in sections.alerts.data.items" :key="`${item.source}:${item.id}`"><span class="v3-alert-dot">!</span><div><router-link :to="item.source === 'website' ? `/websites/${item.website}` : `/servers/${encodeURIComponent(item.node)}`">{{ item.name }}</router-link><small>{{ item.source === 'website' ? '网站状态异常' : `服务器 ${item.kind} 异常` }}</small></div><time>{{ timeText(item.since) }}</time></li></ul></el-card>
    <div class="v3-section-heading"><h2>组件总览</h2><span class="v3-muted">缺少证据时显示未知</span></div>
    <div class="v3-component-grid"><el-card v-for="card in components" :key="card.key" shadow="never"><div class="v3-component-heading"><h3>{{ card.title }}</h3><span :class="['v3-component-status', { good: card.status === '正常', bad: card.status === '异常' }]">{{ card.status === '正常' ? '✓' : card.status === '异常' ? '!' : '—' }} {{ card.status }}</span></div><p>{{ card.reason }}</p><footer><time>{{ timeText(card.at) }}</time><router-link :to="card.to">查看</router-link></footer></el-card></div>
    <p v-if="sections?.resources?.error" class="v3-expired">资源 {{ sections.resources.error }} · 上次 {{ timeText(sections.resources.updated_at) }}</p>
    <div class="v3-ranking-grid"><div v-for="chart in charts" :key="chart.title"><MetricChart v-if="chart.known" :title="chart.title" :option="chart.option" /><el-card v-else shadow="never"><h2>{{ chart.title }}</h2><p class="v3-muted">暂无有效的新鲜采样</p></el-card></div></div>
    <el-card shadow="never"><div class="v3-section-heading"><h2>服务器资源</h2><router-link to="/servers">管理全部服务器</router-link></div><p class="v3-muted">按编号展示前 20 台启用服务器；排名从全部有效采样计算。缺失数据为 —。</p><el-table :data="sections?.resources?.data?.items || []" empty-text="尚无服务器采集数据"><el-table-column label="服务器" min-width="160"><template #default="{ row }"><router-link :to="`/servers/${encodeURIComponent(row.id)}`">{{ row.name }}</router-link></template></el-table-column><el-table-column label="运行方式" min-width="110"><template #default="{ row }">{{ row.actual_mode || '未知' }}<small class="v3-muted v3-block">配置 {{ row.mode }}</small></template></el-table-column><el-table-column prop="agent_version" label="Agent 版本" min-width="130"><template #default="{ row }">{{ row.agent_version || '—' }}</template></el-table-column><el-table-column label="CPU" min-width="90"><template #default="{ row }">{{ percent(row.cpu_percent) }}</template></el-table-column><el-table-column label="内存" min-width="90"><template #default="{ row }">{{ percent(row.memory_percent) }}</template></el-table-column><el-table-column label="磁盘" min-width="90"><template #default="{ row }">{{ percent(row.disk_percent) }}</template></el-table-column><el-table-column label="采集时间" min-width="170"><template #default="{ row }">{{ timeText(row.sampled_at) }}<small v-if="row.has_error" class="v3-expired v3-block">采集异常</small></template></el-table-column></el-table></el-card>
  </section>
</template>
