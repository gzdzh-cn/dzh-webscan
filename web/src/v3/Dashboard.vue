<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { Monitor, Cpu, Document, FirstAidKit, Connection, Link, Coin, Bell, Message, Setting, Warning, FolderOpened, List, CircleCheck, CircleClose, QuestionFilled, Remove } from '@element-plus/icons-vue'
import { rankingOption } from '../charts'
import PageHeading from './PageHeading.vue'
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
    { title: '服务器采集', value: s?.servers?.data ? `${s.servers.data.fresh} 正常 / ${s.servers.data.abnormal} 异常` : '—', detail: s?.servers?.data ? `共 ${s.servers.data.servers} 台，未知 ${s.servers.data.unknown} 台` : '尚无采集汇总', section: s?.servers, to: '/servers' },
    { title: '网站状态', value: s?.websites?.data ? `${s.websites.data.normal} 正常 / ${s.websites.data.down} 异常` : '—', detail: `共 ${number(s?.websites?.data?.total)} 个，暂停 ${number(s?.websites?.data?.paused)} 个，待检查 ${number(s?.websites?.data?.pending)} 个`, section: s?.websites, to: '/websites' },
    { title: '当前异常', value: number(s?.alerts?.data?.total), detail: '服务器与网站', section: s?.alerts, to: '/alerts' },
    { title: '文件与安全事件 · 24 小时', value: number(s?.events?.data?.total), detail: `安全命中 ${number(s?.events?.data?.security)} · 排除探针`, section: s?.events, to: '/events' },
    { title: '待投递通知', value: notifications ? `飞书 ${notifications.feishu.pending} / 邮箱 ${notifications.email.pending}` : '—', detail: '暂停、重试任务继续保留', section: s?.notifications, to: '/alerts?tab=feishu' },
    { title: '部署任务', value: !s?.deployments?.data ? '未知' : s.deployments.data.running ? '执行中' : '空闲', detail: `待恢复 ${number(s?.deployments?.data?.recovery_required)}`, section: s?.deployments, to: '/deployments' },
  ]
})
const icons = { central: Monitor, metrics: Cpu, files: Document, scans: FirstAidKit, delivery: Connection, websites: Link, database: Coin, feishu: Bell, email: Message, host: Setting, watchdog: Warning, cleanup: FolderOpened, deployments: List }
const charts = computed(() => (['cpu_percent', 'memory_percent', 'disk_percent'] as const).map((metric, index) => ({
  title: ['CPU 使用率排名', '内存使用率排名', '磁盘使用率排名'][index]!,
  option: rankingOption((sections.value?.resources?.data?.rankings[metric] || []).map(row => ({ name: row.name, status: 'normal', snapshot: { ok: true, values: { [metric]: row.value } } })), metric),
})))
const statusClass = (status: string) => ({ '正常': 'normal', '异常': 'abnormal', '维护中': 'maintenance' }[status] || 'unknown')
function componentMetrics(key: string): [string, string][] {
  const s = sections.value
  switch (key) {
    case 'central': return [['当前版本', value.value?.version || '未知'], ['采集方式', '主控主动采集']]
    case 'metrics': return [['正常节点', number(s?.servers?.data?.fresh)], ['异常 / 未知', `${number(s?.servers?.data?.abnormal)} / ${number(s?.servers?.data?.unknown)}`]]
    case 'files': return [['待确认事件', number(s?.monitoring?.data?.pending_events)], ['最长等待', s?.monitoring?.data?.oldest_wait_seconds == null ? '未知' : `${s.monitoring.data.oldest_wait_seconds} 秒`]]
    case 'scans': return [['YARA / ClamAV', `${number(s?.monitoring?.data?.yara_nodes)} / ${number(s?.monitoring?.data?.clamav_nodes)}`], ['待扫描', number(s?.monitoring?.data?.pending_scans)]]
    case 'websites': return [['网站总数', number(s?.websites?.data?.total)], ['等待检查', number(s?.websites?.data?.due)]]
    case 'database': return [['业务数据库', 'PostgreSQL'], ['业务表与索引', s?.services?.data ? `${(s.services.data.database_bytes / 1048576).toFixed(2)} MiB` : '未知']]
    case 'feishu': case 'email': { const d = s?.notifications?.data?.[key]; return [['通道配置', !d ? '未知' : d.enabled ? '开启' : '关闭'], ['待投递 / 重试', `${number(d?.pending)} / ${number(d?.retrying)}`]] }
    case 'deployments': return [['正在执行', number(s?.deployments?.data?.running)], ['需要恢复', number(s?.deployments?.data?.recovery_required)]]
    default: return []
  }
}
</script>

<template>
  <section class="v3-dashboard">
    <PageHeading title="监控总览" />
    <div class="dashboard-heading"><div><el-tag>{{ value?.version || '版本未知' }}</el-tag><p class="muted">{{ value?.updated_at ? `最近更新：${timeText(value.updated_at)}` : '等待加载' }} · 页面每 30 秒刷新，后台标签暂停</p></div><el-button :loading="read.loading.value" @click="refresh">立即刷新</el-button></div>
    <el-alert v-if="read.error.value" :title="`${read.error.value}；保留上次数据，等待重试`" type="error" :closable="false" />
    <el-alert v-else-if="value?.stale || value?.error" title="汇总已过期或生成异常；以下为上次观测数据" type="warning" :closable="false" />
    <div class="stats dashboard-stats"><router-link v-for="item in summaries" :key="item.title" :to="item.to" class="v3-summary-card"><el-card shadow="never"><span class="muted">{{ item.title }}</span><strong>{{ item.value }}</strong><small>{{ item.detail }}</small><small v-if="item.section?.error" class="v3-expired">分区读取失败 · 上次 {{ timeText(item.section.updated_at) }}</small></el-card></router-link></div>
    <el-card shadow="never"><div class="card-heading"><h3>当前异常</h3><router-link to="/alerts">查看全部 →</router-link></div><el-alert v-if="sections?.alerts?.error" :title="`${sections.alerts.error} · 上次 ${timeText(sections.alerts.updated_at)}`" type="warning" :closable="false" />
      <el-table :data="sections?.alerts?.data?.items || []" :empty-text="!sections?.alerts?.data ? read.loading.value ? '正在读取异常…' : '当前异常未知，尚无可用结果' : sections.alerts.error || value?.stale || read.error.value ? '上次观测没有异常，当前状态待确认' : '当前没有异常'">
        <el-table-column label="服务器 / 网站" min-width="170"><template #default="{ row }"><router-link :to="row.source === 'website' ? `/websites/${row.website}` : `/servers/${encodeURIComponent(row.node)}`">{{ row.name }}</router-link></template></el-table-column>
        <el-table-column label="原因" min-width="260"><template #default="{ row }">{{ row.message || (row.source === 'website' ? '网站状态异常' : `${row.kind} 异常`) }}</template></el-table-column><el-table-column label="状态"><template #default>异常中</template></el-table-column><el-table-column label="开始时间" min-width="190"><template #default="{ row }">{{ timeText(row.since) }}</template></el-table-column>
      </el-table>
    </el-card>
    <section class="component-section"><div class="card-heading"><h3>组件总览</h3><router-link to="/servers/central?tab=system">中心健康详情 →</router-link></div><div class="component-grid"><el-card v-for="card in components" :key="card.key" shadow="never" :class="['component-card', `component-${statusClass(card.status)}`]"><div class="component-heading v3-component-heading"><el-icon :size="22"><component :is="icons[card.key as keyof typeof icons] || QuestionFilled" /></el-icon><h4>{{ card.title }}</h4><el-tag :type="card.status === '正常' ? 'success' : card.status === '异常' ? 'danger' : card.status === '维护中' ? 'warning' : 'info'"><el-icon><component :is="card.status === '正常' ? CircleCheck : card.status === '异常' ? CircleClose : card.status === '已停用' ? Remove : QuestionFilled" /></el-icon> {{ card.status }}</el-tag></div><dl><template v-for="[label, text] in componentMetrics(card.key)" :key="label"><dt>{{ label }}</dt><dd>{{ text }}</dd></template></dl><p class="muted">{{ card.reason }}</p><footer><small>{{ timeText(card.at) }}</small><router-link :to="card.to">查看详情 →</router-link></footer></el-card></div></section>
    <p v-if="sections?.resources?.error" class="v3-expired">资源 {{ sections.resources.error }} · 上次 {{ timeText(sections.resources.updated_at) }}</p>
    <div class="chart-grid ranking-grid"><MetricChart v-for="chart in charts" :key="chart.title" :title="chart.title" :option="chart.option" /></div>
    <el-card shadow="never"><div class="card-heading"><h3>服务器资源</h3><router-link to="/servers">管理服务器 →</router-link></div><el-table :data="sections?.resources?.data?.items || []" empty-text="尚无服务器采集数据"><el-table-column label="服务器" min-width="160"><template #default="{ row }"><router-link :to="`/servers/${encodeURIComponent(row.id)}`">{{ row.name }}</router-link></template></el-table-column><el-table-column label="采集状态" min-width="100"><template #default="{ row }">{{ row.has_error ? '采集异常' : row.sampled_at ? '已采集' : '未知' }}</template></el-table-column><el-table-column v-for="[metric, label] in [['cpu_percent','CPU'], ['memory_percent','内存'], ['disk_percent','磁盘']]" :key="metric" :label="label" min-width="90"><template #default="{ row }">{{ percent(row[metric!]) }}</template></el-table-column><el-table-column label="运行方式" min-width="110"><template #default="{ row }">{{ row.actual_mode === 'docker' ? 'Docker 容器' : row.actual_mode === 'native' ? '直接运行 Go' : '未知' }}</template></el-table-column><el-table-column label="Agent / 中心版本" min-width="140"><template #default="{ row }">{{ row.agent_version || '未知' }}</template></el-table-column><el-table-column label="最近采集" min-width="190"><template #default="{ row }">{{ timeText(row.sampled_at) }}</template></el-table-column></el-table></el-card>
  </section>
</template>
