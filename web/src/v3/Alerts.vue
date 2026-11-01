<script setup lang="ts">
import CursorPagination from './CursorPagination.vue'
import { useCursorPage } from './cursorPage'
import PageHeading from './PageHeading.vue'
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { queryParams } from '../api'
import type { V3HealthRecord, V3HealthState, V3HistoryCategory, V3Node, V3Notification, V3NotificationDeliveryState, V3NotificationSource, V3SiteIncident } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import HistoryDelete from './HistoryDelete.vue'
import NotificationDetail from './NotificationDetail.vue'
import MetricChart from '../MetricChart.vue'
import type { EChartsOption } from 'echarts'

type Tab = 'current' | 'history' | 'feishu' | 'email'
type AlertRow = { id: string; node: string; name: string; kind: string; message: string; status: string; time: string | number; ended?: number | null;
  record_key: string; can_delete: boolean; delete_reason: string; site?: number; attempts?: number; nextTry?: string | null; event?: string; category?: V3HistoryCategory }
const pagination = useCursorPage(), pageLimit = pagination.limit

const { client, session } = useConsole(), route = useRoute(), router = useRouter(), read = useReadScope(), options = useReadScope()
const statsRead = useReadScope(), stats = ref<{day:string;delivered:number;pending:number;retrying:number}[]>([])
const chart = computed<EChartsOption>(() => ({tooltip:{trigger:'axis'},legend:{bottom:0},grid:{left:45,right:20,top:20,bottom:55},xAxis:{type:'category',data:stats.value.map(v=>v.day)},yAxis:{type:'value'},series:[['delivered','已完成'],['pending','待发送'],['retrying','重试中']].map(([key,label])=>({name:label!,type:'bar',stack:'messages',data:stats.value.map(v=>v[key as 'delivered'|'pending'|'retrying'])}))}))
const filters = reactive({ tab: 'current' as Tab, source: 'server', node: '', site: 0, hours: 24, phase: '', state: '', notificationSource: '' as '' | V3NotificationSource, q: '', recipient: '', delivery_state: '' as '' | V3NotificationDeliveryState })
const rows = ref<AlertRow[]>([]), nodes = ref<V3Node[]>([]), next = ref(''), checked = ref<AlertRow[]>([]), detail = ref<AlertRow>()
const loaded = ref(false), appliedKey = ref(''), updated = ref(0), deletion = ref<InstanceType<typeof HistoryDelete>>()
const current = computed(() => filters.tab === 'current'), notifications = computed(() => ['feishu', 'email'].includes(filters.tab))
const cursor = computed(() => typeof route.query.cursor === 'string' ? route.query.cursor : '')
const canWrite = computed(() => !!session.value && session.value.role !== 'viewer')
const categories = computed<V3HistoryCategory[]>(() => [notifications.value ? filters.tab as 'feishu' | 'email' : filters.source === 'website' ? 'website-incidents' : 'server-alerts'])
const kindLabels: Record<string, string> = { cpu: 'CPU 使用率', memory: '内存使用率', disk: '磁盘空间', inode: 'inode 使用率', clock: '时钟同步', node_unreachable: '采集失联', unreachable: '采集失联', agent: '文件监控心跳', scanner: '安全扫描', coverage: '监控目录覆盖', backlog: '事件积压', dropped: '事件丢弃', outage: '网站访问', certificate: '证书有效期', slow: '响应缓慢' }
const sourceLabels: Record<string, string> = { event: '文件与安全事件', server_health: '服务器告警', website: '网站监控', test: '测试通知', legacy: '旧版记录', unknown: '未知' }
const phaseLabels: Record<string, string> = { firing: '异常中', resolved: '已恢复', reminder: '持续提醒', completed: '已完成', migration_pending: '等待迁移切换', paused: '已暂停', sending: '正在发送', waiting: '等待前序通知', retrying: '等待重试', pending: '待发送' }
function conditions() {
  return { limit: pageLimit.value === 20 ? undefined : pageLimit.value, tab: filters.tab, source: notifications.value ? filters.notificationSource : filters.source, node: filters.node, site: !notifications.value && filters.source === 'website' ? filters.site || undefined : undefined,
    hours: current.value ? undefined : filters.hours, phase: !notifications.value && !current.value && filters.source === 'server' ? filters.phase : undefined,
    state: notifications.value ? filters.state : undefined, delivery_state: notifications.value ? filters.delivery_state : undefined, q: notifications.value ? filters.q : undefined, recipient: filters.tab === 'email' ? filters.recipient : undefined }
}
const queryKey = computed(() => JSON.stringify(conditions()))
const stale = computed(() => loaded.value && appliedKey.value !== queryKey.value)
const emptyText = computed(() => read.error.value ? '当前状态读取失败，上一次结果为空' : stale.value ? '正在读取当前筛选，上一次结果为空' : read.loading.value ? '正在更新，上一次结果为空' : current.value ? '当前筛选下暂无异常' : '当前筛选下暂无记录')
const previousCursors = new Map<string, string>()
let cursorScope = ''
let generation = 0, disposed = false, timer: ReturnType<typeof setTimeout> | undefined, range = { start: '', end: '' }, rangeKey = ''
function healthRow(value: V3HealthState | V3HealthRecord): AlertRow {
  const history = 'record_key' in value
  return { id: history ? value.id : value.key, node: value.node, name: value.node, kind: value.kind, message: value.message,
    status: value.phase, time: (history ? value.time : value.since) * 1000, record_key: history ? value.record_key : `current:${value.key}`,
    can_delete: history && value.can_delete, delete_reason: history ? value.delete_reason : '当前异常不能直接删除', category: 'server-alerts' }
}
function incidentRow(value: V3SiteIncident, active: boolean): AlertRow {
  return { id: String(value.id), node: value.node || '', name: value.site_name || `网站 #${value.site}`, kind: value.kind, message: value.reason,
    status: value.ended === null ? 'firing' : 'resolved', time: value.started * 1000, ended: value.ended === null ? null : value.ended * 1000,
    record_key: value.record_key, can_delete: !active && value.can_delete, delete_reason: active ? '当前异常不能直接删除' : value.delete_reason, site: value.site, category: 'website-incidents' }
}
function notificationRow(value: V3Notification): AlertRow {
  return { id: value.id, node: value.node, name: value.recipient || '飞书机器人', kind: value.channel, message: value.subject || value.summary || (value.event_id ? `关联事件：${value.event_id}` : '查看通知详情'),
    status: value.state || (value.done_at ? 'completed' : 'pending'), time: value.created_at, ended: value.done_at ? Date.parse(value.done_at) : null,
    record_key: value.record_key, can_delete: value.can_delete, delete_reason: value.delete_reason, attempts: value.attempts, nextTry: value.next_try,
    event: value.event_id, category: value.channel }
}
function schedule() { clearTimeout(timer); if (!disposed && !document.hidden) timer = setTimeout(() => void load(true), 30_000) }
async function load(roll = false, replace = false) {
  if (disposed || document.hidden || read.loading.value && !replace) return
  clearTimeout(timer); const token = ++generation, key = queryKey.value, selected = { ...filters }, active = current.value, channel = notifications.value, after = cursor.value
  if (roll || !range.start || key !== rangeKey) { rangeKey = key; const end = new Date(); range = { start: new Date(end.getTime() - selected.hours * 3600_000).toISOString(), end: end.toISOString() } }
  if (cursorScope !== key) { cursorScope = key; previousCursors.clear() }
  const window = { ...range }
  await read.run(async signal => {
    if (channel) {
      const page = await client.notifications({ channel: selected.tab as 'feishu' | 'email', node: selected.node, state: selected.state as '' | 'pending' | 'completed', source: selected.notificationSource, q: selected.q, recipient: selected.tab === 'email' ? selected.recipient : '', delivery_state: selected.delivery_state, ...window, cursor: after, limit: pageLimit.value }, signal)
      return { ...page, items: page.items.map(notificationRow) }
    }
    if (selected.source === 'website') {
      const page = await client.websiteIncidents(selected.site || undefined, after, pageLimit.value, { node: selected.node, current: active, ...(active ? {} : window) }, signal)
      return { ...page, items: page.items.map(value => incidentRow(value, active)) }
    }
    if (active) {
      const page = await client.currentAlerts(selected.node, after, pageLimit.value, signal)
      return { ...page, items: page.items.map(healthRow) }
    }
    const page = await client.alertHistory({ node: selected.node, phase: selected.phase as '' | 'firing' | 'resolved' | 'reminder', ...window, cursor: after, limit: pageLimit.value }, signal)
    return { ...page, items: page.items.map(healthRow) }
  }, page => {
    rows.value = page.items; next.value = page.next_cursor; checked.value = []; loaded.value = true; appliedKey.value = key; updated.value = Date.now()
    // Walk visited cursor pages after cleanup; a deep link with no known
    // predecessor safely returns to the first page of the same filter.
    if (!page.items.length && after) {
      const previous = previousCursors.get(after) || ''
      previousCursors.delete(after)
      void router.replace({ path: '/alerts', query: Object.fromEntries(queryParams({ ...conditions(), cursor: previous })) })
    }
  })
  if (!disposed && token === generation) schedule()
}
function loadStats() { if (notifications.value) void statsRead.run(signal => client.notificationStats(filters.tab as 'feishu'|'email', filters.node, signal), value => { stats.value = value.items }); else statsRead.cancel() }
async function sync() {
  const before = route.fullPath
  await router.push({ path: '/alerts', query: Object.fromEntries(queryParams(conditions())) })
  if (before === route.fullPath) void load(true, true)
}
function page(value: string) { if (value) previousCursors.set(value, cursor.value); void router.push({ path: '/alerts', query: Object.fromEntries(queryParams({ ...conditions(), cursor: value })) }) }
function chooseTab(value: Tab) { filters.tab = value; void sync() }
function loadOptions(q = '') { void options.run(signal => client.servers(q, '', 20, signal), page => { nodes.value = page.items }) }
function visibility() { clearTimeout(timer); if (document.hidden) { generation++; read.cancel(); statsRead.cancel() } else {void load(true, true);loadStats()} }
watch(() => route.fullPath, () => {
  const previousKey = queryKey.value
  filters.tab = ['current', 'history', 'feishu', 'email'].includes(String(route.query.tab)) ? route.query.tab as Tab : 'current'
  filters.source = route.query.source === 'website' ? 'website' : 'server'; filters.node = typeof route.query.node === 'string' ? route.query.node : ''
  filters.site = Number.isSafeInteger(Number(route.query.site)) && Number(route.query.site) > 0 ? Number(route.query.site) : 0
  filters.hours = [24, 168, 720].includes(Number(route.query.hours)) ? Number(route.query.hours) : 24
  filters.phase = ['firing', 'resolved', 'reminder'].includes(String(route.query.phase)) ? String(route.query.phase) : ''
  filters.state = ['pending', 'completed'].includes(String(route.query.state)) ? String(route.query.state) : ''
  filters.notificationSource = Object.hasOwn(sourceLabels, String(route.query.source)) ? route.query.source as V3NotificationSource : ''
  filters.q = typeof route.query.q === 'string' ? route.query.q : ''; filters.recipient = typeof route.query.recipient === 'string' ? route.query.recipient : ''
  filters.delivery_state = Object.hasOwn(phaseLabels, String(route.query.delivery_state)) && !['firing', 'resolved', 'reminder'].includes(String(route.query.delivery_state)) ? route.query.delivery_state as V3NotificationDeliveryState : ''
  checked.value = []; detail.value = undefined
  void load(previousKey !== queryKey.value, true); stats.value = []; loadStats()
}, { immediate: true })
onMounted(() => { loadOptions(); document.addEventListener('visibilitychange', visibility) })
onUnmounted(() => { disposed = true; generation++; clearTimeout(timer); document.removeEventListener('visibilitychange', visibility) })
</script>

<template>
  <section>
    <PageHeading title="告警中心"><span v-if="updated" class="small muted">最近更新：{{ timeText(updated) }}</span><el-button :loading="read.loading.value" @click="load(true, true)">刷新</el-button></PageHeading>
    <el-card shadow="never"><div class="card-heading"><span></span><router-link :to="{path:'/settings',query:{tab:'storage',node:filters.node}}">存储与清理 →</router-link></div><nav class="v3-alert-tabs" aria-label="告警分类"><el-button v-for="[value, label] in [['current', '当前异常'], ['history', '告警历史'], ['feishu', '飞书通知'], ['email', '邮箱通知']]" :key="value" :type="filters.tab === value ? 'primary' : ''" @click="chooseTab(value as Tab)">{{ label }}</el-button></nav>
      <div class="filters v3-event-filters"><el-select v-if="!notifications" v-model="filters.source" aria-label="告警来源" @change="sync"><el-option value="server" label="服务器" /><el-option value="website" label="网站" /></el-select><el-select v-model="filters.node" aria-label="服务器筛选" clearable :value-on-clear="''" filterable remote :remote-method="loadOptions" :loading="options.loading.value" placeholder="全部服务器（输入名称搜索）" @change="sync"><el-option v-if="filters.node && !nodes.some(node => node.id === filters.node)" :value="filters.node" :label="filters.node" /><el-option v-for="node in nodes" :key="node.id" :value="node.id" :label="`${node.name} · ${node.id}`" /></el-select><el-select v-if="!current" v-model="filters.hours" aria-label="历史时间范围" @change="sync"><el-option v-for="[value, label] in [[24, '最近 24 小时'], [168, '最近 7 天'], [720, '最近 30 天']]" :key="value" :value="value" :label="String(label)" /></el-select><el-select v-if="filters.tab === 'history' && filters.source === 'server'" v-model="filters.phase" clearable :value-on-clear="''" aria-label="告警阶段" placeholder="全部告警阶段" @change="sync"><el-option v-for="value in ['firing', 'resolved', 'reminder']" :key="value" :value="value" :label="phaseLabels[value]" /></el-select><el-select v-if="notifications" v-model="filters.state" clearable :value-on-clear="''" aria-label="通知完成状态" placeholder="全部完成状态" @change="sync"><el-option value="pending" label="未完成" /><el-option value="completed" label="已完成" /></el-select><template v-if="notifications"><el-select v-model="filters.notificationSource" clearable :value-on-clear="''" aria-label="通知来源" placeholder="全部通知来源" @change="sync"><el-option v-for="(label, value) in sourceLabels" :key="value" :value="value" :label="label" /></el-select><el-select v-model="filters.delivery_state" clearable :value-on-clear="''" aria-label="通知发送状态" placeholder="全部发送状态" @change="sync"><el-option v-for="value in ['completed', 'migration_pending', 'paused', 'sending', 'waiting', 'retrying', 'pending']" :key="value" :value="value" :label="phaseLabels[value]" /></el-select><el-input v-model="filters.q" aria-label="通知关键词" :maxlength="200" placeholder="通知主题或内容" clearable @keyup.enter="sync" /><el-input v-if="filters.tab === 'email'" v-model="filters.recipient" aria-label="通知收件人" :maxlength="254" placeholder="收件人" clearable @keyup.enter="sync" /><el-button @click="sync">查询通知</el-button></template></div>
      <div v-if="!notifications && filters.source === 'website' && filters.site" class="v3-history-toolbar"><span>当前网站：{{ rows.find(row => row.site === filters.site)?.name || `网站 #${filters.site}` }}</span><el-button text @click="filters.site = 0; sync()">清除网站筛选</el-button></div><el-alert v-if="options.error.value" title="服务器选项读取失败，可重新搜索；当前筛选保留。" type="warning" :closable="false" /><el-alert v-if="stale" title="正在更新筛选，上一次查询结果暂时保留。" type="info" :closable="false" /><el-alert v-if="read.error.value" :title="`${read.error.value}${loaded ? '；保留上一次结果。' : ''}`" type="error" :closable="false" />
      <div v-if="!current && canWrite && loaded && !stale" class="v3-history-toolbar"><HistoryDelete ref="deletion" :records="checked" :categories="categories" :label="notifications ? '通知历史' : '告警历史'" @done="load(true, true)" /><span class="v3-muted">保护最近 24 小时、当前异常和未完成任务。</span></div>
      <el-empty v-if="!loaded" :description="read.error.value ? '告警读取失败，请重试' : '正在读取告警…'" />
      <el-table v-else :data="rows" row-key="record_key" :aria-busy="read.loading.value" :empty-text="emptyText" @selection-change="checked = $event"><el-table-column v-if="!current && canWrite" type="selection" :selectable="(row: AlertRow) => !stale && row.can_delete" width="48" /><el-table-column label="时间（北京时间）" min-width="185"><template #default="{ row }">{{ timeText(row.time) }}</template></el-table-column><el-table-column :label="notifications ? '收件人 / 目标' : '服务器 / 网站'" min-width="170"><template #default="{ row }">{{ row.name }}<small v-if="row.site && row.node" class="v3-block v3-muted">{{ row.node }}</small></template></el-table-column><el-table-column label="类型" min-width="140"><template #default="{ row }">{{ kindLabels[row.kind] || (row.kind === 'email' ? '邮箱通知' : row.kind === 'feishu' ? '飞书通知' : row.kind) }}</template></el-table-column><el-table-column label="问题 / 内容" min-width="280"><template #default="{ row }"><el-button link type="primary" class="v3-event-content" @click="detail = row">{{ row.message || '查看记录详情' }}</el-button></template></el-table-column><el-table-column label="状态" min-width="140"><template #default="{ row }"><el-tag :type="row.status === 'firing' ? 'danger' : row.status === 'resolved' ? 'success' : 'info'">{{ phaseLabels[row.status] || '未知' }}</el-tag><small v-if="row.attempts !== undefined" class="v3-block v3-muted">尝试 {{ row.attempts }} 次</small></template></el-table-column><el-table-column label="结束时间 / 持续时长" min-width="190"><template #default="{ row }">{{ row.ended ? timeText(row.ended) : row.status === 'firing' ? '持续异常' : '未提供' }}</template></el-table-column><el-table-column v-if="!current" label="删除保护" min-width="220"><template #default="{ row }"><el-button v-if="canWrite" text type="danger" :disabled="stale || !row.can_delete" @click="deletion?.open([row])">删除</el-button><small class="v3-block v3-muted">{{ row.delete_reason || '可删除历史' }}</small></template></el-table-column></el-table>
      <CursorPagination v-if="loaded" :previous="!!cursor" :next="!!next" :limit="pageLimit" :loading="read.loading.value || stale" @previous="page(previousCursors.get(cursor) || '')" @next="page(next)" @resize="pagination.resize" />
      <p v-if="notifications" class="v3-muted">已完成不代表收件人已读；邮件到达收件箱仍需核对实际收件。关闭通知通道时，未完成记录保留并暂停。</p>
    </el-card>
    <template v-if="notifications"><el-alert v-if="statsRead.error.value" :title="`${statsRead.error.value}；统计未更新`" type="warning" :closable="false" /><MetricChart :title="filters.tab === 'email' ? '最近 7 天邮箱通知结果' : '最近 7 天飞书通知结果'" :option="chart" /><p class="small muted">按北京时间及任务创建日期统计当前结果，包含暂停任务。已完成不代表已读；SMTP 接受不代表进入收件箱。</p></template>
    <NotificationDetail v-if="detail && notifications" :id="detail.id" @close="detail = undefined" /><el-dialog :model-value="!!detail && !notifications" title="告警详情" class="v3-node-dialog" width="760px" @update:model-value="detail = undefined"><div v-if="detail" class="detail-grid v3-detail-grid"><div><span>记录 ID</span><strong>{{ detail.id }}</strong></div><div><span>服务器</span><strong>{{ detail.node || '监控中心' }}</strong></div><div><span>对象</span><strong>{{ detail.name }}</strong></div><div><span>状态</span><strong>{{ phaseLabels[detail.status] || '未知' }}</strong></div><div><span>时间</span><strong>{{ timeText(detail.time) }}</strong></div><div><span>结束 / 完成</span><strong>{{ timeText(detail.ended) }}</strong></div><template v-if="detail.attempts !== undefined"><div><span>尝试次数</span><strong>{{ detail.attempts }}</strong></div><div><span>计划发送时间</span><strong>{{ timeText(detail.nextTry) }}</strong></div></template><div><span>内容</span><strong>{{ detail.message }}</strong></div><div><span>删除保护</span><strong>{{ detail.delete_reason || '可删除历史' }}</strong></div></div><template #footer><el-button @click="detail = undefined">关闭</el-button></template></el-dialog>
  </section>
</template>
