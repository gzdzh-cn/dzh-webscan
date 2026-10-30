<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { queryParams } from '../api'
import type { V3HealthRecord, V3HealthState, V3HistoryCategory, V3Node, V3Notification, V3SiteIncident } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import HistoryDelete from './HistoryDelete.vue'

type Tab = 'current' | 'history' | 'feishu' | 'email'
type AlertRow = { id: string; node: string; name: string; kind: string; message: string; status: string; time: string | number; ended?: number | null;
  record_key: string; can_delete: boolean; delete_reason: string; site?: number; attempts?: number; nextTry?: string | null; event?: string; category?: V3HistoryCategory }
const { client, session } = useConsole(), route = useRoute(), router = useRouter(), read = useReadScope(), options = useReadScope()
const filters = reactive({ tab: 'current' as Tab, source: 'server', node: '', site: 0, hours: 24, phase: '', state: '' })
const rows = ref<AlertRow[]>([]), nodes = ref<V3Node[]>([]), next = ref(''), checked = ref<AlertRow[]>([]), detail = ref<AlertRow>()
const loaded = ref(false), appliedKey = ref(''), updated = ref(0), deletion = ref<InstanceType<typeof HistoryDelete>>()
const current = computed(() => filters.tab === 'current'), notifications = computed(() => ['feishu', 'email'].includes(filters.tab))
const cursor = computed(() => typeof route.query.cursor === 'string' ? route.query.cursor : '')
const canWrite = computed(() => !!session.value && session.value.role !== 'viewer')
const categories = computed<V3HistoryCategory[]>(() => [notifications.value ? filters.tab as 'feishu' | 'email' : filters.source === 'website' ? 'website-incidents' : 'server-alerts'])
const kindLabels: Record<string, string> = { cpu: 'CPU 使用率', memory: '内存使用率', disk: '磁盘空间', inode: 'inode 使用率', clock: '时钟同步', node_unreachable: '采集失联', unreachable: '采集失联', agent: '文件监控心跳', scanner: '安全扫描', coverage: '监控目录覆盖', backlog: '事件积压', dropped: '事件丢弃', outage: '网站访问', certificate: '证书有效期', slow: '响应缓慢' }
const phaseLabels: Record<string, string> = { firing: '异常中', resolved: '已恢复', reminder: '持续提醒', completed: '已完成', migration_pending: '等待迁移切换', paused: '已暂停', sending: '正在发送', waiting: '等待前序通知', retrying: '等待重试', pending: '待发送' }
function conditions() {
  return { tab: filters.tab, source: notifications.value ? undefined : filters.source, node: filters.node, site: !notifications.value && filters.source === 'website' ? filters.site || undefined : undefined,
    hours: current.value ? undefined : filters.hours, phase: !notifications.value && !current.value && filters.source === 'server' ? filters.phase : undefined,
    state: notifications.value ? filters.state : undefined }
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
  return { id: value.id, node: value.node, name: value.recipient || '飞书机器人', kind: value.channel, message: `关联事件：${value.event_id}`,
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
      const page = await client.notifications({ channel: selected.tab as 'feishu' | 'email', node: selected.node, state: selected.state as '' | 'pending' | 'completed', ...window, cursor: after, limit: 20 }, signal)
      return { ...page, items: page.items.map(notificationRow) }
    }
    if (selected.source === 'website') {
      const page = await client.websiteIncidents(selected.site || undefined, after, 20, { node: selected.node, current: active, ...(active ? {} : window) }, signal)
      return { ...page, items: page.items.map(value => incidentRow(value, active)) }
    }
    if (active) {
      const page = await client.currentAlerts(selected.node, after, 20, signal)
      return { ...page, items: page.items.map(healthRow) }
    }
    const page = await client.alertHistory({ node: selected.node, phase: selected.phase as '' | 'firing' | 'resolved' | 'reminder', ...window, cursor: after, limit: 20 }, signal)
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
async function sync() {
  const before = route.fullPath
  await router.push({ path: '/alerts', query: Object.fromEntries(queryParams(conditions())) })
  if (before === route.fullPath) void load(true, true)
}
function page(value: string) { if (value) previousCursors.set(value, cursor.value); void router.push({ path: '/alerts', query: Object.fromEntries(queryParams({ ...conditions(), cursor: value })) }) }
function chooseTab(value: Tab) { filters.tab = value; void sync() }
function loadOptions(q = '') { void options.run(signal => client.servers(q, '', 20, signal), page => { nodes.value = page.items }) }
function visibility() { clearTimeout(timer); if (document.hidden) { generation++; read.cancel() } else void load(true, true) }
watch(() => route.fullPath, () => {
  const previousKey = queryKey.value
  filters.tab = ['current', 'history', 'feishu', 'email'].includes(String(route.query.tab)) ? route.query.tab as Tab : 'current'
  filters.source = route.query.source === 'website' ? 'website' : 'server'; filters.node = typeof route.query.node === 'string' ? route.query.node : ''
  filters.site = Number.isSafeInteger(Number(route.query.site)) && Number(route.query.site) > 0 ? Number(route.query.site) : 0
  filters.hours = [24, 168, 720].includes(Number(route.query.hours)) ? Number(route.query.hours) : 24
  filters.phase = ['firing', 'resolved', 'reminder'].includes(String(route.query.phase)) ? String(route.query.phase) : ''
  filters.state = ['pending', 'completed'].includes(String(route.query.state)) ? String(route.query.state) : ''
  checked.value = []; detail.value = undefined
  void load(previousKey !== queryKey.value, true)
}, { immediate: true })
onMounted(() => { loadOptions(); document.addEventListener('visibilitychange', visibility) })
onUnmounted(() => { disposed = true; generation++; clearTimeout(timer); document.removeEventListener('visibilitychange', visibility) })
</script>

<template>
  <section>
    <div class="v3-page-heading"><div><h1>告警中心</h1><p class="v3-muted">每 30 秒更新，后台标签暂停。当前异常通过监控恢复或维护处理。</p></div><div class="v3-actions"><span v-if="updated" class="v3-muted">最近更新：{{ timeText(updated) }}</span><el-button :loading="read.loading.value" @click="load(true, true)">刷新</el-button></div></div>
    <el-card shadow="never"><nav class="v3-alert-tabs" aria-label="告警分类"><el-button v-for="[value, label] in [['current', '当前异常'], ['history', '告警历史'], ['feishu', '飞书通知'], ['email', '邮箱通知']]" :key="value" :type="filters.tab === value ? 'primary' : ''" @click="chooseTab(value as Tab)">{{ label }}</el-button></nav>
      <div class="v3-event-filters"><el-select v-if="!notifications" v-model="filters.source" aria-label="告警来源" @change="sync"><el-option value="server" label="服务器" /><el-option value="website" label="网站" /></el-select><el-select v-model="filters.node" aria-label="服务器筛选" clearable :value-on-clear="''" filterable remote :remote-method="loadOptions" :loading="options.loading.value" placeholder="全部服务器（输入名称搜索）" @change="sync"><el-option v-if="filters.node && !nodes.some(node => node.id === filters.node)" :value="filters.node" :label="filters.node" /><el-option v-for="node in nodes" :key="node.id" :value="node.id" :label="`${node.name} · ${node.id}`" /></el-select><el-select v-if="!current" v-model="filters.hours" aria-label="历史时间范围" @change="sync"><el-option v-for="[value, label] in [[24, '最近 24 小时'], [168, '最近 7 天'], [720, '最近 30 天']]" :key="value" :value="value" :label="String(label)" /></el-select><el-select v-if="filters.tab === 'history' && filters.source === 'server'" v-model="filters.phase" clearable :value-on-clear="''" aria-label="告警阶段" placeholder="全部告警阶段" @change="sync"><el-option v-for="value in ['firing', 'resolved', 'reminder']" :key="value" :value="value" :label="phaseLabels[value]" /></el-select><el-select v-if="notifications" v-model="filters.state" clearable :value-on-clear="''" aria-label="通知状态" placeholder="全部通知状态" @change="sync"><el-option value="pending" label="未完成" /><el-option value="completed" label="已完成" /></el-select></div>
      <div v-if="!notifications && filters.source === 'website' && filters.site" class="v3-history-toolbar"><span>当前网站：{{ rows.find(row => row.site === filters.site)?.name || `网站 #${filters.site}` }}</span><el-button text @click="filters.site = 0; sync()">清除网站筛选</el-button></div><el-alert v-if="options.error.value" title="服务器选项读取失败，可重新搜索；当前筛选保留。" type="warning" :closable="false" /><el-alert v-if="stale" title="正在更新筛选，上一次查询结果暂时保留。" type="info" :closable="false" /><el-alert v-if="read.error.value" :title="`${read.error.value}${loaded ? '；保留上一次结果。' : ''}`" type="error" :closable="false" />
      <div v-if="!current && canWrite && loaded && !stale" class="v3-history-toolbar"><HistoryDelete ref="deletion" :records="checked" :categories="categories" :label="notifications ? '通知历史' : '告警历史'" @done="load(true, true)" /><span class="v3-muted">保护最近 24 小时、当前异常和未完成任务。</span></div>
      <el-empty v-if="!loaded" :description="read.error.value ? '告警读取失败，请重试' : '正在读取告警…'" />
      <el-table v-else :data="rows" row-key="record_key" :aria-busy="read.loading.value" :empty-text="emptyText" @selection-change="checked = $event"><el-table-column v-if="!current && canWrite" type="selection" :selectable="(row: AlertRow) => !stale && row.can_delete" width="48" /><el-table-column label="时间" min-width="185"><template #default="{ row }">{{ timeText(row.time) }}</template></el-table-column><el-table-column :label="notifications ? '收件人 / 目标' : '服务器 / 网站'" min-width="170"><template #default="{ row }">{{ row.name }}<small v-if="row.site && row.node" class="v3-block v3-muted">{{ row.node }}</small></template></el-table-column><el-table-column label="类型" min-width="140"><template #default="{ row }">{{ kindLabels[row.kind] || (row.kind === 'email' ? '邮箱通知' : row.kind === 'feishu' ? '飞书通知' : row.kind) }}</template></el-table-column><el-table-column label="内容" min-width="280"><template #default="{ row }"><el-button link type="primary" class="v3-event-content" @click="detail = row">{{ row.message || '查看记录详情' }}</el-button></template></el-table-column><el-table-column label="状态" min-width="140"><template #default="{ row }"><el-tag :type="row.status === 'firing' ? 'danger' : row.status === 'resolved' ? 'success' : 'info'">{{ phaseLabels[row.status] || '未知' }}</el-tag><small v-if="row.attempts !== undefined" class="v3-block v3-muted">尝试 {{ row.attempts }} 次</small></template></el-table-column><el-table-column v-if="!current" label="删除保护" min-width="220"><template #default="{ row }"><el-button v-if="canWrite" text type="danger" :disabled="stale || !row.can_delete" @click="deletion?.open([row])">删除</el-button><small class="v3-block v3-muted">{{ row.delete_reason || '可删除历史' }}</small></template></el-table-column></el-table>
      <div v-if="loaded" class="v3-pagination"><el-button :disabled="!cursor || read.loading.value" @click="page('')">回到首页</el-button><span>每页最多 20 条</span><el-button :disabled="!next || read.loading.value" @click="page(next)">下一页</el-button></div>
      <p v-if="notifications" class="v3-muted">已完成不代表收件人已读；邮件到达收件箱仍需核对实际收件。关闭通知通道时，未完成记录保留并暂停。</p>
    </el-card>
    <el-dialog :model-value="!!detail" title="告警与通知详情" class="v3-node-dialog" width="760px" @update:model-value="detail = undefined"><dl v-if="detail" class="v3-detail-grid"><dt>记录 ID</dt><dd>{{ detail.id }}</dd><dt>服务器</dt><dd>{{ detail.node || '监控中心' }}</dd><dt>对象</dt><dd>{{ detail.name }}</dd><dt>状态</dt><dd>{{ phaseLabels[detail.status] || '未知' }}</dd><dt>时间</dt><dd>{{ timeText(detail.time) }}</dd><dt>结束 / 完成</dt><dd>{{ timeText(detail.ended) }}</dd><template v-if="detail.attempts !== undefined"><dt>尝试次数</dt><dd>{{ detail.attempts }}</dd><dt>计划发送时间</dt><dd>{{ timeText(detail.nextTry) }}</dd></template><dt>内容</dt><dd>{{ detail.message }}</dd><dt>删除保护</dt><dd>{{ detail.delete_reason || '可删除历史' }}</dd></dl><template #footer><el-button @click="detail = undefined">关闭</el-button></template></el-dialog>
  </section>
</template>
