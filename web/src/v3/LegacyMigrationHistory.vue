<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useConsole, timeText } from './context'
import { useReadScope } from './readScope'
import PageHeading from './PageHeading.vue'
import CursorPagination from './CursorPagination.vue'
import LegacyMetricHistory from './LegacyMetricHistory.vue'

type HistoryItem = { id: string; role: string; legacy_table: string; record_key: number; summary: Record<string, unknown> }
type HistorySession = { id: string; phase: string; created_at: string; history_records: number; generations: { generation: string; revision: string; state: string }[] }
const { client, session: account } = useConsole(), sessionsRead = useReadScope(), historyRead = useReadScope()
const isAdmin = computed(() => account.value?.role === 'admin')
const sessions = ref<HistorySession[]>([]), session = ref(''), role = ref(''), table = ref(''), limit = ref(20)
const items = ref<HistoryItem[]>([]), cursor = ref(''), next = ref(''), previous = ref<string[]>([]), queried = ref(false), inputError = ref('')
const tableLabels: Record<string, string> = {
 jobs: '旧部署任务', logs: '旧部署日志', job_workflow: '原任务关联', job_progress: '原任务阶段', upgrade_jobs: '原升级版本',
 config_backups: '旧配置备份', config_backup_details: '原备份恢复记录', config_backup_previews: '原备份预览', job_archives: '原历史归档', backup_import_attempts: '原备份导入限制',
 recovery_previews: '原恢复预览', upgrade_previews: '原升级预览', node_removal_previews: '原移除预览', node_removals: '原节点移除记录',
 watchdog_state: '旧看门狗状态', watchdog_outbox: '旧看门狗通知', probes: '旧探针记录', website_backup_pins: '原网站备份保护', website_incident_origins: '原网站异常来源',
}
const centralTables = new Set(['probes', 'website_backup_pins', 'website_incident_origins'])
const tables = computed(() => Object.entries(tableLabels).filter(([key]) => !role.value || (role.value === 'central') === centralTables.has(key)))
const selectedSession = computed(() => sessions.value.find(item => item.id === session.value))
const phases: Record<string, string> = { collecting: '收集资料', indexed: '已归档', frozen: '旧写入已冻结', reconciled: '已核对', active: '已切换', rolled_back: '已回退' }
const states: Record<string, string> = { complete: '已完成', failed: '失败', interrupted: '中断', queued: '待执行', running: '执行中', expired: '原授权已过期', 'active-legacy': '原授权仍有效', healthy: '历史正常', firing: '历史异常', resolved: '历史恢复', unknown: '未知', legacy: '旧版记录' }
const kinds: Record<string, string> = { apply: '应用配置', 'add-node': '添加子控', 'upgrade-node': '升级子控', resume: '继续原任务', rollback: '原任务回退', 'remove-nodes': '移除节点', external: '命令行任务', legacy: '旧版操作', 'configuration-backup': '配置备份' }
let disposed = false, listTimer: ReturnType<typeof setTimeout> | undefined, historyTimer: ReturnType<typeof setTimeout> | undefined
let lastQuery: { session: string; role: string; table: string; limit: number; cursor: string; previous: string[] } | undefined
const shortID = (value: unknown) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value) ? `${value.slice(0, 12)}…` : '未知'
const numberText = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? String(value) : '未知'
const timestamp = (value: unknown) => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? timeText(value) : '未知'
const rowStatus = (row: HistoryItem) => {
 const value = row.summary
 if (typeof value.status === 'string') return states[value.status] || '未知'
 if (typeof value.complete === 'boolean') return value.complete ? '已完成' : '未完成'
 if (typeof value.done === 'boolean') return value.done ? '已确认' : '未确认'
 if (typeof value.phase === 'string') return states[value.phase] || '历史状态，不能代表当前健康'
 return '未提供'
}
function summary(row: HistoryItem) {
 const value = row.summary, parts: string[] = []
 if (typeof value.kind === 'string' && kinds[value.kind]) parts.push(kinds[value.kind]!)
 if (value.message_available === true) parts.push('原日志已加密保留')
 if (value.current_health_evidence === false) parts.push('仅历史记录，不代表当前健康')
 if (value.artifact_available === true) parts.push('备份文件已保留')
 if (value.restore_verified === true) parts.push('已通过隔离恢复验证')
 else if (value.artifact_available === true) parts.push('恢复尚未验证')
 if (value.authorization_imported === false) parts.push('旧授权不会复用')
 if (value.previously_restored === true) parts.push('旧版曾执行恢复')
 if (typeof value.step === 'number' && Number.isSafeInteger(value.step) && value.step >= 0) parts.push(`原步骤 ${value.step}`)
 if (value.failed_attempts !== undefined) parts.push(`原失败次数 ${numberText(value.failed_attempts)}`)
 if (value.omitted_fields !== undefined) parts.push(`省略字段数 ${numberText(value.omitted_fields)}`)
 if (value.active_rate_limit === true) parts.push('原导入限制尚未结束')
 return parts.join('；') || '未提供可展示摘要'
}
function invalidate() {
 clearTimeout(historyTimer); historyRead.cancel(); items.value = []; cursor.value = ''; next.value = ''; previous.value = []; queried.value = false; inputError.value = ''; lastQuery = undefined
}
async function loadSessions() {
 if (!isAdmin.value || disposed || document.hidden || sessionsRead.loading.value) return
 clearTimeout(listTimer)
 await sessionsRead.run(signal => client.migrationHistorySessions(signal), value => {
  sessions.value = value.items
  if (!sessions.value.some(item => item.id === session.value)) session.value = sessions.value[0]?.id || ''
 })
 if (!disposed && !document.hidden && sessionsRead.error.value) listTimer = setTimeout(() => void loadSessions(), 3000)
}
async function query(value = '', history: string[] = []) {
 if (!isAdmin.value || disposed || document.hidden || historyRead.loading.value) return
 if (!sessions.value.some(item => item.id === session.value)) { inputError.value = '请先选择已归档的迁移会话'; return }
 clearTimeout(historyTimer); inputError.value = ''
 const request = { session: session.value, role: role.value, table: table.value, limit: limit.value, cursor: value, previous: history }
 lastQuery = request; queried.value = true
 await historyRead.run(signal => client.legacyHistory(request.session, request.role, request.table, request.cursor, request.limit, signal), result => {
  if (result.read_only !== true || result.items.length > request.limit) throw new Error('旧版历史响应格式或条数不正确')
  items.value = result.items; cursor.value = request.cursor; previous.value = request.previous; next.value = result.next_cursor
 })
 if (!disposed && !document.hidden && historyRead.error.value && lastQuery === request) historyTimer = setTimeout(() => void query(request.cursor, request.previous), 3000)
}
function nextPage() { if (next.value && !historyRead.loading.value) void query(next.value, [...previous.value, cursor.value]) }
function previousPage() { if (previous.value.length && !historyRead.loading.value) void query(previous.value.at(-1) || '', previous.value.slice(0, -1)) }
function resize(value: number) { const reload = queried.value; invalidate(); limit.value = value; if (reload) void query() }
function setFilters(values: { session?: string; role?: string; table?: string }) {
 if (values.session !== undefined) session.value = values.session
 if (values.role !== undefined) role.value = values.role
 if (values.table !== undefined) table.value = values.table
}
function visibility() {
 if (document.hidden) { clearTimeout(listTimer); clearTimeout(historyTimer); sessionsRead.cancel(); historyRead.cancel() }
 else { if (!sessions.value.length || sessionsRead.error.value) void loadSessions(); if (lastQuery) void query(lastQuery.cursor, lastQuery.previous) }
}
watch([session, role, table], () => { invalidate(); if (table.value && !tables.value.some(([key]) => key === table.value)) table.value = '' })
watch(isAdmin, allowed => { if (!allowed) { sessionsRead.cancel(); clearTimeout(listTimer); sessions.value = []; session.value = ''; invalidate() } else void loadSessions() })
onMounted(() => { document.addEventListener('visibilitychange', visibility); void loadSessions() })
onUnmounted(() => { disposed = true; clearTimeout(listTimer); clearTimeout(historyTimer); document.removeEventListener('visibilitychange', visibility) })
defineExpose({ setFilters, search: () => query(), nextPage, previousPage, resize })
</script>

<template>
 <section class="legacy-migration-history">
  <PageHeading title="旧版迁移历史" description="查看旧版部署、日志、配置备份及辅助记录的迁移摘要。"><el-button v-if="isAdmin" :loading="sessionsRead.loading.value" @click="loadSessions">刷新迁移会话</el-button></PageHeading>
  <el-alert v-if="!isAdmin" title="仅管理员可以查看旧版迁移历史。" type="warning" :closable="false" />
  <template v-else>
  <el-alert title="此处仅查看历史。旧任务不会转换为可继续或回退的新版部署任务；旧授权不会复用。原日志、路径及凭据已加密保留，不在页面展示。" type="info" :closable="false" />
  <el-alert v-if="sessionsRead.error.value" :title="`${sessionsRead.error.value}；保留已有会话，3 秒后重试。`" type="error" :closable="false" />
  <el-card shadow="never">
   <form class="filters v3-filters history-filters" @submit.prevent="query()">
    <el-select v-model="session" aria-label="迁移会话" placeholder="选择迁移会话" :loading="sessionsRead.loading.value"><el-option v-for="item in sessions" :key="item.id" :value="item.id" :label="`${timestamp(item.created_at)} · ${shortID(item.id)}`" /></el-select>
    <el-select v-model="role" aria-label="来源角色"><el-option value="" label="全部来源" /><el-option value="host-manager" label="旧宿主管理服务" /><el-option value="central" label="旧主控服务" /></el-select>
    <el-select v-model="table" aria-label="历史类别"><el-option value="" label="全部历史类别" /><el-option v-for="[key, label] in tables" :key="key" :value="key" :label="label" /></el-select>
    <el-button type="primary" native-type="submit" :loading="historyRead.loading.value" :disabled="!selectedSession">查询历史</el-button>
   </form>
   <p v-if="selectedSession" class="muted history-context">会话 {{ shortID(selectedSession.id) }} · {{ phases[selectedSession.phase] || '未知状态' }} · 已归档历史 {{ numberText(selectedSession.history_records) }} 条。这里只展示受控摘要，不代表对应旧服务仍在运行。</p>
   <el-alert v-if="inputError" :title="inputError" type="warning" :closable="false" />
   <el-alert v-if="historyRead.error.value" :title="`${historyRead.error.value}；保留上一次结果，3 秒后重试。`" type="error" :closable="false" />
   <p v-if="!queried" class="muted" role="status">选择迁移会话及筛选条件后，点击“查询历史”。</p>
   <el-table :data="items" row-key="id" :aria-busy="historyRead.loading.value" :empty-text="queried ? '没有符合条件的旧版历史' : '尚未查询历史'">
    <el-table-column label="历史类别" min-width="160"><template #default="{row}">{{ tableLabels[row.legacy_table] || '未知历史类别' }}<small class="muted history-block">{{ row.role === 'host-manager' ? '旧宿主管理服务' : row.role === 'central' ? '旧主控服务' : '来源未知' }}</small></template></el-table-column>
    <el-table-column label="原记录" min-width="160"><template #default="{row}">{{ numberText(row.record_key) }}<small class="muted history-block">{{ shortID(row.id) }}</small></template></el-table-column>
    <el-table-column label="状态" min-width="140"><template #default="{row}"><el-tag type="info">{{ rowStatus(row) }}</el-tag></template></el-table-column>
    <el-table-column label="时间（北京时间）" min-width="185"><template #default="{row}">{{ timestamp(row.summary.updated_at || row.summary.created_at || row.summary.observed_at) }}</template></el-table-column>
    <el-table-column label="历史摘要" min-width="300"><template #default="{row}">{{ summary(row) }}<small v-if="row.summary.parent" class="muted history-block">原关联 {{ shortID(row.summary.parent) }}</small></template></el-table-column>
   </el-table>
   <CursorPagination :previous="!!previous.length" :next="!!next" :limit="limit" :loading="historyRead.loading.value" :page="queried ? previous.length + 1 : undefined" @previous="previousPage" @next="nextPage" @resize="resize" />
  </el-card>
  <LegacyMetricHistory v-if="selectedSession" :session="selectedSession.id" :generations="selectedSession.generations" />
  </template>
 </section>
</template>
<style scoped>
.history-block { display: block; margin-top: 4px; overflow-wrap: anywhere; }
.history-filters { gap: 12px; flex-wrap: wrap; }
.history-filters .el-select { min-width: 180px; flex: 1; }
.history-filters .el-select:first-child { min-width: 260px; flex: 1.5; }
.history-context { overflow-wrap: anywhere; }
.legacy-migration-history > .el-alert { margin-bottom: 16px; }
@media(max-width:600px) { .history-filters { flex-direction:column; align-items:stretch; } .history-filters .el-select,.history-filters .el-select:first-child { width:100%; min-width:0; } }
</style>
