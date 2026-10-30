<script setup lang="ts">
import { nextTick, computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { queryParams } from '../api'
import { resourceCharts, healthCharts, trendOption, metricValue, metricLabel, type MetricPoint } from '../charts'
import MetricChart from '../MetricChart.vue'
import PageHeading from './PageHeading.vue'
import CursorPagination from './CursorPagination.vue'
import { useCursorPage } from './cursorPage'
import type { V3Node, V3NodeInput, V3ServerDetail, V3Dashboard } from '../controlV3'
import { jobLabel, timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import DeploymentFlow from './DeploymentFlow.vue'
import DeploymentRequirements from './DeploymentRequirements.vue'

const { client, session } = useConsole(), route = useRoute(), router = useRouter()
const { loading, error, run, cancel } = useReadScope()
const items = ref<V3Node[]>([]), detail = ref<V3ServerDetail | null>(null), q = ref(''), next = ref(''), feedback = ref('')
const dialog = ref(false), saving = ref(false), saveError = ref(''), editVersion = ref(0)
const blank = (): V3NodeInput => ({ id: '', name: '', endpoint: '', server_name: '', enabled: true, mode: 'docker' })
const form = reactive(blank())
const flow = ref<InstanceType<typeof DeploymentFlow>>(), flowBusy = ref(false), progress = ref(''), progressError = ref(false), upgradeOnly = ref(false), appliedVersion = ref(0)
const busy = computed(() => saving.value || flowBusy.value)
const admin = computed(() => session.value?.role === 'admin')
const pagination = useCursorPage(), { cursor, limit } = pagination
const filterStatus = ref('')
const nodeOptions = ref<V3Node[]>([]), optionRead = useReadScope()
function findNodes(keyword = '') { void optionRead.run(signal => client.servers(keyword, '', 20, signal), value => {nodeOptions.value=value.items}) }
function changeNode(id: string) { void router.push({path:`/servers/${encodeURIComponent(id)}`,query:{...route.query}}) }
const center = ref<V3Dashboard>(), trend = useReadScope(), points = ref<MetricPoint[]>([]), resolution = ref(30)
const hours = ref(1), customStart = ref(''), customEnd = ref('')
const centerView = computed(() => selected.value === 'central' && route.query.tab === 'system')
const tab = computed(() => route.query.tab === 'health' ? 'health' : route.query.tab === 'system' ? 'system' : 'resources')
const specs = computed(() => tab.value === 'health' ? healthCharts : resourceCharts)
const snapshot = computed(() => Object.fromEntries(Object.entries(detail.value?.status?.metrics || {}).filter((entry): entry is [string, number] => typeof entry[1] === 'number' && Number.isFinite(entry[1]))))
const stateLabels: Record<string, string> = { normal: '正常', unreachable: '采集异常', stale: '数据过期', unknown: '未知', disabled: '已停用' }
let timer: ReturnType<typeof setTimeout> | undefined
const selected = computed(() => typeof route.params.id === 'string' ? route.params.id : '')
let disposed = false, dialogGeneration = 0, intent: { body: string; key: string } | undefined
function load() {
  clearTimeout(timer)
  if (disposed || document.hidden || loading.value) return
  if (centerView.value) void run(signal => client.dashboard(signal), value => { center.value = value })
  else if (selected.value) void run(signal => client.server(selected.value, signal), value => { detail.value = value })
  else void run(signal => client.servers(String(route.query.q || ''), cursor.value, limit.value, signal, String(route.query.status || '')), value => {
    items.value = value.items; next.value = value.next_cursor
    if (!value.items.length && cursor.value) void pagination.previous()
  })
  timer = setTimeout(refresh, 30_000)
}
async function loadTrend() {
  if (!selected.value || centerView.value || document.hidden) return
  let start: Date, end = new Date()
  if (hours.value === 0) {
    start = new Date(customStart.value + '+08:00'); end = new Date(customEnd.value + '+08:00')
  } else start = new Date(end.getTime() - hours.value * 3600_000)
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end <= start || end.getTime()-start.getTime()>31*86400_000) { trend.cancel(); trend.error.value = '请选择有效的起止时间，范围不能超过 31 天'; return }
  await trend.run(signal => client.serverMetrics(selected.value, start.toISOString(), end.toISOString(), signal), value => { points.value = value.points; resolution.value = value.resolution_seconds })
}
function refresh() { load(); if (!trend.loading.value) void loadTrend() }
async function search() { const before = route.fullPath; await router.push({ path: '/servers', query: Object.fromEntries(queryParams({ q: q.value.trim(), status: filterStatus.value, limit: limit.value === 20 ? undefined : limit.value })) }); if (before === route.fullPath) load() }
function detailLink(id: string) { return { path: `/servers/${encodeURIComponent(id)}`, query: { return_q: String(route.query.q || ''), return_status: String(route.query.status || ''), return_cursor: cursor.value, return_limit: String(limit.value) } } }
const returnLink = computed(() => ({ path: '/servers', query: { q: route.query.return_q || undefined, status: route.query.return_status || undefined, cursor: route.query.return_cursor || undefined, limit: route.query.return_limit || undefined } }))
function setTab(value: string) { void router.replace({ path: route.path, query: { ...route.query, tab: value } }) }
function setRange() {
  if (hours.value === 0 && !customStart.value) { const local = (d: Date) => new Date(d.getTime()+8*3600_000).toISOString().slice(0,16); customEnd.value = local(new Date()); customStart.value = local(new Date(Date.now()-3600_000)) }
  void router.replace({ path: route.path, query: { ...route.query, hours: String(hours.value), start: hours.value === 0 ? customStart.value : undefined, end: hours.value === 0 ? customEnd.value : undefined } })
}
function visibility() { if (document.hidden) { clearTimeout(timer); cancel(); trend.cancel() } else refresh() }

function open(node?: V3Node) {
  dialogGeneration++; intent = undefined; saving.value = false; flowBusy.value = false; progress.value = ''; progressError.value = false; upgradeOnly.value = false; appliedVersion.value = node?.applied_version || 0; saveError.value = ''; editVersion.value = node?.version || 0
  Object.assign(form, node ? { id: node.id, name: node.name, endpoint: node.endpoint, server_name: node.server_name, enabled: node.enabled, mode: node.mode } : blank()); dialog.value = true
}
function closed() { if (dialog.value) return; dialogGeneration++; saveError.value = ''; progress.value = ''; flowBusy.value = false; saving.value = false }
function flowStatus(text: string, failed: boolean) { progress.value = text; progressError.value = failed }
function jobCreated(id: string) { dialog.value = false; void router.push(`/deployments/${encodeURIComponent(id)}`) }
async function upgrade() { upgradeOnly.value = true; saveError.value = ''; await nextTick(); await flow.value?.begin() }
async function save(deploy = false) {
  if (busy.value || !admin.value) return
  const node = { ...form, id: form.id.trim(), name: form.name.trim(), endpoint: form.endpoint.trim(), server_name: form.server_name.trim() }
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(node.id) || !node.name || !node.endpoint || !node.server_name) { saveError.value = '请填写有效的节点 ID、名称、指标地址和 TLS 名称'; return }
  const body = JSON.stringify({ node, expected: editVersion.value })
  if (intent?.body !== body) intent = { body, key: crypto.randomUUID() }
  const current = dialogGeneration
  saving.value = true; saveError.value = ''
  try {
    const response = await client.saveServer(node, editVersion.value, intent.key)
    if (disposed || current !== dialogGeneration) return
    feedback.value = '配置已保存，尚未部署'; editVersion.value = response.version; load()
    if (deploy) { upgradeOnly.value = false; await nextTick(); await flow.value?.begin() } else dialog.value = false
  } catch (e) { if (!disposed && current === dialogGeneration) saveError.value = e instanceof Error ? e.message : '保存失败' }
  finally { if (!disposed && current === dialogGeneration) saving.value = false }
}
const percent = (value?: number | null) => value === null || value === undefined ? '—' : `${value.toFixed(1)}%`
const runtimeMonitoring = (n: V3Node) => n.configuration?.runtime_enabled === null ? '尚未登记' : n.configuration?.runtime_enabled === true ? '已启用' : n.configuration?.runtime_enabled === false ? '已停用' : '未知'
const pending = (n: V3Node) => n.applied_version === 0 ? '尚未部署' : n.version !== n.applied_version ? '待应用' : '已应用'
watch(() => route.fullPath, (_next, before) => { cancel(); trend.cancel(); q.value = String(route.query.q || ''); filterStatus.value = String(route.query.status || ''); hours.value = [0,1,6,24,168].includes(Number(route.query.hours)) ? Number(route.query.hours) : 1; customStart.value = String(route.query.start || ''); customEnd.value = String(route.query.end || ''); if (before?.split('?')[0] !== route.path) { detail.value = null; points.value = []; trend.cancel() }; refresh() }, { immediate: true })
onMounted(() => document.addEventListener('visibilitychange', visibility))
onUnmounted(() => { disposed = true; dialogGeneration++; clearTimeout(timer); document.removeEventListener('visibilitychange', visibility) })
</script>

<template>
  <section>
    <PageHeading :title="centerView ? '中心健康' : selected ? '服务器详情' : '服务器管理'" :back="selected ? returnLink : undefined" back-label="返回服务器列表"><el-button v-if="admin && selected && !centerView" :disabled="!detail" type="primary" @click="open(detail?.node)">编辑配置</el-button></PageHeading>
    <el-alert v-if="feedback" :title="feedback" type="success" :closable="false" /><el-alert v-if="error" :title="error" type="error" :closable="false" />
    <template v-if="!selected">
      <DeploymentRequirements />
      <el-card shadow="never"><form class="filters v3-filters" @submit.prevent="search"><el-input v-model="q" placeholder="搜索名称、IP、节点 ID" clearable aria-label="服务器名称或 ID" @clear="search" /><el-select v-model="filterStatus" placeholder="全部状态" clearable :value-on-clear="''" aria-label="采集状态筛选" @change="search"><el-option v-for="(label, key) in stateLabels" :key="key" :label="label" :value="key" /></el-select><el-button v-if="admin" type="primary" @click="open()">添加子服务器</el-button><el-button :loading="loading" @click="refresh">刷新</el-button><el-button native-type="submit">查询</el-button><router-link to="/servers/central?tab=system">中心健康 →</router-link></form>
      <el-button v-if="admin" type="danger" disabled title="当前 v3 尚未开放网页卸载接口">卸载并移除已选（0）</el-button>
      <el-table :data="items" :empty-text="loading ? '正在读取服务器…' : '没有匹配的服务器'" row-key="id" :aria-busy="loading"><el-table-column v-if="admin" type="selection" :selectable="() => false" width="48" /><el-table-column label="服务器" min-width="180"><template #default="{ row }"><router-link :to="detailLink(row.id)">{{ row.name }}</router-link><small class="muted v3-block">{{ row.endpoint }} · {{ row.id }}</small></template></el-table-column><el-table-column label="采集状态" min-width="120"><template #default="{ row }"><el-tag :type="row.collection_state === 'normal' ? 'success' : row.collection_state === 'unreachable' ? 'danger' : 'info'">{{ stateLabels[row.collection_state || 'unknown'] }}</el-tag><small class="muted v3-block">{{ runtimeMonitoring(row) }} · 保存：{{ row.enabled ? '启用' : '停用' }}</small></template></el-table-column><el-table-column v-for="[key,label] in [['cpu_percent','CPU'],['memory_percent','内存'],['disk_percent','最满磁盘']]" :key="key" :label="label" min-width="110"><template #default="{ row }">{{ row.collection_state === 'normal' ? percent(row.status?.metrics[key!]) : '未知' }}</template></el-table-column><el-table-column label="部署方式 / 版本" min-width="210"><template #default="{ row }">{{ row.status?.info.agent_mode === 'docker' ? 'Docker 容器' : row.status?.info.agent_mode === 'native' ? '直接运行 Go' : '尚未确认' }} · {{ row.status?.info.agent_version || '未知' }}<small class="muted v3-block">配置：{{ row.mode === 'docker' ? 'Docker 容器' : '直接运行 Go' }}</small></template></el-table-column><el-table-column label="配置状态" min-width="160"><template #default="{ row }"><el-tag :type="row.applied_version > 0 && row.version === row.applied_version ? 'success' : 'warning'">{{ pending(row) }}</el-tag><small class="muted v3-block">保存 {{ row.version }} / 下发 {{ row.configuration?.delivered_version || '—' }} / 生效 {{ row.applied_version || '—' }}</small></template></el-table-column><el-table-column label="最近采集" min-width="190"><template #default="{ row }">{{ timeText(row.status?.sampled_at) }}</template></el-table-column><el-table-column label="操作" min-width="200"><template #default="{ row }"><el-button link type="primary" @click="router.push(detailLink(row.id))">详情</el-button><el-button v-if="admin" link type="primary" @click="open(row)">编辑配置</el-button><el-button v-if="admin" link type="danger" disabled title="当前 v3 尚未开放网页卸载接口">卸载并移除</el-button></template></el-table-column></el-table>
      <CursorPagination :previous="!!cursor" :next="!!next" :limit="limit" :loading="loading" @previous="pagination.previous" @next="pagination.go(next)" @resize="pagination.resize" /></el-card>
    </template>
    <template v-else-if="centerView">
      <el-card shadow="never"><div class="card-heading"><h3>监控中心健康</h3><el-button :loading="loading" @click="load">刷新</el-button></div><div class="detail-grid"><div><span>当前版本</span><strong>{{ center?.version || '未知' }}</strong></div><div><span>采集方式</span><strong>主控主动采集</strong></div><div><span>业务数据库</span><strong>PostgreSQL</strong></div><div><span>指标存储</span><strong>VictoriaMetrics</strong></div><div><span>宿主管理服务</span><strong>{{ center?.summary.sections?.services?.data?.roles.executor?.healthy === true ? '正常' : center?.summary.sections?.services?.data?.roles.executor?.healthy === false ? '异常' : '未知' }}</strong></div><div><span>最近更新</span><strong>{{ timeText(center?.updated_at) }}</strong></div></div><p class="muted">{{ center?.stale ? '汇总已过期，请刷新检查。' : '组件状态以实际采集证据为准。' }}</p></el-card>
    </template>
    <template v-else-if="detail">
      <el-card shadow="never"><div class="filters"><el-select :model-value="selected" filterable remote :remote-method="findNodes" :loading="optionRead.loading.value" aria-label="选择服务器" @visible-change="$event && findNodes()" @change="changeNode"><el-option v-if="!nodeOptions.some(n => n.id === selected)" :value="selected" :label="detail.node.name" /><el-option v-for="node in nodeOptions" :key="node.id" :value="node.id" :label="`${node.name} · ${node.endpoint}`" /></el-select><el-select v-model="hours" aria-label="资源时间范围" @change="setRange"><el-option v-for="[value,label] in [[1,'最近 1 小时'],[6,'最近 6 小时'],[24,'最近 24 小时'],[168,'最近 7 天']]" :key="value" :value="value" :label="String(label)" /><el-option :value="0" label="自定义时间范围" /></el-select><template v-if="hours === 0"><label>起始（北京时间）<input v-model="customStart" type="datetime-local" @change="setRange" /></label><label>结束（北京时间）<input v-model="customEnd" type="datetime-local" @change="setRange" /></label></template><el-select v-if="tab === 'resources'" disabled placeholder="全部磁盘汇总" aria-label="磁盘历史维度" title="v3 当前只提供聚合历史，分设备历史尚未提供" /><el-select v-if="tab === 'resources'" disabled placeholder="物理网卡汇总" aria-label="网卡历史维度" title="v3 当前只提供聚合历史，分设备历史尚未提供" /><el-button :loading="loading || trend.loading.value" @click="refresh">刷新</el-button></div>
        <p class="muted">最近采集：{{ timeText(detail.status?.sampled_at) }} · 曲线精度 {{ resolution }} 秒；缺失数据留空。</p><el-alert v-if="detail.status?.error" :title="detail.status.error" type="warning" :closable="false" /><p class="muted">实际部署：{{ detail.status?.info.agent_mode === 'docker' ? 'Docker 容器' : detail.status?.info.agent_mode === 'native' ? '直接运行 Go' : '未知' }} · 配置方式：{{ detail.node.mode === 'docker' ? 'Docker 容器' : '直接运行 Go' }} · 版本：{{ detail.status?.info.agent_version || '未知' }}</p><p class="muted">主机：{{ detail.status?.info.hostname || '未知' }} · 系统：{{ detail.status?.info.kernel || '未知' }} · 架构：{{ detail.status?.info.architecture || '未知' }}</p>
        <div class="detail-grid"><div v-for="[key,label,unit] in [['cpu_cores','CPU 核数',''],['uptime','运行时间','s'],['memory_total','总内存','B'],['webscan_watches','监听目录数','']]" :key="key"><span>{{ label }}</span><strong>{{ metricValue(snapshot[key!], unit) }}</strong></div></div>
        <div class="filters"><el-button :type="tab === 'resources' ? 'primary' : ''" @click="setTab('resources')">资源指标</el-button><el-button :type="tab === 'health' ? 'primary' : ''" @click="setTab('health')">事件投递</el-button><router-link :to="`/alerts?node=${encodeURIComponent(selected)}`">相关告警 →</router-link></div>
      </el-card>
      <el-alert v-if="trend.error.value" :title="`${trend.error.value}；尚未取得所选时间范围；下方保留上次曲线。`" type="error" :closable="false" />
      <div class="chart-grid"><MetricChart v-for="spec in specs" :key="spec.title" :title="spec.title" :option="trendOption(points, spec, '', snapshot)" /></div>
      <el-card v-if="tab === 'health'" shadow="never"><h3>事件采集与监控链路指标</h3><el-table :data="Object.entries(snapshot).filter(([key]) => key.startsWith('webscan_')).map(([key,value]) => ({ key: metricLabel(key), value }))" empty-text="尚未取得链路指标"><el-table-column prop="key" label="指标" min-width="220" /><el-table-column prop="value" label="最近数值" /></el-table><p class="muted">主控主动读取事件，子控保留未确认队列；缺失指标表示尚未取得数据。</p></el-card>
      <el-card shadow="never"><h3>配置与采集</h3><div class="detail-grid"><div><span>节点 ID</span><strong>{{ detail.node.id }}</strong></div><div><span>指标地址</span><strong>{{ detail.node.endpoint }}</strong></div><div><span>TLS 名称</span><strong>{{ detail.node.server_name }}</strong></div><div><span>配置状态</span><strong>{{ pending(detail.node) }}（保存 {{ detail.node.version }} / 下发 {{ detail.node.configuration?.delivered_version || '—' }} / 生效 {{ detail.node.applied_version || '—' }}）</strong></div><div><span>运行登记</span><strong>{{ runtimeMonitoring(detail.node) }}</strong></div><div><span>采集结果</span><strong>{{ detail.node.configuration?.runtime_enabled === false ? '已停用' : detail.node.configuration?.runtime_enabled === null ? '尚未登记，待部署' : detail.status?.error || (detail.status?.sampled_at ? '最近一次采集成功' : '未知，尚无采集证据') }}</strong></div></div></el-card>
      <el-card shadow="never"><div class="card-heading"><h3>最近部署</h3><router-link v-if="detail.latest_deployment" :to="`/deployments/${detail.latest_deployment.id}`">查看任务与日志 →</router-link></div><template v-if="detail.latest_deployment"><el-tag>{{ jobLabel(detail.latest_deployment.status) }}</el-tag><p>{{ timeText(detail.latest_deployment.updated_at) }}</p></template><el-empty v-else description="暂无部署任务" /></el-card>
    </template>
    <el-dialog v-model="dialog" :title="editVersion ? '编辑子服务器' : '添加子服务器'" class="v3-node-dialog" width="720px" :show-close="!busy" :close-on-click-modal="!busy" :close-on-press-escape="!busy" @closed="closed">
      <DeploymentRequirements compact :mode="form.mode" /><el-alert title="仅保存不改变当前采集或告警；保存并部署完成准备后需要确认预览。" type="info" :closable="false" /><el-form label-position="top" @submit.prevent="save(false)"><h3>基本信息</h3><div class="form-grid v3-form-grid"><el-form-item label="节点 ID"><el-input v-model="form.id" :disabled="editVersion > 0" maxlength="128" /></el-form-item><el-form-item label="服务器名称"><el-input v-model="form.name" maxlength="256" /></el-form-item><el-form-item label="指标地址（主机:端口）"><el-input v-model="form.endpoint" placeholder="192.0.2.10:19100" /></el-form-item><el-form-item label="TLS 证书名称"><el-input v-model="form.server_name" placeholder="与节点证书名称一致" /></el-form-item></div><h3>部署方式</h3><div class="form-grid v3-form-grid"><el-form-item label="部署方式"><el-select v-model="form.mode"><el-option label="直接运行 Go" value="native" /><el-option label="Docker 单容器" value="docker" /></el-select></el-form-item><el-form-item label="启用监控"><el-switch v-model="form.enabled" /></el-form-item></div></el-form>
      <DeploymentFlow v-if="dialog" ref="flow" :node="{ id: form.id, version: editVersion, applied_version: appliedVersion, mode: form.mode }" :upgrade="upgradeOnly" @status="flowStatus" @busy="flowBusy = $event" @job="jobCreated" /><h3>文件监控</h3><p class="muted">沿用主控已保存的节点监控配置。目录、规则和扫描服务随受控配置包下发；本弹窗暂不提供规则编辑。</p>
      <template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="saveError || progressError" :title="saveError || progress" type="error" :closable="false" /><span v-else>{{ saving ? '正在校验并保存配置…' : progress || '仅保存不会安装或升级服务。' }}</span></div><div class="v3-actions"><el-button :disabled="busy" @click="dialog = false">取消</el-button><el-button v-if="editVersion && appliedVersion && form.enabled" :disabled="busy" @click="upgrade">升级子服务器</el-button><el-button :loading="saving" :disabled="flowBusy" @click="save(false)">仅保存</el-button><el-button type="primary" :loading="busy" @click="save(true)">保存并部署</el-button></div></template>
    </el-dialog>
  </section>
</template>
