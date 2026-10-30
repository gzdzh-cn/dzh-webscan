<script setup lang="ts">
import { nextTick, computed, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { queryParams } from '../api'
import type { V3Node, V3NodeInput, V3ServerDetail } from '../controlV3'
import { jobLabel, timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import DeploymentFlow from './DeploymentFlow.vue'

const { client, session } = useConsole(), route = useRoute(), router = useRouter()
const { loading, error, run } = useReadScope()
const items = ref<V3Node[]>([]), detail = ref<V3ServerDetail | null>(null), q = ref(''), next = ref(''), feedback = ref('')
const dialog = ref(false), saving = ref(false), saveError = ref(''), editVersion = ref(0)
const blank = (): V3NodeInput => ({ id: '', name: '', endpoint: '', server_name: '', enabled: true, mode: 'docker' })
const form = reactive(blank())
const flow = ref<InstanceType<typeof DeploymentFlow>>(), flowBusy = ref(false), progress = ref(''), progressError = ref(false), upgradeOnly = ref(false), appliedVersion = ref(0)
const busy = computed(() => saving.value || flowBusy.value)
const admin = computed(() => session.value?.role === 'admin')
const cursor = computed(() => typeof route.query.cursor === 'string' ? route.query.cursor : '')
const selected = computed(() => typeof route.params.id === 'string' ? route.params.id : '')
let disposed = false, dialogGeneration = 0, intent: { body: string; key: string } | undefined
function load() {
  if (selected.value) void run(signal => client.server(selected.value, signal), value => { detail.value = value })
  else void run(signal => client.servers(String(route.query.q || ''), cursor.value, 20, signal), value => { items.value = value.items; next.value = value.next_cursor })
}
async function search() { const before = route.fullPath; await router.push({ path: '/servers', query: Object.fromEntries(queryParams({ q: q.value.trim() })) }); if (before === route.fullPath) load() }
function page(value: string) { void router.push({ path: '/servers', query: Object.fromEntries(queryParams({ q: String(route.query.q || ''), cursor: value })) }) }
function open(node?: V3Node) {
  dialogGeneration++; intent = undefined; saving.value = false; flowBusy.value = false; progress.value = ''; progressError.value = false; upgradeOnly.value = false; appliedVersion.value = node?.applied_version || 0; saveError.value = ''; editVersion.value = node?.version || 0
  Object.assign(form, node ? { id: node.id, name: node.name, endpoint: node.endpoint, server_name: node.server_name, enabled: node.enabled, mode: node.mode } : blank()); dialog.value = true
}
function closed() { dialogGeneration++; saveError.value = ''; progress.value = ''; flowBusy.value = false; saving.value = false }
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
watch(() => route.fullPath, () => { q.value = String(route.query.q || ''); load() }, { immediate: true })
onUnmounted(() => { disposed = true; dialogGeneration++ })
</script>

<template>
  <section>
    <div class="v3-page-heading"><div><router-link v-if="selected" :to="{ path: '/servers', query: { q: route.query.q } }" class="v3-back"><el-button>返回服务器列表</el-button></router-link><h1>{{ selected ? detail?.node.name || '服务器详情' : '服务器管理' }}</h1><p class="v3-muted">{{ selected ? '查看采集状态、配置版本与最近部署任务。' : '按名称或 ID 查询；列表由服务端分页加载。' }}</p></div><div class="v3-actions"><el-button :loading="loading" @click="load">刷新</el-button><el-button v-if="admin" :disabled="Boolean(selected && !detail)" type="primary" @click="open(selected ? detail?.node : undefined)">{{ selected ? '编辑配置' : '添加服务器' }}</el-button></div></div>
    <el-alert v-if="feedback" :title="feedback" type="success" :closable="false" /><el-alert v-if="error" :title="error" type="error" :closable="false" />
    <template v-if="!selected">
      <el-card shadow="never"><form class="v3-filters" @submit.prevent="search"><el-input v-model="q" placeholder="服务器名称或 ID" clearable aria-label="服务器名称或 ID" /><el-button type="primary" native-type="submit">查询</el-button><el-button @click="q = ''; search()">重置</el-button></form><el-table :data="items" :empty-text="loading ? '正在读取服务器…' : '没有匹配的服务器'" row-key="id" :aria-busy="loading"><el-table-column label="服务器" min-width="190"><template #default="{ row }"><router-link :to="{ path: `/servers/${encodeURIComponent(row.id)}`, query: { q: route.query.q } }">{{ row.name }}</router-link><small class="v3-block v3-muted">{{ row.id }}</small></template></el-table-column><el-table-column prop="endpoint" label="采集地址" min-width="180" /><el-table-column label="配置方式" width="140"><template #default="{ row }">{{ row.mode === 'native' ? '直接运行 Go' : 'Docker' }}</template></el-table-column><el-table-column label="配置状态" min-width="160"><template #default="{ row }"><el-tag :type="row.version === row.applied_version ? 'success' : 'warning'">{{ pending(row) }}</el-tag><small class="v3-block v3-muted">保存 {{ row.version }} / 下发 {{ row.configuration?.delivered_version || '—' }} / 生效 {{ row.applied_version || '—' }}</small></template></el-table-column><el-table-column label="运行监控" min-width="140"><template #default="{ row }">{{ runtimeMonitoring(row) }}<small class="v3-block v3-muted">保存：{{ row.enabled ? '启用' : '停用' }}</small></template></el-table-column><el-table-column v-if="admin" label="操作" width="100"><template #default="{ row }"><el-button text @click="open(row)">编辑</el-button></template></el-table-column></el-table><div class="v3-pagination"><el-button :disabled="!cursor || loading" @click="page('')">回到首页</el-button><span>每页最多 20 台</span><el-button :disabled="!next || loading" @click="page(next)">下一页</el-button></div></el-card>
    </template>
    <template v-else-if="detail">
      <div class="v3-stats"><el-card v-for="metric in (['cpu_percent', 'memory_percent', 'disk_percent'] as const)" :key="metric" shadow="never"><span class="v3-muted">{{ { cpu_percent: 'CPU 使用率', memory_percent: '内存使用率', disk_percent: '磁盘使用率' }[metric] }}</span><strong>{{ percent(detail.status?.metrics[metric]) }}</strong></el-card></div>
      <el-card shadow="never"><h2>配置与采集</h2><dl class="v3-detail-grid"><dt>节点 ID</dt><dd>{{ detail.node.id }}</dd><dt>指标地址</dt><dd>{{ detail.node.endpoint }}</dd><dt>TLS 名称</dt><dd>{{ detail.node.server_name }}</dd><dt>配置方式</dt><dd>{{ detail.node.mode === 'native' ? '直接运行 Go' : 'Docker' }}</dd><dt>实际运行方式</dt><dd>{{ detail.status?.info.agent_mode || '未知' }}</dd><dt>Agent 版本</dt><dd>{{ detail.status?.info.agent_version || '未知' }}</dd><dt>配置状态</dt><dd>{{ pending(detail.node) }}（保存 {{ detail.node.version }} / 下发 {{ detail.node.configuration?.delivered_version || '—' }} / 生效 {{ detail.node.applied_version || '—' }}）</dd><dt>运行登记</dt><dd>{{ runtimeMonitoring(detail.node) }}<template v-if="detail.node.configuration?.registered_version">（版本 {{ detail.node.configuration.registered_version }}，{{ detail.node.configuration.runtime_endpoint }}）</template></dd><dt>采样时间</dt><dd>{{ timeText(detail.status?.sampled_at) }}</dd><dt>采集结果</dt><dd>{{ detail.node.configuration?.runtime_enabled === false ? '已停用' : detail.node.configuration?.runtime_enabled === null ? '尚未登记，待部署' : detail.status?.error || (detail.status?.sampled_at ? '最近一次采集成功' : '未知，尚无采集证据') }}</dd></dl></el-card>
      <el-card shadow="never"><h2>最近部署</h2><template v-if="detail.latest_deployment"><el-tag>{{ jobLabel(detail.latest_deployment.status) }}</el-tag><p>{{ timeText(detail.latest_deployment.updated_at) }}</p><router-link :to="`/deployments/${detail.latest_deployment.id}`">查看任务与日志 →</router-link></template><el-empty v-else description="暂无部署任务" /></el-card>
    </template>
    <el-dialog v-model="dialog" :title="editVersion ? '编辑服务器配置' : '添加服务器配置'" class="v3-node-dialog" width="660px" :show-close="!busy" :close-on-click-modal="!busy" :close-on-press-escape="!busy" @closed="closed">
      <el-alert title="仅保存不改变当前采集或告警；保存并部署完成准备后需要确认预览。" type="info" :closable="false" /><el-form label-position="top" @submit.prevent="save(false)"><div class="v3-form-grid"><el-form-item label="节点 ID"><el-input v-model="form.id" :disabled="editVersion > 0" maxlength="128" /></el-form-item><el-form-item label="服务器名称"><el-input v-model="form.name" maxlength="256" /></el-form-item><el-form-item label="指标地址（主机:端口）"><el-input v-model="form.endpoint" placeholder="192.0.2.10:19100" /></el-form-item><el-form-item label="TLS 证书名称"><el-input v-model="form.server_name" placeholder="与节点证书名称一致" /></el-form-item><el-form-item label="部署方式"><el-select v-model="form.mode"><el-option label="直接运行 Go" value="native" /><el-option label="Docker 单容器" value="docker" /></el-select></el-form-item><el-form-item label="启用监控"><el-switch v-model="form.enabled" /></el-form-item></div></el-form>
      <DeploymentFlow v-if="dialog" ref="flow" :node="{ id: form.id, version: editVersion, applied_version: appliedVersion, mode: form.mode }" :upgrade="upgradeOnly" @status="flowStatus" @busy="flowBusy = $event" @job="jobCreated" />
      <template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="saveError || progressError" :title="saveError || progress" type="error" :closable="false" /><span v-else>{{ saving ? '正在校验并保存配置…' : progress || '仅保存不会安装或升级服务。' }}</span></div><div class="v3-actions"><el-button :disabled="busy" @click="dialog = false">取消</el-button><el-button v-if="editVersion && appliedVersion && form.enabled" :disabled="busy" @click="upgrade">升级子服务器</el-button><el-button :loading="saving" :disabled="flowBusy" @click="save(false)">仅保存</el-button><el-button type="primary" :loading="busy" @click="save(true)">保存并部署</el-button></div></template>
    </el-dialog>
  </section>
</template>
