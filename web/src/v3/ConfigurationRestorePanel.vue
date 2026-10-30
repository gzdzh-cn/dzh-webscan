<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { V3Error, type V3ConfigurationRestoreStage, type V3ConfigurationRestorePreview, type V3ConfigurationRestoreDetail, type V3ConfigurationLocalReport } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
const router = useRouter()
const emit = defineEmits<{ changed: [] }>()
const { client, session } = useConsole(), read = useReadScope(), detailRead = useReadScope()
const secure = window.location.protocol === 'https:', admin = computed(() => session.value?.role === 'admin')
const rows = ref<V3ConfigurationRestoreStage[]>([]), cursor = ref(''), next = ref(''), previous = new Map<string, string>()
const open = ref(false), backup = ref(''), currentID = ref(''), preview = ref<V3ConfigurationRestorePreview>(), detail = ref<V3ConfigurationRestoreDetail>(), report = ref<V3ConfigurationLocalReport>()
const useCredentials = ref(false), confirmed = ref(false), busy = ref(false), error = ref(''), message = ref(''), expired = ref(false), applyConfirmed = ref(false)
const summary = computed(() => detail.value?.summary || preview.value?.summary)
const visibleChanges = computed(() => summary.value?.nodes.slice(0, 100) || [])
let alive = true, generation = 0, controller = new AbortController(), timer: ReturnType<typeof setTimeout> | undefined
const keys = new Map<string, string>()
function status(stage: V3ConfigurationRestoreStage) {
  const job = stage.application
  if (stage.status === 'saved' && job) {
    if (job.recovery_hold) return '应用已冻结'
    if ((job.status === 'queued' || job.status === 'running') && job.direction === 'rollback') return '回退中'
    return ({ queued: '等待应用', running: '应用中', failed: '应用未完成', succeeded: '本次应用完成', rolled_back: '已回退', cancelled: '应用已取消' } as Record<string, string>)[job.status] || '应用状态未知'
  }
  return ({ pending_validation: '待本机检查', pending_application: '候选已准备', saved: '已保存，待应用', cancelled: '已取消' } as Record<string, string>)[stage.status] || '未知'
}
const phaseText = (value: string) => ({ environment: '环境检查', nodes: '节点应用', bootstrap: '中心启动交接', settings: '运行设置', verify: '生效验收', finalize: '完成确认', 'restore-settings': '恢复设置', 'restore-bootstrap': '恢复中心启动', 'restore-nodes': '恢复节点', 'verify-rollback': '回退验收', complete: '已结束' } as Record<string, string>)[value] || '未知阶段'
const labels: Record<string, string> = { retention: '历史期限', backup: '备份策略', monitoring: '监控规则', website_monitor: '网站检测', email: '邮箱通道', feishu: '飞书通道', other: '其他设置', topology_migration_required: '需要专用拓扑迁移', node_mode_migration_required: '需要专用部署方式迁移', node_uninstall_required: '需先卸载并移除节点', configuration_incomplete: '配置或凭据需补全', add: '新增', update: '修改', remove: '移除', configuration: '配置', name: '名称', endpoint: '连接地址', server_name: '证书身份', enabled: '启用状态', mode: '运行方式', rules: '规则', requires_uninstall: '需要卸载' }
const text = (value: string) => labels[value] || '未知项'
const checkLabels: Record<string, string> = {
 database_credentials: '数据库凭据', central_tls: '后台证书', collector_tls: '采集证书', collector_revocation: '证书吊销配置', collector_revocation_floor: '吊销记录下限',
 exports_directory: '导出目录', metrics_spool_directory: '指标缓冲目录', deployment_trust: '部署信任资料', vault_continuity: '历史密钥连续性', executor_directory: '执行器目录', node_issuer: '节点签发资料', ha_ssh_keys: '高可用 SSH 私钥',
 passed: '通过', failed: '失败', not_configured: '未配置', local_material_verified: '本机资料检查通过', private_dsn_file_unavailable: '数据库凭据文件不可用', https_proxy_not_checked: '反向代理需在实际应用时检查',
 server_certificate_key_or_hostname_invalid: '后台证书、私钥或主机名无效', collector_identity_trust_or_revocation_invalid: '采集身份、信任或吊销资料无效', revocation_not_configured: '未配置吊销检查', persistent_floor_not_configured: '未配置持久化下限', persistent_floor_missing_or_rollback_detected: '持久化下限缺失或检测到回退',
 private_directory_or_reserve_unavailable: '受保护目录、权限或预留空间不足', spool_not_configured: '未配置指标缓冲', vault_release_signature_or_artifacts_invalid: '密钥、发布签名或工具资料无效', current_decryption_keys_not_retained: '缺少当前存档解密所需密钥', deployment_trust_not_configured: '未配置部署信任', executor_disabled: '执行器未启用', issuer_key_or_collector_trust_mismatch: '签发密钥或采集信任不匹配', online_issuer_disabled: '在线签发未启用', ha_private_key_unavailable: '高可用私钥不可用',
}
const checkText = (value: string) => checkLabels[value] || '未知检查项'

async function load() {
  if (!admin.value) return
  await read.run(signal => client.configurationRestores(cursor.value, 20, signal), value => { rows.value = value.items; next.value = value.next_cursor })
}
async function page(forward: boolean) {
  const target = forward ? next.value : previous.get(cursor.value) || ''
  if (forward) previous.set(target, cursor.value)
  cursor.value = target; await load()
}
function reset() {
  generation++; controller.abort(); controller = new AbortController(); detailRead.cancel(); clearTimeout(timer)
  preview.value = undefined; detail.value = undefined; report.value = undefined; confirmed.value = false; applyConfirmed.value = false; expired.value = false
  error.value = ''; message.value = ''; keys.clear(); busy.value = false
}
function start(id: string) {
  if (busy.value || !secure) return
  reset(); backup.value = id; currentID.value = ''; useCredentials.value = false; open.value = true
}
function close() { if (busy.value) return; open.value = false; reset() }
async function inspect(id: string) {
  if (busy.value) return
  reset(); backup.value = ''; currentID.value = id; open.value = true; await reloadDetail()
}
async function reloadDetail() {
  if (!currentID.value) return
  await detailRead.run(signal => client.configurationRestore(currentID.value, signal), value => { detail.value = value; applyConfirmed.value = false })
}
watch(useCredentials, () => { if (!currentID.value) { preview.value = undefined; confirmed.value = false; keys.clear(); clearTimeout(timer) } })
async function run(action: string, fn: (key: string, signal: AbortSignal) => Promise<void>) {
  if (busy.value || !alive || !secure) return
  busy.value = true; error.value = ''; message.value = ''; const current = generation
  const key = keys.get(action) || crypto.randomUUID(); keys.set(action, key)
  try { await fn(key, controller.signal); if (alive && current === generation) keys.delete(action) }
  catch (e) {
    if (!alive || current !== generation) return
    error.value = e instanceof Error ? e.message : '操作失败，请重试'
    // Ambiguous transport failures retain the same key. Explicit conflicts
    // require inspection/re-preview, never a silent replacement confirmation.
    if (e instanceof V3Error && e.status === 409) { confirmed.value = false; applyConfirmed.value = false; if (!currentID.value) { preview.value = undefined; keys.clear() } }
  } finally { if (alive && current === generation) busy.value = false }
}
async function previewRestore() {
  await run('preview', async (_, signal) => {
    const value = await client.previewConfigurationRestore(backup.value, useCredentials.value, signal)
    if (!alive || signal.aborted) return
    preview.value = value; confirmed.value = false
    const remaining = Date.parse(value.expires_at) - Date.now(); expired.value = remaining <= 0; clearTimeout(timer)
    if (remaining > 0) timer = setTimeout(() => { expired.value = true }, remaining)
  })
}
async function stage() {
  if (!preview.value || !confirmed.value || expired.value || !preview.value.summary.can_prepare) return
  await run('stage', async (key, signal) => {
    const value = await client.stageConfigurationRestore(preview.value!.token, key, signal)
    if (!alive || signal.aborted) return
    currentID.value = value.id; preview.value = undefined; confirmed.value = false; clearTimeout(timer); message.value = value.message
    await Promise.all([reloadDetail(), load()]); emit('changed')
  })
}
async function check() {
  if (!detail.value?.can_continue) return
  await run('check', async (key, signal) => { const value = await client.checkConfigurationRestore(currentID.value, key, signal); if (alive && !signal.aborted) report.value = value })
}
async function prepare() {
  if (!detail.value?.can_continue) return
  await run('prepare', async (key, signal) => {
    await client.prepareConfigurationRestore(currentID.value, key, signal)
    if (!alive || signal.aborted) return
    confirmed.value = false; report.value = undefined; message.value = '候选已准备，请确认后提交到保存配置。'; await Promise.all([reloadDetail(), load()])
  })
}
async function commit() {
  if (!confirmed.value || !detail.value?.can_continue || !detail.value.revision) return
  await run('commit', async (key, signal) => {
    const value = await client.commitConfigurationRestore(currentID.value, detail.value!.revision!.generation, key, signal)
    if (!alive || signal.aborted) return
    confirmed.value = false; message.value = value.message; await Promise.all([reloadDetail(), load()]); emit('changed')
  })
}
async function applySaved() {
  if (!applyConfirmed.value || !detail.value?.can_apply || !detail.value.revision || detailRead.error.value || detailRead.loading.value) return
  const stageID = currentID.value, candidate = detail.value.revision.generation
  await run('apply', async (key, signal) => {
    const task = await client.queueConfigurationApplication(stageID, candidate, key, signal)
    if (!alive || signal.aborted) return
    message.value = '应用任务已创建，正在打开进度日志'; applyConfirmed.value = false
    await router.push(`/configuration-applications/${encodeURIComponent(task.id)}`)
  })
}
async function cancel() {
  if (!confirmed.value || !detail.value?.can_cancel) return
  await run('cancel', async (key, signal) => {
    const value = await client.cancelConfigurationRestore(currentID.value, key, signal)
    if (!alive || signal.aborted) return
    confirmed.value = false; message.value = value.message; await Promise.all([reloadDetail(), load()]); emit('changed')
  })
}
watch([() => session.value?.username, admin], () => { open.value = false; reset(); read.cancel(); rows.value = []; if (admin.value) void load() })
void load()
defineExpose({ start })
onUnmounted(() => { alive = false; generation++; controller.abort(); clearTimeout(timer) })
</script>
<template>
  <section v-if="admin" aria-label="配置恢复记录">
    <h3>配置恢复记录</h3>
    <p class="v3-muted">可继续未完成的恢复。恢复仅提交到保存配置，不会自动部署或切换运行状态。</p>
    <el-alert v-if="read.error.value" :title="`${read.error.value}；已有记录保留`" type="error" :closable="false" />
    <el-button :loading="read.loading.value" :disabled="busy" @click="load">刷新恢复记录</el-button>
    <el-table :data="rows" row-key="id"><el-table-column label="创建时间" min-width="175"><template #default="{ row }">{{ timeText(row.created_at) }}</template></el-table-column><el-table-column prop="username" label="操作人" width="120" /><el-table-column label="状态" min-width="150"><template #default="{ row }">{{ status(row) }}</template></el-table-column><el-table-column label="操作" width="130"><template #default="{ row }"><el-button link type="primary" :disabled="busy" @click="inspect(row.id)">查看恢复</el-button></template></el-table-column></el-table>
    <div class="v3-pagination"><el-button :disabled="!cursor || busy || read.loading.value" @click="page(false)">上一页恢复</el-button><span>每页 20 条</span><el-button :disabled="!next || busy || read.loading.value" @click="page(true)">下一页恢复</el-button></div>
  </section>
  <el-dialog :model-value="open" title="恢复到保存配置" class="v3-node-dialog" width="860px" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @update:model-value="!$event && close()">
    <el-alert title="此流程不会切换运行配置；本机检查只读，不连接数据库、子服务器或通知渠道。实际应用仍需独立检查与部署。" type="warning" :closable="false" />
    <template v-if="!currentID"><el-checkbox class="v3-restore-checkbox" v-model="useCredentials" :disabled="busy">使用备份中的配置凭据（默认保留当前完整通知通道及凭据）</el-checkbox><p class="v3-muted">不包含外部私钥、PKI 和独立凭据文件；缺失资料需另行补全。</p><el-button :disabled="busy" @click="previewRestore">生成恢复预览</el-button></template>
    <template v-if="detail"><p>{{ status(detail.stage) }} · {{ detail.stage.message }}</p><p class="v3-muted">操作人 {{ detail.stage.username }} · 更新 {{ timeText(detail.stage.updated_at) }}</p><p v-if="detail.stage.application" role="status">应用阶段：{{ phaseText(detail.stage.application.phase) }} · 任务更新 {{ timeText(detail.stage.application.updated_at) }}。此处只读展示历史任务，不执行应用或回退。</p><p v-if="detail.stage.application"><a :href="`/configuration-applications/${encodeURIComponent(detail.stage.application.id)}`">查看应用进度与日志 →</a></p><p v-if="detail.can_cancel && !detail.can_continue">仅原操作账号且账号版本未变化时可继续；管理员可取消后重新预览。</p></template>
    <el-alert v-if="detailRead.error.value" :title="detail ? `${detailRead.error.value}；以上为上次读取结果，请刷新确认` : `${detailRead.error.value}；请重试读取恢复状态`" type="error" :closable="false" />
    <template v-if="summary">
      <p>新增 {{ summary.added }} · 修改 {{ summary.updated }} · 不变 {{ summary.unchanged }} · 移除 {{ summary.removed }}</p>
      <p>凭据保留 {{ summary.credentials_kept }} · 替换 {{ summary.credentials_replaced }} · 缺失 {{ summary.credentials_missing }}</p>
      <p>设置分区：{{ summary.sections.map(text).join('、') || '无变化' }}；启动配置{{ summary.bootstrap_changed ? '变化，实际应用需中心重启' : '无变化' }}。</p>
      <el-alert v-if="summary.blocked_reasons.length" :title="summary.blocked_reasons.map(text).join('；')" type="error" :closable="false" />
      <p v-if="summary.nodes.length > 100" class="v3-muted">共 {{ summary.nodes.length }} 个节点有变化，仅展示前 100 个；本次确认范围仍为预览中的全部节点。</p>
      <el-table :data="visibleChanges" row-key="node" max-height="280"><el-table-column prop="node" label="节点" min-width="180" /><el-table-column label="操作" width="100"><template #default="{ row }">{{ text(row.action) }}</template></el-table-column><el-table-column label="变化字段" min-width="200"><template #default="{ row }">{{ row.fields.map(text).join('、') }}</template></el-table-column></el-table>
      <p v-if="preview" class="v3-muted">预览有效至 {{ timeText(preview.expires_at) }}。配置或部署状态改变后需重新预览。</p>
    </template>
    <template v-if="report"><h4>本机资料检查</h4><p>{{ report.local_checks_passed ? '本次本机资料检查通过；提交时会再次检查' : '本机资料检查未通过，请补齐后重新检查' }}</p><ul><li v-for="item in report.checks" :key="item.component">{{ checkText(item.component) }} · {{ checkText(item.status) }} · {{ checkText(item.reason) }}</li></ul></template>
    <template #footer>
      <div class="v3-dialog-feedback" role="status"><el-alert v-if="error" :title="error" type="error" :closable="false" /><p v-if="message">{{ message }}</p><p v-if="expired">恢复预览已过期，请重新生成。</p><span v-if="busy">正在处理，请稍候…</span></div>
      <el-checkbox class="v3-restore-checkbox" v-if="preview || detail?.can_cancel" v-model="confirmed" :disabled="busy">我确认本次操作；恢复仅写入保存配置，取消不会撤销已生效配置</el-checkbox>
      <el-checkbox v-if="detail?.can_apply" v-model="applyConfirmed" class="v3-restore-checkbox" :disabled="busy || !secure || !!detailRead.error.value || detailRead.loading.value">我确认应用已保存的配置，允许执行检查、部署及生效验收</el-checkbox>
      <div class="v3-actions">
        <el-button v-if="detail?.can_apply" type="primary" :disabled="busy || !secure || !applyConfirmed || !!detailRead.error.value || detailRead.loading.value" @click="applySaved">应用已保存配置</el-button>
        <el-button :disabled="busy" @click="close">关闭</el-button>
        <el-button v-if="currentID" :disabled="busy" :loading="detailRead.loading.value" @click="reloadDetail">刷新恢复状态</el-button>
        <el-button v-if="preview" type="primary" :disabled="busy || !confirmed || expired || !preview.summary.can_prepare" @click="stage">创建恢复记录</el-button>
        <el-button v-if="detail?.can_continue" :disabled="busy || !secure" @click="check">检查本机资料</el-button>
        <el-button v-if="detail?.can_continue && detail.stage.status === 'pending_validation'" type="primary" :disabled="busy || !secure" @click="prepare">检查并准备候选</el-button>
        <el-button v-if="detail?.can_continue && detail.stage.status === 'pending_application'" type="primary" :disabled="busy || !secure || !confirmed || !detail.revision" @click="commit">提交到保存配置</el-button>
        <el-button v-if="detail?.can_cancel" type="danger" :disabled="busy || !secure || !confirmed" @click="cancel">取消此恢复</el-button>
      </div>
    </template>
  </el-dialog>
</template>

<style scoped>
.v3-restore-checkbox{height:auto;align-items:flex-start;margin:12px 0;max-width:100%;white-space:normal;text-align:left}
.v3-restore-checkbox :deep(.el-checkbox__label){white-space:normal;overflow-wrap:anywhere;line-height:1.6}
.v3-restore-checkbox :deep(.el-checkbox__input){margin-top:4px}
</style>
