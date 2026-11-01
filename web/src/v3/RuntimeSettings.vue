<script setup lang="ts">
import { computed, onUnmounted, reactive, ref, toRaw, watch } from 'vue'
import { V3Error, type V3SettingsEdit, type V3SettingsField, type V3SettingsPreview, type V3SettingsRequest, type V3SettingsView } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import MonitoringRules from './MonitoringRules.vue'
import NotificationTest from './NotificationTest.vue'
const props = defineProps<{group?: string}>()
const { client, session } = useConsole(), read = useReadScope()
const view = ref<V3SettingsView>(), draft = reactive<Record<string, string>>({})
const secrets = reactive<Record<string, { action: 'keep' | 'replace' | 'clear'; value: string }>>({})
const secretLabels: Record<string, string> = { 'email.password': 'SMTP 密码／授权码', 'feishu.webhook_url': '飞书 Webhook', 'feishu.signing_secret': '飞书签名密钥' }
const groups = [{ id: 'website_monitor', label: '网站检测' }, { id: 'collector', label: '主控指标采集' }, { id: 'metrics', label: '指标历史保留' }, { id: 'monitoring', label: '服务器告警' }, { id: 'backup', label: '自动完整备份' }, { id: 'email', label: '邮箱通知' }, { id: 'feishu', label: '飞书通知' }]
const admin = computed(() => session.value?.role === 'admin')
const busy = ref(false), error = ref(''), message = ref(''), reloadConfirm = ref(false), confirm = ref(false), preview = ref<V3SettingsPreview>()
let disposed = false, generation = 0, pending: V3SettingsRequest | undefined, retryKey = ''
const text = (value: unknown) => value === undefined ? '' : Array.isArray(value) ? value.join('\n') : String(value)
const dirty = computed(() => !!view.value && (view.value.fields.some(f => draft[f.path] !== text(view.value!.values[f.path])) || Object.values(secrets).some(s => s.action !== 'keep')))
const metricFields = ['monitoring.raw_hours', 'monitoring.history_days']
const fields = (group: string) => view.value?.fields.filter(f => group === 'metrics' ? !!view.value?.metrics_retention?.available && metricFields.includes(f.path) : !metricFields.includes(f.path) && f.path.startsWith(group + '.')) || []
const groupHelp: Record<string,string> = { metrics:'原始指标与长期历史使用独立时序库。保存不生效；明确应用后，宿主维护任务先完成备份，再核验引擎。原始指标支持 24～168 小时，长期历史支持 1～90 天。',collector:'设置主控主动连接子控拉取指标的实际周期，支持 10～3600 秒；保存不生效，明确应用后采集调度使用新周期。',monitoring:'告警判定参考间隔用于服务器告警规则，不修改主控拉取指标的实际周期；实际周期请到“主控指标采集”设置。',backup:'设置自动完整备份的时间、IANA 时区和保留天数。停用仅暂停自动执行，手动备份不受影响；最新成功备份始终保留。' }
const fieldHints: Record<string,string> = { 'collector.interval_seconds':'主控实际拉取周期，单位为秒。','monitoring.interval_seconds':'仅用于告警判定参考，不是主控指标采集周期。','backup.time':'24 小时制 HH:MM；首次显式设置备份策略时，未填写此项采用 03:00。','backup.timezone':'显式 IANA 时区，例如 Asia/Shanghai 或 UTC；不使用浏览器时区。首次显式设置时未填写采用 UTC。','backup.keep_days':'单位为天，支持 1～3650 天，不是保留份数；首次显式设置时未填写采用 7 天。' }
const backupKeys = ['backup.enabled','backup.time','backup.timezone','backup.keep_days']
function backupDescription(values: V3SettingsView['values']) { return `自动执行${values['backup.enabled'] === false ? '暂停' : '启用'} · 每天 ${values['backup.time'] ?? '03:00'} · 时区 ${values['backup.timezone'] ?? 'UTC'} · 保留 ${values['backup.keep_days'] ?? 7} 天；最新成功备份保留。` }
const backupRuntime = computed(() => !view.value ? '' : backupKeys.some(key => view.value!.runtime_values[key] !== undefined) ? `当前生效：${backupDescription(view.value.runtime_values)}` : '当前生效：沿用原宿主策略，在主机时区 03:00 执行并沿用原保留份数；未转换为天数策略。')
const backupPreview = computed(() => preview.value && view.value && preview.value.changed_fields.some(path => path.startsWith('backup.')) ? backupDescription({ ...view.value.values,...(pending?.action === 'save' ? pending.edit.values : {}) }) : '')
function clearSecrets() { for (const path of Object.keys(secretLabels)) secrets[path] = { action: 'keep', value: '' } }
function invalidate() { preview.value = undefined; pending = undefined; retryKey = ''; confirm.value = false }
function edited() { invalidate(); error.value = ''; message.value = '' }
function adopt(value: V3SettingsView) { view.value = structuredClone(value); Object.keys(draft).forEach(k => delete draft[k]); value.fields.forEach(f => { draft[f.path] = text(value.values[f.path]) }); clearSecrets(); invalidate() }
async function load() { if (!admin.value || busy.value) return; await read.run(signal => client.settings(signal), adopt) }
function reload() { if (dirty.value) reloadConfirm.value = true; else void load() }
function buildEdit(): V3SettingsEdit {
  const values: NonNullable<V3SettingsEdit['values']> = {}, changedSecrets: NonNullable<V3SettingsEdit['secrets']> = {}
  for (const f of view.value!.fields) {
    const value = draft[f.path] ?? ''
    if (value === text(view.value!.values[f.path])) continue
    if (f.kind === 'integer') {
      if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) < f.min! || Number(value) > f.max!) throw new Error(`${f.label}：请输入 ${f.min}～${f.max} 的整数`)
      values[f.path] = Number(value)
    } else if (f.kind === 'bool') {
      if (!['true', 'false'].includes(value)) throw new Error(`${f.label}：请选择启用或停用`)
      values[f.path] = value === 'true'
    } else if (f.kind === 'addresses') {
      const addresses = value.split(/[\n,，]/).map(v => v.trim()).filter(Boolean)
      if (addresses.length > f.max!) throw new Error(`${f.label}：最多 ${f.max} 个邮箱`)
      values[f.path] = addresses
    } else {
      if (f.kind === 'choice' && !f.choices?.includes(value)) throw new Error(`${f.label}：请选择有效选项`)
      if (f.path === 'backup.time' && !/^([01]\d|2[0-3]):[0-5]\d$/.test(value)) throw new Error(`${f.label}：请输入有效的 24 小时制 HH:MM`)
      if (f.path === 'backup.timezone') { try { if (!value || value === 'Local' || value.length > 128 || /[\x00\r\n]/.test(value)) throw Error();new Intl.DateTimeFormat('en',{timeZone:value}) } catch { throw new Error(`${f.label}：请输入有效的 IANA 时区，例如 Asia/Shanghai 或 UTC`) } }
      values[f.path] = value
    }
  }
  for (const [path, secret] of Object.entries(secrets)) {
    if (secret.action === 'keep') continue
    if (secret.action === 'replace' && !secret.value) throw new Error(`${secretLabels[path]}：请输入替换内容`)
    changedSecrets[path] = secret.action === 'replace' ? { action: 'replace', value: secret.value } : { action: 'clear' }
  }
  return { values, secrets: changedSecrets }
}
async function prepare(action: 'save' | 'apply') {
  if (busy.value || read.loading.value || !view.value || !admin.value || (action === 'apply' && dirty.value)) return
  invalidate(); error.value = ''; message.value = ''
  const current = ++generation
  try {
    const input: V3SettingsRequest = { action, expected_generation: view.value.state.generation, expected_runtime_version: view.value.state.runtime_version, edit: action === 'save' ? buildEdit() : {} }
    busy.value = true
    const result = await client.previewSettings(input)
    if (disposed || generation !== current) return
    pending = structuredClone({ ...input, preview: result.token }); preview.value = result; retryKey = crypto.randomUUID(); confirm.value = true
  } catch (e) { if (!disposed && generation === current) error.value = e instanceof Error ? e.message : '预览失败' }
  finally { if (!disposed && generation === current) busy.value = false }
}
async function submit() {
  if (busy.value || !pending || !preview.value || !view.value) return
  if (Date.now() >= Date.parse(preview.value.expires_at)) { invalidate(); error.value = '预览已过期，请重新预览'; return }
  busy.value = true; error.value = ''; const current = ++generation, input = structuredClone(pending)
  try {
    const state = await client.confirmSettings(input, retryKey)
    if (disposed || generation !== current) return
    // Keep the acknowledged version even when the subsequent refresh fails.
    const updated = structuredClone(toRaw(view.value))
    updated.state = state
    if (input.action === 'save') {
      Object.assign(updated.values, input.edit.values)
      for (const [path, value] of Object.entries(input.edit.secrets || {})) if (value.action !== 'keep') updated.secret_configured[path] = value.action === 'replace'
    } else { updated.runtime_values = structuredClone(updated.values); updated.runtime_secret_configured = { ...updated.secret_configured } }
    const metricsApplied = input.action === 'apply' && preview.value?.changed_fields.some(path => metricFields.includes(path))
    adopt(updated); message.value = input.action === 'save' ? '配置已保存，尚未应用。' : metricsApplied ? '设置已应用，指标保留期限等待宿主备份及引擎确认。' : '已保存设置已应用，后续任务使用新配置。'
    busy.value = false; void load()
  } catch (e) {
    if (!disposed && generation === current) { error.value = e instanceof Error ? e.message : '操作失败'; if (e instanceof V3Error && [400, 409].includes(e.status)) invalidate() }
  } finally { if (!disposed && generation === current) busy.value = false }
}
function closePreview() { if (busy.value) return; invalidate(); clearSecrets() }
function runtimeDiff(f: V3SettingsField) { return text(view.value?.values[f.path]) !== text(view.value?.runtime_values[f.path]) }
clearSecrets(); void load()
onUnmounted(() => { disposed = true; generation++; invalidate(); clearSecrets() })
watch(() => props.group, () => { generation++; busy.value = false; clearSecrets(); invalidate(); error.value = ''; message.value = '' })

</script>

<template>
  <el-alert v-if="!admin" title="只有管理员可以管理运行设置。" type="info" :closable="false" />
  <template v-else>
    <el-alert v-if="read.error.value" :title="`${read.error.value}；已有输入保留`" type="error" :closable="false" />
    <el-card shadow="never" class="runtime-settings-card">
      <div class="card-heading v3-job-heading"><h2>运行设置</h2><el-button :disabled="busy" :loading="read.loading.value" @click="reload">重新读取运行设置</el-button></div>
      <p class="v3-muted">先预览并保存，再明确应用。未设置的字段沿用运行默认；主控实际采集周期与告警参考间隔独立设置。凭据不回显。</p>
      <p v-if="!view">{{ read.loading.value ? '正在读取设置…' : '运行设置尚未读取成功' }}</p>
      <template v-else>
        <MonitoringRules v-if="props.group === 'monitoring'" />
        <p>运行版本 {{ view.state.runtime_version }} · 保存版本 {{ view.state.generation }} · {{ view.state.pending ? '已保存，待应用' : '已应用' }} · {{ timeText(view.state.updated_at) }}</p>
        <component :is="props.group ? 'section' : 'details'" v-for="group in groups.filter(item => !props.group || props.group === item.id)" :key="group.id" class="runtime-group" :open="props.group ? undefined : group.id === 'website_monitor'">
          <h3 v-if="props.group">{{ group.label }}</h3><summary v-else>{{ group.label }}</summary>
          <p v-if="groupHelp[group.id]" class="v3-muted runtime-group-help">{{ groupHelp[group.id] }}</p><template v-if="group.id === 'backup'"><p class="v3-muted">{{ backupRuntime }}</p><p class="v3-muted">首次明确应用任一备份字段后，其余未设置项采用每天 03:00、UTC、7 天；页面空白不表示原策略已使用这些默认值。</p></template>
          <template v-if="group.id === 'metrics' "><el-alert v-if="!view.metrics_retention?.available" :title="view.metrics_retention?.reason || '尚未配置独立双层指标维护；现有保留方式不变。'" type="info" :closable="false" /><template v-else><p>实际引擎保留：{{ view.metrics_retention.status?.effective ? `原始 ${view.metrics_retention.status.effective.raw_hours} 小时 · 历史 ${view.metrics_retention.status.effective.history_days} 天` : '未知，尚未取得确认' }}</p><p class="v3-muted">{{ view.metrics_retention.status?.state === 'confirmed' ? '已核验引擎' : '维护任务未完成' }} · {{ timeText(view.metrics_retention.status?.observed_at) }}</p><el-alert v-if="view.metrics_retention.reason" :title="view.metrics_retention.reason" type="warning" :closable="false" /></template></template>
          <el-form label-position="top" class="form-grid v3-form-grid" @submit.prevent="prepare('save')">
            <el-form-item v-for="field in fields(group.id)" :key="field.path" :label="field.label">
              <select v-if="field.kind === 'bool' || field.kind === 'choice'" v-model="draft[field.path]" :aria-label="field.label" :disabled="busy || read.loading.value" @change="edited">
                <option value="" :disabled="view.values[field.path] !== undefined">未设置（沿用运行默认）</option>
                <template v-if="field.kind === 'bool'"><option value="true">启用</option><option value="false">停用</option></template>
                <option v-for="choice in field.choices" v-else :key="choice" :value="choice">{{ choice }}</option>
              </select>
              <el-input v-else v-model="draft[field.path]" :type="field.kind === 'addresses' ? 'textarea' : 'text'" :aria-label="field.label" :inputmode="field.kind === 'integer' ? 'numeric' : undefined" :placeholder="field.kind === 'addresses' ? '每行一个邮箱' : '未设置（沿用运行默认）'" :disabled="busy || read.loading.value" @input="edited" />
              <small v-if="fieldHints[field.path]" class="v3-muted runtime-field-hint">{{ fieldHints[field.path] }}</small>
              <small v-if="runtimeDiff(field)" class="v3-muted">待应用；当前生效：{{ text(view.runtime_values[field.path]) || '未设置' }}</small>
            </el-form-item>
            <template v-for="(label, path) in secretLabels" :key="path">
              <el-form-item v-if="String(path).startsWith(group.id + '.')" :label="label">
                <p class="v3-muted">{{ view.secret_configured[path] ? '已配置，留空保留' : '未配置' }} · 运行中{{ view.runtime_secret_configured[path] ? '已配置' : '未配置' }}</p>
                <select v-model="secrets[path]!.action" :aria-label="`${label}操作`" :disabled="busy || read.loading.value" @change="secrets[path]!.value = ''; edited()"><option value="keep">保留</option><option value="replace">替换</option><option value="clear">清除</option></select>
                <el-input v-if="secrets[path]!.action === 'replace'" v-model="secrets[path]!.value" :aria-label="label" type="password" autocomplete="new-password" :disabled="busy || read.loading.value" @input="edited" />
              </el-form-item>
            </template>
          </el-form>
          <NotificationTest v-if="group.id === 'email' || group.id === 'feishu'" :key="group.id" :channel="group.id" :runtime-version="view.state.runtime_version" :dirty="dirty" :pending="view.state.pending" />
        </component>
        <div class="runtime-save-bar"><div class="v3-save-feedback" role="status" aria-live="polite"><el-alert v-if="error" :title="error" type="error" :closable="false" /><el-alert v-else-if="message" :title="message" type="success" :closable="false" /><p v-else>{{ busy ? '正在校验、备份并处理设置…' : dirty ? '有未保存修改，请预览后保存。' : view.state.pending ? '已保存配置尚未应用；应用前将再次预览。' : '配置与运行状态一致。' }}</p></div>
        <div class="runtime-actions"><el-button type="primary" :loading="busy" :disabled="!dirty || read.loading.value" @click="prepare('save')">预览并保存设置</el-button><el-button :disabled="!view.state.pending || dirty || busy || read.loading.value" @click="prepare('apply')">预览应用已保存设置</el-button></div></div>
      </template>
    </el-card>
  </template>
  <el-dialog :model-value="confirm" title="确认设置变更" width="560px" class="v3-node-dialog" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @update:model-value="closePreview">
    <template v-if="preview"><p>{{ preview.action === 'save' ? '仅保存配置，不立即生效。' : '应用数据库中已保存设置，后续检测及通知任务使用新配置；采集与备份设置由对应工作器按已应用版本执行。' }}</p><p>预览有效至 {{ timeText(preview.expires_at) }}。确认前自动保存加密配置备份。</p>
      <ul><li v-for="path in preview.changed_fields" :key="path">{{ secretLabels[path] || view?.fields.find(f => f.path === path)?.label || path }}</li></ul>
      <el-alert v-if="backupPreview" :title="`本次备份策略：${backupPreview}`" type="info" :closable="false" /><p v-if="backupPreview" class="v3-muted">{{ preview.action === 'save' ? '仅保存，当前自动备份策略保持生效；明确应用后才采用上述时间、时区和天数。' : '应用后自动备份工作器采用上述时间、时区和天数；手动备份不受启停影响。' }}</p>
      <el-alert v-if="preview.notifications_enabled" title="将启用通知通道；应用后已有待投递记录可能继续投递。" type="warning" :closable="false" />
      <el-alert v-if="preview.retention_shortened" title="将缩短历史保留期限，符合规则的旧历史会永久清理；指标保留变更需先完成完整备份，再由宿主核验引擎。" type="warning" :closable="false" />
      <el-alert v-if="error" :title="error" type="error" :closable="false" />
    </template>
    <template #footer><el-button :disabled="busy" @click="closePreview">返回修改</el-button><el-button type="primary" :loading="busy" @click="submit">{{ preview?.action === 'save' ? '确认仅保存' : '确认应用已保存设置' }}</el-button></template>
  </el-dialog>
  <el-dialog v-model="reloadConfirm" title="重新读取运行设置" width="480px" class="v3-node-dialog"><p>将放弃当前未保存草稿及临时凭据输入，读取最新配置。</p><template #footer><el-button @click="reloadConfirm = false">保留草稿</el-button><el-button type="primary" @click="reloadConfirm = false; load()">放弃草稿并读取设置</el-button></template></el-dialog>
</template>
<style scoped>
.runtime-group { border-top: 1px solid var(--el-border-color-light); padding: 14px 0; }
.runtime-group summary { cursor: pointer; font-weight: 600; padding-bottom: 12px; }
.runtime-group select { width: 100%; padding: 8px; border: 1px solid var(--el-border-color); border-radius: 4px; color: var(--el-text-color-primary); background: var(--el-bg-color); }
.runtime-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.runtime-actions .el-button { margin-left: 0; }
.runtime-field-hint { display: block; line-height: 1.6; overflow-wrap: anywhere; }
.runtime-settings-card { overflow: visible; }
.runtime-settings-card > :deep(.el-card__body) { overflow: visible; }
.runtime-save-bar { position: sticky; bottom: 0; z-index: 3; background: var(--el-bg-color); border-top: 1px solid var(--el-border-color-light); padding: 8px 0 12px; }
.runtime-save-bar .v3-save-feedback { margin: 8px 0; }
</style>
