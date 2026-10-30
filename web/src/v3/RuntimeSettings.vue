<script setup lang="ts">
import { computed, onUnmounted, reactive, ref, toRaw } from 'vue'
import { V3Error, type V3SettingsEdit, type V3SettingsField, type V3SettingsPreview, type V3SettingsRequest, type V3SettingsView } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
const { client, session } = useConsole(), read = useReadScope()
const view = ref<V3SettingsView>(), draft = reactive<Record<string, string>>({})
const secrets = reactive<Record<string, { action: 'keep' | 'replace' | 'clear'; value: string }>>({})
const secretLabels: Record<string, string> = { 'email.password': 'SMTP 密码／授权码', 'feishu.webhook_url': '飞书 Webhook', 'feishu.signing_secret': '飞书签名密钥' }
const groups = [{ id: 'website_monitor', label: '网站检测' }, { id: 'monitoring', label: '服务器告警' }, { id: 'email', label: '邮箱通知' }, { id: 'feishu', label: '飞书通知' }]
const admin = computed(() => session.value?.role === 'admin')
const busy = ref(false), error = ref(''), message = ref(''), reloadConfirm = ref(false), confirm = ref(false), preview = ref<V3SettingsPreview>()
let disposed = false, generation = 0, pending: V3SettingsRequest | undefined, retryKey = ''
const text = (value: unknown) => value === undefined ? '' : Array.isArray(value) ? value.join('\n') : String(value)
const dirty = computed(() => !!view.value && (view.value.fields.some(f => draft[f.path] !== text(view.value!.values[f.path])) || Object.values(secrets).some(s => s.action !== 'keep')))
const fields = (group: string) => view.value?.fields.filter(f => f.path.startsWith(group + '.')) || []
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
    adopt(updated); message.value = input.action === 'save' ? '配置已保存，尚未应用。' : '已保存设置已应用，后续任务使用新配置。'
    busy.value = false; void load()
  } catch (e) {
    if (!disposed && generation === current) { error.value = e instanceof Error ? e.message : '操作失败'; if (e instanceof V3Error && [400, 409].includes(e.status)) invalidate() }
  } finally { if (!disposed && generation === current) busy.value = false }
}
function closePreview() { if (busy.value) return; invalidate(); clearSecrets() }
function runtimeDiff(f: V3SettingsField) { return text(view.value?.values[f.path]) !== text(view.value?.runtime_values[f.path]) }
clearSecrets(); void load()
onUnmounted(() => { disposed = true; generation++; invalidate(); clearSecrets() })
</script>

<template>
  <el-alert v-if="!admin" title="只有管理员可以管理运行设置。" type="info" :closable="false" />
  <template v-else>
    <el-alert v-if="read.error.value" :title="`${read.error.value}；已有输入保留`" type="error" :closable="false" />
    <el-card shadow="never">
      <div class="v3-job-heading"><h2>运行设置</h2><el-button :disabled="busy" :loading="read.loading.value" @click="reload">重新读取运行设置</el-button></div>
      <p class="v3-muted">先预览并保存，再明确应用。未设置的字段沿用运行默认；此处间隔不修改主控指标采集周期。凭据不回显。</p>
      <p v-if="!view">{{ read.loading.value ? '正在读取设置…' : '运行设置尚未读取成功' }}</p>
      <template v-else>
        <p>运行版本 {{ view.state.runtime_version }} · 保存版本 {{ view.state.generation }} · {{ view.state.pending ? '已保存，待应用' : '已应用' }} · {{ timeText(view.state.updated_at) }}</p>
        <details v-for="group in groups" :key="group.id" class="runtime-group" :open="group.id === 'website_monitor'">
          <summary>{{ group.label }}</summary>
          <el-form label-position="top" class="v3-form-grid" @submit.prevent="prepare('save')">
            <el-form-item v-for="field in fields(group.id)" :key="field.path" :label="field.label">
              <select v-if="field.kind === 'bool' || field.kind === 'choice'" v-model="draft[field.path]" :aria-label="field.label" :disabled="busy || read.loading.value" @change="edited">
                <option value="" :disabled="view.values[field.path] !== undefined">未设置（沿用运行默认）</option>
                <template v-if="field.kind === 'bool'"><option value="true">启用</option><option value="false">停用</option></template>
                <option v-for="choice in field.choices" v-else :key="choice" :value="choice">{{ choice }}</option>
              </select>
              <el-input v-else v-model="draft[field.path]" :type="field.kind === 'addresses' ? 'textarea' : 'text'" :aria-label="field.label" :inputmode="field.kind === 'integer' ? 'numeric' : undefined" :placeholder="field.kind === 'addresses' ? '每行一个邮箱' : '未设置（沿用运行默认）'" :disabled="busy || read.loading.value" @input="edited" />
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
        </details>
        <div class="v3-save-feedback" role="status" aria-live="polite"><el-alert v-if="error" :title="error" type="error" :closable="false" /><el-alert v-else-if="message" :title="message" type="success" :closable="false" /><p v-else>{{ busy ? '正在校验、备份并处理设置…' : dirty ? '有未保存修改，请预览后保存。' : view.state.pending ? '已保存配置尚未应用；应用前将再次预览。' : '配置与运行状态一致。' }}</p></div>
        <div class="runtime-actions"><el-button type="primary" :loading="busy" :disabled="!dirty || read.loading.value" @click="prepare('save')">预览并保存设置</el-button><el-button :disabled="!view.state.pending || dirty || busy || read.loading.value" @click="prepare('apply')">预览应用已保存设置</el-button></div>
      </template>
    </el-card>
  </template>
  <el-dialog :model-value="confirm" title="确认设置变更" width="560px" class="v3-node-dialog" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @update:model-value="closePreview">
    <template v-if="preview"><p>{{ preview.action === 'save' ? '仅保存配置，不立即生效。' : '应用数据库中已保存设置，后续检测及通知任务使用新配置。' }}</p><p>预览有效至 {{ timeText(preview.expires_at) }}。确认前自动保存加密配置备份。</p>
      <ul><li v-for="path in preview.changed_fields" :key="path">{{ secretLabels[path] || view?.fields.find(f => f.path === path)?.label || path }}</li></ul>
      <el-alert v-if="preview.notifications_enabled" title="将启用通知通道；应用后已有待投递记录可能继续投递。" type="warning" :closable="false" />
      <el-alert v-if="preview.retention_shortened" title="将缩短历史保留期限，符合规则的旧历史会永久清理。" type="warning" :closable="false" />
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
</style>
