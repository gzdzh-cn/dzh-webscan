<script setup lang="ts">
import { computed, onUnmounted, ref, toRaw } from 'vue'
import { V3Error, type V3MonitoringRulesEdit, type V3MonitoringRulesPreview, type V3MonitoringRulesView, type V3NodeMonitoring } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import NodeMonitoringFields from './NodeMonitoringFields.vue'
import MonitoringApplication from './MonitoringApplication.vue'

const { client, session } = useConsole(), read = useReadScope()
const baseline = ref<V3MonitoringRulesView>(), draft = ref<V3NodeMonitoring>(), preview = ref<V3MonitoringRulesPreview>()
const busy = ref(false), error = ref(''), message = ref(''), confirm = ref(false), reloadConfirm = ref(false)
const admin = computed(() => session.value?.role === 'admin')
const dirty = computed(() => !!baseline.value && !!draft.value && JSON.stringify(draft.value.rules) !== JSON.stringify(baseline.value.rules))
let disposed = false, generation = 0, key = '', pending: V3MonitoringRulesEdit | undefined
function invalidate() { generation++; preview.value = undefined; confirm.value = false; pending = undefined; key = '' }
function edit(value: V3NodeMonitoring) { draft.value = value; invalidate(); error.value = ''; message.value = '' }
function adopt(value: V3MonitoringRulesView) { baseline.value = structuredClone(value); draft.value = { source: 'independent', rules: structuredClone(value.rules), rules_version: value.version }; invalidate() }
async function load() { if (!admin.value || busy.value) return; await read.run(signal => client.monitoringRules(signal), adopt) }
function reload() { if (dirty.value) reloadConfirm.value = true; else void load() }
async function prepare() {
  if (!admin.value || !baseline.value || !draft.value || busy.value || read.loading.value || !dirty.value) return
  invalidate(); error.value = ''; message.value = ''
  const rules = draft.value.rules
  if (!rules.roots.length) { error.value = '请填写至少一个公共监控根目录'; return }
  if (!Number.isSafeInteger(rules.reconciliation_interval_hours) || rules.reconciliation_interval_hours < 1 || rules.reconciliation_interval_hours > 8760) { error.value = '清单核对间隔请输入 1～8760 的整数'; return }
  const current = generation, input = { expected_version: baseline.value.version, rules: structuredClone(toRaw(rules)) }
  busy.value = true
  try {
    const value = await client.previewMonitoringRules(input)
    if (disposed || current !== generation) return
    pending = input; preview.value = value; key = crypto.randomUUID(); confirm.value = true
  } catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '规则预览失败' }
  finally { if (!disposed && current === generation) busy.value = false }
}
async function save() {
  if (!pending || !preview.value || busy.value || !admin.value) return
  if (Date.now() >= Date.parse(preview.value.expires_at)) { invalidate(); error.value = '预览已过期，请重新预览'; return }
  const current = generation, input = { ...pending, preview: preview.value.token }
  busy.value = true; error.value = ''
  try {
    const value = await client.saveMonitoringRules(input, key)
    if (disposed || current !== generation) return
    adopt(value); message.value = '公共规则已保存，尚未下发；节点当前监控范围保持不变。'
  } catch (e) {
    if (!disposed && current === generation) { error.value = e instanceof Error ? e.message : '规则保存失败'; if (e instanceof V3Error && [400,409].includes(e.status)) invalidate() }
  } finally { if (!disposed) busy.value = false }
}
void load()
onUnmounted(() => { disposed = true; invalidate() })
</script>

<template>
  <section class="v3-public-monitoring" aria-label="公共文件监控">
    <div class="card-heading"><h3>公共文件监控</h3><el-button v-if="admin" :disabled="busy" :loading="read.loading.value" @click="reload">重新读取公共规则</el-button></div>
    <el-alert v-if="!admin" title="只有管理员可以查看和修改公共监控规则。" type="info" :closable="false" />
    <template v-else>
      <p class="muted">保存前自动备份；保存不自动下发。应用时需要明确选择目标节点，独立规则节点不受影响。</p>
      <el-alert v-if="read.error.value" :title="read.error.value" type="error" :closable="false" />
      <NodeMonitoringFields :model-value="draft" public-only :disabled="busy || read.loading.value" :loading="read.loading.value" @update:model-value="edit" />
      <p v-if="baseline" class="muted">公共规则版本 {{ baseline.version }}</p>
      <div class="v3-save-feedback" role="status" aria-live="polite"><el-alert v-if="error" :title="error" type="error" :closable="false" /><el-alert v-else-if="message" :title="message" type="success" :closable="false" /><span v-else>{{ busy ? confirm ? '正在保存公共规则…' : '正在校验并生成预览…' : dirty ? '规则已修改，尚未保存。' : '仅保存不会改变正在运行的子控。' }}</span></div>
      <el-button type="primary" :disabled="!dirty || busy || read.loading.value" :loading="busy" @click="prepare">校验并预览公共规则</el-button>
    </template>
    <MonitoringApplication v-if="baseline && admin" :version="baseline.version" :disabled="busy || dirty" />
    <el-dialog v-model="confirm" title="保存公共监控规则" width="600px" class="v3-node-dialog" :close-on-click-modal="!busy" :close-on-press-escape="!busy" :show-close="!busy">
      <p>本次只保存公共规则，不自动下发，不改变任何节点当前监控范围。</p><p>变更字段：{{ preview?.changed_fields.join('、') || '无' }}</p><p>预览有效期至 {{ timeText(preview?.expires_at) }}</p>
      <template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="error" :title="error" type="error" :closable="false" /><span v-else>{{ busy ? '正在保存…' : '保存后请预览并选择需要应用的节点。' }}</span></div><div class="v3-actions"><el-button :disabled="busy" @click="invalidate">返回修改</el-button><el-button type="primary" :loading="busy" @click="save">确认仅保存公共规则</el-button></div></template>
    </el-dialog>
    <el-dialog v-model="reloadConfirm" title="重新读取公共规则" width="480px" class="v3-node-dialog"><p>重新读取将放弃当前公共规则草稿，使用服务器最新版本。</p><template #footer><el-button @click="reloadConfirm = false">保留草稿</el-button><el-button type="primary" @click="reloadConfirm = false; load()">放弃草稿并读取</el-button></template></el-dialog>
  </section>
</template>
