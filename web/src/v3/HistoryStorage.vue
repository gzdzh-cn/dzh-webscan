<script setup lang="ts">
import { computed, onUnmounted, reactive, ref, watch } from 'vue'
import { ElCheckboxGroup } from 'element-plus'
import type { V3HistoryCategory, V3HistoryPreview, V3HistoryScope } from '../controlV3'
import { timeText, useConsole } from './context'
import { historyCategories, historyCategory } from './historyLabels'
import NodePicker from './NodePicker.vue'
import HistoryTask from './HistoryTask.vue'
import HistoryJobs from './HistoryJobs.vue'
const { client, session } = useConsole()
function cutoffDefault() { const date = new Date(Date.now() - 30 * 86400_000); return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16) }
const form = reactive({ categories: ['events'] as V3HistoryCategory[], node: '', before: cutoffDefault(), include_probes: false })
const preview = ref<V3HistoryPreview>(), busy = ref(false), error = ref(''), confirm = ref(false), exportFirst = ref(true), task = ref(''), revision = ref(0)
const canWrite = computed(() => !!session.value && session.value.role !== 'viewer')
const fingerprint = computed(() => JSON.stringify(form))
let disposed = false, generation = 0, intent = '', key = ''
function invalidate() { generation++; preview.value = undefined; confirm.value = false; busy.value = false; error.value = ''; intent = ''; key = '' }
watch(fingerprint, invalidate)
function scope(): V3HistoryScope | undefined {
  error.value = ''
  if (!form.categories.length) { error.value = '请至少选择一个历史类别'; return }
  const at = new Date(form.before)
  if (!form.before || !Number.isFinite(at.getTime())) { error.value = '请选择有效的截止日期和时间'; return }
  if (at.getTime() > Date.now() - 86400_000) { error.value = '不能清理最近 24 小时，请将截止时间设在 24 小时之前'; return }
  return { categories: [...form.categories], node: form.node || undefined, before: at.toISOString(), include_probes: form.include_probes }
}
async function inspect() {
  if (busy.value || !canWrite.value) return
  const selected = scope(); if (!selected) return
  preview.value = undefined; busy.value = true; const current = ++generation
  try { const value = await client.previewHistory(selected); if (!disposed && current === generation) preview.value = value }
  catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '预览失败' }
  finally { if (!disposed && current === generation) busy.value = false }
}
function prepareCleanup() {
  if (!preview.value || !canWrite.value || busy.value) return
  if (Date.parse(preview.value.expires_at) <= Date.now()) { preview.value = undefined; error.value = '预览已过期，请重新预览'; return }
  error.value = ''; confirm.value = true
}
async function submit(kind: 'export' | 'cleanup') {
  if (!preview.value || busy.value || !canWrite.value) return
  if (Date.parse(preview.value.expires_at) <= Date.now()) { confirm.value = false; preview.value = undefined; error.value = '预览已过期，请重新预览'; return }
  busy.value = true; error.value = ''; const current = generation, token = preview.value.token
  const body = JSON.stringify({ token, kind, export_first: kind === 'cleanup' && exportFirst.value })
  if (intent !== body) { intent = body; key = crypto.randomUUID() }
  try {
    const value = kind === 'export' ? await client.exportHistory(token, key) : await client.cleanupHistory(token, { export_first: exportFirst.value, confirm_without_export: !exportFirst.value }, key)
    if (disposed || current !== generation) return
    confirm.value = false; task.value = value.id; preview.value = undefined; revision.value++
  } catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '任务创建失败，请核实后重试' }
  finally { if (!disposed && current === generation) busy.value = false }
}
onUnmounted(() => { disposed = true; generation++ })
</script>
<template><el-card shadow="never"><h2>历史范围预览</h2><p class="v3-muted">默认 30 天前，禁止清理最近 24 小时。当前异常、未完成任务和待投递通知继续受保护；指标与备份由各自策略管理。</p><el-alert v-if="!canWrite" title="当前账号只读，可查看任务；不能发起导出或清理。" type="info" :closable="false" /><el-form label-position="top" @submit.prevent="inspect"><el-form-item label="历史类别"><el-checkbox-group v-model="form.categories" :disabled="busy || !canWrite" class="v3-checkbox-grid"><el-checkbox v-for="item in historyCategories" :key="item.value" :value="item.value">{{ item.label }}</el-checkbox></el-checkbox-group></el-form-item><div class="v3-form-grid"><el-form-item label="服务器范围"><NodePicker v-model="form.node" :disabled="busy || !canWrite" /></el-form-item><el-form-item label="截止时间（本地时间）"><el-input v-model="form.before" type="datetime-local" aria-label="历史截止时间" :disabled="busy || !canWrite" /></el-form-item></div><el-checkbox v-model="form.include_probes" :disabled="busy || !canWrite">包含链路探针历史（与事件页面显示设置独立）</el-checkbox></el-form><p class="v3-muted">这是指定范围内的历史操作，不是列表勾选删除。预览固定范围和配置版本，有效 10 分钟；执行时重新检查保护条件。</p><section v-if="preview" class="v3-scope-summary" aria-label="历史清理预览"><strong>可处理 {{ preview.eligible }} 条 · 受保护 {{ preview.protected }} 条</strong><p>{{ preview.scope.categories.map(historyCategory).join('、') }}；{{ preview.scope.node || '全部服务器' }}；截止 {{ timeText(preview.scope.before) }}；{{ preview.scope.include_probes ? '包含探针' : '不包含探针' }}</p><p>配置版本 {{ preview.settings_version }} · 有效至 {{ timeText(preview.expires_at) }}</p></section><div class="v3-save-feedback" role="status" aria-live="polite"><el-alert v-if="error" :title="error" type="error" :closable="false" /><span v-else-if="busy">{{ preview ? '正在创建任务，请勿重复提交…' : '正在检查范围和保护条件…' }}</span></div><div v-if="canWrite" class="v3-actions v3-actions-start"><el-button :loading="busy && !preview" :disabled="busy" @click="inspect">预览范围</el-button><el-button :disabled="!preview || busy || !preview.eligible" @click="submit('export')">仅导出 JSONL</el-button><el-button type="danger" :disabled="!preview || busy || !preview.eligible" @click="prepareCleanup">清理范围内历史</el-button></div></el-card>
  <HistoryJobs :revision="revision" />
  <el-dialog v-model="confirm" title="确认历史范围清理" class="v3-node-dialog" width="620px" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy"><p>将永久清理预览范围内符合保护条件的 {{ preview?.eligible }} 条历史，执行时数量可能因新增保护而减少。</p><p>删除不可逆，不代表风险已处理，也不保证立即释放磁盘空间。</p><el-checkbox v-model="exportFirst" :disabled="busy">先导出 JSONL，导出成功后再清理</el-checkbox><el-alert v-if="!exportFirst" title="你选择不导出，删除后无法通过本次操作找回历史。" type="warning" :closable="false" /><template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="error" :title="error" type="error" :closable="false" /><span v-else-if="busy">正在创建清理任务…</span></div><div class="v3-actions"><el-button :disabled="busy" @click="confirm = false">取消</el-button><el-button type="danger" :loading="busy" @click="submit('cleanup')">{{ exportFirst ? '导出成功后清理' : '确认不导出，永久清理' }}</el-button></div></template></el-dialog>
  <el-dialog :model-value="!!task" title="历史处理任务" class="v3-node-dialog" width="720px" @update:model-value="task = ''"><HistoryTask v-if="task" :key="task" :id="task" @finished="revision++" /><template #footer><el-button @click="task = ''">关闭</el-button></template></el-dialog>
</template>
