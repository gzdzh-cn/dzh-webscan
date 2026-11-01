<script setup lang="ts">
import { computed, onUnmounted, ref } from 'vue'
import type { V3DeploymentJob, V3DeploymentHistoryDeletePreview } from '../controlV3'
import { useConsole } from './context'
import DeploymentDeleteTask from './DeploymentDeleteTask.vue'

const props = defineProps<{ rows: V3DeploymentJob[] }>(), emit = defineEmits<{ changed: [] }>()
const { client, session } = useConsole(), admin = computed(() => session.value?.role === 'admin')
const visible = ref(false), busy = ref(false), error = ref(''), confirmed = ref(false), expired = ref(false)
const preview = ref<V3DeploymentHistoryDeletePreview>(), taskID = ref('')
const storageKey = `webscan.deployment.history.delete.${session.value?.username || ''}`
try { taskID.value = sessionStorage.getItem(storageKey) || '' } catch { /* Progress can still be opened for this page. */ }
let disposed = false, generation = 0, operation = new AbortController(), expiryTimer: ReturnType<typeof setTimeout> | undefined
let previewIntent: { body: string; key: string } | undefined, confirmKey = '', retryRecords: V3DeploymentJob[] = []
function close() { generation++; operation.abort(); operation = new AbortController(); visible.value = false; busy.value = false; preview.value = undefined; confirmed.value = false; expired.value = false; error.value = ''; previewIntent = undefined; confirmKey = ''; retryRecords = []; clearTimeout(expiryTimer) }
function closed() { if (!visible.value) close() }
async function open(records: V3DeploymentJob[]) {
 if (!admin.value || busy.value || !records.length || records.length > 200) return
 const keys = records.filter(row => row.can_delete === true && row.record_key && props.rows.some(current => current.id === row.id && current.record_key === row.record_key && current.can_delete === true)).map(row => row.record_key!)
 if (keys.length !== records.length || new Set(keys).size !== keys.length) return
 retryRecords = records.map(row => ({ ...row }))
 const body = JSON.stringify(keys)
 if (previewIntent?.body !== body) previewIntent = { body, key: crypto.randomUUID() }
 const current = ++generation; visible.value = true; busy.value = true; error.value = ''; preview.value = undefined; confirmed.value = false; expired.value = false
 clearTimeout(expiryTimer)
 try {
  const value = await client.previewDeploymentHistoryDelete(keys, previewIntent.key, operation.signal)
  if (disposed || current !== generation) return
  preview.value = value; confirmKey = crypto.randomUUID()
  const remaining = Date.parse(value.expires_at) - Date.now()
  expired.value = !Number.isFinite(remaining) || remaining <= 0
  if (!expired.value) expiryTimer = setTimeout(() => { expired.value = true }, remaining)
 } catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '删除预览失败，原历史保留' }
 finally { if (!disposed && current === generation) busy.value = false }
}
async function submit() {
 if (busy.value || !preview.value || !confirmed.value || expired.value || preview.value.eligible < 1) return
 const current = generation; busy.value = true; error.value = ''
 try {
  const value = await client.deleteDeploymentHistory(preview.value.token, confirmKey, operation.signal)
  if (disposed || current !== generation) return
  taskID.value = value.id
  try { sessionStorage.setItem(storageKey, value.id) } catch { /* Task remains visible while this page is open. */ }
  close(); emit('changed')
 } catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '任务响应未确认，请重试查询' }
 finally { if (!disposed && current === generation) busy.value = false }
}
onUnmounted(() => { disposed = true; generation++; operation.abort(); clearTimeout(expiryTimer) })
defineExpose({ open })
</script>

<template>
 <el-card v-if="admin && taskID" shadow="never"><h3>最近的部署历史删除任务</h3><p class="v3-muted">任务已创建不代表删除完成；以逐项结果为准。</p><DeploymentDeleteTask :id="taskID" @finished="emit('changed')" /></el-card>
 <el-dialog v-model="visible" title="删除部署历史及日志" width="680px" class="v3-node-dialog" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @closed="closed">
  <el-alert title="仅删除页面历史及日志；保留防重、安装证明和恢复资料。不会卸载子控，也不会移除服务器记录。" type="warning" :closable="false" />
  <template v-if="preview"><p>可删除 {{ preview.eligible }} 项 · 受保护 {{ preview.protected }} 项</p><p>{{ preview.message }}</p><ul class="v3-delete-preview"><li v-for="item in preview.items" :key="item.id"><code>{{ item.id }}</code><strong>{{ item.status === 'eligible' ? '可删除' : '受保护' }}</strong><p>{{ item.reason || '执行时会再次核对保护条件' }}</p></li></ul><el-alert v-if="expired" title="预览已过期，请关闭后重新选择记录预览。" type="warning" :closable="false" /><el-checkbox v-model="confirmed" :disabled="busy || expired || preview.eligible < 1">确认删除以上可删除的部署历史及日志</el-checkbox></template>
  <template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="error" :title="error" type="error" :closable="false" /><span v-else>{{ busy ? '正在核对保护条件并处理请求…' : '受保护的记录会保留，任务执行结果可逐项查询。' }}</span></div><div class="v3-actions"><el-button :disabled="busy" @click="close">取消</el-button><el-button v-if="error && !preview" :disabled="busy" @click="open(retryRecords)">重试删除预览</el-button><el-button type="danger" :loading="busy" :disabled="!preview || !confirmed || expired || !preview.eligible" @click="submit">确认并创建删除任务</el-button></div></template>
 </el-dialog>
</template>

<style scoped>
.v3-delete-preview{padding:0;list-style:none}.v3-delete-preview li{padding:12px 0;border-bottom:1px solid var(--el-border-color-lighter)}.v3-delete-preview code{overflow-wrap:anywhere;margin-right:12px}:deep(.el-checkbox){height:auto;white-space:normal;align-items:flex-start}:deep(.el-checkbox__label){white-space:normal;line-height:1.6}
</style>
