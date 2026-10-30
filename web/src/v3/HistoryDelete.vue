<script setup lang="ts">
import { computed, onUnmounted, ref } from 'vue'
import type { V3HistoryCategory, V3HistoryJob, V3HistoryPreview } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'

type RecordRef = { record_key: string; can_delete: boolean; delete_reason: string }
const props = defineProps<{ records: RecordRef[]; categories: V3HistoryCategory[]; label: string }>()
const emit = defineEmits<{ done: [] }>()
const { client } = useConsole(), read = useReadScope()
const visible = ref(false), selected = ref<string[]>([]), preview = ref<V3HistoryPreview>(), job = ref<V3HistoryJob>()
const busy = ref(false), downloading = ref(false), error = ref(''), exportFirst = ref(true)
const jobLabels: Record<string, string> = { succeeded: '已完成', partial: '部分完成', cancelled: '已取消', failed: '失败' }
const terminal = computed(() => !!job.value && !['queued', 'running'].includes(job.value.status))
let generation = 0, disposed = false, timer: ReturnType<typeof setTimeout> | undefined, key = '', intent = ''
let downloadController: AbortController | undefined
function cancelRead() { generation++; read.cancel(); clearTimeout(timer) }
async function open(records = props.records) {
  if (busy.value || records.length < 1 || records.length > 200 || records.some(value => !value.can_delete)) return
  cancelRead(); const current = generation
  selected.value = records.map(value => value.record_key); preview.value = undefined; job.value = undefined
  error.value = ''; exportFirst.value = true; visible.value = true; busy.value = true; key = ''; intent = ''
  try {
    const value = await client.previewHistory({ categories: [...props.categories], records: [...selected.value], include_probes: true })
    if (!disposed && generation === current) preview.value = value
  } catch (e) { if (!disposed && generation === current) error.value = e instanceof Error ? e.message : '预览失败' }
  finally { if (!disposed && generation === current) busy.value = false }
}
defineExpose({ open })
async function poll() {
  if (!job.value || disposed || !visible.value || terminal.value) return
  const current = generation
  await read.run(signal => client.historyJob(job.value!.id, signal), value => {
    job.value = value.job
    if (terminal.value) emit('done')
  })
  if (!disposed && current === generation && visible.value && !terminal.value) timer = setTimeout(() => void poll(), 3000)
}
async function execute() {
  if (busy.value || !preview.value || job.value) return
  busy.value = true; error.value = ''; const current = generation
  const body = JSON.stringify({ token: preview.value.token, exportFirst: exportFirst.value })
  if (intent !== body) { intent = body; key = crypto.randomUUID() }
  try {
    const value = await client.cleanupHistory(preview.value.token, { export_first: exportFirst.value, confirm_without_export: !exportFirst.value }, key)
    if (disposed || generation !== current) return
    job.value = value
    if (terminal.value) emit('done'); else void poll()
  } catch (e) { if (!disposed && generation === current) error.value = e instanceof Error ? e.message : '删除任务提交失败' }
  finally { if (!disposed && generation === current) busy.value = false }
}
async function download() {
  if (!job.value || downloading.value) return
  downloading.value = true; error.value = ''; const current = generation
  try {
    downloadController = new AbortController()
    const file = await client.downloadHistory(job.value.id, downloadController.signal)
    if (disposed || current !== generation) return
    const url = URL.createObjectURL(file), anchor = document.createElement('a')
    anchor.href = url; anchor.download = `webscan-history-${job.value.id}.jsonl`; anchor.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  } catch (e) { if (!disposed && generation === current) error.value = e instanceof Error ? e.message : '下载失败' }
  finally { if (!disposed && generation === current) downloading.value = false }
}
function closed() { cancelRead(); downloadController?.abort(); downloading.value = false }
onUnmounted(() => { disposed = true; cancelRead(); downloadController?.abort() })
</script>

<template>
  <el-button type="danger" :disabled="!records.length || busy" @click="open()">删除已选（{{ records.length }}）</el-button>
  <el-dialog v-model="visible" :title="`删除${label}`" class="v3-node-dialog" width="620px" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @closed="closed">
    <p>仅处理当前页明确选择的 {{ selected.length }} 条{{ label }}，不会删除全部筛选结果。</p><p>永久删除不能撤销。最近 24 小时、当前异常和未完成任务仍受保护；执行时会再次检查。删除记录不会立即释放磁盘空间。</p>
    <p v-if="preview">预览：可删除 {{ preview.eligible }} 条，受保护 {{ preview.protected }} 条；有效至 {{ timeText(preview.expires_at) }}。</p>
    <el-checkbox v-if="!job" v-model="exportFirst" :disabled="busy">先导出 JSONL，导出成功后再删除</el-checkbox>
    <template v-if="job"><p>任务 {{ job.id }}</p><p v-if="!terminal">{{ job.phase === 'export' ? '正在导出' : job.phase === 'cleanup' ? '正在删除' : '排队中' }}，每 3 秒更新；关闭弹窗不会停止任务。</p><el-alert v-else :type="job.status === 'succeeded' ? 'success' : 'warning'" :closable="false" :title="`状态：${jobLabels[job.status] || job.status}；已删除 ${job.deleted} 条，跳过 ${job.skipped} 条，已导出 ${job.exported} 条。${job.message || ''}`" /><p v-if="job.export_ready">导出保留至 {{ timeText(job.export_expires_at) }}。</p><el-button v-if="job.export_ready" :loading="downloading" @click="download">下载 JSONL</el-button></template>
    <template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="error || read.error.value" :title="error || read.error.value" type="error" :closable="false" /><span v-else-if="busy">{{ preview ? '正在创建删除任务…' : '正在检查删除保护…' }}</span></div><div class="v3-actions"><el-button :disabled="busy" @click="visible = false">{{ job ? '关闭' : '取消' }}</el-button><el-button v-if="!job" type="danger" :loading="busy" :disabled="!preview || !preview.eligible" @click="execute">{{ exportFirst ? '导出并删除' : '确认不导出，永久删除' }}</el-button></div></template>
  </el-dialog>
</template>
