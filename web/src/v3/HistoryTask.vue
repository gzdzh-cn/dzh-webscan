<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import type { V3HistoryJob, V3HistoryScope } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import { historyCategory, historyStatus } from './historyLabels'
const props = defineProps<{ id: string }>(), emit = defineEmits<{ finished: [] }>()
const { client } = useConsole(), read = useReadScope(), job = ref<V3HistoryJob>(), scope = ref<V3HistoryScope>()
const downloading = ref(false), error = ref('')
const terminal = computed(() => !!job.value && !['queued', 'running'].includes(job.value.status))
const downloadable = computed(() => !!job.value?.export_ready && !!job.value.export_expires_at && Date.parse(job.value.export_expires_at) > Date.now())
let disposed = false, generation = 0, scheduleGeneration = 0, timer: ReturnType<typeof setTimeout> | undefined, downloadController: AbortController | undefined
async function load() {
  if (disposed || document.hidden || read.loading.value) return
  clearTimeout(timer); const current = scheduleGeneration
  await read.run(signal => client.historyJob(props.id, signal), value => {
    const wasTerminal = terminal.value
    job.value = value.job; scope.value = value.scope
    if (terminal.value && !wasTerminal) emit('finished')
  })
  if (!disposed && current === scheduleGeneration && !terminal.value && !document.hidden) timer = setTimeout(() => void load(), 3000)
}
async function download() {
  if (!job.value || downloading.value || !downloadable.value) return
  downloading.value = true; error.value = ''; const current = generation, id = job.value.id
  try {
    const blob = await client.downloadHistory(id, (downloadController = new AbortController()).signal)
    if (disposed || current !== generation) return
    const url = URL.createObjectURL(blob), anchor = document.createElement('a'); anchor.href = url; anchor.download = `webscan-history-${id}.jsonl`; anchor.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  } catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '下载失败' }
  finally { if (!disposed && current === generation) downloading.value = false }
}
function visibility() { scheduleGeneration++; clearTimeout(timer); if (document.hidden) read.cancel(); else void load() }
watch(() => props.id, () => { generation++; scheduleGeneration++; clearTimeout(timer); read.cancel(); downloadController?.abort(); downloading.value = false; error.value = ''; job.value = undefined; scope.value = undefined; void load() }, { immediate: true })
onMounted(() => document.addEventListener('visibilitychange', visibility))
onUnmounted(() => { disposed = true; generation++; clearTimeout(timer); downloadController?.abort(); document.removeEventListener('visibilitychange', visibility) })
</script>
<template><el-alert v-if="read.error.value || error" :title="read.error.value || error" type="error" :closable="false" /><p v-if="!job">{{ read.loading.value ? '正在读取任务…' : '尚未读取到任务，请重试' }}</p><template v-else><p>任务 {{ job.id }}</p><p>{{ historyStatus(job.status) }} · {{ job.kind === 'export' ? '历史导出' : '历史清理' }} · {{ job.phase === 'export' ? '导出阶段' : job.phase === 'cleanup' ? '清理阶段' : '处理结束' }}</p><p v-if="!terminal" class="v3-muted">每 3 秒更新。关闭页面不会停止任务；可从本账号历史任务中继续查看。</p><dl class="v3-detail-grid"><dt>处理数量</dt><dd>已扫描 {{ job.scanned }} · 已清理 {{ job.deleted }} · 跳过 {{ job.skipped }} · 已导出 {{ job.exported }}</dd><dt>关联记录清理</dt><dd>{{ job.dependent_deleted }}</dd><dt>结果说明</dt><dd>{{ job.message || '—' }}</dd><dt>创建 / 完成</dt><dd>{{ timeText(job.created_at) }} / {{ timeText(job.finished_at) }}</dd><template v-if="scope"><dt>固定范围</dt><dd>{{ scope.categories.map(historyCategory).join('、') }}；{{ scope.node || '全部服务器' }}；截止 {{ timeText(scope.before) }}；{{ scope.include_probes ? '包含探针' : '不包含探针' }}<template v-if="scope.records">；明确选中 {{ scope.records.length }} 条</template></dd></template><dt>导出有效期</dt><dd>{{ timeText(job.export_expires_at) }}（最长保留 24 小时）</dd></dl><el-button v-if="downloadable" :loading="downloading" @click="download">下载 JSONL</el-button><p v-else-if="job.export_ready" class="v3-muted">导出已过期，请重新预览并导出。</p></template><el-button :loading="read.loading.value" @click="load">更新任务状态</el-button></template>
