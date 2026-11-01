<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import type { V3DeploymentHistoryDeleteJob } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'

const props = defineProps<{ id: string }>(), emit = defineEmits<{ finished: [] }>()
const { client } = useConsole(), read = useReadScope(), job = ref<V3DeploymentHistoryDeleteJob>()
const terminal = computed(() => !!job.value && ['succeeded', 'partial', 'cancelled'].includes(job.value.status))
const labels: Record<string, string> = { queued: '已排队', running: '处理中', succeeded: '已完成', partial: '部分完成', cancelled: '已取消', pending: '等待处理', deleted: '已删除', skipped: '已跳过', failed: '失败' }
let disposed = false, generation = 0, timer: ReturnType<typeof setTimeout> | undefined
async function load() {
 if (disposed || document.hidden || read.loading.value) return
 clearTimeout(timer); const current = generation
 await read.run(signal => client.deploymentHistoryDeleteJob(props.id, signal), value => {
  const wasTerminal = terminal.value
  job.value = value
  if (terminal.value && !wasTerminal) emit('finished')
 })
 if (!disposed && current === generation && !terminal.value && !document.hidden) timer = setTimeout(() => void load(), 3000)
}
function visibility() { generation++; clearTimeout(timer); if (document.hidden) read.cancel(); else void load() }
watch(() => props.id, () => { generation++; clearTimeout(timer); read.cancel(); job.value = undefined; void load() }, { immediate: true })
onMounted(() => document.addEventListener('visibilitychange', visibility))
onUnmounted(() => { disposed = true; generation++; clearTimeout(timer); document.removeEventListener('visibilitychange', visibility) })
</script>

<template>
 <el-alert v-if="read.error.value" :title="`${read.error.value}；已读取的进度保留`" type="error" :closable="false" />
 <p v-if="!job">{{ read.loading.value ? '正在读取删除任务…' : '尚未读取到任务，请重试' }}</p>
 <template v-else>
  <p class="v3-wrap">删除任务 {{ job.id }} · {{ labels[job.status] || '未知' }}</p>
  <p v-if="!terminal" class="v3-muted">每 3 秒更新；关闭页面不会停止任务，重新打开部署任务页可继续查看。</p>
  <p role="status">选中 {{ job.selected }} · 已删除 {{ job.deleted }} · 跳过 {{ job.skipped }} · 失败 {{ job.failed }}</p>
  <p>{{ job.message }}</p><p class="v3-muted">创建 {{ timeText(job.created_at) }} · 完成 {{ timeText(job.finished_at) }}</p>
  <ul class="v3-deployment-delete-items" aria-label="逐项部署历史删除结果"><li v-for="item in job.items || []" :key="item.id"><div><code>{{ item.id }}</code><el-tag :type="item.status === 'deleted' ? 'success' : item.status === 'failed' ? 'danger' : 'info'">{{ labels[item.status] || '未知' }}</el-tag></div><p>{{ item.reason || '等待工作器核对保护条件' }} · 删除日志 {{ item.deleted_logs }} 条</p></li></ul>
 </template>
 <el-button :loading="read.loading.value" @click="load">更新删除进度</el-button>
</template>

<style scoped>
.v3-deployment-delete-items{list-style:none;margin:18px 0;padding:0}.v3-deployment-delete-items li{padding:14px 0;border-bottom:1px solid #edf1f3}.v3-deployment-delete-items li>div{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.v3-deployment-delete-items code{font-size:12px;overflow-wrap:anywhere}.v3-deployment-delete-items p{margin:10px 0 0}
</style>
