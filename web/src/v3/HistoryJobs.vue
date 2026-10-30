<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch } from 'vue'
import type { V3HistoryJob, V3RetentionJob } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import { historyStatus } from './historyLabels'
import HistoryTask from './HistoryTask.vue'
const props = defineProps<{ revision?: number }>()
const { client } = useConsole(), read = useReadScope(), mode = ref<'manual' | 'automatic'>('manual')
const rows = ref<(V3HistoryJob | V3RetentionJob)[]>([]), next = ref(''), cursor = ref(''), previous = ref<string[]>([]), loaded = ref(false), detail = ref('')
let disposed = false, generation = 0, timer: ReturnType<typeof setTimeout> | undefined
async function load(replace = false) {
  if (disposed || document.hidden || read.loading.value && !replace) return
  clearTimeout(timer); const current = ++generation, kind = mode.value, after = cursor.value
  await read.run<{ items: (V3HistoryJob | V3RetentionJob)[]; next_cursor: string }>(signal => kind === 'manual' ? client.historyJobs(after, 20, signal) : client.retentionJobs(after, 20, signal), value => {
    rows.value = value.items; next.value = value.next_cursor; loaded.value = true
    if (!value.items.length && after) { cursor.value = previous.value.pop() || ''; void load(true) }
  })
  if (!disposed && current === generation && !document.hidden && rows.value.some(value => ['queued', 'running'].includes(value.status))) timer = setTimeout(() => void load(), 3000)
}
function page(forward: boolean) { if (forward) { previous.value.push(cursor.value); cursor.value = next.value } else cursor.value = previous.value.pop() || ''; void load(true) }
function reset() { generation++; read.cancel(); clearTimeout(timer); rows.value = []; next.value = ''; cursor.value = ''; previous.value = []; loaded.value = false; detail.value = ''; void load(true) }
function visibility() { clearTimeout(timer); if (document.hidden) { generation++; read.cancel() } else void load(true) }
watch(mode, reset)
watch(() => props.revision, () => { cursor.value = ''; previous.value = []; void load(true) })
onMounted(() => { document.addEventListener('visibilitychange', visibility); void load() })
onUnmounted(() => { disposed = true; generation++; clearTimeout(timer); document.removeEventListener('visibilitychange', visibility) })
</script>
<template><el-card shadow="never"><div class="card-heading v3-job-heading"><h2>清理与导出记录</h2><el-button :loading="read.loading.value" @click="load(true)">刷新任务列表</el-button></div><div class="v3-alert-tabs"><el-button :type="mode === 'manual' ? 'primary' : 'default'" @click="mode = 'manual'">本账号手动任务</el-button><el-button :type="mode === 'automatic' ? 'primary' : 'default'" @click="mode = 'automatic'">自动清理记录</el-button></div><p class="v3-muted">记录只读。任务创建不代表处理完成，失败或部分完成时请查看实际数量。</p><el-alert v-if="read.error.value" :title="`${read.error.value}；保留上次结果`" type="error" :closable="false" /><el-table :data="rows" :empty-text="read.loading.value ? '正在读取…' : read.error.value ? '任务读取失败' : loaded ? '暂无任务' : '尚未查询'"><el-table-column label="创建时间" min-width="170"><template #default="{ row }">{{ timeText(row.created_at) }}</template></el-table-column><el-table-column label="状态" min-width="95"><template #default="{ row }">{{ historyStatus(row.status) }}</template></el-table-column><el-table-column label="扫描 / 清理" min-width="110"><template #default="{ row }">{{ row.scanned }} / {{ row.deleted }}</template></el-table-column><el-table-column :label="mode === 'manual' ? '跳过 / 导出' : '受保护 / 关联清理'" min-width="140"><template #default="{ row }">{{ mode === 'manual' ? `${row.skipped} / ${row.exported}` : `${row.protected} / ${row.dependent_deleted}` }}</template></el-table-column><el-table-column label="说明" min-width="200"><template #default="{ row }">{{ row.message || '—' }}</template></el-table-column><el-table-column v-if="mode === 'manual'" label="查看" width="100"><template #default="{ row }"><el-button link type="primary" @click="detail = row.id">任务详情</el-button></template></el-table-column></el-table><div class="v3-pagination"><el-button :disabled="!cursor || read.loading.value" @click="page(false)">上一页</el-button><span>每页 20 条</span><el-button :disabled="!next || read.loading.value" @click="page(true)">下一页</el-button></div></el-card><el-dialog :model-value="!!detail" title="历史任务详情" class="v3-node-dialog" width="720px" @update:model-value="detail = ''"><HistoryTask v-if="detail" :key="detail" :id="detail" @finished="load(true)" /><template #footer><el-button @click="detail = ''">关闭</el-button></template></el-dialog></template>
