<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import type { V3AuditRecord } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
const { client } = useConsole(), read = useReadScope()
const draft = reactive({ actor: '', kind: '', days: 1 }), rows = ref<V3AuditRecord[]>([]), detail = ref<V3AuditRecord>()
const cursor = ref(''), next = ref(''), previous = ref<string[]>([]), loaded = ref(false)
let submitted = { actor: '', kind: '', start: '', end: '' }
async function load() {
  await read.run(signal => client.audit({ ...submitted, cursor: cursor.value, limit: 20 }, signal), page => {
    rows.value = page.items; next.value = page.next_cursor; loaded.value = true
    if (!page.items.length && cursor.value) { cursor.value = previous.value.pop() || ''; void load() }
  })
}
function search() {
  const end = new Date(); submitted = { actor: draft.actor.trim(), kind: draft.kind.trim(), start: new Date(end.getTime() - draft.days * 86400_000).toISOString(), end: end.toISOString() }
  cursor.value = ''; previous.value = []; void load()
}
function page(forward: boolean) { if (forward) { previous.value.push(cursor.value); cursor.value = next.value } else cursor.value = previous.value.pop() || ''; void load() }
onMounted(search)
</script>
<template><el-card shadow="never"><h2>操作审计</h2><p class="v3-muted">只读，按 365 天保留。每次查询最多 31 天；非管理员仅可查看本账号及系统记录。结果只展示服务端允许的摘要。</p><form class="v3-event-filters" @submit.prevent="search"><el-input v-model="draft.actor" aria-label="操作账号" placeholder="操作账号（可选）" clearable /><el-input v-model="draft.kind" aria-label="审计操作类型" placeholder="操作类型（可选）" clearable /><el-select v-model="draft.days" aria-label="审计时间范围"><el-option v-for="days in [1, 7, 30]" :key="days" :value="days" :label="`最近 ${days} 天`" /></el-select><el-button native-type="submit" :loading="read.loading.value">查询审计</el-button></form><el-alert v-if="read.error.value" :title="`${read.error.value}；保留上次结果`" type="error" :closable="false" /><el-table :data="rows" :empty-text="read.loading.value ? '正在读取…' : read.error.value ? '审计读取失败' : loaded ? '当前查询无审计记录' : '尚未查询'"><el-table-column label="时间" min-width="175"><template #default="{ row }">{{ timeText(row.created_at) }}</template></el-table-column><el-table-column prop="username" label="账号" width="110" /><el-table-column prop="kind" label="操作" min-width="180" /><el-table-column prop="resource" label="对象" min-width="170" /><el-table-column label="结果" width="110"><template #default="{ row }"><el-button link type="primary" @click="detail = row">查看摘要</el-button></template></el-table-column></el-table><div class="v3-pagination"><el-button :disabled="!cursor || read.loading.value" @click="page(false)">上一页</el-button><span>每页 20 条</span><el-button :disabled="!next || read.loading.value" @click="page(true)">下一页</el-button></div></el-card><el-dialog :model-value="!!detail" title="审计摘要" class="v3-node-dialog" width="650px" @update:model-value="detail = undefined"><template v-if="detail"><p>{{ detail.kind }} · {{ detail.username }} · {{ timeText(detail.created_at) }}</p><p>对象：{{ detail.resource }}</p><pre class="v3-event-json">{{ JSON.stringify(detail.result, null, 2) }}</pre><p class="v3-muted">{{ detail.delete_reason }}</p></template><template #footer><el-button @click="detail = undefined">关闭</el-button></template></el-dialog></template>
