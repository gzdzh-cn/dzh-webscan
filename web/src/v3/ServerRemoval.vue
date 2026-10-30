<script setup lang="ts">
import { onUnmounted, ref } from 'vue'
import type { V3Node } from '../controlV3'
import { useConsole } from './context'

const emit = defineEmits<{ done: [message: string] }>()
const { client, session } = useConsole()
const visible = ref(false), busy = ref(false), error = ref(''), confirmed = ref(false), records = ref<V3Node[]>([])
let disposed = false, generation = 0, key = ''
function open(values: V3Node[]) {
  if (busy.value || session.value?.role !== 'admin' || !values.length || values.length > 200 || values.some(value => !value.can_remove)) return
  generation++; records.value = values.map(value => ({ ...value })); confirmed.value = false; error.value = ''; key = crypto.randomUUID(); visible.value = true
}
async function remove() {
  if (busy.value || !confirmed.value || !visible.value) return
  const current = generation
  busy.value = true; error.value = ''
  try {
    const result = await client.removeServerRecords(records.value.map(value => ({ id: value.id, expected_version: value.version })), key)
    if (disposed || generation !== current) return
    visible.value = false; emit('done', result.message)
  } catch (e) { if (!disposed && generation === current) error.value = e instanceof Error ? e.message : '移除失败，原记录保留' }
  finally { if (!disposed && generation === current) busy.value = false }
}
function closed() { generation++; error.value = ''; confirmed.value = false }
onUnmounted(() => { disposed = true; generation++ })
defineExpose({ open })
</script>

<template>
  <el-dialog v-model="visible" title="移除服务器记录" width="620px" class="v3-node-dialog" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @closed="closed">
    <el-alert title="仅从中心移除记录并停止采集，不会连接服务器或卸载远程程序。历史事件、指标和任务记录保留。" type="warning" :closable="false" />
    <ul><li v-for="record in records" :key="record.id">{{ record.name }} · {{ record.endpoint }} · {{ record.id }}</li></ul>
    <p class="muted">移除后该节点 ID 留作历史关联，不能重复添加；重新接入请使用新的节点 ID。</p>
    <el-checkbox v-model="confirmed" :disabled="busy">确认移除以上 {{ records.length }} 台服务器记录，远程程序由我另行处理</el-checkbox>
    <template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="error" :title="error" type="error" :closable="false" /><span v-else-if="busy">正在检查关联和任务、备份配置并移除记录…</span></div><div class="v3-actions"><el-button :disabled="busy" @click="visible = false">取消</el-button><el-button type="danger" :loading="busy" :disabled="!confirmed" @click="remove">确认移除记录</el-button></div></template>
  </el-dialog>
</template>

<style scoped>
li { margin: .5rem 0; overflow-wrap: anywhere; }
:deep(.el-checkbox) { height: auto; align-items: flex-start; white-space: normal; }
:deep(.el-checkbox__label) { white-space: normal; overflow-wrap: anywhere; line-height: 1.6; }
</style>
