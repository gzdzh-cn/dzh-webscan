<script setup lang="ts">
import { nextTick, onUnmounted, ref } from 'vue'
import type { V3Node } from '../controlV3'
import { useConsole } from './context'
import DeploymentFlow from './DeploymentFlow.vue'

const emit = defineEmits<{ job: [id: string] }>()
const { session } = useConsole()
const visible = ref(false), node = ref<V3Node>(), busy = ref(false), message = ref(''), failed = ref(false)
const flow = ref<InstanceType<typeof DeploymentFlow>>()
let generation = 0, disposed = false
async function open(value: V3Node) {
 if (busy.value || session.value?.role !== 'admin' || value.can_uninstall !== true) return
 const current = ++generation
 node.value = { ...value }; message.value = ''; failed.value = false; visible.value = true
 await nextTick()
 if (!disposed && visible.value && current === generation) await flow.value?.begin()
}
function created(id: string) { visible.value = false; emit('job', id) }
function closed() { if (!visible.value) { generation++; node.value = undefined; busy.value = false; message.value = ''; failed.value = false } }
onUnmounted(() => { disposed = true; generation++ })
defineExpose({ open })
</script>

<template>
 <el-dialog v-model="visible" title="卸载子控" width="720px" class="v3-node-dialog" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @closed="closed">
  <p v-if="node">{{ node.name }} · {{ node.id }}</p>
  <p class="v3-muted">按实际安装资料操作；不保存编辑草稿，也不应用尚未下发的新地址或部署方式。</p>
  <DeploymentFlow v-if="visible && node" ref="flow" :node="node" operation="uninstall" @busy="busy = $event" @status="(text, error) => { message = text; failed = error }" @job="created" />
  <template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="failed" :title="message" type="error" :closable="false" /><span v-else>{{ message || '卸载保留子控数据、证书、中心记录和历史。' }}</span></div><div class="v3-actions"><el-button :disabled="busy" @click="visible = false">关闭</el-button><el-button :loading="busy" @click="flow?.begin()">重新检查卸载条件</el-button></div></template>
 </el-dialog>
</template>
