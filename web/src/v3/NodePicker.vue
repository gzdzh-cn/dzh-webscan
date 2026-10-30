<script setup lang="ts">
import { onMounted, ref } from 'vue'
import type { V3Node } from '../controlV3'
import { useConsole } from './context'
import { useReadScope } from './readScope'
defineProps<{ modelValue: string; disabled?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()
const { client } = useConsole(), read = useReadScope(), nodes = ref<V3Node[]>([])
async function search(q: string) { await read.run(signal => client.servers(q, '', 50, signal), page => { nodes.value = page.items }) }
onMounted(() => void search(''))
</script>
<template><div class="v3-node-picker"><el-select :model-value="modelValue" aria-label="服务器范围" placeholder="全部服务器" clearable filterable remote :remote-method="search" :loading="read.loading.value" :disabled="disabled" @update:model-value="emit('update:modelValue', $event || '')"><el-option v-if="modelValue && !nodes.some(node => node.id === modelValue)" :value="modelValue" :label="modelValue" /><el-option v-for="node in nodes" :key="node.id" :value="node.id" :label="`${node.name} (${node.id})`" /></el-select><small v-if="read.error.value" role="status">服务器选项读取失败，可重试搜索；当前范围保留。</small></div></template>
