<script setup lang="ts">
withDefaults(defineProps<{ previous: boolean; next: boolean; limit: number; loading?: boolean; page?: number }>(), { loading: false })
defineEmits<{ previous: []; next: []; resize: [limit: number] }>()
</script>

<template>
  <div class="cursor-pagination v3-pagination" aria-label="列表分页">
    <el-select :model-value="limit" :disabled="loading" aria-label="每页条数" @update:model-value="$emit('resize', Number($event))"><el-option v-for="size in [20, 50, 100]" :key="size" :value="size" :label="`${size} 条／页`" /></el-select>
    <el-button :disabled="!previous || loading" @click="$emit('previous')">上一页</el-button><span v-if="page">第 {{ page }} 页</span><el-button :disabled="!next || loading" @click="$emit('next')">下一页</el-button>
  </div>
</template>
