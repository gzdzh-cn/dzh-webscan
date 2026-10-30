<script setup lang="ts">
import type { RouteLocationRaw } from 'vue-router'
defineProps<{ title: string; description?: string; back?: RouteLocationRaw; backLabel?: string }>()
</script>

<template>
  <div class="page-heading v3-page-heading">
    <div><span class="eyebrow">WEBSITE MONITOR</span><h1>{{ title }}</h1><p class="muted">{{ description || '服务器资源、网站可用性、文件安全与告警投递。' }}</p></div>
    <div v-if="back || $slots.default" class="v3-actions page-heading-actions"><router-link v-if="back" :to="back"><el-button>{{ backLabel || '返回列表' }}</el-button></router-link><slot /></div>
  </div>
</template>
