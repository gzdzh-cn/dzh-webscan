<script setup lang="ts">
import type { Recovery } from './monitoring'
defineProps<{ recovery?:Recovery }>()
</script>
<template><el-alert v-if="recovery?.pending || recovery?.running" type="warning" :closable="false" title="有部署任务需要关注"><p>{{recovery.scope}} · {{recovery.running?'正在执行':'尚未完成'}}。{{recovery.reason}}</p><router-link :to="recovery.job_id ? `/deployments/${recovery.job_id}` : '/deployments'">{{recovery.can_resume?'查看并继续原任务':'查看任务进度'}} →</router-link></el-alert></template>
