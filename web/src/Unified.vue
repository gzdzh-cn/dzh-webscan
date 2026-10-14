<script setup lang="ts">
import { computed, defineAsyncComponent } from 'vue'
import { useRoute } from 'vue-router'
const route = useRoute()
const Dashboard = defineAsyncComponent(() => import('./Dashboard.vue'))
const Servers = defineAsyncComponent(() => import('./Servers.vue'))
const Activity = defineAsyncComponent(() => import('./Activity.vue'))
const Settings = defineAsyncComponent(() => import('./SystemSettings.vue'))
const Deployments = defineAsyncComponent(() => import('./Deployments.vue'))
const ConfigBackups = defineAsyncComponent(() => import('./ConfigBackups.vue'))
const path = computed(() => route.path)
</script>
<template><Dashboard v-if="path === '/'" /><Servers v-else-if="path.startsWith('/servers')" /><Activity v-else-if="path === '/alerts' || path === '/events'" :key="path" :events="path === '/events'" /><Settings v-else-if="path === '/settings'" /><Deployments v-else-if="path.startsWith('/deployments')" /><ConfigBackups v-else-if="path === '/config-backups'" /></template>
