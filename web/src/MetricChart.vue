<script setup lang="ts">
import { init, use, type ECharts } from 'echarts/core'
import type { EChartsOption } from 'echarts'
import { LineChart, BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { onMounted, onUnmounted, ref, watch } from 'vue'
use([LineChart, BarChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer])
const props = defineProps<{ option: EChartsOption; title: string }>()
const root = ref<HTMLElement>()
let chart: ECharts | undefined, observer: ResizeObserver | undefined
onMounted(() => { if (!root.value) return; chart = init(root.value); chart.setOption(props.option); observer = new ResizeObserver(() => chart?.resize()); observer.observe(root.value) })
watch(() => props.option, option => chart?.setOption(option, true), { deep: true })
onUnmounted(() => { observer?.disconnect(); chart?.dispose() })
</script>
<template><el-card shadow="never" class="metric-card"><h3>{{ title }}</h3><div ref="root" class="metric-chart" role="img" :aria-label="title" /></el-card></template>
<style scoped>.metric-chart{height:260px;width:100%}.metric-card h3{margin:0 0 10px}</style>
