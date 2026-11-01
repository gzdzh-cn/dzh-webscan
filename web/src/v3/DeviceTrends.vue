<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import type { EChartsOption } from 'echarts'
import type { V3DeviceTrends, V3MetricDevice } from '../controlV3'
import MetricChart from '../MetricChart.vue'
import { metricValue } from '../charts'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
const props = defineProps<{ node: string; start: string; end: string }>()
const { client } = useConsole(), inventory = useReadScope(), history = useReadScope()
const items = ref<V3MetricDevice[]>([]), chosen = ref<string[]>([]), known = ref<Record<string,V3MetricDevice>>({}), truncated = ref(false)
const result = ref<V3DeviceTrends>(), error = ref(''), applied = ref('')
const disks = computed(() => items.value.filter(item => item.kind === 'disk')), networks = computed(() => items.value.filter(item => item.kind === 'network'))
const selected = (kind: 'disk'|'network') => chosen.value.filter(id => known.value[id]?.kind === kind)
const options = (kind: 'disk'|'network') => Object.values(known.value).filter(item => item.kind === kind && (items.value.some(current => current.id === item.id) || chosen.value.includes(item.id)))
const missing = computed(() => chosen.value.filter(id => !items.value.some(item => item.id === id)).map(id => known.value[id]?.name || id))
const signature = computed(() => JSON.stringify([props.node,props.start,props.end,chosen.value]))
const stale = computed(() => !!result.value && applied.value !== signature.value)
const names: Record<string,string> = { disk_read:'读取',disk_write:'写入',disk_read_iops:'读取 IOPS',disk_write_iops:'写入 IOPS',net_receive:'接收',net_transmit:'发送',net_receive_errors:'接收错误',net_transmit_errors:'发送错误',net_receive_drops:'接收丢包',net_transmit_drops:'发送丢包' }
const groups = [ { title:'设备磁盘读写速率',metrics:['disk_read','disk_write'],unit:'B/s' },{ title:'设备磁盘 IOPS',metrics:['disk_read_iops','disk_write_iops'],unit:'次/s' },{ title:'设备网络收发速率',metrics:['net_receive','net_transmit'],unit:'B/s' },{ title:'设备网络错误与丢包速率',metrics:['net_receive_errors','net_transmit_errors','net_receive_drops','net_transmit_drops'],unit:'次/s' } ]
const charts = computed(() => groups.flatMap(group => {
 const series = result.value?.series.filter(series => group.metrics.includes(series.metric) && chosen.value.includes(series.device_id) && items.value.some(item => item.id === series.device_id)) || []
 if (!series.length) return []
 const option: EChartsOption = { tooltip:{trigger:'axis',valueFormatter:value=>metricValue(typeof value === 'number'?value:undefined,group.unit)},legend:{type:'scroll',bottom:0},grid:{left:65,right:20,top:20,bottom:60},xAxis:{type:'time',splitNumber:3,axisLabel:{hideOverlap:true,formatter:value=>new Intl.DateTimeFormat('zh-CN',{timeZone:'Asia/Shanghai',hour:'2-digit',minute:'2-digit'}).format(value)}},yAxis:{type:'value',axisLabel:{formatter:value=>metricValue(Number(value),group.unit)}},series:series.map(series=>({ name:`${known.value[series.device_id]?.name || '未知设备'} · ${names[series.metric] || '未知指标'}`,type:'line',showSymbol:false,connectNulls:false,smooth:false,data:(result.value?.points || []).map(point=>{const value=point.values[series.key];return [point.time*1000,point.ok && typeof value === 'number' && Number.isFinite(value)?value:null]}) })) }
 return [{ title:group.title,option }]
}))
let disposed = false, previousNode = '', timer: ReturnType<typeof setTimeout> | undefined
function validRange() { const start=Date.parse(props.start),end=Date.parse(props.end);return props.node && Number.isFinite(start) && Number.isFinite(end) && end>start && end-start<=31*86400_000 }
function schedule() { clearTimeout(timer); if (!disposed && !document.hidden && chosen.value.length) timer=setTimeout(()=>void loadHistory(),30_000) }
async function loadHistory() {
 if (disposed || document.hidden || !validRange() || inventory.loading.value || history.loading.value) return
 const devices=chosen.value.filter(id=>items.value.some(item=>item.id===id)), key=signature.value
 clearTimeout(timer)
 if (!devices.length) { history.cancel(); result.value=undefined; applied.value=key; return }
 await history.run(async signal=>{const value=await client.deviceMetrics(props.node,devices,props.start,props.end,signal);if(value.points.length>1000 || value.series.length>64)throw Error('设备历史响应超过限制，未更新曲线');return value},value=>{result.value=value;applied.value=key})
 schedule()
}
async function loadInventory() {
 clearTimeout(timer);history.cancel();inventory.cancel()
 if (disposed || document.hidden || !validRange()) return
 let loaded=false
 await inventory.run(signal=>client.metricDevices(props.node,props.start,props.end,signal),value=>{items.value=value.items;truncated.value=value.truncated;for(const item of value.items)known.value[item.id]=item;loaded=true})
 if (loaded) void loadHistory()
}
function selectDevices(kind:'disk'|'network',ids:string[]) {
 const allowed=new Set(options(kind).map(item=>item.id)),next=[...chosen.value.filter(id=>known.value[id]?.kind!==kind),...ids]
 if (next.length>8 || new Set(next).size!==next.length || ids.some(id=>!allowed.has(id))) { error.value='磁盘与网卡合计最多选择 8 个服务端清单中的设备。';return }
 chosen.value=next;error.value='';history.cancel();void loadHistory()
}
function clear() { chosen.value=[];result.value=undefined;history.cancel();clearTimeout(timer);error.value='' }
function visibility() { if(document.hidden){clearTimeout(timer);inventory.cancel();history.cancel()}else void loadInventory() }
watch(()=>[props.node,props.start,props.end],()=>{inventory.cancel();history.cancel();error.value='';if(previousNode!==props.node){chosen.value=[];known.value={};items.value=[];result.value=undefined;previousNode=props.node}void loadInventory()},{immediate:true})
onMounted(()=>document.addEventListener('visibilitychange',visibility))
onUnmounted(()=>{disposed=true;clearTimeout(timer);document.removeEventListener('visibilitychange',visibility)})
defineExpose({ selectDevices })
</script>
<template>
 <el-card shadow="never" class="device-history"><div class="card-heading"><h3>磁盘与网卡设备历史</h3><el-button :loading="inventory.loading.value || history.loading.value" @click="loadInventory">刷新设备历史</el-button></div><p class="v3-muted">从服务端所选时段清单选择设备，磁盘与网卡合计最多 8 个。上方汇总曲线保持不变；分设备历史从本版启用后开始记录。</p>
  <el-alert v-if="inventory.error.value" :title="`${inventory.error.value}；已有清单及曲线保留。`" type="error" :closable="false" /><el-alert v-if="history.error.value" :title="`${history.error.value}；保留上一次曲线。`" type="error" :closable="false" /><el-alert v-if="error" :title="error" type="warning" :closable="false" />
  <div class="filters device-filters"><el-select :model-value="selected('disk')" multiple :multiple-limit="8" collapse-tags collapse-tags-tooltip aria-label="磁盘设备" placeholder="选择磁盘设备" :loading="inventory.loading.value" :disabled="inventory.loading.value" @update:model-value="selectDevices('disk',$event)"><el-option v-for="item in options('disk')" :key="item.id" :value="item.id" :label="`${item.name}${items.some(current=>current.id===item.id)?'':'（此时段未发现）'}`" :disabled="!chosen.includes(item.id) && chosen.length>=8" /></el-select><el-select :model-value="selected('network')" multiple :multiple-limit="8" collapse-tags collapse-tags-tooltip aria-label="网卡设备" placeholder="选择网卡设备" :loading="inventory.loading.value" :disabled="inventory.loading.value" @update:model-value="selectDevices('network',$event)"><el-option v-for="item in options('network')" :key="item.id" :value="item.id" :label="`${item.name}${items.some(current=>current.id===item.id)?'':'（此时段未发现）'}`" :disabled="!chosen.includes(item.id) && chosen.length>=8" /></el-select><span class="v3-muted">已选 {{ chosen.length }} / 8</span><el-button :disabled="!chosen.length" @click="clear">清除设备选择</el-button></div>
  <p v-if="truncated" class="v3-muted">服务端设备清单已截断，当前仅显示返回的设备，未列出设备不代表不存在。</p><p v-if="missing.length" class="v3-muted">所选时段未发现：{{ missing.join('、') }}。保留选择，不查询这些设备，也不填零。</p>
  <p v-if="chosen.length" class="device-selected">当前设备：{{ chosen.map(id=>known[id]?.name || '未知设备').join('、') }}</p><p v-if="result" class="v3-muted">{{ timeText(result.start*1000) }} ～ {{ timeText(result.end*1000) }} · 精度 {{ result.resolution_seconds }} 秒。断线、设备消失及计数重置留空。</p><el-alert v-if="stale" title="正在读取新的设备或时段；下方暂时保留上一次结果。" type="info" :closable="false" />
  <el-empty v-if="!chosen.length" :description="inventory.loading.value?'正在读取设备清单…':!disks.length && !networks.length?'所选时段尚无设备历史；未提供的数据不会补零':'请选择设备查看历史曲线'" /><el-empty v-else-if="!charts.length && !history.loading.value" description="所选设备在此时段尚无可用历史；缺失数据留空" />
 </el-card>
 <div v-if="charts.length" class="chart-grid"><MetricChart v-for="chart in charts" :key="chart.title" :title="chart.title" :option="chart.option" /></div>
</template>
<style scoped>
.device-filters { align-items: center; }
.device-filters .el-select { min-width: 220px; flex: 1; }
.device-selected { overflow-wrap: anywhere; }
@media(max-width:600px){ .device-filters { flex-direction:column;align-items:stretch; }.device-filters .el-select { min-width:0;width:100%; }.card-heading { flex-wrap:wrap;gap:8px; } }
</style>
