<script setup lang="ts">
import { computed, markRaw, onMounted, onUnmounted, ref } from 'vue'
import { Monitor, Cpu, Document, FirstAidKit, Connection, Link, Coin, Bell, Message, Setting, Warning, FolderOpened, List, CircleCheck, CircleClose, QuestionFilled, Remove } from '@element-plus/icons-vue'
import { api, beijingTime } from './api'
import MetricChart from './MetricChart.vue'
import { rankingOption, metricValue } from './charts'
import { errorMessage, statusLabel, type Server, type Alert } from './monitoring'
interface Component { id:string; name:string; status:string; reason:string; href:string; updated:number; metrics:Record<string,unknown> }
interface Dashboard { release?:string; updated?:number; started?:number; servers:Server[]; components:Component[]; errors:Record<string,string>; [key:string]:unknown }
const data=ref<Dashboard>({servers:[],components:[],errors:{}}), alerts=ref<Alert[]>([]), error=ref(''), alertError=ref(''), loaded=ref(false), loading=ref(false)
const icons=Object.fromEntries(Object.entries({receiver:Monitor,metrics:Cpu,files:Document,scanner:FirstAidKit,transport:Connection,websites:Link,database:Coin,feishu:Bell,email:Message,manager:Setting,watchdog:Warning,maintenance:FolderOpened,deployment:List}).map(([k,v])=>[k,markRaw(v)]))
const labels:Record<string,string>={normal:'正常',abnormal:'异常',unknown:'未知',disabled:'已停用',unmanaged:'未接管',maintenance:'维护中'}
const display=(v:unknown)=>v===undefined||v===null||v===''?'—':typeof v==='boolean'?v?'开启 / 执行中':'关闭 / 空闲':String(v)
function componentValue(key:string,v:unknown){if(v===undefined||v===null||v==='')return '—';if(typeof v==='boolean')return key==='正在执行'?(v?'执行中':'空闲'):key==='调度正常'?(v?'正常':'异常'):key==='配置应用'?(v?'可用':'不可用'):(v?'开启':'关闭');if(key.includes('字节')&&typeof v==='number')return `${(v/1048576).toFixed(2)} MiB`;if(key.includes('时间')&&typeof v==='number')return v>0?beijingTime(v):'—';if(typeof v==='string'&&(labels[v]||['complete','failed','running','pending','interrupted'].includes(v)))return labels[v]||statusLabel(v);return String(v)}
const summaries=computed(()=>[
 {label:'服务器采集',value:`${display(data.value.server_normal)} 正常 / ${display(data.value.server_abnormal)} 异常`,hint:`共 ${display(data.value.server_total)} 台，未知 ${display(data.value.server_unknown)} 台`,href:'/servers'},
 {label:'网站状态',value:`${display(data.value.website_normal)} 正常 / ${display(data.value.website_down)} 异常`,hint:`共 ${display(data.value.website_total)} 个，暂停 ${display(data.value.website_paused)} 个，待检查 ${display(data.value.website_pending)} 个`,href:'/websites'},
 {label:'当前异常',value:display(data.value.current_issues),hint:'服务器及网站已确认异常',href:'/alerts'},
 {label:'文件与安全事件 · 24 小时',value:display(data.value.events_24h),hint:`扫描命中 ${display(data.value.security_24h)} 条，不含链路探针`,href:'/events'},
 {label:'待投递通知',value:`飞书 ${display(data.value.pending_notifications)} / 邮箱 ${display(data.value.pending_email)}`,hint:'暂停、重试任务继续保留',href:'/alerts?tab=notifications'},
 {label:'部署任务',value:data.value.deployment_running===true?'执行中':data.value.deployment_running===false?'空闲':'未知',hint:'详情中查看最近结果及日志',href:'/deployments'},
])
let timer:ReturnType<typeof setInterval>|undefined,generation=0,disposed=false
async function load(){if(disposed||document.hidden||loading.value)return;loading.value=true;const current=++generation
 await Promise.allSettled([
 (async()=>{try{const result=await api<Dashboard>('/api/dashboard');if(disposed||current!==generation)return;const previous=data.value;for(const [k,v] of Object.entries(result)){if(v===null&&previous[k]!=null)result[k]=previous[k]};if(result.errors.metrics)result.servers=previous.servers;result.components=result.components.map(c=>{const old=previous.components.find(v=>v.id===c.id);return c.status==='unknown'&&old?{...c,metrics:old.metrics,updated:old.updated}:c});data.value=result;loaded.value=true;error.value=''}catch(e){if(!disposed&&current===generation)error.value=errorMessage(e)}})(),
 (async()=>{try{const result=await api<{items:Alert[]}>('/api/alerts?page_size=8');if(!disposed&&current===generation){alerts.value=result.items;alertError.value=''}}catch(e){if(!disposed&&current===generation)alertError.value=errorMessage(e)}})()
 ]);loading.value=false
}
function visibility(){if(!document.hidden)void load()}
onMounted(()=>{void load();timer=setInterval(load,30000);document.addEventListener('visibilitychange',visibility)})
onUnmounted(()=>{disposed=true;generation++;clearInterval(timer);document.removeEventListener('visibilitychange',visibility)})
</script>
<template>
<div class="dashboard-heading"><div><el-tag>{{data.release||'版本未知'}}</el-tag><p class="muted">{{data.updated?`最近更新：${beijingTime(data.updated)}`:'等待加载'}} · 页面每 30 秒刷新，后台标签暂停</p></div><el-button :loading="loading" @click="load">立即刷新</el-button></div>
<el-alert v-if="error" :title="error+'；已有内容可能已过期'" type="error" :closable="false"/>
<el-alert v-for="[key,message] in Object.entries(data.errors)" :key="key" :title="message+'；对应分区显示上次结果或未知'" type="warning" :closable="false"/>
<div class="stats dashboard-stats"><router-link v-for="item in summaries" :key="item.label" :to="item.href"><el-card shadow="never"><span class="muted">{{item.label}}</span><strong>{{item.value}}</strong><small>{{item.hint}}</small></el-card></router-link></div>
<el-card shadow="never"><div class="card-heading"><h3>当前异常</h3><router-link to="/alerts">查看全部 →</router-link></div><el-alert v-if="alertError" :title="alertError+'；未取得最新异常状态'" type="error" :closable="false"/><el-table :data="alerts" :empty-text="alertError?'异常查询失败':loaded?'当前没有已确认异常':'正在读取异常'"><el-table-column label="服务器 / 网站"><template #default="{row}"><router-link :to="row.source==='website'?`/websites/${row.site}`:`/servers/${row.node}`">{{row.name||data.servers.find(s=>s.id===row.node)?.name||row.node}}</router-link></template></el-table-column><el-table-column prop="message" label="原因" min-width="260"/><el-table-column label="状态"><template #default="{row}">{{statusLabel(row.phase)}}</template></el-table-column><el-table-column label="开始时间" min-width="190"><template #default="{row}">{{row.since?beijingTime(row.since):'—'}}</template></el-table-column></el-table></el-card>
<section class="component-section"><div class="card-heading"><h3>组件总览</h3><router-link to="/servers/central?tab=system">中心健康详情 →</router-link></div><div class="component-grid"><el-card v-for="c in data.components" :key="c.id" shadow="never" :class="['component-card',`component-${c.status}`]"><div class="component-heading"><el-icon :size="22"><component :is="icons[c.id]||QuestionFilled"/></el-icon><h4>{{c.name}}</h4><el-tag :type="c.status==='normal'?'success':c.status==='abnormal'?'danger':c.status==='maintenance'?'warning':'info'"><el-icon><component :is="c.status==='normal'?CircleCheck:c.status==='abnormal'?CircleClose:c.status==='disabled'?Remove:QuestionFilled"/></el-icon> {{labels[c.status]||c.status}}</el-tag></div><dl><template v-for="[key,value] in Object.entries(c.metrics)" :key="key"><dt>{{key}}</dt><dd>{{componentValue(key,value)}}</dd></template></dl><p class="muted">{{c.reason}}</p><footer><small>{{c.updated?beijingTime(c.updated):'更新时间未知'}}</small><router-link :to="c.href">查看详情 →</router-link></footer></el-card></div></section>
<div class="chart-grid ranking-grid"><MetricChart v-for="[key,title] in [['cpu_percent','CPU 使用率排名'],['memory_percent','内存使用率排名'],['disk_percent','磁盘使用率排名']]" :key="key" :title="title!" :option="rankingOption(data.servers,key!)"/></div>
<el-card shadow="never"><div class="card-heading"><h3>服务器资源</h3><router-link to="/servers">管理服务器 →</router-link></div><el-table :data="data.servers"><el-table-column label="服务器"><template #default="{row}"><router-link :to="`/servers/${row.id}`">{{row.name}}</router-link></template></el-table-column><el-table-column label="采集状态"><template #default="{row}">{{statusLabel(row.status)}}</template></el-table-column><el-table-column v-for="[key,label] in [['cpu_percent','CPU'],['memory_percent','内存'],['disk_percent','磁盘']]" :key="key" :label="label"><template #default="{row}">{{row.status==='normal'?metricValue(row.snapshot.values[key!],'%'):'未知'}}</template></el-table-column><el-table-column label="运行方式"><template #default="{row}">{{row.actual_mode||'未知'}}</template></el-table-column><el-table-column label="Agent / 中心版本"><template #default="{row}">{{row.agent_version||'未知'}}</template></el-table-column><el-table-column label="最近采集" min-width="180"><template #default="{row}">{{row.snapshot.time?beijingTime(row.snapshot.time):'—'}}</template></el-table-column></el-table></el-card>
</template>
