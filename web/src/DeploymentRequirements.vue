<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api } from './api'
export interface Requirements { platform:string;minimum_systemd:number;reserve_mib:number;ssh_port:number;metrics_port:number;allowed_source_ip:string;event_url:string;clamav_enabled?:boolean;nodes:{id:string;ssh_port:number;metrics_port:number;allowed_source_ip:string;clamav_enabled?:boolean}[] }
const props=defineProps<{compact?:boolean;nodeId?:string;sshPort?:number|string;mode?:string}>()
const data=ref<Requirements>(),expanded=ref(false),failed=ref(false)
let disposed=false
async function load(){failed.value=false;try{const result=await api<Requirements>('/api/servers/requirements');if(!disposed)data.value=result}catch{if(!disposed)failed.value=true}}
onMounted(load);onUnmounted(()=>{disposed=true})
const node=computed(()=>data.value?.nodes.find(n=>n.id===props.nodeId))
const ssh=computed(()=>props.sshPort||node.value?.ssh_port||data.value?.ssh_port)
const metrics=computed(()=>node.value?.metrics_port||data.value?.metrics_port)
const source=computed(()=>node.value?.allowed_source_ip||data.value?.allowed_source_ip)
</script>
<template>
<section class="deployment-requirements" :class="{compact}" aria-label="部署前须知">
 <div class="requirements-heading"><strong>部署前须知</strong><el-button link type="primary" :aria-expanded="expanded" @click="expanded=!expanded">{{expanded?'收起说明':compact?'查看完整部署要求':'展开端口与环境要求'}}</el-button></div>
 <p>子服务器需支持 root SSH 登录，运行 Linux amd64。推荐直接运行 Go，无需安装 Docker。</p>
 <p v-if="!compact">请同时检查云安全组、宝塔防火墙和系统防火墙：允许主服务器连接子服务器 SSH、指标端口，并允许子服务器连接主服务器事件接口。</p>
 <p>保存并部署会自动检查环境和连接；仅保存配置不会安装或升级服务。</p>
 <div v-if="expanded" class="requirements-details">
  <p v-if="failed" role="status">暂时无法读取当前端口配置，以下默认值仅供参考。<el-button link type="primary" @click="load">重新读取</el-button></p>
  <dl><dt>主服务器 → 子服务器 SSH</dt><dd>TCP {{ssh||'22（默认）'}}，使用 root 认证</dd><dt>中心采集 → 子服务器指标</dt><dd>TCP {{metrics||'19100（默认）'}}；配置允许来源：{{source||'待检查确认'}}。实际来源以连接检测结果为准。</dd><dt>子服务器 → 主服务器事件接口</dt><dd>{{data?.event_url||'TCP 19443（默认），实际地址待读取配置'}}；需允许子服务器出站及主服务器入站。</dd></dl>
  <table v-if="!compact && data?.nodes.length" class="node-ports"><thead><tr><th>节点 ID</th><th>SSH</th><th>指标</th><th>配置允许来源</th></tr></thead><tbody><tr v-for="item in data.nodes" :key="item.id"><td>{{item.id}}</td><td>{{item.ssh_port}}</td><td>{{item.metrics_port}}</td><td>{{item.allowed_source_ip||'待检查确认'}}</td></tr></tbody></table>
  <p v-if="!mode||mode==='native'">直接运行 Go：systemd ≥{{data?.minimum_systemd||231}}，CPU／内存 cgroup 可用，不要求 Docker、Go、Node.js、Python 或 jq。</p>
  <p v-if="!mode||mode==='docker'">Docker：引擎、Compose 和资源限制须可用；全新受支持 Debian／Ubuntu 可自动安装，已有异常引擎不会自动重装或重启。</p>
  <p v-if="node?.clamav_enabled??data?.clamav_enabled"><strong>当前已启用 ClamAV：</strong>子服务器必须已有可用的 clamd 扫描服务。</p><p>监控目录必须存在且可访问；启用 ClamAV 时需已有扫描服务。磁盘需容纳程序、数据库双份备份及至少 {{data?.reserve_mib||256}} MiB 预留，实际需求由检查计算。</p>
  <p>HTTPS 验证证书和双向 TLS。端口未监听不等于防火墙未放行；部署前会在空闲指标端口短暂监听检测，结束自动清理，不修改防火墙或其他业务服务。</p>
 </div>
</section>
</template>
<style scoped>
.deployment-requirements{border:1px solid var(--el-color-primary-light-7);background:var(--el-color-primary-light-9);border-radius:8px;padding:14px 18px;margin-bottom:16px;font-size:14px;line-height:1.65;overflow-wrap:anywhere}.requirements-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.deployment-requirements p{margin:6px 0}.requirements-details{border-top:1px solid var(--el-color-primary-light-7);margin-top:10px;padding-top:8px}dl{display:grid;grid-template-columns:minmax(170px,auto) 1fr;gap:8px 16px}.node-ports{width:100%;border-collapse:collapse;font-size:13px}.node-ports th,.node-ports td{text-align:left;border-bottom:1px solid var(--el-color-primary-light-7);padding:6px;overflow-wrap:anywhere}dt{font-weight:600}dd{margin:0}.compact{padding:10px 14px}@media(max-width:600px){dl{grid-template-columns:1fr;gap:4px}dd{margin-bottom:8px}}
</style>
