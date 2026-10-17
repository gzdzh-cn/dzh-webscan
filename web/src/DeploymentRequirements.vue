<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api } from './api'
export interface Requirements { platform:string;minimum_systemd:number;reserve_mib:number;ssh_port:number;metrics_port:number;allowed_source_ip:string;event_url:string;clamav_enabled?:boolean;nodes:{id:string;ssh_port:number;metrics_port:number;allowed_source_ip:string;clamav_enabled?:boolean}[] }
const props=defineProps<{compact?:boolean;nodeId?:string;mode?:string}>()
const data=ref<Requirements>(),failed=ref(false)
let disposed=false
async function load(){failed.value=false;try{const result=await api<Requirements>('/api/servers/requirements');if(!disposed)data.value=result}catch{if(!disposed)failed.value=true}}
onMounted(load);onUnmounted(()=>{disposed=true})
const node=computed(()=>data.value?.nodes.find(n=>n.id===props.nodeId))
</script>
<template>
<section class="deployment-requirements" :class="{compact}" aria-label="端口与环境要求">
 <strong>端口与环境要求</strong>
 <ul>
  <li>子服务器放行入站 TCP 22、19100，仅允许主服务器访问。</li>
  <li>主服务器放行入站 TCP 19443，允许子服务器访问；子服务器同时允许出站连接该端口。</li>
  <li>云安全组、宝塔防火墙和系统防火墙都要检查。自定义端口以实际配置为准。</li>
 </ul>
 <div class="environment-requirements">
  <p>需 Linux amd64、root SSH 登录，监控目录存在且可访问。</p>
  <p v-if="!mode||mode==='native'">直接运行 Go：需要 systemd ≥{{data?.minimum_systemd||231}} 及 CPU／内存资源控制，无需 Docker。</p>
  <p v-if="!mode||mode==='docker'">Docker：需要可用的 Docker／Compose，支持的 Debian／Ubuntu 可自动安装。</p>
  <p v-if="node?.clamav_enabled??data?.clamav_enabled">已启用 ClamAV，需提前配置可用的 clamd 扫描服务。</p>
  <p v-if="failed" role="status">环境配置读取失败。<el-button link type="primary" @click="load">重试</el-button></p>
 </div>
</section>
</template>
<style scoped>
.deployment-requirements{border:1px solid var(--el-color-primary-light-7);background:var(--el-color-primary-light-9);border-radius:8px;padding:14px 18px;margin-bottom:16px;font-size:14px;line-height:1.65;overflow-wrap:anywhere}.deployment-requirements ul{margin:6px 0;padding-left:20px}.deployment-requirements li{margin:4px 0}.environment-requirements{border-top:1px solid var(--el-color-primary-light-7);margin-top:10px;padding-top:4px}.deployment-requirements p{margin:6px 0}.compact{padding:10px 14px}@media(max-width:600px){.deployment-requirements{padding:10px 12px}}
</style>
