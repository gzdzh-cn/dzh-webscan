<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { api } from './api'
import { errorMessage } from './monitoring'
type Build={release?:string;commit?:string;built_at?:string;source_digest?:string}
const data=ref<{central:Build;manager:Build;hotfix:string}>(),error=ref('');let disposed=false
onMounted(async()=>{try{const result=await api<typeof data.value>('/api/system/version');if(!disposed)data.value=result}catch(e){if(!disposed)error.value=errorMessage(e)}})
onUnmounted(()=>{disposed=true})
</script>
<template><el-card shadow="never"><h3>运行版本</h3><el-alert v-if="error" :title="error" type="warning" :closable="false"/><el-alert v-if="data?.central.release && data?.manager.release && (data.central.release!==data.manager.release || data.central.source_digest!==data.manager.source_digest)" title="中心与宿主管理程序构建不一致，请核对部署版本。" type="warning" :closable="false"/><div v-if="data" class="form-grid"><div v-for="(build,name) in {中心程序:data.central,宿主管理程序:data.manager}" :key="name"><strong>{{name}} · {{build.release||'未知'}}</strong><p>源码：{{build.commit||'未知'}}</p><p>构建时间：{{build.built_at||'未知'}}</p><p class="wrap">源码摘要：{{build.source_digest||'未知'}}</p></div></div><p class="muted">{{data?.hotfix==='none'?'运行正式镜像内程序，无临时程序挂载。':data?.hotfix==='mounted'?'程序使用临时文件挂载，后续升级请使用包含修复的正式镜像。':'热修复状态：尚未取得可靠部署校验信息。'}}各子服务器实际版本见服务器管理。</p></el-card></template>
