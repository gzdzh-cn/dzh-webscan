<script setup lang="ts">
import { useRoute,useRouter } from 'vue-router'
import Backups from './Backups.vue'
import ConfigBackups from './ConfigBackups.vue'
const route=useRoute(),router=useRouter()
function tab(value:string){void router.push({path:'/backups',query:{...route.query,tab:value}})}
</script>
<template><el-card shadow="never"><div class="filters"><el-button :type="route.query.tab!=='deployment'?'primary':''" @click="tab('website')">网站配置</el-button><el-button :type="route.query.tab==='deployment'?'primary':''" @click="tab('deployment')">部署配置</el-button></div><p class="muted">配置备份不包含监控数据库、故障历史或后台当前管理员密码。加密包不附外部私钥、PKI 和独立部署凭据；完整灾备还需要一致性数据库备份与配套资料。</p></el-card><ConfigBackups v-if="route.query.tab==='deployment'" key="deployment"/><Backups v-else key="website"/></template>
