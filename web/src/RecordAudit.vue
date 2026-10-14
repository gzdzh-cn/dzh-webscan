<script setup lang="ts">
import {onMounted,ref} from 'vue'
import {api,beijingTime} from './api'
import {errorMessage,statusLabel} from './monitoring'
interface Audit{id:string;owner:string;kind:string;created:number;status:string;ids:string[];results:{status:string;reason:string}[]}
const source=ref('center'),page=ref(1),items=ref<Audit[]>([]),total=ref(0),error=ref('')
const labels:Record<string,string>={website:'网站软删除','website-backup':'网站备份删除','deployment-backup':'部署配置备份删除','deployment-job':'部署历史删除'}
async function load(){try{const data=await api<{items:Audit[];total:number}>(`/api/record-operations?source=${source.value}&page=${page.value}`);items.value=data.items;total.value=data.total;error.value=''}catch(e){error.value=errorMessage(e)}}
onMounted(load)
</script>
<template><el-card shadow="never"><h3>记录删除审计（只读，保留 365 天）</h3><el-alert v-if="error" :title="error" type="error" :closable="false"/><el-select v-model="source" @change="page=1;load()"><el-option value="center" label="网站与网站备份"/><el-option value="host" label="部署配置备份与部署任务"/></el-select><el-table :data="items"><el-table-column label="时间"><template #default="{row}">{{beijingTime(row.created)}}</template></el-table-column><el-table-column prop="owner" label="操作人"/><el-table-column label="范围"><template #default="{row}">{{labels[row.kind]||row.kind}} · 明确选中 {{row.ids.length}} 条</template></el-table-column><el-table-column label="结果"><template #default="{row}">{{statusLabel(row.status)}} · 成功 {{row.results.filter((r:{status:string})=>r.status==='deleted').length}} / 跳过 {{row.results.filter((r:{status:string})=>r.status==='skipped').length}} / 失败 {{row.results.filter((r:{status:string})=>r.status==='failed').length}}<small>{{row.results.filter((r:{status:string})=>r.status!=='deleted').map((r:{reason:string})=>r.reason).join('；')}}</small></template></el-table-column></el-table><el-pagination v-model:current-page="page" :total="total" :page-size="20" layout="total,prev,pager,next" @change="load"/></el-card></template>
