<script setup lang="ts">
import { onUnmounted, ref } from 'vue'
import { api } from './api'
import { errorMessage, requestKey } from './monitoring'
export interface Deletable { id?: string|number; record_key?: string; can_delete?: boolean; delete_reason?: string }
const props=defineProps<{records:Deletable[];label:string;endpoint?:string;history?:boolean;soft?:boolean}>()
const emit=defineEmits<{done:[]}>()
const visible=ref(false), chosen=ref<Deletable[]>([]), busy=ref(false), error=ref(''),result=ref(''),preview=ref<{id:string;counts:{eligible:number;protected:number}}>()
let disposed=false,timer:ReturnType<typeof setTimeout>|undefined
async function open(records=props.records){if(busy.value)return;chosen.value=[...records];error.value='';result.value='';preview.value=undefined;if(!records.length||records.length>200){error.value='请选择当前页的 1～200 条记录';return};visible.value=true
 if(props.history){busy.value=true;try{preview.value=await api('/api/retention/preview','POST',{category:'all',records:records.map(r=>r.record_key)})}catch(e){error.value=errorMessage(e)}finally{busy.value=false}}}
defineExpose({open})
async function execute(){busy.value=true;error.value='';try{
 const endpoint=props.history?'/api/retention/cleanup':props.endpoint!
 const job=await api<{id:string}>(endpoint,'POST',props.history?{preview:preview.value?.id,confirm:true}:{ids:chosen.value.map(r=>String(r.id)),confirm:true,request_key:requestKey()})
 await poll(job.id)
}catch(e){busy.value=false;error.value=errorMessage(e)}}
async function poll(id:string){if(disposed)return;try{
 const job=await api<{status:string;processed?:number;skipped?:number;message?:string;results?:{status:string;reason:string}[]}>(props.history?`/api/retention/jobs/${id}`:`${props.endpoint}?id=${encodeURIComponent(id)}`)
 if(disposed)return
 if(['pending','running'].includes(job.status)){timer=setTimeout(()=>void poll(id),1000);return}
 busy.value=false
 const success=job.processed??job.results?.filter(r=>r.status==='deleted').length??0,skipped=job.skipped??job.results?.filter(r=>r.status==='skipped').length??0,failed=job.results?.filter(r=>r.status==='failed').length??(job.status==='failed'?1:0)
 result.value=`已处理 ${success} 条，跳过 ${skipped} 条，失败 ${failed} 条。${job.message||''}${job.results?.filter(r=>r.status!=='deleted').map(r=>r.reason).join('；')||''}`
 emit('done')
 }catch(e){busy.value=false;error.value=errorMessage(e)}}
onUnmounted(()=>{disposed=true;clearTimeout(timer)})
</script>
<template><el-button type="danger" :disabled="!records.length||busy" @click="open()">删除已选（{{records.length}}）</el-button><el-dialog v-model="visible" :title="`确认删除${label}`" width="min(620px,96vw)" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy"><p>仅处理当前页明确选择的 {{chosen.length}} 条{{label}}，不删除全部筛选结果。</p><p>{{soft?'网站将软删除，保留故障历史和通知，不发送恢复通知。':'此操作永久删除符合条件的记录，不能撤销。历史保留最近 24 小时及当前异常、未完成任务；备份按依赖保护。'}}删除记录不代表立即释放磁盘空间。</p><p v-if="preview">可删除 {{preview.counts.eligible}} 条，受保护 {{preview.counts.protected}} 条。</p><el-alert v-if="error" :title="error" type="error" :closable="false"/><el-alert v-if="result" :title="result" :type="result.includes('失败 0 条')?'success':'warning'" :closable="false"/><template #footer><el-button :disabled="busy" @click="visible=false">{{result?'关闭':'取消'}}</el-button><el-button v-if="!result" type="danger" :loading="busy" :disabled="!!error||history&&!preview" @click="execute">确认删除</el-button></template></el-dialog></template>
