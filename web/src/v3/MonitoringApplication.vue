<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { V3Error, type V3MonitoringApplication, type V3MonitoringApplicationPreview, type V3Node, type V3NodeMonitoring } from '../controlV3'
import { timeText, useConsole } from './context'
const props = defineProps<{ version?: string; disabled?: boolean }>()
const { client, session } = useConsole()
const admin = computed(() => session.value?.role === 'admin')
const open = ref(false), query = ref(''), items = ref<V3Node[]>([]), next = ref(''), cursors = ref<string[]>(['']), selected = ref<Record<string, V3Node>>({})
const activeId = ref(''), authorization = ref<{token:string; expires_at:string; version:string; id:string}>(), authorizationConfirm = ref(false)
const loading = ref(false), busy = ref(false), error = ref(''), readError = ref(''), preview = ref<V3MonitoringApplicationPreview>(), task = ref<V3MonitoringApplication>(), polling = ref(false)
let disposed = false, generation = 0, previewGeneration = 0, preparing = false, listGeneration = 0, controller: AbortController | undefined, pollController: AbortController | undefined, timer: ReturnType<typeof setTimeout> | undefined, confirmKey = '', preparationKey = ''
const recoveryKeys = new Map<string,string>()
const storageKey = `webscan.monitoring.application.${session.value?.username || 'unknown'}`
const count = computed(() => Object.keys(selected.value).length)
const editable = computed(() => admin.value && !props.disabled && !busy.value)
function eligible(node: V3Node) { return node.enabled && node.applied_version > 0 && node.monitoring?.source === 'inherited' }
function reason(node: V3Node) { return !node.enabled ? '未启用' : node.applied_version <= 0 ? '尚未安装' : node.monitoring?.source !== 'inherited' ? '独立配置或规则未知' : '' }
function invalidate() { preview.value = undefined; confirmKey = '' }
function cancelPreview() { previewGeneration++; invalidate(); preparationKey=''; if(preparing) { preparing=false; busy.value=false } }
function select(node: V3Node, checked: boolean) { if (!editable.value || !eligible(node)) return; cancelPreview(); error.value = ''; if (checked) selected.value[node.id] = node; else delete selected.value[node.id] }
function text(value?: V3NodeMonitoring) { if (!value) return '未知／未提供'; const r = value.rules; return `目录：${r.roots.join('、') || '无'}；后缀：${r.extensions.join('、') || '无'}；重要文件：${r.important_filenames.join('、') || '无'}；重要路径：${r.critical_paths.join('、') || '无'}；忽略：${r.exclude_paths.join('、') || '无'}；核对：${r.reconciliation_interval_hours} 小时` }
const labels: Record<string,string> = { pending:'等待', preparing:'准备中', running:'执行中', succeeded:'已完成', failed:'失败', rolled_back:'已回退', paused:'已暂停', rollback:'回退', forward:'应用', apply:'应用', interrupted:'已中断' }
function state(value: string) { return labels[value] || value }
async function list(cursor = '') {
 if (!admin.value || disposed) return
 controller?.abort(); const current = ++listGeneration; const signal = (controller = new AbortController()).signal; loading.value = true; readError.value = ''
 try { const page = await client.servers(query.value.trim(),cursor,20,signal); if (!disposed && current === listGeneration) { items.value = page.items; next.value = page.next_cursor } }
 catch(e) { if (!disposed && current === listGeneration && !signal.aborted) readError.value = e instanceof Error ? e.message : '节点查询失败' }
 finally { if (!disposed && current === listGeneration) loading.value = false }
}
function search() { cursors.value = ['']; void list() }
function page(forward: boolean) { if (loading.value) return; if (forward && next.value) cursors.value.push(next.value); else if (!forward && cursors.value.length > 1) cursors.value.pop(); else return; void list(cursors.value.at(-1)) }
function show() { open.value = !open.value; if (open.value && !items.value.length) void list() }
async function prepare() {
 if (!editable.value || !count.value || !props.version) return
 const current = ++generation, currentPreview = ++previewGeneration, expectedVersion = props.version; invalidate(); error.value = ''; busy.value = true; preparing = true
 try { const result = await client.previewMonitoringApplication({ expected_version:expectedVersion, nodes:Object.values(selected.value).map(n=>({id:n.id,expected_version:n.version})) },preparationKey || (preparationKey=crypto.randomUUID())); if (!disposed && current === generation && currentPreview === previewGeneration && expectedVersion === props.version) { preview.value = result; confirmKey = crypto.randomUUID() } }
 catch(e) { if (!disposed && current === generation && currentPreview === previewGeneration) error.value = e instanceof Error ? e.message : '应用预览失败' }
 finally { if (!disposed && current === generation && currentPreview === previewGeneration) { preparing=false; busy.value = false } }
}
function remember(id: string) { try { sessionStorage.setItem(storageKey,id) } catch { /* task remains visible in current view */ } }
function adopt(value: V3MonitoringApplication) { if(authorization.value && (authorization.value.id!==value.id || authorization.value.version!==value.version || !value.can_reauthorize)) { authorization.value=undefined; authorizationConfirm.value=false }; activeId.value=value.id; task.value = value; remember(value.id) }
function schedule() { if (timer) clearTimeout(timer); if (!disposed && admin.value && activeId.value && !document.hidden) timer = setTimeout(() => void refresh(),3000) }
async function refresh(id = activeId.value) {
 if (!id || disposed || !admin.value || polling.value || document.hidden || busy.value) { schedule(); return }
 const current = generation; const signal = (pollController = new AbortController()).signal; polling.value = true
 try { const value = await client.monitoringApplication(id,signal); if (!disposed && current === generation && !signal.aborted) { adopt(value); readError.value = '' } }
 catch(e) { if (!disposed && current === generation && !signal.aborted) readError.value = e instanceof Error ? e.message : '连接中断，正在重连；后台任务继续执行' }
 finally { polling.value = false; if (!disposed) schedule() }
}
async function confirm() {
 if (!editable.value || !preview.value) return
 if (!Number.isFinite(Date.parse(preview.value.expires_at)) || Date.now() >= Date.parse(preview.value.expires_at)) { cancelPreview(); error.value = '预览已过期，请重新预览'; return }
 const current = generation; busy.value = true; error.value = ''; pollController?.abort()
 try { const result = await client.confirmMonitoringApplication({preview:preview.value.id,token:preview.value.token},confirmKey); if (!disposed && current === generation) { adopt(result); invalidate(); preparationKey=''  } }
 catch(e) { if (!disposed && current === generation) { error.value = e instanceof Error ? e.message : '任务创建失败'; if (e instanceof V3Error && [400,409,410].includes(e.status)) cancelPreview() } }
 finally { if (!disposed && current === generation) { busy.value = false; schedule() } }
}
async function recover(direction:'resume'|'rollback', node?:string) {
 if (!editable.value || !task.value) return
 const allowed = node ? task.value.nodes.find(n=>n.id===node)?.[direction==='resume'?'can_resume':'can_rollback'] : task.value[direction==='resume'?'can_resume':'can_rollback']; if (!allowed) return
 const current = ++generation, saved = task.value, identity = `${saved.id}:${saved.version}:${direction}:${node || ''}`
 let key = recoveryKeys.get(identity); if (!key) { key = crypto.randomUUID(); recoveryKeys.set(identity,key) }
 busy.value = true; error.value = ''; pollController?.abort()
 try { const result = await client.recoverMonitoringApplication(saved.id,direction,saved.version,key,node); if (!disposed && current === generation) adopt(result) }
 catch(e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '恢复操作失败' }
 finally { if (!disposed && current === generation) { busy.value = false; schedule() } }
}
function authorizationKey(kind:string,id:string,version:string) { const identity=`authorization:${kind}:${id}:${version}`; let key=recoveryKeys.get(identity); if(!key) { key=crypto.randomUUID(); recoveryKeys.set(identity,key) };return key }
async function prepareAuthorization() {
 if(!editable.value || !task.value?.can_reauthorize) return
 const current=++generation,saved=task.value;busy.value=true;error.value='';pollController?.abort()
 try { const value=await client.previewMonitoringReauthorization(saved.id,saved.version,authorizationKey('preview',saved.id,saved.version));if(!disposed && current===generation) { authorization.value={...value,id:saved.id,version:saved.version};authorizationConfirm.value=true } }
 catch(e) { if(!disposed && current===generation)error.value=e instanceof Error?e.message:'重新授权预览失败' }
 finally { if(!disposed && current===generation) { busy.value=false;schedule() } }
}
async function authorize() {
 if(!editable.value || !task.value?.can_reauthorize || !authorization.value)return
 const saved=authorization.value
 if(!Number.isFinite(Date.parse(saved.expires_at))||Date.now()>=Date.parse(saved.expires_at)) { authorization.value=undefined;authorizationConfirm.value=false;recoveryKeys.delete(`authorization:preview:${saved.id}:${saved.version}`);recoveryKeys.delete(`authorization:confirm:${saved.id}:${saved.version}`);error.value='重新授权预览已过期，请重新预览';return }
 if(task.value.id!==saved.id||task.value.version!==saved.version) { authorization.value=undefined;authorizationConfirm.value=false;error.value='任务版本已变化，请重新预览';return }
 const current=++generation;busy.value=true;error.value='';pollController?.abort()
 try { const value=await client.reauthorizeMonitoringApplication(saved.id,saved.version,saved.token,authorizationKey('confirm',saved.id,saved.version));if(!disposed && current===generation) { authorization.value=undefined;authorizationConfirm.value=false;adopt(value) } }
 catch(e) { if(!disposed && current===generation)error.value=e instanceof Error?e.message:'重新授权失败' }
 finally { if(!disposed && current===generation) { busy.value=false;schedule() } }
}
function visibility() { if (document.hidden) { if (timer) clearTimeout(timer); pollController?.abort() } else void refresh() }
watch(() => props.version, cancelPreview)
watch(admin,value => { if (!value) { generation++; listGeneration++; controller?.abort(); pollController?.abort(); if(timer) clearTimeout(timer); items.value=[]; selected.value={}; preview.value=undefined; task.value=undefined; activeId.value=''; authorization.value=undefined; authorizationConfirm.value=false } })
document.addEventListener('visibilitychange',visibility)
if (admin.value) { try { const id = sessionStorage.getItem(storageKey); if (id) { activeId.value=id; void refresh(id) } } catch { /* storage unavailable */ } }
onUnmounted(() => { disposed=true; generation++; listGeneration++; controller?.abort(); pollController?.abort(); if(timer) clearTimeout(timer); document.removeEventListener('visibilitychange',visibility) })
</script>
<template>
 <section class="v3-monitoring-application" aria-label="公共规则批量应用">
  <div class="card-heading"><h3>应用公共规则</h3><el-button v-if="admin" :disabled="busy || disabled || !version" @click="show">{{ open ? '收起节点选择' : '选择应用节点' }}</el-button></div>
  <p class="muted">保存不自动下发。每批最多 20 台、最多同时 5 台；失败暂停后续批次。只选择已安装、已启用且继承公共规则的节点。</p>
  <el-alert v-if="!admin" title="只有管理员可以应用公共规则。" type="info" :closable="false" />
  <template v-else>
   <el-alert v-if="readError" :title="readError" type="warning" :closable="false" />
   <template v-if="open">
    <form class="filters v3-filters" @submit.prevent="search"><el-input v-model="query" aria-label="搜索应用节点" placeholder="搜索节点名称或地址" :disabled="busy"/><el-button native-type="submit" :loading="loading" :disabled="busy">查询节点</el-button></form>
    <div class="v3-monitoring-table"><table><thead><tr><th>选择</th><th>服务器</th><th>当前规则</th></tr></thead><tbody><tr v-for="node in items" :key="node.id"><td><input type="checkbox" :aria-label="`选择 ${node.name}`" :checked="!!selected[node.id]" :disabled="!editable || !eligible(node)" @change="select(node,($event.target as HTMLInputElement).checked)" /></td><td>{{node.name}}<small class="muted v3-block">{{node.endpoint}}</small></td><td>{{reason(node) || `继承 · ${node.monitoring?.rules_version}`}}</td></tr></tbody></table></div>
    <div class="v3-actions"><el-button :disabled="loading || cursors.length < 2" @click="page(false)">上一页</el-button><el-button :disabled="loading || !next" @click="page(true)">下一页</el-button><span>每页 20 条 · 已选 {{count}} 台</span></div>
    <p v-if="count" class="muted">已选：{{Object.values(selected).map(n=>n.name).join('、')}}</p>
    <el-button type="primary" :disabled="!editable || !count || !version" :loading="busy" @click="prepare">预览所选节点差异</el-button>
   </template>
   <div v-if="preview" class="v3-monitoring-preview"><h4>应用预览 · {{preview.release}}</h4><p>有效期至 {{timeText(preview.expires_at)}}。确认后创建后台任务。</p><div v-for="node in preview.nodes" :key="node.id" class="v3-monitoring-diff"><strong>{{node.name}} · 第 {{node.batch+1}} 批 · {{node.changed?'有变更':'无变更'}}</strong><p>当前：{{text(node.before)}}</p><p>应用后：{{text(node.effective)}}</p></div><el-button type="primary" :disabled="!editable" :loading="busy" @click="confirm">确认应用所选节点</el-button><el-button :disabled="busy" @click="cancelPreview">取消预览</el-button></div>
   <div class="v3-save-feedback" role="status" aria-live="polite"><el-alert v-if="error" :title="error" type="error" :closable="false"/><span v-else-if="busy">正在提交操作，请稍候…</span></div>
   <div v-if="task" class="v3-monitoring-progress"><div class="card-heading"><h4>批量任务 {{task.id}}</h4><el-button :loading="polling" :disabled="busy" @click="refresh()">刷新任务</el-button></div><p>状态：{{state(task.status)}} · {{state(task.direction)}} · 规则版本 {{task.rules_version}}</p><p v-if="task.error_code" class="muted">{{task.error_code}}</p><p v-if="task.reauthorization_reason" class="muted">{{task.reauthorization_reason}}</p><p class="muted">后台任务独立执行，离开页面后仍可恢复查看。</p><div class="v3-actions"><el-button v-if="task.can_reauthorize" :disabled="!editable" :loading="busy" @click="prepareAuthorization">重新授权任务</el-button><el-button v-if="task.can_resume" :disabled="!editable" :loading="busy" @click="recover('resume')">继续任务</el-button><el-button v-if="task.can_rollback" :disabled="!editable" :loading="busy" @click="recover('rollback')">回退任务</el-button></div><div class="v3-monitoring-table"><table><thead><tr><th>节点／批次</th><th>真实状态</th><th>操作</th></tr></thead><tbody><tr v-for="node in task.nodes" :key="node.id"><td>{{node.name}} · {{node.batch+1}}</td><td>{{state(node.state)}}<small v-if="node.error_code" class="muted v3-block">{{node.error_code}}</small></td><td><router-link v-if="node.job" :to="`/deployments/${encodeURIComponent(node.job)}`">查看节点日志</router-link><el-button v-if="node.can_resume" link :disabled="!editable" @click="recover('resume',node.id)">继续此节点</el-button><el-button v-if="node.can_rollback" link :disabled="!editable" @click="recover('rollback',node.id)">回退此节点</el-button></td></tr></tbody></table></div></div>
   <el-dialog v-model="authorizationConfirm" title="重新授权固定计划" width="600px" class="v3-node-dialog" :close-on-click-modal="!busy" :close-on-press-escape="!busy" :show-close="!busy">
    <p>由当前管理员承担原固定计划。重新授权仅恢复任务操作权限，不会立即执行 SSH；之后需明确点击继续或回退。</p><template v-if="task"><p>任务：{{task.id}} · 规则版本：{{task.rules_version}} · 目标版本：{{task.release}}</p><p class="v3-monitoring-digest">固定物料摘要：{{task.manifest_sha256}}</p><p>节点：{{task.nodes.map(n=>n.name).join('、')}}</p></template><p>确认有效期至 {{timeText(authorization?.expires_at)}}</p>
    <template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="error" :title="error" type="error" :closable="false"/><span v-else>{{busy?'正在重新授权…':'确认后任务保持暂停，等待继续或回退。'}}</span></div><div class="v3-actions"><el-button :disabled="busy" @click="authorizationConfirm=false;authorization=undefined">取消重新授权</el-button><el-button type="primary" :disabled="!editable || !task?.can_reauthorize" :loading="busy" @click="authorize">确认承担原固定计划</el-button></div></template>
   </el-dialog>
  </template>
 </section>
</template>
<style scoped>
.v3-monitoring-application{margin-top:24px;border-top:1px solid var(--el-border-color-light);padding-top:16px}.v3-monitoring-table{overflow-x:auto;margin:12px 0}.v3-monitoring-table table{width:100%;min-width:440px;border-collapse:collapse;text-align:left}.v3-monitoring-table td,.v3-monitoring-table th{padding:12px;border-bottom:1px solid var(--el-border-color-light)}.v3-monitoring-diff{background:var(--el-fill-color-light);padding:12px;margin:12px 0;overflow-wrap:anywhere}.v3-monitoring-progress,.v3-monitoring-preview{margin-top:20px;overflow-wrap:anywhere}.v3-actions{flex-wrap:wrap}.v3-monitoring-application p,.v3-monitoring-digest{overflow-wrap:anywhere}
</style>
