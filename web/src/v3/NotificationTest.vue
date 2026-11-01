<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { V3Error, type V3NotificationTestJob, type V3NotificationTestPreview } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
const props = defineProps<{ channel: 'feishu' | 'email'; runtimeVersion: number; dirty?: boolean; pending?: boolean }>()
const { client, session } = useConsole(), read = useReadScope(), capabilitiesRead = useReadScope()
const availability = ref<{ available: boolean; reason: string }>()
const taskId = ref('')
const visible = ref(false), busy = ref(false), error = ref(''), preview = ref<V3NotificationTestPreview>(), job = ref<V3NotificationTestJob>()
const admin = computed(() => session.value?.role === 'admin')
const active = computed(() => !!job.value && ['queued', 'running'].includes(job.value.status))
const statuses: Record<string, string> = { queued: '排队中', running: '测试中', succeeded: '已完成', partial: '部分完成', failed: '失败', unknown: '结果未知', cancelled: '已取消' }
const itemStates: Record<string, string> = { queued: '排队中', sending: '发送中', accepted: '通道已接受', unknown: '结果未知', cancelled: '已取消' }
function storageKey() { return `webscan-v3-notification-test:${encodeURIComponent(session.value?.username || '')}:${props.channel}` }
function remember(id: string) { taskId.value = id; try { if (id) sessionStorage.setItem(storageKey(), id); else sessionStorage.removeItem(storageKey()) } catch { /* Task remains queryable in this page when session storage is unavailable. */ } }
let generation = 0, disposed = false, timer: ReturnType<typeof setTimeout> | undefined, previewKey = '', confirmKey = ''
function stop() { clearTimeout(timer); read.cancel() }
function schedule() { clearTimeout(timer); if (!disposed && visible.value && !document.hidden && (active.value || !!taskId.value && !job.value)) timer = setTimeout(() => void poll(), 3000) }
async function poll(restoring = false) {
 if (disposed || !visible.value && !restoring || document.hidden || !taskId.value || read.loading.value) return
 const id = taskId.value
 await read.run(async signal => {
  try { return await client.notificationTest(id, signal) }
  catch (e) {
   if (!signal.aborted && e instanceof V3Error && [403, 404].includes(e.status)) { job.value = undefined; remember(''); error.value = e.status === 404 ? '上次测试任务不存在或已清理，未确认发送成功；不会自动重发。' : '当前账号无权读取上次测试任务，未确认发送成功；不会自动重发。' }
   throw e
  }
 }, value => { job.value = value })
 schedule()
}
async function prepare() {
 if (!admin.value || !availability.value?.available || busy.value || taskId.value || document.hidden) return
 busy.value = true; error.value = ''; const current = ++generation
 previewKey ||= crypto.randomUUID()
 try { const value = await client.notificationTestPreview(props.channel, props.runtimeVersion, previewKey); if (!disposed && current === generation && visible.value) { preview.value = value; confirmKey = crypto.randomUUID() } }
 catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '测试预览失败' }
 finally { if (!disposed && current === generation) busy.value = false }
}
async function confirm() {
 if (!admin.value || busy.value || !preview.value || job.value) return
 if (Date.now() >= Date.parse(preview.value.expires_at)) { preview.value = undefined; previewKey = ''; confirmKey = ''; error.value = '测试预览已过期，请重新预览'; return }
 busy.value = true; error.value = ''; const current = ++generation
 try { const value = await client.createNotificationTest(preview.value.token, confirmKey); if (!disposed && current === generation && visible.value) { job.value = value; remember(value.id); preview.value = undefined; schedule() } }
 catch (e) { if (!disposed && current === generation) error.value = `${e instanceof Error ? e.message : '创建测试任务失败'}；结果尚未确认，可使用原凭据重试确认，不会自动重发。` }
 finally { if (!disposed && current === generation) busy.value = false }
}
function open() { if (!admin.value || !availability.value?.available && !taskId.value) return; visible.value = true; if (taskId.value) void poll(); else if (!preview.value) void prepare() }
function close() { visible.value = false; generation++; busy.value = false; stop() }
function reset() { if (active.value || busy.value) return; generation++; stop(); remember(''); job.value = undefined; preview.value = undefined; previewKey = ''; confirmKey = ''; error.value = ''; void prepare() }
function visibility() { if (document.hidden) stop(); else if (taskId.value) void poll(!visible.value) }
watch(() => [props.channel, props.runtimeVersion, session.value?.username], () => {
 generation++; stop(); visible.value = false; busy.value = false; job.value = undefined; taskId.value = ''; preview.value = undefined; previewKey = ''; confirmKey = ''; error.value = ''
 if (admin.value) { try { taskId.value = sessionStorage.getItem(storageKey()) || '' } catch { /* Storage can be disabled. */ } if (taskId.value) void poll(true) }
}, { immediate: true })
function loadCapabilities() { if (admin.value && !capabilitiesRead.loading.value) void capabilitiesRead.run(signal => client.capabilities(signal), value => { availability.value = value.notification_tests || { available: false, reason: '服务端未提供通知测试能力。' } }) }
onMounted(() => { document.addEventListener('visibilitychange', visibility); loadCapabilities() })
onUnmounted(() => { disposed = true; generation++; stop(); document.removeEventListener('visibilitychange', visibility) })
</script>
<template>
 <section v-if="admin" class="notification-test"><div class="card-heading"><h3>{{ channel === 'email' ? '邮箱' : '飞书' }}通知测试</h3><el-button :disabled="!taskId && (!availability?.available || capabilitiesRead.loading.value)" @click="open">{{ taskId ? '查看测试结果' : '测试当前已应用配置' }}</el-button></div><el-alert v-if="error && !visible" :title="error" type="warning" :closable="false" /><p v-if="!availability?.available || capabilitiesRead.error.value" class="v3-muted">{{ capabilitiesRead.error.value || availability?.reason || '正在核对通知测试能力…' }} <el-button text :loading="capabilitiesRead.loading.value" @click="loadCapabilities">重新检查测试能力</el-button></p><p class="v3-muted">只测试当前已应用配置，不保存或应用本页草稿。测试内容及目标由服务端确认。</p><el-alert v-if="dirty || pending" title="存在未保存草稿或待应用设置；本次只测试当前已应用配置，草稿和待应用设置不参与。" type="warning" :closable="false" /></section>
 <el-dialog :model-value="visible" :title="channel === 'email' ? '测试邮箱通知' : '测试飞书通知'" width="740px" class="v3-node-dialog" :close-on-click-modal="false" @update:model-value="close">
  <p>只测试当前已应用配置，运行版本 {{ runtimeVersion }}。不会保存或应用设置。</p>
  <el-alert v-if="dirty || pending" title="草稿和待应用设置不参与本次测试。" type="warning" :closable="false" />
  <template v-if="preview"><p>运行版本 {{ preview.runtime_version }} · 预览有效至 {{ timeText(preview.expires_at) }}</p><h3>收件人 / 目标</h3><ul><li v-for="recipient in preview.recipients" :key="recipient">{{ recipient }}</li></ul><h3>{{ preview.subject }}</h3><pre class="test-content">{{ preview.body }}</pre></template>
  <p v-else-if="taskId && !job">正在恢复上次测试任务 {{ taskId }}，不会重新发送。</p><p v-else-if="!job">{{ busy ? '正在读取实际应用配置并创建测试预览…' : '测试预览尚未就绪，请重新预览。' }}</p>
  <template v-if="job"><div class="detail-grid v3-detail-grid"><div><span>任务 ID</span><strong>{{ job.id }}</strong></div><div><span>运行版本</span><strong>{{ job.runtime_version }}</strong></div><div><span>状态</span><strong>{{ statuses[job.status] || '未知' }}</strong></div><div><span>更新时间</span><strong>{{ timeText(job.updated_at) }}</strong></div></div><p>{{ job.message || '等待实际测试结果。' }}</p><el-alert v-if="job.status === 'unknown' || job.items.some(item => item.state === 'unknown')" title="部分发送结果未知，不会自动重发；请先核对通道或实际收件。" type="warning" :closable="false" /><el-table :data="job.items" row-key="ordinal"><el-table-column prop="recipient" label="收件人 / 目标" min-width="180" /><el-table-column label="状态" min-width="130"><template #default="{ row }">{{ itemStates[row.state] || '未知' }}</template></el-table-column><el-table-column prop="message" label="说明" min-width="230" /></el-table></template>
  <template #footer><div class="v3-dialog-feedback" role="status" aria-live="polite"><el-alert v-if="error || read.error.value" :title="error || `${read.error.value}；保留原任务结果，稍后重连。`" type="error" :closable="false" /><span v-else>{{ busy ? '正在处理，请勿重复提交。' : active ? '测试任务进行中，每 3 秒查询；后台标签暂停。' : '任务已完成不代表已读；SMTP 接受不代表进入收件箱。' }}</span></div><div class="v3-actions"><el-button @click="close">关闭</el-button><el-button v-if="taskId" :loading="read.loading.value" @click="poll(false)">刷新结果</el-button><el-button v-if="job && !active && job.status !== 'unknown' && !job.items.some(item => item.state === 'unknown')" @click="reset">重新预览测试</el-button><el-button v-if="!taskId && !job && !preview" :loading="busy" @click="prepare">重新预览</el-button><el-button v-if="preview && !job" type="primary" :loading="busy" @click="confirm">确认创建测试任务</el-button></div></template>
 </el-dialog>
</template>
<style scoped>
.notification-test { border-top: 1px solid var(--el-border-color-light); margin-top: 12px; padding-top: 12px; }
.test-content { white-space: pre-wrap; overflow-wrap: anywhere; max-height: 35vh; overflow: auto; }
:deep(li), :deep(strong) { overflow-wrap: anywhere; }
</style>
