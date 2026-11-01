<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch } from 'vue'
import type { V3NotificationAttempt, V3NotificationDetail } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import CursorPagination from './CursorPagination.vue'
const props = defineProps<{ id: string }>()
const emit = defineEmits<{ close: [] }>()
const { client } = useConsole(), read = useReadScope(), attemptsRead = useReadScope()
const detail = ref<V3NotificationDetail>(), attempts = ref<V3NotificationAttempt[]>([])
const cursor = ref(''), next = ref(''), limit = ref(20), previous = new Map<string, string>()
const states: Record<string, string> = { completed: '已完成', migration_pending: '等待迁移切换', paused: '已暂停', sending: '正在发送', waiting: '等待前序通知', retrying: '等待重试', pending: '待发送' }
const sources: Record<string, string> = { event: '文件与安全事件', server_health: '服务器告警', website: '网站监控', test: '测试通知', legacy: '旧版记录', unknown: '未知' }
const outcomes: Record<string, string> = { pending: '尚未完成', accepted: '通道已接受', unknown: '结果未知' }
let closed = false
function close() { closed = true; read.cancel(); attemptsRead.cancel(); emit('close') }
async function loadDetail() { if (closed || document.hidden) return; await read.run(signal => client.notificationDetail(props.id, signal), value => { detail.value = value }) }
async function loadAttempts() { if (closed || document.hidden) return; await attemptsRead.run(signal => client.notificationAttempts(props.id, cursor.value, limit.value, signal), value => { attempts.value = value.items; next.value = value.next_cursor }) }
function page(value: string) { if (value) previous.set(value, cursor.value); cursor.value = value; void loadAttempts() }
function resize(value: number) { limit.value = value; cursor.value = ''; previous.clear(); void loadAttempts() }
function visibility() { if (document.hidden) { read.cancel(); attemptsRead.cancel() } else { void loadDetail(); void loadAttempts() } }
watch(() => props.id, () => { closed = false; read.cancel(); attemptsRead.cancel(); detail.value = undefined; attempts.value = []; cursor.value = ''; next.value = ''; previous.clear(); void loadDetail(); void loadAttempts() }, { immediate: true })
onMounted(() => document.addEventListener('visibilitychange', visibility))
onUnmounted(() => { closed = true; document.removeEventListener('visibilitychange', visibility) })
</script>
<template>
 <el-dialog :model-value="true" title="通知详情" width="820px" class="v3-node-dialog" @update:model-value="close">
  <el-alert v-if="read.error.value" :title="`${read.error.value}${detail ? '；保留上一次详情。' : ''}`" type="error" :closable="false" />
  <p v-if="!detail">{{ read.loading.value ? '正在读取通知详情…' : '详情尚未读取成功' }}</p>
  <template v-if="detail">
   <div class="detail-grid v3-detail-grid"><div><span>记录 ID</span><strong>{{ detail.notification.id }}</strong></div><div><span>服务器</span><strong>{{ detail.notification.node || '监控中心' }}</strong></div><div><span>收件人 / 目标</span><strong>{{ detail.notification.recipient || '飞书机器人' }}</strong></div><div><span>状态</span><strong>{{ states[detail.notification.state || (detail.notification.done_at ? 'completed' : 'pending')] || '未知' }}</strong></div><div><span>来源</span><strong>{{ sources[detail.notification.source || 'unknown'] || '未知' }}</strong></div><div><span>创建时间</span><strong>{{ timeText(detail.notification.created_at) }}</strong></div><div><span>完成时间</span><strong>{{ timeText(detail.notification.done_at) }}</strong></div><div><span>关联事件</span><strong>{{ detail.notification.event_id || '未提供' }}</strong></div></div>
   <p class="v3-muted">以下为受控业务摘要，可能与通知通道的原始模板不同。</p>
   <h3>{{ detail.notification.subject || '通知内容' }}</h3>
   <el-alert v-if="detail.notification.content_state === 'unsupported'" :title="detail.notification.content_reason || '该记录未提供可展示的内容。'" type="info" :closable="false" />
   <pre v-else class="notification-content">{{ detail.body || '未提供正文' }}</pre>
   <p v-if="detail.notification.truncated" class="v3-muted">内容过长，仅展示截取部分。</p>
   <p>{{ outcomes[detail.outcome.code] || '结果未知' }}：{{ detail.outcome.message || '未提供补充说明' }}</p>
  </template>
  <div class="card-heading"><h3>发送尝试</h3><el-button :loading="attemptsRead.loading.value" @click="loadAttempts">刷新尝试记录</el-button></div>
  <el-alert v-if="attemptsRead.error.value" :title="`${attemptsRead.error.value}；已有尝试记录保留。`" type="error" :closable="false" />
  <el-table :data="attempts" row-key="id" :aria-busy="attemptsRead.loading.value" empty-text="暂无尝试记录"><el-table-column label="时间（北京时间）" min-width="185"><template #default="{ row }">{{ timeText(row.created_at) }}</template></el-table-column><el-table-column label="代次" prop="epoch" min-width="100" /><el-table-column label="结果" min-width="130"><template #default="{ row }">{{ row.outcome === 'accepted' ? '通道已接受' : '结果未知' }}</template></el-table-column><el-table-column label="说明" prop="message" min-width="250" /></el-table>
  <CursorPagination :previous="!!cursor" :next="!!next" :limit="limit" :loading="attemptsRead.loading.value" @previous="page(previous.get(cursor) || '')" @next="page(next)" @resize="resize" />
  <template #footer><div class="v3-dialog-feedback" role="status">通道已接受、任务已完成均不代表已读；SMTP 接受不代表进入收件箱。</div><div class="v3-actions"><el-button :loading="read.loading.value" @click="loadDetail">刷新详情</el-button><el-button @click="close">关闭</el-button></div></template>
 </el-dialog>
</template>
<style scoped>
.notification-content { white-space: pre-wrap; overflow-wrap: anywhere; max-height: 45vh; overflow: auto; padding: 12px; background: var(--el-fill-color-light); border-radius: 4px; }
:deep(.v3-detail-grid strong) { overflow-wrap: anywhere; }
</style>
