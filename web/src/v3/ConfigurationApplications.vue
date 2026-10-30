<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { queryParams } from '../api'
import { V3Error, type V3ConfigurationApplication, type V3ConfigurationApplicationLog, type V3ConfigurationApplicationAction, type V3ConfigurationApplicationActions } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'

const { client, session } = useConsole(), route = useRoute(), router = useRouter(), read = useReadScope()
const admin = computed(() => session.value?.role === 'admin')
const items = ref<V3ConfigurationApplication[]>([]), job = ref<V3ConfigurationApplication>(), logs = ref<V3ConfigurationApplicationLog[]>([])
const next = ref(''), cursor = ref('0'), clipped = ref(false)
const secure = window.location.protocol === 'https:'
const actions = ref<Partial<V3ConfigurationApplicationActions>>({}), writeError = ref(''), writing = ref(false)
const pending = ref<{ id: string; action: V3ConfigurationApplicationAction; cursor: string; key: string }>()
let writeController = new AbortController(), writeGeneration = 0
const actionLabel = (action: V3ConfigurationApplicationAction) => ({ resume: '继续应用', rollback: '回退应用', cancel: '取消应用' })[action]
const canAct = computed(() => secure && !read.error.value && !read.loading.value && !writing.value && !pending.value)
function confirmAction(action: V3ConfigurationApplicationAction) {
  if (!canAct.value || !job.value || !actions.value[`can_${action}`]) return
  clearTimeout(timer)
  pending.value = { id: job.value.id, action, cursor: job.value.log_cursor, key: crypto.randomUUID() }; writeError.value = ''
}
function dismissAction() { if (writing.value) return; pending.value = undefined; writeError.value = ''; void refresh() }
async function executeAction() {
  if (!pending.value || writing.value || !admin.value || !secure || disposed) return
  const target = pending.value, current = writeGeneration
  writing.value = true; writeError.value = ''; clearTimeout(timer); read.cancel()
  try {
    await client.controlConfigurationApplication(target.id, target.action, target.cursor, target.key, writeController.signal)
    if (disposed || current !== writeGeneration) return
    pending.value = undefined; actions.value = {}
  } catch (e) {
    if (disposed || current !== writeGeneration || writeController.signal.aborted) return
    writeError.value = e instanceof Error ? e.message : '操作结果暂时无法确认，请保留原请求重试'
    if (e instanceof V3Error && [400, 403, 404, 409].includes(e.status)) { pending.value = undefined; actions.value = {} }
    // An ambiguous failure keeps the exact action, cursor and retry key.
  } finally {
    if (!disposed && current === writeGeneration) { writing.value = false; if (!pending.value) void refresh() }
  }
}
let disposed = false, generation = 0, timer: ReturnType<typeof setTimeout> | undefined
const phases: Record<string, string> = { environment: '环境检查', nodes: '节点应用', bootstrap: '中心启动交接', settings: '运行设置', verify: '生效验收', finalize: '完成确认', 'restore-settings': '恢复设置', 'restore-bootstrap': '恢复中心启动', 'restore-nodes': '恢复节点', 'verify-rollback': '回退验收', complete: '已结束' }
const codes: Record<string, string> = { queued: '等待执行', claimed: '工作器已领取', takeover: '接管未完成任务', 'phase-complete': '阶段完成', 'recovery-armed': '已保护回退资料', resumed: '继续原任务', 'rollback-requested': '已申请回退', cancelled: '应用已取消', succeeded: '本次应用完成', 'rolled-back': '回退已完成', 'environment-failed': '环境检查失败', 'deployment-failed': '节点应用失败', 'bootstrap-failed': '中心启动交接失败', 'settings-failed': '运行设置应用失败', 'verification-failed': '验收失败', 'state-conflict': '配置状态冲突', 'runtime-unavailable': '应用运行环境不可用', interrupted: '执行中断' }
const phaseText = (v: string) => phases[v] || '未知阶段'
const codeText = (v: string) => codes[v] || '未知进度，请刷新确认'
const statusText = (v: V3ConfigurationApplication) => v.recovery_hold ? '应用已冻结' : v.direction === 'rollback' && ['queued', 'running'].includes(v.status) ? '回退中' : ({ queued: '等待应用', running: '应用中', failed: '应用未完成', succeeded: '本次应用完成', rolled_back: '已回退', cancelled: '应用已取消' } as Record<string, string>)[v.status] || '未知'

async function refresh() {
  if (disposed || document.hidden || read.loading.value || writing.value || pending.value || !admin.value) return
  clearTimeout(timer)
  const current = generation, id = String(route.params.id || '')
  let backlog = false
  if (id) {
    await read.run(signal => client.configurationApplicationLogs(id, cursor.value, 100, signal), result => {
      // Never convert the database's bigint cursor into a JavaScript number.
      let expected = BigInt(cursor.value)
      for (const line of result.items) {
        if (!/^[1-9][0-9]*$/.test(line.cursor) || BigInt(line.cursor) !== expected + 1n) throw new Error('日志游标不连续，请刷新重试；已读内容保留')
        expected++
      }
      if (result.job.id !== id || result.next_cursor !== expected.toString()) throw new Error('任务日志状态不一致，请刷新重试；已读内容保留')
      actions.value = { can_resume: result.can_resume, can_rollback: result.can_rollback, can_cancel: result.can_cancel }; job.value = result.job; logs.value.push(...result.items); cursor.value = result.next_cursor
      if (logs.value.length > 1000) { logs.value.splice(0, logs.value.length - 1000); clipped.value = true }
      backlog = result.items.length === 100
    })
  } else {
    await read.run(signal => client.configurationApplications(String(route.query.stage || ''), String(route.query.cursor || ''), 20, signal), page => { items.value = page.items; next.value = page.next_cursor })
  }
  if (!disposed && current === generation && !document.hidden && admin.value && id && (backlog || read.error.value || !job.value || ['queued', 'running'].includes(job.value.status))) timer = setTimeout(() => void refresh(), backlog ? 0 : 3000)
}
function page(value: string) { void router.push({ path: '/configuration-applications', query: Object.fromEntries(queryParams({ stage: route.query.stage, cursor: value })) }) }
function visibility() { generation++; clearTimeout(timer); if (document.hidden) read.cancel(); else void refresh() }
watch([() => route.fullPath, admin, () => session.value?.username], () => {
  generation++; clearTimeout(timer); read.cancel(); writeGeneration++; writeController.abort(); writeController = new AbortController(); pending.value = undefined; actions.value = {}; writing.value = false; writeError.value = ''; items.value = []; job.value = undefined; logs.value = []; next.value = ''; cursor.value = '0'; clipped.value = false
  void refresh()
}, { immediate: true })
document.addEventListener('visibilitychange', visibility)
onUnmounted(() => { disposed = true; generation++; writeGeneration++; writeController.abort(); clearTimeout(timer); document.removeEventListener('visibilitychange', visibility) })
</script>

<template>
  <section v-if="admin">
    <div class="v3-page-heading"><div><router-link to="/deployments" class="v3-back">← 返回部署任务</router-link><h1>配置应用{{ route.params.id ? '进度与日志' : '任务' }}</h1><p class="v3-muted">运行中每 3 秒更新。继续或回退需确认当前任务版本；历史成功不代表当前配置版本。</p></div><el-button :loading="read.loading.value" :disabled="writing || !!pending" @click="refresh">刷新应用进度</el-button></div>
    <el-alert v-if="read.error.value" :title="`${read.error.value}；上次读取结果保留`" type="error" :closable="false" />
    <el-alert v-if="writeError" :title="writeError" type="error" :closable="false" />
    <el-card v-if="pending" shadow="never" class="v3-application-confirmation" aria-label="配置应用操作确认">
      <h2>确认{{ actionLabel(pending.action) }}</h2><p>任务 {{ pending.id }} · 确认版本 #{{ pending.cursor }}</p>
      <p>{{ pending.action === 'rollback' ? '将按原任务的恢复资料回退，保留任务记录；请确认影响范围。' : pending.action === 'cancel' ? '只取消尚未承担恢复职责的任务，不撤销已经生效的配置。' : '按原任务检查点继续，不创建新的配置或保存表单草稿。' }}</p>
      <p v-if="writeError">结果未确认时，重试将使用同一请求；不会自动重复提交。</p>
      <div class="v3-actions"><el-button :disabled="writing" @click="dismissAction">返回查看</el-button><el-button type="primary" :loading="writing" @click="executeAction">确认{{ actionLabel(pending.action) }}</el-button></div>
    </el-card>
    <p v-if="job && !secure && (actions.can_resume || actions.can_rollback || actions.can_cancel)" class="v3-muted">继续、回退或取消需要使用 HTTPS 后台。</p>
    <div v-if="job && !pending" class="v3-actions v3-application-actions">
      <el-button v-if="actions.can_resume" :disabled="!canAct" @click="confirmAction('resume')">继续应用</el-button>
      <el-button v-if="actions.can_rollback" :disabled="!canAct" type="warning" @click="confirmAction('rollback')">回退应用</el-button>
      <el-button v-if="actions.can_cancel" :disabled="!canAct" type="danger" @click="confirmAction('cancel')">取消应用</el-button>
    </div>
    <el-card v-if="!route.params.id" shadow="never">
      <el-table :data="items" row-key="id" empty-text="暂无配置应用任务"><el-table-column label="状态" min-width="140"><template #default="{ row }">{{ statusText(row) }}</template></el-table-column><el-table-column label="阶段" min-width="140"><template #default="{ row }">{{ phaseText(row.phase) }}</template></el-table-column><el-table-column prop="controller" label="当前操作人" min-width="120" /><el-table-column label="更新时间" min-width="180"><template #default="{ row }">{{ timeText(row.updated_at) }}</template></el-table-column><el-table-column label="进度" width="120"><template #default="{ row }"><router-link :to="`/configuration-applications/${encodeURIComponent(row.id)}`">查看应用日志</router-link></template></el-table-column></el-table>
      <div class="v3-pagination"><el-button :disabled="!route.query.cursor || read.loading.value" @click="page('')">回到首页</el-button><span>每页最多 20 条</span><el-button :disabled="!next || read.loading.value" @click="page(next)">下一页</el-button></div>
    </el-card>
    <template v-else-if="job">
      <el-card shadow="never"><h2>{{ statusText(job) }} · {{ phaseText(job.phase) }}</h2><p v-if="job.recovery_hold" role="status">任务已冻结，需管理员检查恢复资料；未完成生效验收。</p><p v-else-if="job.recovery_required" role="status">本任务仍承担继续或回退职责，请保留原任务和恢复资料。</p><el-alert v-if="job.error_code" :title="codeText(job.error_code)" type="error" :closable="false" /><dl class="v3-detail-grid"><dt>任务 ID</dt><dd>{{ job.id }}</dd><dt>配置候选代次</dt><dd>{{ job.generation }}</dd><dt>操作人</dt><dd>{{ job.controller }}</dd><dt>更新时间</dt><dd>{{ timeText(job.updated_at) }}</dd></dl><router-link to="/backups?tab=deployment">查看部署配置备份与恢复记录 →</router-link></el-card>
      <el-card shadow="never"><div class="v3-job-heading"><h2>应用进程日志</h2><span class="v3-muted">已读至 #{{ cursor }}</span></div><p v-if="clipped" class="v3-muted">页面保留最近 1000 行，完整记录仍保存在主控。</p><ol v-if="logs.length" class="v3-logs" aria-label="配置应用进程日志"><li v-for="line in logs" :key="line.cursor"><time>{{ timeText(line.created_at) }}</time><span class="v3-log-phase">{{ phaseText(line.phase) }}</span><span>{{ codeText(line.code) }}</span></li></ol><el-empty v-else description="暂无阶段日志" /></el-card>
    </template>
    <p v-else-if="route.params.id">{{ read.loading.value ? '正在读取应用任务…' : '暂未读取到任务，请刷新重试' }}</p>
  </section>
  <el-alert v-else title="只有管理员可以查看配置应用任务" type="warning" :closable="false" />
</template>

<style scoped>
.v3-application-confirmation p{overflow-wrap:anywhere}
.v3-application-actions{margin:16px 0}
</style>
