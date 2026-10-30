<script setup lang="ts">
import CursorPagination from './CursorPagination.vue'
import { useCursorPage } from './cursorPage'
import PageHeading from './PageHeading.vue'
import { computed, nextTick, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { queryParams } from '../api'
import type { V3DeploymentDetail, V3DeploymentJob, V3DeploymentLog } from '../controlV3'
import { jobLabel, timeText, useConsole } from './context'
import { useReadScope } from './readScope'

const pagination = useCursorPage(), pageLimit = pagination.limit

const { client, session } = useConsole(), route = useRoute(), router = useRouter()
const { loading, error, run, cancel } = useReadScope()
const items = ref<V3DeploymentJob[]>([]), detail = ref<V3DeploymentDetail | null>(null), logs = ref<V3DeploymentLog[]>([])
const logSearch = ref(''), errorsOnly = ref(false), autoScroll = ref(true), logElement = ref<HTMLElement>()
const visibleLogs = computed(() => logs.value.filter(line => (!logSearch.value || `${phaseLabel(line.phase)} ${codeLabel(line.code)}`.toLowerCase().includes(logSearch.value.toLowerCase())) && (!errorsOnly.value || /failed|invalid|unavailable|conflict|interrupted|unknown/.test(line.code))))
const stageRows = computed(() => [...new Map(logs.value.map(line => [line.phase, line])).values()])
const acting = ref(false), actionError = ref('')
const node = ref(''), next = ref(''), lastCursor = ref(0), clipped = ref(false)
let disposed = false, refreshing = false, version = 0, timer: ReturnType<typeof setTimeout> | undefined
const phases: Record<string,string> = { preflight: '环境检查', stage: '准备程序与配置', backup: '一致性备份', activate: '切换服务', verify: '采集与扫描验收', finalize: '完成部署', restore: '恢复原服务', 'verify-rollback': '回退验收', complete: '已完成' }
const codes: Record<string,string> = { queued: '等待执行器', claimed: '执行器已领取', takeover: '接管未完成任务', 'phase-complete': '阶段完成', resumed: '继续原任务', 'rollback-requested': '已申请回退', succeeded: '部署成功', 'rolled-back': '回退完成', 'preflight-failed': '环境检查失败', 'artifact-invalid': '程序或配置校验失败', 'backup-failed': '备份失败', 'activation-failed': '切换服务失败', 'verification-failed': '验收失败', 'remote-unavailable': '远端连接不可用', 'remote-conflict': '远端状态冲突', 'remote-state-unknown': '无法确认远端状态', interrupted: '执行中断', 'recovery-protected': '已保留继续与回退资料', 'configuration-conflict': '配置版本冲突', 'executor-unavailable': '执行器不可用' }
const phaseLabel = (value: string) => phases[value] || value
const codeLabel = (value: string) => codes[value] || value
const kindLabel = (value: string) => (({ install: '安装', upgrade: '升级', recover: '历史恢复' } as Record<string, string>)[value] || '未知操作')
async function refresh() {
  if (disposed || document.hidden || refreshing) return
  clearTimeout(timer); refreshing = true
  const current = version
  let backlog = false
  try {
    const id = String(route.params.id || '')
    if (id) {
      await run(async signal => {
        const [value, tail] = await Promise.all([client.deployment(id, signal), client.deploymentLogs(id, lastCursor.value, 100, signal)])
        return { value, tail }
      }, ({ value, tail }) => {
        detail.value = value
        const fresh = tail.items.filter(line => line.cursor > lastCursor.value)
        logs.value.push(...fresh)
        if (logs.value.length > 1000) { logs.value.splice(0, logs.value.length - 1000); clipped.value = true }
        lastCursor.value = Math.max(lastCursor.value, tail.next_cursor)
        backlog = tail.items.length === 100
        void nextTick(() => { if (autoScroll.value && logElement.value) logElement.value.scrollTop = logElement.value.scrollHeight })
      })
    } else await run(signal => client.deployments(String(route.query.node || ''), String(route.query.cursor || ''), pageLimit.value, signal), value => { items.value = value.items; next.value = value.next_cursor })
  } finally {
    if (current === version) {
      refreshing = false
      if (!disposed && !document.hidden && route.params.id && (backlog || error.value || detail.value && ['queued','running'].includes(detail.value.job.status))) timer = setTimeout(() => void refresh(), backlog ? 0 : 3000)
    }
  }
}
async function recover(action: 'resume' | 'rollback') {
 if (acting.value || !detail.value) return
 const job = detail.value.job, current = version; acting.value = true; actionError.value = ''
 try { await client.recoverDeployment(job.id, action, job.plan_digest, job.log_cursor, crypto.randomUUID()); if (!disposed && current === version) await refresh() } catch (e) { if (!disposed && current === version) actionError.value = e instanceof Error ? e.message : '操作失败，请刷新后重试' } finally { if (current === version) acting.value = false }
}
async function search() { const before = route.fullPath; await router.push({ path: '/deployments', query: Object.fromEntries(queryParams({ node: node.value.trim(), limit: pageLimit.value === 20 ? undefined : pageLimit.value })) }); if (before === route.fullPath) void refresh() }
function page(cursor: string) { void pagination.go(cursor) }
function visible() { clearTimeout(timer); if (!document.hidden) void refresh() }
watch(() => route.fullPath, () => { version++; cancel(); clearTimeout(timer); refreshing = false; node.value = String(route.query.node || ''); detail.value = null; logs.value = []; lastCursor.value = 0; clipped.value = false; acting.value = false; actionError.value = ''; void refresh() }, { immediate: true })
document.addEventListener('visibilitychange', visible)
onUnmounted(() => { disposed = true; clearTimeout(timer); document.removeEventListener('visibilitychange', visible) })
</script>

<template>
  <section>
    <p v-if="session?.role === 'admin'" class="small muted"><router-link to="/configuration-applications">查看配置应用任务与日志 →</router-link></p>
    <PageHeading :title="route.params.id ? '部署详情' : '部署任务'" :back="route.params.id ? '/deployments' : undefined" back-label="返回部署任务"><el-button :loading="loading" @click="refresh">刷新</el-button></PageHeading>
    <el-alert v-if="actionError" :title="actionError" type="error" :closable="false" /><el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-card v-if="!route.params.id" shadow="never"><form class="filters v3-filters" @submit.prevent="search"><el-input v-model="node" placeholder="按节点 ID 筛选" clearable aria-label="按节点 ID 筛选" /><el-button type="primary" native-type="submit">查询</el-button><el-button @click="node = ''; search()">重置</el-button></form><el-table :data="items" row-key="id" empty-text="暂无后台部署任务"><el-table-column label="任务" min-width="240"><template #default="{row}"><router-link :to="`/deployments/${encodeURIComponent(row.id)}`">{{ kindLabel(row.kind) }} · {{ row.node }}</router-link></template></el-table-column><el-table-column label="状态" min-width="110"><template #default="{row}"><el-tag :type="row.status === 'succeeded' ? 'success' : ['failed','interrupted'].includes(row.status) ? 'danger' : 'info'">{{ jobLabel(row.status) }}</el-tag></template></el-table-column><el-table-column label="开始时间" min-width="190"><template #default="{row}">{{ timeText(row.created_at) }}</template></el-table-column><el-table-column label="结果" min-width="220"><template #default="{row}">{{ row.error_code ? codeLabel(row.error_code) : jobLabel(row.status) }}<small class="muted v3-block">操作人：{{ row.username }} · 更新：{{ timeText(row.updated_at) }}</small></template></el-table-column><el-table-column label="操作与保护" min-width="220"><template #default="{row}"><el-button link type="primary" @click="router.push(`/deployments/${encodeURIComponent(row.id)}`)">{{ row.recovery_required ? '继续 / 回退' : '查看日志' }}</el-button><small v-if="row.recovery_required" class="muted v3-block">原任务保留恢复资料</small></template></el-table-column></el-table><CursorPagination :previous="!!route.query.cursor" :next="!!next" :limit="pageLimit" :loading="loading" @previous="pagination.previous" @next="page(next)" @resize="pagination.resize" /></el-card>
    <template v-else-if="detail"><el-card shadow="never"><div class="card-heading v3-job-heading"><div><el-tag>{{ jobLabel(detail.job.status) }}</el-tag><h2>{{ detail.job.node }} · {{ kindLabel(detail.job.kind) }}</h2></div><router-link :to="`/servers/${encodeURIComponent(detail.job.node)}`">查看服务器 →</router-link></div><div class="detail-grid v3-detail-grid"><div><span>当前阶段</span><strong>{{ phaseLabel(detail.phase) }}</strong></div><div><span>配置版本</span><strong>{{ detail.job.node_version }}</strong></div><div><span>更新时间</span><strong>{{ timeText(detail.job.updated_at) }}</strong></div><div><span>任务 ID</span><strong>{{ detail.job.id }}</strong></div></div><el-alert v-if="detail.job.error_code" :title="codeLabel(detail.job.error_code)" type="error" :closable="false" /><el-alert v-if="detail.recovery_required" :title="detail.recovery_reason || '任务已保留恢复资料，可继续原任务或回退。'" type="warning" :closable="false" /><div v-if="session?.role === 'admin'" class="v3-actions"><el-button v-if="detail.can_resume" type="primary" :loading="acting" @click="recover('resume')">继续原任务</el-button><el-popconfirm v-if="detail.can_rollback" title="确认回退该节点到原服务？保留未确认事件。" @confirm="recover('rollback')"><template #reference><el-button :disabled="acting" type="warning">回退</el-button></template></el-popconfirm></div></el-card>
      <el-card shadow="never"><h3>部署阶段</h3><el-table :data="stageRows" empty-text="尚无已执行的阶段记录"><el-table-column label="阶段" min-width="230"><template #default="{row}">{{ phaseLabel(row.phase) }}</template></el-table-column><el-table-column label="服务器" min-width="160"><template #default>{{ detail.job.node }}</template></el-table-column><el-table-column label="状态" min-width="160"><template #default="{row}">{{ codeLabel(row.code) }}</template></el-table-column></el-table></el-card>
      <el-card shadow="never"><div class="card-heading"><h3>执行日志</h3><span class="muted">已读至 #{{ lastCursor }}</span></div><div class="filters"><el-input v-model="logSearch" clearable placeholder="搜索日志" aria-label="搜索日志" /><el-checkbox v-model="errorsOnly">仅看错误</el-checkbox><el-checkbox v-model="autoScroll">自动滚动</el-checkbox></div><p class="muted">页面保留最近 1000 条日志，断线后沿游标继续读取。{{ clipped ? '较早内容已从页面移除，记录仍保存在主控。' : '' }}</p><pre ref="logElement" class="task-log" aria-label="部署进程日志">{{ visibleLogs.map(line => `[${timeText(line.created_at)}][${phaseLabel(line.phase)}] ${codeLabel(line.code)}`).join('\n') || (loading ? '正在读取日志' : '暂无符合条件的日志') }}</pre></el-card>
    </template>
  </section>
</template>

<style scoped>.task-log{white-space:pre-wrap;overflow-wrap:anywhere;background:#112038;color:#dae6fa;padding:20px;border-radius:8px;max-height:65vh;overflow:auto;font:13px/1.7 monospace}</style>
