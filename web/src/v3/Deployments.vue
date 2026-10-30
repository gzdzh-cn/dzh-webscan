<script setup lang="ts">
import { onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { queryParams } from '../api'
import type { V3DeploymentDetail, V3DeploymentJob, V3DeploymentLog } from '../controlV3'
import { jobLabel, timeText, useConsole } from './context'
import { useReadScope } from './readScope'

const { client, session } = useConsole(), route = useRoute(), router = useRouter()
const { loading, error, run, cancel } = useReadScope()
const items = ref<V3DeploymentJob[]>([]), detail = ref<V3DeploymentDetail | null>(null), logs = ref<V3DeploymentLog[]>([])
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
      })
    } else await run(signal => client.deployments(String(route.query.node || ''), String(route.query.cursor || ''), 20, signal), value => { items.value = value.items; next.value = value.next_cursor })
  } finally {
    if (current === version) {
      refreshing = false
      if (!disposed && !document.hidden && route.params.id && (backlog || detail.value && ['queued','running'].includes(detail.value.job.status))) timer = setTimeout(() => void refresh(), backlog ? 0 : 3000)
    }
  }
}
async function recover(action: 'resume' | 'rollback') {
 if (acting.value || !detail.value) return
 const job = detail.value.job, current = version; acting.value = true; actionError.value = ''
 try { await client.recoverDeployment(job.id, action, job.plan_digest, job.log_cursor, crypto.randomUUID()); if (!disposed && current === version) await refresh() } catch (e) { if (!disposed && current === version) actionError.value = e instanceof Error ? e.message : '操作失败，请刷新后重试' } finally { if (current === version) acting.value = false }
}
async function search() { const before = route.fullPath; await router.push({ path: '/deployments', query: Object.fromEntries(queryParams({ node: node.value.trim() })) }); if (before === route.fullPath) void refresh() }
function page(cursor: string) { void router.push({ path: '/deployments', query: Object.fromEntries(queryParams({ node: route.query.node, cursor })) }) }
function visible() { clearTimeout(timer); if (!document.hidden) void refresh() }
watch(() => route.fullPath, () => { version++; cancel(); clearTimeout(timer); refreshing = false; node.value = String(route.query.node || ''); detail.value = null; logs.value = []; lastCursor.value = 0; clipped.value = false; acting.value = false; actionError.value = ''; void refresh() }, { immediate: true })
document.addEventListener('visibilitychange', visible)
onUnmounted(() => { disposed = true; clearTimeout(timer); document.removeEventListener('visibilitychange', visible) })
</script>

<template>
  <section>
    <p v-if="session?.role === 'admin'"><router-link to="/configuration-applications">查看配置应用任务与日志 →</router-link></p>
    <div class="v3-page-heading"><div><router-link v-if="route.params.id" to="/deployments" class="v3-back">← 返回部署任务</router-link><h1>{{ route.params.id ? '任务进度与日志' : '部署任务' }}</h1><p class="v3-muted">{{ route.params.id ? '运行中每 3 秒更新，连接恢复后从已读游标续读。' : '查看持久化任务、恢复操作与进程日志。' }}</p></div><el-button :loading="loading" @click="refresh">刷新</el-button></div>
    <el-alert v-if="actionError" :title="actionError" type="error" :closable="false" /><el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-card v-if="!route.params.id" shadow="never"><form class="v3-filters" @submit.prevent="search"><el-input v-model="node" placeholder="按节点 ID 筛选" clearable aria-label="按节点 ID 筛选" /><el-button type="primary" native-type="submit">查询</el-button><el-button @click="node = ''; search()">重置</el-button></form><el-table :data="items" row-key="id" empty-text="暂无部署任务"><el-table-column label="节点" min-width="150"><template #default="{row}"><router-link :to="`/servers/${encodeURIComponent(row.node)}`">{{ row.node }}</router-link></template></el-table-column><el-table-column label="操作" width="110"><template #default="{row}">{{ kindLabel(row.kind) }}</template></el-table-column><el-table-column label="状态" width="110"><template #default="{row}"><el-tag :type="row.status === 'succeeded' ? 'success' : ['failed','interrupted'].includes(row.status) ? 'danger' : 'info'">{{ jobLabel(row.status) }}</el-tag></template></el-table-column><el-table-column label="更新时间" min-width="190"><template #default="{row}">{{ timeText(row.updated_at) }}</template></el-table-column><el-table-column label="操作人" prop="username" min-width="100" /><el-table-column label="详情" width="110"><template #default="{row}"><router-link :to="`/deployments/${encodeURIComponent(row.id)}`">查看日志</router-link></template></el-table-column></el-table><div class="v3-pagination"><el-button :disabled="!route.query.cursor || loading" @click="page('')">回到首页</el-button><span>每页最多 20 条</span><el-button :disabled="!next || loading" @click="page(next)">下一页</el-button></div></el-card>
    <template v-else-if="detail"><el-card shadow="never"><div class="v3-job-heading"><div><el-tag>{{ jobLabel(detail.job.status) }}</el-tag><h2>{{ detail.job.node }} · {{ kindLabel(detail.job.kind) }}</h2></div><router-link :to="`/servers/${encodeURIComponent(detail.job.node)}`">查看服务器 →</router-link></div><dl class="v3-detail-grid"><dt>当前阶段</dt><dd>{{ phaseLabel(detail.phase) }}</dd><dt>配置版本</dt><dd>{{ detail.job.node_version }}</dd><dt>更新时间</dt><dd>{{ timeText(detail.job.updated_at) }}</dd><dt>任务 ID</dt><dd>{{ detail.job.id }}</dd></dl><el-alert v-if="detail.job.error_code" :title="codeLabel(detail.job.error_code)" type="error" :closable="false" /><el-alert v-if="detail.recovery_required" :title="detail.recovery_reason || '任务已保留恢复资料，可继续原任务或回退。'" type="warning" :closable="false" /><div v-if="session?.role === 'admin'" class="v3-actions"><el-button v-if="detail.can_resume" type="primary" :loading="acting" @click="recover('resume')">继续原任务</el-button><el-popconfirm v-if="detail.can_rollback" title="确认回退该节点到原服务？保留未确认事件。" @confirm="recover('rollback')"><template #reference><el-button :disabled="acting" type="warning">回退</el-button></template></el-popconfirm></div></el-card>
      <el-card shadow="never"><div class="v3-job-heading"><h2>进程日志</h2><span class="v3-muted">已读至 #{{ lastCursor }}</span></div><p v-if="clipped" class="v3-muted">页面仅保留最近 1000 行，完整记录仍保存在主控。</p><ol v-if="logs.length" class="v3-logs" aria-label="部署进程日志"><li v-for="line in logs" :key="line.cursor"><time>{{ timeText(line.created_at) }}</time><span class="v3-log-phase">{{ phaseLabel(line.phase) }}</span><span>{{ codeLabel(line.code) }}</span></li></ol><el-empty v-else :description="loading ? '正在读取日志' : '暂无阶段日志'" /></el-card>
    </template>
  </section>
</template>
