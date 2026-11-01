<script setup lang="ts">
import PageHeading from './PageHeading.vue'
import { computed, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { V3RetentionPolicy, V3RetentionPolicyView, V3RetentionStatus } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import HistoryStorage from './HistoryStorage.vue'
import Audit from './Audit.vue'
import RuntimeSettings from './RuntimeSettings.vue'

const { client, session } = useConsole(), route = useRoute(), router = useRouter(), read = useReadScope()
const groupLabels: Record<string,string> = {monitoring:'公共监控', collector:'主控指标采集', metrics:'指标历史保留', website_monitor:'网站检测', backup:'自动完整备份', feishu:'飞书通知', email:'邮箱通知', retention:'历史与备份', storage:'存储与清理', audit:'操作审计'}
const tab = computed(() => route.query.storage === '1' ? 'storage' : route.query.group === '历史与备份' ? 'retention' : ['runtime','retention','storage','audit'].includes(String(route.query.tab)) ? String(route.query.tab) : 'runtime')
const runtimeGroup = computed(() => ['monitoring','collector','metrics','website_monitor','backup','feishu','email'].includes(String(route.query.group)) ? String(route.query.group) : 'monitoring')
const category = computed(() => tab.value === 'runtime' ? runtimeGroup.value : tab.value)
function chooseCategory(value: string) { void router.push({path:'/settings', query: {tab:['retention','storage','audit'].includes(value) ? value : 'runtime', group:['retention','storage','audit'].includes(value) ? undefined : value}}) }
const fields: { key: keyof V3RetentionPolicy; label: string }[] = [
  { key: 'sqlite_events_days', label: '普通文件及运行事件' }, { key: 'security_events_days', label: '安全扫描命中事件' },
  { key: 'website_incidents_days', label: '网站故障历史' }, { key: 'server_alerts_days', label: '服务器告警历史' },
  { key: 'delivery_records_days', label: '飞书、邮箱通知历史' },
]
const baseline = ref<V3RetentionPolicyView>(), status = ref<V3RetentionStatus>(), draft = reactive<Record<string, string>>({})
const busy = ref(false), error = ref(''), message = ref(''), confirm = ref(false), reloadConfirm = ref(false)
const admin = computed(() => session.value?.role === 'admin')
const dirty = computed(() => !!baseline.value && fields.some(({ key }) => String(baseline.value!.policy[key]) !== draft[key]))
const changedElsewhere = computed(() => !!baseline.value && !!status.value && baseline.value.version !== status.value.policy.version)
let disposed = false, generation = 0, key = '', intent = ''
let pending: { policy: V3RetentionPolicy; version: number } | undefined
function adopt(value: V3RetentionPolicyView) { baseline.value = structuredClone(value); fields.forEach(({ key }) => { draft[key] = String(value.policy[key]) }) }
function edited() { message.value = ''; error.value = ''; pending = undefined; confirm.value = false }
async function load(discard = false) {
  if (busy.value) return
  await read.run(signal => client.retentionStatus(signal), value => {
    status.value = value
    if (discard || !baseline.value || !dirty.value) adopt(value.policy)
  })
}
function reload() { if (dirty.value) reloadConfirm.value = true; else void load(true) }
function prepare() {
  if (busy.value || !baseline.value || !dirty.value || !admin.value) return
  error.value = ''; message.value = ''
  const policy = {} as V3RetentionPolicy
  for (const { key, label } of fields) {
    const value = draft[key] || ''
    if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 3650) { error.value = `${label}：请输入 1～3650 天整数`; return }
    policy[key] = Number(value)
  }
  pending = { policy, version: baseline.value.version }
  if (fields.some(({ key }) => policy[key] < baseline.value!.policy[key])) confirm.value = true
  else void save()
}
async function save() {
  if (!pending || busy.value || !admin.value) return
  confirm.value = false; busy.value = true; error.value = ''; message.value = ''; const current = ++generation
  const submitted = structuredClone(pending), body = JSON.stringify(submitted)
  if (body !== intent) { intent = body; key = crypto.randomUUID() }
  try {
    const value = await client.saveRetentionPolicy(submitted.policy, submitted.version, key)
    if (disposed || generation !== current) return
    adopt({ policy: value.policy, version: value.version, updated_at: new Date().toISOString() })
    message.value = value.message; pending = undefined
    // A status query failure must not turn an acknowledged save into a failure.
    busy.value = false; void load()
  } catch (e) { if (!disposed && generation === current) error.value = e instanceof Error ? e.message : '保存失败' }
  finally { if (!disposed && generation === current) busy.value = false }
}
watch(tab, () => { confirm.value = false; reloadConfirm.value = false; read.cancel(); if (tab.value === 'retention') void load() }, { immediate: true })
onUnmounted(() => { disposed = true; generation++ })
const bytes = (value?: number) => value === undefined ? '—' : `${(value / 1024 / 1024).toFixed(2)} MiB`
</script>

<template>
  <PageHeading title="系统设置" />
  <el-card shadow="never"><div class="filters"><el-select :model-value="category" aria-label="设置分类" :disabled="busy" @update:model-value="chooseCategory(String($event))"><el-option v-for="(label,key) in groupLabels" :key="key" :value="key" :label="label" /></el-select><router-link to="/backups?tab=deployment">部署配置备份 →</router-link></div><p class="muted">修改主控已保存配置，保存前自动备份；应用前请核对变更预览。</p></el-card>
  <template v-if="tab === 'retention'">
    <el-alert v-if="read.error.value" :title="`${read.error.value}；已有内容保留`" type="error" :closable="false" />
    <el-card shadow="never"><div class="card-heading v3-job-heading"><h2>历史保留期限</h2><el-button :loading="read.loading.value" :disabled="busy" @click="reload">重新读取</el-button></div>
      <p class="v3-muted">按各类记录独立计算。当前异常、未完成任务和待投递通知继续受保护；调大期限不能找回已清理记录。</p>
      <p v-if="!baseline">{{ read.loading.value ? '正在读取保留期限…' : '保留期限尚未读取成功' }}</p>
      <template v-else>
        <p class="v3-muted">配置版本 {{ baseline.version }} · 更新时间 {{ timeText(baseline.updated_at) }}</p>
        <el-alert v-if="changedElsewhere" title="配置已被其他操作修改。当前草稿已保留，请重新读取后再提交。" type="warning" :closable="false" />
        <el-form label-position="top" class="form-grid v3-form-grid" @submit.prevent="prepare"><el-form-item v-for="field in fields" :key="field.key" :label="`${field.label}（天）`"><el-input v-model="draft[field.key]" :aria-label="field.label" inputmode="numeric" :disabled="busy || !admin" @input="edited" /></el-form-item></el-form>
        <div class="v3-save-feedback" role="status" aria-live="polite"><el-alert v-if="error" :title="error" type="error" :closable="false" /><el-alert v-else-if="message" :title="message" type="success" :closable="false" /><p v-else>{{ busy ? '正在保存并应用保留期限…' : dirty ? '保留期限已修改，尚未保存。' : admin ? '各项支持 1～3650 天整数，保存后生效。' : '只有管理员可以修改保留期限。' }}</p></div>
        <el-button v-if="admin" type="primary" :loading="busy" :disabled="!dirty || changedElsewhere || read.loading.value" @click="prepare">保存并应用保留期限</el-button>
      </template>
    </el-card>
    <el-card v-if="status" shadow="never"><h2>自动清理状态</h2><div class="detail-grid v3-detail-grid"><div><span>工作器</span><strong>{{ status.worker_healthy === null ? '未知，尚无心跳证据' : status.worker_healthy ? '正常' : '异常' }} {{ status.reason }}</strong></div><div><span>心跳时间</span><strong>{{ timeText(status.worker_heartbeat) }}</strong></div><div><span>业务表及索引</span><strong>{{ bytes(status.managed_storage_bytes) }}（当前 PostgreSQL 应用 schema）</strong></div><div><span>最近清理</span><strong>{{ status.last_job ? `${status.last_job.status === 'succeeded' ? '已完成' : status.last_job.status === 'running' ? '执行中' : '已取消'} · 已清理 ${status.last_job.deleted} 条` : '暂无清理任务' }}</strong></div></div><p class="v3-muted">删除记录不等于立即释放磁盘。可复用空间由数据库后续写入使用；此处不包含时序库、导出文件或其他项目的数据。</p></el-card>
  </template>
  <RuntimeSettings v-else-if="tab === 'runtime'" :group="runtimeGroup" />
  <HistoryStorage v-else-if="tab === 'storage'" />
  <Audit v-else />
  <el-dialog v-model="confirm" title="确认缩短保留期限" width="530px" class="v3-node-dialog"><p>缩短期限后，符合保护规则的旧历史将被自动永久清理。删除不可逆，调大期限不能恢复。</p><p>账号、网站配置、当前异常和未完成任务不属于本次历史清理范围。</p><template #footer><el-button @click="confirm = false">返回修改</el-button><el-button type="danger" @click="save">确认保存并应用</el-button></template></el-dialog>
  <el-dialog v-model="reloadConfirm" title="重新读取保留期限" width="480px" class="v3-node-dialog"><p>重新读取将放弃当前保留期限草稿，使用数据库中的最新配置。</p><template #footer><el-button @click="reloadConfirm = false">保留草稿</el-button><el-button type="primary" @click="reloadConfirm = false; load(true)">放弃草稿并读取</el-button></template></el-dialog>
</template>
