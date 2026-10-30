<script setup lang="ts">
import CursorPagination from './CursorPagination.vue'
import { useCursorPage } from './cursorPage'
import { computed, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { V3ConfigurationBackup, V3ConfigurationDeletePreview, V3ConfigurationDeleteJob } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import ConfigurationDeleteTask from './ConfigurationDeleteTask.vue'
import ConfigurationRestorePanel from './ConfigurationRestorePanel.vue'

const pagination = useCursorPage(), pageLimit = pagination.limit

const { client, session } = useConsole(), route = useRoute(), router = useRouter(), read = useReadScope()
const admin = computed(() => session.value?.role === 'admin')
const secure = window.location.protocol === 'https:'
const rows = ref<V3ConfigurationBackup[]>([]), next = ref(''), loaded = ref(false), busy = ref(false), error = ref(''), message = ref('')
const importing = ref(false), exporting = ref<V3ConfigurationBackup>(), mode = ref<'yaml' | 'age'>('yaml')
const content = ref(''), file = ref<File>(), password = ref(''), confirm = ref(''), reading = ref(false), fileInput = ref<HTMLInputElement>()
const cursor = computed(() => typeof route.query.deployment_cursor === 'string' ? route.query.deployment_cursor : '')
const previous = new Map<string, string>()
const selected = ref<V3ConfigurationBackup[]>([]), table = ref<{ clearSelection(): void }>(), deleteAvailable = ref(false)
const deleting = ref(false), deletion = ref<V3ConfigurationDeletePreview>(), deleteConfirmed = ref(false), deleteKey = ref(''), taskID = ref('')
const jobs = ref<V3ConfigurationDeleteJob[]>([]), jobsNext = ref(''), jobsCursor = ref(''), jobsPrevious = new Map<string, string>(), jobRead = useReadScope()
const restorePanel = ref<InstanceType<typeof ConfigurationRestorePanel>>(), savedRestoreAvailable = ref(false)
const deleteExpired = ref(false)
let expiryTimer: ReturnType<typeof setTimeout> | undefined
function clearSelection() { selected.value = []; table.value?.clearSelection() }
function closeDelete() { deleting.value = false; deletion.value = undefined; deleteConfirmed.value = false; deleteKey.value = ''; clearTimeout(expiryTimer) }
async function previewDelete(records: V3ConfigurationBackup[]) {
  if (busy.value || !deleteAvailable.value || records.length < 1 || records.length > 200) return
  // The request is restricted to explicit rows on the currently rendered page.
  const keys = records.filter(row => row.can_delete && rows.value.some(current => current.record_key === row.record_key)).map(row => row.record_key)
  if (keys.length !== records.length) return
  closeDelete(); deleting.value = true; busy.value = true; error.value = ''; message.value = ''; deleteExpired.value = false
  try {
    const value = await client.previewConfigurationDelete(keys, operation.signal)
    if (!alive) return
    deletion.value = value; deleteKey.value = crypto.randomUUID()
    const remaining = Date.parse(value.expires_at) - Date.now()
    deleteExpired.value = remaining <= 0
    if (remaining > 0) expiryTimer = setTimeout(() => { deleteExpired.value = true }, remaining)
  } catch (e) { feedback(e) }
  finally { if (alive) busy.value = false }
}
async function submitDelete() {
  if (busy.value || !deletion.value || !deleteConfirmed.value || deleteExpired.value || deletion.value.eligible < 1) return
  busy.value = true; error.value = ''; message.value = ''
  try {
    const value = await client.deleteConfigurationBackups(deletion.value.token, deleteKey.value, operation.signal)
    if (!alive) return
    taskID.value = value.id; closeDelete(); clearSelection(); message.value = '删除任务已创建，请查看实际处理进度；尚不代表删除完成。'
    await Promise.all([load(), loadJobs()])
  } catch (e) { feedback(e) }
  finally { if (alive) busy.value = false }
}
const jobStatus = (status: string) => ({ queued: '已排队', running: '处理中', succeeded: '已完成', partial: '部分完成', cancelled: '已取消' } as Record<string, string>)[status] || status
async function loadJobs() {
  if (!admin.value) return
  const after = jobsCursor.value
  await jobRead.run(signal => client.configurationDeleteJobs(after, 20, signal), value => {
    jobs.value = value.items; jobsNext.value = value.next_cursor
    if (!value.items.length && after) { jobsCursor.value = jobsPrevious.get(after) || ''; void loadJobs() }
  })
}
async function pageJobs(forward: boolean) {
  const target = forward ? jobsNext.value : jobsPrevious.get(jobsCursor.value) || ''
  if (forward) jobsPrevious.set(target, jobsCursor.value)
  jobsCursor.value = target; await loadJobs()
}
async function deletionFinished() { await Promise.all([load(), loadJobs()]) }
let alive = true, fileGeneration = 0, operation = new AbortController(), createKey = '', importKey = ''
const sourceText = (source: string) => ({ manual: '手动', before_edit: '编辑前', before_deploy: '部署前', before_restore: '恢复前', import: '导入' } as Record<string, string>)[source] || '历史备份'
function feedback(e: unknown) { if (alive) error.value = e instanceof Error ? e.message : '操作失败，请稍后重试' }
function clearSecrets() { fileGeneration++; content.value = ''; file.value = undefined; password.value = ''; confirm.value = ''; reading.value = false }
function closeDialog() { importing.value = false; exporting.value = undefined; clearSecrets() }
watch([content, file, password, mode], () => { importKey = '' })
watch(mode, clearSecrets)
async function load() {
  if (!admin.value) return
  const after = cursor.value
  await read.run(signal => client.configurationBackups(after, pageLimit.value, signal), result => {
    clearSelection(); rows.value = result.items; next.value = result.next_cursor; loaded.value = true; deleteAvailable.value = result.delete_available; savedRestoreAvailable.value = result.saved_restore_available === true
    if (!result.items.length && after) void router.replace({ query: { ...route.query, deployment_cursor: previous.get(after) || undefined } })
  })
}
async function firstPage() { if (cursor.value) await router.replace({ query: { ...route.query, deployment_cursor: undefined } }); else await load() }
async function page(forward: boolean) {
  const target = forward ? next.value : previous.get(cursor.value) || ''
  if (forward) previous.set(target, cursor.value)
  await router.push({ query: { ...route.query, deployment_cursor: target || undefined } })
}
async function create() {
  if (busy.value || !admin.value) return
  busy.value = true; error.value = ''; message.value = ''; createKey ||= crypto.randomUUID()
  try {
    const result = await client.createConfigurationBackup(createKey, operation.signal)
    if (!alive) return
    createKey = ''; message.value = `已备份已保存配置，共 ${result.node_count} 个子服务器；不代表已部署。`; await firstPage()
  } catch (e) { feedback(e) }
  finally { if (alive) busy.value = false }
}
function openImport() { if (!secure) return; clearSecrets(); importKey = ''; error.value = ''; importing.value = true }
function openExport(row: V3ConfigurationBackup) { if (!secure) return; clearSecrets(); error.value = ''; exporting.value = row }
async function chosen(event: Event) {
  const input = event.target as HTMLInputElement, files = Array.from(input.files || []); input.value = ''
  const current = ++fileGeneration, selected = files[0], limit = (mode.value === 'age' ? 34 : 32) * 1024 * 1024
  error.value = ''; reading.value = false
  if (files.length !== 1 || !selected?.size || selected.size > limit) { error.value = `请选择一个非空且不超过 ${mode.value === 'age' ? 34 : 32} MiB 的备份文件，原输入已保留`; return }
  if (mode.value === 'age') { file.value = selected; return }
  reading.value = true
  try {
    const text = await selected.text()
    if (!alive || current !== fileGeneration || !importing.value) return
    if (!text.trim() || new TextEncoder().encode(text).byteLength > limit) { error.value = '文件为空或解码后超过 32 MiB，原输入已保留'; return }
    content.value = text
  } catch { if (alive && current === fileGeneration) error.value = '文件读取失败，原输入已保留' }
  finally { if (alive && current === fileGeneration) reading.value = false }
}
async function importBackup() {
  if (busy.value || reading.value || !admin.value || !secure || mode.value === 'age' && !file.value) return
  busy.value = true; error.value = ''; message.value = ''; importKey ||= crypto.randomUUID()
  try {
    const result = mode.value === 'age'
      ? await client.importEncryptedConfigurationBackup(file.value!, password.value, importKey, operation.signal)
      : await client.importConfigurationBackup(content.value, importKey, operation.signal)
    if (!alive) return
    importKey = ''; closeDialog(); message.value = `已加入备份列表，未覆盖或应用配置。${result.needs_completion ? '此备份含省略字段，需补全。' : ''}`; await firstPage()
  } catch (e) { feedback(e) }
  finally { if (alive) busy.value = false }
}
async function download(row: V3ConfigurationBackup, encrypted = false) {
  if (busy.value || !admin.value || encrypted && !secure) return
  busy.value = true; error.value = ''; message.value = ''
  try {
    const blob = encrypted
      ? await client.exportEncryptedConfigurationBackup(row.id, password.value, confirm.value, operation.signal)
      : await client.exportConfigurationBackup(row.id, operation.signal)
    if (!alive) return
    const url = URL.createObjectURL(blob), anchor = document.createElement('a')
    try { anchor.href = url; anchor.download = `webscan-configuration-${row.id}.${encrypted ? 'age' : 'yaml'}`; anchor.click() }
    finally { setTimeout(() => URL.revokeObjectURL(url), 1000) }
    closeDialog(); message.value = '已生成配置下载，请检查浏览器下载结果。'
  } catch (e) { feedback(e) }
  finally { if (alive) busy.value = false }
}
watch([cursor,pageLimit], () => { clearSelection(); read.cancel(); void load() }, { immediate: true })
void loadJobs()
onUnmounted(() => { alive = false; operation.abort(); clearTimeout(expiryTimer); clearSecrets() })
</script>

<template>
  <el-card shadow="never">
    <div class="card-heading v3-job-heading"><h2>部署配置存档</h2><div v-if="admin" class="v3-actions"><el-button :disabled="busy || !secure" @click="openImport">导入配置备份</el-button><el-button type="primary" :loading="busy && !importing && !exporting" :disabled="busy" @click="create">手动备份部署配置</el-button></div></div>
    <p class="v3-muted">备份包含主控启动时配置、数据库中已保存的设置和子服务器配置；不包含后来修改的磁盘 YAML，也不表示配置已生效。</p>
    <p class="v3-muted">不包含监控数据库、历史、后台密码及外部私钥、PKI、独立凭据文件。完整灾备仍需一致性数据库备份、独立密钥和配套文件。</p>
    <el-alert title="配置备份可恢复到保存配置，之后仍需独立应用；导入、导出及删除不会切换运行状态。" type="info" :closable="false" />
    <el-alert v-if="!admin" title="部署配置存档仅允许管理员管理。" type="info" :closable="false" />
    <template v-else>
      <el-alert v-if="!secure" title="导入与加密导出需使用 HTTPS；当前可进行脱敏导出。" type="warning" :closable="false" />
      <el-alert v-if="error && !importing && !exporting && !deleting" :title="error" type="error" :closable="false" />
      <el-alert v-if="message" :title="message" type="success" :closable="false" />
      <el-alert v-if="read.error.value" :title="`${read.error.value}；已有结果保留`" type="error" :closable="false" />
      <el-button :loading="read.loading.value" :disabled="busy" @click="load">刷新配置存档</el-button>
      <div class="v3-actions"><el-button type="danger" :disabled="busy || !deleteAvailable || !selected.length || selected.length > 200" @click="previewDelete(selected)">删除已选（{{ selected.length }}）</el-button><span class="v3-muted">仅当前页明确勾选的备份；有引用的备份不能删除。</span></div>
      <el-table ref="table" :data="rows" row-key="id" @selection-change="selected = $event">
        <el-table-column type="selection" width="45" :selectable="(row: V3ConfigurationBackup) => deleteAvailable && row.can_delete && !busy" />
        <el-table-column label="备份时间" min-width="175"><template #default="{ row }">{{ timeText(row.created_at) }}</template></el-table-column>
        <el-table-column label="来源" min-width="90"><template #default="{ row }">{{ sourceText(row.source) }}</template></el-table-column>
        <el-table-column prop="settings_version" label="设置版本" width="100" /><el-table-column prop="node_count" label="子服务器数" width="110" />
        <el-table-column label="补全状态" min-width="130"><template #default="{ row }">{{ row.needs_completion ? '含省略字段，需补全' : '未标记省略字段' }}</template></el-table-column>
        <el-table-column label="保护原因" min-width="130"><template #default="{ row }">{{ row.delete_reason || '—' }}</template></el-table-column>
        <el-table-column label="导出" min-width="190"><template #default="{ row }"><el-button link type="primary" :disabled="busy" @click="download(row)">脱敏 YAML</el-button><el-button link type="primary" :disabled="busy || !secure" @click="openExport(row)">加密配置包</el-button></template></el-table-column>
        <el-table-column label="恢复" width="100"><template #default="{ row }"><el-button link type="primary" :disabled="busy || !secure || !savedRestoreAvailable" @click="restorePanel?.start(row.id)">恢复预览</el-button></template></el-table-column>
        <el-table-column label="删除" width="100"><template #default="{ row }"><el-button link type="danger" :disabled="busy || !deleteAvailable || !row.can_delete" :title="row.delete_reason" @click="previewDelete([row])">删除</el-button></template></el-table-column>
        <template #empty>{{ read.loading.value ? '正在读取…' : read.error.value ? '存档读取失败' : loaded ? '暂无部署配置存档' : '尚未读取' }}</template>
      </el-table>
      <CursorPagination :previous="!!cursor" :next="!!next" :limit="pageLimit" :loading="read.loading.value || busy" @previous="page(false)" @next="page(true)" @resize="size => { previous.clear(); router.push({query: {...route.query, deployment_cursor: undefined, limit: String(size)}}) }" />
      <ConfigurationRestorePanel ref="restorePanel" @changed="load" />
      <h3>本账号删除任务</h3>
      <el-alert v-if="jobRead.error.value" :title="`${jobRead.error.value}；已读取任务保留`" type="error" :closable="false" />
      <el-button :loading="jobRead.loading.value" @click="loadJobs">刷新删除任务</el-button>
      <el-table :data="jobs" row-key="id"><el-table-column label="创建时间" min-width="175"><template #default="{ row }">{{ timeText(row.created_at) }}</template></el-table-column><el-table-column label="状态" width="110"><template #default="{ row }">{{ jobStatus(row.status) }}</template></el-table-column><el-table-column label="结果" min-width="240"><template #default="{ row }">选中 {{ row.selected }} · 已删除 {{ row.deleted }} · 跳过 {{ row.skipped }} · 失败 {{ row.failed }}</template></el-table-column><el-table-column label="进度" width="110"><template #default="{ row }"><el-button link type="primary" @click="taskID = row.id">查看进度</el-button></template></el-table-column></el-table>
      <div class="v3-pagination"><el-button :disabled="!jobsCursor || jobRead.loading.value" @click="pageJobs(false)">上一页任务</el-button><span>每页 20 条</span><el-button :disabled="!jobsNext || jobRead.loading.value" @click="pageJobs(true)">下一页任务</el-button></div>
    </template>
  </el-card>
  <el-dialog :model-value="deleting" title="永久删除部署配置备份" class="v3-node-dialog" width="760px" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @update:model-value="!$event && closeDelete()">
    <p>仅处理本次明确选择的备份，永久删除不可恢复。不会修改运行配置；删除记录不保证立即释放磁盘空间。</p>
    <template v-if="deletion"><p>可删除 {{ deletion.eligible }} · 受保护或不存在 {{ deletion.protected }} · 预览有效至 {{ timeText(deletion.expires_at) }}</p><el-table :data="deletion.items" row-key="id"><el-table-column prop="id" label="备份标识" min-width="210" /><el-table-column label="检查结果" min-width="230"><template #default="{ row }">{{ row.reason || '可删除；执行时再次检查引用' }}</template></el-table-column></el-table><el-checkbox v-model="deleteConfirmed" :disabled="busy || deleteExpired">我确认永久删除本次可删除的备份</el-checkbox></template>
    <template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="error" :title="error" type="error" :closable="false" /><span v-else>{{ busy ? '正在提交或检查，请稍候…' : deleteExpired ? '预览已过期，请关闭后重新预览。' : '任务创建后仍需查看实际删除、跳过及失败结果。' }}</span></div><div class="v3-actions"><el-button :disabled="busy" @click="closeDelete">取消</el-button><el-button type="danger" :loading="busy" :disabled="!deletion?.eligible || !deleteConfirmed || deleteExpired" @click="submitDelete">确认创建删除任务</el-button></div></template>
  </el-dialog>
  <el-dialog :model-value="!!taskID" title="部署配置删除进度" class="v3-node-dialog" width="860px" @update:model-value="taskID = ''"><ConfigurationDeleteTask v-if="taskID" :key="taskID" :id="taskID" @finished="deletionFinished" /></el-dialog>
  <el-dialog v-model="importing" title="导入部署配置备份" class="v3-node-dialog" width="740px" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @closed="!importing && !exporting && clearSecrets()">
    <p>只加入备份列表，不覆盖或部署。支持原生 v3 配置文档；旧版 YAML 备份映射尚未接入。</p>
    <el-radio-group v-model="mode" :disabled="busy"><el-radio value="yaml">YAML（最大 32 MiB）</el-radio><el-radio value="age">age 加密包（最大 34 MiB）</el-radio></el-radio-group>
    <input ref="fileInput" type="file" hidden @change="chosen" /><el-button :loading="reading" :disabled="busy" @click="fileInput?.click()">选择配置文件</el-button>
    <el-input v-if="mode === 'yaml'" v-model="content" type="textarea" :rows="10" aria-label="部署配置 YAML" :disabled="busy || reading" />
    <template v-else><p>{{ file ? '已选择加密包' : '请选择加密包' }}</p><el-input v-model="password" type="password" autocomplete="off" aria-label="导入密码" placeholder="加密包密码" :disabled="busy" /></template>
    <template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="error" :title="error" type="error" :closable="false" /><span v-else>{{ busy ? '正在校验并加入备份列表…' : '密码仅用于本次操作，关闭窗口后清除。' }}</span></div><div class="v3-actions"><el-button :disabled="busy" @click="closeDialog">取消</el-button><el-button type="primary" :loading="busy" :disabled="reading || (mode === 'yaml' ? !content.trim() : !file || !password)" @click="importBackup">校验并存档</el-button></div></template>
  </el-dialog>
  <el-dialog :model-value="!!exporting" title="导出包含配置凭据的加密包" class="v3-node-dialog" width="600px" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @update:model-value="closeDialog">
    <p>使用标准 age 密码加密。请另行安全保存密码；本系统不保存密码。包内不附外部私钥和独立凭据文件。</p>
    <el-input v-model="password" type="password" autocomplete="new-password" aria-label="导出密码" placeholder="12～1024 字节" :disabled="busy" /><el-input v-model="confirm" type="password" autocomplete="new-password" aria-label="确认导出密码" placeholder="再次输入密码" :disabled="busy" />
    <template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="error" :title="error" type="error" :closable="false" /><span v-else-if="busy">正在生成加密包…</span></div><div class="v3-actions"><el-button :disabled="busy" @click="closeDialog">取消</el-button><el-button type="primary" :loading="busy" :disabled="!password || !confirm" @click="exporting && download(exporting, true)">加密并下载</el-button></div></template>
  </el-dialog>
</template>
