<script setup lang="ts">
import CursorPagination from './CursorPagination.vue'
import { useCursorPage } from './cursorPage'
import PageHeading from './PageHeading.vue'
import { computed, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { V3WebsiteBackup, V3WebsiteBackupPreview } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import ConfigurationBackups from './ConfigurationBackups.vue'

const pagination = useCursorPage(), pageLimit = pagination.limit

const { client, session } = useConsole(), route = useRoute(), router = useRouter(), read = useReadScope()
const tab = computed(() => route.query.tab === 'deployment' ? 'deployment' : 'website')
const cursor = computed(() => typeof route.query.cursor === 'string' ? route.query.cursor : '')
const rows = ref<V3WebsiteBackup[]>([]), checked = ref<V3WebsiteBackup[]>([]), next = ref(''), loaded = ref(false)
const busy = ref(false), error = ref(''), message = ref(''), importing = ref(false), content = ref(''), reading = ref(false), fileInput = ref<HTMLInputElement>()
const remove = ref<V3WebsiteBackup[]>([]), restoring = ref<V3WebsiteBackup>(), preview = ref<V3WebsiteBackupPreview>(), previewAt = ref(0)
const canWrite = computed(() => !!session.value && session.value.role !== 'viewer')
const previous = new Map<string, string>()
let disposed = false, generation = 0, fileGeneration = 0, intent = '', key = '', downloadController: AbortController | undefined
function requestKey(body: unknown) { const next = JSON.stringify(body); if (intent !== next) { intent = next; key = crypto.randomUUID() }; return key }
const sourceText = (source: string) => ({ manual: '手动', import: '导入', 'pre-restore': '恢复前', before_restore: '恢复前', 'before-restore': '恢复前', restore: '恢复前' } as Record<string, string>)[source] || `历史来源：${source}`
function selection(value: V3WebsiteBackup[]) { checked.value = value.filter(value => rows.value.some(row => row.id === value.id && row.can_delete)) }
async function load() {
  if (tab.value !== 'website') return
  const after = cursor.value
  await read.run(signal => client.websiteBackups(after, pageLimit.value, signal), value => {
    rows.value = value.items; next.value = value.next_cursor; checked.value = []; loaded.value = true
    if (!value.items.length && after) { const before = previous.get(after) || ''; previous.delete(after); void router.replace({ path: '/backups', query: { tab: 'website', limit: pageLimit.value === 20 ? undefined : String(pageLimit.value), ...(before ? { cursor: before } : {}) } }) }
  })
}
async function create() {
  if (busy.value || !canWrite.value) return
  busy.value = true; error.value = ''; message.value = ''; const current = generation
  try {
    const value = await client.createWebsiteBackup(requestKey({ action: 'create' }))
    if (disposed || current !== generation) return
    intent = ''; message.value = `网站配置已备份，共 ${value.count} 个网站。`; await firstPage()
  } catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '创建备份失败' }
  finally { if (!disposed && current === generation) busy.value = false }
}
async function firstPage() { if (cursor.value) await router.replace({ path: '/backups', query: { tab: 'website' } }); else await load() }
async function page(forward: boolean) {
  const target = forward ? next.value : previous.get(cursor.value) || ''
  if (forward) previous.set(target, cursor.value)
  await router.push({ path: '/backups', query: { tab: 'website', limit: pageLimit.value === 20 ? undefined : String(pageLimit.value), ...(target ? { cursor: target } : {}) } })
}
function openImport() { fileGeneration++; content.value = ''; error.value = ''; message.value = ''; importing.value = true; reading.value = false }
function closeImport() { fileGeneration++; reading.value = false; importing.value = false; content.value = '' }
async function fileChosen(event: Event) {
  const input = event.target as HTMLInputElement, files = Array.from(input.files || []); input.value = ''; const current = ++fileGeneration
  error.value = ''
  if (files.length !== 1 || !files[0]?.size || files[0].size > 2 * 1024 * 1024) { reading.value = false; error.value = '每次请选择一个非空且不超过 2 MiB 的网站备份文件'; return }
  reading.value = true
  try {
    const text = await files[0].text()
    if (disposed || current !== fileGeneration || !importing.value) return
    if (!text.trim() || new TextEncoder().encode(text).byteLength > 2 * 1024 * 1024) { error.value = '文件为空或解码后超过 2 MiB，原输入已保留'; return }
    content.value = text
  } catch { if (!disposed && current === fileGeneration && importing.value) error.value = '文件读取失败，原输入已保留' }
  finally { if (!disposed && current === fileGeneration) reading.value = false }
}
async function importBackup() {
  if (busy.value || reading.value || !canWrite.value) return
  busy.value = true; error.value = ''; message.value = ''; const current = generation
  try {
    const value = await client.importWebsiteBackupText(content.value, requestKey({ action: 'import', content: content.value }))
    if (disposed || current !== generation) return
    intent = ''; closeImport(); message.value = `已导入 ${value.count} 个网站的配置备份，尚未恢复。`; await firstPage()
  } catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '导入失败' }
  finally { if (!disposed && current === generation) busy.value = false }
}
async function exportBackup(row: V3WebsiteBackup) {
  if (busy.value) return
  busy.value = true; error.value = ''; message.value = ''; const current = generation
  try {
    const doc = await client.exportWebsiteBackup(row.id, (downloadController = new AbortController()).signal)
    if (disposed || current !== generation) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' })), anchor = document.createElement('a')
    anchor.href = url; anchor.download = `webscan-websites-${row.id}.json`; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000)
    message.value = '已生成网站配置 JSON 下载。'
  } catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '导出失败' }
  finally { if (!disposed && current === generation) busy.value = false }
}
async function inspect(row: V3WebsiteBackup) {
  if (busy.value || !canWrite.value) return
  busy.value = true; restoring.value = row; preview.value = undefined; error.value = ''; message.value = ''; const current = generation
  try {
    const value = await client.previewWebsiteBackup(row.id)
    if (disposed || current !== generation) return
    preview.value = value; previewAt.value = Date.now(); void load()
  } catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '恢复预览失败' }
  finally { if (!disposed && current === generation) busy.value = false }
}
async function restore() {
  if (!restoring.value || !preview.value?.token || busy.value || !canWrite.value) return
  if (Date.now() - previewAt.value >= 600_000) { preview.value = undefined; error.value = '恢复预览已过期，请关闭后重新预览'; return }
  const id = restoring.value.id, token = preview.value.token, current = generation; busy.value = true; error.value = ''
  try {
    const value = await client.restoreWebsiteBackup(id, token, requestKey({ action: 'restore', id, token }))
    if (disposed || current !== generation) return
    intent = ''; restoring.value = undefined; preview.value = undefined
    message.value = `网站配置已合并恢复：新增 ${value.added}，更新 ${value.updated}，不变 ${value.unchanged}。恢复前配置已自动备份。`; await firstPage()
  } catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '恢复失败，配置未确认变更' }
  finally { if (!disposed && current === generation) busy.value = false }
}
function prepareRemove(values: V3WebsiteBackup[]) {
  if (busy.value || !canWrite.value || !values.length || values.length > 200 || values.some(value => !value.can_delete)) return
  remove.value = values.map(value => ({ ...value })); error.value = ''; message.value = ''
}
async function deleteSelected() {
  if (busy.value || !remove.value.length || !canWrite.value) return
  busy.value = true; error.value = ''; const current = generation, ids = remove.value.map(value => value.id)
  try {
    const value = await client.deleteWebsiteBackups(ids, requestKey({ action: 'delete', ids }))
    if (disposed || current !== generation) return
    intent = ''; remove.value = []; message.value = `已删除 ${value.deleted} 份备份，跳过 ${value.skipped.length} 份。${value.skipped.map(value => `${value.id}：${value.reason}`).join('；')}`; await load()
  } catch (e) { if (!disposed && current === generation) error.value = e instanceof Error ? e.message : '备份删除失败' }
  finally { if (!disposed && current === generation) busy.value = false }
}
watch(() => route.fullPath, () => {
  // Cursor changes are only possible through explicit paging; a successful
  // mutation may move to page one while keeping its acknowledged feedback.
  read.cancel(); checked.value = []; rows.value = []; loaded.value = false; next.value = ''; void load()
}, { immediate: true })
watch(pageLimit, () => previous.clear())
watch(tab, () => { generation++; fileGeneration++; downloadController?.abort(); busy.value = false; reading.value = false; closeImport(); restoring.value = undefined; preview.value = undefined; remove.value = []; error.value = ''; message.value = ''; previous.clear(); intent = '' })
onUnmounted(() => { disposed = true; generation++; fileGeneration++; downloadController?.abort() })
</script>

<template><PageHeading title="备份管理"><template v-if="tab === 'website' && canWrite"><el-button :disabled="busy" @click="openImport">导入网站备份</el-button><el-button type="primary" :loading="busy && !importing && !restoring && !remove.length" :disabled="busy" @click="create">手动备份网站配置</el-button></template></PageHeading><el-card shadow="never"><div class="filters" aria-label="备份类别"><el-button :disabled="busy" :type="tab === 'website' ? 'primary' : 'default'" @click="router.push('/backups?tab=website')">网站配置</el-button><el-button :disabled="busy" :type="tab === 'deployment' ? 'primary' : 'default'" @click="router.push('/backups?tab=deployment')">部署配置</el-button></div><p class="muted">配置备份不包含监控数据库、故障历史或后台当前管理员密码。加密包不附外部私钥、PKI 和独立部署凭据；完整灾备还需要一致性数据库备份与配套资料。</p></el-card>
  <el-alert v-if="error && !importing && !restoring && !remove.length" :title="error" type="error" :closable="false" /><el-alert v-if="message" :title="message" type="success" :closable="false" />
  <ConfigurationBackups v-if="tab === 'deployment'" />
  <el-card v-else shadow="never"><div class="card-heading v3-job-heading"><h2>网站配置历史</h2><el-button :loading="read.loading.value" :disabled="busy" @click="load">刷新备份列表</el-button></div><p class="v3-muted">保存网站网址、关键词、关联服务器等配置。导入只加入列表；恢复前先预览，按网址合并，并自动备份当前配置。不包含监控数据库、故障历史或后台密码。</p><el-alert v-if="read.error.value" :title="`${read.error.value}；已有结果保留`" type="error" :closable="false" /><div v-if="canWrite" class="v3-history-toolbar"><el-button type="danger" :disabled="!checked.length || busy" @click="prepareRemove(checked)">删除已选（{{ checked.length }}）</el-button><span class="v3-muted">仅处理当前页勾选的备份，最多 200 份；有效恢复预览引用的备份受保护。</span></div><el-table :data="rows" row-key="id" @selection-change="selection"><el-table-column v-if="canWrite" type="selection" width="45" :selectable="(row: V3WebsiteBackup) => row.can_delete && !busy" /><el-table-column label="备份时间" min-width="175"><template #default="{ row }">{{ timeText(row.created_at) }}</template></el-table-column><el-table-column label="来源" min-width="110"><template #default="{ row }">{{ sourceText(row.source) }}</template></el-table-column><el-table-column prop="count" label="网站数" width="85" /><el-table-column label="最近恢复" min-width="175"><template #default="{ row }">{{ timeText(row.restored_at) }}<span v-if="row.result?.added !== undefined" class="v3-muted v3-block">新增 {{ row.result.added }} · 更新 {{ row.result.updated }} · 不变 {{ row.result.unchanged }}</span></template></el-table-column><el-table-column label="保护原因" min-width="140"><template #default="{ row }">{{ row.delete_reason || '—' }}</template></el-table-column><el-table-column label="操作" min-width="210"><template #default="{ row }"><el-button link type="primary" :disabled="busy" @click="exportBackup(row)">导出 JSON</el-button><el-button v-if="canWrite" link type="primary" :disabled="busy" @click="inspect(row)">恢复预览</el-button><el-button v-if="canWrite" link type="danger" :disabled="!row.can_delete || busy" :title="row.delete_reason" @click="prepareRemove([row])">删除</el-button></template></el-table-column><template #empty>{{ read.loading.value ? '正在读取…' : read.error.value ? '备份列表读取失败' : loaded ? '暂无网站备份' : '尚未查询' }}</template></el-table><CursorPagination :previous="!!cursor" :next="!!next" :limit="pageLimit" :loading="read.loading.value || busy" @previous="page(false)" @next="page(true)" @resize="pagination.resize" /></el-card>
  <el-dialog v-model="importing" title="导入网站配置备份" class="v3-node-dialog" width="740px" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @closed="closeImport"><p>请选择或粘贴 format_version: 1 的网站备份 JSON，最大 2 MiB。导入不会覆盖当前网站，也不会立即恢复。</p><input ref="fileInput" type="file" accept=".json,application/json" hidden @change="fileChosen" /><el-button :loading="reading" :disabled="busy" @click="fileInput?.click()">选择备份文件</el-button><el-input v-model="content" type="textarea" :rows="12" aria-label="网站备份 JSON" :disabled="busy || reading" class="v3-import-text" /><template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="error" :title="error" type="error" :closable="false" /><span v-else>{{ busy ? '正在校验并加入备份列表…' : reading ? '正在读取文件…' : '格式、版本、重复字段和参数由服务端校验。' }}</span></div><div class="v3-actions"><el-button :disabled="busy" @click="closeImport">取消</el-button><el-button type="primary" :loading="busy" :disabled="!content.trim() || reading" @click="importBackup">校验并加入备份列表</el-button></div></template></el-dialog>
  <el-dialog :model-value="!!restoring" title="网站配置恢复预览" class="v3-node-dialog" width="650px" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @update:model-value="restoring = undefined; preview = undefined"><p>按规范化网址合并，不删除备份中没有的网站。恢复软删除网站会复用原身份，故障历史和通知保留。</p><template v-if="preview"><p>新增 {{ preview.added }} · 更新 {{ preview.updated }} · 不变 {{ preview.unchanged }}</p><el-alert v-if="preview.unknown_nodes.length" :title="`以下服务器不存在，恢复时清除关联并由主服务器检测：${preview.unknown_nodes.join('、')}`" type="warning" :closable="false" /><p class="v3-muted">预览有效 10 分钟；配置或节点变化后需重新预览。恢复前在同一事务中备份当前网站配置，失败则停止。</p></template><template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="error" :title="error" type="error" :closable="false" /><span v-else-if="busy">{{ preview ? '正在备份当前配置并合并恢复…' : '正在生成恢复预览…' }}</span></div><div class="v3-actions"><el-button :disabled="busy" @click="restoring = undefined; preview = undefined">取消</el-button><el-button type="primary" :loading="busy" :disabled="!preview?.token" @click="restore">备份当前配置并合并恢复</el-button></div></template></el-dialog>
  <el-dialog :model-value="!!remove.length" title="永久删除网站配置备份" class="v3-node-dialog" width="600px" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @update:model-value="remove = []"><p>仅永久删除当前页明确选择的 {{ remove.length }} 份网站配置备份，不改变网站或故障历史。此操作不可逆，不保证立即释放磁盘空间。</p><p>服务端将重新检查引用和迁移保护；受保护的备份跳过并显示原因。</p><template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="error" :title="error" type="error" :closable="false" /><span v-else-if="busy">正在删除备份…</span></div><div class="v3-actions"><el-button :disabled="busy" @click="remove = []">取消</el-button><el-button type="danger" :loading="busy" @click="deleteSelected">确认永久删除 {{ remove.length }} 份备份</el-button></div></template></el-dialog>
</template>
