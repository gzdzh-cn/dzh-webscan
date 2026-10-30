<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { queryParams } from '../api'
import type { V3Node, V3Site, V3SiteFilter, V3SiteInput, V3SiteVersion, V3WebsiteOverview } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'

const { client, session } = useConsole(), route = useRoute(), router = useRouter()
const read = useReadScope(), summaryRead = useReadScope(), options = useReadScope()
const items = ref<V3Site[]>([]), detail = ref<V3Site>(), summary = ref<V3WebsiteOverview>(), nodes = ref<V3Node[]>([])
const filters = reactive({ q: '', node: '', status: '' }), next = ref(''), checked = ref<V3Site[]>([]), loaded = ref(false), applied = ref('')
const feedback = ref(''), operationError = ref(''), operating = ref(false), updated = ref(0)
const edit = ref(false), saving = ref(false), formError = ref(''), expected = ref(0), confirmation = ref(false), targets = ref<V3SiteVersion[]>([])
const blank = (): V3SiteInput => ({ id: 0, name: '', url: '', node: '', keyword: '', slow_alert: false, paused: false })
const form = reactive(blank())
const writable = computed(() => !!session.value && session.value.role !== 'viewer')
const selected = computed(() => typeof route.params.id === 'string' ? Number(route.params.id) : 0)
const cursor = computed(() => typeof route.query.cursor === 'string' ? route.query.cursor : '')
const scope = computed(() => JSON.stringify({ id: selected.value, q: route.query.q, node: route.query.node, status: route.query.status }))
const stale = computed(() => loaded.value && applied.value !== scope.value)
const actionsDisabled = computed(() => read.loading.value || stale.value || operating.value || saving.value)
const statusLabels: Record<string, string> = { normal: '正常', down: '无法访问', pending: '等待检查', unknown: '未知', migration_pending: '等待迁移切换' }
const emptyText = computed(() => read.error.value ? '网站读取失败，上次结果保留' : read.loading.value ? '正在读取网站…' : '没有匹配的网站')
const inputName = ref<{ focus: () => void }>(), inputURL = ref<{ focus: () => void }>()
let disposed = false, generation = 0, timer: ReturnType<typeof setTimeout> | undefined, editGeneration = 0, operationGeneration = 0
let saveIntent: { body: string; key: string } | undefined, deleteIntent: string | undefined, checkIntent: { body: string; key: string } | undefined
const predecessors = new Map<string, string>()
let cursorScope = ''
function status(site: V3Site) { return site.migration_pending ? '等待迁移切换' : site.paused ? '已暂停' : statusLabels[site.state.status] || '未知' }
function poll() { clearTimeout(timer); if (!disposed && !document.hidden && !edit.value && !confirmation.value) timer = setTimeout(() => { void load(); if (!selected.value && !summaryRead.loading.value) loadSummary() }, 30_000) }
async function load(replace = false) {
  if (disposed || document.hidden || read.loading.value && !replace) return
  clearTimeout(timer); const token = ++generation, key = scope.value, id = selected.value, after = cursor.value
  if (cursorScope !== key) { cursorScope = key; predecessors.clear() }
  if (id) {
    await read.run(signal => client.website(id, signal), value => { detail.value = value; loaded.value = true; applied.value = key; updated.value = Date.now() })
  } else {
    await read.run(signal => client.websites({ q: String(route.query.q || ''), node: String(route.query.node || ''), status: String(route.query.status || '') as V3SiteFilter['status'], cursor: after, limit: 20 }, signal), page => {
      items.value = page.items; next.value = page.next_cursor; checked.value = []; loaded.value = true; applied.value = key; updated.value = Date.now()
      if (!page.items.length && after) {
        const previous = predecessors.get(after) || ''; predecessors.delete(after)
        void router.replace({ path: '/websites', query: { ...route.query, cursor: previous || undefined } })
      }
    })
  }
  if (!disposed && token === generation) poll()
}
function loadSummary() { void summaryRead.run(signal => client.websiteOverview(signal), value => { summary.value = value }) }
function refresh() { void load(true); if (!selected.value) loadSummary() }
async function search() {
  const before = route.fullPath
  await router.push({ path: '/websites', query: Object.fromEntries(queryParams({ q: filters.q.trim(), node: filters.node, status: filters.status })) })
  if (before === route.fullPath) void load(true)
}
function page(after: string) { if (after) predecessors.set(after, cursor.value); void router.push({ path: '/websites', query: { ...route.query, cursor: after || undefined } }) }
function loadOptions(q = '') { void options.run(signal => client.servers(q, '', 20, signal), page => { nodes.value = page.items }) }
function open(site?: V3Site) {
  if (!writable.value || site?.migration_pending) return
  clearTimeout(timer); editGeneration++; saving.value = false; saveIntent = undefined; formError.value = ''; feedback.value = ''; operationError.value = ''; expected.value = site?.version || 0
  Object.assign(form, site ? { id: site.id, name: site.name, url: site.url, node: site.node, keyword: site.keyword, slow_alert: site.slow_alert, paused: site.paused } : blank())
  edit.value = true
}
function closeEdit() { editGeneration++; edit.value = false; saving.value = false; formError.value = ''; poll() }
function validForm() {
  if (!form.name.trim() || [...form.name.trim()].length > 100) { formError.value = '请填写 1～100 字的网站名称'; inputName.value?.focus(); return false }
  try { const url = new URL(form.url.trim()); if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) throw new Error() }
  catch { formError.value = '请填写完整的 HTTP／HTTPS 网站网址，网址不能包含账号或密码'; inputURL.value?.focus(); return false }
  if ([...form.keyword].length > 200) { formError.value = '关键词最多 200 字'; return false }
  return true
}
async function save() {
  if (saving.value || !writable.value || !validForm()) return
  const site = { ...form, name: form.name.trim(), url: form.url.trim() }, body = JSON.stringify({ site, expected: expected.value })
  if (saveIntent?.body !== body) saveIntent = { body, key: crypto.randomUUID() }
  const token = editGeneration; saving.value = true; formError.value = ''
  try {
    const value = await client.saveWebsite(site, expected.value, saveIntent.key)
    if (disposed || token !== editGeneration) return
    feedback.value = value.message; operationError.value = ''; closeEdit(); refresh()
  } catch (e) { if (!disposed && token === editGeneration) formError.value = e instanceof Error ? e.message : '网站保存失败' }
  finally { if (!disposed && token === editGeneration) saving.value = false }
}
function prepareDelete(sites: V3Site[]) {
  if (!writable.value || actionsDisabled.value || !sites.length || sites.some(site => site.migration_pending)) return
  clearTimeout(timer); operationGeneration++; targets.value = sites.map(site => ({ id: site.id, version: site.version })); deleteIntent = crypto.randomUUID()
  operationError.value = ''; confirmation.value = true
}
function closeDelete() { operationGeneration++; confirmation.value = false; operating.value = false; targets.value = []; poll() }
async function remove() {
  if (operating.value || !writable.value || !deleteIntent || !targets.value.length) return
  const token = operationGeneration; operating.value = true; operationError.value = ''
  try {
    const value = await client.deleteWebsites([...targets.value], deleteIntent)
    if (disposed || token !== operationGeneration) return
    feedback.value = `${value.message}（${value.deleted} 个网站）`; closeDelete(); checked.value = []
    if (selected.value) await router.push('/websites'); else refresh()
    loadSummary()
  } catch (e) { if (!disposed && token === operationGeneration) operationError.value = e instanceof Error ? e.message : '网站删除失败' }
  finally { if (!disposed && token === operationGeneration) operating.value = false }
}
async function check(site: V3Site) {
  if (!writable.value || actionsDisabled.value || site.paused || site.migration_pending) return
  const body = JSON.stringify({ id: site.id, version: site.version })
  if (checkIntent?.body !== body) checkIntent = { body, key: crypto.randomUUID() }
  const token = ++operationGeneration; operating.value = true; operationError.value = ''; feedback.value = ''
  try {
    const value = await client.checkWebsite(site.id, site.version, checkIntent.key)
    if (disposed || token !== operationGeneration) return
    feedback.value = `${value.message}，请等待工作器检测；当前结果尚未更新。`; checkIntent = undefined; refresh()
  } catch (e) { if (!disposed && token === operationGeneration) operationError.value = e instanceof Error ? e.message : '加入检测队列失败' }
  finally { if (!disposed && token === operationGeneration) operating.value = false }
}
function visibility() {
  clearTimeout(timer)
  if (document.hidden) { generation++; read.cancel(); summaryRead.cancel() }
  else if (!edit.value && !confirmation.value) refresh()
}
watch(() => route.fullPath, () => {
  filters.q = String(route.query.q || ''); filters.node = String(route.query.node || '')
  filters.status = ['normal', 'down', 'pending', 'paused', 'unknown', 'migration_pending'].includes(String(route.query.status)) ? String(route.query.status) : ''
  checked.value = []; operationGeneration++; operating.value = false; operationError.value = ''; closeEdit(); closeDelete(); void load(true)
}, { immediate: true })
onMounted(() => { loadOptions(); if (!selected.value) loadSummary(); document.addEventListener('visibilitychange', visibility) })
onUnmounted(() => { disposed = true; generation++; editGeneration++; operationGeneration++; clearTimeout(timer); document.removeEventListener('visibilitychange', visibility) })
</script>

<template>
  <section>
    <div class="v3-page-heading"><div><router-link v-if="selected" to="/websites" class="v3-back">← 返回网站列表</router-link><h1>{{ selected ? detail?.name || '网站详情' : '网站监控' }}</h1><p class="v3-muted">由主控统一检测；关联服务器用于归属管理。每 30 秒更新，后台标签暂停。</p></div><div class="v3-actions"><el-button :loading="read.loading.value" @click="refresh">刷新</el-button><el-button v-if="writable" type="primary" :disabled="selected ? !detail || detail.migration_pending || actionsDisabled : false" @click="open(selected ? detail : undefined)">{{ selected ? '编辑配置' : '添加网站' }}</el-button></div></div>
    <el-alert v-if="feedback" :title="feedback" type="success" :closable="false" /><el-alert v-if="operationError && !confirmation" :title="operationError" type="error" :closable="false" /><el-alert v-if="read.error.value" :title="`${read.error.value}；上一次结果保留。`" type="error" :closable="false" />
    <template v-if="!selected">
      <el-alert v-if="summaryRead.error.value" title="全站统计读取失败，上一次统计保留。" type="warning" :closable="false" />
      <div class="v3-stats v3-site-stats"><el-card v-for="[key, label] in [['total', '全部网站'], ['normal', '正常'], ['down', '无法访问'], ['pending', '等待检查'], ['paused', '已暂停'], ['migration_pending', '等待迁移切换']]" :key="key" shadow="never"><span class="v3-muted">{{ label }}</span><strong>{{ summary ? summary[key as 'total' | 'normal' | 'down' | 'pending' | 'paused' | 'migration_pending'] : '—' }}</strong></el-card></div>
      <p v-if="summary?.unknown" class="v3-muted">另有 {{ summary.unknown }} 个网站状态未知，请检查最近结果。</p><el-card shadow="never"><form class="v3-event-filters" @submit.prevent="search"><el-input v-model="filters.q" aria-label="网站名称或网址" placeholder="网站名称或网址" clearable /><el-select v-model="filters.node" aria-label="关联服务器筛选" clearable :value-on-clear="''" filterable remote :remote-method="loadOptions" placeholder="全部关联服务器"><el-option label="主控" value="central" /><el-option v-if="filters.node && filters.node !== 'central' && !nodes.some(node => node.id === filters.node)" :value="filters.node" :label="filters.node" /><el-option v-for="node in nodes" :key="node.id" :value="node.id" :label="`${node.name} · ${node.id}`" /></el-select><el-select v-model="filters.status" aria-label="网站状态筛选" clearable :value-on-clear="''" placeholder="全部状态"><el-option v-for="[key,label] in Object.entries(statusLabels)" :key="key" :value="key" :label="label" /><el-option value="paused" label="已暂停" /></el-select><el-button type="primary" native-type="submit">查询</el-button><el-button @click="Object.assign(filters,{q:'',node:'',status:''}); search()">重置</el-button></form>
      <el-alert v-if="options.error.value" title="服务器选项读取失败，可重新搜索；已选关联保留。" type="warning" :closable="false" /><el-alert v-if="stale" title="筛选正在更新，上一次列表暂时保留。" type="info" :closable="false" />
      <div v-if="writable" class="v3-history-toolbar"><el-button type="danger" plain :disabled="!checked.length || actionsDisabled" @click="prepareDelete(checked)">删除已选（{{ checked.length }}）</el-button><span class="v3-muted">仅软删除当前页明确选择的网站，保留故障历史和已排队通知。</span></div>
      <el-table :data="items" row-key="id" :empty-text="emptyText" :aria-busy="read.loading.value" @selection-change="checked = $event"><el-table-column v-if="writable" type="selection" :selectable="(site: V3Site) => !site.migration_pending && !actionsDisabled" width="48" /><el-table-column label="网站" min-width="230"><template #default="{ row }"><router-link :to="`/websites/${row.id}`">{{ row.name }}</router-link><small class="v3-block v3-muted">{{ row.url }}</small></template></el-table-column><el-table-column label="归属" min-width="140"><template #default="{ row }">{{ row.node || '主控' }}</template></el-table-column><el-table-column label="状态" min-width="150"><template #default="{ row }"><el-tag :type="row.migration_pending || row.paused ? 'info' : row.state.status === 'normal' ? 'success' : row.state.status === 'down' ? 'danger' : 'warning'">{{ status(row) }}</el-tag><small v-if="row.state.last?.reason" class="v3-block v3-muted">{{ row.state.last.reason }}</small></template></el-table-column><el-table-column label="最近检查" min-width="180"><template #default="{ row }">{{ row.state.last?.time ? timeText(row.state.last.time * 1000) : '—' }}</template></el-table-column><el-table-column label="响应时间" min-width="115"><template #default="{ row }">{{ row.state.last?.time && Number.isFinite(row.state.last.latency) ? `${(row.state.last.latency * 1000).toFixed(0)} ms` : '—' }}</template></el-table-column><el-table-column v-if="writable" label="操作" min-width="205"><template #default="{ row }"><el-button text :disabled="row.migration_pending || actionsDisabled" @click="open(row)">编辑</el-button><el-button text :disabled="row.paused || row.migration_pending || actionsDisabled" @click="check(row)">检测</el-button><el-button text type="danger" :disabled="row.migration_pending || actionsDisabled" @click="prepareDelete([row])">删除</el-button></template></el-table-column></el-table><div class="v3-pagination"><el-button :disabled="!cursor || read.loading.value" @click="page('')">回到首页</el-button><span>每页最多 20 个网站</span><el-button :disabled="!next || read.loading.value" @click="page(next)">下一页</el-button></div></el-card>
    </template>
    <template v-else-if="detail">
      <el-alert v-if="detail.migration_pending" title="此网站等待迁移切换，当前不会检测，也不能编辑或删除。" type="warning" :closable="false" />
      <el-card shadow="never"><h2>监控状态</h2><dl class="v3-detail-grid"><dt>当前状态</dt><dd>{{ status(detail) }}</dd><dt>网站网址</dt><dd>{{ detail.url }}</dd><dt>关联服务器</dt><dd>{{ detail.node || '主控' }}</dd><dt>配置版本</dt><dd>{{ detail.version }}</dd><dt>关键词</dt><dd>{{ detail.keyword || '未设置' }}</dd><dt>慢响应告警</dt><dd>{{ detail.slow_alert ? '已启用' : '已停用' }}</dd><dt>最近检查</dt><dd>{{ detail.state.last?.time ? timeText(detail.state.last.time * 1000) : '尚未检查' }}</dd><dt>HTTP 状态</dt><dd>{{ detail.state.last?.http_status || '—' }}</dd><dt>响应耗时</dt><dd>{{ detail.state.last?.time && Number.isFinite(detail.state.last.latency) ? `${(detail.state.last.latency * 1000).toFixed(0)} ms` : '—' }}</dd><dt>检查结果</dt><dd>{{ detail.state.last?.reason || '—' }}</dd><dt>证书到期</dt><dd>{{ detail.state.last?.cert_expires ? timeText(detail.state.last.cert_expires * 1000) : '—' }}</dd><dt>证书检查</dt><dd>{{ detail.state.last?.cert_error || (detail.state.last?.cert_checked ? timeText(detail.state.last.cert_checked * 1000) : '—') }}</dd></dl><div class="v3-actions"><router-link :to="{path:'/alerts', query:{tab:'history',source:'website',site:detail.id}}">查看此网站故障历史 →</router-link><el-button v-if="writable" :disabled="detail.paused || detail.migration_pending || actionsDisabled" :loading="operating" @click="check(detail)">立即检测</el-button><el-button v-if="writable" type="danger" plain :disabled="detail.migration_pending || actionsDisabled" @click="prepareDelete([detail])">删除网站</el-button></div></el-card>
    </template>
    <el-empty v-else :description="read.error.value ? '网站读取失败，请重试' : '正在读取网站…'" />
    <el-dialog v-model="edit" :title="expected ? '编辑网站' : '添加网站'" class="v3-node-dialog" width="680px" :show-close="!saving" :close-on-click-modal="!saving" :close-on-press-escape="!saving" @close="closeEdit">
      <el-form label-position="top" @submit.prevent="save"><el-form-item label="网站名称"><el-input ref="inputName" v-model="form.name" maxlength="100" /></el-form-item><el-form-item label="网站网址"><el-input ref="inputURL" v-model="form.url" placeholder="https://example.com" maxlength="2048" /></el-form-item><el-form-item label="关联服务器"><el-select v-model="form.node" aria-label="网站关联服务器" filterable remote :remote-method="loadOptions" clearable :value-on-clear="''" placeholder="主控"><el-option label="主控" value="central" /><el-option v-if="form.node && form.node !== 'central' && !nodes.some(node => node.id === form.node)" :value="form.node" :label="form.node" /><el-option v-for="node in nodes" :key="node.id" :value="node.id" :label="`${node.name} · ${node.id}`" /></el-select></el-form-item><el-form-item label="内容关键词（可选）"><el-input v-model="form.keyword" maxlength="200" /></el-form-item><div class="v3-form-grid"><el-form-item label="慢响应告警"><el-switch v-model="form.slow_alert" /></el-form-item><el-form-item label="暂停监控"><el-switch v-model="form.paused" /></el-form-item></div></el-form>
      <template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="formError" :title="formError" type="error" :closable="false" /><span v-else>{{ saving ? '正在保存网站…' : '保存后由主控调度检测；暂停期间不执行检测。' }}</span></div><div class="v3-actions"><el-button :disabled="saving" @click="closeEdit">取消</el-button><el-button type="primary" :loading="saving" @click="save">保存</el-button></div></template>
    </el-dialog>
    <el-dialog v-model="confirmation" title="软删除网站" class="v3-node-dialog" width="620px" :show-close="!operating" :close-on-click-modal="!operating" :close-on-press-escape="!operating" @close="closeDelete"><p>仅处理当前页明确选择的 {{ targets.length }} 个网站。软删除后取消检测，保留故障历史和已排队通知，不发送恢复通知。可通过网站配置备份合并恢复。</p><template #footer><div class="v3-dialog-feedback" role="status"><el-alert v-if="operationError" :title="operationError" type="error" :closable="false" /><span v-else>{{ operating ? '正在软删除所选网站…' : '执行前重新核对各网站配置版本；版本冲突不会部分删除。' }}</span></div><div class="v3-actions"><el-button :disabled="operating" @click="closeDelete">取消</el-button><el-button type="danger" :loading="operating" @click="remove">确认软删除</el-button></div></template></el-dialog>
  </section>
</template>
