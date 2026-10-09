<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, beijingTime, type Page } from './api'
interface Backup { id: string; created: number; source: string; count: number; restored: number; result: string }
interface Preview { added: number; updated: number; unchanged: number; unknown_nodes: string[]; token: string }
const items = ref<Backup[]>([]), total = ref(0), page = ref(1), busy = ref(false), error = ref(''), feedback = ref('')
const file = ref<HTMLInputElement | null>(null), selected = ref<Backup | null>(null), preview = ref<Preview | null>(null)
function fail(e: unknown) { error.value = e instanceof Error ? e.message : '备份操作失败，请重试' }
async function refresh() { try { const data = await api<Page<Backup>>('/api/backups?page=' + page.value); items.value = data.items; total.value = data.total } catch (e) { fail(e) } }
async function create() { busy.value = true; error.value = ''; try { await api('/api/backups', 'POST'); page.value = 1; feedback.value = '全部网站配置已备份到服务器本地'; await refresh() } catch (e) { fail(e) } finally { busy.value = false } }
async function importFile(event: Event) {
 const input = event.target as HTMLInputElement, chosen = input.files?.[0]
 input.value = ''; if (!chosen) return
 busy.value = true; error.value = ''
 try {
  if (chosen.size > 2 * 1024 * 1024) throw new Error('备份文件不能超过 2 MiB')
  let doc: unknown
  try { doc = JSON.parse(await chosen.text()) } catch { throw new Error('文件不是有效的 JSON 备份') }
  await api('/api/backups/import', 'POST', doc); page.value = 1; feedback.value = '备份已导入历史列表，尚未修改网站。请预览后恢复。'; await refresh()
 } catch (e) { fail(e) } finally { busy.value = false }
}
async function exportFile(b: Backup) {
 error.value = ''
 try {
  const doc = await api('/api/backups/' + b.id + '/export')
  const url = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' }))
  const link = document.createElement('a'); link.href = url; link.download = 'webscan-websites-' + b.id + '.json'; document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000)
 } catch (e) { fail(e) }
}
async function showPreview(b: Backup) {
 error.value = ''; busy.value = true
 try { const result = await api<Preview>('/api/backups/' + b.id + '/preview', 'POST'); preview.value = result; selected.value = b } catch (e) { fail(e) } finally { busy.value = false }
}
async function restore() {
 if (!selected.value || !preview.value) return
 busy.value = true; error.value = ''
 try { await api('/api/backups/' + selected.value.id + '/restore', 'POST', { token: preview.value.token }); selected.value = null; feedback.value = '配置已合并恢复，其他网站与故障历史保留'; await refresh() }
 catch (e) { fail(e); preview.value = null } finally { busy.value = false }
}
function source(value: string) { return ({ manual: '手动备份', import: 'JSON 导入', before_restore: '恢复前自动备份' }[value] || value) }
onMounted(refresh)
</script>
<template>
 <div>
  <el-alert v-if="error" :title="error" type="error" :closable="false" />
  <el-alert v-if="feedback" :title="feedback" type="success" closable @close="feedback = ''" />
  <el-card shadow="never">
   <div class="card-heading"><div><h3>网站配置备份</h3><p class="small muted">保存全部网站配置（含暂停网站）。导入仅加入历史；恢复按网址合并，保留其他网站。</p></div><div class="backup-actions"><el-button type="primary" :loading="busy" @click="create">一键备份</el-button><el-button :disabled="busy" @click="file?.click()">导入 JSON</el-button></div></div>
   <input ref="file" type="file" accept=".json,application/json" hidden @change="importFile" />
   <el-table :data="items" empty-text="暂无备份，点击一键备份保存网站配置">
    <el-table-column label="备份时间（北京时间）" min-width="190"><template #default="{ row }">{{ beijingTime(row.created) }}</template></el-table-column>
    <el-table-column label="来源" min-width="145"><template #default="{ row }">{{ source(row.source) }}</template></el-table-column>
    <el-table-column prop="count" label="网站数量" width="100" />
    <el-table-column label="最近恢复" min-width="240"><template #default="{ row }"><div>{{ row.restored ? beijingTime(row.restored) : '尚未恢复' }}</div><span class="small muted">{{ row.result }}</span></template></el-table-column>
    <el-table-column label="操作" width="170"><template #default="{ row }"><el-button link type="primary" @click="exportFile(row)">导出 JSON</el-button><el-button link type="primary" :disabled="busy" @click="showPreview(row)">恢复</el-button></template></el-table-column>
   </el-table>
   <el-pagination v-model:current-page="page" :page-size="20" :total="total" layout="total, prev, pager, next" @change="refresh" />
  </el-card>
  <el-dialog :model-value="!!selected" title="合并恢复预览" width="min(540px, 94vw)" :close-on-click-modal="false" @close="selected = null">
   <el-alert v-if="error" :title="error" type="error" :closable="false" />
   <template v-if="preview"><p>新增 {{ preview.added }} 个，更新 {{ preview.updated }} 个，不变 {{ preview.unchanged }} 个。</p><el-alert v-if="preview.unknown_nodes.length" :title="'这些关联节点已不存在，恢复时会清空关联：' + preview.unknown_nodes.join('、')" type="warning" :closable="false" /></template>
   <p class="muted">恢复前自动备份当前配置；其他网站、故障历史及通知队列保留。密码不在此备份中。</p>
   <template #footer><el-button @click="selected = null">取消</el-button><el-button v-if="!preview" :loading="busy" @click="selected && showPreview(selected)">重新预览</el-button><el-button v-else type="primary" :loading="busy" @click="restore">确认合并恢复</el-button></template>
  </el-dialog>
 </div>
</template>
