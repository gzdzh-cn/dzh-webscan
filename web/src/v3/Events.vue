<script setup lang="ts">
import CursorPagination from './CursorPagination.vue'
import PageHeading from './PageHeading.vue'
import { computed, ref } from 'vue'
import type { V3Node } from '../controlV3'
import { timeText, useConsole } from './context'
import { useReadScope } from './readScope'
import { refreshIntervals, useEventQuery } from './eventQuery'
import HistoryDelete from './HistoryDelete.vue'

const { client, session } = useConsole(), options = useReadScope()
const nodes = ref<V3Node[]>([]), deletion = ref<InstanceType<typeof HistoryDelete>>()
const { draft, items, queried, attempted, ready, loading, error, changed, auto, interval, countdown, lastUpdated,
  hidden, next, previous, detail, checked, submit, page, refresh, resize } = useEventQuery()
const canWrite = computed(() => session.value?.role !== 'viewer')
const labels: Record<string, string> = { create: '新增文件', modify: '修改文件', delete: '删除文件', move: '移动文件', scan: '安全扫描', health: '监控异常', test: '测试', probe: '链路探针' }
const operation = (payload: Record<string, unknown>) => labels[String(payload.operation)] || String(payload.operation || '运行事件')
function text(payload: Record<string, unknown>) { return String(payload.path || payload.reason || payload.message || '查看事件详情') }
const nodeName = (id: string) => nodes.value.find(node => node.id === id)?.name || id
const scanLabels: Record<string,string> = {pending:'等待扫描',matched:'发现可疑特征',no_match:'未发现可疑特征',error:'扫描失败',skipped:'已跳过'}
const riskLabels: Record<string,string> = {high:'高风险',critical:'严重风险',medium:'中风险',low:'低风险',unclassified:'待核查'}
function eventState(payload: Record<string,unknown>) { const scan = payload.scan as Record<string,unknown> | undefined; return payload.operation === 'scan' ? scanLabels[String(scan?.status)] || '尚未记录' : payload.risk ? riskLabels[String(payload.risk)] || '尚未分类' : '已记录' }
function loadOptions(q = '') { void options.run(signal => client.servers(q, '', 20, signal), value => { nodes.value = value.items }) }
loadOptions()
</script>

<template>
  <section>
    <PageHeading title="文件与安全事件" />
    <el-card shadow="never">
      <div class="card-heading"><span></span><router-link :to="{path: '/settings', query: {tab: 'storage', node: draft.node}}">存储与清理 →</router-link></div>
      <form class="filters v3-event-filters" @submit.prevent="submit">
        <el-select v-model="draft.node" clearable :value-on-clear="''" filterable remote :remote-method="loadOptions" :loading="options.loading.value" placeholder="全部服务器（输入名称搜索）" aria-label="服务器筛选"><el-option v-if="draft.node && !nodes.some(node => node.id === draft.node)" :value="draft.node" :label="draft.node" /><el-option v-for="node in nodes" :key="node.id" :value="node.id" :label="`${node.name} · ${node.id}`" /></el-select>
        <el-select v-model="draft.operation" clearable :value-on-clear="''" placeholder="全部事件类型" aria-label="事件类型"><el-option v-for="(label, value) in labels" :key="value" :value="value" :label="label" /></el-select>
        <el-input v-model="draft.q" clearable placeholder="搜索文件路径或原因" aria-label="事件关键词" />
        <el-select v-model="draft.hours" aria-label="查询时间范围"><el-option v-for="[value, label] in [[24, '最近 24 小时'], [168, '最近 7 天'], [720, '最近 30 天']]" :key="value" :value="value" :label="String(label)" /></el-select>
        <el-switch v-model="draft.include_probes" active-text="包含链路探针" aria-label="包含链路探针" /><el-button type="primary" native-type="submit">{{ loading ? '重新查询' : '查询' }}</el-button>
      </form>
      <p v-if="options.error.value" class="v3-muted">服务器选项读取失败，可重新输入名称搜索；事件筛选仍保留。</p>
      <div class="event-refresh v3-event-refresh"><el-switch v-model="auto" :disabled="!queried" active-text="自动刷新" aria-label="自动刷新" /><el-select v-model="interval" aria-label="自动刷新间隔"><el-option v-for="value in refreshIntervals" :key="value" :value="value" :label="`${value} 秒`" /></el-select><span v-if="!queried">请先查询，再开启自动刷新</span><span v-else-if="changed">已暂停，等待提交筛选</span><span v-else-if="auto">{{ !ready ? '已暂停，等待查询成功' : hidden ? '后台标签已暂停' : loading ? '正在刷新…' : `下次刷新：${countdown} 秒` }}</span><span v-if="lastUpdated">最近更新：{{ timeText(lastUpdated) }}</span></div>
      <el-alert v-if="changed" title="筛选条件已修改，点击查询更新；下方仍为上一次查询结果。" type="info" :closable="false" />
      <el-alert v-if="error" :title="`${error}${queried ? '；保留上一次查询结果。' : ''}`" type="error" :closable="false" />
      <div v-if="queried && canWrite" class="v3-history-toolbar"><HistoryDelete ref="deletion" :records="checked" :categories="['events', 'security-events']" label="文件与安全历史" @done="refresh" /><span class="v3-muted">只处理当前页勾选的历史；受保护记录不可选择。</span></div>
      <el-empty v-if="!queried" :description="loading ? '正在查询记录…' : attempted || error ? '查询未成功，请检查提示后重试' : '请选择筛选条件，点击查询查看记录'" />
      <template v-else>
        <el-table :data="items" row-key="record_key" :aria-busy="loading" :empty-text="loading ? '正在查询记录…' : '当前筛选条件下暂无记录'" @selection-change="checked = $event"><el-table-column v-if="canWrite" type="selection" :selectable="(row: typeof items[number]) => row.can_delete" width="48" /><el-table-column label="时间（北京时间）" min-width="185"><template #default="{ row }">{{ timeText(row.received_at) }}</template></el-table-column><el-table-column label="服务器 / 网站" min-width="150"><template #default="{row}">{{ nodeName(row.node) }}</template></el-table-column><el-table-column label="类型" width="125"><template #default="{ row }">{{ operation(row.payload) }}</template></el-table-column><el-table-column label="问题 / 内容" min-width="280"><template #default="{ row }"><el-button link type="primary" class="v3-event-content" @click="detail = row">{{ text(row.payload) }}</el-button></template></el-table-column><el-table-column label="状态" min-width="140"><template #default="{row}">{{ eventState(row.payload) }}</template></el-table-column><el-table-column label="删除保护" min-width="210"><template #default="{ row }"><el-button v-if="canWrite" text type="danger" :disabled="!row.can_delete" @click="deletion?.open([row])">删除</el-button><small class="v3-block v3-muted">{{ row.delete_reason || '可删除历史' }}</small></template></el-table-column></el-table>
        <CursorPagination :previous="ready && !!previous.length" :next="ready && !!next" :limit="draft.limit" :page="previous.length + 1" :loading="loading" @previous="page(false)" @next="page(true)" @resize="resize" />
      </template>
    </el-card>
    <el-dialog :model-value="!!detail" title="事件详情" class="v3-node-dialog" width="780px" @update:model-value="detail = undefined"><template v-if="detail"><div class="detail-grid v3-detail-grid"><div><span>服务器</span><strong>{{ nodeName(detail.node) }}</strong></div><div><span>事件 ID</span><strong>{{ detail.id }}</strong></div><div><span>来源</span><strong>{{ detail.source === 'migrated_events' ? '迁移历史' : '原生事件' }}</strong></div><div><span>接收时间</span><strong>{{ timeText(detail.received_at) }}</strong></div><div><span>事件类型</span><strong>{{ operation(detail.payload) }}</strong></div></div><p>文件路径：{{ detail.payload.path || '未提供' }}</p><p v-if="detail.payload.old_path">原文件路径：{{ detail.payload.old_path }}</p><p>状态：{{ eventState(detail.payload) }}</p><p v-if="detail.payload.reason">运行原因：{{ detail.payload.reason }}</p><details><summary>原始事件详情</summary><pre class="v3-event-json">{{ JSON.stringify(detail.payload, null, 2) }}</pre></details></template><template #footer><el-button @click="detail = undefined">关闭</el-button></template></el-dialog>
  </section>
</template>
