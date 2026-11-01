<script setup lang="ts">
import { computed, reactive, toRaw, watch } from 'vue'
import type { V3MonitoringRules, V3MonitoringRulesView, V3NodeMonitoring } from '../controlV3'

const props = defineProps<{ modelValue?: V3NodeMonitoring; defaults?: V3MonitoringRulesView; disabled?: boolean; loading?: boolean; error?: string; publicOnly?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [V3NodeMonitoring] }>()
const fields = [
  { key: 'roots', label: '公共监控根目录' }, { key: 'extensions', label: '监控文件后缀' },
  { key: 'important_filenames', label: '重要文件名' }, { key: 'critical_paths', label: '必须监控的文件' },
  { key: 'exclude_paths', label: '忽略路径' },
] as const
const draft = reactive({ roots: '', extensions: '', important_filenames: '', critical_paths: '', exclude_paths: '', reconciliation_interval_hours: '' })
let emitted = ''
watch(() => props.modelValue, value => {
  if (!value || JSON.stringify(value) === emitted) return
  fields.forEach(({key}) => { draft[key] = value.rules[key].join('\n') })
  draft.reconciliation_interval_hours = String(value.rules.reconciliation_interval_hours)
}, { immediate: true, deep: true })
const editable = computed(() => !props.disabled && !props.loading && !!props.modelValue && (props.publicOnly || props.modelValue.source === 'independent'))
function publish() {
  if (!props.modelValue) return
  const rules = {} as V3MonitoringRules
  fields.forEach(({key}) => { rules[key] = draft[key].split('\n').map(value => value.trim()).filter(Boolean) })
  rules.reconciliation_interval_hours = /^\d+$/.test(draft.reconciliation_interval_hours) ? Number(draft.reconciliation_interval_hours) : 0
  const next = { ...props.modelValue, rules }
  emitted = JSON.stringify(next); emit('update:modelValue', next)
}
function source(value: string) {
  if (props.disabled || props.loading || !props.modelValue || !['inherited', 'independent'].includes(value)) return
  if (value === 'inherited') {
    if (!props.defaults) return
    const next: V3NodeMonitoring = { source: 'inherited', rules: structuredClone(toRaw(props.defaults.rules)), rules_version: props.defaults.version }
    emitted = ''; emit('update:modelValue', next)
  } else { emitted = ''; emit('update:modelValue', { ...props.modelValue, source: 'independent', rules: structuredClone(toRaw(props.modelValue.rules)) }) }
}
function copyDefaults() {
  if (!props.defaults || props.disabled || props.loading) return
  emitted = ''; emit('update:modelValue', { source: 'independent', rules: structuredClone(toRaw(props.defaults.rules)), rules_version: props.defaults.version })
}
</script>

<template>
  <section aria-label="文件监控规则" class="v3-monitoring-fields">
    <h3 v-if="!publicOnly">文件监控</h3>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <p v-if="loading" class="muted">正在读取监控规则…</p>
    <p v-else-if="!modelValue" class="muted">监控规则未知，当前不能修改；原有规则保持不变。</p>
    <template v-if="modelValue">
      <template v-if="!publicOnly">
        <el-form-item label="规则来源"><el-select :model-value="modelValue.source" aria-label="规则来源" :disabled="disabled || loading" @update:model-value="source(String($event))"><el-option label="继承公共配置" value="inherited" :disabled="!defaults" /><el-option label="独立配置" value="independent" /></el-select></el-form-item>
        <p class="muted">{{ modelValue.source === 'inherited' ? '跟随公共配置；保存不自动下发，部署后生效。' : '独立维护下列规则，不随公共配置自动变化。' }} 已保存规则版本：{{ modelValue.rules_version || '未知' }}。</p>
        <el-button v-if="modelValue.source === 'independent'" :disabled="disabled || loading || !defaults" @click="copyDefaults">复制公共配置</el-button>
      </template>
      <div class="form-grid v3-form-grid">
        <el-form-item v-for="field in fields" :key="field.key" :label="!publicOnly && field.key === 'roots' ? '监控根目录' : field.label"><el-input v-model="draft[field.key]" :aria-label="field.label" type="textarea" :rows="3" :disabled="!editable" @input="publish" /><small class="muted">每行一项{{ field.key === 'roots' || field.key === 'critical_paths' ? '，使用绝对路径' : '' }}。</small></el-form-item>
        <el-form-item label="清单核对间隔（小时）"><el-input v-model="draft.reconciliation_interval_hours" aria-label="清单核对间隔（小时）" inputmode="numeric" :disabled="!editable" @input="publish" /><small class="muted">1～8760 小时。</small></el-form-item>
      </div>
    </template>
  </section>
</template>
