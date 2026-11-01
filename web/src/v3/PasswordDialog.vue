<script setup lang="ts">
import { onUnmounted, reactive, ref, watch } from 'vue'
import { useConsole } from './context'

const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [boolean]; changed: [] }>()
const { client } = useConsole()
const form = reactive({ current_password: '', new_password: '', confirm_password: '' })
const busy = ref(false), error = ref('')
let generation = 0, disposed = false
function clear() {
  generation++
  Object.assign(form, { current_password: '', new_password: '', confirm_password: '' })
  busy.value = false; error.value = ''
}
function close() { clear(); emit('update:modelValue', false) }
watch(() => props.modelValue, clear, { flush: 'sync' })
async function save() {
  if (!props.modelValue || busy.value) return
  error.value = ''
  const size = new TextEncoder().encode(form.new_password).length
  if (!form.current_password) { error.value = '请输入当前密码'; return }
  if (size < 12 || size > 72) { error.value = '新密码必须为 12～72 字节，中文字符通常占 3 字节'; return }
  if (form.new_password !== form.confirm_password) { error.value = '确认密码与新密码不一致'; return }
  const current = ++generation
  busy.value = true
  try {
    await client.changePassword({ ...form })
    if (disposed || !props.modelValue || current !== generation) return
    clear(); emit('update:modelValue', false); emit('changed')
  } catch (e) {
    if (!disposed && props.modelValue && current === generation) error.value = e instanceof Error ? e.message : '修改失败，请重试'
  } finally { if (!disposed && current === generation) busy.value = false }
}
onUnmounted(() => { disposed = true; clear() })
</script>

<template>
  <el-dialog :model-value="modelValue" title="修改本人密码" class="v3-node-dialog v3-password-dialog" width="500px" :close-on-click-modal="!busy" :close-on-press-escape="!busy" :show-close="!busy" @close="close">
    <p class="muted">修改成功后，本账号的全部登录会话将退出。请使用新密码重新登录；其他账号不受影响。</p>
    <el-form label-position="top" :disabled="busy" @submit.prevent="save">
      <el-form-item label="当前密码"><el-input v-model="form.current_password" aria-label="当前密码" type="password" show-password autocomplete="current-password" /></el-form-item>
      <el-form-item label="新密码（12～72 字节）"><el-input v-model="form.new_password" aria-label="新密码" type="password" show-password autocomplete="new-password" /></el-form-item>
      <el-form-item label="确认新密码"><el-input v-model="form.confirm_password" aria-label="确认新密码" type="password" show-password autocomplete="new-password" @keyup.enter="save" /></el-form-item>
    </el-form>
    <template #footer>
      <div class="v3-dialog-feedback" role="status" aria-live="polite"><el-alert v-if="error" :title="error" type="error" :closable="false" /><span v-else>{{ busy ? '正在校验并修改密码，请勿重复提交…' : '修改仅影响当前账号。' }}</span></div>
      <div class="v3-actions"><el-button :disabled="busy" @click="close">取消</el-button><el-button type="primary" :loading="busy" @click="save">修改密码并退出</el-button></div>
    </template>
  </el-dialog>
</template>
