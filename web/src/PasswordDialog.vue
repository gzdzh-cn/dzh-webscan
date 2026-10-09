<script setup lang="ts">
import { reactive, ref, watch } from 'vue'
import { api } from './api'
const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [boolean]; changed: [] }>()
const form = reactive({ current_password: '', new_password: '', confirm_password: '' }), busy = ref(false), error = ref('')
watch(() => props.modelValue, () => { Object.assign(form, { current_password: '', new_password: '', confirm_password: '' }); error.value = '' })
async function save() {
 const size = new TextEncoder().encode(form.new_password).length
 if (size < 12 || size > 72) { error.value = '新密码必须为 12～72 字节，中文字符通常占 3 字节'; return }
 if (form.new_password !== form.confirm_password) { error.value = '确认密码与新密码不一致'; return }
 busy.value = true; error.value = ''
 try { await api('/api/account/password', 'POST', form); emit('update:modelValue', false); emit('changed') }
 catch (e) { error.value = e instanceof Error ? e.message : '修改失败，请重试' }
 finally { busy.value = false }
}
</script>
<template>
 <el-dialog :model-value="modelValue" title="修改管理员密码" width="min(500px, 94vw)" :close-on-click-modal="false" @close="emit('update:modelValue', false)">
  <p class="muted">修改成功后，所有已登录会话都会退出。请使用新密码重新登录。</p>
  <el-alert v-if="error" :title="error" type="error" :closable="false" />
  <el-form label-position="top" @submit.prevent="save">
   <el-form-item label="当前密码"><el-input v-model="form.current_password" type="password" show-password autocomplete="current-password" /></el-form-item>
   <el-form-item label="新密码（12～72 字节）"><el-input v-model="form.new_password" type="password" show-password autocomplete="new-password" /></el-form-item>
   <el-form-item label="确认新密码"><el-input v-model="form.confirm_password" type="password" show-password autocomplete="new-password" @keyup.enter="save" /></el-form-item>
  </el-form>
  <template #footer><el-button @click="emit('update:modelValue', false)">取消</el-button><el-button type="primary" :loading="busy" @click="save">修改密码并退出</el-button></template>
 </el-dialog>
</template>
