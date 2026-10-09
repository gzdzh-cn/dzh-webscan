<script setup lang="ts">
import { nextTick, ref } from 'vue'
import { ElMessage } from 'element-plus'
import 'element-plus/es/components/message/style/css'
import { copyURL } from './clipboard'
defineProps<{ url: string }>()
const manual = ref(''), input = ref<HTMLInputElement | null>(null)
async function copy(url: string) {
 if (await copyURL(url)) { ElMessage.success('网址已复制'); return }
 manual.value = url
 await nextTick(); input.value?.focus(); input.value?.select()
}
</script>
<template>
 <div class="url-line">
  <a :href="url" target="_blank" rel="noopener noreferrer" class="small break">{{ url }}</a>
  <button class="copy-url" type="button" title="复制完整网址" aria-label="复制完整网址" @click.stop.prevent="copy(url)">
   <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg>
  </button>
 </div>
 <el-dialog :model-value="!!manual" title="手动复制网址" width="min(540px, 94vw)" @close="manual = ''">
  <p>浏览器未允许自动复制。请选中下方完整网址，按 Ctrl+C（Mac 按 ⌘C）复制。</p>
  <input ref="input" :value="manual" readonly aria-label="完整网址，可手动复制" class="manual-url" @click="input?.select()" />
  <template #footer><el-button @click="manual = ''">关闭</el-button></template>
 </el-dialog>
</template>
