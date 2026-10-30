<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import type { V3DeploymentPreview, V3Node, V3Preparation, V3SSHInput } from '../controlV3'
import { useConsole } from './context'
import { privateKeyFileReader } from '../privateKeyFile'
const props = defineProps<{ node: Pick<V3Node, 'id' | 'version' | 'applied_version' | 'mode'>; upgrade?: boolean }>()
const emit = defineEmits<{ job: [id: string]; status: [text: string, error: boolean]; busy: [value: boolean] }>()
const { client } = useConsole()
const busy = ref(false), message = ref(''), error = ref(''), configured = ref(false), statusLoaded = ref(false)
const auth = ref<'key' | 'path' | 'password'>('key'), port = ref(22), content = ref(''), password = ref(''), path = ref('')
const fileInput = ref<HTMLInputElement>(), fileError = ref(''), drag = ref(false)
const fingerprint = ref<V3Preparation | null>(null), preview = ref<V3DeploymentPreview | null>(null), preparation = ref('')
const unfinishedJob = ref(''), fileReading = ref(false), portEdited = ref(false), configuredPort = ref(22)
const saved = computed(() => props.node.version > 0), kind = computed(() => props.upgrade || props.node.applied_version > 0 ? 'upgrade' : 'install')
const credentialChanged = computed(() => Boolean(content.value || password.value || path.value))
let generation = 0, alive = true, controller = new AbortController()
const intents = new Map<string, { body: string; key: string }>()
// Keys survive explicit network retries, but never expose credentials in storage.
function key(action: string, body: unknown) {
 const raw = JSON.stringify(body), old = intents.get(action)
 if (old?.body === raw) return old.key
 const next = { body: raw, key: crypto.randomUUID() }; intents.set(action, next); return next.key
}
const phases: Record<string, string> = { queued: '等待宿主执行器', validating: '正在校验配置', 'reading-fingerprint': '正在读取 SSH 指纹', 'preparing-identity': '正在准备节点证书', 'preparing-configuration': '正在生成部署配置', 'creating-task': '正在创建部署任务' }
const failures: Record<string, string> = { fingerprint_changed: 'SSH 指纹已变化，已停止。请在主服务器核实后处理。', credential_unavailable: 'SSH 凭据不可用，请检查密钥内容或主服务器路径及权限。', upgrade_unnecessary: '版本、摘要和配置均相同，无需升级。', downgrade_rejected: '目标版本低于当前版本，已拒绝降级。', mode_migration_required: '部署方式已变化，请使用专门迁移流程。', deployment_busy: '存在未完成部署，请打开原任务继续或回退。', preparation_conflict: '配置、账号或准备资料已变化或过期，请重新预览。', issuer_unavailable: '宿主签发器不可用，请检查 CA 及证书维护服务。', preparation_failed: '部署准备失败，服务尚未切换。请检查 SSH、执行器和发布资料后重试。' }
function report(text: string, failed = false) { message.value = failed ? '' : text; error.value = failed ? text : ''; emit('status', text, failed) }
async function operation(work: (current: number) => Promise<void>) {
 if (busy.value) return
 if (fileReading.value) { report('正在读取私钥文件，请稍候。'); return }
 const current = generation; busy.value = true; emit('busy', true); report('正在校验…')
 try { await work(current) } catch (e) { if (alive && current === generation && !controller.signal.aborted) report(e instanceof Error ? e.message : '操作失败，请重试', true) }
 finally { if (alive && current === generation) { busy.value = false; emit('busy', false) } }
}
async function wait(p: V3Preparation, current: number, action: string) {
 while (alive && current === generation && !controller.signal.aborted) {
  if (!document.hidden) {
   p = await client.deploymentPreparation(p.id, controller.signal)
   if (!alive || current !== generation || controller.signal.aborted) throw new DOMException('已取消', 'AbortError')
   report(phases[p.phase] || '正在准备部署…')
   if (p.status === 'failed' || p.status === 'expired') { intents.delete(action); throw new Error(failures[p.error_code || ''] || '准备请求已过期，请重试。') }
   if (p.status === 'succeeded') return p
  }
  await new Promise<void>(resolve => { const timer = setTimeout(done, 1000); function done() { clearTimeout(timer); controller.signal.removeEventListener('abort', done); resolve() }; controller.signal.addEventListener('abort', done, { once: true }) })
 }
 throw new DOMException('已取消', 'AbortError')
}
async function readFingerprint(current: number) {
 preview.value = null; fingerprint.value = null
 if (!saved.value) throw new Error('请先保存服务器配置。')
 const p = await wait(await client.sshFingerprint(props.node.id, props.node.version, port.value, key('fingerprint', [props.node, port.value])), current, 'fingerprint')
 if (!alive || current !== generation) return
 fingerprint.value = p; report('请核对下面的 SSH 指纹，确认后继续。')
}
async function prepare(current: number) {
 preview.value = null
 const p = await wait(await client.prepareDeployment(props.node.id, props.node.version, kind.value, key('prepare', [props.node, kind.value])), current, 'prepare')
 if (!alive || current !== generation) return
 if (!p.result?.preview) throw new Error('部署预览未生成，请重试。')
 preparation.value = p.id; preview.value = p.result.preview; report('部署预览已就绪，请确认操作范围。')
}
function begin() {
 return operation(async current => {
  const tasks = await client.deployments(props.node.id, '', 20, controller.signal)
  if (!alive || current !== generation || controller.signal.aborted) return
  const unfinished = tasks.items.find(job => !['succeeded', 'rolled_back'].includes(job.status))
  unfinishedJob.value = unfinished?.id || ''
  if (unfinished) { report('存在未完成部署，请打开原任务继续或回退。', true); return }
  if (!statusLoaded.value && saved.value) { const status = await client.sshCredential(props.node.id, controller.signal); configured.value = status.configured; statusLoaded.value = true; if (!alive || current !== generation || controller.signal.aborted) return; if (status.ssh_port) { configuredPort.value = status.ssh_port; if (!portEdited.value && !credentialChanged.value) port.value = status.ssh_port } }
  if (!configured.value || credentialChanged.value || portEdited.value && port.value !== configuredPort.value) await readFingerprint(current)
  else await prepare(current)
 })
}
function confirmFingerprint() {
 return operation(async current => {
  const pin = fingerprint.value
  if (!pin?.result?.fingerprint_token) throw new Error('请重新读取 SSH 指纹。')
  const input: V3SSHInput = { expected_version: props.node.version, ssh_port: port.value, fingerprint_preparation: pin.id, fingerprint_token: pin.result.fingerprint_token }
  if (auth.value === 'key') input.private_key_content = content.value
  else if (auth.value === 'path') input.private_key_path = path.value
  else input.password = password.value
  await wait(await client.saveSSHCredential(props.node.id, input, key('credential', input)), current, 'credential')
  if (!alive || current !== generation) return
  content.value = ''; password.value = ''; path.value = ''; intents.delete('credential'); fingerprint.value = null; configured.value = true; configuredPort.value = port.value; portEdited.value = false
  await prepare(current)
 })
}
function confirm() {
 return operation(async current => {
  const value = preview.value; if (!value) return
  const result = await wait(await client.confirmDeployment(preparation.value, value, key('confirm', [preparation.value, value.token])), current, 'confirm')
  if (!alive || current !== generation) return
  if (!result.result?.job) throw new Error('任务未创建，请查询准备进度后重试。')
  report('任务已创建，正在打开日志…'); emit('job', result.result.job)
 })
}
const reader = privateKeyFileReader(value => { content.value = value; fileError.value = '' }, text => { fileError.value = text + '，原内容已保留。' }, reading => { fileReading.value = reading })
function files(files: FileList | File[]) { if (!busy.value) return reader.read(Array.from(files)) }
function drop(event: DragEvent) { drag.value = false; if (event.dataTransfer) void files(event.dataTransfer.files) }
function selectFile(event: Event) { const input = event.target as HTMLInputElement; if (input.files) void files(input.files); input.value = '' }
watch(auth, () => { reader.cancel(); content.value = ''; password.value = ''; path.value = ''; fingerprint.value = null; preview.value = null; intents.clear() })
watch([port, content, password, path], () => { fingerprint.value = null; preview.value = null })
watch(() => props.node.id, () => { generation++; controller.abort(); controller = new AbortController(); configured.value = false; statusLoaded.value = false; portEdited.value = false; preview.value = null; fingerprint.value = null })
onUnmounted(() => { alive = false; generation++; reader.cancel(); controller.abort(); content.value = ''; password.value = ''; intents.clear() })
defineExpose({ begin })
</script>
<template>
 <section class="v3-deployment-flow">
  <h2>SSH 认证</h2><p v-if="saved" class="v3-muted">{{ configured ? '已配置，留空保留。' : '已有凭据不回显，留空保留；未配置时需填写认证信息。' }}</p>
  <el-alert v-if="upgrade" title="升级使用已保存配置；本次不保存编辑弹窗中的草稿。" type="info" :closable="false" />
  <el-button v-if="unfinishedJob" type="primary" @click="emit('job', unfinishedJob)">打开未完成任务</el-button>
  <el-form label-position="top" :disabled="busy">
   <el-form-item label="SSH 端口"><el-input-number v-model="port" :min="1" :max="65535" @change="portEdited = true" /></el-form-item>
   <el-form-item label="认证方式"><el-radio-group v-model="auth"><el-radio-button value="key">私钥内容</el-radio-button><el-radio-button value="path">主服务器路径</el-radio-button><el-radio-button value="password">密码</el-radio-button></el-radio-group></el-form-item>
   <template v-if="auth === 'key'"><div class="v3-key-drop" :class="{ 'is-dragging': drag }" @dragover.prevent="drag = true" @dragleave.prevent="drag = false" @drop.prevent="drop"><p>拖入一个私钥文件，或<el-button link type="primary" :disabled="busy" @click="fileInput?.click()">选择文件</el-button>（最大 64 KiB）</p><el-input v-model="content" type="textarea" :rows="5" placeholder="粘贴未加密的 OpenSSH / PEM 私钥；内容不会回显" aria-label="私钥内容" /><input ref="fileInput" type="file" hidden @change="selectFile" /></div><el-alert v-if="fileError" :title="fileError" type="error" :closable="false" /></template>
   <el-form-item v-else-if="auth === 'path'" label="主服务器私钥绝对路径"><el-input v-model="path" placeholder="/var/lib/webscan-deploy/ssh-keys/…" /></el-form-item>
   <el-form-item v-else label="SSH 密码"><el-input v-model="password" type="password" show-password autocomplete="new-password" /></el-form-item>
  </el-form>
  <div v-if="fingerprint?.result" class="v3-deploy-confirm"><h3>确认 SSH 主机指纹</h3><p>{{ fingerprint.result.host }}:{{ fingerprint.result.port }}</p><code>{{ fingerprint.result.fingerprint }}</code><p>确认有效期 10 分钟，指纹变化会停止操作。</p><el-button type="primary" :loading="busy || fileReading" @click="confirmFingerprint">确认指纹并准备部署</el-button></div>
  <div v-if="preview" class="v3-deploy-confirm"><h3>{{ kind === 'upgrade' ? '升级' : '安装' }}预览</h3><dl class="v3-detail-grid"><dt>范围</dt><dd>仅 {{ node.id }}，主控保持运行</dd><dt>部署方式</dt><dd>{{ preview.target.mode }}</dd><dt>当前版本</dt><dd>{{ preview.current?.release || '无法确认旧基线' }}</dd><dt>目标版本</dt><dd>{{ preview.target.release }}</dd><dt>目标摘要</dt><dd><code>{{ preview.target.sha256 }}</code></dd><dt>配置版本</dt><dd>{{ preview.version }}</dd></dl><el-button type="primary" :loading="busy || fileReading" @click="confirm">确认并创建部署任务</el-button></div>
  <el-alert v-if="error" :title="error" type="error" :closable="false" /><p v-else-if="message" role="status">{{ message }}</p>
 </section>
</template>
<style scoped>
.v3-key-drop{border:1px dashed var(--el-border-color);padding:12px;border-radius:6px;margin-bottom:16px}.is-dragging{border-color:var(--el-color-primary);background:var(--el-color-primary-light-9)}.v3-deploy-confirm{margin:16px 0;padding:16px;background:var(--el-fill-color-light);border-radius:6px}.v3-deploy-confirm code{overflow-wrap:anywhere;word-break:break-all}.v3-deployment-flow h2{margin-top:20px}
</style>
