<script setup lang="ts">
import { ElConfigProvider } from 'element-plus'
import { DataAnalysis, Monitor, Link, Bell, FolderOpened, Setting, List, Document } from '@element-plus/icons-vue'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import { computed, onMounted, onUnmounted, provide, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ControlV3, V3Error, type V3Session } from '../controlV3'
import { cancelReadRequests } from '../connection'
import { consoleContext } from './context'
import PasswordDialog from './PasswordDialog.vue'

const router = useRouter(), route = useRoute()
const session = ref<V3Session | null>(null), ready = ref(false), busy = ref(false), error = ref(''), reconnecting = ref(false)
const form = reactive({ username: 'admin', password: '' })
const passwordDialog = ref(false)
let disposed = false, generation = 0
const title = computed(() => route.path === '/' ? '监控总览' : route.path === '/migration-history' ? '旧版迁移历史' : route.path.startsWith('/configuration-applications') ? '配置应用任务' : route.path.startsWith('/deployments') ? '部署任务' : route.path === '/backups' ? '备份管理' : route.path === '/settings' ? '系统设置' : route.path === '/events' ? '文件与安全事件' : route.path === '/alerts' ? '告警中心' : route.path.startsWith('/websites/') ? '网站详情' : route.path === '/websites' ? '网站监控' : route.path.startsWith('/servers/') ? '服务器详情' : '服务器管理')
function unauthorized() {
  const hadSession = Boolean(session.value)
  generation++; cancelReadRequests(true); passwordDialog.value = false; session.value = null; ready.value = true
  if (!disposed) { error.value = hadSession ? '登录已失效，请重新登录' : ''; void router.replace('/login') }
}
const client = new ControlV3(unauthorized)
provide(consoleContext, { client, session })
async function authenticate() {
  const current = ++generation; error.value = ''
  try {
    const value = await client.session()
    if (disposed || current !== generation) return
    session.value = value; ready.value = true
    if (route.path === '/login') await router.replace('/')
  } catch (e) {
    if (disposed || current !== generation) return
    if (e instanceof V3Error && e.status === 401) { ready.value = true; await router.replace('/login') }
    else error.value = e instanceof Error ? e.message : '会话查询失败'
  }
}
async function signIn() {
  if (busy.value) return
  busy.value = true; error.value = ''
  try { await client.login(form.username, form.password); form.password = ''; await authenticate(); if (session.value) await router.replace('/') }
  catch (e) { if (!disposed) error.value = e instanceof Error ? e.message : '登录失败' }
  finally { busy.value = false }
}
async function signOut() {
  if (busy.value) return
  busy.value = true; error.value = ''
  try { await client.logout(); cancelReadRequests(true); generation++; session.value = null; await router.replace('/login') }
  catch (e) { error.value = e instanceof Error ? e.message : '退出失败' }
  finally { busy.value = false }
}
function passwordChanged() {
  generation++; cancelReadRequests(true); passwordDialog.value = false; session.value = null; form.password = ''
  error.value = '密码已修改，请使用新密码重新登录'
  void router.replace('/login')
}
function connection(event: Event) { reconnecting.value = Boolean((event as CustomEvent).detail.reconnecting) }
onMounted(() => { window.addEventListener('backend-connection', connection); void authenticate() })
onUnmounted(() => { disposed = true; generation++; cancelReadRequests(true); window.removeEventListener('backend-connection', connection) })
</script>

<template>
  <el-config-provider :locale="zhCn">
    <main v-if="!ready" class="boot v3-boot" aria-live="polite"><h1>Webscan</h1><p>{{ reconnecting ? '连接暂时中断，正在重连…' : error || '正在读取登录状态…' }}</p><el-button v-if="error && !reconnecting" @click="authenticate">重新连接</el-button></main>
    <main v-else-if="!session" class="login-screen">
      <div class="login-intro"><span class="wordmark">DZH · WEBSCAN</span><h1>让每一个网站<br>都在你的掌握之中。</h1><p>首页可用性 · 证书到期 · 故障恢复</p><div class="intro-note">由主服务器持续检查，异常通过飞书与邮箱独立投递。</div></div>
      <el-card class="login-card" shadow="never"><span class="eyebrow">网站监控管理</span><h2>登录管理后台</h2><p class="muted">使用安装账号；修改密码后请使用最新密码。</p><el-alert v-if="error" :title="error" type="error" :closable="false" /><el-alert v-if="reconnecting" title="连接暂时中断，正在每 3 秒重连" type="warning" :closable="false" /><el-form label-position="top" @submit.prevent="signIn"><el-form-item label="管理员账号"><el-input v-model="form.username" autocomplete="username" placeholder="请输入账号" /></el-form-item><el-form-item label="密码"><el-input v-model="form.password" type="password" autocomplete="current-password" show-password placeholder="请输入密码" /></el-form-item><el-button type="primary" native-type="submit" :loading="busy" class="full">登录</el-button></el-form><p class="small muted">检测结果代表主服务器对网站的访问情况。</p></el-card>
    </main>
    <div v-else class="shell">
      <aside class="v3-sidebar"><div class="brand"><span class="brand-icon">W</span><div>智慧监控中心<small>DZH WEBSCAN</small></div></div><span class="nav-caption">管理工作台</span><nav aria-label="管理菜单"><router-link to="/" :class="{ active: route.path === '/' }"><DataAnalysis class="nav-icon" />监控总览</router-link><router-link to="/servers" :class="{ active: route.path.startsWith('/servers') }"><Monitor class="nav-icon" />服务器管理</router-link><router-link to="/websites" :class="{ active: route.path.startsWith('/websites') }"><Link class="nav-icon" />网站监控</router-link><router-link to="/events" :class="{ active: route.path === '/events' }"><Document class="nav-icon" />文件与安全事件</router-link><router-link to="/alerts" :class="{ active: route.path === '/alerts' }"><Bell class="nav-icon" />告警中心</router-link><router-link to="/settings" :class="{ active: route.path === '/settings' }"><Setting class="nav-icon" />系统设置</router-link><router-link to="/deployments" :class="{ active: route.path.startsWith('/deployments') || route.path === '/migration-history' }"><List class="nav-icon" />部署任务</router-link><router-link to="/backups" :class="{ active: route.path === '/backups' }"><FolderOpened class="nav-icon" />备份管理</router-link></nav><div class="sidebar-foot"><span class="online-dot"></span> 主服务器统一检测<br><small>{{ route.path === "/events" ? "手动查询，可开启自动刷新" : "指标每 30 秒自动刷新" }}</small></div></aside>
      <div class="workspace"><header class="v3-topbar"><span>统一监控 / {{ title }}</span><div>{{ session.username }} <el-tag class="account-role" size="small">{{ { admin: '管理员', operator: '操作员', viewer: '只读' }[session.role] }}</el-tag><el-button text :disabled="busy" @click="passwordDialog = true">修改密码</el-button><el-button text :loading="busy" @click="signOut">退出登录</el-button></div></header><main class="content v3-content"><el-alert v-if="reconnecting" title="连接暂时中断，已有内容保留；正在每 3 秒重连" type="warning" :closable="false" /><el-alert v-if="error" :title="error" type="error" :closable="false" /><router-view :key="route.path" /><footer>智慧监控中心 · 主控主动采集 · 历史按已应用保留策略清理</footer></main></div>
      <PasswordDialog v-model="passwordDialog" @changed="passwordChanged" />
    </div>
  </el-config-provider>
</template>
