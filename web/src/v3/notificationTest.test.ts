// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App, type Ref } from 'vue'
import { installElements } from '../elements'
import { ControlV3, V3Error, type V3NotificationTestJob, type V3NotificationTestPreview, type V3Session } from '../controlV3'
import { consoleContext } from './context'
import NotificationTest from './NotificationTest.vue'
let app: App | undefined, host: HTMLDivElement, activeSession: Ref<V3Session | null>
async function settle() { for (let i = 0; i < 30; i++) { await Promise.resolve(); await nextTick() } }
const preview = (): V3NotificationTestPreview => ({ token: 'preview-only', channel: 'email', runtime_version: 7, expires_at: new Date(Date.now() + 600000).toISOString(), recipients: ['applied@example.test'], subject: '固定测试内容', body: '<script>文本</script>' })
const job = (status: V3NotificationTestJob['status'] = 'running'): V3NotificationTestJob => ({ id: 'test-1', channel:'email',runtime_version:7,status,created_at:'',updated_at:'',finished_at:null,message:'持久任务结果',items:[{ordinal:1,recipient:'applied@example.test',state:status === 'unknown' ? 'unknown' : status === 'succeeded' ? 'accepted' : 'sending',outcome:'',message:'仅通道确认'}] })
function button(text: string) { return Array.from(document.body.querySelectorAll('button')).find(e => e.textContent?.trim() === text)! }
async function mount(client: ControlV3, role: 'admin'|'viewer' = 'admin', channel = ref<'email'|'feishu'>('email'), username = 'fixture', available = true) { vi.spyOn(client,'capabilities').mockResolvedValue({ api_version:3,topology:'single',features:[],implementation_stage:'fixture',notification_tests:{available,reason:available?'':'测试工作器心跳未知'} }); host = document.createElement('div'); document.body.append(host); app = createApp({ components:{NotificationTest},setup:()=>({channel}),template:'<NotificationTest :channel="channel" :runtime-version="7" :dirty="true" :pending="true" />' });installElements(app);activeSession=ref({username,role,csrf:'csrf'});app.provide(consoleContext,{client,session:activeSession});app.mount(host);await settle();return channel }
beforeEach(() => { sessionStorage.clear(); Object.defineProperty(document,'hidden',{configurable:true,value:false}) })
afterEach(() => { app?.unmount();app=undefined;host?.remove();document.querySelectorAll('.el-overlay').forEach(e=>e.remove());vi.restoreAllMocks();vi.useRealTimers() })
it('uses only applied runtime configuration and retains stable confirmation key after unknown HTTP response',async()=>{
 const client=new ControlV3(), prepare=vi.spyOn(client,'notificationTestPreview').mockResolvedValue(preview()), submit=vi.spyOn(client,'createNotificationTest').mockRejectedValueOnce(new Error('502')).mockResolvedValue(job('unknown')), save=vi.spyOn(client,'confirmSettings')
 await mount(client);expect(host.textContent).toContain('草稿和待应用设置不参与');button('测试当前已应用配置').click();await settle();expect(prepare.mock.calls[0]?.slice(0,2)).toEqual(['email',7]);expect(document.body.textContent).toContain('applied@example.test');expect(document.body.textContent).toContain('<script>文本</script>');expect(document.querySelector('.test-content script')).toBeNull()
 button('确认创建测试任务').click();await settle();expect(document.body.textContent).toContain('不会自动重发');button('确认创建测试任务').click();await settle();expect(submit.mock.calls[0]).toEqual(submit.mock.calls[1]);expect(submit.mock.calls[0]?.[0]).toBe('preview-only');expect(save).not.toHaveBeenCalled();expect(document.body.textContent).toContain('结果未知');expect(button('重新预览测试')).toBeUndefined()
})
it('rejects expired preview without creating a task',async()=>{
 const client=new ControlV3();vi.spyOn(client,'notificationTestPreview').mockResolvedValue({...preview(),expires_at:new Date(Date.now()-1000).toISOString()});const submit=vi.spyOn(client,'createNotificationTest');await mount(client);button('测试当前已应用配置').click();await settle();button('确认创建测试任务').click();await settle();expect(submit).not.toHaveBeenCalled();expect(document.body.textContent).toContain('预览已过期')
})
it('polls without overlap, pauses in hidden tabs and retains original result after an outage',async()=>{
 vi.useFakeTimers();const client=new ControlV3();vi.spyOn(client,'notificationTestPreview').mockResolvedValue(preview());vi.spyOn(client,'createNotificationTest').mockResolvedValue(job());let complete:(v:V3NotificationTestJob)=>void=()=>{};const poll=vi.spyOn(client,'notificationTest').mockImplementationOnce(()=>new Promise(resolve=>{complete=resolve})).mockRejectedValueOnce(new Error('503')).mockResolvedValue(job('succeeded'))
 await mount(client);button('测试当前已应用配置').click();await settle();button('确认创建测试任务').click();await settle();await vi.advanceTimersByTimeAsync(3000);await settle();expect(poll).toHaveBeenCalledTimes(1);button('刷新结果').click();await settle();expect(poll).toHaveBeenCalledTimes(1)
 Object.defineProperty(document,'hidden',{configurable:true,value:true});document.dispatchEvent(new Event('visibilitychange'));complete(job('succeeded'));await settle();expect(document.body.textContent).toContain('测试中');await vi.advanceTimersByTimeAsync(10000);expect(poll).toHaveBeenCalledTimes(1)
 Object.defineProperty(document,'hidden',{configurable:true,value:false});document.dispatchEvent(new Event('visibilitychange'));await settle();expect(document.body.textContent).toContain('503');expect(document.body.textContent).toContain('持久任务结果');await vi.advanceTimersByTimeAsync(3000);await settle();expect(document.body.textContent).toContain('已完成');expect(poll).toHaveBeenCalledTimes(3)
})
it('ignores late previews after changing channel and offers no test actions to viewers',async()=>{
 const client=new ControlV3();let complete:(v:V3NotificationTestPreview)=>void=()=>{};vi.spyOn(client,'notificationTestPreview').mockImplementation(()=>new Promise(resolve=>{complete=resolve}));const channel=await mount(client);button('测试当前已应用配置').click();await settle();channel.value='feishu';await settle();complete(preview());await settle();expect(button('确认创建测试任务')).toBeUndefined();expect(document.body.textContent).not.toContain('applied@example.test');app?.unmount();app=undefined;host.remove();await mount(client,'viewer');expect(button('测试当前已应用配置')).toBeUndefined()
})

it('restores only a stored task ID after refresh without issuing another preview or send',async()=>{
 const client=new ControlV3();sessionStorage.setItem('webscan-v3-notification-test:fixture:email','restored-task');const poll=vi.spyOn(client,'notificationTest').mockResolvedValue({...job('unknown'),id:'restored-task'}),prepare=vi.spyOn(client,'notificationTestPreview'),submit=vi.spyOn(client,'createNotificationTest');await mount(client);expect(poll.mock.calls[0]?.[0]).toBe('restored-task');button('查看测试结果').click();await settle();expect(document.body.textContent).toContain('结果未知');expect(prepare).not.toHaveBeenCalled();expect(submit).not.toHaveBeenCalled();expect(sessionStorage.getItem('webscan-v3-notification-test:fixture:email')).toBe('restored-task')
})
it('isolates stored task IDs by account and channel and explains an expired task without sending',async()=>{
 const client=new ControlV3();sessionStorage.setItem('webscan-v3-notification-test:other:email','private-task');sessionStorage.setItem('webscan-v3-notification-test:fixture:feishu','old-feishu');const poll=vi.spyOn(client,'notificationTest').mockRejectedValue(new V3Error(404,'not_found','未找到')),submit=vi.spyOn(client,'createNotificationTest');const channel=await mount(client);expect(poll).not.toHaveBeenCalled();channel.value='feishu';await settle();expect(poll.mock.calls[0]?.[0]).toBe('old-feishu');expect(sessionStorage.getItem('webscan-v3-notification-test:fixture:feishu')).toBeNull();expect(host.textContent).toContain('上次测试任务不存在或已清理');expect(submit).not.toHaveBeenCalled();expect(poll.mock.calls.some(call=>call[0]==='private-task')).toBe(false)
})
it('keeps testing disabled when the actual worker capability is unavailable',async()=>{
 const client=new ControlV3(),prepare=vi.spyOn(client,'notificationTestPreview');await mount(client,'admin',ref('email'),'fixture',false);expect(button('测试当前已应用配置').disabled).toBe(true);expect(host.textContent).toContain('测试工作器心跳未知');expect(prepare).not.toHaveBeenCalled()
})

it('clears visible results on account change before restoring only that account task',async()=>{
 const client=new ControlV3();sessionStorage.setItem('webscan-v3-notification-test:fixture:email','first-account-task');const poll=vi.spyOn(client,'notificationTest').mockResolvedValue({...job('succeeded'),id:'first-account-task'});await mount(client);button('查看测试结果').click();await settle();expect(document.body.textContent).toContain('first-account-task');activeSession.value={username:'second',role:'admin',csrf:'second'};await settle();expect(document.body.textContent).not.toContain('first-account-task');expect(button('查看测试结果')).toBeUndefined();expect(poll.mock.calls.every(call=>call[0]==='first-account-task')).toBe(true)
})
