// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { installElements } from './elements'
import Activity from './Activity.vue'
import { api, queryParams, durationText } from './api'
vi.mock('./MetricChart.vue',()=>({default:{render:()=>null}}))
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), api:vi.fn() }))
let app:App, host:HTMLDivElement
const calls:string[]=[]
async function settle(){for(let i=0;i<10;i++){await Promise.resolve();await nextTick()} if(vi.isFakeTimers())await vi.advanceTimersByTimeAsync(30);else await new Promise(r=>setTimeout(r,30))}
beforeEach(()=>{calls.length=0;vi.mocked(api).mockReset();Object.defineProperty(document,'hidden',{configurable:true,value:false})})
afterEach(()=>{app?.unmount();host?.remove()})
async function mount(initial:string, events=true){
 const router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:{render:()=>null}}]})
 await router.push(initial);await router.isReady()
 host=document.createElement('div');document.body.append(host);app=createApp(Activity,{events});app.use(router);installElements(app);app.mount(host);await settle();return router
}
function mock(handler?:(url:string)=>Promise<unknown>){vi.mocked(api).mockImplementation(async <T,>(url:string)=>{calls.push(url);if(url==='/api/servers')return {items:[{id:'node-a',name:'服务器 A',host:'192.0.2.1',snapshot:{values:{}}}]} as T;return (handler?await handler(url):{items:[],total:0}) as T})}
it('query values omit absent filters but preserve zero and false',()=>{expect(queryParams({node:undefined,operation:null,q:'',page:0,history:false}).toString()).toBe('page=0&history=false');expect(durationText(undefined)).toBe('—')})
it('clear server restores all records while preserving other filters and resets page',async()=>{
 mock();const router=await mount('/events?node=node-a&operation=modify&q=keyword&hours=168&page=3')
 host.querySelector('.el-select')!.dispatchEvent(new MouseEvent('mouseenter'));await settle()
 expect(calls.some(v=>v.startsWith('/api/events'))).toBe(false)
 const clear=host.querySelector('.el-select__clear') as HTMLElement;expect(clear).toBeTruthy();clear.click();await settle()
 expect(calls.some(v=>v.startsWith('/api/events'))).toBe(false);(host.querySelector('[data-testid=event-query]') as HTMLElement).click();await settle()
 const params=new URL(calls.filter(v=>v.startsWith('/api/events')).at(-1)!,'http://fixture').searchParams
 expect(params.has('node')).toBe(false);expect(params.get('operation')).toBe('modify');expect(params.get('q')).toBe('keyword');expect(params.get('hours')).toBe('168');expect(params.get('page')).toBe('1');expect(router.currentRoute.value.query.node).toBeUndefined()
 await router.push('/events?node=node-a');await settle();expect(router.currentRoute.value.query.node).toBe('node-a')
})
it('stale request errors cannot replace records for cleared filters',async()=>{
 let rejectOld:(e:Error)=>void=()=>{};let pending=true
 mock(async url=>{if(url.includes('node=node-a')&&pending)return await new Promise((_,reject)=>{rejectOld=reject});return {items:[{time:Date.now()/1000,message:'最新记录'}],total:1}})
 await mount('/events?node=node-a');(host.querySelector('[data-testid=event-query]') as HTMLElement).click();await settle();host.querySelector('.el-select')!.dispatchEvent(new MouseEvent('mouseenter'));await settle();(host.querySelector('.el-select__clear') as HTMLElement).click();await settle();(host.querySelector('[data-testid=event-query]') as HTMLElement).click();await settle();pending=false;rejectOld(new Error('旧请求错误'));await settle()
 expect(host.textContent).toContain('最新记录');expect(host.textContent).not.toContain('旧请求错误');expect(calls.filter(v=>v.startsWith('/api/events')).at(-1)).not.toContain('node=')
})
it('clearing search immediately queries and deletes its URL parameter',async()=>{
 mock();const router=await mount('/alerts?tab=email&recipient=a%40example.com&q=old&status=partial&page=3',false)
 host.querySelector('.el-input')!.dispatchEvent(new MouseEvent('mouseenter'));await settle()
 ;(host.querySelector('.el-input__clear') as HTMLElement).click();await settle()
 expect(router.currentRoute.value.query.q).toBeUndefined();expect(router.currentRoute.value.query.recipient).toBe('a@example.com');expect(router.currentRoute.value.query.status).toBe('partial');expect(router.currentRoute.value.query.page).toBe('1')
 expect(calls.filter(v=>v.startsWith('/api/notifications?')).at(-1)).toContain('channel=email')
})
it('security event details retain scan result, path and localized reasons',async()=>{
 mock(async()=>({items:[{node:'node-a',time:Date.now()/1000,event:{operation:'scan',path:'/www/wwwroot/fixture.php',time:new Date().toISOString(),risk:'high',scan:{status:'error',reason:'scanner_exit'}}}],total:1}))
 await mount('/events');(host.querySelector('[data-testid=event-query]') as HTMLElement).click();await settle();await nextTick();(host.querySelector('button.el-button.is-link') as HTMLElement).click();await settle()
 expect(document.body.textContent).toContain('扫描结果：扫描失败');expect(document.body.textContent).toContain('扫描原因：扫描超时或执行失败');expect(document.body.textContent).toContain('/www/wwwroot/fixture.php');expect(document.body.textContent).toContain('高风险')
})

it('events do not fetch on entry, route changes or visibility unless explicitly enabled',async()=>{
 mock();const router=await mount('/events?node=node-a');expect(calls.filter(v=>v.startsWith('/api/events'))).toHaveLength(0);expect(host.textContent).toContain('请选择筛选条件');
 await router.push('/events?operation=scan');document.dispatchEvent(new Event('visibilitychange'));await settle();expect(calls.filter(v=>v.startsWith('/api/events'))).toHaveLength(0);
 (host.querySelector('[data-testid=event-query]') as HTMLElement).click();await settle();expect(calls.filter(v=>v.startsWith('/api/events'))).toHaveLength(1);expect(calls.at(-1)).toContain('include_probes=false');
 const count=calls.length;document.dispatchEvent(new Event('visibilitychange'));await settle();expect(calls.length).toBe(count)
})
it('refresh interval is account scoped, refresh pauses on changed draft and resets on reentry',async()=>{
 mock();localStorage.setItem('webscan:event-refresh:', '10');const router=await mount('/events');
 (host.querySelector('[data-testid=event-query]') as HTMLElement).click();await settle();const control=host.querySelector('[data-testid=auto-refresh]') as HTMLElement;control.click();await settle();expect(control.classList.contains('is-checked')).toBe(true);
 await router.push('/events?q=unsubmitted');await settle();expect(host.textContent).toContain('已暂停，等待提交筛选');const count=calls.length;document.dispatchEvent(new Event('visibilitychange'));await settle();expect(calls.length).toBe(count);
 app.unmount();host.remove();await mount('/events');expect((host.querySelector('[data-testid=auto-refresh]') as HTMLElement).classList.contains('is-checked')).toBe(false);localStorage.clear()
})
it('timer refreshes submitted filters, preserves page and stops in background',async()=>{
 vi.useFakeTimers();mock(async()=>({items:[],total:80}));await mount('/events');(host.querySelector('[data-testid=event-query]') as HTMLElement).click();await settle()
 try{
 (host.querySelector('[data-testid=auto-refresh]') as HTMLElement).click();await nextTick();await vi.advanceTimersByTimeAsync(31000);expect(calls.filter(v=>v.startsWith('/api/events'))).toHaveLength(2)
 Object.defineProperty(document,'hidden',{configurable:true,value:true});document.dispatchEvent(new Event('visibilitychange'));await vi.advanceTimersByTimeAsync(60000);expect(calls.filter(v=>v.startsWith('/api/events'))).toHaveLength(2)
 Object.defineProperty(document,'hidden',{configurable:true,value:false});document.dispatchEvent(new Event('visibilitychange'));await vi.advanceTimersByTimeAsync(1);expect(calls.filter(v=>v.startsWith('/api/events'))).toHaveLength(3)
 }finally{vi.useRealTimers()}
})
it('custom invalid interval pauses timer with a Chinese validation message',async()=>{
 mock();await mount('/events');const input=host.querySelector('[aria-label="自定义刷新间隔（秒）"]') as HTMLInputElement;input.value='1.5';input.dispatchEvent(new Event('input',{bubbles:true}));await settle();expect(host.textContent).toContain('刷新间隔须为 10～3600 秒整数')
})
