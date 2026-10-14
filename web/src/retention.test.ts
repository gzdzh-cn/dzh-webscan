// @vitest-environment jsdom
import { createApp, nextTick, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, expect, it, vi } from 'vitest'
import RetentionPanel from './RetentionPanel.vue'
import { installElements } from './elements'
import { api } from './api'
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),api:vi.fn()}))
let app:App,host:HTMLDivElement
async function settle(){for(let i=0;i<20;i++){await Promise.resolve();await nextTick()}}
afterEach(()=>{app?.unmount();host?.remove();vi.clearAllMocks()})
it('export-first blocks cleanup until export completes and requires explicit confirmation',async()=>{
 const requests:{url:string;body:unknown}[]=[]
 vi.mocked(api).mockImplementation(async <T,>(url:string,method='GET',body?:unknown)=>{requests.push({url,body});if(url==='/api/servers')return {items:[]} as T;if(url==='/api/retention/status')return {retention:{},items:[],files:[],automatic:{items:[],total:0}} as T;if(url.includes('/jobs'))return {items:[],total:0} as T;if(url.endsWith('/preview'))return {id:'fixture',expires:Date.now()/1000+600,counts:{eligible:5,protected:2}} as T;if(url.endsWith('/export'))return {id:'export-fixture',status:'complete',kind:'export'} as T;return {id:'cleanup-fixture',status:'pending'} as T})
 const router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:{render:()=>null}}]});await router.push('/settings?category=security');host=document.createElement('div');document.body.append(host);app=createApp(RetentionPanel);installElements(app);app.use(router).mount(host);await settle();Array.from(host.querySelectorAll('button')).find(v=>v.textContent==='预览范围')!.click();await settle();expect(host.textContent).toContain('受保护 2 条')
 ;(host.querySelector('.el-checkbox__input') as HTMLElement).click();await settle();const cleanup=Array.from(host.querySelectorAll('button')).find(v=>v.textContent==='清理本次范围')!;expect(cleanup.disabled).toBe(true)
 Array.from(host.querySelectorAll('button')).find(v=>v.textContent==='导出 JSONL')!.click();await settle();expect(cleanup.disabled).toBe(false);expect(host.querySelector('a[href="/api/retention/jobs/export-fixture/download"]')).toBeTruthy()
 cleanup.click();await settle();expect(requests.some(v=>v.url.endsWith('/cleanup'))).toBe(false);Array.from(document.querySelectorAll('button')).find(v=>v.textContent==='确认清理')!.click();await settle();expect(requests.find(v=>v.url.endsWith('/cleanup'))?.body).toMatchObject({confirm:true,export_job:'export-fixture'})
})
