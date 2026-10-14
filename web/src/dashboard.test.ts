// @vitest-environment jsdom
import { createApp, nextTick, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, expect, it, vi } from 'vitest'
import Dashboard from './Dashboard.vue'
import { installElements } from './elements'
import { api } from './api'
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),api:vi.fn()}))
vi.mock('./MetricChart.vue',()=>({default:{render:()=>null}}))
let app:App,host:HTMLDivElement
async function settle(){for(let i=0;i<20;i++){await Promise.resolve();await nextTick()}}
afterEach(()=>{app?.unmount();host?.remove();vi.clearAllMocks()})
it('partial dashboard failures retain prior values and do not claim there are no alerts',async()=>{
 let failed=false
 vi.mocked(api).mockImplementation(async <T,>(url:string)=>{if(url.startsWith('/api/alerts')){if(failed)throw new Error('告警接口读取失败');return {items:[]} as T};return {servers:[],components:[{id:'email',name:'邮箱通知',status:'disabled',reason:'通知关闭',metrics:{待投递:2},href:'/alerts?tab=email',updated:0}],errors:failed?{events:'事件读取失败'}:{},events_24h:failed?null:9,website_total:3,updated:1,release:'v2.0.36'} as T})
 const router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:{render:()=>null}}]});await router.push('/');host=document.createElement('div');document.body.append(host);app=createApp(Dashboard);installElements(app);app.use(router).mount(host);await settle();expect(host.textContent).toContain('已停用');expect(host.textContent).toContain('文件与安全事件');
 failed=true;const refresh=Array.from(host.querySelectorAll('button')).find(v=>v.textContent==='立即刷新')!;refresh.click();await settle();expect(host.textContent).toContain('告警接口读取失败');expect(host.textContent).not.toContain('当前没有已确认异常');expect(host.textContent).toContain('事件读取失败');expect(host.querySelector('a[href="/events"]')?.textContent).toContain('9')
})
