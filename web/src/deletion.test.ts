// @vitest-environment jsdom
import {afterEach,beforeEach,expect,it,vi} from 'vitest'
import {createApp,nextTick,type App} from 'vue'
import {createMemoryHistory,createRouter} from 'vue-router'
import {installElements} from './elements'
import RecordDelete from './RecordDelete.vue'
import BackupManager from './BackupManager.vue'
import {api} from './api'
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),api:vi.fn()}))
let app:App,host:HTMLDivElement
async function settle(){for(let i=0;i<8;i++){await Promise.resolve();await nextTick()}await new Promise(r=>setTimeout(r,20))}
beforeEach(()=>{vi.mocked(api).mockReset()});afterEach(()=>{app?.unmount();host?.remove();document.body.querySelectorAll('.el-overlay').forEach(n=>n.remove())})
async function mount(component:any,props:any={},url='/backups'){host=document.createElement('div');document.body.append(host);const router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:{render:()=>null}}]});await router.push(url);app=createApp(component,props);app.use(router);installElements(app);app.mount(host);await settle();return router}
it('deletion previews explicit selected keys and shows partial protected results',async()=>{
 vi.mocked(api).mockImplementation(async<T,>(url:string,method?:string,body?:unknown)=>{if(url.endsWith('/preview'))return {id:'preview',counts:{eligible:1,protected:1}} as T;if(url.endsWith('/cleanup'))return {id:'job'} as T;return {status:'complete',processed:1,skipped:1} as T})
 const done=vi.fn();await mount(RecordDelete,{records:[{record_key:'first'},{record_key:'second'}],label:'文件历史',history:true,onDone:done});(host.querySelector('button') as HTMLElement).click();await settle();expect(vi.mocked(api).mock.calls[0]).toEqual(['/api/retention/preview','POST',{category:'all',records:['first','second']}]);expect(document.body.textContent).toContain('可删除 1 条，受保护 1 条');const confirm=Array.from(document.body.querySelectorAll('button')).find(b=>b.textContent==='确认删除')!;confirm.click();await settle();expect(done).toHaveBeenCalledTimes(1);expect(document.body.textContent).toContain('跳过 1 条');expect(vi.mocked(api).mock.calls).not.toContainEqual(expect.arrayContaining([expect.objectContaining({node:'all'})]))
})
it('unified backup tabs preserve independent pagination and never restore on import/list',async()=>{
 vi.mocked(api).mockImplementation(async<T,>(url:string)=>url==='/api/settings'?{revision:'current'} as T:{items:[],total:60} as T)
 const router=await mount(BackupManager,{},'/backups?tab=deployment&website_page=2');expect(host.textContent).toContain('部署配置备份');expect(host.textContent).toContain('手动备份');const website=Array.from(host.querySelectorAll('button')).find(b=>b.textContent==='网站配置')!;website.click();await settle();expect(router.currentRoute.value.query.website_page).toBe('2');expect(host.textContent).toContain('网站配置备份');expect(vi.mocked(api).mock.calls.every(c=>(c[1]||'GET')==='GET')).toBe(true)
})
