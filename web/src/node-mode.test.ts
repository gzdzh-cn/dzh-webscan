// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest'
import { createApp, h, nextTick, ref, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import ElementPlus from 'element-plus'
import NodeDialog from './NodeDialog.vue'
import { api } from './api'
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),api:vi.fn()}))
let app:App,host:HTMLDivElement
async function settle(){for(let i=0;i<8;i++){await Promise.resolve();await nextTick()}await new Promise(r=>setTimeout(r,30))}
afterEach(()=>{app?.unmount();host?.remove();vi.mocked(api).mockReset()})
function checked(){return {id:'check-fixture',status:'complete',expires:Date.now()/1000+600,report:{ok:true,items:[{name:'连接',status:'passed',message:'已通过',duration_ms:1}],mode:'native',checked_at:Date.now()/1000}}}
async function open(existing:boolean){
 vi.mocked(api).mockImplementation(async <T,>(url:string)=> (url==='/api/servers/requirements'?{nodes:[],minimum_systemd:231,reserve_mib:256}:url==='/api/servers/preflight'?{id:'check-fixture'}:url.startsWith('/api/servers/preflight/')?checked():url==='/api/deployments'?{id:'fixture-job'}:url==='/api/settings'?{revision:'fixture',values:{nodes:existing?[{id:'old',name:'旧节点',host:'192.0.2.2',ssh:{auth_method:'key',private_key_path:'/root/key'}}]:[],node_defaults:{}},effective_nodes:existing?[{id:'old',deployment:{mode:'docker'}}]:[]}:{scope:'node',restart:true}) as T)
 const visible=ref(false),router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:{render:()=>null}}]});await router.push('/servers');await router.isReady()
 host=document.createElement('div');document.body.append(host);app=createApp({render:()=>h(NodeDialog,{modelValue:visible.value,nodeId:existing?'old':'','onUpdate:modelValue':(v:boolean)=>{visible.value=v}})});app.use(router).use(ElementPlus).mount(host);visible.value=true;await settle()
 if(!existing){const inputs=document.body.querySelectorAll<HTMLInputElement>('.node-editor-dialog .form-grid input');for(const [i,value] of ['新节点','new-node','192.0.2.3'].entries()){inputs[i]!.value=value;inputs[i]!.dispatchEvent(new Event('input',{bubbles:true}))}await settle()}
}
function button(label:string){return Array.from(document.body.querySelectorAll('button')).find(b=>b.textContent?.trim()===label)!}
it('new nodes preview native without installing Docker',async()=>{
 await open(false);expect(document.body.textContent).toContain('直接运行 Go（无需 Docker）');button('校验并预览').click();await settle()
 const args=vi.mocked(api).mock.calls.find(c=>c[0]==='/api/settings/preview')!;expect((args[2] as {node:{deployment:{mode:string}}}).node.deployment.mode).toBe('native')
})
it('old nodes retain docker and explicit change is saved',async()=>{
 await open(true);expect(document.body.textContent).toContain('Docker 单容器')
 ;(document.body.querySelector('.el-select__wrapper') as HTMLElement).click();await settle()
 ;Array.from(document.body.querySelectorAll('.el-select-dropdown__item')).find(e=>e.textContent?.includes('直接运行 Go'))?.dispatchEvent(new MouseEvent('click',{bubbles:true}));await settle()
 button('校验并预览').click();await settle();button('仅保存').click();await settle()
 const args=vi.mocked(api).mock.calls.find(c=>c[0]==='/api/settings'&&c[1]==='PUT')!;expect((args[2] as {node:{deployment:{mode:string}}}).node.deployment.mode).toBe('native')
})

async function contentMode(){(document.body.querySelector('input[value="content"]') as HTMLInputElement).click();await settle()}
function keyText(){return document.body.querySelector('textarea[data-testid="private-key-content"], [data-testid="private-key-content"] textarea') as HTMLTextAreaElement}
function changeText(text:string){const input=keyText();input.value=text;input.dispatchEvent(new Event('input',{bubbles:true}))}
it('private key file fills the textarea, does not save automatically and is sent only as edit content',async()=>{
 await open(false);await contentMode();const input=document.body.querySelector('[data-testid="private-key-file"]') as HTMLInputElement
 const text='-----BEGIN OPENSSH PRIVATE KEY-----\r\nfixture\r\n-----END OPENSSH PRIVATE KEY-----\r\n'
 const file=new File([text],'without-extension');Object.defineProperty(file,'text',{value:async()=>text});Object.defineProperty(input,'files',{configurable:true,value:[file]});input.dispatchEvent(new Event('change',{bubbles:true}));await settle()
 expect(keyText().value).toBe(text.replaceAll('\r\n','\n'));expect(vi.mocked(api).mock.calls.filter(c=>c[1]==='PUT'||c[1]==='POST')).toHaveLength(0)
 button('校验并预览').click();await settle();button('仅保存').click();await settle();const args=vi.mocked(api).mock.calls.find(c=>c[0]==='/api/settings'&&c[1]==='PUT')!
 const edit=args[2] as {ssh_private_key_content:string;node:{ssh:{private_key_path:string}}};expect(edit.ssh_private_key_content).toBe(text);expect(edit.node.ssh.private_key_path).toBe('')
})
it('drop prevents file navigation, retains text on invalid files and mode changes clear content',async()=>{
 await open(true);await contentMode();changeText('previous');await settle();const event=new Event('drop',{bubbles:true,cancelable:true});Object.defineProperty(event,'dataTransfer',{value:{files:[new File([],'empty')]}});document.body.querySelector('.private-key-entry')!.dispatchEvent(event);await settle()
 expect(event.defaultPrevented).toBe(true);expect(keyText().value).toBe('previous');expect(document.body.textContent).toContain('私钥文件内容为空');expect(document.body.textContent).toContain('已配置，留空保留')
 ;(document.body.querySelector('input[value="path"]') as HTMLInputElement).click();await settle();await contentMode();expect(keyText().value).toBe('')
})
it('pasted content reaches save-and-deploy without entering the node SSH object',async()=>{
 await open(true);await contentMode();changeText('fixture pasted key');await settle();button('校验并预览').click();await settle();button('保存并部署').click();await settle()
 const args=vi.mocked(api).mock.calls.find(c=>c[0]==='/api/deployments')!;expect(args).toBeTruthy();expect((args[2] as {edit:{ssh_private_key_content:string}}).edit.ssh_private_key_content).toBe('fixture pasted key')
})

it('connection check never saves or deploys and late result is ignored after closing',async()=>{
 await open(false)
 let finish!:(value:unknown)=>void
 vi.mocked(api).mockImplementation(async <T,>(url:string)=> {if(url==='/api/servers/preflight')return await new Promise<unknown>(resolve=>{finish=resolve}) as T;throw new Error('unexpected request')})
 button('连接与环境检查').click();await settle()
 expect(vi.mocked(api).mock.calls.filter(c=>c[1]==='POST').map(c=>c[0])).toEqual(['/api/servers/preflight'])
 button('取消').click();await settle();finish({id:'late-check'});await settle()
 expect(document.body.textContent).not.toContain('should not appear')
})
it('opening the node dialog displays inherited configuration without side effects',async()=>{
 await open(false)
 // Existing API fixture remains read-only until the user explicitly invokes a form action.
 expect(vi.mocked(api).mock.calls.map(c=>c[0])).toEqual(['/api/settings','/api/servers/requirements'])
 expect(document.body.textContent).toContain('使用公共配置（推荐）')
 expect(document.body.textContent).toContain('跟随公共配置')
})

it('independent upgrade ignores unsaved form drafts and uses a bound preview',async()=>{
 await open(true)
 vi.mocked(api).mockImplementation(async <T,>(url:string)=>{
  if(url==='/api/settings')return {revision:'saved',values:{nodes:[{id:'old',name:'已保存名称',host:'192.0.2.2',enabled:true,ssh:{auth_method:'key'}}]},effective_nodes:[{id:'old',enabled:true,deployment:{mode:'docker'}}],node_deployments:{old:{mode:'docker',version:'v2.0.43',phase:'complete'}}} as T
  if(url==='/api/servers/requirements')return {nodes:[]} as T
  if(url==='/api/servers/preflight')return {id:'check-fixture'} as T
  if(url.startsWith('/api/servers/preflight/'))return checked() as T
  if(url.endsWith('/upgrade-preview'))return {preview_token:'bound-token',revision:'saved',mode:'docker',current_version:'v2.0.43',target_version:'v2.0.44',target_image:'test@sha256:fixture',changes:[],baseline_known:false,scope:'仅升级此子服务器'} as T
  if(url==='/api/deployments')return {id:'upgrade-job'} as T
  throw new Error('unexpected request')
 })
 button('取消').click();await settle()
 // Reopen by mounting again with installed metadata.
 app.unmount();host.remove()
 const visible=ref(false),router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:{render:()=>null}}]});await router.push('/servers');await router.isReady();host=document.createElement('div');document.body.append(host);app=createApp({render:()=>h(NodeDialog,{modelValue:visible.value,nodeId:'old','onUpdate:modelValue':(v:boolean)=>{visible.value=v}})});app.use(router).use(ElementPlus).mount(host);visible.value=true;await settle()
 const name=document.body.querySelector('.node-editor-dialog input') as HTMLInputElement;name.value='未保存草稿';name.dispatchEvent(new Event('input',{bubbles:true}));await settle()
 button('升级子服务器').click();await settle();expect(document.body.textContent).toContain('不保存弹窗草稿');expect(document.body.textContent).toContain('无法确认配置差异');button('确认升级（不保存草稿）').click();await settle()
 const call=vi.mocked(api).mock.calls.find(c=>c[0]==='/api/deployments')!;expect(call[2]).toMatchObject({kind:'upgrade-node',node:'old',revision:'saved',preview_token:'bound-token'});expect(call[2]).not.toHaveProperty('edit');expect(vi.mocked(api).mock.calls.filter(c=>c[1]==='PUT')).toHaveLength(0)
})

it('deployment automatically checks first and keeps a failed result visible beside footer buttons',async()=>{
 await open(true);button('校验并预览').click();await settle()
 const original=vi.mocked(api).getMockImplementation()!
 vi.mocked(api).mockImplementation(async <T,>(url:string,...args:unknown[])=>url.startsWith('/api/servers/preflight/')?{...checked(),report:{ok:false,items:[{name:'中心到指标',status:'failed',message:'连接超时',suggestion:'检查云安全组'}]}} as T:original(url,...args as [string?,unknown?]) as Promise<T>)
 button('保存并部署').click();await settle()
 expect(vi.mocked(api).mock.calls.find(c=>c[0]==='/api/servers/preflight')?.[2]).toMatchObject({active:true,async:true})
 expect(vi.mocked(api).mock.calls.filter(c=>c[0]==='/api/deployments')).toHaveLength(0)
 expect(document.querySelector('.el-dialog__footer .node-operation-status')?.textContent).toContain('部署前检查未通过')
 expect(document.body.textContent).toContain('检查云安全组')
})
it('warnings require explicit confirmation and only saving does not start preflight',async()=>{
 await open(true);button('校验并预览').click();await settle()
 const original=vi.mocked(api).getMockImplementation()!
 vi.mocked(api).mockImplementation(async <T,>(url:string,...args:unknown[])=>url.startsWith('/api/servers/preflight/')?{...checked(),report:{ok:true,items:[{name:'Docker',status:'warning',message:'将安装 Compose'}]}} as T:original(url,...args as [string?,unknown?]) as Promise<T>)
 button('保存并部署').click();await settle();expect(button('确认警告并继续部署')).toBeTruthy();expect(vi.mocked(api).mock.calls.filter(c=>c[0]==='/api/deployments')).toHaveLength(0)
 button('确认警告并继续部署').click();await settle()
 expect(vi.mocked(api).mock.calls.find(c=>c[0]==='/api/deployments')?.[2]).toMatchObject({preflight_token:'check-fixture',acknowledge_warnings:true})
})
it('requirements display effective custom ports and source without claiming reachability',async()=>{
 await open(true)
 vi.mocked(api).mockImplementation(async <T,>()=>({minimum_systemd:231,reserve_mib:256,event_url:'https://192.0.2.1:20443',nodes:[{id:'old',ssh_port:2222,metrics_port:19101,allowed_source_ip:'192.0.2.10'}]}) as T)
 button('查看完整部署要求').click();await settle()
 expect(document.body.textContent).toContain('实际来源以连接检测结果为准')
})
it('invalid fields are focused after the form is enabled and no request is sent',async()=>{
 await open(false)
 const name=document.querySelector<HTMLInputElement>('.node-editor-dialog .form-grid input')!;name.value='';name.dispatchEvent(new Event('input',{bubbles:true}));await settle()
 button('校验并预览').click();await settle()
 expect(document.activeElement).toBe(name);expect(name.disabled).toBe(false)
 expect(document.querySelector('.el-dialog__footer .node-operation-status')?.textContent).toContain('必填字段')
 expect(vi.mocked(api).mock.calls.some(c=>c[0]==='/api/settings/preview')).toBe(false)
})
