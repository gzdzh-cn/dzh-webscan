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
async function open(existing:boolean){
 vi.mocked(api).mockImplementation(async <T,>(url:string)=> (url==='/api/settings'?{revision:'fixture',values:{nodes:existing?[{id:'old',name:'旧节点',host:'192.0.2.2',ssh:{auth_method:'key',private_key_path:'/root/key'}}]:[],node_defaults:{}},effective_nodes:existing?[{id:'old',deployment:{mode:'docker'}}]:[]}:{scope:'node',restart:true}) as T)
 const visible=ref(false),router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:{render:()=>null}}]});await router.push('/servers');await router.isReady()
 host=document.createElement('div');document.body.append(host);app=createApp({render:()=>h(NodeDialog,{modelValue:visible.value,nodeId:existing?'old':'','onUpdate:modelValue':(v:boolean)=>{visible.value=v}})});app.use(router).use(ElementPlus).mount(host);visible.value=true;await settle()
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
 expect(keyText().value).toBe(text.replaceAll('\r\n','\n'));expect(vi.mocked(api).mock.calls).toHaveLength(1)
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
