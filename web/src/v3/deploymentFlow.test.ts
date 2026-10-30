// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { installElements } from '../elements'
import { ControlV3, type V3Preparation, type V3DeploymentPreview } from '../controlV3'
import { consoleContext } from './context'
import Flow from './DeploymentFlow.vue'
let app: App | undefined, host: HTMLDivElement
const preview: V3DeploymentPreview = { token: 'a'.repeat(64), node: 'node-a', kind: 'upgrade', version: 2, applied_version: 1, target: { release: 'v3.0.0', sha256: 'b'.repeat(64), mode: 'docker' }, comparison: 'newer', expires_at: '2026-10-30T12:00:00Z' }
async function settle() { for (let i = 0; i < 25; i++) { await Promise.resolve(); await nextTick() } }
function button(text: string) { const el = Array.from(host.querySelectorAll('button')).find(e => e.textContent?.trim() === text); if (!el) throw new Error('Missing '+text); return el }
async function mount(client = new ControlV3()) {
 vi.spyOn(client, 'deployments').mockResolvedValue({ items: [], next_cursor: '', limit: 20 })
 host = document.createElement('div'); document.body.append(host)
 const job = vi.fn(), status = vi.fn()
 app = createApp(Flow, { node: { id: 'node-a', version: 2, applied_version: 1, mode: 'docker' }, upgrade: true, onJob: job, onStatus: status }); installElements(app)
 app.provide(consoleContext, { client, session: ref({ username: 'admin', role: 'admin' as const, csrf: 'fixture' }) })
 const instance = app.mount(host) as unknown as { begin: () => Promise<void> }; await settle()
 return { instance, job, status, client }
}
beforeEach(() => { Object.defineProperty(document, 'hidden', { configurable: true, value: false }) })
afterEach(() => { app?.unmount(); app = undefined; host?.remove(); vi.restoreAllMocks(); vi.useRealTimers() })
it('uses saved configuration for independent upgrade and exposes real job navigation only after confirmation', async () => {
 const client = new ControlV3()
 vi.spyOn(client,'sshCredential').mockResolvedValue({ configured: true, version: 2, ssh_port: 555, fingerprint: 'SHA256:fixture' })
 const prepare = vi.spyOn(client,'prepareDeployment').mockResolvedValue({ id: 'prepare', node: 'node-a', kind: 'prepare', phase: 'queued', status: 'queued' })
 const confirm = vi.spyOn(client,'confirmDeployment').mockResolvedValue({ id: 'confirm', node: 'node-a', kind: 'confirm', phase: 'queued', status: 'queued' })
 vi.spyOn(client,'deploymentPreparation').mockImplementation(async id => id === 'prepare' ? { id, node: 'node-a', kind: 'prepare', phase: 'complete', status: 'succeeded', result: { preview } } : { id, node: 'node-a', kind: 'confirm', phase: 'complete', status: 'succeeded', result: { job: 'real-job' } })
 const { instance, job } = await mount(client); await instance.begin(); await settle()
 expect(prepare.mock.calls[0]?.slice(0,3)).toEqual(['node-a',2,'upgrade'])
 expect(host.textContent).toContain('本次不保存编辑弹窗中的草稿')
 expect(host.textContent).toContain('v3.0.0'); expect(job).not.toHaveBeenCalled()
 button('确认并创建部署任务').click(); await settle()
 expect(confirm.mock.calls[0]?.slice(0,2)).toEqual(['prepare',preview]); expect(job).toHaveBeenCalledWith('real-job')
})
it('reads selected content without using the local filename as a server path and keeps content after invalid input', async () => {
 const { instance, client } = await mount()
 vi.spyOn(client,'sshCredential').mockResolvedValue({ configured: false, version: 2, ssh_port: 22, fingerprint: '' })
 const fingerprint = vi.spyOn(client,'sshFingerprint').mockResolvedValue({ id:'pin',node:'node-a',kind:'fingerprint',status:'queued',phase:'queued' })
 vi.spyOn(client,'deploymentPreparation').mockResolvedValue({ id:'pin',node:'node-a',kind:'fingerprint',status:'succeeded',phase:'complete',result:{ host:'192.0.2.1',port:22,fingerprint:'SHA256:public',fingerprint_token:'c'.repeat(64) } })
 const fileInput = host.querySelector('input[type=file]') as HTMLInputElement
 const select = async (files: unknown[]) => { Object.defineProperty(fileInput,'files',{ configurable:true,value:files }); fileInput.dispatchEvent(new Event('change')); await settle() }
 await select([{ size:30,name:'local-private-key',text:async()=> 'private\nkey\ncontent' }])
 expect((host.querySelector('textarea') as HTMLTextAreaElement).value).toBe('private\nkey\ncontent')
 await select([{ size:65537,text:async()=> 'bad' }]); expect(host.textContent).toContain('64 KiB'); expect((host.querySelector('textarea') as HTMLTextAreaElement).value).toContain('private\nkey')
 await select([{ size:1,text:async()=>'' },{ size:2,text:async()=>'' }]);expect(host.textContent).toContain('一个私钥文件')
 await instance.begin(); await settle(); expect(fingerprint).toHaveBeenCalled(); expect(host.textContent).toContain('确认 SSH 主机指纹')
 const save = vi.spyOn(client,'saveSSHCredential').mockRejectedValue(new Error('模拟断网，保留输入'))
 button('确认指纹并准备部署').click(); await settle()
 expect(save.mock.calls[0]?.[1]).toMatchObject({ private_key_content:'private\nkey\ncontent',fingerprint_preparation:'pin' })
 expect(save.mock.calls[0]?.[1]).not.toHaveProperty('private_key_path')
 expect(host.textContent).toContain('保留输入');expect((host.querySelector('textarea') as HTMLTextAreaElement).value).toContain('private\nkey')
})
it('discards late private-file reads after newer selection or unmount', async () => {
 await mount(); const fileInput=host.querySelector('input[type=file]') as HTMLInputElement
 let finish!:(value:string)=>void
 const old = new Promise<string>(r=>{finish=r})
 Object.defineProperty(fileInput,'files',{configurable:true,value:[{size:10,text:()=>old}]});fileInput.dispatchEvent(new Event('change'));await settle()
 Object.defineProperty(fileInput,'files',{configurable:true,value:[{size:10,text:async()=> 'latest'}]});fileInput.dispatchEvent(new Event('change'));await settle()
 finish('stale');await settle();expect((host.querySelector('textarea') as HTMLTextAreaElement).value).toBe('latest')
 app?.unmount();app=undefined;finish('closed');await settle();expect(host.textContent).not.toContain('closed')
})
it('preserves feedback and prevents duplicate work while preparation is pending', async () => {
 vi.useFakeTimers(); const client=new ControlV3()
 vi.spyOn(client,'sshCredential').mockResolvedValue({configured:true,version:2,ssh_port:22,fingerprint:'fp'})
 const prepare=vi.spyOn(client,'prepareDeployment').mockResolvedValue({id:'p',node:'node-a',kind:'prepare',status:'queued',phase:'queued'})
 let finish!:(value:V3Preparation)=>void
 vi.spyOn(client,'deploymentPreparation').mockImplementation(()=>new Promise(resolve=>{finish=resolve}))
 const {instance,job}=await mount(client);void instance.begin();await settle();void instance.begin();await settle()
 expect(prepare).toHaveBeenCalledTimes(1)
 app?.unmount();app=undefined;finish({id:'p',node:'node-a',kind:'prepare',status:'succeeded',phase:'complete',result:{preview}});await settle()
 expect(job).not.toHaveBeenCalled()
})
it('links an unfinished original task before starting another preparation', async () => {
 const { client, instance, job } = await mount()
 vi.mocked(client.deployments).mockResolvedValue({items:[{id:'original-job',node:'node-a',status:'interrupted'} as never],next_cursor:'',limit:20})
 const prepare=vi.spyOn(client,'prepareDeployment')
 await instance.begin();await settle()
 expect(prepare).not.toHaveBeenCalled();expect(host.textContent).toContain('存在未完成部署')
 button('打开未完成任务').click();expect(job).toHaveBeenCalledWith('original-job')
})
it('retains the idempotency key after a lost response but renews it after a terminal failed preparation', async () => {
 const client = new ControlV3()
 vi.spyOn(client,'sshCredential').mockResolvedValue({configured:true,version:2,ssh_port:22,fingerprint:'fp'})
 const prepare=vi.spyOn(client,'prepareDeployment').mockRejectedValueOnce(new Error('network lost')).mockResolvedValue({id:'failed',node:'node-a',kind:'prepare',status:'queued',phase:'queued'})
 vi.spyOn(client,'deploymentPreparation').mockResolvedValue({id:'failed',node:'node-a',kind:'prepare',status:'failed',phase:'failed',error_code:'preparation_failed'})
 const {instance}=await mount(client)
 await instance.begin();await instance.begin();await instance.begin()
 expect(prepare.mock.calls[0]?.[3]).toBe(prepare.mock.calls[1]?.[3])
 expect(prepare.mock.calls[2]?.[3]).not.toBe(prepare.mock.calls[1]?.[3])
})
it('waits for a pending private-file read before submitting any request', async () => {
 const {instance,client}=await mount()
 const check=vi.spyOn(client,'sshCredential')
 let finish!:(value:string)=>void
 const input=host.querySelector('input[type=file]') as HTMLInputElement
 Object.defineProperty(input,'files',{configurable:true,value:[{size:10,text:()=>new Promise<string>(r=>{finish=r})}]})
 input.dispatchEvent(new Event('change'));await settle();await instance.begin()
 expect(check).not.toHaveBeenCalled();expect(host.textContent).toContain('正在读取私钥文件')
 finish('latest');await settle();expect((host.querySelector('textarea') as HTMLTextAreaElement).value).toBe('latest')
})
it('checks a user-edited SSH port without replacing it from saved credentials', async () => {
 const client=new ControlV3()
 vi.spyOn(client,'sshCredential').mockResolvedValue({configured:true,version:2,ssh_port:555,fingerprint:'fp'})
 const fp=vi.spyOn(client,'sshFingerprint').mockResolvedValue({id:'pin',node:'node-a',kind:'fingerprint',status:'queued',phase:'queued'})
 vi.spyOn(client,'deploymentPreparation').mockResolvedValue({id:'pin',node:'node-a',kind:'fingerprint',status:'succeeded',phase:'complete',result:{host:'192.0.2.1',port:2222,fingerprint:'fp',fingerprint_token:'c'.repeat(64)}})
 const {instance}=await mount(client)
 const input=host.querySelector('input[role=spinbutton]') as HTMLInputElement
 input.value='2222';input.dispatchEvent(new Event('input'));input.dispatchEvent(new Event('change'));await settle()
 await instance.begin();expect(fp.mock.calls[0]?.[2]).toBe(2222)
})
