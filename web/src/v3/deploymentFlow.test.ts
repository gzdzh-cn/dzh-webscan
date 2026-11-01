// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, h, nextTick, ref, type App } from 'vue'
import { installElements } from '../elements'
import { ControlV3, type V3Preparation, type V3DeploymentPreview } from '../controlV3'
import { consoleContext } from './context'
import Flow from './DeploymentFlow.vue'
let app: App | undefined, host: HTMLDivElement
const preview: V3DeploymentPreview = { token: 'a'.repeat(64), node: 'node-a', kind: 'upgrade', version: 2, applied_version: 1, target: { release: 'v3.0.0', sha256: 'b'.repeat(64), mode: 'docker' }, comparison: 'newer', expires_at: '2026-10-30T12:00:00Z' }
async function settle() { for (let i = 0; i < 25; i++) { await Promise.resolve(); await nextTick() } }
function button(text: string) { const el = Array.from(host.querySelectorAll('button')).find(e => e.textContent?.trim() === text); if (!el) throw new Error('Missing '+text); return el }
async function mount(client = new ControlV3(), operation?: 'uninstall') {
 if (operation && !vi.isMockFunction(client.capabilities)) vi.spyOn(client, 'capabilities').mockResolvedValue({ api_version: 3, topology: 'single', features: [], implementation_stage: 'fixture', operations: { uninstall: { available: true, reason: '' } } })
 vi.spyOn(client, 'deployments').mockResolvedValue({ items: [], next_cursor: '', limit: 20 })
 host = document.createElement('div'); document.body.append(host)
 const job = vi.fn(), status = vi.fn()
 const node = ref({ id: 'node-a', version: 2, applied_version: 1, mode: 'docker' as const }), exposed = ref<{ begin: () => Promise<void> }>()
 app = createApp({ render: () => h(Flow, { ref: exposed, node: node.value, upgrade: !operation, operation, onJob: job, onStatus: status }) }); installElements(app)
 app.provide(consoleContext, { client, session: ref({ username: 'admin', role: 'admin' as const, csrf: 'fixture' }) })
 app.mount(host); await settle()
 return { instance: exposed.value!, job, status, client, node }
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

const installation = { job: 'original-installation', plan_digest: 'd'.repeat(64), release: 'v3.0.2', sha256: 'e'.repeat(64), mode: 'native' as const, endpoint: '192.0.2.17:19100', host: '192.0.2.17', ssh_port: 2222 }
it('threads uninstall through credential, fingerprint, credential replacement and fixed-installation preview', async () => {
 const client = new ControlV3()
 const read = vi.spyOn(client, 'sshCredential').mockResolvedValue({ configured: false, version: 2, ssh_port: 555, fingerprint: '', installation, can_uninstall: true })
 const fp = vi.spyOn(client, 'sshFingerprint').mockResolvedValue({ id: 'pin', node: 'node-a', kind: 'fingerprint', status: 'queued', phase: 'queued' })
 const save = vi.spyOn(client, 'saveSSHCredential').mockResolvedValue({ id: 'credential', node: 'node-a', kind: 'credential', status: 'queued', phase: 'queued' })
 const prepare = vi.spyOn(client, 'prepareDeployment').mockResolvedValue({ id: 'uninstall', node: 'node-a', kind: 'prepare', status: 'queued', phase: 'queued' })
 vi.spyOn(client, 'deploymentPreparation').mockImplementation(async id => ({ id, node: 'node-a', kind: id === 'pin' ? 'fingerprint' : id === 'credential' ? 'credential' : 'prepare', phase: 'complete', status: 'succeeded', result: id === 'pin' ? { host: installation.host, port: 2222, fingerprint: 'SHA256:source', fingerprint_token: 'f'.repeat(64) } : id === 'uninstall' ? { preview: { ...preview, kind: 'uninstall', target: { release: installation.release, sha256: installation.sha256, mode: installation.mode } } } : {} }))
 const { instance } = await mount(client, 'uninstall')
 const input = host.querySelector('textarea') as HTMLTextAreaElement; input.value = 'replacement private key'; input.dispatchEvent(new Event('input')); await settle()
 await instance.begin(); await settle()
 expect(read.mock.calls[0]?.[2]).toBe('uninstall')
 expect(fp.mock.calls[0]?.slice(0, 3)).toEqual(['node-a', 2, 2222]); expect(fp.mock.calls[0]?.[4]).toBe('uninstall')
 expect((host.querySelector('input[role=spinbutton]') as HTMLInputElement).disabled).toBe(true)
 expect(host.textContent).toContain('192.0.2.17:2222'); expect(host.textContent).toContain('native · v3.0.2')
 button('确认指纹并准备卸载').click(); await settle()
 expect(save.mock.calls[0]?.[1]).toMatchObject({ kind: 'uninstall', ssh_port: 2222, private_key_content: 'replacement private key' })
 expect(prepare.mock.calls[0]?.slice(0, 3)).toEqual(['node-a', 2, 'uninstall'])
 expect(host.textContent).toContain('卸载预览'); expect(host.textContent).toContain('不会清空子控数据')
})
it('blocks uninstall with missing or unavailable installation evidence instead of using saved metadata', async () => {
 const client = new ControlV3()
 vi.spyOn(client, 'sshCredential').mockResolvedValue({ configured: true, version: 2, ssh_port: 555, fingerprint: 'fp', can_uninstall: false, reason: '实际安装身份无法确认' })
 const prepare = vi.spyOn(client, 'prepareDeployment'), fp = vi.spyOn(client, 'sshFingerprint')
 const { instance } = await mount(client, 'uninstall'); await instance.begin(); await settle()
 expect(host.textContent).toContain('实际安装身份无法确认'); expect(prepare).not.toHaveBeenCalled(); expect(fp).not.toHaveBeenCalled()
})

it('invalidates preparations on saved-version changes while preserving SSH input for Save and Deploy', async () => {
 const client = new ControlV3()
 vi.spyOn(client, 'sshCredential').mockResolvedValue({ configured: true, version: 2, ssh_port: 22, fingerprint: 'fp' })
 vi.spyOn(client, 'prepareDeployment').mockResolvedValue({ id: 'old', node: 'node-a', kind: 'prepare', status: 'queued', phase: 'queued' })
 let finish!: (value: V3Preparation) => void
 vi.spyOn(client, 'deploymentPreparation').mockImplementation(() => new Promise(resolve => { finish = resolve }))
 const { instance, node } = await mount(client)
 const pending = instance.begin(); await settle()
 const input = host.querySelector('textarea') as HTMLTextAreaElement; input.value = 'keep saved draft credential'; input.dispatchEvent(new Event('input')); await settle()
 node.value = { ...node.value, version: 3 }; await settle()
 finish({ id: 'old', node: 'node-a', kind: 'prepare', status: 'succeeded', phase: 'complete', result: { preview } }); await pending; await settle()
 expect(host.textContent).not.toContain('升级预览'); expect((host.querySelector('textarea') as HTMLTextAreaElement).value).toBe('keep saved draft credential')
})
it('rejects a mismatched operation preview instead of presenting an install as an uninstall', async () => {
 const client = new ControlV3()
 vi.spyOn(client, 'sshCredential').mockResolvedValue({ configured: true, version: 2, ssh_port: 2222, fingerprint: 'fp', installation, can_uninstall: true })
 vi.spyOn(client, 'prepareDeployment').mockResolvedValue({ id: 'wrong', node: 'node-a', kind: 'prepare', status: 'queued', phase: 'queued' })
 vi.spyOn(client, 'deploymentPreparation').mockResolvedValue({ id: 'wrong', node: 'node-a', kind: 'prepare', status: 'succeeded', phase: 'complete', result: { preview } })
 const { instance } = await mount(client, 'uninstall'); await instance.begin(); await settle()
 expect(host.textContent).toContain('预览操作类型不符'); expect(host.querySelector('.v3-deploy-confirm')).toBeNull()
})

it('uses uninstall readiness even when the ordinary issuer and rule preparation are unavailable', async () => {
 const client = new ControlV3()
 vi.spyOn(client, 'capabilities').mockResolvedValue({ api_version: 3, topology: 'single', features: [], implementation_stage: 'fixture', deployments: { available: false, reason: '签发器及规则未就绪' }, executor: { available: false, reason: '普通部署不可用' }, operations: { uninstall: { available: true, reason: '' } } })
 vi.spyOn(client, 'sshCredential').mockResolvedValue({ configured: true, version: 2, ssh_port: 2222, fingerprint: 'fp', installation, can_uninstall: true })
 const prepare = vi.spyOn(client, 'prepareDeployment').mockResolvedValue({ id: 'uninstall', node: 'node-a', kind: 'prepare', phase: 'queued', status: 'queued' })
 vi.spyOn(client, 'deploymentPreparation').mockResolvedValue({ id: 'uninstall', node: 'node-a', kind: 'prepare', phase: 'preparing-uninstall', status: 'succeeded', result: { preview: { ...preview, kind: 'uninstall' } } })
 const { instance } = await mount(client, 'uninstall'); await instance.begin(); await settle()
 expect(prepare.mock.calls[0]?.[2]).toBe('uninstall'); expect(host.textContent).toContain('卸载预览已就绪'); expect(host.textContent).not.toContain('签发器及规则未就绪')
})
it('keeps unknown or unavailable uninstall readiness separate from ordinary deployment availability', async () => {
 const client = new ControlV3(), credential = vi.spyOn(client, 'sshCredential'), prepare = vi.spyOn(client, 'prepareDeployment')
 const capability = vi.spyOn(client, 'capabilities').mockResolvedValueOnce({ api_version: 3, topology: 'single', features: [], implementation_stage: 'fixture', deployments: { available: true, reason: '' } }).mockResolvedValue({ api_version: 3, topology: 'single', features: [], implementation_stage: 'fixture', operations: { uninstall: { available: false, reason: '卸载执行器没有心跳' } } })
 const { instance } = await mount(client, 'uninstall'); await instance.begin(); await settle()
 expect(host.textContent).toContain('未提供独立卸载能力'); expect(credential).not.toHaveBeenCalled(); expect(prepare).not.toHaveBeenCalled()
 await instance.begin(); await settle(); expect(capability).toHaveBeenCalledTimes(2); expect(host.textContent).toContain('卸载执行器没有心跳'); expect(credential).not.toHaveBeenCalled()
})
