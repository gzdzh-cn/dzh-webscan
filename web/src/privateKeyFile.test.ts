import { expect, it, vi } from 'vitest'
import { privateKeyFileReader, maxPrivateKeyBytes } from './privateKeyFile'
function file(text:string,size=text.length){return {size,text:async()=>text} as File}
it('reads complete content and rejects empty, multiple, oversized and failed files without accepting them',async()=>{
 const accept=vi.fn(),fail=vi.fn(),reader=privateKeyFileReader(accept,fail,vi.fn())
 const text='-----BEGIN PRIVATE KEY-----\r\nfixture\r\n-----END PRIVATE KEY-----\r\n';await reader.read([file(text)]);expect(accept).toHaveBeenLastCalledWith(text)
 for(const files of [[],[file('a'),file('b')],[file('')],[file('  ')],[file('a',maxPrivateKeyBytes+1)],[{size:1,text:async()=>{throw new Error('fixture')}} as unknown as File]])await reader.read(files)
 expect(accept).toHaveBeenCalledTimes(1);expect(fail.mock.calls.map(v=>v[0])).toEqual(['每次请选择一个私钥文件','每次请选择一个私钥文件','私钥文件内容为空','私钥文件内容为空','私钥文件不能超过 64 KiB','读取私钥文件失败，请重新选择或直接粘贴内容'])
})
it('only the latest selection completes and cancellation ignores late success and failure',async()=>{
 const accept=vi.fn(),fail=vi.fn(),loading=vi.fn(),reader=privateKeyFileReader(accept,fail,loading)
 let finish:(v:string)=>void=()=>{},reject:(e:Error)=>void=()=>{}
 const old=reader.read([{size:1,text:()=>new Promise<string>(resolve=>{finish=resolve})} as File]);await reader.read([file('new')]);finish('old');await old;expect(accept.mock.calls).toEqual([['new']])
 const closing=reader.read([{size:1,text:()=>new Promise<string>((_,r)=>{reject=r})} as File]);reader.cancel();reject(new Error('fixture'));await closing;expect(fail).not.toHaveBeenCalled();expect(loading).toHaveBeenLastCalledWith(false)
})
