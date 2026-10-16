// @vitest-environment jsdom
import {afterEach,beforeEach,expect,it,vi} from 'vitest'
import {api} from './api'
import {cancelReadRequests} from './connection'
beforeEach(()=>{vi.useFakeTimers();Object.defineProperty(document,'hidden',{configurable:true,value:false})})
afterEach(()=>{cancelReadRequests(true);vi.useRealTimers();vi.restoreAllMocks()})
const ok=(value:unknown)=>({ok:true,status:200,json:async()=>value})
it('502 reconnects after three seconds with the same URL, retains cursor and never logs out',async()=>{
 const expired=vi.fn();window.addEventListener('session-expired',expired)
 const fetcher=vi.fn().mockResolvedValueOnce({ok:false,status:502,json:async()=>({})}).mockResolvedValueOnce(ok({cursor:42}));vi.stubGlobal('fetch',fetcher)
 const result=api('/api/deployments/job?cursor=41');await vi.advanceTimersByTimeAsync(2999);expect(fetcher).toHaveBeenCalledTimes(1);await vi.advanceTimersByTimeAsync(1);expect(await result).toEqual({cursor:42});expect(fetcher.mock.calls.map(c=>c[0])).toEqual(['/api/deployments/job?cursor=41','/api/deployments/job?cursor=41']);expect(expired).not.toHaveBeenCalled();window.removeEventListener('session-expired',expired)
})
it('hidden tabs pause retries and returning schedules a single reconnect',async()=>{
 const fetcher=vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(ok({ok:true}));vi.stubGlobal('fetch',fetcher);const result=api('/api/session');await vi.advanceTimersByTimeAsync(1)
 Object.defineProperty(document,'hidden',{configurable:true,value:true});document.dispatchEvent(new Event('visibilitychange'));await vi.advanceTimersByTimeAsync(60000);expect(fetcher).toHaveBeenCalledTimes(1)
 Object.defineProperty(document,'hidden',{configurable:true,value:false});document.dispatchEvent(new Event('visibilitychange'));await vi.advanceTimersByTimeAsync(3000);expect(await result).toEqual({ok:true});expect(fetcher).toHaveBeenCalledTimes(2)
})
it('navigation and logout cancel retry timers',async()=>{
 const fetcher=vi.fn().mockRejectedValue(new Error('offline'));vi.stubGlobal('fetch',fetcher);const result=api('/api/servers');const rejected=expect(result).rejects.toMatchObject({name:'AbortError'});await vi.advanceTimersByTimeAsync(1);cancelReadRequests();await rejected;await vi.advanceTimersByTimeAsync(60000);expect(fetcher).toHaveBeenCalledTimes(1)
})
it('writes never replay, and database failures remain service errors',async()=>{
 const fetcher=vi.fn().mockResolvedValue({ok:false,status:503,json:async()=>({message:'服务暂不可用'})});vi.stubGlobal('fetch',fetcher);await expect(api('/api/deployments','POST',{})).rejects.toMatchObject({status:503});await vi.advanceTimersByTimeAsync(60000);expect(fetcher).toHaveBeenCalledTimes(1)
 fetcher.mockResolvedValue({ok:false,status:500,json:async()=>({message:'数据库暂不可用'})});await expect(api('/api/session')).rejects.toMatchObject({status:500})
})

it('initial navigation does not abort session discovery',async()=>{const fetcher=vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(ok({username:'fixture'}));vi.stubGlobal('fetch',fetcher);const result=api('/api/session');await vi.advanceTimersByTimeAsync(1);cancelReadRequests();await vi.advanceTimersByTimeAsync(3000);expect(await result).toEqual({username:'fixture'})})
