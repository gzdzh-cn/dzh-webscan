import { afterEach, expect, it, vi } from 'vitest'
import { preflightController } from './preflight'
import { api } from './api'
vi.mock('./api',()=>({api:vi.fn()}))
afterEach(()=>{vi.mocked(api).mockReset();vi.useRealTimers()})
it('polls progress and completes without creating a deployment',async()=>{
 vi.useFakeTimers();vi.mocked(api).mockResolvedValueOnce({id:'report'}).mockResolvedValueOnce({id:'report',status:'running',report:{items:[{name:'SSH'}]}}).mockResolvedValueOnce({id:'report',status:'complete',report:{ok:true,items:[]}})
 const update=vi.fn(),controller=preflightController(),done=controller.run({revision:'r'},update);await vi.advanceTimersByTimeAsync(750);expect((await done)?.report.ok).toBe(true)
 expect(update).toHaveBeenCalledTimes(2);expect(vi.mocked(api).mock.calls.every(c=>!c[0].includes('deployments'))).toBe(true);expect(vi.mocked(api).mock.calls[0]?.[2]).toMatchObject({active:true,async:true})
})
it('closing cancels a pending check and ignores late responses',async()=>{
 let resolve!:(value:unknown)=>void;vi.mocked(api).mockImplementationOnce(()=>new Promise(r=>{resolve=r})).mockResolvedValue({})
 const update=vi.fn(),controller=preflightController(),done=controller.run({},update);controller.cancel();resolve({id:'late'});await done
 expect(update).not.toHaveBeenCalled();expect(vi.mocked(api).mock.calls.at(-1)).toEqual(['/api/servers/preflight/late','DELETE'])
})
it('manual inspection preserves read-only mode',async()=>{
 vi.mocked(api).mockResolvedValueOnce({id:'r'}).mockResolvedValueOnce({id:'r',status:'complete',report:{ok:true,items:[]}})
 await preflightController().run({active:false},vi.fn());expect(vi.mocked(api).mock.calls[0]?.[2]).toMatchObject({active:false})
})
