// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { installElements } from '../elements'
import { ControlV3, type V3DeviceTrends, type V3MetricDevice, type V3MetricDeviceList } from '../controlV3'
import { consoleContext } from './context'
import DeviceTrends from './DeviceTrends.vue'
vi.mock('../MetricChart.vue',()=>({default:{props:['title','option'],template:'<pre class="chart-fixture" :data-title="title">{{JSON.stringify(option)}}</pre>'}}))
let app:App|undefined,host:HTMLDivElement
const start='2026-11-01T00:00:00Z',end='2026-11-01T01:00:00Z',startSeconds=Date.parse(start)/1000
const devices=():V3MetricDevice[]=>[...Array.from({length:9},(_,i)=>({id:`disk-${i}`,kind:'disk' as const,name:`sda${i}`,last_seen:startSeconds})),{id:'network-1',kind:'network',name:'eth0',last_seen:null}]
const inventory=(items=devices()):V3MetricDeviceList=>({start:startSeconds,end:Date.parse(end)/1000,items,truncated:false})
const history=(ids=['disk-0']):V3DeviceTrends=>({start:startSeconds,end:Date.parse(end)/1000,resolution_seconds:30,devices:devices().filter(d=>ids.includes(d.id)),series:ids.map(id=>({key:`${id}:disk_read`,device_id:id,metric:'disk_read',unit:'bytes/s'})),points:[{time:startSeconds,ok:true,values:Object.fromEntries(ids.map(id=>[`${id}:disk_read`,1024]))},{time:startSeconds+30,ok:false,values:{}},{time:startSeconds+60,ok:true,values:{}},{time:startSeconds+90,ok:true,values:Object.fromEntries(ids.map(id=>[`${id}:disk_read`,2048]))}]})
async function settle(){for(let i=0;i<30;i++){await Promise.resolve();await nextTick()}}
async function mount(client:ControlV3){const node=ref('node-a'),rangeEnd=ref(end);host=document.createElement('div');document.body.append(host);app=createApp({components:{DeviceTrends},setup:()=>({node,rangeEnd,start}),template:'<DeviceTrends ref="device" :node="node" :start="start" :end="rangeEnd" />'});installElements(app);app.provide(consoleContext,{client,session:ref({username:'fixture',role:'viewer' as const,csrf:'csrf'})});const root=app.mount(host) as unknown as {$refs:{device:{selectDevices(kind:'disk'|'network',ids:string[]):void}}};await settle();return{node,rangeEnd,select:root.$refs.device.selectDevices}}
function button(text:string){return Array.from(document.body.querySelectorAll('button')).find(e=>e.textContent?.trim()===text)!}
beforeEach(()=>Object.defineProperty(document,'hidden',{configurable:true,value:false}))
afterEach(()=>{app?.unmount();app=undefined;host?.remove();document.querySelectorAll('.el-popper').forEach(e=>e.remove());vi.restoreAllMocks();vi.useRealTimers()})
it('loads server inventory and queries only explicitly selected device IDs for read-only users',async()=>{
 const client=new ControlV3(),list=vi.spyOn(client,'metricDevices').mockResolvedValue(inventory()),read=vi.spyOn(client,'deviceMetrics').mockResolvedValue(history());const{select}=await mount(client);expect(list.mock.calls[0]?.slice(0,3)).toEqual(['node-a',start,end]);expect(read).not.toHaveBeenCalled();expect(host.textContent).toContain('从本版启用后开始记录');select('disk',['disk-0']);await settle();expect(read.mock.calls[0]?.slice(0,4)).toEqual(['node-a',['disk-0'],start,end]);expect(host.textContent).toContain('当前设备：sda0');expect(host.querySelector('.chart-fixture')).toBeTruthy()
})
it('keeps restart, missing samples and reset gaps as null and uses exact server metadata keys',async()=>{
 const client=new ControlV3();vi.spyOn(client,'metricDevices').mockResolvedValue(inventory());vi.spyOn(client,'deviceMetrics').mockResolvedValue(history());const{select}=await mount(client);select('disk',['disk-0']);await settle();const chart=JSON.parse(host.querySelector('.chart-fixture')!.textContent!);expect(chart.series[0].data.map((p:unknown[])=>p[1])).toEqual([1024,null,null,2048]);expect(chart.series[0].connectNulls).toBe(false);expect(chart.series[0].name).toBe('sda0 · 读取')
})
it('enforces the combined eight-device limit and rejects IDs outside server inventory',async()=>{
 const client=new ControlV3();vi.spyOn(client,'metricDevices').mockResolvedValue(inventory());const read=vi.spyOn(client,'deviceMetrics').mockImplementation(async(_node,ids)=>history(ids));const{select}=await mount(client);select('disk',devices().filter(d=>d.kind==='disk').slice(0,8).map(d=>d.id));await settle();expect(read.mock.calls[0]?.[1]).toHaveLength(8);select('network',['network-1']);await settle();expect(read).toHaveBeenCalledTimes(1);expect(host.textContent).toContain('合计最多选择 8 个');select('disk',['forged-metric{secret="x"}']);await settle();expect(read).toHaveBeenCalledTimes(1);expect(host.textContent).toContain('已选 8 / 8')
})
it('cancels old node requests and ignores a late response after switching node',async()=>{
 const client=new ControlV3();vi.spyOn(client,'metricDevices').mockResolvedValue(inventory());let complete:(value:V3DeviceTrends)=>void=()=>{};const read=vi.spyOn(client,'deviceMetrics').mockImplementationOnce(()=>new Promise(resolve=>{complete=resolve}));const{select,node}=await mount(client);select('disk',['disk-0']);await settle();node.value='node-b';await settle();expect(read.mock.calls[0]?.[4]?.aborted).toBe(true);complete(history());await settle();expect(host.textContent).not.toContain('当前设备：sda0');expect(host.querySelector('.chart-fixture')).toBeNull()
})
it('preserves selected historical device labels while skipping devices absent from the selected time inventory',async()=>{
 const client=new ControlV3(),list=vi.spyOn(client,'metricDevices').mockResolvedValueOnce(inventory()).mockResolvedValue(inventory([])),read=vi.spyOn(client,'deviceMetrics').mockResolvedValue(history());const{select,rangeEnd}=await mount(client);select('disk',['disk-0']);await settle();rangeEnd.value='2026-11-01T02:00:00Z';await settle();expect(list).toHaveBeenCalledTimes(2);expect(read).toHaveBeenCalledTimes(1);expect(host.textContent).toContain('所选时段未发现：sda0');expect(host.textContent).toContain('保留选择，不查询这些设备，也不填零');expect(host.querySelector('.chart-fixture')).toBeNull()
})
it('retains previous charts after an outage and pauses active reads in a hidden tab',async()=>{
 const client=new ControlV3();vi.spyOn(client,'metricDevices').mockResolvedValue(inventory());const read=vi.spyOn(client,'deviceMetrics').mockResolvedValueOnce(history()).mockRejectedValue(new Error('503 时序库暂时不可用'));const{select}=await mount(client);select('disk',['disk-0']);await settle();button('刷新设备历史').click();await settle();expect(host.textContent).toContain('503 时序库暂时不可用');expect(host.querySelector('.chart-fixture')).toBeTruthy();Object.defineProperty(document,'hidden',{configurable:true,value:true});document.dispatchEvent(new Event('visibilitychange'));expect(read.mock.calls.at(-1)?.[4]?.aborted).toBe(true);button('刷新设备历史').click();await settle();expect(read).toHaveBeenCalledTimes(2)
})
it('shows truncated and empty inventory honestly and rejects oversized history responses',async()=>{
 const client=new ControlV3();vi.spyOn(client,'metricDevices').mockResolvedValue({...inventory(),truncated:true});vi.spyOn(client,'deviceMetrics').mockResolvedValue({...history(),series:Array.from({length:65},()=>history().series[0]!)});const{select}=await mount(client);expect(host.textContent).toContain('设备清单已截断');select('disk',['disk-0']);await settle();expect(host.textContent).toContain('超过限制');expect(host.querySelector('.chart-fixture')).toBeNull()
})
