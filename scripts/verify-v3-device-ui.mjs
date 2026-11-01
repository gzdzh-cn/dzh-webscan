// Stage-four responsive UI verification only. Synthetic data; no proxy,
// production database, VM query, remote node or notification provider.
import { createServer } from '../web/node_modules/vite/dist/node/index.js'
import vue from '../web/node_modules/@vitejs/plugin-vue/dist/index.mjs'
import { mkdir,writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),evidence=path.join(root,'.cache/verification/v3/feature-migration-20261101')
await mkdir(evidence,{recursive:true})
const requests=[],stamp=()=>new Date().toISOString(),devices=[...Array.from({length:7},(_,i)=>({id:`synthetic-disk-${i}`,kind:'disk',name:i===6?'nvme-super-long-device-name-for-mobile-validation':`nvme${i}n1`,last_seen:null})),...Array.from({length:3},(_,i)=>({id:`synthetic-network-${i}`,kind:'network',name:`eth${i}`,last_seen:null}))]
const node=id=>({id,name:id==='node-b'?'设备历史节点B':'设备历史验收节点',endpoint:'192.0.2.30:19100',server_name:'synthetic',enabled:true,mode:'docker',version:2,applied_version:2,shard:0,configuration:{registered_version:2,delivered_version:2,runtime_enabled:true,runtime_mode:'docker',runtime_endpoint:'192.0.2.30:19100'},lifecycle:'installed'})
const metrics={cpu_percent:18,memory_percent:42,disk_percent:36,cpu_cores:4,uptime:86400,memory_total:8*1024**3,disk_read:12000,disk_write:6000,net_receive:18000,net_transmit:5000,'disk_percent:/':36,'inode_percent:/':8}
const history=(url,selected)=>{
 const start=Math.floor(Date.parse(url.searchParams.get('start'))/1000),end=Math.floor(Date.parse(url.searchParams.get('end'))/1000),resolution=Math.max(30,Math.ceil((end-start)/60))
 const series=selected.flatMap(device=>(device.kind==='disk'?['disk_read','disk_write','disk_read_iops','disk_write_iops']:['net_receive','net_transmit','net_receive_errors','net_transmit_errors','net_receive_drops','net_transmit_drops']).map(metric=>({key:`${device.id}:${metric}`,device_id:device.id,metric,unit:metric.endsWith('iops')?'operations/s':metric.includes('errors')||metric.includes('drops')?'packets/s':'bytes/s'})))
 return{start,end,resolution_seconds:resolution,devices:selected,series,points:Array.from({length:61},(_,i)=>{const time=Math.min(end,start+i*resolution),ok=i!==20&&i!==21&&i!==40;return{time,ok,values:ok?selected.length?Object.fromEntries(series.filter(s=>!(i===41&&s.metric==='disk_read')).map((s,index)=>[s.key,s.metric.includes('errors')||s.metric.includes('drops')?(i%7)/10:s.metric.endsWith('iops')?10+Math.sin(i/4)*2:12000+(index+1)*3000+Math.sin(i/5)*3000])):{...metrics,memory_used:3.4*1024**3,memory_available:4.6*1024**3,swap_percent:0,load1:.4,load5:.3,load15:.2}:{} }})}
}
const server=await createServer({configFile:false,root:path.join(root,'web'),cacheDir:path.join(evidence,'device-vite-cache'),plugins:[{name:'synthetic-devices',configureServer(vite){vite.middlewares.use(async(req,res,next)=>{
 const url=new URL(req.url,'http://127.0.0.1'),p=url.pathname
 if(!p.startsWith('/api/')){if(!p.includes('.')&&!p.startsWith('/@')&&!p.startsWith('/node_modules')&&!p.startsWith('/src/'))req.url='/v3.html';return next()}
 const entry={method:req.method,path:p,query:url.search,at:stamp()};requests.push(entry)
 const send=(value,status=200)=>{entry.status=status;res.statusCode=status;res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');res.end(JSON.stringify(value))}
 if(!p.startsWith('/api/v3/'))return send({code:'legacy_api_forbidden',message:'仅允许v3接口'},409)
 if(req.method!=='GET')return send({code:'read_only_fixture',message:'此合成夹具禁止写操作'},405)
 if(p==='/api/v3/session')return send({username:'synthetic-viewer',role:'viewer',csrf:'synthetic-device-csrf'})
 if(p==='/api/v3/capabilities')return send({api_version:3,topology:'single',features:[],implementation_stage:'synthetic-device-history'})
 if(p==='/api/v3/servers')return send({items:[node('node-a'),node('node-b')],next_cursor:'',limit:20})
 const match=p.match(/^\/api\/v3\/servers\/(node-a|node-b)(?:\/(metrics|metric-devices|device-metrics))?$/)
 if(match){const id=match[1],operation=match[2];if(!operation)return send({node:node(id),status:{sampled_at:Date.now(),updated_at:stamp(),error:'',metrics_error:'',events_error:'',protocol_error:'',metrics,info:{hostname:'synthetic-linux',kernel:'6.1.0',architecture:'amd64',agent_version:'synthetic',agent_mode:'docker'}},latest_deployment:null})
  const range=history(url,[])
  if(operation==='metrics')return send(range)
  if(operation==='metric-devices')return send({start:range.start,end:range.end,items:id==='node-b'?[]:devices.map(d=>({...d,last_seen:range.end})),truncated:false})
  const ids=url.searchParams.getAll('devices');if(ids.length>8||ids.length!==new Set(ids).size||ids.some(id=>!devices.some(d=>d.id===id)))return send({code:'invalid_devices',message:'合成设备不在清单或超过8个'},400)
  return send(history(url,devices.filter(d=>ids.includes(d.id))))
 }
 return send({code:'fixture_endpoint_missing',message:`合成夹具未配置 ${p}`},404)
})}},vue()],server:{host:'127.0.0.1',port:61949,strictPort:true,fs:{allow:[root]}},logLevel:'warn'})
await server.listen()
const flush=()=>writeFile(path.join(evidence,'phase4-browser-requests.json'),JSON.stringify(requests,null,2)),timer=setInterval(flush,1000)
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,async()=>{clearInterval(timer);await flush();await server.close();process.exit()})
console.log('Stage-four synthetic device UI: http://127.0.0.1:61949/servers/node-a ; node-b has an empty device inventory')
