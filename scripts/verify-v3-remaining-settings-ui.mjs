// Remaining-settings UI fixture only: synthetic configuration, backups and
// workers. Loopback only; no proxy, database, notification or remote service.
import { createServer } from '../web/node_modules/vite/dist/node/index.js'
import vue from '../web/node_modules/@vitejs/plugin-vue/dist/index.mjs'
import { mkdir,writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),evidence=path.join(root,'.cache/verification/v3/feature-migration-20261101')
await mkdir(evidence,{recursive:true})
const requests=[],previews=new Map(),idempotency=new Map(),stamp=()=>new Date().toISOString()
const fields=[{path:'collector.interval_seconds',label:'主控拉取指标间隔（秒）',kind:'integer',min:10,max:3600},{path:'monitoring.interval_seconds',label:'告警判定参考间隔（秒）',kind:'integer',min:10,max:3600},{path:'backup.enabled',label:'自动完整备份',kind:'bool'},{path:'backup.time',label:'每天备份时间（HH:MM）',kind:'text',max:5},{path:'backup.timezone',label:'备份时区（IANA，未指定为 UTC）',kind:'text',max:128},{path:'backup.keep_days',label:'完整备份保留天数',kind:'integer',min:1,max:3650}]
fields.push({path:'monitoring.raw_hours',label:'原始指标保留小时',kind:'integer',min:24,max:168},{path:'monitoring.history_days',label:'指标历史保留天数',kind:'integer',min:1,max:90})
const metrics_retention={configured:true,available:true,status:{state:'confirmed',observed_at:stamp(),effective:{raw_hours:48,history_days:15,settings_version:7}}}
let values={'collector.interval_seconds':30,'monitoring.interval_seconds':60,'monitoring.raw_hours':48,'monitoring.history_days':15},runtime=structuredClone(values),generation=4,applied=4,version=8,sequence=0
const state=()=>({generation:String(generation),applied_generation:String(applied),runtime_version:version,pending:generation!==applied,updated_at:stamp()})
const server=await createServer({configFile:false,root:path.join(root,'web'),cacheDir:path.join(evidence,'remaining-settings-vite-cache'),plugins:[{name:'synthetic-remaining-settings',configureServer(vite){vite.middlewares.use(async(req,res,next)=>{
 const url=new URL(req.url,'http://127.0.0.1'),p=url.pathname
 if(!p.startsWith('/api/')){if(!p.includes('.')&&!p.startsWith('/@')&&!p.startsWith('/node_modules')&&!p.startsWith('/src/'))req.url='/v3.html';return next()}
 const entry={method:req.method,path:p,at:stamp()};requests.push(entry)
 const send=(value,status=200)=>{entry.status=status;res.statusCode=status;res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');res.end(JSON.stringify(value))}
 const invalid=()=>send({code:'invalid_synthetic_settings',message:'合成设置校验失败'},400),conflict=()=>send({code:'settings_conflict',message:'合成预览已失效，请重新读取'},409)
 if(!p.startsWith('/api/v3/'))return send({code:'legacy_forbidden',message:'仅允许 v3'},409)
 if(p==='/api/v3/session'&&req.method==='GET')return send({username:'synthetic-admin',role:'admin',csrf:'remaining-settings-csrf'})
 if(p==='/api/v3/capabilities'&&req.method==='GET')return send({api_version:3,topology:'single',features:[],settings:{available:true,reason:''},implementation_stage:'synthetic-settings'})
 if(p==='/api/v3/settings'&&req.method==='GET')return send({state:state(),fields,values,runtime_values:runtime,secret_configured:{},runtime_secret_configured:{},metrics_retention})
 if(p==='/api/v3/monitoring/rules'&&req.method==='GET')return send({version:'1',rules:{roots:['/synthetic'],extensions:['.php'],important_filenames:[],critical_paths:[],exclude_paths:[],reconciliation_interval_hours:6},updated_at:stamp()})
 if(!['/api/v3/settings/preview','/api/v3/settings/confirm'].includes(p)||req.method!=='POST')return send({code:'fixture_endpoint_missing',message:'此隔离夹具未开放该接口'},404)
 if(req.headers['x-csrf-token']!=='remaining-settings-csrf')return send({code:'csrf_invalid',message:'合成 CSRF 校验失败'},403)
 let raw='';for await(const chunk of req){raw+=chunk;if(raw.length>65536)return invalid()}
 let input;try{input=JSON.parse(raw)}catch{return invalid()}
 entry.action=input.action;entry.changed_paths=Object.keys(input.edit?.values||{});entry.runtime_before=structuredClone(runtime)
 if(!['save','apply'].includes(input.action)||input.expected_generation!==String(generation)||input.expected_runtime_version!==version)return conflict()
 if(p.endsWith('/preview')){
  const edit=input.edit?.values||{},allowed=new Map(fields.map(f=>[f.path,f]));if(Object.keys(input.edit?.secrets||{}).length||Object.keys(edit).some(key=>!allowed.has(key)))return invalid()
  for(const[key,value]of Object.entries(edit)){const f=allowed.get(key);if(f.kind==='integer'&&(!Number.isSafeInteger(value)||value<f.min||value>f.max)||f.kind==='bool'&&typeof value!=='boolean')return invalid();if(key==='backup.time'&&!/^([01]\d|2[0-3]):[0-5]\d$/.test(value))return invalid();if(key==='backup.timezone'){try{if(!value||value==='Local')throw Error();new Intl.DateTimeFormat('en',{timeZone:value})}catch{return invalid()}}}
  const changed_fields=input.action==='apply'?Object.keys(values).filter(key=>values[key]!==runtime[key]):Object.keys(edit).filter(key=>values[key]!==edit[key]),token=`synthetic-settings-${++sequence}`,result={token,action:input.action,changed_fields,expires_at:new Date(Date.now()+600000).toISOString(),retention_shortened:false,notifications_enabled:false};previews.set(token,{input,result});return send(result)
 }
 if(!req.headers['idempotency-key'])return invalid();if(idempotency.has(req.headers['idempotency-key']))return send(idempotency.get(req.headers['idempotency-key']))
 const preview=previews.get(input.preview);if(!preview||JSON.stringify({...input,preview:undefined})!==JSON.stringify({...preview.input,preview:undefined})||Date.parse(preview.result.expires_at)<=Date.now())return conflict()
 if(input.action==='save'){values={...values,...input.edit.values};generation++}else{runtime=structuredClone(values);applied=generation;version++}
 entry.runtime_after=structuredClone(runtime);const result=state();idempotency.set(req.headers['idempotency-key'],result);return send(result)
})}},vue()],server:{host:'127.0.0.1',port:Number(process.env.WEBSCAN_SETTINGS_UI_PORT||61951),strictPort:true,fs:{allow:[root]}},logLevel:'warn'})
await server.listen()
const flush=()=>writeFile(path.join(evidence,'phase4-retention-browser-requests.json'),JSON.stringify(requests,null,2)),timer=setInterval(flush,1000)
for(const signal of['SIGINT','SIGTERM'])process.on(signal,async()=>{clearInterval(timer);await flush();await server.close();process.exit()})
console.log(`Synthetic settings: http://127.0.0.1:${process.env.WEBSCAN_SETTINGS_UI_PORT||61951}/settings?tab=runtime&group=metrics`)
