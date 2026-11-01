// Stage-three UI only: all data and notification delivery are synthetic.
// This server listens on loopback and has no proxy, remote node or provider.
import { createServer } from '../web/node_modules/vite/dist/node/index.js'
import vue from '../web/node_modules/@vitejs/plugin-vue/dist/index.mjs'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..')
const evidence=path.join(root,'.cache/verification/v3/feature-migration-20261101')
await mkdir(evidence,{recursive:true})
const requests=[],previews=new Map(),jobs=new Map(),idempotency=new Map()
const stamp=()=>new Date().toISOString(),page=items=>({items,next_cursor:''})
const rows=['email','feishu'].flatMap(channel=>Array.from({length:3},(_,index)=>({id:`${channel}-${index+1}`,node:'node-a',event_id:`event-${index+1}`,channel,recipient:channel==='email'?'applied@example.test':'已应用飞书机器人',created_at:stamp(),done_at:index===1?stamp():null,attempts:2,state:index===1?'completed':'retrying',source:['event','test','legacy'][index],subject:['网站文件变更安全提醒','固定测试通知','旧版通知记录'][index],summary:'受控业务摘要，不包含凭据。',content_state:index===2?'unsupported':'available',content_reason:index===2?'旧版记录未提供安全正文。':'',truncated:index===0,record_key:`${channel}:${index+1}`,can_delete:false,delete_reason:'最近 24 小时保护'})))
let sequence=0
const fields=[{path:'email.enabled',label:'邮箱通知',kind:'bool'},{path:'email.host',label:'SMTP 主机',kind:'text'},{path:'email.to',label:'收件邮箱',kind:'addresses',max:20},{path:'feishu.enabled',label:'飞书通知',kind:'bool'}]
const values={'email.enabled':true,'email.host':'saved.example.test','email.to':['saved@example.test'],'feishu.enabled':true}
const runtime={...values,'email.host':'applied.example.test','email.to':['applied@example.test']}
const server=await createServer({configFile:false,root:path.join(root,'web'),cacheDir:path.join(evidence,'notification-vite-cache'),plugins:[{name:'synthetic-notifications',configureServer(vite){vite.middlewares.use(async(req,res,next)=>{
 const url=new URL(req.url,'http://127.0.0.1'),p=url.pathname
 if(!p.startsWith('/api/')){if(!p.includes('.')&&!p.startsWith('/@')&&!p.startsWith('/node_modules')&&!p.startsWith('/src/'))req.url='/v3.html';return next()}
 const entry={method:req.method,path:p,query:url.search,at:stamp()};requests.push(entry)
 const send=(value,status=200)=>{entry.status=status;res.statusCode=status;res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');res.end(JSON.stringify(value))}
 const invalid=()=>send({code:'synthetic_invalid',message:'合成请求不符合冻结契约'},400)
 let input;const body=async()=>{if(input===undefined){let text='';for await(const chunk of req){text+=chunk;if(text.length>65536)throw Error('large request')}input=JSON.parse(text||'{}');entry.body=structuredClone(input);entry.idempotency_key=req.headers['idempotency-key']}return input}
 if(!p.startsWith('/api/v3/'))return send({code:'legacy_api_forbidden',message:'只允许v3接口'},409)
 if(p==='/api/v3/session')return send({username:'synthetic-admin',role:'admin',csrf:'notification-fixture-csrf'})
 if(p==='/api/v3/logout')return send({ok:true})
 if(p==='/api/v3/capabilities')return send({api_version:3,topology:'single',features:[],implementation_stage:'synthetic-notifications',notification_tests:{available:true,reason:''}})
 if(p==='/api/v3/servers')return send({...page([{id:'node-a',name:'通知验收节点',endpoint:'192.0.2.20:19100',server_name:'fixture',enabled:true,mode:'docker',version:1,applied_version:1,shard:0}]),limit:20})
 if(p==='/api/v3/settings'&&req.method==='GET')return send({state:{generation:'8',runtime_version:7,pending:true,updated_at:stamp()},fields,values,runtime_values:runtime,secret_configured:{'email.password':true,'feishu.webhook_url':true},runtime_secret_configured:{'email.password':true,'feishu.webhook_url':true}})
 if(p==='/api/v3/notifications/stats')return send({items:[{day:'2026-11-01',delivered:1,pending:1,retrying:1}]})
 if(p==='/api/v3/notifications'&&req.method==='GET'){
  let items=rows.filter(row=>row.channel===(url.searchParams.get('channel')||'email'))
  for(const key of ['node','recipient','source'])if(url.searchParams.get(key))items=items.filter(row=>row[key]===url.searchParams.get(key))
  if(url.searchParams.get('state'))items=items.filter(row=>(row.done_at?'completed':'pending')===url.searchParams.get('state'))
  if(url.searchParams.get('delivery_state'))items=items.filter(row=>row.state===url.searchParams.get('delivery_state'))
  if(url.searchParams.get('q'))items=items.filter(row=>(row.subject+row.summary).includes(url.searchParams.get('q')))
  return send({...page(items),start:'',end:''})
 }
 if(req.method==='POST'&&(!req.headers['idempotency-key']||req.headers['x-csrf-token']!=='notification-fixture-csrf'))return send({code:'csrf_invalid',message:'合成写入缺少CSRF或幂等键'},403)
 if(p==='/api/v3/notifications/test-preview'&&req.method==='POST'){
  const value=await body();if(Object.keys(value).sort().join(',')!=='channel,expected_runtime_version'||!['email','feishu'].includes(value.channel)||value.expected_runtime_version!==7)return invalid()
  const identity=`preview:${req.headers['idempotency-key']}`;if(idempotency.has(identity))return send(idempotency.get(identity))
  const result={token:`synthetic-preview-${++sequence}`,channel:value.channel,runtime_version:7,expires_at:new Date(Date.now()+600000).toISOString(),recipients:value.channel==='email'?['applied@example.test']:['已应用飞书机器人'],subject:'固定通知测试',body:'本次只使用已应用配置。\n<script>此内容仅作为纯文本展示</script>\n'+('长测试说明，用于验证手机正文滚动与底部操作可见。'.repeat(45))};previews.set(result.token,result);idempotency.set(identity,result);return send(result)
 }
 if(p==='/api/v3/notifications/tests'&&req.method==='POST'){
  const value=await body(),preview=previews.get(value.preview);if(Object.keys(value).sort().join(',')!=='confirm,preview'||value.confirm!==true||!preview)return invalid()
  const identity=`test:${req.headers['idempotency-key']}`;if(idempotency.has(identity))return send(idempotency.get(identity))
  const result={id:`synthetic-test-${++sequence}`,channel:preview.channel,runtime_version:7,status:'running',created_at:stamp(),updated_at:stamp(),finished_at:null,message:'合成测试任务已创建；未连接通知供应商。',items:[{ordinal:1,recipient:preview.recipients[0],state:'sending',outcome:'pending',message:'等待合成结果'}]};jobs.set(result.id,result);idempotency.set(identity,result);return send(result)
 }
 if(/^\/api\/v3\/notifications\/tests\//.test(p)&&req.method==='GET'){
  const result=jobs.get(p.split('/').pop());if(!result)return send({code:'not_found',message:'合成任务不存在'},404)
  result.status=result.channel==='feishu'?'unknown':'succeeded';result.updated_at=stamp();result.finished_at=stamp();result.message=result.channel==='feishu'?'合成响应丢失，结果未知，不会自动重发。':'合成通道已接受，不代表已读。';result.items[0].state=result.status==='unknown'?'unknown':'accepted';result.items[0].outcome=result.items[0].state;result.items[0].message=result.message;return send(result)
 }
 const match=p.match(/^\/api\/v3\/notifications\/([^/]+)(\/attempts)?$/)
 if(match&&req.method==='GET'){
  const row=rows.find(row=>row.id===match[1]);if(!row)return send({code:'not_found',message:'合成通知不存在'},404)
  if(match[2]){const second=!!url.searchParams.get('cursor');return send({items:[{id:second?'attempt-2':'attempt-1',epoch:second?'2':'1',success:second,outcome:second?'accepted':'unknown',message:second?'合成通道确认':'合成网络中断，结果未知',created_at:stamp()}],next_cursor:second?'':'attempt-next'})}
  return send({notification:row,body:'<img src=x onerror=alert(1)>\n这是受控业务摘要。\n'+('长路径 /srv/website/example/very-long-file-name.php\n'.repeat(38)),outcome:{code:row.done_at?'accepted':'unknown',message:'此为安全投影，不返回供应商原始响应。'}})
 }
 if(/\/alerts\/(current|history)$/.test(p)||p==='/api/v3/website-incidents')return send(page([]))
 return send({code:'fixture_endpoint_missing',message:`合成夹具未配置 ${p}`},404)
})}},vue()],server:{host:'127.0.0.1',port:61948,strictPort:true,fs:{allow:[root]}},logLevel:'warn'})
await server.listen()
const flush=()=>writeFile(path.join(evidence,'phase3-browser-requests.json'),JSON.stringify(requests,null,2))
const timer=setInterval(flush,1000)
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,async()=>{clearInterval(timer);await flush();await server.close();process.exit()})
console.log('Stage-three synthetic notification UI: http://127.0.0.1:61948/alerts?tab=email ; http://127.0.0.1:61948/settings?group=email')
