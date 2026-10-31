// Local visual comparison only. Every API is synthetic; no proxy, SSH,
// production database or notification delivery is configured.
import { createServer } from '../web/node_modules/vite/dist/node/index.js'
import vue from '../web/node_modules/@vitejs/plugin-vue/dist/index.mjs'
import { mkdir, writeFile, symlink, access } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const evidence = path.join(root, '.cache/verification/v3/ui-restoration')
await mkdir(evidence, {recursive:true})
const baseline = path.join(evidence,'baseline'); await mkdir(baseline,{recursive:true})
execFileSync('tar',['-x','-C',baseline],{input:execFileSync('git',['archive','v2.0.46','web'],{cwd:root,maxBuffer:16<<20})})
try { await access(path.join(baseline,'web/node_modules')) } catch { await symlink(path.join(root,'web/node_modules'),path.join(baseline,'web/node_modules')) }
const at = Date.parse('2026-10-30T12:00:00Z'), sec = at/1000, iso = new Date(at).toISOString()
const values = {cpu_percent:18.4,cpu_user_percent:12.2,cpu_system_percent:5.4,cpu_iowait_percent:.8,cpu_cores:4,memory_percent:42.6,memory_total:8*1024**3,memory_used:3.4*1024**3,memory_available:4.6*1024**3,disk_percent:36.2,'disk_percent:/':36.2,'inode_percent:/':8.5,load1:.42,load5:.38,load15:.31,uptime:86400,swap_percent:0,net_receive:120*1024,net_transmit:48*1024,disk_read:200*1024,disk_write:90*1024,disk_read_iops:12,disk_write_iops:8,webscan_watches:3,webscan_local_pending_events:0,webscan_pending_scans:0,webscan_agent_heartbeat_seconds:sec-5,webscan_coverage_ok:1}
const points = Array.from({length:61},(_,i)=>({time:sec-3600+i*60,ok:i!==30,values:Object.fromEntries(Object.entries(values).map(([k,v])=>[k,k.startsWith('cpu_')&&k!=='cpu_cores'?Math.max(0,v+Math.sin(i/4)*3):v]))}))
const nodes = ['node-a','node-b'].map((id,i)=>({id,name:['生产节点 A','生产节点 B'][i],endpoint:`192.0.2.${10+i}:19100`,server_name:`${id}.example.test`,enabled:true,mode:'docker',version:2,applied_version:i?1:2,shard:i,configuration:{registered_version:2,delivered_version:2,runtime_enabled:true,runtime_mode:'docker',runtime_endpoint:`192.0.2.${10+i}:19100`},collection_state:'normal',status:{sampled_at:at,updated_at:iso,error:'',metrics_error:'',events_error:'',protocol_error:'',metrics:values,info:{hostname:id,kernel:'6.1.0',architecture:'x86_64',agent_version:'v3.0.0',agent_mode:'docker'}}}))
const legacyNodes = nodes.map(n=>({id:n.id,name:n.name,host:n.endpoint.split(':')[0],status:'normal',central:false,actual_mode:'docker',configured_mode:'docker',agent_version:'v2.0.46',configuration_state:n.version===n.applied_version?'applied':'pending',deployment_state:'complete',snapshot:{time:sec,ok:true,values,info:{nodename:n.id,sysname:'Linux',release:'6.1.0',machine:'x86_64'}},can_remove:true}))
const sites = ['公司官网','产品服务'].map((name,i)=>({id:i+1,name,url:`https://${i?'service':'www'}.example.test/`,node:'node-a',keyword:'欢迎',slow_alert:false,paused:false,version:3,state:{status:'normal',checks:120,passed:120,failures:0,successes:120,last:{time:sec,ok:true,latency:.128+i*.04,http_status:200,cert_expires:sec+80*86400,cert_checked:sec,cert_host:`${i?'service':'www'}.example.test`,reason:''}}}))
const overview={total:2,normal:2,down:0,pending:0,paused:0,scheduler_healthy:true,unknown:0,migration_pending:0,due:0,notification_outbox:{pending:0,oldest_wait_seconds:null},notification_worker:{heartbeat:null,healthy:null},scheduler:{heartbeat:iso,healthy:true}}
const componentNames = ['中心主动采集与后台','主机指标采集','文件监控','安全扫描','事件采集','网站检测','数据库','飞书通知','邮箱通知','宿主管理服务','看门狗','备份与历史清理','部署任务']
const componentKeys = ['receiver','metrics','files','scanner','transport','websites','database','feishu','email','manager','watchdog','maintenance','deployment']
const components = componentNames.map((name,i)=>({id:componentKeys[i],name,status:i===7||i===8?'disabled':i===10?'unknown':'normal',reason:i===7||i===8?'通道未启用，队列保留':'最近一次检查通过',href:i===2||i===3?'/events':i===5?'/websites':i===12?'/deployments':'/servers',updated:sec,metrics:{'运行状态':i===7||i===8?'已停用':'正常'}}))
const section=data=>({data,updated_at:iso,error:''})
const dashboard={version:'v3.0.0',started_at:new Date(at-86400_000).toISOString(),updated_at:iso,stale:false,error:'',summary:{sections:{servers:section({servers:2,enabled:2,fresh:2,abnormal:0,unknown:0}),websites:section(overview),events:section({total:18,security:0}),alerts:section({total:0,items:[]}),notifications:section({feishu:{enabled:false,pending:0,retrying:0,oldest_wait_seconds:null},email:{enabled:false,pending:0,retrying:0,oldest_wait_seconds:null}}),deployments:section({running:0,recovery_required:0,latest:null}),resources:section({items:nodes.map(n=>({id:n.id,name:n.name,mode:n.mode,actual_mode:'docker',agent_version:'v3.0.0',sampled_at:at,...Object.fromEntries(['cpu_percent','memory_percent','disk_percent'].map(k=>[k,values[k]])),has_error:false})),rankings:Object.fromEntries(['cpu_percent','memory_percent','disk_percent'].map(k=>[k,nodes.map(n=>({id:n.id,name:n.name,value:values[k]}))]))}),monitoring:section({states:Object.fromEntries(['files','scans','delivery'].map(k=>[k,{applicable:2,normal:2,abnormal:0,unknown:0}])),pending_events:0,oldest_wait_seconds:0,pending_scans:0,yara_nodes:2,clamav_nodes:0}),services:section({database_bytes:16*1024**2,roles:{executor:{heartbeat:iso,healthy:true,has_error:false},retention:{heartbeat:iso,healthy:true,has_error:false}},last_cleanup:{status:'succeeded',deleted:0,updated_at:iso}})}}}
const job={id:'job-a',node:'node-a',username:'admin',kind:'upgrade',status:'succeeded',direction:'forward',node_version:2,plan_digest:'a'.repeat(64),step:6,rollback_step:0,recovery_required:false,error_code:'',log_cursor:3,created_at:iso,updated_at:iso,finished_at:iso}
const events=[{node:'node-a',id:'fixture-event-a',received_at:iso,payload:{operation:'modify',path:'/srv/website/index.html',reason:'文件内容发生变化'},source:'events',record_key:'events:node-a:fixture-event-a',can_delete:false,delete_reason:'最近 24 小时保护'}]
const retention={version:1,policy:{sqlite_events_days:30,security_events_days:30,website_incidents_days:30,server_alerts_days:30,delivery_records_days:30},updated_at:iso}
const settingsFields=[{path:'website_monitor.interval_seconds',label:'网站检测间隔（秒）',kind:'integer',min:10,max:3600},{path:'website_monitor.enabled',label:'网站检测',kind:'bool'},{path:'monitoring.cpu_threshold',label:'CPU 告警阈值（%）',kind:'integer',min:1,max:100},{path:'email.enabled',label:'邮箱通知',kind:'bool'},{path:'email.host',label:'SMTP 主机',kind:'text'},{path:'feishu.enabled',label:'飞书通知',kind:'bool'}]
const settingsValues={'website_monitor.interval_seconds':30,'website_monitor.enabled':true,'monitoring.cpu_threshold':90,'email.enabled':false,'email.host':'','feishu.enabled':false}
const requests=[], servers=[]
for (const [mode,dir,port] of [['baseline',path.join(baseline,'web'),61946],['restored',path.join(root,'web'),61947]]) {
 const isV3=mode==='restored'
 const server=await createServer({configFile:false,root:dir,cacheDir:path.join(evidence,`vite-cache-${mode}`),plugins:[{name:'isolated-ui-fixtures',transformIndexHtml(html){return html.replace('</head>','<style>*,*::before,*::after{animation-duration:0s!important;transition-duration:0s!important}</style></head>')},transform(code,id){if(id.endsWith('/src/MetricChart.vue'))return code.replaceAll('chart.setOption(props.option)','chart.setOption({...props.option,animation:false})').replaceAll('chart?.setOption(option, true)','chart?.setOption({...option,animation:false}, true)')},configureServer(vite){vite.middlewares.use(async(req,res,next)=>{
  const u=new URL(req.url,'http://127.0.0.1'),p=u.pathname
  if(!p.startsWith('/api/')) {if(!p.includes('.')&&!p.startsWith('/@')&&!p.startsWith('/node_modules')&&!p.startsWith('/src/'))req.url=isV3?'/v3.html':'/index.html';return next()}
  const entry={mode,method:req.method,path:p,query:u.search,at:new Date().toISOString()}; requests.push(entry)
  res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store')
  const send=(v,status=200)=>{entry.status=status;entry.code=v?.code;res.statusCode=status;res.end(JSON.stringify(v))},page=items=>({items,total:items.length,next_cursor:'',limit:Number(u.searchParams.get('limit')||20)})
  const signed=req.headers.cookie?.includes(`fixture_${mode}=yes`)
  if(p.endsWith('/login')){res.setHeader('Set-Cookie',`fixture_${mode}=yes; SameSite=Strict; Path=/`);return send({csrf:'isolated-ui-csrf'})}
  if(p.endsWith('/logout')){res.setHeader('Set-Cookie',`fixture_${mode}=; Max-Age=0; Path=/`);return send({ok:true})}
  if(p.endsWith('/session'))return signed?send({username:'admin',role:'admin',csrf:'isolated-ui-csrf',nodes:legacyNodes}):send({code:'unauthorized',message:'请登录'},401)
  if(!signed)return send({code:'unauthorized',message:'请登录'},401)
  // Protect the fixture boundary: the restored app must never reach legacy API.
  if(isV3&&!p.startsWith('/api/v3/'))return send({code:'legacy_api_forbidden',message:'v3 界面调用了旧接口'},409)
  if(p==='/api/v3/capabilities')return send({api_version:3,topology:'single',features:[],implementation_stage:'local-ui-fixture',settings:{available:true,reason:''},executor:{available:true,reason:''},deployments:{available:true,reason:''},deployment_defaults:{central:'docker',node:'docker',node_modes:['docker','native']}})
  if(p==='/api/v3/dashboard') {
   // Select only synthetic certificate evidence, never host/runtime state.
   const scenario=new URL(req.headers.referer || 'http://127.0.0.1').searchParams.get('fixture_certificate') || 'missing'
   const value=structuredClone(dashboard), now=Date.now(), stamp=new Date(now).toISOString()
   if(['healthy','stale','error','expiring','expired','missing-expiry'].includes(scenario)) {
    const maintenance={heartbeat:scenario==='stale'?new Date(now-7200_000).toISOString():stamp,fresh:scenario!=='stale',has_error:scenario==='error',reason:scenario==='error'?'隔离样例：证书维护失败':'',collector_expires_at:scenario==='missing-expiry'?null:new Date(now+(scenario==='expired'?-1:scenario==='expiring'?3:30)*86400_000).toISOString(),ca_expires_at:new Date(now+365*86400_000).toISOString()}
    value.summary.sections.certificates={data:{maintenance},updated_at:stamp,error:''}
   }
   return send(value)
  }
  if(p==='/api/dashboard')return send({release:'v2.0.46',updated:sec,started:sec-86400,servers:legacyNodes,components,errors:{},server_total:2,server_normal:2,server_abnormal:0,server_unknown:0,website_total:2,website_normal:2,website_down:0,website_paused:0,website_pending:0,current_issues:0,events_24h:18,security_24h:0,pending_notifications:0,pending_email:0,deployment_running:false})
  if(p==='/api/servers/requirements')return send({minimum_systemd:231,nodes:[],clamav_enabled:false})
  if(p==='/api/servers')return send(page(legacyNodes))
  if(isV3 && req.method==='POST' && /\/servers\/[^/]+\/deployment-preview$/.test(p))return send({id:'prep-preview',phase:'complete',status:'succeeded',result:{preview:{token:'synthetic-preview',version:2,kind:'upgrade',target:{mode:'docker',release:'v3.0.0',sha256:'a'.repeat(64)},current:{release:'v2.0.46'}}}})
  if(p==='/api/v3/deployment-preparations/prep-preview')return send({id:'prep-preview',phase:'complete',status:'succeeded',result:{preview:{token:'synthetic-preview',version:2,kind:'upgrade',target:{mode:'docker',release:'v3.0.0',sha256:'a'.repeat(64)},current:{release:'v2.0.46'}}}})
  if(p==='/api/v3/deployment-preparations/prep-confirm')return send({id:'prep-confirm',phase:'complete',status:'succeeded',result:{job:'job-a'}})
  if(p==='/api/v3/deployments' && req.method==='POST')return send({id:'prep-confirm',phase:'complete',status:'succeeded',result:{job:'job-a'}})
  if(p==='/api/v3/servers')return send(page(nodes.filter(n=>!u.searchParams.get('q')||n.name.includes(u.searchParams.get('q')))))
  if(/^\/api\/v3\/servers\/[^/]+\/ssh-credential$/.test(p))return send({configured:true,version:1,ssh_port:22,fingerprint:'SHA256:isolated-fixture-fingerprint'})
  if(/^\/api\/v3\/servers\/[^/]+$/.test(p))return send({node:nodes.find(n=>n.id===p.split('/').pop())||nodes[0],status:nodes[0].status,latest_deployment:job})
  if(/\/servers\/[^/]+\/metrics$/.test(p))return send({points,resolution_seconds:60,start:sec-3600,end:sec})
  if(p==='/api/v3/events')return send({...page(events),start:new Date(at-86400_000).toISOString(),end:iso})
  if(p==='/api/events')return send(page(events.map(e=>({...e,event:e.payload,...e.payload,time:sec}))))
  if(p==='/api/overview'||p==='/api/v3/websites/overview')return send(overview)
  if(p==='/api/websites'||p==='/api/v3/websites')return send(page(sites))
  if(/\/websites\/\d+$/.test(p))return send(sites.find(s=>s.id===Number(p.split('/').pop()))||sites[0])
  if(/\/incidents$/.test(p)||/\/alerts(\/current|\/history)?$/.test(p)||p==='/api/v3/notifications'||p==='/api/notifications')return send(page([]))
  if(p.endsWith('/notifications/stats'))return send({items:Array.from({length:7},(_,i)=>({day:new Date(at-(6-i)*86400_000).toISOString().slice(0,10),delivered:i%3,pending:0,retrying:0})),timezone:'Asia/Shanghai',group_by:'created_at'})
  if(p==='/api/v3/deployments')return send(page([job]))
  if(p==='/api/deployments')return send({...page([{...job,status:'complete',created:sec,updated:sec,scope:'生产节点 A',message:'子服务器升级完成',state:'complete',kind:'node',can_delete:false,delete_reason:'最近 24 小时保护'}]),recovery:{pending:false}})
  if(p==='/api/v3/deployments/job-a')return send({job,phase:'complete',can_resume:false,can_rollback:false,recovery_required:false,recovery_reason:''})
  if(p==='/api/v3/deployments/job-a/logs')return send({items:['preflight','activate','complete'].map((phase,i)=>({cursor:i+1,phase,code:['phase-complete','phase-complete','succeeded'][i],created_at:iso})),next_cursor:3,status:'succeeded'})
  if(p==='/api/deployments/job-a')return send({job:{...job,status:'complete',created:sec,updated:sec,scope:'生产节点 A',message:'子服务器升级完成',state:'complete',kind:'node'},logs:[{id:1,time:sec,level:'信息',message:'部署环境检查通过\n'},{id:2,time:sec,level:'成功',message:'子服务器升级完成\n'}],cursor:2,stages:[{step:1,title:'部署环境检查',host:'生产节点 A',status:'成功'},{step:2,title:'切换服务',host:'生产节点 A',status:'成功'}]})
  if(p==='/api/v3/website-backups')return send(page([{id:'backup-a',record_key:'backup-a',created_at:iso,source:'manual',count:2,restored_at:null,result:{},can_delete:true,delete_reason:''}]))
  if(p==='/api/backups')return send(page([{id:'backup-a',created:sec,source:'manual',count:2,can_delete:true,delete_reason:'',restored:0,result:''}]))
  if(p==='/api/v3/configuration-backups')return send({...page([{id:'config-a',record_key:'config-a',created_at:iso,source:'manual',settings_version:1,node_count:2,needs_completion:false,can_delete:true,delete_reason:''}]),restore_available:false,saved_restore_available:true,delete_available:true})
  if(p.includes('configuration-')||p.includes('config-backups')||p.includes('/settings/backups'))return send({...page([]),revision:'fixture-revision'})
  if(p==='/api/v3/settings')return send({state:{generation:'1',runtime_version:1,pending:false,updated_at:iso},fields:settingsFields,values:settingsValues,runtime_values:settingsValues,secret_configured:{},runtime_secret_configured:{}})
  if(p==='/api/settings')return send({revision:'fixture-revision',effective_nodes:[],values:{common:{watch_dirs:['/srv/website'],file_extensions:['php','html'],scan:{yara:{enabled:true},clamav:{enabled:false}}},central:{monitoring:{mode:'native'},website_monitor:{enabled:true,interval_seconds:30}},feishu:{enabled:false},email:{enabled:false}},pending_task:false,pending_changes:{known:true,changes:[],credential_note:''}})
  if(p==='/api/v3/retention/status')return send({policy:retention,last_job:null,managed_storage_bytes:16*1024**2,worker_heartbeat:iso,worker_healthy:true,reason:''})
  if(p==='/api/retention/status')return send({policy:retention.policy,retention:retention.policy,files:[],items:[],automatic:{items:[]},last_job:null,managed_storage_bytes:16*1024**2,worker_healthy:true,nodes:[]})
  if(p.includes('/retention/jobs')||p==='/api/v3/audit'||p==='/api/record-operations')return send({...page([]),kind:'manual'})
  if(p==='/api/system/health')return send({mode:'native',database:'normal',pending_notifications:0,pending_email:0,oldest_pending:0,oldest_email:0,email_enabled:false,manager:{available:true,watchdog_phase:'normal'}})
  if(p==='/api/system/version')return send({central:{release:'v2.0.46',commit:'isolated-fixture',built_at:iso,source_digest:'a'.repeat(64)},manager:{release:'v2.0.46',commit:'isolated-fixture',built_at:iso,source_digest:'a'.repeat(64)},hotfix:'none'})
  return send({code:'fixture_endpoint_missing',message:`隔离样例尚未提供 ${p}`},404)
 })}},vue()],server:{host:'127.0.0.1',port,strictPort:true,fs:{allow:[root]}},logLevel:'warn'})
 await server.listen();servers.push(server)
}
await writeFile(path.join(evidence,'fixture-context.json'),JSON.stringify({baseline:'v2.0.46',restored:'working-tree',synthetic:true,urls:['http://127.0.0.1:61946','http://127.0.0.1:61947'],time:iso},null,2))
const flush=()=>writeFile(path.join(evidence,'requests.json'),JSON.stringify(requests,null,2))
const timer=setInterval(flush,1000)
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,async()=>{clearInterval(timer);await flush();await Promise.all(servers.map(s=>s.close()));process.exit()})
console.log('Isolated UI fixtures ready: baseline http://127.0.0.1:61946 ; restored http://127.0.0.1:61947')
