// Isolated read-only migration UI fixture. Synthetic data, loopback only;
// no proxy, business database, notification provider or remote node.
import { createServer } from '../web/node_modules/vite/dist/node/index.js'
import vue from '../web/node_modules/@vitejs/plugin-vue/dist/index.mjs'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'), evidence=path.join(root,'.cache/verification/v3/feature-migration-20261101')
await mkdir(evidence,{recursive:true})
const requests=[],session='a'.repeat(64), cursor='b'.repeat(64),generation='d'.repeat(64),stamp=new Date().toISOString()
const server=await createServer({configFile:false,root:path.join(root,'web'),cacheDir:path.join(evidence,'migration-history-vite-cache'),plugins:[{name:'synthetic-readonly-history',configureServer(vite){vite.middlewares.use((req,res,next)=>{
 const url=new URL(req.url,'http://127.0.0.1'),p=url.pathname
 if(!p.startsWith('/api/')){if(!p.includes('.')&&!p.startsWith('/@')&&!p.startsWith('/node_modules')&&!p.startsWith('/src/'))req.url='/v3.html';return next()}
 const entry={method:req.method,path:p,query:url.search,at:new Date().toISOString()};requests.push(entry)
 const send=(value,status=200)=>{entry.status=status;res.statusCode=status;res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');res.end(JSON.stringify(value))}
 if(req.method!=='GET')return send({code:'read_only_fixture',message:'隔离历史夹具仅支持读取'},405)
 if(p==='/api/v3/session')return send({username:'synthetic-admin',role:'admin',csrf:'synthetic-readonly-csrf'})
 if(p==='/api/v3/capabilities')return send({api_version:3,topology:'single',features:[],version:'local-migration-ui'})
 if(p==='/api/v3/migration-history/sessions')return send({items:[{id:session,phase:'frozen',created_at:stamp,history_records:31,generations:[{generation,revision:"e".repeat(64),state:"verified"}]}],limit:100,read_only:true})
 if(p==='/api/v3/migration-history/catalog')return send({nodes:[{id:'legacy-node',first_sample:1793490000,last_sample:1793490600}],series:[{metric:'cpu_percent',dimension:''}],node:'legacy-node',read_only:true})
 if(p==='/api/v3/migration-history')return send({session,generation,node:'legacy-node',metric:'cpu_percent',source:'legacy-v2',points:[{time:1793490000,resolution_seconds:300,origin:'legacy',ok:true,value:12,min:10,max:14,count:10},{time:1793490300,resolution_seconds:300,origin:'legacy',ok:false},{time:1793490600,resolution_seconds:300,origin:'legacy',ok:true,value:0,min:0,max:0,count:10}],read_only:true,interpolated:false})
 if(p==='/api/v3/legacy-history')return send({items:[{id:'1'.repeat(64),role:'host-manager',legacy_table:'logs',record_key:42,summary:{kind:'upgrade-node',status:'complete',created_at:stamp,parent:'c'.repeat(64),raw_source:'PRIVATE-SOURCE-MUST-NOT-RENDER',message:'PRIVATE-MESSAGE-MUST-NOT-RENDER'}},{id:'2'.repeat(64),role:'host-manager',legacy_table:'config_backups',record_key:43,summary:{kind:'configuration-backup',created_at:stamp,artifact_available:true,restore_verified:true}}],next_cursor:url.searchParams.get('cursor')?'':cursor,read_only:true})
 return send({code:'fixture_endpoint_missing',message:'该合成只读页面未提供此接口'},404)
})}},vue()],server:{host:'127.0.0.1',port:Number(process.env.WEBSCAN_MIGRATION_UI_PORT || 61953),strictPort:true,fs:{allow:[root]}},logLevel:'warn'})
await server.listen()
const flush=()=>writeFile(path.join(evidence,'phase5-migration-browser-requests.json'),JSON.stringify(requests,null,2)),timer=setInterval(flush,1000)
for(const sig of ['SIGINT','SIGTERM'])process.on(sig,async()=>{clearInterval(timer);await flush();await server.close();process.exit()})
console.log('Synthetic read-only migration history started on loopback')
