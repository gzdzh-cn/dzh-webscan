// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createApp, nextTick, ref, type App } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { ControlV3, type V3Dashboard, type V3HostWatchdogStatus } from '../controlV3'
import { installElements } from '../elements'
import { consoleContext } from './context'
import { dashboardCards, dashboardHost } from './dashboardCards'
import Dashboard from './Dashboard.vue'
vi.mock('../MetricChart.vue',()=>({default:{props:['title'],template:'<div>{{title}}</div>'}}))
const at='2026-11-01T00:00:00Z',old='2026-10-31T23:58:00Z',future='2026-11-01T00:01:00Z'
const section=<T,>(data:T)=>({data,updated_at:at,error:''})
function fixture():V3Dashboard {
 const status:V3HostWatchdogStatus={instance:'synthetic-host',observed_at:at,runtime_version:12,frozen:false,reason:'',pending:0,checks:['api','postgres','metrics','storage'].map(component=>({component,state:'normal',reason:'',observed_at:at,latency_ms:2})),environment:{os:'linux',architecture:'amd64',kernel:'6.8.0-synthetic',boot_id:'synthetic-boot',uptime_seconds:90000,memory_bytes:8*1024**3,storage:[{component:'watchdog_state',total_bytes:100*1024**3,available_bytes:25*1024**3,inodes:100000,available_inodes:50000}]}}
 return{version:'v3-local',started_at:at,updated_at:at,stale:false,error:'',summary:{sections:{host_watchdog:section({configured:true,available:true,fresh:true,reason:'',status}),services:section({database_bytes:1048576,roles:{'notify-email':{heartbeat:at,healthy:true,has_error:false},'notify-feishu':{heartbeat:at,healthy:true,has_error:false},'notification-tests':{heartbeat:at,healthy:true,has_error:false}},last_cleanup:null}),notifications:section({email:{enabled:true,pending:0,retrying:0,oldest_wait_seconds:null},feishu:{enabled:true,pending:0,retrying:0,oldest_wait_seconds:null}})}}}
}
const card=(value:V3Dashboard,key:string)=>dashboardCards(value).find(item=>item.key===key)!
let app:App|undefined,host:HTMLDivElement
async function settle(){for(let i=0;i<20;i++){await Promise.resolve();await nextTick()}}
async function mount(value:V3Dashboard){const client=new ControlV3();vi.spyOn(client,'dashboard').mockResolvedValue(value);const events=vi.spyOn(client,'events'),router=createRouter({history:createMemoryHistory(),routes:[{path:'/',component:Dashboard},{path:'/:pathMatch(.*)*',component:{template:'<div>详情</div>'}}]});await router.push('/');await router.isReady();host=document.createElement('div');document.body.append(host);app=createApp({template:'<router-view />'});installElements(app);app.use(router);app.provide(consoleContext,{client,session:ref({username:'viewer',role:'viewer' as const,csrf:'synthetic'})});app.mount(host);await settle();return{client,events}}
beforeEach(()=>{vi.useFakeTimers();vi.setSystemTime(new Date(at));Object.defineProperty(document,'hidden',{configurable:true,value:false})})
afterEach(()=>{app?.unmount();app=undefined;host?.remove();vi.clearAllTimers();vi.useRealTimers();vi.restoreAllMocks()})
it('uses independently observed fresh postgres, metrics and watchdog checks',()=>{
 const value=fixture();expect(card(value,'database').status).toBe('正常');expect(card(value,'database').reason).toContain('PostgreSQL 正常');expect(card(value,'database').reason).toContain('VictoriaMetrics 正常');expect(card(value,'database').reason).toContain('此值不是磁盘容量');expect(card(value,'watchdog').status).toBe('正常');expect(card(value,'central').status).toBe('正常')
 value.summary.sections!.host_watchdog!.data!.status!.checks.find(c=>c.component==='metrics')!.state='abnormal';expect(card(value,'database').status).toBe('异常');expect(card(value,'watchdog').status).toBe('异常')
})
it('keeps missing, unconfigured, unreachable, expired and failed observations unknown',()=>{
 const value=fixture(),data=value.summary.sections!.host_watchdog!.data!
 for(const change of [()=>data.configured=false,()=>{data.configured=true;data.available=false},()=>{data.available=true;data.fresh=false},()=>{data.fresh=true;data.status!.observed_at=old},()=>data.status!.observed_at=future,()=>{data.status!.observed_at=at;value.summary.sections!.host_watchdog!.error='snapshot_failed'}]){change();expect(card(value,'watchdog').status).toBe('未知');expect(card(value,'database').status).toBe('未知');expect(dashboardHost(value).status).toBeNull()}
 delete value.summary.sections!.host_watchdog;expect(card(value,'watchdog').status).toBe('未知')
})
it('requires individual new check timestamps and rejects duplicate or missing health evidence',()=>{
 const value=fixture(),checks=value.summary.sections!.host_watchdog!.data!.status!.checks,postgres=checks.find(c=>c.component==='postgres')!
 postgres.observed_at=old;expect(card(value,'database').status).toBe('未知');postgres.observed_at=future;expect(card(value,'database').status).toBe('未知');postgres.observed_at=at;postgres.state='unknown';expect(card(value,'database').status).toBe('未知');postgres.state='normal';checks.push({...postgres});expect(card(value,'database').status).toBe('未知');checks.splice(checks.indexOf(postgres),1);expect(card(value,'database').status).toBe('正常');checks.splice(checks.findIndex(c=>c.component==='metrics'),1);expect(card(value,'database').status).toBe('未知')
})
it('uses each notification channel worker independently and never treats an empty queue as health',()=>{
 const value=fixture(),roles=value.summary.sections!.services!.data!.roles
 expect(card(value,'email').status).toBe('正常');delete roles['notify-email'];expect(card(value,'email').status).toBe('未知');expect(card(value,'email').reason).toContain('队列为空也不能证明正常');expect(card(value,'feishu').status).toBe('正常')
 roles['notify-email']={heartbeat:old,healthy:true,has_error:false};expect(card(value,'email').status).toBe('未知');roles['notify-email']={heartbeat:at,healthy:true,has_error:true};expect(card(value,'email').status).toBe('异常');roles['notify-email']={heartbeat:at,healthy:false,has_error:false};expect(card(value,'email').status).toBe('异常')
 value.summary.sections!.notifications!.data!.email.enabled=false;expect(card(value,'email').status).toBe('已停用');value.summary.sections!.services!.error='role_read_failed';expect(card(value,'feishu').status).toBe('未知')
})
it('explains notification configuration freeze without calling fresh storage unhealthy',()=>{
 const value=fixture(),status=value.summary.sections!.host_watchdog!.data!.status!;status.frozen=true;status.reason='等待事务核验';expect(card(value,'watchdog').status).toBe('维护中');expect(card(value,'email').status).toBe('维护中');expect(card(value,'database').status).toBe('正常');expect(card(value,'email').reason).toContain('通知配置冻结，发送已暂停：等待事务核验');delete value.summary.sections!.services!.data!.roles['notify-email'];expect(card(value,'email').status).toBe('未知')
})
it('renders actual host memory and filesystem evidence separately from application database size',async()=>{
 const{events}=await mount(fixture());expect(host.textContent).toContain('linux / amd64');expect(host.textContent).toContain('6.8.0-synthetic');expect(host.textContent).toContain('8.0 GiB');expect(host.textContent).toContain('100.0 GiB');expect(host.textContent).toContain('25.0 GiB');expect(host.textContent).toContain('50,000 / 100,000');expect(host.textContent).toContain('PostgreSQL 业务表与索引大小不代表磁盘容量');expect(events).not.toHaveBeenCalled();expect(host.querySelectorAll('.host-check')).toHaveLength(4)
})
it('shows zero available capacity honestly and rejects invalid environment values',async()=>{
 const value=fixture(),env=value.summary.sections!.host_watchdog!.data!.status!.environment;env.memory_bytes=-1;env.uptime_seconds=NaN;env.storage[0]!.available_bytes=0;env.storage[0]!.available_inodes=0;env.storage.push({component:'metrics',total_bytes:1,available_bytes:2,inodes:0,available_inodes:0});await mount(value);expect(host.querySelector('.host-environment-details')!.textContent).toContain('宿主总内存未知');expect(host.querySelector('.host-environment-details')!.textContent).toContain('宿主运行时间未知');expect(host.textContent).toContain('100.0%');expect(host.textContent).toContain('0 B');expect(host.textContent).toContain('0 / 100,000');expect(host.textContent).not.toContain('NaN');expect(host.textContent).not.toContain('Infinity')
})
it('hides stale environment numbers and marks every component unknown after a read failure',async()=>{
 const value=fixture();value.stale=true;await mount(value);expect(host.textContent).not.toContain('100.0 GiB');expect(host.textContent).not.toContain('linux / amd64');expect(host.textContent).toContain('尚无新鲜文件系统容量证据');expect(dashboardCards(value).every(item=>item.status==='未知')).toBe(true);value.stale=false;expect(dashboardHost(value,true).status).toBeNull();expect(dashboardCards(value,true).every(item=>item.status==='未知')).toBe(true)
})
