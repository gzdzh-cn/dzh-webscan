import { api } from './api'
export interface CheckItem {name:string;status:'passed'|'failed'|'pending'|'warning'|'running';message:string;suggestion?:string;duration_ms:number}
export interface CheckReport {ok:boolean;items:CheckItem[];checked_at:number;mode:string}
export interface PreflightStatus {id:string;status:'running'|'complete';report:CheckReport;expires:number}
export function checkStatusLabel(status:string){return ({passed:'通过',failed:'未通过',pending:'待后续验证',warning:'需确认'} as Record<string,string>)[status]||'检查中'}
// A fresh controller belongs to one dialog operation. Cancellation wakes any
// pending delay; late responses may finish but never update the reopened dialog.
export function preflightController(){
 let cancelled=false,id='',finished=false,timer:ReturnType<typeof setTimeout>|undefined,wake:(()=>void)|undefined
 return {
 cancel(){cancelled=true;if(timer)clearTimeout(timer);wake?.();if(id&&!finished)void api(`/api/servers/preflight/${encodeURIComponent(id)}`,'DELETE').catch(()=>{})},
 async run(input:Record<string,unknown>,update:(v:PreflightStatus)=>void){
  const started=await api<{id:string}>('/api/servers/preflight','POST',{...input,async:true,active:input.active??true})
  id=started.id
  if(cancelled){void api(`/api/servers/preflight/${encodeURIComponent(id)}`,'DELETE').catch(()=>{});return}
  while(!cancelled){
   const result=await api<PreflightStatus>(`/api/servers/preflight/${encodeURIComponent(started.id)}`)
   if(cancelled)return
   update(result)
   if(result.status==='complete'){finished=true;return result}
   await new Promise<void>(resolve=>{wake=resolve;timer=setTimeout(resolve,750)})
   wake=undefined;timer=undefined
  }
 }
 }
}
