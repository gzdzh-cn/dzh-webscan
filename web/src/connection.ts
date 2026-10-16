// Reads may reconnect; writes are never replayed automatically.
const reads = new Map<AbortController,boolean>()
const reconnecting = new Set<AbortController>()
export function cancelReadRequests(includeSession=false) { for(const [c,persistent] of reads){if(!persistent||includeSession){c.abort();reads.delete(c);reconnecting.delete(c)}}notify() }
function notify(){window.dispatchEvent(new CustomEvent('backend-connection',{detail:{reconnecting:reconnecting.size>0}}))}
function pause(signal:AbortSignal){return new Promise<void>((resolve,reject)=>{
 let timer:ReturnType<typeof setTimeout>|undefined
 const cleanup=()=>{clearTimeout(timer);signal.removeEventListener('abort',abort);document.removeEventListener('visibilitychange',visible)}
 const done=()=>{cleanup();resolve()};const abort=()=>{cleanup();reject(new DOMException('请求已取消','AbortError'))}
 const visible=()=>{clearTimeout(timer);if(!document.hidden)timer=setTimeout(done,3000)}
 signal.addEventListener('abort',abort,{once:true});document.addEventListener('visibilitychange',visible);visible();if(signal.aborted)abort()
})}
export async function readWithReconnect<T>(read:(signal:AbortSignal)=>Promise<T>,transient:(e:unknown)=>boolean,persistent=false):Promise<T>{
 const control=new AbortController();reads.set(control,persistent)
 try {for(;;){try{return await read(control.signal)}catch(e){if(control.signal.aborted||!transient(e))throw e;reconnecting.add(control);notify();await pause(control.signal)}}}
 finally{reads.delete(control);reconnecting.delete(control);notify()}
}
