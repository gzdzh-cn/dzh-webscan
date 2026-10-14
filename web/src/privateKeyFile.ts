export const maxPrivateKeyBytes = 64 * 1024

// Each selection invalidates previous reads; cancellation also protects closed
// dialogs from late File.text() completions.
export function privateKeyFileReader(accept:(value:string)=>void, fail:(message:string)=>void, loading:(value:boolean)=>void) {
 let version=0
 return {
  cancel(){version++;loading(false)},
  async read(files:File[]){
   const current=++version;loading(false)
   if(files.length!==1){fail('每次请选择一个私钥文件');return}
   const file=files[0]!
   if(file.size>maxPrivateKeyBytes){fail('私钥文件不能超过 64 KiB');return}
   if(file.size===0){fail('私钥文件内容为空');return}
   loading(true)
   try {
    const text=await file.text()
    if(current!==version)return
    if(!text.trim()){fail('私钥文件内容为空');return}
    if(new TextEncoder().encode(text).length>maxPrivateKeyBytes){fail('私钥文件不能超过 64 KiB');return}
    accept(text)
   }catch{if(current===version)fail('读取私钥文件失败，请重新选择或直接粘贴内容')}
   finally{if(current===version)loading(false)}
  }
 }
}
