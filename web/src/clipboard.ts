/** Copy from a user's click, including consoles served over plain HTTP. */
export async function copyURL(value: string): Promise<boolean> {
 if (navigator.clipboard?.writeText) {
  try { await navigator.clipboard.writeText(value); return true } catch { /* Try HTTP-compatible copying. */ }
 }
 const previous = document.activeElement as HTMLElement | null
 const input = document.createElement('textarea')
 input.value = value; input.setAttribute('readonly', '')
 input.style.cssText = 'position:fixed;left:-9999px;top:0'
 document.body.appendChild(input); input.focus(); input.select()
 try { return document.execCommand('copy') } catch { return false }
 finally { input.remove(); previous?.focus() }
}
