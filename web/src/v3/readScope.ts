import { onUnmounted, ref } from 'vue'

// Each view owns its requests. Aborting one view must not cancel another view,
// session recovery or a later generation that is already on screen.
export function useReadScope() {
  const loading = ref(false), error = ref('')
  let controller: AbortController | undefined, generation = 0, disposed = false
  function cancel() { generation++; controller?.abort(); loading.value = false }
  async function run<T>(read: (signal: AbortSignal) => Promise<T>, apply: (data: T) => void) {
    cancel()
    if (disposed) return
    const current = generation
    const signal = (controller = new AbortController()).signal
    loading.value = true; error.value = ''
    try {
      const data = await read(signal)
      if (!disposed && current === generation) apply(data)
    } catch (e) {
      if (!disposed && current === generation && !signal.aborted) error.value = e instanceof Error ? e.message : '查询失败，请重试'
    } finally { if (!disposed && current === generation) loading.value = false }
  }
  onUnmounted(() => { disposed = true; cancel() })
  return { loading, error, run, cancel }
}
