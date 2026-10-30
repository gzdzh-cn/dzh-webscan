import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

// Cursors are opaque. Only previously visited pages can be revisited; never
// synthesize an offset, total count or arbitrary page number.
export function useCursorPage() {
  const route = useRoute(), router = useRouter(), visited = new Map<string, string>()
  const limit = computed(() => [20, 50, 100].includes(Number(route.query.limit)) ? Number(route.query.limit) : 20)
  const cursor = computed(() => typeof route.query.cursor === 'string' ? route.query.cursor : '')
  const scope = () => JSON.stringify([route.path, ...Object.entries(route.query).filter(([key]) => key !== 'cursor').sort()])
  function go(target: string) {
    if (target) visited.set(`${scope()}:${target}`, cursor.value)
    return router.push({ path: route.path, query: { ...route.query, cursor: target || undefined } })
  }
  function previous() {
    const target = visited.get(`${scope()}:${cursor.value}`) || ''
    return router.push({ path: route.path, query: { ...route.query, cursor: target || undefined } })
  }
  function resize(value: number) {
    visited.clear()
    return router.push({ path: route.path, query: { ...route.query, cursor: undefined, limit: value === 20 ? undefined : String(value) } })
  }
  return { limit, cursor, go, previous, resize }
}
