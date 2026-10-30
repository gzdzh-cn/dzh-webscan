import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { queryParams } from '../api'
import type { V3Event, V3EventFilter, V3EventPage } from '../controlV3'
import { useConsole } from './context'
import { useReadScope } from './readScope'

const hoursOptions = [24, 168, 720]
export const refreshIntervals = [10, 30, 60, 120, 300]
type Conditions = { node: string; q: string; operation: string; hours: number; include_probes: boolean }
export function useEventQuery() {
  const { client, session } = useConsole(), route = useRoute(), router = useRouter()
  const scope = useReadScope()
  const parse = (): Conditions => ({
    node: typeof route.query.node === 'string' ? route.query.node : '',
    q: typeof route.query.q === 'string' ? route.query.q : '',
    operation: typeof route.query.operation === 'string' ? route.query.operation : '',
    hours: hoursOptions.includes(Number(route.query.hours)) ? Number(route.query.hours) : 24,
    include_probes: route.query.include_probes === 'true',
  })
  const draft = reactive(parse()), submitted = ref<Conditions>(), items = ref<V3Event[]>([])
  const queried = ref(false), attempted = ref(false), ready = ref(false), lastUpdated = ref(0)
  const auto = ref(false), interval = ref(30), now = ref(Date.now()), nextAt = ref(0), hidden = ref(document.hidden)
  const cursor = ref(''), next = ref(''), previous = ref<string[]>([]), queryWindow = ref({ start: '', end: '' })
  const detail = ref<V3Event>(), checked = ref<V3Event[]>([])
  const equal = (a: Conditions, b: Conditions) => JSON.stringify(a) === JSON.stringify(b)
  const changed = computed(() => !!submitted.value && !equal(draft, submitted.value))
  const countdown = computed(() => nextAt.value ? Math.max(0, Math.ceil((nextAt.value - now.value) / 1000)) : 0)
  const preference = `webscan:v3:event-refresh:${session.value?.username || ''}`
  let generation = 0, disposed = false, timer: ReturnType<typeof setInterval> | undefined
  function schedule() {
    now.value = Date.now()
    nextAt.value = auto.value && ready.value && !changed.value && !hidden.value && !scope.loading.value
      ? now.value + interval.value * 1000 : 0
  }
  async function load(roll = false, manual = false) {
    if (!submitted.value || disposed || hidden.value || !manual && scope.loading.value) return
    const current = ++generation, conditions = { ...submitted.value }
    nextAt.value = 0; attempted.value = true; detail.value = undefined
    const end = new Date(), start = new Date(end.getTime() - conditions.hours * 3600_000)
    const range = roll || !queryWindow.value.start ? { start: start.toISOString(), end: end.toISOString() } : { ...queryWindow.value }
    let pageCursor = cursor.value, trail = [...previous.value]
    await scope.run(async signal => {
      for (;;) {
        const filter: V3EventFilter = { node: conditions.node, q: conditions.q, operation: conditions.operation,
          include_probes: conditions.include_probes, ...range, cursor: pageCursor, limit: 20 }
        const data = await client.events(filter, signal, false)
        // Cleanup can empty a previously valid cursor page. Walk only the
        // already visited cursors, keeping the exact submitted query/window.
        if (!data.items.length && pageCursor && trail.length) { pageCursor = trail.pop()!; continue }
        return data
      }
    }, (data: V3EventPage) => {
      items.value = data.items; next.value = data.next_cursor; cursor.value = pageCursor; previous.value = trail
      queryWindow.value = { start: data.start, end: data.end }; checked.value = []
      queried.value = true; ready.value = true; lastUpdated.value = Date.now()
    })
    if (!disposed && generation === current) schedule()
  }
  function submit() {
    if (draft.operation === 'probe' && !draft.include_probes) { scope.error.value = '请先开启包含链路探针'; return }
    submitted.value = { ...draft }; ready.value = false; previous.value = []; cursor.value = ''; queryWindow.value = { start: '', end: '' }
    void load(true, true)
  }
  function page(forward: boolean) {
    if (!ready.value || scope.loading.value) return
    if (forward) { if (!next.value) return; previous.value = [...previous.value, cursor.value]; cursor.value = next.value }
    else { if (!previous.value.length) return; const trail = [...previous.value]; cursor.value = trail.pop()!; previous.value = trail }
    void load()
  }
  function refresh() { if (ready.value) void load(true) }
  function visibility() {
    hidden.value = document.hidden; nextAt.value = 0
    if (hidden.value) { generation++; scope.cancel() }
    else if (auto.value && ready.value && !changed.value) void load(true)
  }
  function stop() { generation++; nextAt.value = 0; scope.cancel() }
  watch(draft, () => {
    schedule()
    const query = Object.fromEntries(queryParams({ ...draft }))
    void router.replace({ path: '/events', query })
  }, { deep: true })
  watch(() => route.fullPath, () => {
    const restored = parse()
    if (equal(draft, restored)) return
    stop(); auto.value = false; Object.assign(draft, restored); submitted.value = undefined
    items.value = []; queried.value = false; attempted.value = false; ready.value = false
    cursor.value = ''; next.value = ''; previous.value = []; checked.value = []; detail.value = undefined; scope.error.value = ''; lastUpdated.value = 0
  })
  watch(auto, schedule)
  watch(interval, value => {
    if (!refreshIntervals.includes(value)) { interval.value = 30; return }
    try { localStorage.setItem(preference, String(value)) } catch { /* Browser storage may be disabled. */ }
    schedule()
  })
  onMounted(() => {
    try { const saved = Number(localStorage.getItem(preference)); if (refreshIntervals.includes(saved)) interval.value = saved } catch { /* Keep the default. */ }
    document.addEventListener('visibilitychange', visibility)
    timer = setInterval(() => {
      now.value = Date.now()
      if (nextAt.value && now.value >= nextAt.value && auto.value && ready.value && !changed.value && !hidden.value && !scope.loading.value) void load(true)
    }, 1000)
  })
  onUnmounted(() => { disposed = true; stop(); clearInterval(timer); document.removeEventListener('visibilitychange', visibility) })
  return { draft, items, queried, attempted, ready, loading: scope.loading, error: scope.error, changed,
    auto, interval, countdown, lastUpdated, hidden, cursor, next, previous, detail, checked, submit, page, refresh }
}
