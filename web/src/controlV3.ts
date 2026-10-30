// v3 transport contract. The released v2 console keeps its existing API until
// all business domains and the verified migration are ready for cutover.
import { queryParams, type Site } from './api'
import { readWithReconnect } from './connection'

export type V3Role = 'admin' | 'operator' | 'viewer'
export interface V3Session { username: string; role: V3Role; csrf: string }
export interface V3Node {
  id: string; name: string; endpoint: string; server_name: string
  enabled: boolean; mode: 'native' | 'docker'
  version: number; applied_version: number; shard: number
  configuration?: { registered_version: number; delivered_version: number; runtime_enabled: boolean | null; runtime_mode: string; runtime_endpoint: string }
}
export type V3NodeInput = Omit<V3Node, 'version' | 'applied_version' | 'shard' | 'configuration'>
export interface V3Page<T> { items: T[]; next_cursor: string }
export interface V3ServerDetail {
  node: V3Node
  status: null | { sampled_at: number | null; updated_at: string; error: string; metrics_error: string; events_error: string; protocol_error: string
    metrics: Record<'cpu_percent' | 'memory_percent' | 'disk_percent' | 'uptime', number | null>
    info: Record<'hostname' | 'kernel' | 'architecture' | 'agent_version' | 'agent_mode', string | null> }
  latest_deployment: V3DeploymentJob | null
}
export interface V3Event {
  node: string; id: string; received_at: string; payload: Record<string, unknown>
  source: 'events' | 'migrated_events'; record_key: string; can_delete: boolean; delete_reason: string
}
export interface V3EventFilter {
  node?: string; operation?: string; q?: string; include_probes?: boolean
  start?: string; end?: string; cursor?: string; limit?: number
}
export interface V3EventPage extends V3Page<V3Event> { start: string; end: string }
export interface V3Availability { available: boolean; reason: string }
export interface V3Capabilities {
 settings?: V3Availability; deployments?: V3Availability; executor?: V3Availability; version?: string
  deployment_defaults?: { central: 'docker'; node: 'docker'; node_modes: ('docker' | 'native')[] }; configuration_application_writes?: boolean; api_version: 3; topology: 'single' | 'ha'; features: string[]; implementation_stage: string
}
export interface V3DashboardSection<T> { data: T | null; updated_at: string | null; error: string }
export interface V3DashboardCounts { applicable: number; normal: number; abnormal: number; unknown: number }
export interface V3DashboardResource {
  id: string; name: string; mode: string; actual_mode: string | null; agent_version: string | null
  sampled_at: number | null; cpu_percent: number | null; memory_percent: number | null; disk_percent: number | null; has_error: boolean
}
export interface V3Dashboard {
  version: string; started_at: string; updated_at: string; stale: boolean; error: string
  summary: { sections?: {
    servers?: V3DashboardSection<{ servers: number; enabled: number; fresh: number; abnormal: number; unknown: number }>
    websites?: V3DashboardSection<V3WebsiteOverview>
    events?: V3DashboardSection<{ total: number; security: number }>
    notifications?: V3DashboardSection<Record<'feishu' | 'email', { enabled: boolean; pending: number; retrying: number; oldest_wait_seconds: number | null }>>
    deployments?: V3DashboardSection<{ running: number; recovery_required: number; latest: null | { id: string; node: string; status: string; updated_at: string } }>
    alerts?: V3DashboardSection<{ total: number; items: { source: 'server' | 'website'; id: string; node: string; name: string; kind: string; since: string; website: string | null }[] }>
    resources?: V3DashboardSection<{ items: V3DashboardResource[]; rankings: Record<'cpu_percent' | 'memory_percent' | 'disk_percent', { id: string; name: string; value: number }[]> }>
    monitoring?: V3DashboardSection<{ states: Partial<Record<'files' | 'scans' | 'delivery', V3DashboardCounts>> | null; pending_events: number | null; oldest_wait_seconds: number | null; pending_scans: number | null; yara_nodes: number; clamav_nodes: number }>
    services?: V3DashboardSection<{ database_bytes: number; roles: Record<string, { heartbeat: string; healthy: boolean; has_error: boolean }>; last_cleanup: null | { status: string; deleted: number; updated_at: string } }>
  } }
}
export interface V3Site extends Site { version: number; migration_pending?: boolean }
export interface V3SiteInput {
  id: number; name: string; url: string; node: string; keyword: string
  slow_alert: boolean; paused: boolean
}
export interface V3SiteFilter { q?: string; node?: string; status?: '' | 'normal' | 'down' | 'pending' | 'paused' | 'unknown' | 'migration_pending'; cursor?: string; limit?: number }
export interface V3SiteVersion { id: number; version: number }
export interface V3WebsiteBackupDocument { format_version: 1; created_at: string; websites: Omit<V3SiteInput, 'id'>[] }
export interface V3WebsiteBackup {
  id: string; record_key: string; created_at: string; source: string; count: number
  restored_at: string | null; result: Record<string, unknown>; can_delete: boolean; delete_reason: string
}
export interface V3WebsiteBackupPreview {
  added: number; updated: number; unchanged: number; unknown_nodes: string[]; token?: string; before_backup?: string
}
export interface V3SiteIncident {
  id: number; site: number; site_name?: string; node?: string; kind: string; started: number; ended: number | null; reason: string
  record_key: string; can_delete: boolean; delete_reason: string
}
export interface V3WebsiteOverview {
  total: number; normal: number; down: number; pending: number; paused: number
  migration_pending: number; unknown: number; due: number
  notification_outbox: { pending: number; oldest_wait_seconds: number | null }
  notification_worker: { heartbeat: string | null; healthy: boolean | null }
  scheduler: { heartbeat: string | null; healthy: boolean | null }
}
export interface V3DeploymentPreview {
 token: string; node: string; kind: 'install' | 'upgrade'; version: number; applied_version: number
 target: { release: string; sha256: string; mode: string }; current?: { release: string; sha256: string; mode: string }
 comparison: string; expires_at: string
}
export interface V3Preparation {
 id: string; node: string; version?: number; kind: string; phase: string
 status: 'queued' | 'running' | 'succeeded' | 'failed' | 'expired'; error_code?: string; expires_at?: string
 result?: { host?: string; port?: number; fingerprint?: string; fingerprint_token?: string; configured?: boolean; preview?: V3DeploymentPreview; job?: string }
}
export interface V3SSHInput {
 expected_version: number; ssh_port: number; fingerprint_preparation: string; fingerprint_token: string
 password?: string; private_key_content?: string; private_key_path?: string
}
export interface V3DeploymentJob {
  id: string; node: string; username: string; kind: 'install' | 'upgrade' | 'recover'
  status: 'queued' | 'running' | 'failed' | 'interrupted' | 'succeeded' | 'rolled_back'
  direction: 'forward' | 'rollback'; node_version: number; plan_digest: string
  step: number; rollback_step: number; recovery_required: boolean; error_code: string; log_cursor: number
  created_at: string; updated_at: string; finished_at: string | null
}
export interface V3DeploymentLog { cursor: number; phase: string; code: string; created_at: string }
export interface V3DeploymentDetail {
  job: V3DeploymentJob; phase: string; can_resume: boolean; can_rollback: boolean
  recovery_required: boolean; recovery_reason: string
}
export interface V3HealthState {
  key: string; node: string; kind: string; phase: 'normal' | 'pending' | 'firing' | 'disabled'
  since: number; last: number; recovery: number; reminder: number; message: string; severity: string
}
export interface V3HealthRecord {
  id: string; node: string; kind: string; phase: 'firing' | 'resolved' | 'reminder'
  time: number; message: string; state: V3HealthState
  record_key: string; can_delete: boolean; delete_reason: string
}
export interface V3HealthFilter {
  node?: string; phase?: '' | 'firing' | 'resolved' | 'reminder'
  start?: string; end?: string; cursor?: string; limit?: number
}
export interface V3RetentionPolicy {
  sqlite_events_days: number; security_events_days: number; website_incidents_days: number
  server_alerts_days: number; delivery_records_days: number
}
export interface V3RetentionPolicyView { version: number; policy: V3RetentionPolicy; updated_at: string }
export interface V3RetentionJob {
  id: string; settings_version: number; policy: V3RetentionPolicy
  status: 'running' | 'succeeded' | 'cancelled'; stage: number
  scanned: number; deleted: number; protected: number; dependent_deleted: number; message: string
  created_at: string; updated_at: string; finished_at: string | null
}
export interface V3RetentionStatus {
  policy: V3RetentionPolicyView; last_job: V3RetentionJob | null; managed_storage_bytes: number
  worker_heartbeat: string | null; worker_healthy: boolean | null; reason: string
}
export type V3HistoryCategory = 'events' | 'security-events' | 'website-incidents' | 'server-alerts' | 'feishu' | 'email'
export interface V3HistoryScope {
  categories: V3HistoryCategory[]; node?: string; before?: string; records?: string[]; include_probes?: boolean
}
export interface V3HistoryPreview {
  token: string; scope: V3HistoryScope; settings_version: number; eligible: number; protected: number; expires_at: string
}
export interface V3HistoryJob {
  id: string; username: string; kind: 'export' | 'cleanup'; export_first: boolean; settings_version: number; cutoff: string
  phase: 'export' | 'cleanup' | 'finished'; status: 'queued' | 'running' | 'succeeded' | 'partial' | 'cancelled' | 'failed'
  scanned: number; deleted: number; skipped: number; dependent_deleted: number; exported: number; export_bytes: number
  export_ready: boolean; export_expires_at: string | null; message: string
  created_at: string; updated_at: string; finished_at: string | null
}
export interface V3IncidentFilter { node?: string; current?: boolean; start?: string; end?: string }
export interface V3Notification {
  id: string; node: string; event_id: string; channel: 'feishu' | 'email'; recipient: string
  created_at: string; done_at: string | null; attempts: number; state?: 'completed' | 'migration_pending' | 'paused' | 'sending' | 'waiting' | 'retrying' | 'pending'; next_try?: string | null; record_key: string; can_delete: boolean; delete_reason: string
}
export interface V3NotificationFilter {
  channel: V3Notification['channel']; node?: string; state?: '' | 'pending' | 'completed'
  start?: string; end?: string; cursor?: string; limit?: number
}
export interface V3AuditRecord {
  id: string; username: string; kind: string; resource: string; result: Record<string, unknown>; created_at: string
  record_key: string; can_delete: false; delete_reason: string
}
export interface V3AuditFilter { actor?: string; kind?: string; start?: string; end?: string; cursor?: string; limit?: number }
export class V3Error extends Error {
  constructor(public status: number, public code: string, message: string) { super(message) }
}

export interface V3ConfigurationBackup {
  id: string; record_key: string; created_at: string; source: string; document_created_at: string
  settings_version: number; node_count: number; needs_completion: boolean; can_delete: boolean; delete_reason: string
}

export interface V3ConfigurationRestoreSummary {
  settings_changed: boolean; bootstrap_changed: boolean; sections: string[]
  added: number; updated: number; unchanged: number; removed: number
  nodes: { node: string; action: string; fields: string[] }[]
  credentials_kept: number; credentials_replaced: number; credentials_missing: number
  missing_nodes: string[]; missing_settings: boolean; missing_bootstrap: boolean
  requires_center_restart: boolean; requires_local_validation: boolean; blocked_reasons: string[]; can_prepare: boolean
}
export interface V3ConfigurationRestorePreview { token: string; backup: string; expires_at: string; summary: V3ConfigurationRestoreSummary }
export interface V3ConfigurationRestoreStage {
  id: string; username: string; backup: string; before_backup: string; settings_version: number
  status: 'pending_validation' | 'pending_application' | 'saved' | 'cancelled'; message: string
  created_at: string; updated_at: string; finished_at: string | null; cancelled_by: string
  application?: V3ConfigurationApplication
}
export interface V3ConfigurationApplication {
  id: string; stage: string; username: string; controller: string; generation: string
  status: 'queued' | 'running' | 'failed' | 'succeeded' | 'rolled_back' | 'cancelled'
  direction: 'forward' | 'rollback'; phase: string; recovery_required: boolean; recovery_hold: boolean
  error_code: string; log_cursor: string; created_at: string; updated_at: string; finished_at: string | null
}
export interface V3ConfigurationApplicationActions { can_resume: boolean; can_rollback: boolean; can_cancel: boolean }
export type V3ConfigurationApplicationAction = 'resume' | 'rollback' | 'cancel'
export interface V3ConfigurationApplicationLog {
  cursor: string; direction: 'forward' | 'rollback'; phase: string; code: string; created_at: string
}
export interface V3ConfigurationRevision {
  id: string; generation: string; stage: string; username: string; base_settings_version: number
  status: 'pending_application' | 'saved' | 'cancelled'; message: string
  created_at: string; updated_at: string; finished_at: string | null
}
export interface V3ConfigurationRestoreDetail {
  stage: V3ConfigurationRestoreStage; summary: V3ConfigurationRestoreSummary; revision: V3ConfigurationRevision | null
  can_continue: boolean; can_cancel: boolean; can_apply?: boolean
}
export interface V3ConfigurationLocalReport {
  checked_at: string; checks: { component: string; status: string; reason: string }[]
  local_checks_passed: boolean; requires_apply_checks: boolean
}
export interface V3ConfigurationSavedReceipt {
  stage: string; revision: string; generation: string; nodes_changed: number; requires_center_restart: boolean
  status: 'saved_pending_application'; message: string; created_at: string
}

export interface V3ConfigurationDeleteItem {
  id: string; record_key: string; status: 'eligible' | 'protected' | 'pending' | 'deleted' | 'skipped' | 'failed'; reason: string
}
export interface V3ConfigurationDeletePreview {
  token: string; settings_version: number; eligible: number; protected: number; expires_at: string; items: V3ConfigurationDeleteItem[]
}
export interface V3ConfigurationDeleteJob {
  id: string; username: string; settings_version: number; selected: number
  status: 'queued' | 'running' | 'succeeded' | 'partial' | 'cancelled'
  deleted: number; skipped: number; failed: number; message: string; created_at: string; updated_at: string; finished_at: string | null
}

export interface V3SettingsState { generation: string; applied_generation: string; runtime_version: number; pending: boolean; updated_at: string }
export interface V3SettingsField { path: string; label: string; kind: 'bool' | 'integer' | 'text' | 'choice' | 'addresses'; min?: number; max?: number; choices?: string[] }
export type V3SettingsValue = boolean | number | string | string[]
export interface V3SettingsEdit { values?: Record<string, V3SettingsValue>; secrets?: Record<string, { action: 'keep' | 'replace' | 'clear'; value?: string }> }
export interface V3SettingsView { state: V3SettingsState; fields: V3SettingsField[]; values: Record<string, V3SettingsValue>; runtime_values: Record<string, V3SettingsValue>; secret_configured: Record<string, boolean>; runtime_secret_configured: Record<string, boolean> }
export interface V3SettingsRequest { action: 'save' | 'apply'; expected_generation: string; expected_runtime_version: number; edit: V3SettingsEdit; preview?: string }
export interface V3SettingsPreview { token: string; action: 'save' | 'apply'; expires_at: string; changed_fields: string[]; retention_shortened: boolean; notifications_enabled: boolean }

export class ControlV3 {
  private csrf = ''
  constructor(private readonly unauthorized: () => void = () => {}) {}

  private async send<T>(path: string, method: string, body?: unknown, key?: string, signal?: AbortSignal, mode: 'json' | 'jsonl' | 'file' = 'json', rawJSON = false, contentType = 'application/json'): Promise<T> {
    const control = new AbortController()
    const abort = () => control.abort(signal?.reason)
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) abort()
    const timer = setTimeout(() => control.abort(), mode === 'jsonl' ? 120_000 : 30_000)
    try {
      let response: Response
      try {
        response = await fetch(`/api/v3/${path}`, {
          method, credentials: 'same-origin', signal: control.signal,
          headers: { ...(body instanceof FormData ? {} : { 'Content-Type': contentType }), 'X-CSRF-Token': this.csrf, ...(key ? { 'Idempotency-Key': key } : {}) },
          body: body === undefined ? undefined : body instanceof FormData ? body : rawJSON ? String(body) : JSON.stringify(body),
        })
      } catch (error) {
        if (signal?.aborted) throw error
        throw new V3Error(0, 'connection_unavailable', '管理后台暂时无法连接，请稍后重试')
      }
      if (!response.ok) {
        const data = await response.json().catch(() => null)
        if (response.status === 401 && path !== 'login') this.unauthorized()
        throw new V3Error(response.status, data?.code || 'request_failed', data?.message || `请求失败（${response.status}）`)
      }
      if (mode === 'jsonl' || mode === 'file') {
        try {
          const file = await response.blob()
          const bytes = response.headers.get('Content-Length')
          if (response.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== (mode === 'jsonl' ? 'application/x-ndjson' : 'application/octet-stream')
            || mode === 'file' && (!file.size || file.size > 34 * 1024 * 1024)
            || bytes !== null && (!/^\d+$/.test(bytes) || Number(bytes) !== file.size)) throw new Error('incomplete')
          return file as T
        } catch (error) {
          if (signal?.aborted) throw error
          throw new V3Error(503, 'invalid_export', '导出下载未完成，请重新下载')
        }
      }
      const data = await response.json().catch(() => null)
      if (data === null) throw new V3Error(503, 'invalid_response', '管理后台返回内容无效')
      return data as T
    } finally {
      clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
    }
  }

  private read<T>(path: string, signal?: AbortSignal): Promise<T> {
    return readWithReconnect(signal => this.send<T>(path, 'GET', undefined, undefined, signal),
      error => error instanceof V3Error && [0, 502, 503, 504].includes(error.status), false, signal)
  }
  async login(username: string, password: string) {
    const data = await this.send<{ csrf: string }>('login', 'POST', { username, password })
    this.csrf = data.csrf
  }
  async session() {
    const session = await this.read<V3Session>('session')
    this.csrf = session.csrf
    return session
  }
  async logout() {
    await this.send('logout', 'POST')
    this.csrf = ''
  }
  capabilities() { return this.read<V3Capabilities>('capabilities') }
  dashboard(signal?: AbortSignal) { return this.read<V3Dashboard>('dashboard', signal) }
  settings(signal?: AbortSignal) { return this.read<V3SettingsView>('settings', signal) }
  previewSettings(input: V3SettingsRequest) { return this.send<V3SettingsPreview>('settings/preview', 'POST', input) }
  confirmSettings(input: V3SettingsRequest, idempotencyKey: string) { return this.send<V3SettingsState>('settings/confirm', 'POST', input, idempotencyKey) }
  retentionPolicy(signal?: AbortSignal) { return this.read<V3RetentionPolicyView>('retention/policy', signal) }
  retentionStatus(signal?: AbortSignal) { return this.read<V3RetentionStatus>('retention/status', signal) }
  retentionJobs(cursor = '', limit = 20, signal?: AbortSignal) {
    return this.read<V3Page<V3RetentionJob> & { limit: number }>(`retention/jobs?${queryParams({ cursor, limit })}`, signal)
  }
  previewHistory(scope: V3HistoryScope) {
    if (scope.records && (!scope.records.length || scope.records.length > 200 || new Set(scope.records).size !== scope.records.length)) {
      throw new Error('请选择当前页的 1～200 条历史记录，不能重复选择')
    }
    return this.send<V3HistoryPreview>('retention/preview', 'POST', scope)
  }
  exportHistory(token: string, idempotencyKey: string) {
    return this.send<V3HistoryJob>('retention/export', 'POST', { token }, idempotencyKey)
  }
  cleanupHistory(token: string, options: { export_first: boolean; confirm_without_export: boolean }, idempotencyKey: string) {
    return this.send<V3HistoryJob>('retention/cleanup', 'POST', { token, ...options }, idempotencyKey)
  }
  historyJobs(cursor = '', limit = 20, signal?: AbortSignal) {
    return this.read<V3Page<V3HistoryJob> & { kind: 'manual' }>(`retention/jobs?${queryParams({ kind: 'manual', cursor, limit })}`, signal)
  }
  async historyJob(id: string, signal?: AbortSignal) {
    const value = await this.read<{ job: V3HistoryJob; scope: V3HistoryScope } | { kind: 'automatic'; job: V3RetentionJob }>(`retention/jobs/${encodeURIComponent(id)}`, signal)
    if ('kind' in value) throw new V3Error(409, 'automatic_history_job', '此任务为自动清理，请在自动清理记录中查看')
    return value
  }
  downloadHistory(id: string, signal?: AbortSignal) {
    // A download is audited once and must finish in full; it is not silently
    // replayed by the normal JSON read/reconnect loop.
    return this.send<Blob>(`retention/jobs/${encodeURIComponent(id)}/download`, 'GET', undefined, undefined, signal, 'jsonl')
  }
  notifications(filter: V3NotificationFilter, signal?: AbortSignal) {
    return this.read<V3Page<V3Notification> & { start: string; end: string }>(`notifications?${queryParams({ ...filter })}`, signal)
  }
  audit(filter: V3AuditFilter = {}, signal?: AbortSignal) {
    return this.read<V3Page<V3AuditRecord> & { start: string; end: string }>(`audit?${queryParams({ ...filter })}`, signal)
  }
  saveRetentionPolicy(policy: V3RetentionPolicy, expectedVersion: number, idempotencyKey: string) {
    return this.send<{ version: number; policy: V3RetentionPolicy; shortened: boolean; message: string }>(
      'retention/policy', 'PUT', { policy, expected_version: expectedVersion }, idempotencyKey)
  }
  servers(q = '', cursor = '', limit = 50, signal?: AbortSignal) {
    return this.read<V3Page<V3Node> & { limit: number }>(`servers?${queryParams({ q, cursor, limit })}`, signal)
  }
  server(id: string, signal?: AbortSignal) { return this.read<V3ServerDetail>(`servers/${encodeURIComponent(id)}`, signal) }
  // Callers keep the same key for an explicitly retried operation. Writes are
  // never replayed by the reconnect loop or combined with unsaved form state.
  saveServer(node: V3NodeInput, expectedVersion: number, idempotencyKey: string) {
    return this.send<{ id: string; version: number; message: string }>('servers', 'POST', { node, expected_version: expectedVersion }, idempotencyKey)
  }
  sshCredential(id: string, signal?: AbortSignal) { return this.read<{ configured: boolean; version: number; ssh_port: number; fingerprint: string }>(`servers/${encodeURIComponent(id)}/ssh-credential`, signal) }
  sshFingerprint(id: string, version: number, port: number, key: string) { return this.send<V3Preparation>(`servers/${encodeURIComponent(id)}/ssh-fingerprint`, 'POST', { expected_version: version, ssh_port: port }, key) }
  saveSSHCredential(id: string, input: V3SSHInput, key: string) { return this.send<V3Preparation>(`servers/${encodeURIComponent(id)}/ssh-credential`, 'POST', input, key) }
  prepareDeployment(id: string, version: number, kind: 'install' | 'upgrade', key: string) { return this.send<V3Preparation>(`servers/${encodeURIComponent(id)}/deployment-preview`, 'POST', { expected_version: version, kind }, key) }
  deploymentPreparation(id: string, signal?: AbortSignal) { return this.read<V3Preparation>(`deployment-preparations/${encodeURIComponent(id)}`, signal) }
  confirmDeployment(preparation: string, preview: V3DeploymentPreview, key: string) { return this.send<V3Preparation>('deployments', 'POST', { expected_version: preview.version, preparation, preview_token: preview.token }, key) }
  recoverDeployment(id: string, action: 'resume' | 'rollback', plan: string, cursor: number, key: string) { return this.send<{ id: string; status: string }>(`deployments/${encodeURIComponent(id)}/${action}`, 'POST', { plan_digest: plan, log_cursor: cursor }, key) }
  events(filter: V3EventFilter, signal?: AbortSignal, reconnect = true) {
    const path = `events?${queryParams({ ...filter })}`
    return reconnect ? this.read<V3EventPage>(path, signal) : this.send<V3EventPage>(path, 'GET', undefined, undefined, signal)
  }
  websites(filter: V3SiteFilter = {}, signal?: AbortSignal) {
    return this.read<V3Page<V3Site> & { limit: number }>(`websites?${queryParams({ ...filter })}`, signal)
  }
  website(id: number, signal?: AbortSignal) { return this.read<V3Site>(`websites/${id}`, signal) }
  websiteBackups(cursor = '', limit = 20, signal?: AbortSignal) {
    return this.read<V3Page<V3WebsiteBackup>>(`website-backups?${queryParams({ cursor, limit })}`, signal)
  }
  configurationBackups(cursor = '', limit = 20, signal?: AbortSignal) {
    return this.read<V3Page<V3ConfigurationBackup> & { restore_available: false; saved_restore_available?: boolean; delete_available: boolean }>(`configuration-backups?${queryParams({ cursor, limit })}`, signal)
  }
  configurationRestores(cursor = '', limit = 20, signal?: AbortSignal) {
    return this.read<V3Page<V3ConfigurationRestoreStage>>(`configuration-restores?${queryParams({ cursor, limit })}`, signal)
  }
  configurationRestore(id: string, signal?: AbortSignal) {
    return this.read<V3ConfigurationRestoreDetail>(`configuration-restores/${encodeURIComponent(id)}`, signal)
  }
  previewConfigurationRestore(id: string, useBackupCredentials: boolean, signal?: AbortSignal) {
    return this.send<V3ConfigurationRestorePreview>(`configuration-backups/${encodeURIComponent(id)}/restore-preview`, 'POST', { use_backup_credentials: useBackupCredentials }, undefined, signal)
  }
  stageConfigurationRestore(preview: string, key: string, signal?: AbortSignal) {
    return this.send<V3ConfigurationRestoreStage>('configuration-restores', 'POST', { preview, confirm: true }, key, signal)
  }
  checkConfigurationRestore(id: string, key: string, signal?: AbortSignal) {
    return this.send<V3ConfigurationLocalReport>(`configuration-restores/${encodeURIComponent(id)}/check`, 'POST', {}, key, signal)
  }
  prepareConfigurationRestore(id: string, key: string, signal?: AbortSignal) {
    return this.send<V3ConfigurationRevision>(`configuration-restores/${encodeURIComponent(id)}/prepare`, 'POST', {}, key, signal)
  }
  commitConfigurationRestore(id: string, generation: string, key: string, signal?: AbortSignal) {
    return this.send<V3ConfigurationSavedReceipt>(`configuration-restores/${encodeURIComponent(id)}/commit`, 'POST', { generation, confirm: true }, key, signal)
  }
  cancelConfigurationRestore(id: string, key: string, signal?: AbortSignal) {
    return this.send<V3ConfigurationRestoreStage>(`configuration-restores/${encodeURIComponent(id)}/cancel`, 'POST', { confirm: true }, key, signal)
  }
  previewConfigurationDelete(records: string[], signal?: AbortSignal) {
    return this.send<V3ConfigurationDeletePreview>('configuration-backups/delete-preview', 'POST', { records }, undefined, signal)
  }
  deleteConfigurationBackups(token: string, key: string, signal?: AbortSignal) {
    return this.send<V3ConfigurationDeleteJob>('configuration-backups/delete', 'POST', { token, confirm: true }, key, signal)
  }
  configurationDeleteJobs(cursor = '', limit = 20, signal?: AbortSignal) {
    return this.read<V3Page<V3ConfigurationDeleteJob>>(`configuration-backups/delete-jobs?${queryParams({ cursor, limit })}`, signal)
  }
  configurationDeleteJob(id: string, signal?: AbortSignal) {
    return this.read<{ job: V3ConfigurationDeleteJob; items: V3ConfigurationDeleteItem[] }>(`configuration-backups/delete-jobs/${encodeURIComponent(id)}`, signal)
  }
  createConfigurationBackup(key: string, signal?: AbortSignal) {
    return this.send<V3ConfigurationBackup>('configuration-backups', 'POST', {}, key, signal)
  }
  importConfigurationBackup(document: string, key: string, signal?: AbortSignal) {
    if (!document.trim() || new TextEncoder().encode(document).byteLength > 32 * 1024 * 1024) throw new Error('请选择非空且不超过 32 MiB 的 v3 YAML')
    return this.send<V3ConfigurationBackup>('configuration-backups/import', 'POST', document, key, signal, 'json', true, 'application/yaml')
  }
  importEncryptedConfigurationBackup(file: File, password: string, key: string, signal?: AbortSignal) {
    if (!file.size || file.size > 34 * 1024 * 1024) throw new Error('请选择非空且不超过 34 MiB 的 age 备份')
    const bytes = new TextEncoder().encode(password).byteLength
    if (bytes < 12 || bytes > 1024) throw new Error('密码须为 12～1024 字节')
    const form = new FormData(); form.append('file', file); form.append('password', password)
    return this.send<V3ConfigurationBackup>('configuration-backups/import-age', 'POST', form, key, signal)
  }
  exportConfigurationBackup(id: string, signal?: AbortSignal) {
    return this.send<Blob>(`configuration-backups/${encodeURIComponent(id)}/export`, 'GET', undefined, undefined, signal, 'file')
  }
  exportEncryptedConfigurationBackup(id: string, password: string, confirm: string, signal?: AbortSignal) {
    const bytes = new TextEncoder().encode(password).byteLength
    if (bytes < 12 || bytes > 1024 || password !== confirm) throw new Error('密码须为 12～1024 字节且两次输入一致')
    return this.send<Blob>(`configuration-backups/${encodeURIComponent(id)}/export-age`, 'POST', { password, confirm }, undefined, signal, 'file')
  }
  createWebsiteBackup(idempotencyKey: string) {
    return this.send<{ id: string; count: number; source: string }>('website-backups', 'POST', {}, idempotencyKey)
  }
  importWebsiteBackup(document: V3WebsiteBackupDocument, idempotencyKey: string) {
    return this.send<{ id: string; count: number; source: string }>('website-backups/import', 'POST', document, idempotencyKey)
  }
  importWebsiteBackupText(document: string, idempotencyKey: string) {
    if (!document.trim() || new TextEncoder().encode(document).byteLength > 2 * 1024 * 1024) throw new Error('请选择非空且不超过 2 MiB 的网站备份 JSON')
    // Preserve duplicate keys for server-side rejection. Parsing and reserializing
    // an untrusted document here would silently turn last-key-wins into valid input.
    return this.send<{ id: string; count: number; source: string }>('website-backups/import', 'POST', document, idempotencyKey, undefined, 'json', true)
  }
  exportWebsiteBackup(id: string, signal?: AbortSignal) {
    return this.read<V3WebsiteBackupDocument>(`website-backups/${encodeURIComponent(id)}/export`, signal)
  }
  previewWebsiteBackup(id: string) {
    return this.send<V3WebsiteBackupPreview>(`website-backups/${encodeURIComponent(id)}/preview`, 'POST', {})
  }
  restoreWebsiteBackup(id: string, token: string, idempotencyKey: string) {
    return this.send<V3WebsiteBackupPreview>(`website-backups/${encodeURIComponent(id)}/restore`, 'POST', { token }, idempotencyKey)
  }
  deleteWebsiteBackups(records: string[], idempotencyKey: string) {
    if (!records.length || records.length > 200 || new Set(records).size !== records.length || records.some(id => !/^[a-f0-9]{64}$/.test(id))) {
      throw new Error('请明确选择 1～200 个不重复的当前页备份')
    }
    return this.send<{ deleted: number; skipped: { id: string; reason: string }[]; message: string }>(
      'website-backups/delete', 'POST', { records }, idempotencyKey)
  }
  saveWebsite(site: V3SiteInput, expectedVersion: number, idempotencyKey: string) {
    return this.send<{ id: number; version: number; message: string }>(site.id === 0 ? 'websites' : `websites/${site.id}`,
      site.id === 0 ? 'POST' : 'PUT', { site, expected_version: expectedVersion }, idempotencyKey)
  }
  deleteWebsites(records: V3SiteVersion[], idempotencyKey: string) {
    if (records.length < 1 || records.length > 200 || new Set(records.map(record => record.id)).size !== records.length)
      throw new V3Error(400, 'invalid_selection', '请明确选择 1～200 个当前页网站，不能重复选择')
    return this.send<{ deleted: number; message: string }>('websites/delete', 'POST', { records }, idempotencyKey)
  }
  checkWebsite(id: number, expectedVersion: number, idempotencyKey: string) {
    return this.send<{ id: number; message: string }>(`websites/${id}/check`, 'POST', { expected_version: expectedVersion }, idempotencyKey)
  }
  deployments(node = '', cursor = '', limit = 20, signal?: AbortSignal) {
    return this.read<V3Page<V3DeploymentJob> & { limit: number }>(`deployments?${queryParams({ node, cursor, limit })}`, signal)
  }
  configurationApplications(stage = '', cursor = '', limit = 20, signal?: AbortSignal) {
    return this.read<V3Page<V3ConfigurationApplication>>(`configuration-applications?${queryParams({ stage, cursor, limit })}`, signal)
  }
  configurationApplication(id: string, signal?: AbortSignal) {
    return this.read<{ job: V3ConfigurationApplication; can_resume: boolean; can_rollback: boolean; can_cancel: boolean }>(
      `configuration-applications/${encodeURIComponent(id)}`, signal)
  }
  configurationApplicationLogs(id: string, after = '0', limit = 100, signal?: AbortSignal) {
    if (!/^(0|[1-9][0-9]{0,18})$/.test(after) || BigInt(after) > 9223372036854775807n) throw new Error('配置应用日志游标不正确')
    return this.read<{ items: V3ConfigurationApplicationLog[]; next_cursor: string; job: V3ConfigurationApplication } & Partial<V3ConfigurationApplicationActions>>(
      `configuration-applications/${encodeURIComponent(id)}/logs?${queryParams({ after, limit })}`, signal)
  }
  queueConfigurationApplication(stage: string, generation: string, key: string, signal?: AbortSignal) {
    this.applicationVersion(generation)
    return this.send<V3ConfigurationApplication>('configuration-applications', 'POST', { stage, generation, confirm: true }, key, signal)
  }
  controlConfigurationApplication(id: string, action: V3ConfigurationApplicationAction, expectedLogCursor: string, key: string, signal?: AbortSignal) {
    this.applicationVersion(expectedLogCursor)
    if (!['resume', 'rollback', 'cancel'].includes(action)) throw new Error('配置应用操作不正确')
    return this.send<V3ConfigurationApplication>(`configuration-applications/${encodeURIComponent(id)}/${action}`, 'POST', { expected_log_cursor: expectedLogCursor, confirm: true }, key, signal)
  }
  private applicationVersion(value: string) {
    if (!/^[1-9][0-9]{0,18}$/.test(value) || BigInt(value) > 9223372036854775807n) throw new Error('配置应用版本不正确，请重新读取任务')
  }
  deployment(id: string, signal?: AbortSignal) { return this.read<V3DeploymentDetail>(`deployments/${encodeURIComponent(id)}`, signal) }
  deploymentLogs(id: string, after = 0, limit = 100, signal?: AbortSignal) {
    return this.read<{ items: V3DeploymentLog[]; next_cursor: number; status: V3DeploymentJob['status'] }>(
      `deployments/${encodeURIComponent(id)}/logs?${queryParams({ after, limit })}`, signal)
  }
  currentAlerts(node = '', cursor = '', limit = 20, signal?: AbortSignal) {
    return this.read<V3Page<V3HealthState>>(`alerts/current?${queryParams({ node, cursor, limit })}`, signal)
  }
  alertHistory(filter: V3HealthFilter = {}, signal?: AbortSignal) {
    return this.read<V3Page<V3HealthRecord> & { start: string; end: string }>(`alerts/history?${queryParams({ ...filter })}`, signal)
  }
  websiteOverview(signal?: AbortSignal) { return this.read<V3WebsiteOverview>('websites/overview', signal) }
  websiteIncidents(site?: number, cursor = '', limit = 20, filter: V3IncidentFilter = {}, signal?: AbortSignal) {
    return this.read<V3Page<V3SiteIncident>>(`${site === undefined ? 'incidents' : `websites/${site}/incidents`}?${queryParams({ cursor, limit, ...filter })}`, signal)
  }
}
