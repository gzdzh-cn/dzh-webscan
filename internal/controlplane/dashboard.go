package controlplane

import (
	"context"
	"encoding/json"
	"time"
)

// All expensive reads belong to the lease-owning summary worker. HTTP requests
// read only v3_dashboard, even with thousands of nodes or concurrent viewers.
type dashboardSection struct {
	Data      json.RawMessage `json:"data"`
	UpdatedAt *time.Time      `json:"updated_at"`
	Error     string          `json:"error"`
}

type dashboardSnapshot struct {
	// Keep the original v3 summary contract during the console transition.
	Servers       *int64                      `json:"servers"`
	Enabled       *int64                      `json:"enabled"`
	Fresh         *int64                      `json:"fresh"`
	Abnormal      *int64                      `json:"abnormal"`
	Unknown       *int64                      `json:"unknown"`
	CurrentAlerts *int64                      `json:"current_alerts"`
	PendingAlerts *int64                      `json:"pending_alerts"`
	Sections      map[string]dashboardSection `json:"sections"`
}

// Each successful section has its own observation time. A failed read retains
// only that section's prior data/time and adds a fixed, credential-free error.
// A cold failure remains null; it must never be confused with an empty result.
func (s *Store) dashboardSnapshot(ctx context.Context, previous dashboardSnapshot, interval int) (dashboardSnapshot, error) {
	var err error
	interval, err = s.effectiveCollectorInterval(ctx, interval)
	if err != nil {
		return dashboardSnapshot{}, err
	}
	freshness := max(60, interval*3)
	out := dashboardSnapshot{Sections: map[string]dashboardSection{}}
	read := func(name string, fn func(context.Context) (json.RawMessage, error)) {
		op, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		defer cancel()
		data, err := fn(op)
		if err != nil {
			section := previous.Sections[name]
			section.Error = "本分区读取失败，保留上次数据；请稍后重试"
			out.Sections[name] = section
			return
		}
		at := time.Now().UTC()
		out.Sections[name] = dashboardSection{Data: data, UpdatedAt: &at}
	}
	query := func(sql string, args ...any) func(context.Context) (json.RawMessage, error) {
		return func(op context.Context) (json.RawMessage, error) {
			var raw json.RawMessage
			err := s.DB.QueryRowContext(op, sql, args...).Scan(&raw)
			return raw, err
		}
	}
	read("servers", func(op context.Context) (json.RawMessage, error) { return s.summaryWithFreshness(op, freshness) })
	read("websites", s.WebsiteSummary)
	read("events", query(`WITH visible AS (`+visibleEvents+`)
 SELECT jsonb_build_object('total',count(*),'security',count(*) FILTER(WHERE security))
 FROM visible WHERE operation<>'probe' AND received_at>=clock_timestamp()-interval '24 hours' AND received_at<=clock_timestamp()`))
	read("notifications", query(`SELECT jsonb_object_agg(channel,value) FROM (
 SELECT ch.channel,jsonb_build_object('enabled',COALESCE(s.payload->ch.channel->'enabled','false'::jsonb),
 'pending',count(n.id),'retrying',count(n.id) FILTER(WHERE n.attempts>0),
 'oldest_wait_seconds',CASE WHEN min(n.created_at) IS NULL THEN NULL ELSE greatest(0,floor(extract(epoch FROM clock_timestamp()-min(n.created_at)))) END) value
 FROM (VALUES('feishu'),('email')) ch(channel) CROSS JOIN v3_settings s
 LEFT JOIN v3_notifications n ON n.channel=ch.channel AND n.done_at IS NULL
 WHERE s.id=1 GROUP BY ch.channel,s.payload) t`))
	read("deployments", query(`SELECT jsonb_build_object('running',count(*) FILTER(WHERE status IN ('queued','running')),
 'recovery_required',count(*) FILTER(WHERE recovery_required AND status NOT IN ('succeeded','rolled_back')),
 'latest',(SELECT jsonb_build_object('id',id,'node',node,'status',status,'updated_at',updated_at) FROM v3_deployment_jobs d WHERE NOT EXISTS(SELECT 1 FROM v3_deployment_history_archives a WHERE a.deployment=d.id) ORDER BY created_at DESC,id DESC LIMIT 1)) FROM v3_deployment_jobs`))
	read("alerts", query(`WITH current AS (
 SELECT 'server'::text source,r.key id,r.node node,n.name name,r.kind kind,to_timestamp(r.since) since,NULL::text website
 FROM v3_health_rules r JOIN v3_active_nodes n ON n.id=r.node WHERE n.enabled AND r.phase='firing'
 UNION ALL SELECT 'website',i.id::text,w.node,w.name,i.kind,to_timestamp(i.started),w.id::text
 FROM v3_website_incidents i JOIN v3_websites w ON w.id=i.site WHERE i.ended IS NULL AND NOT w.deleted AND NOT w.paused AND NOT w.migration_pending)
 SELECT jsonb_build_object('total',(SELECT count(*) FROM current),'items',COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb))
 FROM (SELECT * FROM current ORDER BY since,id LIMIT 8) t`))
	// Deliberately select public metadata and named numeric values, not arbitrary
	// info/config/metric JSON which can contain paths, labels or private data.
	read("resources", query(`WITH resources AS (
 SELECT n.id,n.name,n.mode,s.sampled_at,s.info->>'agent_mode' actual_mode,s.info->>'agent_version' agent_version,
 CASE WHEN jsonb_typeof(s.metrics->'cpu_percent')='number' THEN s.metrics->'cpu_percent' END cpu_percent,
 CASE WHEN jsonb_typeof(s.metrics->'memory_percent')='number' THEN s.metrics->'memory_percent' END memory_percent,
 CASE WHEN jsonb_typeof(s.metrics->'disk_percent')='number' THEN s.metrics->'disk_percent' END disk_percent,
 COALESCE(s.error,'')<>'' has_error
 FROM v3_active_nodes n LEFT JOIN v3_node_status s ON s.node=n.id WHERE n.enabled)
 SELECT jsonb_build_object('items',(SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM (SELECT * FROM resources ORDER BY id LIMIT 20) t),
 'rankings',jsonb_build_object(
 'cpu_percent',(SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM (SELECT id,name,cpu_percent value FROM resources WHERE NOT has_error AND sampled_at>extract(epoch FROM clock_timestamp()-$1*interval '1 second')*1000 AND sampled_at<=extract(epoch FROM clock_timestamp()+interval '5 seconds')*1000 AND cpu_percent BETWEEN '0'::jsonb AND '100'::jsonb ORDER BY cpu_percent DESC,id LIMIT 10) t),
 'memory_percent',(SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM (SELECT id,name,memory_percent value FROM resources WHERE NOT has_error AND sampled_at>extract(epoch FROM clock_timestamp()-$1*interval '1 second')*1000 AND sampled_at<=extract(epoch FROM clock_timestamp()+interval '5 seconds')*1000 AND memory_percent BETWEEN '0'::jsonb AND '100'::jsonb ORDER BY memory_percent DESC,id LIMIT 10) t),
 'disk_percent',(SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM (SELECT id,name,disk_percent value FROM resources WHERE NOT has_error AND sampled_at>extract(epoch FROM clock_timestamp()-$1*interval '1 second')*1000 AND sampled_at<=extract(epoch FROM clock_timestamp()+interval '5 seconds')*1000 AND disk_percent BETWEEN '0'::jsonb AND '100'::jsonb ORDER BY disk_percent DESC,id LIMIT 10) t)))`, freshness))
	read("monitoring", query(`WITH applicable AS (
 SELECT n.id,n.config,s.sampled_at,s.metrics,s.events_error,
 s.sampled_at>extract(epoch FROM clock_timestamp()-$1*interval '1 second')*1000 AND s.sampled_at<=extract(epoch FROM clock_timestamp()+interval '5 seconds')*1000 fresh
 FROM v3_active_nodes n LEFT JOIN v3_node_status s ON s.node=n.id WHERE n.enabled), observations AS (
 SELECT 'files' kind,id,CASE WHEN NOT COALESCE(fresh,false) OR jsonb_typeof(metrics->'webscan_agent_heartbeat_seconds')<>'number' OR metrics->'webscan_agent_heartbeat_seconds' IS NULL OR jsonb_typeof(metrics->'webscan_coverage_ok')<>'number' OR metrics->'webscan_coverage_ok' IS NULL THEN NULL
 ELSE (metrics->>'webscan_agent_heartbeat_seconds')::numeric>extract(epoch FROM clock_timestamp()-$1*interval '1 second') AND (metrics->>'webscan_agent_heartbeat_seconds')::numeric<=extract(epoch FROM clock_timestamp()+interval '5 seconds') AND metrics->'webscan_coverage_ok'='1'::jsonb END healthy FROM applicable
 UNION ALL SELECT 'scans',id,CASE WHEN NOT COALESCE(fresh,false) OR jsonb_typeof(metrics->'webscan_scan_heartbeat_seconds')<>'number' OR metrics->'webscan_scan_heartbeat_seconds' IS NULL THEN NULL ELSE (metrics->>'webscan_scan_heartbeat_seconds')::numeric>extract(epoch FROM clock_timestamp()-interval '180 seconds') AND (metrics->>'webscan_scan_heartbeat_seconds')::numeric<=extract(epoch FROM clock_timestamp()+interval '5 seconds') END FROM applicable
 WHERE COALESCE(config#>'{scan,yara,enabled}','true'::jsonb)='true'::jsonb OR config#>'{scan,clamav,enabled}'='true'::jsonb
 UNION ALL SELECT 'delivery',id,CASE WHEN NOT COALESCE(fresh,false) THEN NULL WHEN events_error<>'' THEN false ELSE NULL END FROM applicable)
 SELECT jsonb_build_object('states',(SELECT jsonb_object_agg(kind,value) FROM (SELECT kind,jsonb_build_object('applicable',count(*),'normal',count(*) FILTER(WHERE healthy),'abnormal',count(*) FILTER(WHERE NOT healthy),'unknown',count(*) FILTER(WHERE healthy IS NULL)) value FROM observations GROUP BY kind) t),
 'pending_events',(SELECT sum((metrics->>'webscan_local_pending_events')::numeric) FILTER(WHERE fresh AND jsonb_typeof(metrics->'webscan_local_pending_events')='number') FROM applicable),
 'oldest_wait_seconds',(SELECT max((metrics->>'webscan_local_oldest_pending_seconds')::numeric) FILTER(WHERE fresh AND jsonb_typeof(metrics->'webscan_local_oldest_pending_seconds')='number') FROM applicable),
 'pending_scans',(SELECT sum((metrics->>'webscan_pending_scans')::numeric) FILTER(WHERE fresh AND jsonb_typeof(metrics->'webscan_pending_scans')='number') FROM applicable),
 'yara_nodes',(SELECT count(*) FROM applicable WHERE COALESCE(config#>'{scan,yara,enabled}','true'::jsonb)='true'::jsonb),
 'clamav_nodes',(SELECT count(*) FROM applicable WHERE config#>'{scan,clamav,enabled}'='true'::jsonb))`, freshness))
	read("host_watchdog", s.hostObservation)
	read("services", query(`SELECT jsonb_build_object(
 'database_bytes',(SELECT COALESCE(sum(pg_total_relation_size(oid)),0)::bigint FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN ('r','p') AND left(relname,3)='v3_'),
 'roles',COALESCE((SELECT jsonb_object_agg(role,value) FROM (
 SELECT DISTINCT ON(role) role,jsonb_build_object('heartbeat',heartbeat,'healthy',heartbeat>clock_timestamp()-interval '20 seconds' AND error='',
 'has_error',error<>'') value FROM v3_role_status WHERE role IN ('retention','executor','websites','website-notifications','server-health','notify-email','notify-feishu','notification-tests') AND COALESCE(details->>'state','active')<>'standby' ORDER BY role,heartbeat DESC) roles),'{}'::jsonb),
 'last_cleanup',(SELECT jsonb_build_object('status',status,'deleted',deleted,'updated_at',updated_at) FROM v3_retention_jobs ORDER BY created_at DESC,id DESC LIMIT 1))`))
	read("certificates", query(`SELECT jsonb_build_object('maintenance',(
 SELECT jsonb_build_object('heartbeat',heartbeat,
 'fresh',heartbeat>clock_timestamp()-interval '70 minutes' AND heartbeat<=clock_timestamp()+interval '5 seconds',
 'has_error',error<>'','reason',CASE WHEN error<>'' THEN '节点证书维护失败，请检查宿主维护回执和签发队列' ELSE '' END,
 'collector_expires_at',details->'collector_expires_at','ca_expires_at',details->'ca_expires_at')
 FROM v3_role_status WHERE role='pki-maintenance' ORDER BY heartbeat DESC LIMIT 1))`))
	read("full_backups", query(`SELECT jsonb_build_object('policy',(
 SELECT jsonb_build_object('enabled',enabled,'keep',policy#>'{policy,keep}') FROM v3_single_backup_policies ORDER BY created_at DESC LIMIT 1),
 'latest',(SELECT jsonb_build_object('status',status,'created_at',created_at,'updated_at',updated_at,
 'files',files,'bytes',bytes,'restore_validated',restore_validated,'has_error',reason<>'')
 FROM v3_single_backup_runs ORDER BY created_at DESC,id DESC LIMIT 1))`))
	if err := ctx.Err(); err != nil {
		return out, err
	}
	var legacy struct {
		Servers, Enabled, Fresh, Abnormal, Unknown *int64
		Current                                    *int64 `json:"current_alerts"`
		Pending                                    *int64 `json:"pending_alerts"`
	}
	if raw := out.Sections["servers"].Data; len(raw) != 0 && json.Unmarshal(raw, &legacy) == nil {
		out.Servers, out.Enabled, out.Fresh, out.Abnormal, out.Unknown = legacy.Servers, legacy.Enabled, legacy.Fresh, legacy.Abnormal, legacy.Unknown
		out.CurrentAlerts, out.PendingAlerts = legacy.Current, legacy.Pending
	}
	return out, nil
}
