package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// This is a public read model, separate from editable node configuration. Never
// serialize an arbitrary config/info/metric document into the console.
const consoleMetricNames = `ARRAY['cpu_percent','cpu_user_percent','cpu_system_percent','cpu_iowait_percent','cpu_cores','memory_total','memory_used','memory_available','memory_percent','swap_percent','load1','load5','load15','disk_percent','disk_read','disk_write','disk_read_iops','disk_write_iops','net_receive','net_transmit','net_receive_errors','net_transmit_errors','net_receive_drops','net_transmit_drops','uptime','webscan_watches','webscan_local_pending_events','webscan_pending_scans','webscan_agent_heartbeat_seconds','webscan_local_probe_seconds','webscan_probe_received_seconds','webscan_probe_query_seconds','webscan_local_oldest_pending_seconds','webscan_coverage_ok','webscan_scan_heartbeat_seconds']`
const consoleMetricPredicate = `(key=ANY(` + consoleMetricNames + `) OR key ~ '^(disk_percent|inode_percent|disk_read|disk_write|disk_read_iops|disk_write_iops|net_receive|net_transmit|net_receive_errors|net_transmit_errors|net_receive_drops|net_transmit_drops):[^[:cntrl:]]+$' AND length(key)<=285) AND jsonb_typeof(value)='number'`
const consoleCollectionStateSQL = `CASE WHEN c.enabled=false THEN 'disabled' WHEN c.node IS NULL OR s.sampled_at IS NULL THEN 'unknown' WHEN COALESCE(s.error,'')<>'' THEN 'unreachable' WHEN s.sampled_at>extract(epoch FROM clock_timestamp()+interval '5 seconds')*1000 THEN 'unknown' WHEN s.sampled_at<extract(epoch FROM clock_timestamp()-$4*interval '1 second')*1000 THEN 'stale' ELSE 'normal' END`
const consoleStatusSQL = `CASE WHEN s.node IS NULL THEN NULL ELSE jsonb_build_object(
 'sampled_at',s.sampled_at,'updated_at',s.updated_at,'error',s.error,'metrics_error',s.metrics_error,'events_error',s.events_error,'protocol_error',s.protocol_error,
 'metrics',COALESCE((SELECT jsonb_object_agg(key,value) FROM jsonb_each(s.metrics) WHERE ` + consoleMetricPredicate + `),'{}'::jsonb) || jsonb_build_object(
 'cpu_percent',CASE WHEN jsonb_typeof(s.metrics->'cpu_percent')='number' THEN s.metrics->'cpu_percent' END,
 'memory_percent',CASE WHEN jsonb_typeof(s.metrics->'memory_percent')='number' THEN s.metrics->'memory_percent' END,
 'disk_percent',CASE WHEN jsonb_typeof(s.metrics->'disk_percent')='number' THEN s.metrics->'disk_percent' END,
 'uptime',CASE WHEN jsonb_typeof(s.metrics->'uptime')='number' THEN s.metrics->'uptime' END),
 'info',jsonb_build_object('hostname',s.info->>'nodename','kernel',s.info->>'release','architecture',s.info->>'machine','agent_version',s.info->>'agent_version','agent_mode',s.info->>'agent_mode')) END`

func (s *Store) consoleNodes(ctx context.Context, after, keyword, state string, limit, interval int) ([]json.RawMessage, error) {
	var err error
	interval, err = s.effectiveCollectorInterval(ctx, interval)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > 200 {
		return nil, errors.New("每页数量须为 1～200")
	}
	switch state {
	case "", "normal", "unreachable", "stale", "unknown", "disabled":
	default:
		return nil, errors.New("采集状态不正确")
	}
	q := `WITH public_nodes AS (SELECT n.id, ` + consoleCollectionStateSQL + ` state, jsonb_build_object(
 'id',n.id,'name',n.name,'endpoint',n.endpoint,'server_name',n.server_name,'enabled',n.enabled,'mode',n.mode,'version',n.version,'applied_version',n.applied_version,'shard',n.shard,
 'configuration',jsonb_build_object('registered_version',COALESCE(c.version,0),'delivered_version',COALESCE(r.delivered_version,0),'runtime_enabled',c.enabled,'runtime_mode',COALESCE(c.mode,''),'runtime_endpoint',COALESCE(c.endpoint,'')),
 'status',` + consoleStatusSQL + `,'collection_state',` + consoleCollectionStateSQL + `,'can_remove',(` + nodeRemovalReasonSQL + `=''),'remove_reason',` + nodeRemovalReasonSQL + `) payload
 FROM ` + managedNodeRelations + ` LEFT JOIN v3_node_status s ON s.node=n.id WHERE n.id>$1 AND (n.name ILIKE $2 ESCAPE '\' OR n.id ILIKE $2 ESCAPE '\' OR n.endpoint ILIKE $2 ESCAPE '\'))
 SELECT payload FROM public_nodes WHERE ($3='' OR state=$3) ORDER BY id LIMIT $5`
	pattern := "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(keyword) + "%"
	rows, err := s.DB.QueryContext(ctx, q, after, pattern, state, max(60, interval*3), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}
