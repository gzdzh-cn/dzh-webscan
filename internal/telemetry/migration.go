package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
)

type HistoricalQuery struct{ Name, Expression, Dimension string }

var ErrQueryTooLarge = errors.New("历史查询响应超过 8 MiB")

var HistoricalQueries = []HistoricalQuery{
	{"cpu_user_percent", `100*avg by(node_id)(rate(node_cpu_seconds_total{mode="user"}[5m]))`, ""}, {"cpu_system_percent", `100*avg by(node_id)(rate(node_cpu_seconds_total{mode="system"}[5m]))`, ""}, {"cpu_iowait_percent", `100*avg by(node_id)(rate(node_cpu_seconds_total{mode="iowait"}[5m]))`, ""}, {"memory_used", `node_memory_MemTotal_bytes-node_memory_MemAvailable_bytes`, ""},
	{"collect_up", `up{job=~"webscan-node-.*|webscan-central-host"}`, ""},
	{"cpu_percent", `100*(1-avg by(node_id)(rate(node_cpu_seconds_total{mode="idle"}[5m])))`, ""},
	{"cpu_cores", `count by(node_id)(node_cpu_seconds_total{mode="idle"})`, ""},
	{"memory_total", "node_memory_MemTotal_bytes", ""}, {"memory_available", "node_memory_MemAvailable_bytes", ""}, {"memory_percent", `100*(1-node_memory_MemAvailable_bytes/node_memory_MemTotal_bytes)`, ""},
	{"swap_total", "node_memory_SwapTotal_bytes", ""}, {"swap_percent", `100*(1-node_memory_SwapFree_bytes/node_memory_SwapTotal_bytes)`, ""},
	{"load1", "node_load1", ""}, {"load5", "node_load5", ""}, {"load15", "node_load15", ""}, {"uptime", `time()-node_boot_time_seconds`, ""},
	{"disk_percent", `100*(1-node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs"}/node_filesystem_size_bytes)`, "mountpoint"}, {"disk_size", `node_filesystem_size_bytes{fstype!~"tmpfs|overlay|squashfs"}`, "mountpoint"}, {"disk_available", `node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs"}`, "mountpoint"}, {"inode_percent", `100*(1-node_filesystem_files_free{fstype!~"tmpfs|overlay|squashfs"}/node_filesystem_files)`, "mountpoint"},
	{"disk_read", `rate(node_disk_read_bytes_total[5m])`, "device"}, {"disk_write", `rate(node_disk_written_bytes_total[5m])`, "device"}, {"disk_read_iops", `rate(node_disk_reads_completed_total[5m])`, "device"}, {"disk_write_iops", `rate(node_disk_writes_completed_total[5m])`, "device"},
	{"net_receive", `rate(node_network_receive_bytes_total[5m])`, "device"}, {"net_transmit", `rate(node_network_transmit_bytes_total[5m])`, "device"}, {"net_receive_errors", `rate(node_network_receive_errs_total[5m])`, "device"}, {"net_transmit_errors", `rate(node_network_transmit_errs_total[5m])`, "device"}, {"net_receive_drops", `rate(node_network_receive_drop_total[5m])`, "device"}, {"net_transmit_drops", `rate(node_network_transmit_drop_total[5m])`, "device"},
	{"webscan_agent_heartbeat_seconds", "webscan_agent_heartbeat_seconds", ""}, {"webscan_local_probe_seconds", "webscan_local_probe_seconds", ""}, {"webscan_probe_received_seconds", "webscan_probe_received_seconds", ""}, {"webscan_probe_query_seconds", "webscan_probe_loki_seconds", ""}, {"webscan_local_pending_events", "webscan_local_pending_events", ""}, {"webscan_pending_scans", "webscan_pending_scans", ""}, {"webscan_watches", "webscan_watches", ""},
}

func QueryLegacy(ctx context.Context, client *http.Client, base, path string, params url.Values) (common.Map, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(base, "/")+path+"?"+params.Encode(), nil)
	if e != nil {
		return nil, e
	}
	resp, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("旧服务查询返回 HTTP %d", resp.StatusCode)
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > 8<<20 {
		return nil, ErrQueryTooLarge
	}
	v, e := common.Decode(raw)
	if e != nil {
		return nil, e
	}
	m := common.M(v)
	if common.S(m["status"]) != "success" {
		return nil, errors.New("旧服务返回查询失败")
	}
	return common.M(m["data"]), nil
}
func (s *Store) ImportSeries(ctx context.Context, query HistoricalQuery, result []any, allowed map[string]bool) error {
	tx, e := persist.BeginWrite(ctx, s.DB)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, v := range result {
		series := common.M(v)
		labels := common.M(series["metric"])
		node := common.S(labels["node_id"])
		if !allowed[node] {
			continue
		}
		name := query.Name
		if query.Dimension != "" {
			name += ":" + common.S(labels[query.Dimension])
		}
		for _, v := range common.A(series["values"]) {
			pair := common.A(v)
			if len(pair) != 2 {
				return errors.New("旧指标样本格式错误")
			}
			tm := int64(common.F(pair[0]))
			number, e := strconv.ParseFloat(common.S(pair[1]), 64)
			if e != nil || strings.ContainsAny(common.S(pair[1]), "NI") {
				continue
			}
			snap := Snapshot{Time: tm, OK: true, Values: map[string]float64{}}
			var raw, source string
			e = tx.QueryRowContext(ctx, "SELECT payload,source FROM samples WHERE node=? AND time=? AND resolution=0", node, tm).Scan(&raw, &source)
			if e == nil {
				if source != "legacy" {
					continue
				}
				if e = json.Unmarshal([]byte(raw), &snap); e != nil {
					return e
				}
			} else if e != sql.ErrNoRows {
				return e
			}
			snap.Values[name] = number
			if query.Dimension != "" {
				total := 0.0
				for key, value := range snap.Values {
					if !strings.HasPrefix(key, query.Name+":") {
						continue
					}
					dimension := strings.TrimPrefix(key, query.Name+":")
					if query.Dimension == "device" {
						if strings.HasPrefix(query.Name, "net_") && (dimension == "lo" || strings.HasPrefix(dimension, "veth") || strings.HasPrefix(dimension, "docker") || strings.HasPrefix(dimension, "br-")) {
							continue
						}
						total += value
					} else if query.Name == "disk_percent" || query.Name == "inode_percent" {
						total = max(total, value)
					}
				}
				if query.Dimension == "device" || query.Name == "disk_percent" || query.Name == "inode_percent" {
					snap.Values[query.Name] = total
				}
			}
			if query.Name == "collect_up" {
				snap.OK = number == 1
			}
			if len(snap.Values) > 4096 {
				return errors.New("迁移指标维度超过限制")
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO samples(node,time,resolution,payload,source) VALUES(?,?,0,?,'legacy') ON CONFLICT(node,time,resolution) DO UPDATE SET payload=excluded.payload", node, tm, string(common.JSON(snap))); e != nil {
				return e
			}
		}
	}
	return tx.Commit()
}
func (s *Store) ImportPrometheus(ctx context.Context, client *http.Client, base string, start, end int64, notify func(string)) error {
	// Durable protection survives interruptions and is shared with the live
	// collector. Keep it on failure so a retry cannot compact partial rows.
	if _, e := s.DB.ExecContext(ctx, "INSERT OR IGNORE INTO import_guards VALUES('prometheus')"); e != nil {
		return e
	}
	nodes, e := s.Nodes(ctx)
	if e != nil {
		return e
	}
	allowed := map[string]bool{}
	for _, n := range nodes {
		allowed[n.ID] = true
	}
	for from := start; from < end; from += 3600 {
		until := min(from+3600, end)
		for _, q := range HistoricalQueries {
			id := fmt.Sprintf("prom-v2:%d:%d:%s", from, until, q.Name)
			var exists int
			s.DB.QueryRowContext(ctx, "SELECT count(*) FROM migrations WHERE id=?", id).Scan(&exists)
			if exists > 0 {
				continue
			}
			if e = s.importWindow(ctx, client, base, q, from, until, allowed); e != nil {
				return e
			}
			if _, e = s.DB.ExecContext(ctx, "INSERT INTO migrations VALUES(?,?)", id, string(common.JSON(common.Map{"time": time.Now().Unix()}))); e != nil {
				return e
			}
		}
		if notify != nil {
			notify(fmt.Sprintf("指标迁移完成至 %s", time.Unix(until, 0).Format(time.RFC3339)))
		}
	}
	_, e = s.DB.ExecContext(ctx, "DELETE FROM import_guards WHERE id='prometheus'")
	return e
}

func (s *Store) importWindow(ctx context.Context, client *http.Client, base string, q HistoricalQuery, start, end int64, allowed map[string]bool) error {
	data, e := QueryLegacy(ctx, client, base, "/api/v1/query_range", url.Values{"query": {q.Expression}, "start": {strconv.FormatInt(start, 10)}, "end": {strconv.FormatInt(end, 10)}, "step": {"30"}})
	if errors.Is(e, ErrQueryTooLarge) && end-start > 30 {
		// Keep the 30-second sample grid when subdividing; repeated boundary
		// samples are merged by primary key rather than creating duplicates.
		middle := start + ((end-start)/60)*30
		if e = s.importWindow(ctx, client, base, q, start, middle, allowed); e != nil {
			return e
		}
		return s.importWindow(ctx, client, base, q, middle, end, allowed)
	}
	if e != nil {
		return e
	}
	return s.ImportSeries(ctx, q, common.A(data["result"]), allowed)
}
