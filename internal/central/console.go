package central

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/notify"
	"webscan/internal/telemetry"
	"webscan/internal/website"
)

func (s *Store) initMonitoring() error {
	m := common.M(s.Config["monitoring"])
	if len(m) == 0 {
		return nil
	}
	nodes := []telemetry.Node{}
	for _, v := range common.A(m["nodes"]) {
		n := common.M(v)
		nodes = append(nodes, telemetry.Node{ID: common.S(n["id"]), Name: common.S(n["name"]), Host: common.S(n["host"]), URL: common.S(n["url"]), Central: common.B(n["central"]), Active: common.B(n["active"])})
	}
	store, e := telemetry.Open(common.S(s.Config["data_dir"]), nodes, m)
	if e != nil {
		return e
	}
	s.Telemetry = store
	return nil
}
func (s *Store) native() bool {
	return common.S(common.M(s.Snapshot()["monitoring"])["mode"]) == "native"
}
func (s *Store) monitoringExtra(node string) map[string]float64 {
	out := map[string]float64{}
	var received, queried float64
	s.DB.QueryRow("SELECT received,loki FROM probes WHERE node=?", node).Scan(&received, &queried)
	out["webscan_probe_received_seconds"] = received
	out["webscan_probe_query_seconds"] = queried
	if node == "central" {
		var oldest sql.NullFloat64
		s.DB.QueryRow("SELECT MIN(created) FROM tasks WHERE target='feishu' AND done IS NULL").Scan(&oldest)
		if oldest.Valid {
			out["webscan_oldest_pending_seconds"] = common.Now() - oldest.Float64
		}
	}
	return out
}
func (s *Store) monitoringDelivery(ctx context.Context, id, node, body string) error {
	kind, msg, _ := strings.Cut(body, "\n")
	if s.Telemetry != nil {
		nodes, e := s.Telemetry.Nodes(ctx)
		if e != nil {
			return e
		}
		for _, n := range nodes {
			if n.ID == node && !n.Active {
				return nil
			}
		}
	}
	category := "health_failures"
	if kind == "resolved" {
		category = "health_recoveries"
	}
	return s.enqueueNotice(ctx, "native:"+id, common.Map{"message": msg, "source": "health", "node_id": node, "notice_kind": kind}, category)
}
func (s *Store) NoticePayload(ctx context.Context, id string, payload common.Map) error {
	return s.enqueueNotice(ctx, id, payload, "")
}
func (s *Store) enqueueNotice(ctx context.Context, id string, payload common.Map, category string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = notify.Enqueue(ctx, tx, s.Snapshot(), "central", id, payload, category, 100); e != nil {
		return e
	}
	return tx.Commit()
}

func consoleError(w http.ResponseWriter, code int, message string) {
	write(w, code, common.Map{"message": message})
}
func page(r *http.Request) (int, int) {
	p, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if size == 0 {
		size = 20
	}
	return max(1, p), min(100, max(1, size))
}
func (s *Store) Console(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	if path == "/api/record-operations" {
		s.managementProxy(w, r)
		return true
	}
	if strings.HasPrefix(path, "/api/retention/") {
		s.retentionAPI(w, r)
		return true
	}
	if strings.HasPrefix(path, "/api/servers/remove") || path == "/api/settings" || path == "/api/settings/preview" || strings.HasPrefix(path, "/api/deployments") || strings.HasPrefix(path, "/api/config-backups") {
		s.managementProxy(w, r)
		return true
	}
	if path == "/api/notifications/email-test" {
		s.emailTest(w, r)
		return true
	}
	recognized := path == "/api/dashboard" || path == "/api/servers" || strings.HasPrefix(path, "/api/servers/") || path == "/api/events" || path == "/api/alerts" || strings.HasPrefix(path, "/api/alerts/") || path == "/api/notifications" || strings.HasPrefix(path, "/api/notifications/") || path == "/api/system/health"
	if !recognized {
		return false
	}
	if r.Method != "GET" {
		consoleError(w, 405, "此接口只支持查看")
		return true
	}
	switch {
	case path == "/api/servers" || strings.HasPrefix(path, "/api/servers/"):
		s.serverAPI(w, r)
	case path == "/api/dashboard":
		s.dashboard(w, r)
	case path == "/api/events":
		s.eventsAPI(w, r)
	case path == "/api/alerts" || strings.HasPrefix(path, "/api/alerts/"):
		s.alertsAPI(w, r)
	case path == "/api/notifications" || strings.HasPrefix(path, "/api/notifications/"):
		s.notificationsAPI(w, r)
	case path == "/api/system/health":
		nodes := []telemetry.Node{}
		if s.Telemetry != nil {
			var e error
			nodes, e = s.Telemetry.Nodes(r.Context())
			if e != nil {
				consoleError(w, 503, "指标库暂不可用")
				return true
			}
		}
		var count int
		var oldest sql.NullFloat64
		if e := s.DB.QueryRowContext(r.Context(), "SELECT COUNT(*),MIN(created) FROM tasks WHERE target='feishu' AND done IS NULL").Scan(&count, &oldest); e != nil {
			consoleError(w, 503, "事件数据库暂不可用")
			return true
		}
		var emails int
		var emailOldest sql.NullFloat64
		s.DB.QueryRowContext(r.Context(), "SELECT count(*),min(created) FROM tasks WHERE target='email' AND done IS NULL").Scan(&emails, &emailOldest)
		write(w, 200, common.Map{"email_enabled": common.B(common.M(s.Snapshot()["email"])["enabled"]), "email_recipients": notify.Recipients(common.M(s.Snapshot()["email"])), "pending_email": emails, "oldest_email": emailOldest.Float64, "nodes": nodes, "pending_notifications": count, "oldest_pending": oldest.Float64, "mode": common.M(s.Snapshot()["monitoring"])["mode"], "database": "normal", "manager": s.managerHealth(r.Context())})
	}
	return true
}

func (s *Store) managerHealth(ctx context.Context) common.Map {
	socket := common.S(s.Snapshot()["management_socket"])
	if socket == "" {
		return common.Map{"available": false, "message": "Compose 尚未接管宿主机管理，查看功能可用"}
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	status, value, e := common.Request(ctx, &http.Client{Transport: transport, Timeout: 2 * time.Second}, "GET", "http://management/health", nil, nil)
	if e != nil || status != 200 {
		return common.Map{"available": false, "message": "宿主机管理服务暂不可用，请检查 webscan-management"}
	}
	return common.M(value)
}
func (s *Store) serverAPI(w http.ResponseWriter, r *http.Request) {
	if s.Telemetry == nil {
		consoleError(w, 503, "当前运行配置尚未启用指标采集，请升级主服务器")
		return
	}
	nodes, e := s.Telemetry.Nodes(r.Context())
	if e != nil {
		consoleError(w, 503, "指标库暂不可用")
		return
	}
	for i := range nodes {
		nodes[i].RemoveReason = "管理服务暂不可用"
		nodes[i].ActualMode = nodes[i].Snapshot.Info["agent_mode"]
		nodes[i].AgentVersion = nodes[i].Snapshot.Info["agent_version"]
		if nodes[i].Central {
			nodes[i].ActualMode = "docker"
			nodes[i].ConfiguredMode = "docker"
			nodes[i].AgentVersion = common.S(s.Snapshot()["release"])
		} else if nodes[i].ActualMode == "" && nodes[i].Snapshot.Time > 0 {
			nodes[i].ActualMode = "docker"
		}
	}
	metadataCtx, metadataCancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer metadataCancel()
	if status, v, e := s.managementRequest(metadataCtx, "GET", "/settings", nil); e == nil && status == 200 {
		meta := common.M(v)
		effective := common.A(meta["effective_nodes"])
		for i := range nodes {
			if nodes[i].Central {
				nodes[i].ConfiguredMode = "docker"
				nodes[i].ActualMode = "docker"
				nodes[i].AgentVersion = common.S(s.Snapshot()["release"])
				continue
			}
			for _, value := range effective {
				n := common.M(value)
				if common.S(n["id"]) == nodes[i].ID {
					nodes[i].ConfiguredMode = common.S(common.M(n["deployment"])["mode"])
					nodes[i].CanRemove = !common.B(meta["pending_task"]) && !common.B(meta["operation_running"])
					nodes[i].RemoveReason = ""
					if !nodes[i].CanRemove {
						nodes[i].RemoveReason = "存在冲突或未完成管理任务"
					}
				}
			}
			deployed := common.M(common.M(meta["node_deployments"])[nodes[i].ID])
			nodes[i].DeploymentState = common.S(deployed["phase"])
			nodes[i].ActualMode = common.S(deployed["mode"])
			nodes[i].AgentVersion = common.S(deployed["version"])
			if nodes[i].ActualMode == "" {
				nodes[i].ActualMode = nodes[i].Snapshot.Info["agent_mode"]
			}
			if nodes[i].AgentVersion == "" {
				nodes[i].AgentVersion = nodes[i].Snapshot.Info["agent_version"]
			}
			if nodes[i].ActualMode == "" && nodes[i].Snapshot.Time > 0 {
				nodes[i].ActualMode = "docker"
			}
			nodes[i].PendingMode = nodes[i].ConfiguredMode != "" && nodes[i].ConfiguredMode != nodes[i].ActualMode
		}
	}
	if r.URL.Path == "/api/servers" {
		q := strings.ToLower(r.URL.Query().Get("q"))
		status := r.URL.Query().Get("status")
		items := []telemetry.Node{}
		for _, n := range nodes {
			if q != "" && !strings.Contains(strings.ToLower(n.Name+" "+n.Host+" "+n.ID), q) {
				continue
			}
			if status != "" && n.Status != status {
				continue
			}
			items = append(items, n)
		}
		write(w, 200, common.Map{"items": items, "total": len(items)})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/servers/"), "/")
	var selected *telemetry.Node
	for i := range nodes {
		if nodes[i].ID == parts[0] {
			selected = &nodes[i]
			break
		}
	}
	if selected == nil {
		consoleError(w, 404, "服务器不存在")
		return
	}
	if len(parts) == 1 {
		write(w, 200, selected)
		return
	}
	if len(parts) != 2 || parts[1] != "metrics" {
		consoleError(w, 404, "接口不存在")
		return
	}
	end := time.Now().Unix()
	start := end - 3600
	if v := r.URL.Query().Get("start"); v != "" {
		start, e = strconv.ParseInt(v, 10, 64)
		if e != nil {
			consoleError(w, 400, "开始时间不正确")
			return
		}
	}
	if v := r.URL.Query().Get("end"); v != "" {
		end, e = strconv.ParseInt(v, 10, 64)
		if e != nil {
			consoleError(w, 400, "结束时间不正确")
			return
		}
	}
	if end > time.Now().Unix()+30 || end-start > int64(common.I(s.Telemetry.Settings()["history_days"]))*86400 {
		consoleError(w, 400, "时间范围超出指标保留期限")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	trend, e := s.Telemetry.Trend(ctx, selected.ID, start, end)
	if e != nil {
		consoleError(w, 400, common.SecretFree(e))
		return
	}
	write(w, 200, trend)
}
func (s *Store) eventsAPI(w http.ResponseWriter, r *http.Request) {
	p, size := page(r)
	include := r.URL.Query().Get("include_probes") == "true"
	if r.URL.Query().Get("operation") == "probe" && !include {
		consoleError(w, 400, "查询链路探针请开启包含链路探针")
		return
	}
	query := " FROM (SELECT node,id,payload,received,'events' AS storage FROM events UNION ALL SELECT node,id,payload,time AS received,'migrated_events' AS storage FROM migrated_logs m WHERE NOT EXISTS(SELECT 1 FROM events e WHERE e.node=m.node AND e.id=json_extract(m.payload,'$.event_id'))) WHERE 1=1"
	args := []any{}
	if !include {
		query += " AND COALESCE(json_extract(payload,'$.operation'),'')<>'probe'"
	}
	for _, field := range []string{"node", "operation"} {
		value := r.URL.Query().Get(field)
		if value != "" {
			if field == "node" {
				query += " AND node=?"
			} else {
				query += " AND json_extract(payload,'$.operation')=?"
			}
			args = append(args, value)
		}
	}
	if q := r.URL.Query().Get("q"); q != "" {
		query += " AND payload LIKE ?"
		args = append(args, "%"+q+"%")
	}
	query, args = timeFilter(r, query, args, "received")
	var total int
	if e := s.DB.QueryRowContext(r.Context(), "SELECT count(*)"+query, args...).Scan(&total); e != nil {
		consoleError(w, 503, "事件读取失败")
		return
	}
	rows, e := s.DB.QueryContext(r.Context(), "SELECT node,id,payload,received,storage"+query+" ORDER BY received DESC LIMIT ? OFFSET ?", append(args, size, (p-1)*size)...)
	if e != nil {
		consoleError(w, 503, "事件读取失败")
		return
	}
	defer rows.Close()
	items := []common.Map{}
	for rows.Next() {
		var node, id, raw, storage string
		var tm float64
		if e = rows.Scan(&node, &id, &raw, &tm, &storage); e != nil {
			consoleError(w, 503, "事件读取失败")
			return
		}
		payload, _ := common.Decode([]byte(raw))
		items = append(items, common.Map{"id": id, "node": node, "time": tm, "event": payload, "_record_source": storage})
	}
	if rows.Err() != nil {
		consoleError(w, 503, "事件读取失败")
		return
	}
	rows.Close()
	s.decorateRecords(r.Context(), items, "events")
	write(w, 200, common.Map{"items": items, "total": total})
}
func timeFilter(r *http.Request, q string, args []any, col string) (string, []any) {
	start := float64(time.Now().Add(-24 * time.Hour).Unix())
	if v, e := strconv.ParseFloat(r.URL.Query().Get("start"), 64); e == nil {
		start = v
	}
	q += " AND " + col + ">=?"
	args = append(args, start)
	if v, e := strconv.ParseFloat(r.URL.Query().Get("end"), 64); e == nil {
		q += " AND " + col + "<=?"
		args = append(args, v)
	}
	return q, args
}
func (s *Store) alertsAPI(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	conn, e := s.DB.Conn(ctx)
	if e != nil {
		consoleError(w, 503, "告警库暂不可用")
		return
	}
	defer conn.Close()
	history := r.URL.Query().Get("history") == "true"
	health := "SELECT '' AS id,'' AS node,'' AS kind,'' AS phase,0 AS time,'' AS message,'{}' AS payload,'health' AS source WHERE 0"
	if s.Telemetry != nil {
		path := filepath.Join(common.S(s.Snapshot()["data_dir"]), "metrics-v1.sqlite3")
		if _, e = conn.ExecContext(ctx, "ATTACH DATABASE ? AS metrics_console", path); e != nil {
			consoleError(w, 503, "指标告警库暂不可用")
			return
		}
		defer conn.ExecContext(context.Background(), "DETACH DATABASE metrics_console")
		health = "SELECT key AS id,node,kind,phase,since AS time,json_extract(payload,'$.message') AS message,payload,'health' AS source FROM metrics_console.health_rules WHERE phase IN ('pending','firing')"
		if history {
			health = "SELECT id,node,kind,phase,time,message,payload,'health' AS source FROM metrics_console.health_events"
		}
	}
	sites := "SELECT 'website:'||i.id AS id,COALESCE((SELECT o.node FROM website_incident_origins o WHERE o.id=i.id),w.node) AS node,i.kind,CASE WHEN i.ended IS NULL THEN 'firing' ELSE 'resolved' END AS phase,i.started AS time,i.reason AS message,json_object('name',w.name,'site',w.id,'url',w.url,'since',i.started,'ended',i.ended) AS payload,'website' AS source FROM website_incidents i JOIN websites w ON w.id=i.site"
	if !history {
		sites += " WHERE i.ended IS NULL AND w.deleted=0 AND w.paused=0"
	}
	query := " FROM (" + health + " UNION ALL " + sites + ") WHERE 1=1"
	args := []any{}
	for _, key := range []string{"node", "kind", "phase", "source"} {
		if v := r.URL.Query().Get(key); v != "" {
			query += " AND " + key + "=?"
			args = append(args, v)
		}
	}
	if q := r.URL.Query().Get("q"); q != "" {
		query += " AND (message LIKE ? OR payload LIKE ?)"
		args = append(args, "%"+q+"%", "%"+q+"%")
	}
	if history {
		query, args = timeFilter(r, query, args, "time")
	}
	var total int
	if e = conn.QueryRowContext(ctx, "SELECT count(*)"+query, args...).Scan(&total); e != nil {
		consoleError(w, 503, "告警读取失败")
		return
	}
	p, size := page(r)
	rows, e := conn.QueryContext(ctx, "SELECT id,node,kind,phase,time,message,payload,source"+query+" ORDER BY time DESC,id DESC LIMIT ? OFFSET ?", append(args, size, (p-1)*size)...)
	if e != nil {
		consoleError(w, 503, "告警读取失败")
		return
	}
	defer rows.Close()
	items := []common.Map{}
	for rows.Next() {
		var id, node, kind, phase, msg, raw, source string
		var tm float64
		if e = rows.Scan(&id, &node, &kind, &phase, &tm, &msg, &raw, &source); e != nil {
			consoleError(w, 503, "告警读取失败")
			return
		}
		v, _ := common.Decode([]byte(raw))
		m := common.M(v)
		started := common.F(m["since"])
		if started == 0 && source == "website" {
			started = tm
		}
		var ended any
		var duration any
		if source == "website" {
			if end := common.F(m["ended"]); end > 0 {
				ended = end
				duration = max(0, end-started)
			} else if started > 0 {
				duration = max(0, common.Now()-started)
			}
		} else if phase == "resolved" && started > 0 {
			ended = tm
			duration = max(0, tm-started)
		} else if started > 0 {
			duration = max(0, tm-started)
		}
		m["started"], m["ended"], m["duration_seconds"] = started, ended, duration
		m["id"], m["key"], m["node"], m["kind"], m["phase"], m["time"], m["message"], m["source"] = id, id, node, kind, phase, tm, msg, source
		if history {
			if source == "website" {
				m["_record_source"] = "website"
			} else {
				m["_record_source"] = "server"
			}
		}
		items = append(items, m)
	}
	if rows.Err() != nil {
		consoleError(w, 503, "告警读取失败")
		return
	}
	rows.Close()
	if history {
		s.decorateRecords(ctx, items, "")
	}
	write(w, 200, common.Map{"items": items, "total": total})
}
func (s *Store) notificationStats(w http.ResponseWriter, r *http.Request) {
	rows, e := s.DB.QueryContext(r.Context(), "SELECT strftime('%Y-%m-%d',created,'unixepoch','+8 hours'),sum(done IS NOT NULL),sum(done IS NULL AND attempts=0),sum(done IS NULL AND attempts>0) FROM tasks WHERE target='feishu' AND created>=? GROUP BY 1 ORDER BY 1", time.Now().Unix()-7*86400)
	if e != nil {
		consoleError(w, 503, "通知统计读取失败")
		return
	}
	defer rows.Close()
	items := []common.Map{}
	for rows.Next() {
		var day string
		var done, pending, retry int
		if e = rows.Scan(&day, &done, &pending, &retry); e != nil {
			consoleError(w, 503, "通知统计读取失败")
			return
		}
		items = append(items, common.Map{"day": day, "delivered": done, "pending": pending, "retrying": retry})
	}
	write(w, 200, common.Map{"items": items})
}
func (s *Store) notificationsAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("channel") == "email" {
		s.emailAPI(w, r)
		return
	}
	if r.URL.Path == "/api/notifications/stats" {
		s.notificationStats(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/notifications/") {
		id, e := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/api/notifications/"), 10, 64)
		if e != nil {
			consoleError(w, 400, "通知编号不正确")
			return
		}
		var raw string
		var node, event, status string
		var tm float64
		var done sql.NullFloat64
		var attempts int
		if e = s.DB.QueryRow("SELECT node,event_id,payload,created,done,attempts,coalesce(result,'') FROM tasks WHERE id=? AND target='feishu'", id).Scan(&node, &event, &raw, &tm, &done, &attempts, &status); e != nil {
			consoleError(w, 404, "通知不存在或已过保留期")
			return
		}
		v, _ := common.Decode([]byte(raw))
		msg := common.S(common.M(v)["message"])
		if msg == "" {
			msg = eventNotice(common.M(v))
		}
		rows, e := s.DB.Query("SELECT time,status FROM delivery_records WHERE task_id=? AND target='feishu' ORDER BY id", id)
		if e != nil {
			consoleError(w, 503, "投递记录读取失败")
			return
		}
		records := []common.Map{}
		for rows.Next() {
			var time float64
			var result string
			rows.Scan(&time, &result)
			records = append(records, common.Map{"time": time, "result": result})
		}
		rows.Close()
		write(w, 200, common.Map{"id": id, "node": node, "event_id": event, "time": tm, "done": done.Float64, "attempts": attempts, "result": status, "message": msg, "metadata": v, "records": records})
		return
	}
	p, size := page(r)
	query := " FROM tasks WHERE target='feishu'"
	args := []any{}
	if node := r.URL.Query().Get("node"); node != "" {
		query += " AND (node=? OR json_extract(payload,'$.node_id')=?)"
		args = append(args, node, node)
	}
	switch r.URL.Query().Get("status") {
	case "delivered":
		query += " AND done IS NOT NULL"
	case "retrying":
		query += " AND done IS NULL AND attempts>0"
	case "pending":
		query += " AND done IS NULL AND attempts=0"
	}
	if q := r.URL.Query().Get("q"); q != "" {
		query += " AND payload LIKE ?"
		args = append(args, "%"+q+"%")
	}
	query, args = timeFilter(r, query, args, "created")
	var total int
	if e := s.DB.QueryRow("SELECT count(*)"+query, args...).Scan(&total); e != nil {
		consoleError(w, 503, "通知读取失败")
		return
	}
	rows, e := s.DB.Query("SELECT id,node,event_id,payload,created,done,attempts,coalesce(result,''),next_try,lease"+query+" ORDER BY id DESC LIMIT ? OFFSET ?", append(args, size, (p-1)*size)...)
	if e != nil {
		consoleError(w, 503, "通知读取失败")
		return
	}
	defer rows.Close()
	items := []common.Map{}
	for rows.Next() {
		var id int64
		var node, event, raw, result string
		var tm, next, lease float64
		var done sql.NullFloat64
		var attempts int
		rows.Scan(&id, &node, &event, &raw, &tm, &done, &attempts, &result, &next, &lease)
		v, _ := common.Decode([]byte(raw))
		payload := common.M(v)
		msg := common.S(payload["message"])
		if msg == "" {
			msg = eventNotice(payload)
		}
		status := "pending"
		if done.Valid {
			status = "delivered"
		} else if lease > common.Now() {
			status = "sending"
		} else if attempts > 0 {
			status = "retrying"
		}
		source := common.S(payload["source"])
		if source == "" {
			source = common.S(payload["operation"])
			if source == "" {
				source = "legacy"
			}
		}
		if actual := common.S(payload["node_id"]); actual != "" {
			node = actual
		}
		items = append(items, common.Map{"id": id, "node": node, "time": tm, "done": done.Float64, "message": msg, "status": status, "source": source, "attempts": attempts, "result": result, "next_try": next})
	}
	rows.Close()
	s.decorateRecords(r.Context(), items, "notifications")
	write(w, 200, common.Map{"items": items, "total": total})
}
func (s *Store) managementProxy(w http.ResponseWriter, r *http.Request) {
	socket := common.S(s.Snapshot()["management_socket"])
	if socket == "" {
		consoleError(w, 503, "宿主机管理服务尚未安装，请先升级主服务器")
		return
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	path := strings.TrimPrefix(r.URL.Path, "/api")
	if path == "/record-operations" {
		path = "/operations"
	}
	path = strings.Replace(path, "/deployments", "/jobs", 1)
	path = strings.Replace(path, "/servers/remove", "/nodes/remove", 1)
	path = strings.Replace(path, "/config-backups", "/backups", 1)
	req, e := http.NewRequestWithContext(r.Context(), r.Method, "http://management"+path+"?"+r.URL.RawQuery, http.MaxBytesReader(w, r.Body, 6<<20))
	if e != nil {
		consoleError(w, 400, "请求格式不正确")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webscan-Owner", website.AuthenticatedUsername(r))
	secure := r.TLS != nil
	if origin, e := url.Parse(r.Header.Get("Origin")); e == nil && origin.Scheme == "https" && origin.Host == r.Host {
		secure = true
	}
	if secure {
		req.Header.Set("X-Webscan-Secure", "true")
	}
	response, e := client.Do(req)
	if e != nil {
		consoleError(w, 503, "无法连接宿主机管理服务，请检查 webscan-management 服务")
		return
	}
	defer response.Body.Close()
	w.Header().Set("Content-Type", response.Header.Get("Content-Type"))
	if v := response.Header.Get("Content-Disposition"); v != "" {
		w.Header().Set("Content-Disposition", v)
	}
	w.WriteHeader(response.StatusCode)
	io.Copy(w, io.LimitReader(response.Body, 8<<20))
}

var _ = filepath.Separator

func (s *Store) managementRequest(ctx context.Context, method, path string, body any) (int, any, error) {
	socket := common.S(s.Snapshot()["management_socket"])
	if socket == "" {
		return 0, nil, fmt.Errorf("management unavailable")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	return common.Request(ctx, &http.Client{Transport: transport, Timeout: 2 * time.Second}, method, "http://management"+path, body, nil)
}
