package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
	"webscan/internal/common"
)

type Rule struct {
	Key            string
	Kind           string
	Severity       string
	Message        string
	Bad            bool
	Known          bool
	For            int64
	Recover        bool
	RecoverSamples int
}
type RuleState struct {
	Key      string `json:"key"`
	Node     string `json:"node"`
	Kind     string `json:"kind"`
	Phase    string `json:"phase"`
	Since    int64  `json:"since"`
	Last     int64  `json:"last"`
	Recovery int    `json:"recovery"`
	Reminder int64  `json:"reminder"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

func rules(n Node, p Snapshot, c common.Map) []Rule {
	a := common.M(c["alerts"])
	now := float64(p.Time)
	rs := []Rule{}
	add := func(kind, msg, severity string, bad, known bool, seconds int) {
		rs = append(rs, Rule{Key: n.ID + ":" + kind, Kind: kind, Message: msg, Severity: severity, Bad: bad, Known: known, For: int64(seconds), Recover: !bad, RecoverSamples: 2})
	}
	val := func(k string, def int) int {
		v := common.I(a[k])
		if v == 0 {
			return def
		}
		return v
	}
	missing := !p.OK
	add("node_unreachable", "无法连接服务器的监控采集服务", "critical", missing, true, val("node_unreachable_seconds", 120))
	if missing {
		return rs
	}
	for _, metric := range []string{"cpu", "memory"} {
		enabled := common.B(a[metric+"_enabled"])
		if !enabled {
			continue
		}
		key := metric + "_percent"
		if metric == "cpu" {
			key = "cpu_5m_percent"
		}
		v, ok := p.Values[key]
		threshold, recovery := val(metric+"_warning_percent", 85), val(metric+"_recovery_percent", 80)
		if metric == "memory" {
			threshold, recovery = val(metric+"_warning_percent", 90), val(metric+"_recovery_percent", 85)
		}
		msg := fmt.Sprintf("%s使用率 %.1f%%，超过 %d%%", map[string]string{"cpu": "CPU", "memory": "内存"}[metric], v, threshold)
		add(metric, msg, "warning", v > float64(threshold), ok, val(metric+"_duration_seconds", 300))
		rs[len(rs)-1].Recover = v < float64(recovery)
	}
	for key, v := range p.Values {
		for _, metric := range []string{"disk", "inode"} {
			if !strings.HasPrefix(key, metric+"_percent:") {
				continue
			}
			mount := strings.TrimPrefix(key, metric+"_percent:")
			for _, severity := range []string{"warning", "critical"} {
				def := 80
				if severity == "critical" {
					def = 90
				}
				threshold := val(metric+"_"+severity+"_percent", def)
				add(metric+":"+mount+":"+severity, fmt.Sprintf("%s %s使用率 %.1f%%", mount, map[string]string{"disk": "磁盘", "inode": "inode"}[metric], v), severity, v > float64(threshold), true, 60)
			}
		}
	}
	offset, hasOffset := p.Values["timex_offset_seconds"]
	sync, hasSync := p.Values["timex_sync_status"]
	add("clock", "服务器时间未同步或偏差过大", "warning", (hasSync && sync == 0) || (hasOffset && math.Abs(offset) > float64(val("clock_offset_warning_seconds", 30))), hasOffset || hasSync, val("clock_failure_duration_seconds", 300))
	if !n.Central {
		for _, r := range []struct {
			kind, metric, msg, key string
			def, wait              int
		}{{"agent", "webscan_agent_heartbeat_seconds", "文件监控心跳长时间未更新", "agent_stopped_seconds", 60, 60}, {"local_probe", "webscan_local_probe_seconds", "本地监控测试长时间未完成", "local_probe_stale_seconds", 180, 0}, {"central_probe", "webscan_probe_received_seconds", "监控中心长时间未收到测试事件", "central_probe_stale_seconds", 180, 0}, {"event_query", "webscan_probe_query_seconds", "测试事件长时间未能确认入库查询", "loki_probe_stale_seconds", 180, 0}, {"scanner", "webscan_scan_heartbeat_seconds", "扫描程序长时间未更新心跳", "", 180, 60}} {
			v, ok := p.Values[r.metric]
			age := now - v
			limit := val(r.key, r.def)
			wait := r.wait
			if r.kind == "agent" {
				limit = max(60, 2*common.I(c["interval_seconds"]))
				wait = val("agent_stopped_seconds", 60)
			}
			add(r.kind, r.msg, "warning", age > float64(limit), ok, wait)
		}
		if value, ok := p.Values["webscan_transport_up"]; ok {
			p.Values["webscan_vector_metrics_up"] = value
		}
		for _, r := range []struct{ kind, metric, msg string }{{"coverage", "webscan_coverage_ok", "部分网站目录未被完整监控"}, {"vector", "webscan_vector_metrics_up", "事件传输服务不可达"}} {
			v, ok := p.Values[r.metric]
			add(r.kind, r.msg, "warning", v == 0, ok, 60)
		}
		v, known := p.Values["webscan_transport_rejected_events"]
		add("transport_rejected", "部分文件事件被中心拒绝，请检查投递失败记录", "critical", v > 0, known, 0)
		_, heartbeat := p.Values["webscan_agent_heartbeat_seconds"]
		add("agent_metric_missing", "采集接口缺少 Agent 心跳指标", "warning", !heartbeat, true, 60)
		for _, r := range []struct{ kind, metric, msg, flag string }{{"inotify_overflow", "webscan_last_inotify_overflow_seconds", "文件监听队列溢出", "alert_on_inotify_overflow"}, {"dropped", "webscan_last_drop_seconds", "文件事件发生丢弃", "alert_on_dropped_events"}} {
			v, ok := p.Values[r.metric]
			bad := v > 0 && now-v < 300
			if r.kind == "dropped" {
				if discarded, exists := p.Values["vector_component_discarded_events_total"]; exists {
					ok = true
					bad = bad || discarded > 0
				}
			}
			add(r.kind, r.msg, "critical", bad, ok && common.B(c[r.flag]), 0)
		}
	}
	for _, key := range []string{"webscan_local_oldest_pending_seconds", "webscan_oldest_pending_seconds"} {
		v, ok := p.Values[key]
		add("backlog:"+key, "监控事件积压过久", "warning", v > float64(val("oldest_pending_task_seconds", 300)), ok, 0)
	}
	return rs
}
func (s *Store) Evaluate(ctx context.Context, n Node, snap Snapshot) error {
	s.alertsMu.Lock()
	defer s.alertsMu.Unlock()
	config := s.Settings()
	if common.S(config["mode"]) != "native" || common.Contains(common.SS(config["maintenance_nodes"]), n.ID) {
		return nil
	}
	s.mu.Lock()
	for _, current := range s.nodes {
		if current.ID == n.ID {
			n.Active = current.Active
			break
		}
	}
	s.mu.Unlock()
	if !n.Active {
		return nil
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, kind := range []string{"cpu", "memory"} {
		if !common.B(common.M(config["alerts"])[kind+"_enabled"]) {
			if _, e = tx.ExecContext(ctx, "UPDATE health_rules SET phase='disabled' WHERE node=? AND kind=?", n.ID, kind); e != nil {
				return e
			}
		}
	}
	for _, r := range rules(n, snap, config) {
		var raw string
		st := RuleState{Key: r.Key, Node: n.ID, Kind: r.Kind, Phase: "normal", Message: r.Message, Severity: r.Severity}
		var phaseColumn string
		e = tx.QueryRowContext(ctx, "SELECT payload,phase FROM health_rules WHERE key=?", r.Key).Scan(&raw, &phaseColumn)
		if e == nil {
			if e = json.Unmarshal([]byte(raw), &st); e != nil {
				return e
			}
			st.Phase = phaseColumn
		} else if e != sql.ErrNoRows {
			return e
		}
		if !r.Known {
			continue
		}
		var phase string
		st, phase = AdvanceRule(st, r, snap.Time, common.I(config["interval_seconds"]), common.I(config["repeat_hours"]))
		if phase != "" {
			id := common.Hash([]byte(fmt.Sprintf("%s:%d:%s:%d", r.Key, st.Since, phase, snap.Time)))
			message := RuleMessage(n, r, st, phase, snap.Time)
			if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO health_events VALUES(?,?,?,?,?,?,?)", id, n.ID, r.Kind, phase, snap.Time, message, string(common.JSON(st))); e != nil {
				return e
			}
			if !RuleInhibited(r, snap, config) {
				if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO alert_outbox(id,node,kind,message,created) VALUES(?,?,?,?,?)", id, n.ID, phase, message, snap.Time); e != nil {
					return e
				}
			}
			st.Reminder = snap.Time
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO health_rules VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET phase=excluded.phase,since=excluded.since,last=excluded.last,recovery=excluded.recovery,reminder=excluded.reminder,payload=excluded.payload", r.Key, n.ID, r.Kind, st.Phase, st.Since, st.Last, st.Recovery, st.Reminder, string(common.JSON(st))); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) Flush(ctx context.Context, deliver func(context.Context, string, string, string) error) error {
	s.alertsMu.Lock()
	defer s.alertsMu.Unlock()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, "SELECT o.id,o.node,o.kind,o.message,o.created FROM alert_outbox o WHERE o.done IS NULL AND NOT EXISTS(SELECT 1 FROM alert_members m WHERE m.event=o.id) ORDER BY o.created,o.rowid LIMIT 500")
	if e != nil {
		tx.Rollback()
		return e
	}
	type item struct {
		id, node, kind, msg string
		created             int64
	}
	items := []item{}
	for rows.Next() {
		var v item
		if e = rows.Scan(&v.id, &v.node, &v.kind, &v.msg, &v.created); e != nil {
			break
		}
		items = append(items, v)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		tx.Rollback()
		return e
	}
	groups := [][]item{}
	lookup := map[string]int{}
	wait := int64(max(15, common.I(s.Settings()["group_wait_seconds"])))
	groupInterval := int64(common.I(s.Settings()["group_interval_seconds"]))
	for _, v := range items {
		if time.Now().Unix()-v.created < wait {
			continue
		}
		var phase, ruleKind string
		if e = tx.QueryRowContext(ctx, "SELECT kind FROM health_events WHERE id=?", v.id).Scan(&ruleKind); e != nil && e != sql.ErrNoRows {
			tx.Rollback()
			return e
		}
		if ruleKind != "node_unreachable" {
			err := tx.QueryRowContext(ctx, "SELECT phase FROM health_rules WHERE node=? AND kind='node_unreachable'", v.node).Scan(&phase)
			if err != nil && err != sql.ErrNoRows {
				tx.Rollback()
				return err
			}
			if phase == "firing" {
				continue
			}
		}
		if groupInterval > 0 {
			var last sql.NullFloat64
			if e = tx.QueryRowContext(ctx, "SELECT max(done) FROM alert_batches WHERE node=? AND kind=?", v.node, v.kind).Scan(&last); e != nil {
				tx.Rollback()
				return e
			}
			if last.Valid && float64(time.Now().Unix())-last.Float64 < float64(groupInterval) {
				continue
			}
		}
		key := v.node + ":" + v.kind + fmt.Sprint(v.created/15)
		index, ok := lookup[key]
		if !ok {
			index = len(groups)
			lookup[key] = index
			groups = append(groups, []item{})
		}
		groups[index] = append(groups[index], v)
	}
	for _, group := range groups {
		// Persist each exact batch before invoking the other database, so a crash
		// cannot change its identity when new alarms arrive.
		batches := [][]item{group}
		if len(group) <= 5 {
			batches = nil
			for _, v := range group {
				batches = append(batches, []item{v})
			}
		}
		for _, batch := range batches {
			ids := []string{}
			messages := []string{}
			for _, v := range batch {
				ids = append(ids, v.id)
				if len(messages) < 5 {
					messages = append(messages, v.msg)
				}
			}
			id := common.Hash(common.JSON(ids))
			msg := strings.Join(messages, "\n\n")
			if len(batch) > 5 {
				msg = fmt.Sprintf("监控告警汇总：%d 项（前 5 项）\n", len(batch)) + msg
			}
			if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO alert_batches VALUES(?,?,?,?,?,NULL)", id, batch[0].node, batch[0].kind, msg, batch[0].created); e != nil {
				tx.Rollback()
				return e
			}
			for _, v := range batch {
				if _, e = tx.ExecContext(ctx, "INSERT INTO alert_members VALUES(?,?)", v.id, id); e != nil {
					tx.Rollback()
					return e
				}
			}
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	rows, e = s.DB.QueryContext(ctx, "SELECT id,node,kind,message FROM alert_batches WHERE done IS NULL ORDER BY created,rowid LIMIT 100")
	if e != nil {
		return e
	}
	pending := []item{}
	for rows.Next() {
		var v item
		if e = rows.Scan(&v.id, &v.node, &v.kind, &v.msg); e != nil {
			break
		}
		pending = append(pending, v)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	for _, v := range pending {
		if e = deliver(ctx, v.id, v.node, v.kind+"\n"+v.msg); e != nil {
			return e
		}
		tx, e = s.DB.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE alert_batches SET done=? WHERE id=?", common.Now(), v.id); e == nil {
			_, e = tx.ExecContext(ctx, "UPDATE alert_outbox SET done=? WHERE id IN(SELECT event FROM alert_members WHERE batch=?)", common.Now(), v.id)
		}
		if e != nil {
			tx.Rollback()
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
	}
	return nil
}
