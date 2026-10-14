package central

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"webscan/internal/common"
	"webscan/internal/telemetry"
)

func (s *Store) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().Unix()
	c := s.Snapshot()
	out := common.Map{"updated": now, "release": c["release"], "started": s.started, "servers": []telemetry.Node{}}
	errs := common.Map{}
	components := []common.Map{}
	card := func(id, name, state, reason, href string, tm int64, metrics common.Map) {
		components = append(components, common.Map{"id": id, "name": name, "status": state, "reason": reason, "href": href, "updated": tm, "metrics": metrics})
	}
	nodes := []telemetry.Node{}
	normal, abnormal, unknown := 0, 0, 0
	metricsState := "disabled"
	if s.Telemetry != nil {
		var e error
		nodes, e = s.Telemetry.Nodes(ctx)
		if e != nil {
			metricsState = "unknown"
			errs["metrics"] = "指标暂不可用"
			out["metrics_error"] = errs["metrics"]
		} else {
			metricsState = "normal"
			for i := range nodes {
				n := &nodes[i]
				if n.Central {
					n.ActualMode = "docker"
					n.AgentVersion = common.S(c["release"])
				} else {
					n.ActualMode = n.Snapshot.Info["agent_mode"]
					n.AgentVersion = n.Snapshot.Info["agent_version"]
				}
				if !n.Active {
					continue
				}
				if n.Status == "normal" {
					normal++
				} else if n.Status == "unknown" {
					unknown++
				} else {
					abnormal++
				}
			}
			if abnormal > 0 {
				metricsState = "abnormal"
			} else if unknown > 0 {
				metricsState = "unknown"
			}
			out["server_total"], out["server_normal"], out["server_abnormal"], out["server_unknown"], out["servers"] = len(nodes), normal, abnormal, unknown, nodes
		}
	}
	card("receiver", "中心接收与后台", "normal", "当前管理请求正常处理", "/servers/central?tab=system", now, common.Map{"版本": c["release"], "启动时间": s.started})
	card("metrics", "主机指标采集", metricsState, "采集状态按现有规则判定", "/servers", now, common.Map{"正常": normal, "异常": abnormal, "未知": unknown})
	// Fold existing node health evidence. Disabled scanners do not count as missing.
	for _, item := range []struct {
		id, name, metric, href string
		kinds                  []string
	}{{"files", "文件监控", "webscan_agent_heartbeat_seconds", "/events", []string{"agent", "coverage", "agent_metric_missing", "inotify_overflow", "dropped"}}, {"scanner", "安全扫描", "webscan_scan_heartbeat_seconds", "/events?operation=scan", []string{"scanner"}}, {"transport", "事件投递", "webscan_transport_up", "/servers", []string{"vector", "transport_rejected", "backlog"}}} {
		applicable, good, bad, missing, yara, clam := 0, 0, 0, 0, 0, 0
		var pending float64
		var oldest float64
		var stamp int64
		for _, n := range nodes {
			if n.Central || !n.Active {
				continue
			}
			cfg := common.M(common.M(c["nodes"])[n.ID])
			if item.id == "scanner" {
				if common.B(cfg["yara_enabled"]) {
					yara++
				}
				if common.B(cfg["clamav_enabled"]) {
					clam++
				}
				if cfg["yara_enabled"] != nil && !common.B(cfg["yara_enabled"]) && !common.B(cfg["clamav_enabled"]) {
					continue
				}
			}
			applicable++
			v, known := n.Snapshot.Values[item.metric]
			if item.id == "transport" && !known {
				v, known = n.Snapshot.Values["webscan_vector_metrics_up"]
			}
			if !known || n.Status != "normal" {
				missing++
				continue
			}
			unhealthy := false
			if item.id == "files" {
				coverage, ok := n.Snapshot.Values["webscan_coverage_ok"]
				if !ok {
					missing++
					continue
				}
				unhealthy = coverage == 0 || float64(now)-v > float64(max(60, 2*common.I(common.M(c["monitoring"])["interval_seconds"])))
			} else if item.id == "scanner" {
				unhealthy = float64(now)-v > 180
				pending += n.Snapshot.Values["webscan_pending_scans"]
			} else {
				unhealthy = v == 0
				pending += n.Snapshot.Values["webscan_local_pending_events"]
				oldest = max(oldest, n.Snapshot.Values["webscan_local_oldest_pending_seconds"])
			}
			if s.Telemetry != nil {
				for _, kind := range item.kinds {
					var firing int
					if e := s.Telemetry.DB.QueryRowContext(ctx, "SELECT count(*) FROM health_rules WHERE node=? AND phase='firing' AND (kind=? OR kind LIKE ?)", n.ID, kind, kind+":%").Scan(&firing); e != nil {
						missing++
						unhealthy = false
						known = false
						break
					}
					if firing > 0 {
						unhealthy = true
					}
				}
			}
			if !known {
				continue
			}
			if unhealthy {
				bad++
			} else {
				good++
			}
			stamp = max(stamp, n.Snapshot.Time)
		}
		state := "normal"
		if errs["metrics"] != nil {
			state = "unknown"
		} else if applicable == 0 {
			state = "disabled"
		} else if bad > 0 {
			state = "abnormal"
		} else if missing > 0 {
			state = "unknown"
		}
		m := common.Map{"适用节点": applicable, "正常": good, "异常": bad, "未知": missing}
		if item.id == "scanner" {
			m["YARA 启用节点"], m["ClamAV 启用节点"], m["待扫描"] = yara, clam, pending
		}
		if item.id == "transport" {
			m["待投递"], m["最老等待秒数"] = pending, oldest
		}
		if missing > 0 {
			if item.id == "scanner" {
				m["待扫描"] = nil
			}
			if item.id == "transport" {
				m["待投递"], m["最老等待秒数"] = nil, nil
			}
		}
		if errs["metrics"] != nil {
			for key := range m {
				m[key] = nil
			}
		}
		card(item.id, item.name, state, "仅统计已启用且适用的节点；缺失数据不代表正常", item.href, stamp, m)
	}
	dbState := "normal"
	var ping int
	if e := s.DB.QueryRowContext(ctx, "SELECT 1").Scan(&ping); e != nil {
		dbState = "unknown"
		errs["database"] = "事件数据库访问失败"
	}
	metricDBState := "disabled"
	if s.Telemetry != nil {
		metricDBState = "normal"
		if e := s.Telemetry.DB.QueryRowContext(ctx, "SELECT 1").Scan(&ping); e != nil {
			metricDBState = "unknown"
			dbState = "unknown"
		}
	}
	sizes := common.Map{"事件库访问": dbState, "指标库访问": metricDBState}
	for _, file := range []string{"events-v1.sqlite3", "metrics-v1.sqlite3"} {
		if info, e := os.Stat(filepath.Join(common.S(c["data_dir"]), file)); e == nil {
			sizes[file+" 字节"] = info.Size()
		} else {
			sizes[file+" 字节"] = nil
		}
	}
	card("database", "数据库", dbState, "文件删除后空间供 SQLite 复用，文件大小不一定立即下降", "/settings?group=历史与备份&storage=1", now, sizes)
	var sites, paused, down, pendingSites, normalSites, issues int
	if s.Websites != nil {
		e := s.DB.QueryRowContext(ctx, `SELECT count(*),COALESCE(sum(paused=1),0),COALESCE(sum(paused=0 AND json_extract(state,'$.status')='down'),0),COALESCE(sum(paused=0 AND json_extract(state,'$.status')='normal'),0) FROM websites WHERE deleted=0`).Scan(&sites, &paused, &down, &normalSites)
		if e != nil {
			errs["website"] = "网站状态读取失败"
		} else {
			pendingSites = sites - paused - down - normalSites
			out["website_total"], out["website_down"], out["website_paused"], out["website_normal"], out["website_pending"] = sites, down, paused, normalSites, pendingSites
		}
		if e = s.DB.QueryRowContext(ctx, "SELECT count(*) FROM website_incidents i JOIN websites w ON i.site=w.id WHERE i.ended IS NULL AND w.deleted=0 AND w.paused=0").Scan(&issues); e != nil {
			errs["website"] = "网站故障读取失败"
		}
		h := s.Websites.HealthSnapshot()
		state := "normal"
		if !common.B(h["healthy"]) {
			state = "abnormal"
		}
		h["待首次判断网站"] = pendingSites
		card("websites", "网站检测", state, "检查由主服务器执行", "/websites", int64(common.I(h["heartbeat"])), common.Map{"调度正常": h["healthy"], "调度心跳时间": h["heartbeat"], "积压持续秒数": h["backlog_seconds"], "待首次判断网站": pendingSites})
	} else {
		card("websites", "网站检测", "disabled", "尚未启用网站检测", "/settings", 0, common.Map{})
	}
	active := 0
	if s.Telemetry != nil {
		if e := s.Telemetry.DB.QueryRowContext(ctx, "SELECT count(*) FROM health_rules WHERE phase='firing'").Scan(&active); e != nil {
			errs["alerts"] = "服务器告警读取失败"
		} else {
			out["active_alerts"] = active
		}
	}
	out["current_issues"] = active + issues
	for _, target := range []string{"feishu", "email"} {
		var count, retry int
		var oldest sql.NullFloat64
		state := "normal"
		cfg := common.M(c[target])
		e := s.DB.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(attempts>0),0),min(created) FROM tasks WHERE target=? AND done IS NULL", target).Scan(&count, &retry, &oldest)
		if target == "email" && e == nil {
			e = s.DB.QueryRowContext(ctx, "SELECT count(DISTINCT task_id) FROM email_recipients WHERE done IS NULL AND attempts>0").Scan(&retry)
		}
		if !common.B(cfg["enabled"]) {
			state = "disabled"
		}
		if e != nil {
			state = "unknown"
			errs[target] = "通知队列读取失败"
		} else {
			if target == "feishu" {
				out["pending_notifications"] = count
			} else {
				out["pending_email"] = count
			}
			if state != "disabled" && (retry > 0 || oldest.Valid && float64(now)-oldest.Float64 > 300) {
				state = "abnormal"
			}
		}
		name, href := "飞书通知", "/alerts?tab=notifications"
		if target == "email" {
			name, href = "邮箱通知", "/alerts?tab=email"
		}
		card(target, name, state, "关闭时任务暂停；成功仅代表通知接口或邮件服务器确认", href, now, common.Map{"待投递": count, "重试": retry, "最早等待时间": oldest.Float64})
	}
	var events, security int
	e := s.DB.QueryRowContext(ctx, `SELECT count(*),COALESCE(sum(json_extract(payload,'$.operation')='scan' AND json_extract(payload,'$.scan.status')='matched'),0) FROM (SELECT node,id,payload,received FROM events UNION ALL SELECT node,id,payload,time FROM migrated_logs m WHERE NOT EXISTS(SELECT 1 FROM events e WHERE e.node=m.node AND e.id=json_extract(m.payload,'$.event_id'))) WHERE received>=? AND COALESCE(json_extract(payload,'$.operation'),'')<>'probe'`, now-86400).Scan(&events, &security)
	if e != nil {
		errs["events"] = "事件摘要读取失败"
	} else {
		out["events_24h"], out["security_24h"] = events, security
	}
	manager := s.managerHealth(ctx)
	managerState := "normal"
	if !common.B(manager["available"]) {
		managerState = "unknown"
		if common.S(c["management_socket"]) == "" {
			managerState = "unmanaged"
		}
		errs["manager"] = manager["message"]
	}
	card("manager", "宿主管理服务", managerState, common.S(manager["message"]), "/settings", now, common.Map{"配置应用": common.B(manager["available"])})
	watchdogState := managerState
	beat := int64(common.I(manager["watchdog_heartbeat"]))
	if managerState == "normal" {
		if common.B(manager["task_running"]) || common.B(manager["pending_task"]) {
			watchdogState = "maintenance"
		} else if beat == 0 || now-beat > 90 {
			watchdogState = "unknown"
		} else if common.S(manager["watchdog_phase"]) == "firing" {
			watchdogState = "abnormal"
		}
	}
	card("watchdog", "看门狗", watchdogState, "维护期间抑制预期故障；缺失心跳显示未知", "/servers/central?tab=system", beat, common.Map{"阶段": manager["watchdog_phase"]})
	deployState := managerState
	latest := common.M(manager["latest_job"])
	if managerState == "normal" && common.S(latest["status"]) == "failed" {
		deployState = "abnormal"
	}
	if common.B(manager["task_running"]) {
		deployState = "maintenance"
	}
	out["deployment_running"], out["deployment_latest"] = manager["task_running"], latest
	card("deployment", "部署任务", deployState, "没有运行任务时为空闲", "/deployments", int64(common.I(latest["updated"])), common.Map{"正在执行": manager["task_running"], "最近结果": latest["status"]})
	var backup string
	s.DB.QueryRowContext(ctx, "SELECT value FROM kv WHERE key='last_backup'").Scan(&backup)
	backupResult := common.Map{}
	var backupRaw string
	if s.DB.QueryRowContext(ctx, "SELECT value FROM kv WHERE key='last_backup_result'").Scan(&backupRaw) == nil {
		v, _ := common.Decode([]byte(backupRaw))
		backupResult = common.M(v)
	}
	cleanup := common.Map{}
	cleanupState := "normal"
	if s.Retention != nil {
		j, e := s.Retention.Jobs(ctx, "system", 1, 1)
		if e == nil && len(common.A(j["items"])) > 0 {
			cleanup = common.M(common.A(j["items"])[0])
		}
		if e != nil {
			cleanupState = "unknown"
		} else if common.S(cleanup["status"]) == "failed" {
			cleanupState = "abnormal"
		}
	} else {
		cleanupState = "unknown"
	}
	if common.S(backupResult["status"]) == "failed" {
		cleanupState = "abnormal"
	}
	card("maintenance", "备份与历史清理", cleanupState, "手工网站配置备份不按自动备份期限删除", "/settings?group=历史与备份&storage=1", int64(common.I(cleanup["updated"])), common.Map{"自动备份": common.B(common.M(c["backup"])["enabled"]), "最近备份": func() string {
		if backup == "" {
			return "未知"
		}
		return filepath.Base(backup)
	}(), "最近清理": cleanup["status"], "最近备份结果": backupResult["status"], "备份原因": backupResult["reason"]})
	out["components"], out["errors"] = components, errs
	// Missing sections stay explicitly unknown, rather than becoming zero.
	for section := range errs {
		switch section {
		case "website":
			for _, key := range []string{"website_total", "website_down", "website_paused", "website_normal", "website_pending", "current_issues"} {
				out[key] = nil
			}
		case "alerts":
			out["active_alerts"], out["current_issues"] = nil, nil
		case "events":
			out["events_24h"], out["security_24h"] = nil, nil
		case "feishu":
			out["pending_notifications"] = nil
		case "email":
			out["pending_email"] = nil
		}
	}
	write(w, 200, out)
}
