package management

import (
	"context"
	"database/sql"
	"fmt"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/config"
	"webscan/internal/deploy"
	"webscan/internal/persist"
	"webscan/internal/telemetry"
)

func (s *Service) migrate(ctx context.Context, id string) error {
	unlock, e := s.lock()
	if e != nil {
		return e
	}
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()
	c, e := config.Load(s.ConfigPath)
	if e != nil {
		return e
	}
	if deploy.Native(c) {
		if _, e := os.Stat(filepath.Join(s.StateDir, "native-migration-ready.json")); e != nil {
			return userError("已经使用 Go 一体化模式")
		}
		unlock()
		locked = false
		return deploy.Run(ctx, deploy.Options{Config: s.ConfigPath, Upgrade: true, CentralOnly: true, NonInteractive: true, KeepImages: true})
	}
	runtimePath := filepath.Join(c.CentralRoot(), "runtime.json")
	runtime, e := common.ReadJSON(runtimePath)
	if e != nil {
		return e
	}
	center := common.M(c.Raw["central"])
	if e = migrationSpace(common.S(center["data_dir"]), common.S(center["backup_dir"])); e != nil {
		return e
	}
	db, e := persist.OpenDB(filepath.Join(common.S(center["data_dir"]), "events-v1.sqlite3"))
	if e != nil {
		return e
	}
	defer db.Close()
	if e = persist.BackupDB(db, filepath.Join(common.S(center["backup_dir"]), "migrations", "events-before-native-"+id+".sqlite3")); e != nil {
		return e
	}
	if _, e = db.Exec(`CREATE TABLE IF NOT EXISTS migrated_logs(id TEXT PRIMARY KEY,node TEXT,operation TEXT,time REAL,payload TEXT);CREATE INDEX IF NOT EXISTS migrated_logs_time ON migrated_logs(time);`); e != nil {
		return e
	}
	m := common.M(runtime["monitoring"])
	nodes := []telemetry.Node{}
	for _, v := range common.A(m["nodes"]) {
		n := common.M(v)
		nodes = append(nodes, telemetry.Node{ID: common.S(n["id"]), Active: common.B(n["active"])})
	}
	metrics, e := telemetry.Open(common.S(center["data_dir"]), nodes, m)
	if e != nil {
		return e
	}
	defer metrics.DB.Close()
	if e = persist.BackupDB(metrics.DB, filepath.Join(common.S(center["backup_dir"]), "migrations", "metrics-before-native-"+id+".sqlite3")); e != nil {
		return e
	}
	client := &http.Client{Timeout: 30 * time.Second}
	now := time.Now().Unix()
	endFile := filepath.Join(s.StateDir, "native-migration-window.json")
	window, err := common.ReadJSON(endFile)
	if os.IsNotExist(err) {
		window = common.Map{"end": now, "start_metrics": now - int64(common.I(common.M(c.Raw["retention"])["prometheus_days"]))*86400, "start_logs": now - int64(common.I(common.M(c.Raw["retention"])["loki_days"]))*86400}
		if e = common.AtomicJSON(endFile, window); e != nil {
			return e
		}
	} else if err != nil {
		return err
	}
	log := func(msg string) { logWriter{s, id, nil}.Write([]byte(msg + "\n")) }
	log("开始分批迁移本项目历史；旧服务继续运行，新引擎不发送告警。")
	if e = metrics.ImportPrometheus(ctx, client, "http://127.0.0.1:19190", int64(common.F(window["start_metrics"])), int64(common.F(window["end"])), log); e != nil {
		return e
	}
	allowed := map[string]bool{}
	for _, n := range nodes {
		allowed[n.ID] = true
	}
	loki := common.S(runtime["loki_url"])
	if loki == "http://loki:3100" {
		loki = "http://127.0.0.1:3100"
	}
	for start := int64(common.F(window["start_logs"])); start < int64(common.F(window["end"])); start += 3600 {
		end := min(start+3600, int64(common.F(window["end"])))
		key := fmt.Sprintf("loki:%d:%d", start, end)
		var count int
		metrics.DB.QueryRow("SELECT count(*) FROM migrations WHERE id=?", key).Scan(&count)
		if count > 0 {
			continue
		}
		if e = importLoki(ctx, dbExec{db}, client, loki, start*1e9, end*1e9-1, allowed); e != nil {
			return e
		}
		if _, e = metrics.DB.Exec("INSERT INTO migrations VALUES(?,?)", key, "{}"); e != nil {
			return e
		}
		log("日志迁移完成至 " + time.Unix(end, 0).Format(time.RFC3339))
	}
	if e = metrics.Compact(ctx); e != nil {
		return e
	}
	// Freeze new Loki tasks through the authenticated internal reload endpoint.
	originalRuntime, e := os.ReadFile(runtimePath)
	if e != nil {
		return e
	}
	common.M(runtime["monitoring"])["drain_loki"] = true
	if e = common.AtomicJSON(runtimePath, runtime); e != nil {
		return e
	}
	reload := func() error {
		port := common.I(common.M(center["event_service"])["port"])
		status, _, err := common.Request(ctx, client, "POST", fmt.Sprintf("http://127.0.0.1:%d/reload-settings", port), common.Map{}, map[string]string{"Authorization": "Bearer " + common.S(runtime["alert_token"])})
		if err != nil {
			return err
		}
		if status != 200 {
			return userError("暂停旧日志投递失败")
		}
		return nil
	}
	switched := false
	defer func() {
		if current, err := common.ReadJSON(runtimePath); !switched && err == nil && common.S(common.M(current["monitoring"])["mode"]) != "native" {
			common.Atomic(runtimePath, originalRuntime, 0600)
			reload()
		}
	}()
	if e = reload(); e != nil {
		return e
	}
	// Old tasks still drain normally. New events remain committed in the event database.

	var pending int
	if e = db.QueryRow("SELECT count(*) FROM tasks WHERE target='loki' AND done IS NULL").Scan(&pending); e != nil {
		return e
	}
	deadline := time.Now().Add(2 * time.Minute)
	for pending > 0 && time.Now().Before(deadline) {
		if !common.Sleep(ctx, time.Second) {
			return ctx.Err()
		}
		if e = db.QueryRow("SELECT count(*) FROM tasks WHERE target='loki' AND done IS NULL").Scan(&pending); e != nil {
			return e
		}
	}
	if pending > 0 {
		return userError("旧 Loki 任务未清空，暂不切换；请检查旧投递后重新执行迁移")
	}
	cutoff := time.Now().Unix()
	if e = metrics.ImportPrometheus(ctx, client, "http://127.0.0.1:19190", int64(common.F(window["end"])), cutoff, log); e != nil {
		return e
	}
	if e = importLoki(ctx, dbExec{db}, client, loki, int64(common.F(window["end"]))*1e9, cutoff*1e9, allowed); e != nil {
		return e
	}
	if e = metrics.Compact(ctx); e != nil {
		return e
	}

	log("历史增量已持久化，接管当前活动告警。")
	alerts, e := telemetry.QueryLegacy(ctx, client, "http://127.0.0.1:19190", "/api/v1/alerts", url.Values{})
	if e != nil {
		return e
	}
	if e = seedAlerts(metrics, common.A(alerts["alerts"])); e != nil {
		return e
	}
	var samples, logs int
	if e = metrics.DB.QueryRowContext(ctx, "SELECT count(*) FROM samples WHERE source='legacy'").Scan(&samples); e != nil {
		return e
	}
	if e = db.QueryRowContext(ctx, "SELECT count(*) FROM migrated_logs").Scan(&logs); e != nil {
		return e
	}
	log(fmt.Sprintf("迁移核对：%d 条指标记录，%d 条日志记录；旧数据目录保留。", samples, logs))

	raw, e := os.ReadFile(s.ConfigPath)
	if e != nil {
		return e
	}
	if _, e = s.backup(raw, "切换一体化前"); e != nil {
		return e
	}
	var doc yaml.Node
	if e = yaml.Unmarshal(raw, &doc); e != nil {
		return e
	}
	if e = set(&doc, []string{"central", "monitoring", "mode"}, "native"); e != nil {
		return e
	}
	next, e := yaml.Marshal(&doc)
	if e != nil {
		return e
	}
	if e = common.AtomicJSON(filepath.Join(s.StateDir, "native-migration-ready.json"), common.Map{"time": time.Now().Unix(), "metrics": true, "logs": true, "old_config_revision": common.Hash(raw), "target_config_revision": common.Hash(next), "cutoff": cutoff, "sample_count": samples, "log_count": logs}); e != nil {
		return e
	}
	if e = common.Atomic(s.ConfigPath, next, 0600); e != nil {
		return e
	}
	unlock()
	locked = false
	if e = deploy.Run(ctx, deploy.Options{Config: s.ConfigPath, Upgrade: true, CentralOnly: true, NonInteractive: true, KeepImages: true}); e != nil {
		return e
	}
	switched = true
	log("Go 一体化切换及验收完成；旧组件数据目录已保留。")
	return nil
}

type dbExec struct{ *sql.DB }

func importLoki(ctx context.Context, db dbExec, client *http.Client, base string, start, end int64, allowed map[string]bool) error {
	data, e := telemetry.QueryLegacy(ctx, client, base, "/loki/api/v1/query_range", url.Values{"query": {`{job="webscan-v1"}`}, "start": {strconv.FormatInt(start, 10)}, "end": {strconv.FormatInt(end, 10)}, "direction": {"forward"}, "limit": {"1000"}})
	if e != nil {
		return e
	}
	result := common.A(data["result"])
	count := 0
	for _, v := range result {
		count += len(common.A(common.M(v)["values"]))
	}
	if count >= 1000 {
		if end-start < 2 {
			return userError("同一时间戳日志超过迁移批次限制，旧服务保留，请人工核对")
		}
		middle := start + (end-start)/2
		if e = importLoki(ctx, db, client, base, start, middle, allowed); e != nil {
			return e
		}
		return importLoki(ctx, db, client, base, middle+1, end, allowed)
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, v := range result {
		stream := common.M(v)
		labels := common.M(stream["stream"])
		node := common.S(labels["node_id"])
		if !allowed[node] {
			continue
		}
		for _, v := range common.A(stream["values"]) {
			pair := common.A(v)
			if len(pair) != 2 {
				return userError("旧日志格式错误")
			}
			stamp, e := strconv.ParseInt(common.S(pair[0]), 10, 64)
			if e != nil {
				return e
			}
			payload := common.S(pair[1])
			event, e := common.Decode([]byte(payload))
			if e != nil {
				return e
			}
			key := common.Hash(common.JSON(common.Map{"node": node, "stamp": stamp, "payload": payload}))
			if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO migrated_logs VALUES(?,?,?,?,?)", key, node, common.S(common.M(event)["operation"]), float64(stamp)/1e9, payload); e != nil {
				return e
			}
		}
	}
	return tx.Commit()
}
func seedAlerts(store *telemetry.Store, alerts []any) error {
	tx, e := store.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE health_rules SET phase='normal' WHERE phase IN ('firing','pending')"); e != nil {
		return e
	}
	for _, v := range alerts {
		a := common.M(v)
		labels := common.M(a["labels"])
		node := common.S(labels["node_id"])
		if node == "" && common.S(labels["job"]) == "webscan-central-host" {
			node = "central"
		}
		name := common.S(labels["alertname"])
		kind := map[string]string{"WebscanNodeUnreachable": "node_unreachable", "WebscanAgentStopped": "agent", "WebscanLocalProbeStale": "local_probe", "WebscanCentralProbeStale": "central_probe", "WebscanLokiProbeStale": "event_query", "WebscanCoverageGap": "coverage", "WebscanVectorStopped": "vector", "WebscanScannerStalled": "scanner", "WebscanClockUnsynchronized": "clock", "WebscanExporterMissingAgentMetric": "agent_metric_missing", "WebscanInotifyOverflow": "inotify_overflow", "WebscanDroppedEvents": "dropped", "WebscanBacklogLocal": "backlog:webscan_local_oldest_pending_seconds", "WebscanBacklogCentral": "backlog:webscan_oldest_pending_seconds", "WebscanCentralHostMetricsDown": "node_unreachable"}[name]
		if kind == "" {
			for _, metric := range []string{"Disk", "Inode"} {
				for _, level := range []string{"Warning", "Critical"} {
					if name == "Webscan"+metric+level {
						kind = strings.ToLower(metric) + ":" + common.S(labels["mountpoint"]) + ":" + strings.ToLower(level)
					}
				}
			}
		}
		if kind == "" {
			continue
		}
		started, _ := time.Parse(time.RFC3339Nano, common.S(a["activeAt"]))
		if started.IsZero() {
			started = time.Now()
		}
		phase := "pending"
		if common.S(a["state"]) == "firing" {
			phase = "firing"
		}
		st := telemetry.RuleState{Key: node + ":" + kind, Node: node, Kind: kind, Phase: phase, Since: started.Unix(), Last: time.Now().Unix(), Reminder: time.Now().Unix(), Severity: common.S(labels["severity"]), Message: common.S(common.M(a["annotations"])["summary"])}
		if _, e := tx.Exec("INSERT OR REPLACE INTO health_rules VALUES(?,?,?,?,?,?,?,?,?)", st.Key, node, kind, phase, st.Since, st.Last, 0, st.Reminder, string(common.JSON(st))); e != nil {
			return e
		}
	}
	return tx.Commit()
}

// Require room for consistent backups and imported history before modifying runtime.
func migrationSpace(data, backup string) error {
	for _, path := range []string{data, backup} {
		if e := os.MkdirAll(path, 0700); e != nil {
			return e
		}
	}
	var size uint64
	if e := filepath.Walk(data, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if info.Mode().IsRegular() {
			size += uint64(info.Size())
		}
		return nil
	}); e != nil {
		return e
	}
	required := size*2 + 512*1024*1024
	for _, path := range []string{data, backup} {
		var st unix.Statfs_t
		if e := unix.Statfs(path, &st); e != nil {
			return e
		}
		if uint64(st.Bavail)*uint64(st.Bsize) < required {
			return userErrorf("迁移空间不足：目录 %s 至少需要 %d MiB 可用空间（含一致性备份和历史导入预留）", path, required/(1024*1024))
		}
	}
	return nil
}
