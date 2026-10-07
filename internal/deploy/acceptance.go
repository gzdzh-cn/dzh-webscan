package deploy

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/progress"
)

func (d *Deploy) nodeClient() (*http.Client, error) {
	c, e := common.HTTPClient(filepath.Join(d.C.CentralRoot(), "pki", "ca.crt"), 10*time.Second)
	if e != nil {
		return nil, e
	}
	cert, e := tls.LoadX509KeyPair(filepath.Join(d.C.CentralRoot(), "pki", "client.crt"), filepath.Join(d.C.CentralRoot(), "pki", "client.key"))
	if e != nil {
		return nil, e
	}
	c.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{cert}
	return c, nil
}
func (d *Deploy) metrics(ctx context.Context, n common.Map) (map[string]float64, error) {
	c, e := d.nodeClient()
	if e != nil {
		return nil, e
	}
	r, e := http.NewRequestWithContext(ctx, "GET", "https://"+common.S(n["host"])+":"+strconv.Itoa(common.I(common.M(n["metrics"])["port"]))+"/metrics", nil)
	if e != nil {
		return nil, e
	}
	resp, e := c.Do(r)
	if e != nil {
		return nil, errors.New("metrics_request_failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("metrics_http_status")
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 4*1048576))
	if e != nil {
		return nil, e
	}
	return parseMetrics(raw), nil
}

func parseMetrics(raw []byte) map[string]float64 {
	out := map[string]float64{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.HasPrefix(line, "#") {
			continue
		}
		value, e := strconv.ParseFloat(fields[1], 64)
		if e == nil {
			out[fields[0]] = value
		}
	}
	return out
}
func (d *Deploy) prom(ctx context.Context, path string) (common.Map, error) {
	_, v, e := common.Request(ctx, d.HTTP, "GET", "http://127.0.0.1:19190/api/v1/"+path, nil, nil)
	if e != nil {
		return nil, e
	}
	if common.S(common.M(v)["status"]) != "success" {
		return nil, errors.New("prometheus_query_failed")
	}
	return common.M(common.M(v)["data"]), nil
}
func (d *Deploy) WaitHealth(ctx context.Context, n common.Map) error {
	deadline := time.Now().Add(6 * time.Minute)
	notice := time.Now().Add(-10 * time.Second)
	for time.Now().Before(deadline) {
		m, e := d.metrics(ctx, n)
		healthy := e == nil && m["webscan_collector_ready"] == 1 && m["webscan_baseline_completed"] == 1 && m["webscan_coverage_ok"] == 1 && m["webscan_vector_metrics_up"] == 1 && common.Now()-m["webscan_agent_heartbeat_seconds"] < 90 && common.Now()-m["webscan_local_probe_seconds"] < 180 && m["webscan_local_oldest_pending_seconds"] < 300
		if healthy {
			for _, metric := range []string{"webscan_probe_received_seconds", "webscan_probe_loki_seconds"} {
				query := metric + `{node_id="` + common.S(n["id"]) + `"}`
				data, err := d.prom(ctx, "query?"+url.Values{"query": {query}}.Encode())
				if err != nil {
					healthy = false
					break
				}
				rows := common.A(data["result"])
				if len(rows) != 1 {
					healthy = false
					break
				}
				value := common.A(common.M(rows[0])["value"])
				if len(value) != 2 {
					healthy = false
					break
				}
				stamp, _ := strconv.ParseFloat(common.S(value[1]), 64)
				if common.Now()-stamp > 180 {
					healthy = false
					break
				}
			}
		}
		if healthy {
			data, err := d.prom(ctx, "alerts")
			if err != nil {
				healthy = false
			} else {
				for _, a := range common.A(data["alerts"]) {
					node := common.S(common.M(common.M(a)["labels"])["node_id"])
					if node == common.S(n["id"]) || node == "" {
						healthy = false
						break
					}
				}
			}
		}
		if healthy {
			return nil
		}
		if time.Since(notice) >= 10*time.Second {
			flag := func(value float64) string {
				if value == 1 {
					return "正常"
				}
				return "等待"
			}
			progress.Info(ctx, fmt.Sprintf("健康核对：清单 %s｜目录覆盖 %s｜Vector %s｜待投递 %.0f 条｜待扫描 %.0f 条", flag(m["webscan_baseline_completed"]), flag(m["webscan_coverage_ok"]), flag(m["webscan_vector_metrics_up"]), m["webscan_local_pending_events"], m["webscan_pending_scans"]))
			if e != nil {
				progress.Info(ctx, "尚未取得节点 HTTPS 指标，继续等待")
			}
			notice = time.Now()
		}
		if !common.Sleep(ctx, 3*time.Second) {
			return ctx.Err()
		}
	}
	return errors.New("node_health_acceptance_timeout")
}
func (d *Deploy) AcceptNode(ctx context.Context, n common.Map) error {
	if !common.B(common.M(d.C.Raw["deployment"])["run_acceptance_tests"]) {
		return errors.New("acceptance_tests_required_before_switch_completion")
	}
	r, e := d.remote(ctx, n)
	if e != nil {
		return e
	}
	base := common.SS(common.M(n["monitor"])["roots"])[0]
	root := base + "/.webscan-deploy-test-" + common.ID()
	moveRoot := base + "/.webscan-deploy-test-" + common.ID()
	yaraRoot := base + "/.webscan-deploy-test-" + common.ID()
	if _, e = r.Run(ctx, "umask 077; mkdir -- "+Q(root)+" "+Q(moveRoot)+" "+Q(yaraRoot)); e != nil {
		return e
	}
	defer r.Run(context.WithoutCancel(ctx), "rm -rf -- "+Q(root)+" "+Q(moveRoot)+" "+Q(yaraRoot))
	db, e := persist.OpenDB(filepath.Join(common.S(common.M(d.C.Raw["central"])["data_dir"]), "events-v1.sqlite3"))
	if e != nil {
		return e
	}
	defer db.Close()
	node := common.S(n["id"])
	path, dest, marker := root+"/fixture.php", moveRoot+"/fixture.php", yaraRoot+"/fixture.php"
	baseline := []byte("<?php /* owned GoFrame acceptance " + common.ID() + " */")
	modified := []byte("<?php /* owned modified GoFrame acceptance " + common.ID() + " */")
	yaraContent := []byte("<?php /* owned detector fixture; eval( base64_decode( never executed */")
	_, ready, err := common.Request(ctx, d.HTTP, "GET", fmt.Sprintf("http://127.0.0.1:%d/ready", common.I(common.M(common.M(d.C.Raw["central"])["event_service"])["port"])), nil, nil)
	if err != nil {
		return err
	}
	quiet := common.B(common.M(ready)["deployment_acceptance"])
	if quiet {
		events := []any{}
		add := func(op, p, hash, status string) {
			events = append(events, common.Map{"operation": op, "path": p, "sha256": hash, "scan": common.Map{"status": status}})
		}
		for _, sample := range []struct {
			op, path string
			content  []byte
			status   string
		}{{"create", path, baseline, "no_match"}, {"modify", path, modified, "no_match"}, {"move", dest, modified, "no_match"}, {"create", marker, yaraContent, "matched"}} {
			add(sample.op, sample.path, common.Hash(sample.content), "")
			add("scan", sample.path, common.Hash(sample.content), sample.status)
		}
		add("delete", dest, common.Hash(modified), "")
		add("delete", marker, common.Hash(yaraContent), "")
		if _, err = d.deploymentAPI(ctx, "/deployment-acceptance", common.Map{"node": node, "events": events}); err != nil {
			return err
		}
		progress.Info(ctx, "已登记本次测试文件和预期内容：普通测试告警汇总，业务文件及意外扫描异常正常告警")
	} else {
		progress.Info(ctx, "现有主服务器兼容原接口：普通文件测试已静默，YARA 测试命中可能单独通知；主服务器升级后支持全部测试通知汇总")
	}
	start := common.Now()
	waitEvent := func(ctx context.Context, operation, path, hash, scan string) error {
		deadline := time.Now().Add(150 * time.Second)
		notice := time.Now()
		for time.Now().Before(deadline) {
			rows, e := db.QueryContext(ctx, "SELECT payload FROM events WHERE node=? AND received>=?", node, start)
			if e != nil {
				return e
			}
			found, scanned := false, scan == ""
			ids := []string{}
			for rows.Next() {
				var payload string
				if e = rows.Scan(&payload); e != nil {
					rows.Close()
					return e
				}
				v, e := common.Decode([]byte(payload))
				if e != nil {
					rows.Close()
					return e
				}
				event := common.M(v)
				if common.S(event["path"]) != path {
					continue
				}
				op := common.S(event["operation"])
				same := hash == "" || common.S(event["sha256"]) == hash
				if op == operation && same {
					found = true
					ids = append(ids, common.S(event["event_id"]))
				}
				if op == "scan" && same && common.S(common.M(event["scan"])["status"]) == scan {
					scanned = true
					ids = append(ids, common.S(event["event_id"]))
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			if found && scanned {
				progress.Info(ctx, "文件事件及扫描结果已收到，正在确认投递和 Loki 查询；测试结果汇总到部署完成通知")
				for _, id := range ids {
					if e = waitDeliveries(ctx, db, node, id); e != nil {
						return e
					}
					if e = d.waitLokiEvent(ctx, node, id); e != nil {
						return e
					}
				}
				return nil
			}
			if time.Since(notice) >= 10*time.Second {
				state := func(ok bool) string {
					if ok {
						return "已收到"
					}
					return "尚未收到"
				}
				progress.Info(ctx, "中央验收记录：文件事件 "+state(found)+"；预期扫描结果 "+state(scanned)+"。若节点本地已有记录，请检查 Vector 传输。")
				notice = time.Now()
			}
			if !common.Sleep(ctx, time.Second) {
				return ctx.Err()
			}
		}
		return fmt.Errorf("acceptance_event_timeout_%s", operation)
	}
	wait := func(operation, path, hash, scan string) error {
		label := map[string]string{"create": "新增 PHP 文件", "modify": "修改 PHP 文件", "move": "移动 PHP 文件", "delete": "删除 PHP 文件"}[operation]
		if scan == "matched" {
			label += "及 YARA 命中"
		}
		return progress.Stage(ctx, progress.Node(n), "验收："+label+"、扫描及消息投递", func(ctx context.Context) error { return waitEvent(ctx, operation, path, hash, scan) })
	}
	content := baseline
	if e = r.Write(ctx, path, content, 0600); e != nil {
		return e
	}
	if e = wait("create", path, common.Hash(content), "no_match"); e != nil {
		return e
	}
	content = modified
	if e = r.Write(ctx, path, content, 0600); e != nil {
		return e
	}
	if e = wait("modify", path, common.Hash(content), "no_match"); e != nil {
		return e
	}
	if _, e = r.Run(ctx, "mv -- "+Q(path)+" "+Q(dest)); e != nil {
		return e
	}
	if e = wait("move", dest, common.Hash(content), "no_match"); e != nil {
		return e
	}
	if _, e = r.Run(ctx, "rm -- "+Q(dest)); e != nil {
		return e
	}
	if e = wait("delete", dest, "", ""); e != nil {
		return e
	}
	content = yaraContent
	if e = r.Write(ctx, marker, content, 0600); e != nil {
		return e
	}
	if e = wait("create", marker, common.Hash(content), "matched"); e != nil {
		return e
	}
	if _, e = r.Run(ctx, "rm -- "+Q(marker)); e != nil {
		return e
	}
	if e = wait("delete", marker, "", ""); e != nil {
		return e
	}
	state := common.M(common.M(d.State["nodes"])[node])
	state["go_acceptance"] = common.Map{"time": common.Now(), "create": true, "modify": true, "move": true, "delete": true, "yara_match": true, "loki_delivered": true, "loki_query_verified": true, "notifications_summarized": quiet, "feishu_business_success": false}
	return d.save()
}
func waitDeliveries(ctx context.Context, db *sql.DB, node, id string) error {
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		var pending int
		if e := db.QueryRowContext(ctx, "SELECT count(*) FROM tasks WHERE node=? AND event_id=? AND done IS NULL", node, id).Scan(&pending); e != nil {
			return e
		}
		if pending == 0 {
			rows, e := db.QueryContext(ctx, "SELECT target,result FROM tasks WHERE node=? AND event_id=?", node, id)
			if e != nil {
				return e
			}
			count := 0
			for rows.Next() {
				var target, result string
				if e = rows.Scan(&target, &result); e != nil {
					rows.Close()
					return e
				}
				want := "http=204"
				if target == "feishu" {
					want = "http=200,business=0"
				}
				if result != want {
					rows.Close()
					return errors.New("acceptance_delivery_not_successful")
				}
				count++
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			if count > 0 {
				return nil
			}
		}
		if !common.Sleep(ctx, time.Second) {
			return ctx.Err()
		}
	}
	return errors.New("acceptance_delivery_timeout")
}

var _ = os.Getpid

func (d *Deploy) waitLokiEvent(ctx context.Context, node, id string) error {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		query := `{job="webscan-v1",node_id="` + node + `"} |= "` + id + `"`
		params := url.Values{"query": {query}, "start": {strconv.FormatInt(time.Now().Add(-15*time.Minute).UnixNano(), 10)}, "end": {strconv.FormatInt(time.Now().UnixNano(), 10)}, "limit": {"100"}}
		_, value, err := common.Request(ctx, d.HTTP, "GET", "http://127.0.0.1:3100/loki/api/v1/query_range?"+params.Encode(), nil, nil)
		if err == nil && common.S(common.M(value)["status"]) == "success" {
			for _, stream := range common.A(common.M(common.M(value)["data"])["result"]) {
				for _, row := range common.A(common.M(stream)["values"]) {
					pair := common.A(row)
					if len(pair) == 2 {
						event, e := common.Decode([]byte(common.S(pair[1])))
						if e == nil && common.S(common.M(event)["event_id"]) == id {
							return nil
						}
					}
				}
			}
		}
		if !common.Sleep(ctx, 2*time.Second) {
			return ctx.Err()
		}
	}
	return errors.New("acceptance_event_not_queryable_in_loki")
}
