package deploy

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/progress"
)

func (d *Deploy) deploymentAPI(ctx context.Context, path string, payload common.Map) (common.Map, error) {
	port := common.I(common.M(common.M(d.C.Raw["central"])["event_service"])["port"])
	_, value, err := common.Request(ctx, d.HTTP, "POST", "http://127.0.0.1:"+strconv.Itoa(port)+path, payload, map[string]string{"Authorization": "Bearer " + common.S(d.Secrets["alert_token"])})
	if err != nil {
		return nil, errors.New("deployment_notification_request_failed")
	}
	return common.M(value), nil
}

func (d *Deploy) waitDeploymentDelivery(ctx context.Context, path string, payload common.Map) (common.Map, error) {
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		v, err := d.deploymentAPI(ctx, path, payload)
		if err == nil && common.B(v["done"]) {
			return v, nil
		}
		if !common.Sleep(ctx, time.Second) {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("deployment_notification_pending_resume")
}

func deploymentMessage(name, host, role, version, stamp string) string {
	t, _ := time.Parse(time.RFC3339Nano, stamp)
	return fmt.Sprintf("监控部署完成\n服务器：%s（%s）\n角色：%s\n版本：%s\n验收结果：监控服务已启动，部署验收通过\n完成时间：%s（北京时间）", name, host, role, version, t.In(time.FixedZone("北京时间", 8*3600)).Format("2006-01-02 15:04:05"))
}

func (d *Deploy) notificationState() common.Map {
	s := common.M(d.State["deployment_notifications"])
	if common.S(s["run_id"]) != d.RunID {
		s = common.Map{"run_id": d.RunID, "nodes": common.Map{}}
		d.State["deployment_notifications"] = s
	}
	return s
}

func (d *Deploy) notifyServer(ctx context.Context, n common.Map, central bool) error {
	s := d.notificationState()
	id, name, host, role := common.S(n["id"]), common.S(n["name"]), common.S(n["host"]), "子服务器（网站文件监控）"
	if central {
		u, _ := url.Parse(common.S(common.M(d.C.Raw["central"])["public_url"]))
		id, name, host, role = "central", "主服务器", u.Hostname(), "主服务器（接收事件和发送告警）"
	}
	entry := common.M(common.M(s["nodes"])[id])
	if common.B(entry["notified"]) {
		return nil
	}
	if common.S(entry["time"]) == "" {
		entry["time"] = common.Stamp()
		common.M(s["nodes"])[id] = entry
		if err := d.save(); err != nil {
			return err
		}
	}
	version := Release
	if central && d.O.AddNode {
		version = common.S(d.State["central_runtime_release"])
	}
	message := deploymentMessage(name, host, role, version, common.S(entry["time"]))
	if !central {
		a := common.M(common.M(common.M(d.State["nodes"])[id])["go_acceptance"])
		if common.B(a["create"]) && common.B(a["modify"]) && common.B(a["move"]) && common.B(a["delete"]) && common.B(a["yara_match"]) {
			message += "\n检测验收：新增、修改、移动、删除 PHP 和可疑代码检测均通过；Loki 记录可查询，待投递队列已核对\n说明：以上为独立目录中的自动测试，不是业务网站异常"
		}
	}
	payload := common.Map{"id": "deployment:" + common.Hash([]byte(d.RunID+":"+id+":complete")), "message": message}
	if _, err := d.waitDeploymentDelivery(ctx, "/deployment-notices", payload); err != nil {
		return err
	}
	entry["notified"], entry["feishu_business_success"] = true, true
	if !central {
		a := common.M(common.M(common.M(d.State["nodes"])[id])["go_acceptance"])
		a["feishu_business_success"] = true
	}
	progress.Info(ctx, "飞书已确认部署完成通知发送成功")
	return d.save()
}

// Run all completion notices first, then each selected node's real PHP modify
// test. A retry uses the same task IDs and test registration, without replacing
// healthy containers just because Feishu was temporarily unreachable.
func (d *Deploy) DeploymentNotifications(ctx context.Context) error {
	if !common.B(common.M(d.C.Raw["feishu"])["enabled"]) {
		progress.Warn(ctx, "feishu.enabled 已关闭：跳过部署完成通知和 PHP 修改通知测试")
		return nil
	}
	if err := progress.Stage(ctx, progress.Host(d.C.Raw), "发送主服务器部署完成通知并确认飞书成功", func(ctx context.Context) error { return d.notifyServer(ctx, nil, true) }); err != nil {
		return err
	}
	selected := []common.Map{}
	if !d.O.CentralOnly {
		selected = d.C.Selected(d.O.Node)
	}
	for _, n := range selected {
		if err := progress.Stage(ctx, progress.Node(n), "发送子服务器部署完成通知并确认飞书成功", func(ctx context.Context) error { return d.notifyServer(ctx, n, false) }); err != nil {
			return err
		}
	}
	for _, n := range selected {
		if err := progress.Stage(ctx, progress.Node(n), "真实修改测试 PHP，确认飞书告警和 Loki 记录", func(ctx context.Context) error { return d.DeploymentPHPTest(ctx, n) }); err != nil {
			return err
		}
	}
	return nil
}

func waitFixtureCreate(ctx context.Context, db *sql.DB, node, path, hash string) error {
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM events WHERE node=? AND json_extract(payload,'$.operation')='create' AND json_extract(payload,'$.path')=? AND json_extract(payload,'$.sha256')=?", node, path, hash).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			return nil
		}
		if !common.Sleep(ctx, time.Second) {
			return ctx.Err()
		}
	}
	return errors.New("deployment_php_baseline_timeout")
}

func (d *Deploy) DeploymentPHPTest(ctx context.Context, n common.Map) error {
	node := common.S(n["id"])
	entry := common.M(common.M(d.notificationState()["nodes"])[node])
	if common.B(entry["php_complete"]) {
		return nil
	}
	r, err := d.remote(ctx, n)
	if err != nil {
		return err
	}
	key := common.Hash([]byte(d.RunID + ":" + node))[:32]
	root, err := deploymentFixtureRoot(n, key)
	if err != nil {
		return err
	}
	path := filepath.Join(root, "fixture.php")
	if err = d.requireFixtureCapability(ctx, path); err != nil {
		return err
	}
	baseline := []byte("<?php /* deployment fixture baseline " + key + " */\n")
	modified := []byte("<?php /* deployment fixture modified " + key + " */\n")
	payload := common.Map{"id": "deployment:" + key + ":php", "node": node, "path": path, "sha256": common.Hash(modified)}
	status, err := d.deploymentAPI(ctx, "/deployment-tests", payload)
	if err != nil {
		return err
	}
	if common.S(status["event_id"]) == "" && !common.B(entry["php_modified"]) {
		if !common.B(entry["php_baseline"]) {
			progress.Info(ctx, "创建独立测试 PHP，等待节点采集新增事件："+path)
			if err = r.Write(ctx, path, baseline, 0600); err != nil {
				return err
			}
			db, err := persist.OpenDB(filepath.Join(common.S(common.M(d.C.Raw["central"])["data_dir"]), "events-v1.sqlite3"))
			if err != nil {
				return err
			}
			err = waitFixtureCreate(ctx, db, node, path, common.Hash(baseline))
			db.Close()
			if err != nil {
				return err
			}
			entry["php_baseline"] = true
			if err = d.save(); err != nil {
				return err
			}
		}
		progress.Info(ctx, "测试文件基线已收到，正在原地修改 PHP；等待真实修改告警")
		// Write in place and close, so the Agent must detect a real PHP modify
		// rather than an atomic rename or a fabricated API event.
		command := "set -eu; test -f " + Q(path) + "; test ! -L " + Q(root) + "; test ! -L " + Q(path) + "; cat > " + Q(path) + "; sync -f " + Q(path)
		if _, err = r.Exec(ctx, command, bytes.NewReader(modified)); err != nil {
			return err
		}
		entry["php_modified"], entry["php_path"] = true, path
		if err = d.save(); err != nil {
			return err
		}
	}
	status, err = d.waitDeploymentDelivery(ctx, "/deployment-tests", payload)
	if err != nil {
		return err
	}
	if err = d.waitLokiEvent(ctx, node, common.S(status["event_id"])); err != nil {
		return err
	}
	if _, err = r.Run(ctx, "set -eu; rm -f -- "+Q(path)+"; if test -d "+Q(root)+"; then rmdir -- "+Q(root)+"; fi"); err != nil {
		return err
	}
	entry["php_complete"], entry["php_event_id"], entry["php_completed_at"] = true, status["event_id"], common.Stamp()
	progress.Info(ctx, "真实 PHP 修改告警：飞书业务响应成功，Loki 可查询，测试文件已清理")
	return d.save()
}
