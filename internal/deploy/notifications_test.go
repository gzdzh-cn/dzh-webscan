package deploy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"webscan/internal/common"
)

func TestDeploymentNotificationSelectionAndResume(t *testing.T) {
	oldRoot := StateRoot
	StateRoot = t.TempDir()
	defer func() { StateRoot = oldRoot }()
	c := fixture(t)
	common.M(c.Raw["feishu"])["enabled"] = true
	var messages []string
	var mu sync.Mutex
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer deployment-admin" || r.URL.Path != "/deployment-notices" {
			t.Error("incorrect authenticated endpoint")
		}
		raw, _ := io.ReadAll(r.Body)
		v, _ := common.Decode(raw)
		mu.Lock()
		messages = append(messages, common.S(common.M(v)["message"]))
		mu.Unlock()
		w.Write([]byte(`{"done":true}`))
	}))
	defer sink.Close()
	u, _ := url.Parse(sink.URL)
	port, _ := strconv.Atoi(u.Port())
	common.M(common.M(c.Raw["central"])["event_service"])["port"] = port
	d := &Deploy{C: c, O: Options{Node: "node-202"}, RunID: "fixture-run", State: common.Map{"deployment_notifications": common.Map{"run_id": "fixture-run", "nodes": common.Map{"node-202": common.Map{"php_complete": true}}}}, Secrets: common.Map{"alert_token": "deployment-admin"}, HTTP: sink.Client()}
	if err := d.DeploymentNotifications(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(messages) != 2 || !strings.Contains(messages[0], "角色：主服务器") || !strings.Contains(messages[1], "202") || strings.Contains(messages[1], "28（") {
		t.Fatal("single node notification scope/order incorrect", messages)
	}
	if !strings.Contains(messages[0], "192.0.2.1") || strings.Contains(messages[0], "（主服务器") {
		t.Fatal("main server IP formatting", messages[0])
	}
	mu.Unlock()
	if err := d.DeploymentNotifications(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(messages) != 2 {
		t.Fatal("resume resent confirmed notifications", len(messages))
	}
	mu.Unlock()
	d.RunID = "next-run"
	d.O.CentralOnly = true
	if err := d.DeploymentNotifications(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(messages) != 3 || !strings.Contains(messages[2], "角色：主服务器") {
		t.Fatal("central-only notified nodes", messages)
	}
	mu.Unlock()
	common.M(c.Raw["feishu"])["enabled"] = false
	d.RunID = "disabled-run"
	if err := d.DeploymentNotifications(context.Background()); err != nil || len(messages) != 3 {
		t.Fatal("disabled notification sent", err)
	}
}

func TestDeploymentMessageBeijingTime(t *testing.T) {
	message := deploymentMessage("测试服务器", "192.0.2.1", "子服务器", "v2.0.6", "2026-10-06T08:16:52Z")
	if !strings.Contains(message, "2026-10-06 16:16:52（北京时间）") || !strings.Contains(message, "监控部署完成") {
		t.Fatal(message)
	}
}

func TestNodeCompletionIncludesOneAcceptanceSummary(t *testing.T) {
	oldRoot := StateRoot
	StateRoot = t.TempDir()
	defer func() { StateRoot = oldRoot }()
	c := fixture(t)
	var messages []string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		v, _ := common.Decode(b)
		messages = append(messages, common.S(common.M(v)["message"]))
		w.Write([]byte(`{"done":true}`))
	}))
	defer sink.Close()
	u, _ := url.Parse(sink.URL)
	port, _ := strconv.Atoi(u.Port())
	common.M(common.M(c.Raw["central"])["event_service"])["port"] = port
	a := common.Map{"create": true, "modify": true, "move": true, "delete": true, "yara_match": true, "feishu_business_success": false}
	d := &Deploy{C: c, RunID: "summary-run", State: common.Map{"nodes": common.Map{"node-202": common.Map{"go_acceptance": a}}}, Secrets: common.Map{"alert_token": "fixture"}, HTTP: sink.Client()}
	if err := d.notifyServer(context.Background(), c.Selected("node-202")[0], false); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || !strings.Contains(messages[0], "新增、修改、移动、删除 PHP 和可疑代码检测均通过") || !common.B(a["feishu_business_success"]) {
		t.Fatal(messages, a)
	}
	if err := d.notifyServer(context.Background(), c.Selected("node-202")[0], false); err != nil || len(messages) != 1 {
		t.Fatal("summary duplicated on retry", err, messages)
	}
}

func TestResumeNotificationsMustKeepOriginalNodeScope(t *testing.T) {
	oldRoot := StateRoot
	StateRoot = t.TempDir()
	defer func() { StateRoot = oldRoot }()
	c := fixture(t)
	d, err := New(c, Options{Node: "node-202"})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.initialize(); err != nil {
		t.Fatal(err)
	}
	d.State["step"] = "notifying"
	if err = d.save(); err != nil {
		t.Fatal(err)
	}
	wrong, err := New(c, Options{Resume: true, Node: "node-28"})
	if err != nil {
		t.Fatal(err)
	}
	if err = wrong.initialize(); err == nil || err.Error() != "resume_scope_must_match_original_run" {
		t.Fatal("resume widened node scope", err)
	}
	resumed, err := New(c, Options{Resume: true, Node: "node-202"})
	if err != nil {
		t.Fatal(err)
	}
	if err = resumed.initialize(); err != nil || resumed.RunID != d.RunID || common.S(resumed.State["step"]) != "notifying" {
		t.Fatal("resume lost notification phase", err)
	}
}
