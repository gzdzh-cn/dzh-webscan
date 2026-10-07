package central

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"webscan/internal/common"
)

func TestBeijingNotificationTime(t *testing.T) {
	for input, expected := range map[string]string{
		"2026-10-06T08:16:52.144979+00:00": "2026-10-06 16:16:52（北京时间）",
		"2026-10-06T23:59:59.999999999Z":   "2026-10-07 07:59:59（北京时间）",
		"2026-10-06T16:16:52+08:00":        "2026-10-06 16:16:52（北京时间）",
		"2026-10-06T03:16:52-05:00":        "2026-10-06 16:16:52（北京时间）",
		"invalid":                          "时间未记录",
	} {
		if got := noticeTime(input); got != expected {
			t.Fatalf("%q: %q", input, got)
		}
	}
}

func TestChineseEventNoticesDoNotChangeCanonicalEvent(t *testing.T) {
	for _, tc := range []struct{ op, status, reason, want string }{
		{"create", "pending", "", "发现新增文件"}, {"modify", "pending", "", "发现文件被修改"},
		{"delete", "not_applicable", "", "文件已删除，无需扫描"}, {"move", "pending", "", "原位置：/网站/原文件.php"},
		{"scan", "matched", "", "发现可疑代码"}, {"scan", "no_match", "", "未发现可疑特征"},
		{"scan", "error", "scanner_exit", "扫描超时或执行失败"}, {"scan", "error", "unknown_error", "扫描未能完成"},
		{"scan", "skipped", "", "本次未扫描"}, {"health", "not_applicable", "file_read_gap", "部分文件无法读取"},
	} {
		t.Run(tc.op+"-"+tc.status+"-"+tc.reason, func(t *testing.T) {
			e := common.Map{"event_id": "deadbeef", "server_name": "子服务器", "server_ip": "192.0.2.1", "site": "网站", "path": "/网站/文件.php", "old_path": "/网站/原文件.php", "operation": tc.op, "time": "2026-10-06T08:16:52.144979+00:00", "risk": "unclassified", "reason": tc.reason, "scan": common.Map{"status": tc.status, "engines": common.Map{"yara": common.Map{"status": tc.status, "reason": tc.reason}}}}
			before, _ := common.Canonical(e, false)
			got := eventNotice(e)
			if !strings.Contains(got, tc.want) || !strings.Contains(got, "16:16:52（北京时间）") {
				t.Fatal(got)
			}
			for _, raw := range []string{"unclassified", "pending", "matched", "scanner_exit", "unknown_error", "not_applicable", "UTC", "\"status\"", "deadbeef", "file_read_gap"} {
				if strings.Contains(got, raw) {
					t.Fatalf("raw value leaked: %s", got)
				}
			}
			after, _ := common.Canonical(e, false)
			if string(before) != string(after) {
				t.Fatal("notification changed stored event")
			}
		})
	}
}

func TestFeishuRequestUsesChineseBeijingNotice(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload common.Map
		json.NewDecoder(r.Body).Decode(&payload)
		got = common.S(common.M(payload["content"])["text"])
		w.Write([]byte(`{"code":0}`))
	}))
	defer server.Close()
	s := testStore(t)
	f := common.M(s.Config["feishu"])
	f["webhook_url"] = server.URL
	f["message_prefix"] = "【网站监控】"
	e := fixture()
	e["time"] = "2026-10-06T08:16:52.144979+00:00"
	result, err := s.send(context.Background(), &Task{Target: "feishu", Payload: string(common.JSON(e))})
	if err != nil || result != "http=200,business=0" {
		t.Fatal(result, err)
	}
	if !strings.Contains(got, "发现文件被修改") || !strings.Contains(got, "2026-10-06 16:16:52（北京时间）") || strings.Contains(got, "pending") {
		t.Fatal(got)
	}
}

func TestChineseHealthAlerts(t *testing.T) {
	s := testStore(t)
	for _, status := range []string{"firing", "resolved"} {
		a := common.Map{"status": status, "startsAt": "2026-10-06T08:03:00Z", "endsAt": "2026-10-06T08:08:00Z", "labels": common.Map{"node_id": "node", "alertname": "WebscanNodeUnreachable", "severity": "critical"}, "annotations": common.Map{"summary": "WebscanNodeUnreachable"}}
		got := s.alertNotice(a)
		if !strings.Contains(got, "无法连接该服务器的监控采集服务") || strings.Contains(got, "Webscan") || strings.Contains(got, "critical") {
			t.Fatal(got)
		}
		if status == "resolved" && (!strings.Contains(got, "监控已恢复") || !strings.Contains(got, "16:08:00")) {
			t.Fatal(got)
		}
	}
}
