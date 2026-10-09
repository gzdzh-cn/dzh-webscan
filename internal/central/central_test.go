package central

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"
	"webscan/internal/persist"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	c := common.Map{"data_dir": t.TempDir(), "max_batch_events": 100, "max_request_mib": 2, "nodes": common.Map{"node": common.Map{"host": "127.0.0.1", "name": "测试", "token": "fixture-token"}}, "active_nodes": []string{"node"}, "feishu": common.Map{"enabled": true, "notifications": common.Map{"file_changes": true, "important_config_changes": true, "scan_matches": true, "scan_errors": true, "health_failures": true}, "timeout_seconds": 10, "retry": common.Map{"initial_delay_seconds": 1, "max_delay_seconds": 10}, "rate_limit": common.Map{"max_per_second": 10, "max_per_minute": 100}}}
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	return s
}
func fixture() common.Map {
	return common.Map{"event_id": "fixture-1", "node_id": "node", "operation": "modify", "time": "2026-10-06T00:00:00+00:00", "path": "/中文/<at>\u2028.php", "risk": "unclassified", "scan": common.Map{"status": "pending"}}
}
func TestIngestLegacyDigestDedupAndConflict(t *testing.T) {
	s := testStore(t)
	e := fixture()
	b, err := common.Canonical(e, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ids, err := s.Ingest(ctx, "node", []any{e})
	if err != nil || len(ids) != 1 {
		t.Fatal(err)
	}
	var digest string
	s.DB.QueryRow("SELECT digest FROM events").Scan(&digest)
	if digest != common.Hash(b) {
		t.Fatal("digest incompatible")
	}
	if _, err = s.Ingest(ctx, "node", []any{e}); err != nil {
		t.Fatal(err)
	}
	var n int
	s.DB.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&n)
	if n != 2 {
		t.Fatal("duplicate delivery", n)
	}
	e["path"] = "/different.php"
	if _, err = s.Ingest(ctx, "node", []any{e}); err == nil {
		t.Fatal("conflicting event accepted")
	}
}
func TestNotificationsAndDurableRetry(t *testing.T) {
	s := testStore(t)
	e := fixture()
	e["operation"] = "scan"
	e["scan"] = common.Map{"status": "no_match"}
	s.Ingest(context.Background(), "node", []any{e})
	var n int
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='feishu'").Scan(&n)
	if n != 0 {
		t.Fatal("unmatched scan notified")
	}
	task, err := s.claim(context.Background(), "loki")
	if err != nil || task == nil {
		t.Fatal(err)
	}
	if err = s.finish(context.Background(), task, "network_error", true); err != nil {
		t.Fatal(err)
	}
	var attempts int
	s.DB.QueryRow("SELECT attempts FROM tasks WHERE id=?", task.ID).Scan(&attempts)
	if attempts != 1 {
		t.Fatal("retry lost")
	}
}
func TestHTTPRejectsUnauthorizedAndOversize(t *testing.T) {
	s := testStore(t)
	r := httptest.NewRequest("POST", "/events", strings.NewReader(string(common.JSON(fixture()))))
	w := httptest.NewRecorder()
	s.Handler(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	r = httptest.NewRequest("POST", "/events", strings.NewReader(strings.Repeat("a", 2*1048576+1)))
	r.Header.Set("Authorization", "Bearer fixture-token")
	w = httptest.NewRecorder()
	s.Handler(w, r)
	if w.Code != 413 {
		t.Fatal(w.Code)
	}
}
func TestFeishuSignatureMentionAndBusinessError(t *testing.T) {
	f := common.Map{"message_prefix": "test", "signing_enabled": true, "signing_secret": "fixture-secret"}
	p := FeishuPayload(f, "<at user_id=\"all\">x</at>", 123)
	mac := hmac.New(sha256.New, []byte("123\nfixture-secret"))
	if common.S(p["sign"]) != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatal("signature")
	}
	if strings.Contains(common.S(common.M(p["content"])["text"]), "<at") {
		t.Fatal("unsafe mention")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"code":19001}`)) }))
	defer server.Close()
	s := testStore(t)
	common.M(s.Config["feishu"])["webhook_url"] = server.URL
	_, err := s.send(context.Background(), &Task{Target: "feishu", Payload: string(common.JSON(common.Map{"message": "test"}))})
	if err == nil || !strings.HasPrefix(err.Error(), "feishu_business_code_") {
		t.Fatal(err)
	}
}

func TestOldSchemaPriorityMigrationAndUnfinishedTask(t *testing.T) {
	c := common.Map{"data_dir": t.TempDir(), "feishu": common.Map{"timeout_seconds": 10}}
	db, e := persist.OpenDB(filepath.Join(common.S(c["data_dir"]), "events-v1.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	oldSchema := strings.ReplaceAll(Schema, ",priority INTEGER NOT NULL DEFAULT 0", "")
	if _, e = db.Exec(oldSchema); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO tasks(node,event_id,target,payload,created,next_try,attempts,lease) VALUES('node','old-id','loki','{}',1,1,7,0)"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	task, e := s.claim(context.Background(), "loki")
	if e != nil || task == nil || task.EventID != "old-id" || task.Attempts != 7 {
		t.Fatal("unfinished task not preserved", task, e)
	}
}

func TestWebsiteRecoveryWaitsForOutageRetryWithoutBlockingFileAlerts(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for _, id := range []string{"website:1:0", "website:2:0", "ordinary-file-event"} {
		if _, e := s.DB.Exec("INSERT INTO tasks(node,event_id,target,payload,created,next_try) VALUES('central',?,'feishu','{}',?,?)", id, common.Now(), common.Now()); e != nil {
			t.Fatal(e)
		}
	}
	first, e := s.claim(ctx, "feishu")
	if e != nil || first.EventID != "website:1:0" {
		t.Fatal(first, e)
	}
	if e = s.finish(ctx, first, "offline", true); e != nil {
		t.Fatal(e)
	}
	next, e := s.claim(ctx, "feishu")
	if e != nil || next.EventID != "ordinary-file-event" {
		t.Fatal("website retry blocks file event", next, e)
	}
	s.finish(ctx, next, "ok", false)
	next, e = s.claim(ctx, "feishu")
	if e != nil || next != nil {
		t.Fatal("recovery overtook outage", next, e)
	}
	s.DB.Exec("UPDATE tasks SET next_try=0 WHERE id=?", first.ID)
	next, e = s.claim(ctx, "feishu")
	if e != nil || next.ID != first.ID {
		t.Fatal(next, e)
	}
	s.finish(ctx, next, "ok", false)
	next, e = s.claim(ctx, "feishu")
	if e != nil || next.EventID != "website:2:0" {
		t.Fatal("recovery not released", next, e)
	}
}
