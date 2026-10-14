package central

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"
	"webscan/internal/notify"
)

func emailConfig(t *testing.T) common.Map {
	return common.Map{"data_dir": t.TempDir(), "backup_dir": t.TempDir(), "nodes": common.Map{}, "email": common.Map{"enabled": true, "smtp_host": "smtp.example.com", "smtp_port": 465, "tls_mode": "tls", "username": "sender@example.com", "password": "fixture-secret", "from_address": "sender@example.com", "from_name": "网站监控", "recipients": []string{"a@example.com", "b@example.com"}, "timeout_seconds": 1, "max_per_minute": 30, "retry": common.Map{"initial_delay_seconds": 1, "max_delay_seconds": 60}, "notifications": common.Map{"health_failures": true, "health_recoveries": true}}, "feishu": common.Map{"enabled": false}}
}
func TestEmailPartialRetryOrderingAndRestart(t *testing.T) {
	ctx := context.Background()
	c := emailConfig(t)
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	calls := map[string]int{}
	sender := func(_ context.Context, _ common.Map, r, _, _, _ string) error {
		calls[r]++
		if r == "b@example.com" && calls[r] == 1 {
			return fmt.Errorf("recipient rejected")
		}
		return nil
	}
	s.emailSend = sender
	if e = s.NoticePayload(ctx, "website:failure", common.Map{"message": "网站异常", "source": "website"}); e != nil {
		t.Fatal(e)
	}
	if e = s.NoticePayload(ctx, "website:recovery", common.Map{"message": "网站恢复", "source": "website"}); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		task, r, err := s.claimEmail(ctx, false)
		if err != nil || task == nil {
			t.Fatal(err)
		}
		if err = s.emailAttempt(ctx, task, r); err != nil {
			t.Fatal(err)
		}
	}
	if calls["a@example.com"] != 2 || calls["b@example.com"] != 1 {
		t.Fatal(calls)
	}
	s.DB.Close()
	s, e = New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	s.emailSend = sender
	s.DB.Exec("UPDATE email_recipients SET next_try=0")
	for i := 0; i < 2; i++ {
		task, r, err := s.claimEmail(ctx, false)
		if err != nil || task == nil {
			t.Fatal(err)
		}
		if err = s.emailAttempt(ctx, task, r); err != nil {
			t.Fatal(err)
		}
	}
	if calls["a@example.com"] != 2 || calls["b@example.com"] != 3 {
		t.Fatal(calls)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='email' AND done IS NOT NULL").Scan(&count)
	if count != 2 {
		t.Fatal(count)
	}
	// Duplicate enqueue cannot add new recipients to an existing notification.
	common.M(c["email"])["recipients"] = []string{"c@example.com"}
	s.NoticePayload(ctx, "website:failure", common.Map{"message": "same"})
	s.DB.QueryRow("SELECT count(*) FROM email_recipients WHERE recipient='c@example.com'").Scan(&count)
	if count != 0 {
		t.Fatal("recipient snapshot changed")
	}
}
func TestEmailPauseHistoryAndChannelIndependence(t *testing.T) {
	c := emailConfig(t)
	common.M(c["feishu"])["enabled"] = true
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	ctx := context.Background()
	s.NoticePayload(ctx, "native:fault", common.Map{"message": "test", "node_id": "node"})
	var email, feishu int
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='email'").Scan(&email)
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='feishu'").Scan(&feishu)
	if email != 1 || feishu != 1 {
		t.Fatal(email, feishu)
	}
	common.M(c["email"])["enabled"] = false
	if task, _, err := s.claimEmail(ctx, false); err != nil || task != nil {
		t.Fatal(task, err)
	}
	w := httptest.NewRecorder()
	s.emailAPI(w, httptest.NewRequest("GET", "/api/notifications?channel=email&status=paused", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"paused"`) || strings.Contains(w.Body.String(), "fixture-secret") {
		t.Fatal(w.Body.String())
	}
	common.M(c["email"])["enabled"] = true
	if task, _, e := s.claimEmail(ctx, false); e != nil || task == nil {
		t.Fatal(e)
	}
}
func TestEmailMigrationBackupAndOldTasks(t *testing.T) {
	c := emailConfig(t)
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	s.DB.Exec("INSERT INTO tasks(node,event_id,target,payload,created,next_try) VALUES('node','old','feishu','{}',1,1)")
	s.DB.Exec("DROP TABLE email_attempts")
	s.DB.Exec("DROP TABLE email_recipients")
	s.DB.Close()
	s, e = New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	files, _ := filepath.Glob(filepath.Join(common.S(c["backup_dir"]), "email-migration-*.sqlite3"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	info, _ := os.Stat(files[0])
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE event_id='old'").Scan(&count)
	if count != 1 {
		t.Fatal("old task lost")
	}
	_ = notify.Categories
}

func TestEmailTestAuthCSRFThrottle(t *testing.T) {
	s := consoleFixture(t)
	c := emailConfig(t)
	s.Config["email"] = c["email"]
	w := httptest.NewRecorder()
	s.Websites.Handler(w, httptest.NewRequest("POST", "/api/notifications/email-test", strings.NewReader(`{}`)))
	if w.Code != 401 {
		t.Fatal("anonymous mail test", w.Code)
	}
	w = httptest.NewRecorder()
	s.Websites.Handler(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"fixture-password"}`)))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	cookies := w.Result().Cookies()
	v, _ := common.Decode(w.Body.Bytes())
	csrf := common.S(common.M(v)["csrf_token"])
	send := func(token string) int {
		req := httptest.NewRequest("POST", "/api/notifications/email-test", strings.NewReader(`{}`))
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		req.Header.Set("X-CSRF-Token", token)
		out := httptest.NewRecorder()
		s.Websites.Handler(out, req)
		return out.Code
	}
	if code := send(""); code != 403 {
		t.Fatal("CSRF missing", code)
	}
	if code := send(csrf); code != 200 {
		t.Fatal("enqueue", code)
	}
	if code := send(csrf); code != 429 {
		t.Fatal("test throttle", code)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='email'").Scan(&count)
	if count != 1 {
		t.Fatal(count)
	}
}

func TestEmailRateSharedAndWatchdogQueue(t *testing.T) {
	c := emailConfig(t)
	common.M(c["email"])["max_per_minute"] = 1
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	ctx := context.Background()
	if e = WatchdogNotice(ctx, c, "watchdog:fixture:firing", "测试中心异常", false); e != nil {
		t.Fatal(e)
	}
	task, recipient, e := s.claimEmail(ctx, true)
	if e != nil || task == nil || !strings.HasPrefix(task.EventID, "watchdog:") {
		t.Fatal(task, e)
	}
	var history string
	s.DB.QueryRow("SELECT value FROM kv WHERE key='email_rate_history'").Scan(&history)
	if history == "" {
		t.Fatal("rate not persisted")
	}
	if next, _, e := s.claimEmail(ctx, false); e != nil || next != nil {
		t.Fatal("shared rate exceeded", e)
	}
	s.DB.Exec("UPDATE email_recipients SET lease=0 WHERE task_id=? AND recipient=?", task.ID, recipient)
	common.M(c["email"])["enabled"] = false
	if next, _, e := s.claimEmail(ctx, true); e != nil || next != nil {
		t.Fatal("disabled watchdog mail", e)
	}
}
func TestEmailMigrationBackupFailurePreservesData(t *testing.T) {
	c := emailConfig(t)
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	s.DB.Exec("INSERT INTO tasks(node,event_id,target,payload,created,next_try) VALUES('node','must-preserve','feishu','{}',1,1)")
	s.DB.Exec("DROP TABLE email_attempts")
	s.DB.Exec("DROP TABLE email_recipients")
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	os.WriteFile(blocker, []byte("block"), 0600)
	c["backup_dir"] = blocker
	if _, e = New(c); e == nil {
		t.Fatal("migration proceeded without backup")
	}
	var n int
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE event_id='must-preserve'").Scan(&n)
	if n != 1 {
		t.Fatal("lost original task")
	}
	s.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='email_recipients'").Scan(&n)
	if n != 0 {
		t.Fatal("schema modified after failed backup")
	}
	s.DB.Close()
}

func TestFileMailCategoryAndInternalProbe(t *testing.T) {
	c := emailConfig(t)
	c["max_batch_events"] = 100
	c["active_nodes"] = []string{"node"}
	c["nodes"] = common.Map{"node": common.Map{"name": "fixture", "host": "192.0.2.1"}}
	common.M(common.M(c["email"])["notifications"])["file_changes"] = true
	c["feishu"] = common.Map{"enabled": true, "notifications": common.Map{"file_changes": false}}
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	event := fixture()
	if _, e = s.Ingest(context.Background(), "node", []any{event}); e != nil {
		t.Fatal(e)
	}
	probe := common.Clone(event)
	probe["event_id"] = "internal-probe"
	probe["operation"] = "probe"
	if _, e = s.Ingest(context.Background(), "node", []any{probe}); e != nil {
		t.Fatal(e)
	}
	var email, feishu int
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='email'").Scan(&email)
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='feishu'").Scan(&feishu)
	if email != 1 || feishu != 0 {
		t.Fatal("category coupling or internal notification", email, feishu)
	}
}
