package management

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/config"
	"webscan/internal/deploy"
)

func preflightRequest(t *testing.T, s *Service, method, path, owner string, input any) (int, common.Map) {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(common.JSON(input)))
	r.Header.Set("X-Webscan-Owner", owner)
	w := httptest.NewRecorder()
	s.Handler(w, r)
	v, e := common.Decode(w.Body.Bytes())
	if e != nil {
		t.Fatal(w.Body.String())
	}
	return w.Code, common.M(v)
}
func awaitPreflight(t *testing.T, s *Service, id string) common.Map {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, v := request(t, s, "GET", "/servers/preflight/"+id, nil)
		if common.S(v["status"]) == "complete" {
			return v
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("preflight did not finish")
	return nil
}
func TestAutomaticCheckFailureDoesNotSaveKeyConfigOrCreateJob(t *testing.T) {
	s := managerFixture(t)
	key := fixturePrivateKey(t, "openssh")
	edit := keyEdit(t, s, key)
	before := revision(t, s)
	calls := 0
	s.preflightRunner = func(_ context.Context, _ *config.Config, _ common.Map, content string, active bool, _ func(deploy.CheckItem)) deploy.CheckReport {
		calls++
		if content != key || !active {
			t.Error("draft/check mode lost")
		}
		return deploy.CheckReport{OK: false, Items: []deploy.CheckItem{{Name: "指标连接", Status: "failed", Message: "连接超时", Suggestion: "检查安全组"}}}
	}
	code, v := request(t, s, "POST", "/jobs", Start{Key: "blocked", Kind: "add-node", Node: common.S(edit.Node["id"]), Revision: before, Edit: &edit})
	if code < 400 || !strings.Contains(common.S(v["message"]), "安全组") || calls != 1 {
		t.Fatal(code, v, calls)
	}
	var jobs int
	s.DB.QueryRow("SELECT count(*) FROM jobs").Scan(&jobs)
	if revision(t, s) != before || len(keyFiles(t, s)) != 0 || jobs != 0 {
		t.Fatal("failed preflight committed state")
	}
}
func TestAsyncReportProgressOwnerBindingAndWarningConfirmation(t *testing.T) {
	s := managerFixture(t)
	edit := keyEdit(t, s, fixturePrivateKey(t, "openssh"))
	before := revision(t, s)
	release := make(chan struct{})
	entered := make(chan struct{})
	s.preflightRunner = func(ctx context.Context, _ *config.Config, _ common.Map, _ string, _ bool, emit func(deploy.CheckItem)) deploy.CheckReport {
		item := deploy.CheckItem{Name: "Docker", Status: "warning", Message: "将安装 Compose"}
		emit(item)
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return deploy.CheckReport{OK: false}
		}
		return deploy.CheckReport{OK: true, Items: []deploy.CheckItem{item}}
	}
	code, v := request(t, s, "POST", "/servers/preflight", preflightInput{Edit: edit, Async: true, Active: true})
	if code != 202 {
		t.Fatal(code, v)
	}
	id := common.S(v["id"])
	<-entered
	_, progress := request(t, s, "GET", "/servers/preflight/"+id, nil)
	if len(common.A(common.M(progress["report"])["items"])) != 1 {
		t.Fatal("missing progress", progress)
	}
	if code, _ := preflightRequest(t, s, "GET", "/servers/preflight/"+id, "other", nil); code != 404 {
		t.Fatal("cross-account read")
	}
	if code, _ := preflightRequest(t, s, "DELETE", "/servers/preflight/"+id, "other", nil); code != 404 {
		t.Fatal("cross-account cancel")
	}
	close(release)
	completed := awaitPreflight(t, s, id)
	if strings.Contains(string(common.JSON(completed)), "PRIVATE KEY") || revision(t, s) != before || len(keyFiles(t, s)) != 0 {
		t.Fatal("report leaked or persisted secrets")
	}
	in := Start{Key: "warned", Kind: "add-node", Node: common.S(edit.Node["id"]), Revision: before, Edit: &edit, PreflightToken: id}
	code, _ = request(t, s, "POST", "/jobs", in)
	if code < 400 {
		t.Fatal("warning not confirmed")
	}
	// A draft modification must invalidate the completed check.
	changed := edit
	changed.Node = common.Clone(edit.Node)
	changed.Node["name"] = "changed"
	in.Edit = &changed
	in.AcknowledgeWarnings = true
	if code, _ := request(t, s, "POST", "/jobs", in); code < 400 {
		t.Fatal("changed draft accepted")
	}
	in.Edit = &edit
	s.execute = func(context.Context, string, string, string) error { return errors.New("isolated failure after save") }
	if code, v := request(t, s, "POST", "/jobs", in); code != 202 {
		t.Fatal(code, v)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()
		if !running {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(keyFiles(t, s)) != 1 {
		t.Fatal("accepted key not retained")
	}
}
func TestReadOnlyExpiredAndCancelledReportsCannotAuthorizeDeployment(t *testing.T) {
	for _, variant := range []string{"readonly", "expired", "state"} {
		t.Run(variant, func(t *testing.T) {
			s := managerFixture(t)
			edit := keyEdit(t, s, fixturePrivateKey(t, "openssh"))
			code, v := request(t, s, "POST", "/servers/preflight", preflightInput{Edit: edit, Async: true, Active: variant != "readonly"})
			if code != 202 {
				t.Fatal(v)
			}
			id := common.S(v["id"])
			awaitPreflight(t, s, id)
			if variant == "expired" {
				s.mu.Lock()
				s.preflights[id].Expires = 0
				s.mu.Unlock()
			}
			if variant == "state" {
				common.AtomicJSON(s.StateDir+"/state.json", common.Map{"changed": true})
			}
			if code, _ := request(t, s, "POST", "/jobs", Start{Key: "test", Kind: "add-node", Node: common.S(edit.Node["id"]), Revision: edit.Revision, Edit: &edit, PreflightToken: id}); code < 400 {
				t.Fatal("invalid report accepted")
			}
		})
	}
	s := managerFixture(t)
	edit := keyEdit(t, s, "")
	entered := make(chan struct{})
	s.preflightRunner = func(ctx context.Context, _ *config.Config, _ common.Map, _ string, _ bool, _ func(deploy.CheckItem)) deploy.CheckReport {
		close(entered)
		<-ctx.Done()
		return deploy.CheckReport{OK: false, Items: []deploy.CheckItem{{Status: "failed", Message: "已取消"}}}
	}
	_, v := request(t, s, "POST", "/servers/preflight", preflightInput{Edit: edit, Async: true, Active: true})
	id := common.S(v["id"])
	<-entered
	request(t, s, "DELETE", "/servers/preflight/"+id, nil)
	done := awaitPreflight(t, s, id)
	if common.B(common.M(done["report"])["ok"]) {
		t.Fatal("cancelled check passed")
	}
	unlock, e := s.lock()
	if e != nil {
		t.Fatal("cancel left deployment lock", e)
	}
	unlock()
}
func TestRequirementsUseAppliedMainSettingsAndDoNotReturnSecrets(t *testing.T) {
	s := managerFixture(t)
	c, _ := config.Load(s.ConfigPath)
	saved := common.Clone(c.Raw)
	common.M(saved["central"])["public_url"] = "https://192.0.2.99:20443"
	common.AtomicJSON(s.StateDir+"/state.json", common.Map{"central_installed": true, "configuration": saved})
	before, _ := os.ReadFile(s.ConfigPath)
	code, v := request(t, s, "GET", "/servers/requirements", nil)
	if code != 200 || common.S(v["event_url"]) != "https://192.0.2.99:20443" || bytes.Contains(common.JSON(v), []byte("fixture-only-password")) {
		t.Fatal(code, v)
	}
	after, _ := os.ReadFile(s.ConfigPath)
	if !bytes.Equal(before, after) {
		t.Fatal("requirements wrote config")
	}
}
