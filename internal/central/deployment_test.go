package central

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"webscan/internal/common"
)

func deploymentCall(s *Store, path, token string, body common.Map) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(string(common.JSON(body))))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler(w, r)
	return w
}

func TestDeploymentEndpointsRequireAdminAndStayOffPublicListener(t *testing.T) {
	s := testStore(t)
	s.Config["alert_token"] = "deployment-admin"
	s.Config["https"] = common.Map{"allowed_sources": []string{"0.0.0.0/0"}}
	body := common.Map{"id": "deployment:fixture", "message": "部署完成"}
	for _, token := range []string{"", "fixture-token", "wrong"} {
		if w := deploymentCall(s, "/deployment-notices", token, body); w.Code != 401 {
			t.Fatal("unauthorized", w.Code)
		}
	}
	r := httptest.NewRequest("POST", "https://example.test/deployment-notices", strings.NewReader(string(common.JSON(body))))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer deployment-admin")
	w := httptest.NewRecorder()
	s.Handler(w, r)
	if w.Code != 404 {
		t.Fatal("public deployment API exposed", w.Code)
	}
	common.M(s.Config["feishu"])["enabled"] = false
	if w = deploymentCall(s, "/deployment-notices", "deployment-admin", body); w.Code != 409 {
		t.Fatal("disabled Feishu accepted", w.Code)
	}
}

func TestDeploymentNoticeDurableBusinessRetryAndDedup(t *testing.T) {
	s := testStore(t)
	s.Config["alert_token"] = "deployment-admin"
	body := common.Map{"id": "deployment:fixture", "message": "主服务器部署完成"}
	w := deploymentCall(s, "/deployment-notices", "deployment-admin", body)
	if w.Code != 200 || strings.Contains(w.Body.String(), `"done":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"code":19001}`)) }))
	defer sink.Close()
	common.M(s.Config["feishu"])["webhook_url"] = sink.URL
	task, err := s.claim(context.Background(), "feishu")
	if err != nil || task == nil {
		t.Fatal(err)
	}
	_, err = s.send(context.Background(), task)
	if err == nil {
		t.Fatal("business failure counted as success")
	}
	if err = s.finish(context.Background(), task, err.Error(), true); err != nil {
		t.Fatal(err)
	}
	// A new store instance resumes the same persisted task and registration.
	reopened, err := New(s.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	w = deploymentCall(reopened, "/deployment-notices", "deployment-admin", body)
	if strings.Contains(w.Body.String(), `"done":true`) {
		t.Fatal("retry marked done")
	}
	var count int
	if err = reopened.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='feishu'").Scan(&count); err != nil || count != 1 {
		t.Fatal("retry duplicated notification", count, err)
	}
	if err = reopened.finish(context.Background(), task, "http=200,business=0", false); err != nil {
		t.Fatal(err)
	}
	w = deploymentCall(reopened, "/deployment-notices", "deployment-admin", body)
	if !strings.Contains(w.Body.String(), `"done":true`) {
		t.Fatal(w.Body.String())
	}
}

func TestRegisteredRealPHPModifyOverridesFileSwitchOnce(t *testing.T) {
	s := testStore(t)
	s.Config["alert_token"] = "deployment-admin"
	common.M(common.M(s.Config["feishu"])["notifications"])["file_changes"] = false
	path := "/sites/.webscan-deploy-test-0123456789abcdef0123456789abcdef/fixture.php"
	hash := common.Hash([]byte("modified PHP fixture"))
	body := common.Map{"id": "deployment:php", "node": "node", "path": path, "sha256": hash}
	if w := deploymentCall(s, "/deployment-tests", "deployment-admin", body); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	ctx := context.Background()
	for i, op := range []string{"create", "modify", "modify", "delete"} {
		e := fixture()
		e["event_id"], e["operation"], e["path"], e["sha256"] = []string{"baseline", "real-modify", "same-hash-modify", "cleanup"}[i], op, path, hash
		if _, err := s.Ingest(ctx, "node", []any{e}); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='feishu'").Scan(&count)
	if count != 1 {
		t.Fatal("missing or duplicate PHP test", count)
	}
	var eventID string
	s.DB.QueryRow("SELECT event_id FROM tasks WHERE target='feishu'").Scan(&eventID)
	if eventID != "real-modify" {
		t.Fatal("test was not the real modify", eventID)
	}
	w := deploymentCall(s, "/deployment-tests", "deployment-admin", body)
	if !strings.Contains(w.Body.String(), `"event_id":"real-modify"`) || strings.Contains(w.Body.String(), `"done":true`) {
		t.Fatal(w.Body.String())
	}
	for _, target := range []string{"feishu", "loki"} {
		want := "http=200,business=0"
		if target == "loki" {
			want = "http=204"
		}
		s.DB.Exec("UPDATE tasks SET done=1,result=? WHERE event_id='real-modify' AND target=?", want, target)
	}
	w = deploymentCall(s, "/deployment-tests", "deployment-admin", body)
	if !strings.Contains(w.Body.String(), `"done":true`) {
		t.Fatal(w.Body.String())
	}
	body["sha256"] = common.Hash([]byte("different"))
	if w = deploymentCall(s, "/deployment-tests", "deployment-admin", body); w.Code != 409 {
		t.Fatal("conflicting registration accepted", w.Code)
	}
}

func TestUnregisteredOrWrongHashPHPModificationDoesNotPassTest(t *testing.T) {
	s := testStore(t)
	path := "/sites/.webscan-deploy-test-0123456789abcdef0123456789abcdef/fixture.php"
	e := fixture()
	e["path"], e["sha256"] = path, common.Hash([]byte("wrong"))
	if _, err := s.Ingest(context.Background(), "node", []any{e}); err != nil {
		t.Fatal(err)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='feishu'").Scan(&count)
	if count != 0 {
		t.Fatal("unregistered modification generated deployment notification")
	}
	if err := s.registerDeploymentTest(context.Background(), deploymentTestKey("node", path), common.Map{"id": "deployment:wrong-hash", "node": "node", "path": path, "sha256": common.Hash([]byte("expected"))}); err != nil {
		t.Fatal(err)
	}
	e["event_id"] = "wrong-hash-event"
	if _, err := s.Ingest(context.Background(), "node", []any{e}); err != nil {
		t.Fatal(err)
	}
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='feishu'").Scan(&count)
	if count != 0 {
		t.Fatal("wrong content passed deployment PHP test")
	}
}
