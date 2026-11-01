package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeploymentHistoryDeleteAPIAuthenticationTransportStrictnessAndOwner(t *testing.T) {
	f := newDeploymentHistoryFixture(t)
	api := NewAPI(f.s, Config{})
	admin := token()
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,'admin',1,'history-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(admin)))
	viewer := historyAPISession(t, f.s, "reader", "viewer")
	other := historyAPISession(t, f.s, "other", "admin")
	call := func(method, path, body, session, csrf, key string, https bool) *httptest.ResponseRecorder {
		t.Helper()
		url := "https://local/api/v3/deployments/" + path
		if !https {
			url = "http://local/api/v3/deployments/" + path
		}
		r := httptest.NewRequest(method, url, strings.NewReader(body))
		if session != "" {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: session})
		}
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	body := `{"records":["deployment-job:` + f.old.ID + `"]}`
	for _, c := range []struct {
		name, session, csrf string
		https               bool
		want                int
	}{{"anonymous", "", "", true, 401}, {"csrf", admin, "", true, 403}, {"viewer", viewer, "history-csrf", true, 403}, {"http", admin, "history-csrf", false, 403}} {
		if w := call("POST", "history-delete-preview", body, c.session, c.csrf, "api-preview-"+c.name, c.https); w.Code != c.want {
			t.Fatal(c.name, w.Code, w.Body.String())
		}
	}
	for i, bad := range []string{`{"records":[],"records":[]}`, `{"Records":[]}`, `{"records":[],"unknown":true}`, `{"records":null}`, `{"records":["event:wrong"]}`} {
		if w := call("POST", "history-delete-preview", bad, admin, "history-csrf", "bad-body-"+strings.Repeat("a", i+1), true); w.Code != 400 {
			t.Fatal("noncanonical request accepted", w.Code, w.Body.String())
		}
	}
	if w := call("POST", "history-delete-preview", body, admin, "history-csrf", "", true); w.Code != 400 {
		t.Fatal("missing idempotency key", w.Code)
	}
	w := call("POST", "history-delete-preview", body, admin, "history-csrf", "api-valid-preview", true)
	var p deploymentHistoryDeletePreview
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Eligible != 1 || p.Token == "" {
		t.Fatal("preview failed", w.Code, w.Body.String())
	}
	confirm := `{"token":"` + p.Token + `","confirm":true}`
	if w = call("POST", "history-delete", confirm, other, "history-csrf", "foreign-confirm", true); w.Code != 409 {
		t.Fatal("foreign preview accepted", w.Code, w.Body.String())
	}
	w = call("POST", "history-delete", confirm, admin, "history-csrf", "api-valid-confirm", true)
	var job deploymentHistoryDeleteJob
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &job) != nil || job.Status != "queued" || job.Deleted != 0 {
		t.Fatal("task creation falsely claimed completion", w.Code, w.Body.String())
	}
	if w = call("GET", "history-delete-jobs/"+job.ID, "", other, "", "", true); w.Code != 404 {
		t.Fatal("foreign task readable", w.Code)
	}
	if w = call("GET", "history-delete-jobs/"+job.ID, "", viewer, "", "", true); w.Code != 403 {
		t.Fatal("viewer read destructive task", w.Code)
	}
	historyDeletionFinish(t, f, job)
	w = call("GET", "history-delete-jobs/"+job.ID, "", admin, "", "", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &job) != nil || job.Status != "succeeded" || len(job.Items) != 1 || job.Items[0].Status != "deleted" {
		t.Fatal("task outcomes unavailable", w.Code, w.Body.String())
	}
	for _, suffix := range []string{f.old.ID, f.old.ID + "/logs"} {
		if w = call("GET", suffix, "", admin, "", "", true); w.Code != 404 {
			t.Fatal("archived public history remains accessible", w.Code, w.Body.String())
		}
	}
	if _, err := f.s.Deployment(context.Background(), f.old.ID); err != nil {
		t.Fatal("public archive erased internal recovery history", err)
	}
}
