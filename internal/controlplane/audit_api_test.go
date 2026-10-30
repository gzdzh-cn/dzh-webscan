package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuditSummaryRejectsPrivateNestedAndUntypedFields(t *testing.T) {
	raw := []byte(`{"deleted":12,"skipped":3,"processed":9007199254740993,"status":"complete","phase":"PRIVATE","token":"PRIVATE","password":"PRIVATE","message":"PRIVATE","scope":{"categories":["events","PRIVATE"],"node":"node-a","before":"2026-01-01T00:00:00Z","records":["PRIVATE-record"],"password":"PRIVATE"},"scope_summary":[{"source":"events","node":"node-a","before":100,"upper":9007199254740993,"selected":2,"password":"PRIVATE"}],"exported":{"password":"PRIVATE"}}`)
	public, err := json.Marshal(publicAuditResult(raw))
	if err != nil || strings.Contains(string(public), "PRIVATE") || !strings.Contains(string(public), "9007199254740993") || !strings.Contains(string(public), `"selected":1`) {
		t.Fatal(string(public), err)
	}
	if !publicAuditResult([]byte("not-json"))["details_unavailable"].(bool) {
		t.Fatal("malformed summary not marked unknown")
	}
}

func TestAuditAPIReadOnlyRoleIsolationPaginationAndFailure(t *testing.T) {
	s := testStore(t)
	admin := historyAPISession(t, s, "admin", "admin")
	operator := historyAPISession(t, s, "operator", "operator")
	viewer := historyAPISession(t, s, "viewer", "viewer")
	mustHistoryExec(t, s.DB, `INSERT INTO v3_audit(id,username,kind,resource,result,created_at) VALUES(9007199254740993,'admin','fixture','a','{"deleted":1,"password":"PRIVATE"}',clock_timestamp()-interval '1 hour'),(9007199254740994,'operator','fixture','b','{}',clock_timestamp()-interval '1 hour'),(9007199254740995,'viewer','fixture','c','{}',clock_timestamp()-interval '1 hour'),(9007199254740996,'system','fixture','d','{}',clock_timestamp()-interval '1 hour')`)
	api := &API{Store: s}
	call := func(method, query, value string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "/api/v3/audit?"+query, nil)
		if value != "" {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: value})
		}
		r.Header.Set("X-CSRF-Token", "history-csrf")
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, method := range []string{"POST", "DELETE", "PUT"} {
		if w := call(method, "", admin); w.Code != 405 {
			t.Fatal("audit mutation exposed", method, w.Code)
		}
	}
	for value, actors := range map[string]map[string]bool{admin: {"admin": true, "operator": true, "viewer": true, "system": true}, operator: {"operator": true, "system": true}, viewer: {"viewer": true, "system": true}} {
		w := call("GET", "kind=fixture", value)
		var page struct {
			Items []AuditRecord `json:"items"`
			Next  string        `json:"next_cursor"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != len(actors) || strings.Contains(w.Body.String(), "PRIVATE") {
			t.Fatal(w.Code, w.Body.String())
		}
		for _, v := range page.Items {
			if !actors[v.Username] || v.CanDelete || v.DeleteReason == "" || v.RecordKey != "audit:"+v.ID {
				t.Fatal("audit permissions or identity lost", v)
			}
		}
	}
	w := call("GET", "kind=fixture&limit=1", admin)
	var page struct {
		Items []AuditRecord `json:"items"`
		Next  string        `json:"next_cursor"`
	}
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Next == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	first := page.Items[0].ID
	w = call("GET", "kind=fixture&limit=1&cursor="+page.Next, admin)
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || w.Code != 200 || len(page.Items) != 1 || page.Items[0].ID == first {
		t.Fatal("audit pagination repeated or rounded identity", w.Code, w.Body.String())
	}
	if w = call("GET", "actor=admin", operator); w.Code != 200 || strings.Contains(w.Body.String(), "audit:9007199254740993") {
		t.Fatal("actor filter bypassed permission", w.Code)
	}
	for _, query := range []string{"limit=201", "cursor=bad", "actor=%00", "kind=%00", "start=bad"} {
		if w = call("GET", query, admin); w.Code != 400 {
			t.Fatal(query, w.Code)
		}
	}
	s.DB.Close()
	if w = call("GET", "", admin); w.Code != 503 {
		t.Fatal("database failure treated as logout", w.Code)
	}
}
