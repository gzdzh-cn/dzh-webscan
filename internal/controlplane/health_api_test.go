package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthAPIAuthenticationPaginationProtectionAndFailure(t *testing.T) {
	s, n, _, _ := healthFixture(t)
	api := &API{Store: s}
	for _, path := range []string{"/api/v3/alerts/current", "/api/v3/alerts/history"} {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 401 {
			t.Fatal(path, w.Code)
		}
	}
	if err := s.Provision(context.Background(), "viewer", "fixture-password-123"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE v3_accounts SET role='viewer'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,'viewer',1,'csrf',clock_timestamp()+interval '1 hour')`, digest([]byte("fixture-token"))); err != nil {
		t.Fatal(err)
	}
	// Tokens have the same fixed length as actual login tokens.
	value := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := s.DB.Exec("UPDATE v3_sessions SET token_hash=$1", digest([]byte(value))); err != nil {
		t.Fatal(err)
	}
	call := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: value})
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	at := time.Now().Unix() - 100
	seedHealthNotice(t, s, n, "memory", at)
	seedHealthNotice(t, s, n, "clock", at)
	page := func(path string) (string, []string) {
		t.Helper()
		w := call(path)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var p struct {
			Items []json.RawMessage `json:"items"`
			Next  string            `json:"next_cursor"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		ids := []string{}
		for _, raw := range p.Items {
			var v map[string]any
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			if key, ok := v["record_key"].(string); ok {
				ids = append(ids, key)
				if v["can_delete"] != false || v["delete_reason"] == "" {
					t.Fatal(v)
				}
			} else {
				ids = append(ids, v["key"].(string))
			}
		}
		return p.Next, ids
	}
	for _, path := range []string{"/api/v3/alerts/current?limit=1", "/api/v3/alerts/history?limit=1"} {
		cursor, first := page(path)
		_, second := page(path + "&cursor=" + cursor)
		if len(first) != 1 || len(second) != 1 || first[0] == second[0] {
			t.Fatal("unstable same-timestamp page", first, second)
		}
	}
	for _, path := range []string{"/api/v3/alerts/history?phase=no", "/api/v3/alerts/history?cursor=broken", "/api/v3/alerts/history?limit=201", "/api/v3/alerts/current?cursor=broken", "/api/v3/alerts/current?node=bad/path"} {
		if w := call(path); w.Code != 400 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	raw, err := s.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Current int `json:"current_alerts"`
	}
	if err = json.Unmarshal(raw, &summary); err != nil || summary.Current != 2 {
		t.Fatal(string(raw), err)
	}
	if _, err = s.DB.Exec("UPDATE v3_nodes SET enabled=false"); err != nil {
		t.Fatal(err)
	}
	_, ids := page("/api/v3/alerts/current")
	if len(ids) != 2 {
		t.Fatal("saved disable hid running alerts")
	}
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	snapshot, err := captureSavedNodeTx(context.Background(), tx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = publishNodeRuntimeTx(context.Background(), tx, n.ID, snapshot, 1); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_, ids = page("/api/v3/alerts/current")
	if len(ids) != 0 {
		t.Fatal("disabled node still current")
	}
	s.DB.Close()
	if w := call("/api/v3/alerts/history"); w.Code != 503 {
		t.Fatal("DB error became empty alarms or logout", w.Code)
	}
}
