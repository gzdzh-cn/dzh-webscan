package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRetentionAPIAuthCSRFVersionPaginationAndFailure(t *testing.T) {
	s := testStore(t)
	api := configurationEditAPIFixture(t, s)
	ctx := context.Background()
	for _, path := range []string{"policy", "status", "jobs"} {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, httptest.NewRequest("GET", "/api/v3/retention/"+path, nil))
		if w.Code != 401 {
			t.Fatal(path, w.Code)
		}
	}
	if err := s.Provision(ctx, "admin", "retention-password-123"); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("b", 64)
	if _, err := s.DB.Exec(`INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,'admin',1,'fixture-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(token))); err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body, csrf, key string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "/api/v3/retention/"+path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: token})
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	w := call("GET", "status", "", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"worker_healthy":null`) || !strings.Contains(w.Body.String(), `"last_job":null`) {
		t.Fatal(w.Code, w.Body.String())
	}
	body := `{"expected_version":1,"policy":{"sqlite_events_days":60,"security_events_days":120,"website_incidents_days":30,"server_alerts_days":60,"delivery_records_days":30}}`
	if w = call("PUT", "policy", body, "", "one"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if _, err := s.DB.Exec(`UPDATE v3_accounts SET role='operator'`); err != nil {
		t.Fatal(err)
	}
	if w = call("PUT", "policy", body, "fixture-csrf", "one"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if _, err := s.DB.Exec(`UPDATE v3_accounts SET role='admin'`); err != nil {
		t.Fatal(err)
	}
	if w = call("PUT", "policy", body, "fixture-csrf", "one"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = call("PUT", "policy", body, "fixture-csrf", "two"); w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = call("PUT", "policy", strings.Replace(body, ":60", ":0", 1), "fixture-csrf", "invalid"); w.Code != 400 {
		t.Fatal(w.Code, w.Body.String())
	}
	l, j := retentionFixture(t, s)
	finishRetention(t, s, l, j)
	if _, err := s.DB.Exec(`UPDATE v3_retention_jobs SET slot=slot-1`); err != nil {
		t.Fatal(err)
	}
	j, err := s.ScheduleRetention(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	finishRetention(t, s, l, j)
	if w = call("GET", "jobs?limit=1", "", "", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var first struct {
		Items []RetentionJob `json:"items"`
		Next  string         `json:"next_cursor"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &first); err != nil || len(first.Items) != 1 || first.Next == "" {
		t.Fatal(first, err)
	}
	w = call("GET", "jobs?limit=1&cursor="+first.Next, "", "", "")
	var second struct {
		Items []RetentionJob `json:"items"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &second); err != nil || w.Code != 200 || len(second.Items) != 1 || first.Items[0].ID == second.Items[0].ID {
		t.Fatal(second, w.Code, err)
	}
	if w = call("GET", "jobs?cursor=invalid", "", "", ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w = call("GET", "jobs?limit=201", "", "", ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w = call("POST", "cleanup", "{}", "fixture-csrf", "unknown"); w.Code != 400 || tableCount(t, s, "v3_history_jobs") != 0 {
		t.Fatal("manual deletion accepted without a bound preview", w.Code)
	}
	if _, err = s.DB.Exec(`INSERT INTO v3_migration_domains(domain,source) VALUES('events',repeat('a',64))`); err != nil {
		t.Fatal(err)
	}
	body = strings.Replace(body, `"expected_version":1`, `"expected_version":2`, 1)
	if w = call("PUT", "policy", body, "fixture-csrf", "frozen"); w.Code != 503 || !strings.Contains(w.Body.String(), "migration_pending") {
		t.Fatal(w.Code, w.Body.String())
	}
	s.DB.Close()
	if w = call("GET", "status", "", "", ""); w.Code != 503 {
		t.Fatal("database failure masqueraded as logout", w.Code)
	}
}

func TestRetentionWorkerRunsAndStatusExpires(t *testing.T) {
	s := testStore(t)
	oldEvent(t, s, "worker-expired", false, 40, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { s.RunRetention(ctx, "retention-worker"); close(done) }()
	defer func() { cancel(); <-done }()
	for {
		st, err := s.RetentionStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.Last != nil && st.Last.Status == "succeeded" && st.Healthy != nil && *st.Healthy {
			if st.Last.Deleted != 1 || st.StorageBytes <= 0 {
				t.Fatal(st)
			}
			break
		}
		if ctx.Err() != nil {
			t.Fatal("worker did not finish", ctx.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := s.DB.Exec(`UPDATE v3_role_status SET heartbeat=clock_timestamp()-interval '1 minute' WHERE role='retention'`); err != nil {
		t.Fatal(err)
	}
	st, err := s.RetentionStatus(ctx)
	if err != nil || st.Healthy == nil || *st.Healthy {
		t.Fatal(st, err)
	}
}

func TestRetentionStandbyCannotMaskFailedActiveWorker(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	mustHistoryExec(t, s.DB, `INSERT INTO v3_role_status(role,instance,heartbeat,details) VALUES('retention','standby',clock_timestamp(),'{"state":"standby"}')`)
	st, err := s.RetentionStatus(ctx)
	if err != nil || st.Healthy != nil || st.Heartbeat != nil {
		t.Fatal(st, err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_role_status(role,instance,heartbeat,error,details) VALUES('retention','active',clock_timestamp()-interval '5 seconds','清理失败，等待重试','{"state":"active"}')`)
	st, err = s.RetentionStatus(ctx)
	if err != nil || st.Healthy == nil || *st.Healthy || st.Reason == "" {
		t.Fatal(st, err)
	}
}
