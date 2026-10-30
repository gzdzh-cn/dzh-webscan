package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPasswordResetRevokesPersistedSessionsAndSurvivesRestart(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.Provision(ctx, "admin", "old-password-fixture"); err != nil {
		t.Fatal(err)
	}
	api := &API{Store: s}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest("POST", "/api/v3/login", strings.NewReader(`{"username":"admin","password":"old-password-fixture"}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if err := s.ResetPassword(ctx, "admin", "new-password-fixture"); err != nil {
		t.Fatal(err)
	}
	api = &API{Store: s}
	r := httptest.NewRequest("GET", "/api/v3/session", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("reset did not revoke old session", w.Code)
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest("POST", "/api/v3/login", strings.NewReader(`{"username":"admin","password":"new-password-fixture"}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestHousekeepingLeavesValidSessionsAndRecentAudit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.Provision(ctx, "admin", "password-fixture-123"); err != nil {
		t.Fatal(err)
	}
	_, err := s.DB.Exec(`INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES('expired','admin',1,'test',clock_timestamp()-interval '1 minute'),('valid','admin',1,'test',clock_timestamp()+interval '1 hour');INSERT INTO v3_login_attempts VALUES('expired',1,clock_timestamp()-interval '1 minute'),('valid',1,clock_timestamp()+interval '1 minute');INSERT INTO v3_audit(username,kind,resource,result,created_at) VALUES('admin','test','expired','{}',clock_timestamp()-interval '366 days'),('admin','test','recent','{}',clock_timestamp())`)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Housekeeping(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"v3_sessions", "v3_login_attempts", "v3_audit"} {
		var count int
		if err = s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatal(table, count, err)
		}
	}
	// Health is public and read-only, independently of session state.
	w := httptest.NewRecorder()
	(&API{Store: s}).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}
