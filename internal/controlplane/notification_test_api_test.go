package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotificationTestAPIAuthenticationTransportStrictnessAndOwner(t *testing.T) {
	f := newNotificationTestFixture(t)
	api := NewAPI(f.s, Config{})
	api.Config.DeploymentTrust.VaultKeyFile = f.vaultPath
	admin := token()
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,'admin',1,'history-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(admin)))
	viewer := historyAPISession(t, f.s, "viewer", "viewer")
	other := historyAPISession(t, f.s, "other", "admin")
	if e := f.worker.heartbeat(context.Background(), nil); e != nil {
		t.Fatal(e)
	}
	call := func(method, path, body, session, csrf, key string, https bool) *httptest.ResponseRecorder {
		t.Helper()
		scheme := "https://local"
		if !https {
			scheme = "http://local"
		}
		r := httptest.NewRequest(method, scheme+"/api/v3/notifications/"+path, strings.NewReader(body))
		if session != "" {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: session})
		}
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	body := `{"channel":"email","expected_runtime_version":1}`
	for _, tc := range []struct {
		name, session, csrf string
		https               bool
		want                int
	}{{"anonymous", "", "", true, 401}, {"csrf", admin, "", true, 403}, {"viewer", viewer, "history-csrf", true, 403}, {"http", admin, "history-csrf", false, 403}} {
		if w := call("POST", "test-preview", body, tc.session, tc.csrf, "preview-"+tc.name, tc.https); w.Code != tc.want {
			t.Fatal(tc.name, w.Code, w.Body.String())
		}
	}
	for i, bad := range []string{`{"channel":"email","channel":"feishu","expected_runtime_version":1}`, `{"Channel":"email","expected_runtime_version":1}`, `{"channel":"email","expected_runtime_version":1,"url":"https://bad.test"}`, `{"channel":null,"expected_runtime_version":1}`, `{"channel":"email","expected_runtime_version":null}`, `{"channel":"email"}`} {
		if w := call("POST", "test-preview", bad, admin, "history-csrf", "bad-preview-"+strings.Repeat("a", i+1), true); w.Code != 400 {
			t.Fatal("noncanonical input accepted", w.Code, w.Body.String())
		}
	}
	if w := call("POST", "test-preview", body, admin, "history-csrf", "", true); w.Code != 400 {
		t.Fatal("missing idempotency", w.Code)
	}
	w := call("POST", "test-preview", body, admin, "history-csrf", "valid-preview", true)
	var p notificationTestPreview
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	confirm := `{"preview":"` + p.Token + `","confirm":true}`
	if w = call("POST", "tests", confirm, other, "history-csrf", "foreign-confirm", true); w.Code != 409 {
		t.Fatal("foreign preview accepted", w.Code)
	}
	w = call("POST", "tests", confirm, admin, "history-csrf", "valid-confirm", true)
	var j notificationTestJob
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &j) != nil || j.Status != "queued" {
		t.Fatal("creation claimed delivery", w.Code, w.Body.String())
	}
	if w = call("GET", "tests/"+j.ID, "", other, "", "", true); w.Code != 404 {
		t.Fatal("foreign job visible", w.Code)
	}
	if w = call("GET", "tests/"+j.ID, "", viewer, "", "", true); w.Code != 403 {
		t.Fatal("viewer read admin test", w.Code)
	}
	mustHistoryExec(t, f.s.DB, `DELETE FROM v3_role_status WHERE role='notification-tests'`)
	if w = call("GET", "tests/"+j.ID, "", admin, "", "", true); w.Code != 200 {
		t.Fatal("worker outage hid stored outcome", w.Code, w.Body.String())
	}
	if w = call("POST", "test-preview", body, admin, "history-csrf", "outage-preview", true); w.Code != 503 {
		t.Fatal("worker outage permitted test", w.Code)
	}
}
func TestNotificationTestAvailabilityRequiresFreshMatchingVaultHeartbeat(t *testing.T) {
	f := newNotificationTestFixture(t)
	api := NewAPI(f.s, Config{})
	api.Config.DeploymentTrust.VaultKeyFile = f.vaultPath
	for _, change := range []string{`heartbeat=clock_timestamp()-interval '31 seconds'`, `error='unavailable'`, `details='{"vault_key_id":"different"}'`} {
		if e := f.worker.heartbeat(context.Background(), nil); e != nil {
			t.Fatal(e)
		}
		if !api.notificationTestAvailability(context.Background()).Available {
			t.Fatal("healthy worker unavailable")
		}
		mustHistoryExec(t, f.s.DB, `UPDATE v3_role_status SET `+change+` WHERE role='notification-tests'`)
		if api.notificationTestAvailability(context.Background()).Available {
			t.Fatal("invalid worker reported ready", change)
		}
	}
	api.Config.DeploymentTrust.VaultKeyFile = ""
	if api.notificationTestAvailability(context.Background()).Available {
		t.Fatal("missing Vault available")
	}
}
