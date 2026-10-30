package controlplane

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
)

func restoreAPIFixture(t *testing.T) (*API, configurationLocalFixture, configurationRestoreStage, map[string]string) {
	t.Helper()
	s, f, stage := configurationRevisionFixture(t, false)
	a := NewAPI(s, f.c)
	sessions := map[string]string{}
	for _, user := range []string{"admin", "other-admin", "operator", "viewer"} {
		value := token()
		mustHistoryExec(t, s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,$2,1,'configuration-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(value)), user)
		sessions[user] = value
	}
	return a, f, stage, sessions
}
func restoreAPICall(a *API, method, path, body, session, csrf, key string, secure bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/v3/"+path, strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: session})
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Idempotency-Key", key)
	if secure {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func TestConfigurationRestoreAPISavedWorkflowAndResume(t *testing.T) {
	a, f, old, sessions := restoreAPIFixture(t)
	call := func(method, path, body, key string) *httptest.ResponseRecorder {
		return restoreAPICall(a, method, path, body, sessions["admin"], "configuration-csrf", key, true)
	}
	want := func(w *httptest.ResponseRecorder, code int) {
		t.Helper()
		if w.Code != code {
			t.Fatalf("code=%d expected=%d body=%s", w.Code, code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "private-revision-password") || strings.Contains(w.Body.String(), f.c.DeploymentTrust.VaultKeyFile) {
			t.Fatal("private input escaped")
		}
	}
	w := call("GET", "configuration-restores?limit=1", "", "")
	want(w, 200)
	var page struct {
		Items []configurationRestoreStage `json:"items"`
		Next  string                      `json:"next_cursor"`
	}
	json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Items) != 1 || page.Items[0].ID != old.ID || page.Next == "" {
		t.Fatal("pending restore not discoverable")
	}
	w = call("GET", "configuration-restores?limit=1&cursor="+page.Next, "", "")
	want(w, 200)
	if !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal("cursor repeated stage")
	}
	w = call("GET", "configuration-restores/"+old.ID, "", "")
	want(w, 200)
	var detail configurationRestoreDetail
	json.Unmarshal(w.Body.Bytes(), &detail)
	if !detail.CanContinue || !detail.CanCancel || detail.Revision != nil {
		t.Fatal("incorrect initial detail")
	}
	want(call("POST", "configuration-restores/"+old.ID+"/cancel", `{"confirm":true}`, "cancel-original"), 200)
	w = call("POST", "configuration-backups/"+old.Backup+"/restore-preview", `{"use_backup_credentials":false}`, "")
	want(w, 200)
	var preview configurationRestorePreview
	json.Unmarshal(w.Body.Bytes(), &preview)
	if !preview.Summary.CanPrepare {
		t.Fatal("fixture cannot restore")
	}
	w = call("POST", "configuration-restores", `{"preview":"`+preview.Token+`","confirm":true}`, "public-stage")
	want(w, 200)
	stage := configurationStageReceipt(t, w.Body.Bytes(), nil)
	replay := call("POST", "configuration-restores", `{"preview":"`+preview.Token+`","confirm":true}`, "public-stage")
	want(replay, 200)
	if canonicalBackupResponse(t, w.Body.Bytes()) != canonicalBackupResponse(t, replay.Body.Bytes()) {
		t.Fatal("stage replay changed receipt")
	}
	want(call("POST", "configuration-restores/"+stage.ID+"/check", `{}`, "local-check"), 200)
	w = call("POST", "configuration-restores/"+stage.ID+"/prepare", `{}`, "prepare")
	want(w, 200)
	revision := configurationRevisionReceipt(t, w.Body.Bytes(), nil)
	// A new API instance recovers durable workflow state; nothing relies on a modal.
	a = NewAPI(a.Store, f.c)
	w = call("GET", "configuration-restores/"+stage.ID, "", "")
	want(w, 200)
	json.Unmarshal(w.Body.Bytes(), &detail)
	if detail.Stage.Status != "pending_application" || detail.Revision == nil || detail.Revision.Generation != revision.Generation {
		t.Fatal("prepared candidate not recoverable")
	}
	commit := `{"generation":"` + strconv.FormatInt(revision.Generation, 10) + `","confirm":true}`
	w = call("POST", "configuration-restores/"+stage.ID+"/commit", commit, "public-commit")
	want(w, 200)
	var receipt configurationSavedReceipt
	if json.Unmarshal(w.Body.Bytes(), &receipt) != nil || receipt.Status != "saved_pending_application" {
		t.Fatal("not saved")
	}
	want(call("POST", "configuration-restores/"+stage.ID+"/commit", commit, "public-commit"), 200)
	w = call("GET", "configuration-restores/"+stage.ID, "", "")
	want(w, 200)
	json.Unmarshal(w.Body.Bytes(), &detail)
	if detail.Stage.Status != "saved" || detail.CanContinue || detail.CanCancel {
		t.Fatal("saved stage reported as applicable")
	}
	var runtime, applied int
	var name string
	a.Store.DB.QueryRow(`SELECT version FROM v3_settings`).Scan(&runtime)
	a.Store.DB.QueryRow(`SELECT name,applied_version FROM v3_nodes WHERE id='revision-node'`).Scan(&name, &applied)
	if runtime != 6 || applied != 4 || name != "backup-node-name" || tableCount(t, a.Store, "v3_deployment_jobs") != 0 || tableCount(t, a.Store, "v3_notifications") != 0 {
		t.Fatal("restore applied runtime or lost desired changes", runtime, applied, name)
	}
}
func TestConfigurationRestoreAPIProtectionAndStrictInput(t *testing.T) {
	a, _, stage, sessions := restoreAPIFixture(t)
	call := func(method, path, body, user, csrf, key string, secure bool) *httptest.ResponseRecorder {
		return restoreAPICall(a, method, path, body, sessions[user], csrf, key, secure)
	}
	for _, user := range []string{"", "viewer", "operator"} {
		expected := 403
		if user == "" {
			expected = 401
		}
		for _, method := range []string{"GET", "POST"} {
			if w := call(method, "configuration-restores", "{}", user, "configuration-csrf", "key", true); w.Code != expected {
				t.Fatalf("unauthorized %s %s=%d", user, method, w.Code)
			}
		}
	}
	for _, tc := range []struct {
		csrf   string
		secure bool
		code   int
	}{{"", true, 403}, {"configuration-csrf", false, 403}} {
		w := call("POST", "configuration-restores/"+stage.ID+"/prepare", "{}", "admin", tc.csrf, "key", tc.secure)
		if w.Code != tc.code {
			t.Fatal("transport/CSRF bypass", w.Code)
		}
	}
	for _, tc := range []struct{ path, body string }{
		{"configuration-backups/" + stage.Backup + "/restore-preview", `{"use_backup_credentials":false,"Use_Backup_Credentials":true}`},
		{"configuration-backups/" + stage.Backup + "/restore-preview", `{"use_backup_credentials":false,"use_backup_credentials":true}`},
		{"configuration-backups/" + stage.Backup + "/restore-preview", `{"use_backup_credentials":null}`},
		{"configuration-restores", `{"preview":"` + strings.Repeat("a", 64) + `","confirm":false}`},
		{"configuration-restores/" + stage.ID + "/prepare", `{"path":"/tmp/should-not-read"}`},
		{"configuration-restores/" + stage.ID + "/commit", `{"generation":9007199254740993,"confirm":true}`},
		{"configuration-restores/" + stage.ID + "/commit", `{"generation":"01","confirm":true}`},
		{"configuration-restores/" + stage.ID + "/commit", `{"generation":"+1","confirm":true}`},
		{"configuration-restores/" + stage.ID + "/prepare", "{} {}"},
		{"configuration-restores/" + stage.ID + "/prepare", `{"padding":"` + strings.Repeat("a", 4096) + `"}`},
	} {
		w := call("POST", tc.path, tc.body, "admin", "configuration-csrf", "strict-key", true)
		if w.Code != 400 {
			t.Fatalf("strict request accepted %s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
	w := call("POST", "configuration-restores/"+stage.ID+"/prepare", `{}`, "other-admin", "configuration-csrf", "other-prepare", true)
	if w.Code != 409 {
		t.Fatal("other admin continued intent", w.Code)
	}
	w = call("GET", "configuration-restores/"+stage.ID, "", "other-admin", "", "", true)
	if w.Code != 200 || strings.Contains(w.Body.String(), `"can_continue":true`) {
		t.Fatal("other admin gained owner authority", w.Code)
	}
	w = call("POST", "configuration-restores/"+stage.ID+"/cancel", `{"confirm":true}`, "other-admin", "configuration-csrf", "other-cancel", true)
	if w.Code != 200 {
		t.Fatal("cannot cancel abandoned intent", w.Code, w.Body.String())
	}
}
func TestConfigurationRestoreAPIConflictAndLocalFailure(t *testing.T) {
	a, f, stage, sessions := restoreAPIFixture(t)
	call := func(action, body, key string) *httptest.ResponseRecorder {
		return restoreAPICall(a, "POST", "configuration-restores/"+stage.ID+"/"+action, body, sessions["admin"], "configuration-csrf", key, true)
	}
	// Trusted local materials are re-opened, never accepted from a previous report.
	mustHistoryExec(t, a.Store.DB, `UPDATE v3_settings SET version=version+1`)
	if w := call("prepare", "{}", "changed"); w.Code != 409 || !strings.Contains(w.Body.String(), "restore_conflict") {
		t.Fatal("stale restore accepted", w.Code, w.Body.String())
	}
	if _, e := a.Store.cancelConfigurationRestore(context.Background(), "admin", "cancel-conflict", stage.ID); e != nil {
		t.Fatal(e)
	}
	p, e := a.Store.previewConfigurationRestore(context.Background(), f.v, f.c, "admin", stage.Backup, configurationRestoreOptions{})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := a.Store.stageConfigurationRestore(context.Background(), f.v, f.c, "admin", "local-stage", p.Token)
	stage = configurationStageReceipt(t, raw, e)
	// Free-space/directory diagnostic must fail safely without leaking its path.
	if e := os.Remove(f.c.Central.ExportDirectory); e != nil {
		t.Fatal(e)
	}
	w := call("check", "{}", "check-failed")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"local_checks_passed":false`) {
		t.Fatal("missing material passed", w.Code, w.Body.String())
	}
	w = call("prepare", "{}", "prepare-failed")
	if w.Code != 409 || !strings.Contains(w.Body.String(), "restore_local_check_failed") || strings.Contains(w.Body.String(), f.c.Central.ExportDirectory) {
		t.Fatal("unsafe local failure", w.Code, w.Body.String())
	}
	if tableCount(t, a.Store, "v3_configuration_revisions") != 0 {
		t.Fatal("failed candidate persisted")
	}
	mustHistoryExec(t, a.Store.DB, `UPDATE v3_configuration_restore_stages SET summary=jsonb_set(summary,'{sections}','["private-corrupted-label"]') WHERE id=$1`, stage.ID)
	w = restoreAPICall(a, "GET", "configuration-restores/"+stage.ID, "", sessions["admin"], "", "", true)
	if w.Code != 503 || strings.Contains(w.Body.String(), "private-corrupted-label") {
		t.Fatal("stored summary leaked", w.Code, w.Body.String())
	}
}

func TestConfigurationRestoreAPICancelWithoutLocalKeys(t *testing.T) {
	a, _, stage, sessions := restoreAPIFixture(t)
	a.Config.DeploymentTrust.VaultKeyFile = "/unavailable/private-vault"
	a.bootstrapConfig = nil
	w := restoreAPICall(a, "POST", "configuration-restores/"+stage.ID+"/prepare", "{}", sessions["admin"], "configuration-csrf", "prepare-missing", true)
	if w.Code != 503 || strings.Contains(w.Body.String(), "/unavailable/") {
		t.Fatal("unsafe unavailable response", w.Code, w.Body.String())
	}
	w = restoreAPICall(a, "POST", "configuration-restores/"+stage.ID+"/cancel", `{"confirm":true}`, sessions["other-admin"], "configuration-csrf", "cancel-missing", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"cancelled"`) {
		t.Fatal("cannot cancel with missing local materials", w.Code, w.Body.String())
	}
}
