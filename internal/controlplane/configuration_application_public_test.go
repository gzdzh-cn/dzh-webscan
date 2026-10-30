package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func publicApplicationSessions(t *testing.T, s *Store) map[string]string {
	t.Helper()
	mustHistoryExec(t, s.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('other-admin','not-a-login','admin'),('viewer','not-a-login','viewer') ON CONFLICT DO NOTHING`)
	sessions := map[string]string{}
	for _, user := range []string{"admin", "other-admin", "viewer"} {
		sessions[user] = token()
		mustHistoryExec(t, s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,$2,1,'application-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(sessions[user])), user)
	}
	return sessions
}
func publicApplicationPost(a *API, session, path, body, key string) *httptest.ResponseRecorder {
	return restoreAPICall(a, "POST", "configuration-applications"+path, body, session, "application-csrf", key, true)
}
func publicApplicationControl(j configurationApplicationJob) string {
	return fmt.Sprintf(`{"expected_log_cursor":"%d","confirm":true}`, j.LogCursor)
}
func publicApplicationView(t *testing.T, a *API, session, id string) configurationApplicationView {
	t.Helper()
	w := restoreAPICall(a, "GET", "configuration-applications/"+id, "", session, "", "", true)
	var view configurationApplicationView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	return view
}
func TestConfigurationApplicationPublicQueueActualWorkerAndIdempotency(t *testing.T) {
	s, f, stage, revision := workerSourceFixture(t, false)
	sessions := publicApplicationSessions(t, s)
	a := NewAPI(s, f.c)
	detail, err := s.configurationRestoreDetail(context.Background(), "admin", stage.ID, a.configurationApplicationVault, true)
	if err != nil || !detail.CanApply {
		t.Fatal("saved stage unavailable", err)
	}
	body := fmt.Sprintf(`{"stage":%q,"generation":"%d","confirm":true}`, stage.ID, revision.Generation)
	var results [2]*httptest.ResponseRecorder
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = publicApplicationPost(a, sessions["admin"], "", body, "public-queue")
		}(i)
	}
	wg.Wait()
	for _, w := range results {
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	job := applicationReceipt(t, results[0].Body.Bytes(), nil)
	if !sameProvisioningResponse(results[0].Body.Bytes(), results[1].Body.Bytes()) || tableCount(t, s, "v3_configuration_applications") != 1 {
		t.Fatal("duplicate queued job")
	}
	detail, err = s.configurationRestoreDetail(context.Background(), "admin", stage.ID, a.configurationApplicationVault, true)
	if err != nil || detail.CanApply || detail.Stage.Application == nil {
		t.Fatal("duplicate apply offered", err)
	}
	view := publicApplicationView(t, a, sessions["admin"], job.ID)
	if view.CanResume || view.CanRollback || !view.CanCancel {
		t.Fatal("queued controls incorrect", view)
	}
	process := startBootstrapServeForTest(t, s, f.c, "all", 0)
	done := waitWorkerApplication(t, s, f, job.ID, "succeeded", 30*time.Second)
	process.cancel()
	if done.RecoveryRequired || done.Finished == nil {
		t.Fatal("worker not verified")
	}
	policy, err := s.RetentionPolicy(context.Background())
	if err != nil || policy.Policy.Events != 45 {
		t.Fatal("API did not reach real runtime", err)
	}
	replay := publicApplicationPost(a, sessions["admin"], "", body, "public-queue")
	if replay.Code != 200 || !sameProvisioningResponse(replay.Body.Bytes(), results[0].Body.Bytes()) {
		t.Fatal("retry changed task", replay.Code, replay.Body.String())
	}
	view = publicApplicationView(t, a, sessions["admin"], job.ID)
	if view.CanResume || view.CanRollback || view.CanCancel {
		t.Fatal("terminal action offered")
	}
	if tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("test emitted notifications")
	}
}
func TestConfigurationApplicationPublicInputTransportAndAuthority(t *testing.T) {
	s, f, stage, revision := workerSourceFixture(t, false)
	sessions := publicApplicationSessions(t, s)
	a := NewAPI(s, f.c)
	valid := fmt.Sprintf(`{"stage":%q,"generation":"%d","confirm":true}`, stage.ID, revision.Generation)
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"missing-confirm", fmt.Sprintf(`{"stage":%q,"generation":"%d"}`, stage.ID, revision.Generation), 400},
		{"duplicate", strings.TrimSuffix(valid, "}") + `,"confirm":true}`, 400},
		{"unknown", strings.TrimSuffix(valid, "}") + `,"command":"private-payload"}`, 400},
		{"numeric", strings.Replace(valid, fmt.Sprintf(`"%d"`, revision.Generation), fmt.Sprint(revision.Generation), 1), 400},
		{"leading-zero", strings.Replace(valid, fmt.Sprintf(`"%d"`, revision.Generation), fmt.Sprintf(`"0%d"`, revision.Generation), 1), 400},
		{"overflow", strings.Replace(valid, fmt.Sprintf(`"%d"`, revision.Generation), `"9223372036854775808"`, 1), 400},
		{"null", strings.Replace(valid, fmt.Sprintf(`"%d"`, revision.Generation), `null`, 1), 400},
		{"bad-stage", strings.Replace(valid, stage.ID, "bad", 1), 400},
		{"second-object", valid + `{}`, 400},
		{"oversize", strings.Repeat(" ", 2<<20) + valid, 400},
		{"stale", fmt.Sprintf(`{"stage":%q,"generation":"%d","confirm":true}`, stage.ID, revision.Generation+1), 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := publicApplicationPost(a, sessions["admin"], "", tc.body, "reject-"+tc.name)
			if w.Code != tc.want || strings.Contains(w.Body.String(), "private-") {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	for _, tc := range []struct {
		user, csrf, key string
		secure          bool
		want            int
	}{
		{"", "", "key", true, 401}, {"viewer", "application-csrf", "key", true, 403}, {"admin", "", "key", true, 403}, {"admin", "application-csrf", "", true, 400}, {"admin", "application-csrf", "key", false, 403},
	} {
		w := restoreAPICall(a, "POST", "configuration-applications", valid, sessions[tc.user], tc.csrf, tc.key, tc.secure)
		if w.Code != tc.want {
			t.Fatal(tc, w.Code, w.Body.String())
		}
	}
	{
		r := httptest.NewRequest("POST", "/api/v3/configuration-applications", strings.NewReader(valid))
		r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: sessions["admin"]})
		r.Header.Set("X-CSRF-Token", "application-csrf")
		r.Header.Set("Idempotency-Key", "cross-origin")
		r.Header.Set("Origin", "https://untrusted.example.test")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("cross-origin write accepted", w.Code, w.Body.String())
		}
	}
	for _, enabled := range []bool{false, true} {
		a.bootstrapConfig.Executor.ApplicationsEnabled = enabled
		r := httptest.NewRequest("POST", "/api/v3/configuration-applications", strings.NewReader(valid))
		r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: sessions["admin"]})
		r.Header.Set("X-CSRF-Token", "application-csrf")
		r.Header.Set("Idempotency-Key", "proxy")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.RemoteAddr = "127.0.0.1:10000"
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		want := 503
		if enabled {
			want = 403
		}
		if w.Code != want {
			t.Fatal("untrusted proxy", w.Code, w.Body.String())
		}
	}
	if tableCount(t, s, "v3_configuration_applications") != 0 {
		t.Fatal("invalid request created task")
	}
	a.Config.Central.TrustedProxies = []string{"127.0.0.1"}
	r := httptest.NewRequest("POST", "/api/v3/configuration-applications", strings.NewReader(valid))
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: sessions["admin"]})
	r.Header.Set("X-CSRF-Token", "application-csrf")
	r.Header.Set("Idempotency-Key", "proxy")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.RemoteAddr = "127.0.0.1:10000"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("trusted HTTPS proxy failed", w.Code, w.Body.String())
	}
}
func TestConfigurationApplicationPublicControlsConflictReplayAndActor(t *testing.T) {
	a, f, j, sessions := applicationAPIFixture(t)
	control := func(user, action, body, key string) *httptest.ResponseRecorder {
		return publicApplicationPost(a, sessions[user], "/"+j.ID+"/"+action, body, key)
	}
	if w := control("admin", "resume", publicApplicationControl(j), "queued-resume"); w.Code != 409 {
		t.Fatal("queued resume", w.Code)
	}
	p := claimApplicationForTest(t, a.Store, f, "public-control-worker")
	view := publicApplicationView(t, a, sessions["admin"], j.ID)
	if view.CanResume || view.CanRollback || view.CanCancel {
		t.Fatal("live lease actions")
	}
	if w := control("admin", "cancel", publicApplicationControl(p.public()), "live-cancel"); w.Code != 409 {
		t.Fatal("cancelled active worker", w.Code)
	}
	if err := a.Store.failConfigurationApplication(context.Background(), f.v, p, "environment-failed"); err != nil {
		t.Fatal(err)
	}
	view = publicApplicationView(t, a, sessions["admin"], j.ID)
	if !view.CanResume || view.CanRollback || !view.CanCancel {
		t.Fatal("failed harmless hints", view)
	}
	other := publicApplicationView(t, a, sessions["other-admin"], j.ID)
	if other.CanResume || !other.CanCancel {
		t.Fatal("foreign actor hints")
	}
	if w := control("other-admin", "resume", publicApplicationControl(view.Job), "foreign-resume"); w.Code != 403 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := control("admin", "resume", publicApplicationControl(j), "stale-resume"); w.Code != 409 {
		t.Fatal("stale cursor", w.Code)
	}
	a.bootstrapConfig.Central.Instance = "other-member"
	if v := publicApplicationView(t, a, sessions["admin"], j.ID); v.CanResume || v.CanCancel {
		t.Fatal("foreign member action")
	}
	if w := control("admin", "resume", publicApplicationControl(view.Job), "wrong-member"); w.Code != 409 {
		t.Fatal("foreign member control", w.Code)
	}
	a.bootstrapConfig.Central.Instance = f.c.Central.Instance
	w := control("admin", "resume", publicApplicationControl(view.Job), "public-resume")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	resumed := applicationReceipt(t, w.Body.Bytes(), nil)
	if resumed.Status != "queued" || resumed.ID != j.ID {
		t.Fatal("resume replaced job")
	}
	replay := control("admin", "resume", publicApplicationControl(view.Job), "public-resume")
	if replay.Code != 200 || !sameProvisioningResponse(w.Body.Bytes(), replay.Body.Bytes()) {
		t.Fatal("lost reply not replayable", replay.Code, replay.Body.String())
	}
	if bad := control("admin", "resume", publicApplicationControl(resumed), "public-resume"); bad.Code != 409 {
		t.Fatal("changed retry accepted", bad.Code)
	}
	if bad := control("admin", "rollback", publicApplicationControl(resumed), "no-recovery"); bad.Code != 409 {
		t.Fatal("rollback without recovery")
	}
	w = control("admin", "cancel", publicApplicationControl(resumed), "public-cancel")
	if w.Code != 200 || applicationReceipt(t, w.Body.Bytes(), nil).Status != "cancelled" {
		t.Fatal(w.Code, w.Body.String())
	}
	if tableCount(t, a.Store, "v3_configuration_applications") != 1 || tableCount(t, a.Store, "v3_deployment_jobs") != 0 {
		t.Fatal("control created new deployment")
	}
}
func TestConfigurationApplicationPublicRecoveryAndRevocation(t *testing.T) {
	a, f, j, sessions := applicationAPIFixture(t)
	p := claimApplicationForTest(t, a.Store, f, "public-recovery-worker")
	var err error
	// Synthetic environment checkpoint isolates HTTP recovery authorization;
	// real execution is separately covered by the API-to-Serve worker test.
	if _, err = a.Store.checkpointConfigurationApplication(context.Background(), f.v, p, applicationComplete(p)); err != nil {
		t.Fatal(err)
	}
	p = claimApplicationForTest(t, a.Store, f, "public-recovery-worker")
	p, err = a.Store.armConfigurationApplication(context.Background(), f.v, p)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Store.failConfigurationApplication(context.Background(), f.v, p, "environment-failed"); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, a.Store.DB, `UPDATE v3_configuration_applications SET recovery_hold=true WHERE id=$1`, j.ID)
	view := publicApplicationView(t, a, sessions["other-admin"], j.ID)
	if view.CanResume || !view.CanRollback || view.CanCancel {
		t.Fatal("recovery hints", view)
	}
	for _, body := range []string{`{"expected_log_cursor":1,"confirm":true}`, `{"expected_log_cursor":"01","confirm":true}`, `{"expected_log_cursor":"1","confirm":false}`, `{"expected_log_cursor":"1","confirm":true,"edit":{}}`} {
		if w := publicApplicationPost(a, sessions["admin"], "/"+j.ID+"/cancel", body, "invalid-control"); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if w := publicApplicationPost(a, sessions["admin"], "/"+j.ID+"/cancel", publicApplicationControl(view.Job), "protected-cancel"); w.Code != 409 {
		t.Fatal("recovery cancelled", w.Code)
	}
	w := publicApplicationPost(a, sessions["other-admin"], "/"+j.ID+"/rollback", publicApplicationControl(view.Job), "public-rollback")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	rolled := applicationReceipt(t, w.Body.Bytes(), nil)
	if rolled.Direction != "rollback" || rolled.Controller != "other-admin" || rolled.RecoveryHold {
		t.Fatal("rollback not authenticated")
	}
	mustHistoryExec(t, a.Store.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='other-admin'`)
	w = publicApplicationPost(a, sessions["other-admin"], "/"+j.ID+"/rollback", publicApplicationControl(view.Job), "public-rollback")
	if w.Code != 401 {
		t.Fatal("revoked actor replayed", w.Code, w.Body.String())
	}
}

func TestConfigurationApplicationPublicFailedWorkerRequiresExplicitResume(t *testing.T) {
	var healthy atomic.Bool
	s, f, stage, revision := workerSourceFixture(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			http.Error(w, "private-vm-error", 503)
			return
		}
		environmentMetrics(w, r)
	}))
	sessions := publicApplicationSessions(t, s)
	a := NewAPI(s, f.c)
	body := fmt.Sprintf(`{"stage":%q,"generation":"%d","confirm":true}`, stage.ID, revision.Generation)
	w := publicApplicationPost(a, sessions["admin"], "", body, "failure-queue")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	j := applicationReceipt(t, w.Body.Bytes(), nil)
	process := startBootstrapServeForTest(t, s, f.c, "all", 0)
	deadline := time.Now().Add(15 * time.Second)
	var failed privateConfigurationApplication
	for time.Now().Before(deadline) {
		failed = privateApplicationForTest(t, s, f.v, j.ID)
		if failed.Status == "failed" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if failed.Status != "failed" || failed.RecoveryRequired || failed.ErrorCode != "environment-failed" {
		t.Fatal("worker concealed environment failure", failed.Status, failed.ErrorCode)
	}
	healthy.Store(true)
	// The running worker must not automatically replay a failed phase.
	time.Sleep(1200 * time.Millisecond)
	if current := privateApplicationForTest(t, s, f.v, j.ID); current.Status != "failed" || current.LogCursor != failed.LogCursor {
		t.Fatal("failed task replayed automatically")
	}
	w = publicApplicationPost(a, sessions["admin"], "/"+j.ID+"/resume", publicApplicationControl(failed.public()), "explicit-resume")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	done := waitWorkerApplication(t, s, f, j.ID, "succeeded", 30*time.Second)
	process.cancel()
	if done.RecoveryRequired {
		t.Fatal("completed task retains recovery")
	}
	if tableCount(t, s, "v3_configuration_applications") != 1 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("resume duplicated task or notification")
	}
}

func TestConfigurationApplicationPublicDecimalCursorAndDisabledActions(t *testing.T) {
	a, f, j, sessions := applicationAPIFixture(t)
	p := privateApplicationForTest(t, a.Store, f.v, j.ID)
	// A signed high cursor fixture exercises public JSON precision, not execution.
	p.LogCursor = 9007199254740993
	proof, err := applicationStateProof(f.v, f.v.active, p)
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, a.Store.DB, `UPDATE v3_configuration_applications SET log_cursor=$2,state_proof=$3 WHERE id=$1`, j.ID, p.LogCursor, proof)
	a.bootstrapConfig.Executor.ApplicationsEnabled = false
	v := publicApplicationView(t, a, sessions["admin"], j.ID)
	if v.CanResume || v.CanCancel || v.CanRollback {
		t.Fatal("disabled actions exposed")
	}
	if w := publicApplicationPost(a, sessions["admin"], "/"+j.ID+"/cancel", publicApplicationControl(p.public()), "high-cancel"); w.Code != 503 {
		t.Fatal("disabled write accepted")
	}
	a.bootstrapConfig.Executor.ApplicationsEnabled = true
	if w := publicApplicationPost(a, sessions["admin"], "/"+j.ID+"/cancel", `{"expected_log_cursor":"9007199254740992","confirm":true}`, "rounded-cancel"); w.Code != 409 {
		t.Fatal("rounded cursor accepted", w.Code)
	}
	w := publicApplicationPost(a, sessions["admin"], "/"+j.ID+"/cancel", publicApplicationControl(p.public()), "high-cancel")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"log_cursor":"9007199254740994"`) {
		t.Fatal("high cursor lost precision", w.Code, w.Body.String())
	}
}
