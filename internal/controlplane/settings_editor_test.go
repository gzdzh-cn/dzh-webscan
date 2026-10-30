package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
)

func TestSettingsEditorFieldProjectionAndValidation(t *testing.T) {
	raw := []byte(`{"future":{"exact":9007199254740993},"email":{"enabled":false,"password":"private-password"},"feishu":{"enabled":false,"webhook_url":"private-webhook","signing_secret":"private-signing"},"website_monitor":{"interval_seconds":30}}`)
	var root configurationValues
	if decodeConfigurationObject(raw, &root) != nil {
		t.Fatal("fixture")
	}
	values, secrets, e := projectSettingsValues(raw)
	if e != nil || len(values) != 3 || !secrets["email.password"] || !secrets["feishu.webhook_url"] {
		t.Fatal("bad projection", e)
	}
	if bytes.Contains(common.JSON(values), []byte("private")) || bytes.Contains(common.JSON(values), []byte("future")) {
		t.Fatal("projection leaked")
	}
	valid := settingsEdit{Values: map[string]json.RawMessage{"website_monitor.interval_seconds": json.RawMessage(`60`)}, Secrets: map[string]settingsSecretEdit{"email.password": {Action: "keep"}}}
	edited, changed, e := editSettings(root, valid)
	if e != nil || len(changed) != 1 || !bytes.Contains(common.JSON(edited), []byte(`9007199254740993`)) || common.M(edited["email"])["password"] != "private-password" {
		t.Fatal("lossy edit", e)
	}
	if common.I(common.M(root["website_monitor"])["interval_seconds"]) != 30 {
		t.Fatal("mutated original")
	}
	for _, tc := range []struct{ path, raw string }{
		{"email.password", `"exposed"`}, {"future.exact", `1`}, {"website_monitor.interval_seconds", `1e2`}, {"website_monitor.interval_seconds", `10.0`}, {"website_monitor.interval_seconds", `null`}, {"website_monitor.interval_seconds", `"30"`}, {"website_monitor.interval_seconds", `9`}, {"website_monitor.interval_seconds", `3601`}, {"website_monitor.enabled", `0`}, {"email.recipients", `[1]`}, {"email.smtp_host", `"smtp\nsecret"`}, {"email.tls_mode", `"none"`},
	} {
		if _, _, e := editSettings(root, settingsEdit{Values: map[string]json.RawMessage{tc.path: json.RawMessage(tc.raw)}}); !errors.Is(e, errSettingsEdit) {
			t.Fatal("accepted invalid", tc.path, tc.raw)
		}
	}
	for _, tc := range []settingsSecretEdit{{Action: "keep", Value: "bad"}, {Action: "clear", Value: "bad"}, {Action: "replace"}, {Action: "replace", Value: "a\nb"}, {Action: "replace", Value: strings.Repeat("x", 4097)}, {Action: "invented"}} {
		if _, _, e := editSettings(root, settingsEdit{Secrets: map[string]settingsSecretEdit{"email.password": tc}}); e == nil {
			t.Fatal("accepted invalid secret")
		}
	}
	for _, raw := range []string{`{"values":{"email.enabled":false,"email.enabled":true}}`, `{"edit":{"secrets":{"email.password":{"action":"keep","action":"clear"}}}}`, `null`, `[]`, `{"action":"save","action":"apply"}`, `{"edit":{"values":{},"unexpected":"private"}}`, `{} {}`, `{"edit":{"values":{"a":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":1}}}}}}}}}}}}}}}}}}}`} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(raw))
		if _, e := decodeSettingsEditor(httptest.NewRecorder(), r); e == nil {
			t.Fatal("accepted ambiguous body")
		}
	}
	if _, e := decodeSettingsEditor(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat(" ", 2<<20)+"{}"))); e == nil {
		t.Fatal("unbounded body")
	}
	if strings.Contains(fmt.Sprintf("%#v %v", valid, settingsEditorRequest{Edit: valid}), "private-password") {
		t.Fatal("format leaks")
	}
}

func settingsEditorAPICall(a *API, method, path string, body []byte, session, key string, secure bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/v3/settings"+path, bytes.NewReader(body))
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: session})
	r.Header.Set("X-CSRF-Token", "configuration-csrf")
	r.Header.Set("Idempotency-Key", key)
	if secure {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func editorRequestForTest(t *testing.T, s *Store, action string, edit settingsEdit) settingsEditorRequest {
	t.Helper()
	d := settingsStateForTest(t, s)
	return settingsEditorRequest{Action: action, ExpectedGeneration: d.Generation, ExpectedRuntime: d.RuntimeVersion, Edit: edit}
}
func editorPreviewForTest(t *testing.T, a *API, session string, in settingsEditorRequest) settingsEditorRequest {
	t.Helper()
	w := settingsEditorAPICall(a, "POST", "/preview", common.JSON(in), session, "", true)
	var p settingsEditorPreview
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Token == "" {
		t.Fatal("preview failed", w.Code, w.Body.String())
	}
	in.Preview = p.Token
	return in
}

func TestSettingsEditorAPIProjectionSaveAndExplicitApply(t *testing.T) {
	a, _, sessions := configurationAPIFixture(t)
	s := a.Store
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=payload||'{"future":{"exact":9007199254740993}}'::jsonb`)
	for _, user := range []string{"", "operator", "viewer"} {
		w := settingsEditorAPICall(a, "GET", "", nil, sessions[user], "", true)
		want := 403
		if user == "" {
			want = 401
		}
		if w.Code != want {
			t.Fatal("authorization", user, w.Code)
		}
	}
	w := settingsEditorAPICall(a, "GET", "", nil, sessions["admin"], "", true)
	var view settingsEditorView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || !view.Secrets["email.password"] || strings.Contains(w.Body.String(), "private-") || strings.Contains(w.Body.String(), "future") {
		t.Fatal("unsafe projection", w.Code)
	}
	original := settingsStateForTest(t, s)
	in := editorRequestForTest(t, s, "save", settingsEdit{Values: map[string]json.RawMessage{"website_monitor.interval_seconds": json.RawMessage(`42`)}, Secrets: map[string]settingsSecretEdit{"email.password": {Action: "replace", Value: "private-replacement"}}})
	if w = settingsEditorAPICall(a, "POST", "/preview", common.JSON(in), sessions["admin"], "", false); w.Code != 403 {
		t.Fatal("plain HTTP accepted", w.Code)
	}
	in = editorPreviewForTest(t, a, sessions["admin"], in)
	if tableCount(t, s, "v3_configuration_backups") != 0 || tableCount(t, s, "v3_requests") != 0 || !configurationJSONEqual(settingsStateForTest(t, s).Runtime, original.Runtime) {
		t.Fatal("preview changed desired/runtime")
	}
	r := httptest.NewRequest("POST", "/api/v3/settings/confirm", bytes.NewReader(common.JSON(in)))
	r.TLS = &tls.ConnectionState{}
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: sessions["admin"]})
	r.Header.Set("Idempotency-Key", "save")
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("missing csrf")
	}
	w = settingsEditorAPICall(a, "POST", "/confirm", common.JSON(in), sessions["admin"], "save", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	saved := settingsStateForTest(t, s)
	if !saved.Pending || saved.RuntimeVersion != original.RuntimeVersion || !configurationJSONEqual(saved.Runtime, original.Runtime) || !bytes.Contains(saved.Desired, []byte("9007199254740993")) || !bytes.Contains(saved.Desired, []byte("private-replacement")) {
		t.Fatal("save applied or lost content")
	}
	again := settingsEditorAPICall(a, "POST", "/confirm", common.JSON(in), sessions["admin"], "save", true)
	if again.Code != 200 || !configurationJSONEqual(w.Body.Bytes(), again.Body.Bytes()) || tableCount(t, s, "v3_configuration_backups") != 1 {
		t.Fatal("retry not idempotent")
	}
	apply := editorPreviewForTest(t, a, sessions["admin"], editorRequestForTest(t, s, "apply", settingsEdit{}))
	w = settingsEditorAPICall(a, "POST", "/confirm", common.JSON(apply), sessions["admin"], "apply", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	applied := settingsStateForTest(t, s)
	if applied.Pending || applied.RuntimeVersion != original.RuntimeVersion+1 || !configurationJSONEqual(applied.Runtime, saved.Desired) {
		t.Fatal("apply failed")
	}
	if tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("settings caused external work")
	}
	var raw []byte
	if e := s.DB.QueryRow(`SELECT jsonb_agg(result) FROM v3_audit`).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("private-")) || bytes.Contains(raw, []byte(in.Preview)) || bytes.Contains(raw, []byte("9007199254740993")) {
		t.Fatal("audit leaked")
	}
}

func TestSettingsEditorPreviewInvalidationAndAtomicity(t *testing.T) {
	for _, kind := range []string{"draft", "runtime", "account", "other-admin", "node", "bootstrap", "deployment", "completed-deployment", "expiry", "token", "edit", "audit", "backup", "unknown-policy"} {
		t.Run(kind, func(t *testing.T) {
			a, _, sessions := configurationAPIFixture(t)
			s := a.Store
			ctx := context.Background()
			before, e := a.configurationEditBackup()
			if e != nil {
				t.Fatal(e)
			}
			in := editorPreviewForTest(t, a, sessions["admin"], editorRequestForTest(t, s, "save", settingsEdit{Values: map[string]json.RawMessage{"website_monitor.interval_seconds": json.RawMessage(`60`)}}))
			user := "admin"
			switch kind {
			case "draft":
				if _, e = s.saveSettingsDraft(ctx, "admin", "concurrent", []byte(`{"email":{"enabled":false},"website_monitor":{"interval_seconds":61}}`), 0, 5, before); e != nil {
					t.Fatal(e)
				}
			case "runtime":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=version+1`)
			case "account":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin';UPDATE v3_sessions SET revision=revision+1 WHERE username='admin'`)
			case "other-admin":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='admin' WHERE username='operator'`)
				user = "operator"
			case "node":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET name='changed',version=version+1`)
			case "bootstrap":
				a.bootstrapConfig.Central.PublicURL = "https://changed.example.test"
			case "deployment", "completed-deployment":
				mustHistoryExec(t, s.DB, `INSERT INTO v3_credentials(id,node,key_id,nonce,ciphertext) VALUES('synthetic','saved-node','unused',''::bytea,''::bytea)`)
				mustHistoryExec(t, s.DB, `INSERT INTO v3_deployment_jobs(id,node,username,credential,kind,node_version,plan,plan_digest,status) VALUES($1,'saved-node','admin','synthetic','install',1,'{}',$2,'queued')`, token(), strings.Repeat("a", 64))
				if kind == "completed-deployment" {
					mustHistoryExec(t, s.DB, `UPDATE v3_deployment_jobs SET status='succeeded'`)
				}
			case "expiry":
				ticket, _, err := parseSettingsTicket(in.Preview)
				if err != nil {
					t.Fatal(err)
				}
				ticket.Expires = time.Now().Add(-time.Minute).Unix()
				in.Preview = base64.RawURLEncoding.EncodeToString(common.JSON(ticket)) + "." + strings.Repeat("0", 64)
			case "token":
				in.Preview = in.Preview[:len(in.Preview)-64] + strings.Repeat("0", 64)
			case "edit":
				in.Edit.Values["website_monitor.interval_seconds"] = json.RawMessage(`61`)
			case "audit":
				mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_editor_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='settings-save' THEN RAISE EXCEPTION 'synthetic';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_editor_audit BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION fail_editor_audit()`)
			case "backup":
				mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_editor_backup() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic';END$$;CREATE TRIGGER fail_editor_backup BEFORE INSERT ON v3_configuration_backups FOR EACH ROW EXECUTE FUNCTION fail_editor_backup()`)
			case "unknown-policy":
				if _, e = s.saveSettingsDraft(ctx, "admin", "future", []byte(`{"email":{"enabled":false},"future":{"enabled":true}}`), 0, 5, before); e != nil {
					t.Fatal(e)
				}
				in = editorRequestForTest(t, s, "apply", settingsEdit{})
				w := settingsEditorAPICall(a, "POST", "/preview", common.JSON(in), sessions[user], "", true)
				if w.Code != 400 {
					t.Fatal("unknown policy applied", w.Code)
				}
				return
			}
			baseline := settingsStateForTest(t, s)
			count := tableCount(t, s, "v3_configuration_backups")
			requests := tableCount(t, s, "v3_requests")
			w := settingsEditorAPICall(a, "POST", "/confirm", common.JSON(in), sessions[user], "save", true)
			if w.Code != 409 && w.Code != 503 {
				t.Fatal("changed state authorized", w.Code, w.Body.String())
			}
			after := settingsStateForTest(t, s)
			if after.Generation != baseline.Generation || !configurationJSONEqual(after.Runtime, baseline.Runtime) || tableCount(t, s, "v3_configuration_backups") != count || tableCount(t, s, "v3_requests") != requests {
				t.Fatal("failed mutation partially committed")
			}
			if kind == "audit" || kind == "backup" {
				name := "fail_editor_" + kind
				mustHistoryExec(t, s.DB, "DROP TRIGGER "+name+" ON "+map[string]string{"audit": "v3_audit", "backup": "v3_configuration_backups"}[kind])
				retry := settingsEditorAPICall(a, "POST", "/confirm", common.JSON(in), sessions[user], "save", true)
				if retry.Code != 200 || tableCount(t, s, "v3_configuration_backups") != count+1 {
					t.Fatal("rolled-back request not retryable", retry.Code, retry.Body.String())
				}
			}

		})
	}
}

func TestSettingsEditorHTTPBoundsAndTrustedProxy(t *testing.T) {
	a, _, sessions := configurationAPIFixture(t)
	in := editorRequestForTest(t, a.Store, "save", settingsEdit{Values: map[string]json.RawMessage{"website_monitor.interval_seconds": json.RawMessage(`55`)}})
	raw := common.JSON(in)
	if _, e := decodeSettingsEditor(httptest.NewRecorder(), httptest.NewRequest("POST", "/", bytes.NewReader(raw))); e != nil {
		t.Fatal("valid body rejected", e)
	}
	for _, body := range []string{`{"action":"save","Action":"apply","expected_generation":"0","expected_runtime_version":5,"edit":{}}`, `{"action":"save","expected_generation":"0","expected_runtime_version":5,"edit":{"Values":{}}}`, `{"action":"save","expected_generation":"0","expected_runtime_version":5,"edit":{"secrets":{"email.password":{"action":"keep","Action":"clear"}}}}`, `{"action":"save","expected_generation":"0","expected_runtime_version":5,"edit":{"secrets":{"email.password":null}}}`, `{}`, `{"action":"save","expected_generation":null,"expected_runtime_version":5,"edit":{}}`, `{"action":"save","expected_generation":"0","expected_runtime_version":5,"edit":null}`, `{"action":"save","expected_generation":"00","expected_runtime_version":5,"edit":{}}`, `{"action":"save","expected_generation":"0","expected_runtime_version":5,"edit":{"values":null}}`, `{"action":"save","expected_generation":"0","expected_runtime_version":5,"edit":{"secrets":[]}}`, `{"action":"save","expected_generation":"0","expected_runtime_version":5,"edit":{"values":{"email.password":"private-forbidden"}}}`, `{"action":"save","expected_generation":"0","expected_runtime_version":5,"edit":{"values":{"website_monitor.interval_seconds":40,"website_monitor.interval_seconds":50}}}`} {
		w := settingsEditorAPICall(a, "POST", "/preview", []byte(body), sessions["admin"], "", true)
		if w.Code != 400 || strings.Contains(w.Body.String(), "private-") {
			t.Fatal("bad input accepted/echoed", w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/api/v3/settings/preview", bytes.NewReader(raw))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-CSRF-Token", "configuration-csrf")
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: sessions["admin"]})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("untrusted proxy accepted")
	}
	a.Config.Central.TrustedProxies = []string{"127.0.0.1"}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("trusted proxy rejected", w.Code, w.Body.String())
	}
	if tableCount(t, a.Store, "v3_requests") != 0 || tableCount(t, a.Store, "v3_configuration_backups") != 0 {
		t.Fatal("preview wrote config")
	}
}

func TestSettingsEditorVaultRotationConcurrentConfirmAndCancellation(t *testing.T) {
	s, b := settingsDraftFixture(t)
	ctx := context.Background()
	old, oldPath := testVault(t)
	next, nextPath := testVault(t)
	b.vault = old
	in := editorRequestForTest(t, s, "save", settingsEdit{Secrets: map[string]settingsSecretEdit{"email.password": {Action: "replace", Value: "private-rotating-secret"}}})
	p, e := s.previewSettingsEditor(ctx, "admin", in, b)
	if e != nil {
		t.Fatal(e)
	}
	in.Preview = p.Token
	b.vault = next
	if _, e = s.confirmSettingsEditor(ctx, "admin", "rotate", in, b); !errors.Is(e, errSettingsPreview) {
		t.Fatal("missing preview key accepted", e)
	}
	b.vault, e = OpenVault(nextPath, oldPath)
	if e != nil {
		t.Fatal(e)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, e = s.confirmSettingsEditor(canceled, "admin", "rotate", in, b); e == nil {
		t.Fatal("canceled request committed")
	}
	type result struct {
		raw json.RawMessage
		e   error
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() { raw, e := s.confirmSettingsEditor(ctx, "admin", "rotate", in, b); results <- result{raw, e} }()
	}
	first, second := <-results, <-results
	if first.e != nil || second.e != nil || !configurationJSONEqual(first.raw, second.raw) || tableCount(t, s, "v3_configuration_backups") != 1 {
		t.Fatal("concurrent retry failed", first.e, second.e)
	}
	d := settingsStateForTest(t, s)
	if !strings.HasPrefix(d.Proof, next.active+":") || checkSettingsDraftProof(next, d) != nil {
		t.Fatal("saved draft not signed by new key")
	}
	// The completed operation's receipt survives a later edit; a new key does
	// not replay the mutation from an obsolete preview.
	if _, e = s.confirmSettingsEditor(ctx, "admin", "different-key", in, b); !errors.Is(e, errSettingsPreview) {
		t.Fatal("obsolete preview committed", e)
	}
}

func TestSettingsEditorCredentialConstraintsAndIndependentChannels(t *testing.T) {
	s, b := settingsDraftFixture(t)
	ctx := context.Background()
	base := settingsStateForTest(t, s)
	for _, secret := range []string{"***", "********", "<redacted>"} {
		in := editorRequestForTest(t, s, "save", settingsEdit{Secrets: map[string]settingsSecretEdit{"email.password": {Action: "replace", Value: secret}}})
		if _, e := s.previewSettingsEditor(ctx, "admin", in, b); e == nil {
			t.Fatal("credential mask accepted")
		}
	}
	raw := []byte(`{"email":{"enabled":true,"smtp_host":"smtp.example.test","smtp_port":465,"tls_mode":"tls","username":"test@example.test","password":"isolated-only-password","from_address":"test@example.test","recipients":["recipient@example.test"],"timeout_seconds":5,"max_per_minute":10,"retry":{"initial_delay_seconds":2,"max_delay_seconds":60}},"feishu":{"enabled":false}}`)
	if _, e := s.saveSettingsDraft(ctx, "admin", "isolated-channel", raw, base.Generation, base.RuntimeVersion, b); e != nil {
		t.Fatal(e)
	}
	if _, e := s.applySettingsDraft(ctx, "admin", "isolated-channel-apply", settingsStateForTest(t, s).Generation, base.RuntimeVersion, b); e != nil {
		t.Fatal(e)
	}
	clear := editorRequestForTest(t, s, "save", settingsEdit{Secrets: map[string]settingsSecretEdit{"email.password": {Action: "clear"}}})
	if _, e := s.previewSettingsEditor(ctx, "admin", clear, b); !errors.Is(e, errSettingsEdit) {
		t.Fatal("enabled email accepted missing password", e)
	}
	clear.Edit.Values = map[string]json.RawMessage{"email.enabled": json.RawMessage(`false`)}
	p, e := s.previewSettingsEditor(ctx, "admin", clear, b)
	if e != nil {
		t.Fatal(e)
	}
	clear.Preview = p.Token
	if _, e = s.confirmSettingsEditor(ctx, "admin", "disable-and-clear", clear, b); e != nil {
		t.Fatal(e)
	}
	d := settingsStateForTest(t, s)
	if !d.Pending || !bytes.Contains(d.Runtime, []byte("isolated-only-password")) {
		t.Fatal("save modified runtime")
	}
	var desired configurationValues
	if decodeConfigurationObject(d.Desired, &desired) != nil || common.S(common.M(desired["email"])["password"]) != "" {
		t.Fatal("clear not saved")
	}
	// Disabled worker selection has no outbound call; the test never starts any sender.
	if n, e := s.claimNotification(ctx, "feishu", "isolated-worker"); e != nil || n != nil {
		t.Fatal("disabled feishu claimed work", e)
	}
}

func TestSettingsEditorSignedExpiryBounds(t *testing.T) {
	s, b := settingsDraftFixture(t)
	ctx := context.Background()
	in := editorRequestForTest(t, s, "save", settingsEdit{Values: map[string]json.RawMessage{"website_monitor.interval_seconds": json.RawMessage(`70`)}})
	for _, expires := range []int64{time.Now().Add(-time.Minute).Unix(), time.Now().Add(time.Hour).Unix()} {
		tx, e := s.DB.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		if e = b.lock(ctx, tx, "admin"); e != nil {
			tx.Rollback()
			t.Fatal(e)
		}
		_, doc, target, deployments, account, _, e := prepareSettingsEditorTx(ctx, tx, b, "admin", in)
		if e != nil {
			tx.Rollback()
			t.Fatal(e)
		}
		ticket := settingsPreviewTicket{Key: b.vault.active, Action: "save", Expires: expires, Nonce: token()}
		proof, e := settingsPreviewProof(b.vault, ticket, "admin", account, doc, target, deployments)
		tx.Rollback()
		if e != nil {
			t.Fatal(e)
		}
		in.Preview = base64.RawURLEncoding.EncodeToString(common.JSON(ticket)) + "." + proof
		if _, e = s.confirmSettingsEditor(ctx, "admin", "expired", in, b); !errors.Is(e, errSettingsPreview) {
			t.Fatal("signed invalid lifetime accepted", e)
		}
	}
	if tableCount(t, s, "v3_requests") != 0 || tableCount(t, s, "v3_configuration_backups") != 0 {
		t.Fatal("invalid lifetime left writes")
	}
}
