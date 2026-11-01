package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
	"webscan/internal/nodeconfig"
)

func publicMonitoringCall(a *API, method, path string, body []byte, session, csrf, key string, secure bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
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

func publicMonitoringView(t *testing.T, a *API, session string) monitoringRulesView {
	t.Helper()
	w := publicMonitoringCall(a, "GET", "/api/v3/monitoring/rules", nil, session, "", "", true)
	var out monitoringRulesView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatal("read public monitoring", w.Code, w.Body.String())
	}
	return out
}

func publicMonitoringPreview(t *testing.T, a *API, session string, in monitoringRulesRequest) monitoringRulesRequest {
	t.Helper()
	w := publicMonitoringCall(a, "POST", "/api/v3/monitoring/rules/preview", common.JSON(in), session, "configuration-csrf", "", true)
	var p struct {
		Token   string    `json:"token"`
		Expires time.Time `json:"expires_at"`
		Changed []string  `json:"changed_fields"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Token == "" || time.Until(p.Expires) < 9*time.Minute || time.Until(p.Expires) > 10*time.Minute {
		t.Fatal("public monitoring preview", w.Code, w.Body.String())
	}
	in.Preview = p.Token
	return in
}

func publicMonitoringRows(t *testing.T, s *Store, table, order string) string {
	t.Helper()
	var out string
	if e := s.DB.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY ` + order + `),'[]'::jsonb)::text FROM ` + table + ` r`).Scan(&out); e != nil {
		t.Fatal(e)
	}
	return out
}

func publicMonitoringNode(t *testing.T, s *Store, id string) Node {
	t.Helper()
	n, e := scanNode(s.DB.QueryRow(`SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, id))
	if e != nil {
		t.Fatal(e)
	}
	return n
}

func TestPublicMonitoringSaveBackupsAndRuntimeIsolation(t *testing.T) {
	a, v, sessions := configurationAPIFixture(t)
	s := a.Store
	mustHistoryExec(t, s.DB, `INSERT INTO v3_events(node,id,received_at,operation,payload) VALUES('saved-node','preserved-event',clock_timestamp(),'modify','{"path":"/www/preserved.php"}')`)
	before := settingsStateForTest(t, s)
	nodeBefore := publicMonitoringRows(t, s, "v3_nodes", "id")
	activeBefore := publicMonitoringRows(t, s, "v3_active_nodes", "id")
	eventsBefore := publicMonitoringRows(t, s, "v3_events", "node,id")
	sessionsBefore := publicMonitoringRows(t, s, "v3_sessions", "token_hash")
	view := publicMonitoringView(t, a, sessions["admin"])
	if view.Version != "0" || !reflect.DeepEqual(view.Rules, defaultMonitoringRules()) {
		t.Fatal("initial rules must reflect defaults", view)
	}
	rules := view.Rules
	rules.Roots = []string{"/srv/public-sites"}
	rules.Extensions = []string{".php", ".html"}
	rules.ReconciliationIntervalHours = 9
	in := publicMonitoringPreview(t, a, sessions["admin"], monitoringRulesRequest{Expected: view.Version, Rules: rules})
	if tableCount(t, s, "v3_configuration_backups") != 0 || tableCount(t, s, "v3_requests") != 0 || settingsStateForTest(t, s).Generation != 0 {
		t.Fatal("preview must not mutate settings, backup or task state")
	}
	w := publicMonitoringCall(a, "PUT", "/api/v3/monitoring/rules", common.JSON(in), sessions["admin"], "configuration-csrf", "save-rules", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	saved := settingsStateForTest(t, s)
	if saved.Generation < 1 || !saved.Pending || saved.RuntimeVersion != before.RuntimeVersion || !configurationJSONEqual(saved.Runtime, before.Runtime) || !bytes.Contains(saved.Desired, []byte("/srv/public-sites")) || !bytes.Contains(saved.Desired, []byte("private-stored-mail-value")) {
		t.Fatal("save applied runtime or lost existing settings")
	}
	newView := publicMonitoringView(t, a, sessions["admin"])
	if newView.Version != strconv.FormatInt(saved.Generation, 10) || !reflect.DeepEqual(newView.Rules, rules) {
		t.Fatal("saved read model mismatch")
	}
	again := publicMonitoringCall(a, "PUT", "/api/v3/monitoring/rules", common.JSON(in), sessions["admin"], "configuration-csrf", "save-rules", true)
	if again.Code != 200 || !configurationJSONEqual(w.Body.Bytes(), again.Body.Bytes()) || tableCount(t, s, "v3_configuration_backups") != 1 {
		t.Fatal("save replay created extra changes", again.Code)
	}
	in.Rules.ReconciliationIntervalHours++
	if got := publicMonitoringCall(a, "PUT", "/api/v3/monitoring/rules", common.JSON(in), sessions["admin"], "configuration-csrf", "save-rules", true); got.Code != 409 {
		t.Fatal("same key accepted different rules", got.Code)
	}
	items, e := s.configurationBackups(context.Background(), "admin", retentionCursor{}, 20)
	if e != nil || len(items) != 1 {
		t.Fatal("missing atomic backup", e)
	}
	doc := readPrivateConfigurationBackup(t, s, v, items[0].ID)
	if _, ok := doc.Settings["file_monitoring"]; ok || doc.Nodes["saved-node"].Version != 1 || doc.SettingsVersion != before.RuntimeVersion {
		t.Fatal("backup did not capture original snapshot")
	}
	for _, tc := range []struct{ table, order, before string }{{"v3_nodes", "id", nodeBefore}, {"v3_active_nodes", "id", activeBefore}, {"v3_events", "node,id", eventsBefore}, {"v3_sessions", "token_hash", sessionsBefore}} {
		if publicMonitoringRows(t, s, tc.table, tc.order) != tc.before {
			t.Fatal("rule save changed unrelated records", tc.table)
		}
	}
	if tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("rule save published work")
	}
	var audit string
	if e := s.DB.QueryRow(`SELECT jsonb_agg(result)::text FROM v3_audit`).Scan(&audit); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(audit, "private-") {
		t.Fatal("public audit disclosed private configuration")
	}
}

func TestPublicMonitoringAuthenticationTransportAndStrictInput(t *testing.T) {
	a, _, sessions := configurationAPIFixture(t)
	view := publicMonitoringView(t, a, sessions["admin"])
	body := common.JSON(monitoringRulesRequest{Expected: view.Version, Rules: view.Rules})
	for _, user := range []string{"", "operator", "viewer"} {
		want := 403
		if user == "" {
			want = 401
		}
		for _, method := range []string{"GET", "POST", "PUT"} {
			path := "/api/v3/monitoring/rules"
			if method == "POST" {
				path += "/preview"
			}
			if w := publicMonitoringCall(a, method, path, body, sessions[user], "configuration-csrf", "rejected", true); w.Code != want {
				t.Fatal("permission", user, method, w.Code)
			}
		}
	}
	for _, tc := range []struct {
		name, csrf string
		secure     bool
	}{{"missing csrf", "", true}, {"bad csrf", "bad", true}, {"plain HTTP", "configuration-csrf", false}} {
		if w := publicMonitoringCall(a, "POST", "/api/v3/monitoring/rules/preview", body, sessions["admin"], tc.csrf, "", tc.secure); w.Code != 403 {
			t.Fatal(tc.name, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/api/v3/monitoring/rules/preview", bytes.NewReader(body))
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: sessions["admin"]})
	r.Header.Set("X-CSRF-Token", "configuration-csrf")
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("untrusted proxy accepted", w.Code)
	}
	valid := string(body)
	for _, raw := range []string{
		strings.Replace(valid, `"roots":`, `"unexpected":true,"roots":`, 1),
		strings.Replace(valid, `"roots":`, `"roots":["/srv/a"],"roots":`, 1),
		strings.Replace(valid, `"roots":`, `"Roots":`, 1),
		strings.Replace(valid, `"roots":["/www/wwwroot"],`, ``, 1),
		strings.Replace(valid, `"roots":["/www/wwwroot"]`, `"roots":null`, 1),
		strings.Replace(valid, `"reconciliation_interval_hours":6`, `"reconciliation_interval_hours":null`, 1),
		strings.Replace(valid, `"expected_version":"0"`, `"expected_version":"00"`, 1),
		strings.Replace(valid, `"expected_version":"0"`, `"expected_version":"0","expected_version":"0"`, 1),
		valid + ` {}`, `null`,
	} {
		if got := publicMonitoringCall(a, "POST", "/api/v3/monitoring/rules/preview", []byte(raw), sessions["admin"], "configuration-csrf", "", true); got.Code != 400 {
			t.Errorf("ambiguous input accepted (%d): %s", got.Code, raw)
		}
	}
	in := publicMonitoringPreview(t, a, sessions["admin"], monitoringRulesRequest{Expected: view.Version, Rules: view.Rules})
	if got := publicMonitoringCall(a, "PUT", "/api/v3/monitoring/rules", common.JSON(in), sessions["admin"], "configuration-csrf", "", true); got.Code != 400 {
		t.Fatal("missing idempotency key", got.Code)
	}
	if tableCount(t, a.Store, "v3_configuration_backups") != 0 || tableCount(t, a.Store, "v3_requests") != 0 {
		t.Fatal("rejected inputs mutated state")
	}
}

func TestPublicMonitoringArchiveRejectsInvalidPolicyAndRoundtripsValidPolicy(t *testing.T) {
	c := configurationBootstrapFixture(t)
	for _, policy := range []string{
		`null`, `{}`, `{"source":"inherited"}`,
		`{"source":"inherit","rules_version":"0"}`,
		`{"source":"inherited","rules_version":"00"}`,
		`{"source":"inherited","rules_version":0}`,
		`{"Source":"inherited","rules_version":"0"}`,
		`{"source":"inherited","rules_version":"0","unknown":true}`,
	} {
		n := nodeFixture("archive-policy")
		n.Config = []byte(`{"monitoring_policy":` + policy + `}`)
		if _, e := newConfigurationDocument(c, []byte(`{}`), 1, []Node{n}, time.Now().UTC()); e == nil {
			t.Errorf("archive accepted invalid monitoring policy: %s", policy)
		}
	}
	for _, source := range []string{"inherited", "independent"} {
		n := nodeFixture("archive-policy")
		n.Config = common.JSON(map[string]any{"monitoring_policy": map[string]string{"source": source, "rules_version": "7"}})
		doc, e := newConfigurationDocument(c, []byte(`{}`), 1, []Node{n}, time.Now().UTC())
		if e != nil {
			t.Fatal("valid policy rejected", source, e)
		}
		raw, e := marshalConfigurationDocument(doc)
		if e != nil {
			t.Fatal(e)
		}
		restored, e := parseConfigurationDocument(raw)
		if e != nil {
			t.Fatal("valid policy failed restore validation", e)
		}
		rawAgain, e := marshalConfigurationDocument(restored)
		if e != nil || !bytes.Equal(raw, rawAgain) {
			t.Fatal("archive policy roundtrip changed", e)
		}
	}
}

func TestPublicMonitoringConcurrentPreviewsCommitOneVersion(t *testing.T) {
	a, _, sessions := configurationAPIFixture(t)
	view := publicMonitoringView(t, a, sessions["admin"])
	inputs := []monitoringRulesRequest{{Expected: view.Version, Rules: view.Rules}, {Expected: view.Version, Rules: view.Rules}}
	for i := range inputs {
		inputs[i].Rules.ReconciliationIntervalHours = 12 + i
		inputs[i] = publicMonitoringPreview(t, a, sessions["admin"], inputs[i])
	}
	start := make(chan struct{})
	done := make(chan *httptest.ResponseRecorder, 2)
	for i, in := range inputs {
		i, in := i, in
		go func() {
			<-start
			done <- publicMonitoringCall(a, "PUT", "/api/v3/monitoring/rules", common.JSON(in), sessions["admin"], "configuration-csrf", "concurrent-"+strconv.Itoa(i), true)
		}()
	}
	close(start)
	codes := map[int]int{}
	for range inputs {
		w := <-done
		codes[w.Code]++
		if w.Code != 200 && w.Code != 409 {
			t.Errorf("concurrent save failed unexpectedly: %d %s", w.Code, w.Body.String())
		}
	}
	if codes[200] != 1 || codes[409] != 1 || tableCount(t, a.Store, "v3_configuration_backups") != 1 || tableCount(t, a.Store, "v3_requests") != 1 {
		t.Fatal("concurrent previews bypassed version lock", codes)
	}
	current := publicMonitoringView(t, a, sessions["admin"])
	if current.Version == view.Version || current.Rules.ReconciliationIntervalHours < 12 || current.Rules.ReconciliationIntervalHours > 13 {
		t.Fatal("concurrent save produced unexpected configuration")
	}
}

func TestPublicMonitoringNodeRejectsAmbiguousPolicy(t *testing.T) {
	a, _, sessions := configurationAPIFixture(t)
	n := nodeFixture("strict-policy")
	n.Monitoring = &NodeMonitoring{Source: "independent", Rules: defaultMonitoringRules(), RulesVersion: "0"}
	valid := string(common.JSON(map[string]any{"node": n, "expected_version": 0}))
	for _, raw := range []string{
		strings.Replace(valid, `"source":"independent"`, `"Source":"independent"`, 1),
		strings.Replace(valid, `"source":"independent"`, `"source":"independent","source":"inherited"`, 1),
		strings.Replace(valid, `"rules_version":"0"`, `"rules_version":null`, 1),
		strings.Replace(valid, `"rules_version":"0"`, `"rules_version":"00"`, 1),
		strings.Replace(valid, `"source":"independent"`, `"source":"unexpected"`, 1),
		strings.Replace(valid, `"roots":`, `"unexpected":true,"roots":`, 1),
		strings.Replace(valid, `"roots":["/www/wwwroot"]`, `"roots":null`, 1),
	} {
		w := publicMonitoringCall(a, "POST", "/api/v3/servers", []byte(raw), sessions["admin"], "configuration-csrf", "strict-policy", true)
		if w.Code != 400 {
			t.Errorf("node accepted ambiguous policy: %d %s", w.Code, raw)
		}
	}
	if tableCount(t, a.Store, "v3_nodes") != 1 || tableCount(t, a.Store, "v3_configuration_backups") != 0 || tableCount(t, a.Store, "v3_requests") != 0 {
		t.Fatal("rejected policy mutated node configuration")
	}
}

func TestPublicMonitoringPreviewBindingsExpiryAndAccountRevision(t *testing.T) {
	for _, kind := range []string{"expired", "overlong", "changed-rules", "changed-version", "different-account", "account-revision"} {
		t.Run(kind, func(t *testing.T) {
			a, v, sessions := configurationAPIFixture(t)
			view := publicMonitoringView(t, a, sessions["admin"])
			in := publicMonitoringPreview(t, a, sessions["admin"], monitoringRulesRequest{Expected: view.Version, Rules: view.Rules})
			session := sessions["admin"]
			switch kind {
			case "expired", "overlong":
				parts := strings.Split(in.Preview, ".")
				raw, e := base64.RawURLEncoding.DecodeString(parts[0])
				if e != nil {
					t.Fatal(e)
				}
				var ticket monitoringRulesTicket
				if json.Unmarshal(raw, &ticket) != nil {
					t.Fatal("ticket")
				}
				ticket.Expires = time.Now().Add(-time.Second).Unix()
				if kind == "overlong" {
					ticket.Expires = time.Now().Add(11 * time.Minute).Unix()
				}
				raw = common.JSON(ticket)
				in.Preview = base64.RawURLEncoding.EncodeToString(raw) + "." + monitoringMAC(v, ticket.Key, raw)
			case "changed-rules":
				in.Rules.ReconciliationIntervalHours++
			case "changed-version":
				in.Expected = "1"
			case "different-account":
				mustHistoryExec(t, a.Store.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('other','not-a-login-hash','admin')`)
				session = token()
				mustHistoryExec(t, a.Store.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,'other',1,'configuration-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(session)))
			case "account-revision":
				mustHistoryExec(t, a.Store.DB, `UPDATE v3_accounts SET revision=2 WHERE username='admin';UPDATE v3_sessions SET revision=2 WHERE username='admin'`)
			}
			w := publicMonitoringCall(a, "PUT", "/api/v3/monitoring/rules", common.JSON(in), session, "configuration-csrf", "bound-preview", true)
			if w.Code != 409 {
				t.Fatal("unbound preview accepted", w.Code, w.Body.String())
			}
			if settingsStateForTest(t, a.Store).Generation != 0 || tableCount(t, a.Store, "v3_configuration_backups") != 0 || tableCount(t, a.Store, "v3_requests") != 0 {
				t.Fatal("invalid preview wrote state")
			}
		})
	}
}

func TestPublicMonitoringBackupFailureRollsBackAndRetry(t *testing.T) {
	for _, table := range []string{"v3_configuration_backups", "v3_configuration_backup_parts", "v3_audit"} {
		t.Run(table, func(t *testing.T) {
			a, _, sessions := configurationAPIFixture(t)
			view := publicMonitoringView(t, a, sessions["admin"])
			view.Rules.ReconciliationIntervalHours++
			in := publicMonitoringPreview(t, a, sessions["admin"], monitoringRulesRequest{Expected: view.Version, Rules: view.Rules})
			before := settingsStateForTest(t, a.Store)
			mustHistoryExec(t, a.Store.DB, `CREATE FUNCTION reject_monitoring_backup() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated private-detail backup failure';END$$;CREATE TRIGGER reject_monitoring_backup BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION reject_monitoring_backup()`)
			call := func() *httptest.ResponseRecorder {
				return publicMonitoringCall(a, "PUT", "/api/v3/monitoring/rules", common.JSON(in), sessions["admin"], "configuration-csrf", "retry-after-backup", true)
			}
			w := call()
			if w.Code != 503 || strings.Contains(w.Body.String(), "private-detail") {
				t.Fatal("backup error handling", w.Code, w.Body.String())
			}
			after := settingsStateForTest(t, a.Store)
			if after.Generation != before.Generation || !configurationJSONEqual(after.Desired, before.Desired) || !configurationJSONEqual(after.Runtime, before.Runtime) {
				t.Fatal("backup failure modified configuration")
			}
			for _, check := range []string{"v3_configuration_backups", "v3_configuration_backup_parts", "v3_audit", "v3_requests"} {
				if tableCount(t, a.Store, check) != 0 {
					t.Fatal("partial backup/mutation committed", check)
				}
			}
			mustHistoryExec(t, a.Store.DB, `DROP TRIGGER reject_monitoring_backup ON `+table)
			if w = call(); w.Code != 200 || tableCount(t, a.Store, "v3_configuration_backups") != 1 {
				t.Fatal("retry failed", w.Code, w.Body.String())
			}
		})
	}
}

func TestPublicMonitoringNodeInheritanceAndExistingConfigPreservation(t *testing.T) {
	a, _, sessions := configurationAPIFixture(t)
	s := a.Store
	view := publicMonitoringView(t, a, sessions["admin"])
	view.Rules.Roots = []string{"/srv/inherited"}
	view.Rules.ReconciliationIntervalHours = 8
	in := publicMonitoringPreview(t, a, sessions["admin"], monitoringRulesRequest{Expected: view.Version, Rules: view.Rules})
	if w := publicMonitoringCall(a, "PUT", "/api/v3/monitoring/rules", common.JSON(in), sessions["admin"], "configuration-csrf", "public-rules", true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	view = publicMonitoringView(t, a, sessions["admin"])
	activeBefore := publicMonitoringRows(t, s, "v3_active_nodes", "id")
	old := publicMonitoringNode(t, s, "saved-node")
	old.Name = "edited legacy node"
	old.Monitoring = nil // Existing callers omit the newly introduced policy.
	save := func(n Node, expected int64, key string) *httptest.ResponseRecorder {
		return publicMonitoringCall(a, "POST", "/api/v3/servers", common.JSON(map[string]any{"node": n, "expected_version": expected}), sessions["admin"], "configuration-csrf", key, true)
	}
	if w := save(old, old.Version, "legacy-edit"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	stored := publicMonitoringNode(t, s, old.ID)
	if !configurationJSONEqual(stored.Config, old.Config) || monitoringForNode(stored).Source != "independent" {
		t.Fatal("legacy edit silently changed monitor config")
	}
	fresh := nodeFixture("inherited-node")
	fresh.Mode = "docker"
	if w := save(fresh, 0, "new-inherit"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	newNode := publicMonitoringNode(t, s, fresh.ID)
	policy := monitoringForNode(newNode)
	if policy == nil || policy.Source != "inherited" || policy.RulesVersion != view.Version || !reflect.DeepEqual(policy.Rules, view.Rules) {
		t.Fatal("new node did not inherit saved public rules", policy)
	}
	settings, e := nodeRuntimeSettings(newNode.Config)
	if e != nil || settings.ProbeDirectory != "/srv/inherited/.webscan-probe" {
		t.Fatal("inherited probe not derived", e)
	}
	if activeBefore != publicMonitoringRows(t, s, "v3_active_nodes", "id") {
		t.Fatal("saved monitoring configuration published active registration")
	}
	stale := nodeFixture("stale-inheritance")
	stale.Monitoring = &NodeMonitoring{Source: "inherited", Rules: view.Rules, RulesVersion: "99999"}
	if w := save(stale, 0, "stale-inheritance"); w.Code != 409 {
		t.Fatal("stale inherited version accepted", w.Code, w.Body.String())
	}
	independent := nodeFixture("independent-node")
	own := defaultMonitoringRules()
	own.Roots = []string{"/srv/private"}
	independent.Monitoring = &NodeMonitoring{Source: "independent", Rules: own, RulesVersion: "0"}
	if w := save(independent, 0, "new-independent"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if got := monitoringForNode(publicMonitoringNode(t, s, independent.ID)); got == nil || got.Source != "independent" || !reflect.DeepEqual(got.Rules, own) {
		t.Fatal("independent rules lost", got)
	}
}

func TestPublicMonitoringIndependentEditPreservesAdvancedSettingsAndCustomProbe(t *testing.T) {
	for _, custom := range []bool{false, true} {
		name := "derived-probe"
		if custom {
			name = "custom-probe"
		}
		t.Run(name, func(t *testing.T) {
			a, _, sessions := configurationAPIFixture(t)
			settings := nodeconfig.DefaultSettings()
			settings.Monitor.Reconciliation.StartJitterMinutes = 21
			settings.Monitor.Reconciliation.MaxReadMiBPerSecond = 7
			settings.Monitor.Reconciliation.Nice = 12
			if custom {
				settings.ProbeDirectory = "/www/wwwroot/special-probe"
			}
			root := map[string]any{}
			if json.Unmarshal(common.JSON(settings), &root) != nil {
				t.Fatal("settings")
			}
			root["private"] = map[string]any{"token": "isolated-kept-secret"}
			mustHistoryExec(t, a.Store.DB, `UPDATE v3_nodes SET config=$1 WHERE id='saved-node'`, common.JSON(root))
			n := publicMonitoringNode(t, a.Store, "saved-node")
			rules := rulesFromMonitor(settings.Monitor)
			rules.Roots = []string{"/srv/moved"}
			rules.Extensions = []string{".go"}
			rules.ReconciliationIntervalHours = 17
			n.Monitoring = &NodeMonitoring{Source: "independent", Rules: rules, RulesVersion: "0"}
			before := publicMonitoringRows(t, a.Store, "v3_nodes", "id")
			w := publicMonitoringCall(a, "POST", "/api/v3/servers", common.JSON(map[string]any{"node": n, "expected_version": n.Version}), sessions["admin"], "configuration-csrf", "change-monitor", true)
			if custom {
				if w.Code != 409 || before != publicMonitoringRows(t, a.Store, "v3_nodes", "id") {
					t.Fatal("custom probe silently moved or invalid config saved", w.Code, w.Body.String())
				}
				return
			}
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			saved := publicMonitoringNode(t, a.Store, n.ID)
			got, e := nodeRuntimeSettings(saved.Config)
			if e != nil || got.ProbeDirectory != "/srv/moved/.webscan-probe" || got.Monitor.Reconciliation.IntervalHours != 17 || got.Monitor.Reconciliation.StartJitterMinutes != 21 || got.Monitor.Reconciliation.MaxReadMiBPerSecond != 7 || got.Monitor.Reconciliation.Nice != 12 || !reflect.DeepEqual(got.Scan, settings.Scan) || !reflect.DeepEqual(got.Resources, settings.Resources) || !reflect.DeepEqual(got.Transport, settings.Transport) || !bytes.Contains(saved.Config, []byte("isolated-kept-secret")) {
				t.Fatal("monitor edit destroyed advanced/private settings", e)
			}
		})
	}
}
