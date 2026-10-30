package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func applicationAPIFixture(t *testing.T) (*API, configurationLocalFixture, configurationApplicationJob, map[string]string) {
	t.Helper()
	s, f, j := workerSavedFixture(t, false)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('other-admin','not-a-login','admin'),('operator','not-a-login','operator'),('viewer','not-a-login','viewer')`)
	sessions := map[string]string{}
	for _, user := range []string{"admin", "other-admin", "operator", "viewer"} {
		sessions[user] = token()
		mustHistoryExec(t, s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,$2,1,'application-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(sessions[user])), user)
	}
	return NewAPI(s, f.c), f, j, sessions
}

func TestConfigurationApplicationAPIReadAuthPaginationAndLogs(t *testing.T) {
	a, f, j, sessions := applicationAPIFixture(t)
	if j.Created.IsZero() || j.Updated.IsZero() {
		t.Fatal("queue receipt omitted persisted timestamps")
	}
	call := func(user, path string) *httptest.ResponseRecorder {
		return restoreAPICall(a, "GET", "configuration-applications"+path, "", sessions[user], "", "", true)
	}
	for _, user := range []string{"", "viewer", "operator", "admin", "other-admin"} {
		want := 403
		if user == "" {
			want = 401
		}
		if user == "admin" || user == "other-admin" {
			want = 200
		}
		for _, path := range []string{"?limit=1", "/" + j.ID, "/" + j.ID + "/logs?after=0&limit=1"} {
			if w := call(user, path); w.Code != want {
				t.Fatalf("%s %s: %d %s", user, path, w.Code, w.Body.String())
			}
		}
	}
	w := call("admin", "?limit=1&stage="+j.Stage)
	var page struct {
		Items []configurationApplicationJob `json:"items"`
		Next  string                        `json:"next_cursor"`
	}
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].ID != j.ID || page.Next == "" {
		t.Fatal("wrong page", w.Body.String())
	}
	if w = call("admin", "?limit=1&cursor="+page.Next); w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal("cursor repeated task", w.Body.String())
	}
	if w = call("admin", "?stage="+strings.Repeat("f", 64)); w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal("stage filter ignored")
	}
	_ = claimApplicationForTest(t, a.Store, f, "api-worker")
	w = call("admin", "/"+j.ID+"/logs?after=0&limit=1")
	var logs struct {
		Items []configurationApplicationLog `json:"items"`
		Next  string                        `json:"next_cursor"`
		Job   configurationApplicationJob   `json:"job"`
	}
	if json.Unmarshal(w.Body.Bytes(), &logs) != nil || len(logs.Items) != 1 || logs.Items[0].Code != "queued" || logs.Next != "1" || logs.Job.LogCursor != 2 {
		t.Fatal("wrong first log window", w.Body.String())
	}
	w = call("admin", "/"+j.ID+"/logs?after="+logs.Next)
	if json.Unmarshal(w.Body.Bytes(), &logs) != nil || len(logs.Items) != 1 || logs.Items[0].Code != "claimed" || logs.Next != "2" {
		t.Fatal("log replay lost cursor", w.Body.String())
	}
	w = call("admin", "/"+j.ID+"/logs?after=2")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) || !strings.Contains(w.Body.String(), `"next_cursor":"2"`) {
		t.Fatal("empty window changed cursor")
	}
	p := privateApplicationForTest(t, a.Store, f.v, j.ID)
	for _, path := range []string{"", "/" + j.ID, "/" + j.ID + "/logs"} {
		w = call("admin", path)
		for _, secret := range []string{f.f.root, p.planProof, p.sourceProof, p.stateProof, p.member, "private-dsn-password", "PRIVATE KEY"} {
			if secret != "" && strings.Contains(w.Body.String(), secret) {
				t.Fatal("public read leaked private material")
			}
		}
	}
	if w = call("admin", "/"+j.ID); !strings.Contains(w.Body.String(), `"can_resume":false`) || !strings.Contains(w.Body.String(), `"can_cancel":false`) {
		t.Fatal("read granted execution")
	}
}

func TestConfigurationApplicationAPIRejectsInvalidReadsAndUnavailableWrites(t *testing.T) {
	a, _, j, sessions := applicationAPIFixture(t)
	for _, suffix := range []string{"?limit=0", "?limit=201", "?limit=bad", "?cursor=bad", "?stage=bad", "/" + j.ID + "/logs?after=-1", "/" + j.ID + "/logs?after=2", "/" + j.ID + "/logs?after=9223372036854775808", "/" + j.ID + "/logs?limit=201"} {
		w := restoreAPICall(a, "GET", "configuration-applications"+suffix, "", sessions["admin"], "", "", true)
		if w.Code != 400 {
			t.Fatal(suffix, w.Code, w.Body.String())
		}
	}
	for _, after := range []string{"01", "%2B1", "1.0"} {
		if w := restoreAPICall(a, "GET", "configuration-applications/"+j.ID+"/logs?after="+after, "", sessions["admin"], "", "", true); w.Code != 400 {
			t.Fatal("noncanonical log cursor accepted", w.Code)
		}
	}
	for _, suffix := range []string{"/bad", "/" + j.ID + "/unknown", "/" + strings.Repeat("f", 64), "/" + strings.Repeat("f", 64) + "/logs"} {
		if w := restoreAPICall(a, "GET", "configuration-applications"+suffix, "", sessions["admin"], "", "", true); w.Code != 404 {
			t.Fatal(suffix, w.Code)
		}
	}
	for _, enabled := range []bool{false, true} {
		a.bootstrapConfig.Executor.ApplicationsEnabled = enabled
		for _, path := range []string{"configuration-applications", "configuration-applications/" + j.ID + "/resume", "configuration-applications/" + j.ID + "/rollback", "configuration-applications/" + j.ID + "/cancel"} {
			for _, tc := range []struct {
				user, csrf string
				want       int
			}{{"", "", 401}, {"admin", "", 403}, {"viewer", "application-csrf", 403}, {"operator", "application-csrf", 403}, {"admin", "application-csrf", 503}} {
				w := restoreAPICall(a, "POST", path, `{"confirm":true}`, sessions[tc.user], tc.csrf, "blocked-post", true)
				want := tc.want
				if enabled && tc.user == "admin" && tc.csrf != "" {
					want = 400
				}
				if w.Code != want {
					t.Fatal(enabled, path, tc.user, w.Code, w.Body.String())
				}
			}
		}
	}
	if tableCount(t, a.Store, "v3_configuration_applications") != 1 || tableCount(t, a.Store, "v3_configuration_application_logs") != 1 {
		t.Fatal("unavailable write changed journal")
	}
}

func TestConfigurationApplicationAPIUnverifiedJournalsAndLogCorruption(t *testing.T) {
	for _, kind := range []string{"signature", "log-code", "log-phase", "log-gap", "log-upper-gap"} {
		t.Run(kind, func(t *testing.T) {
			a, f, j, sessions := applicationAPIFixture(t)
			_ = claimApplicationForTest(t, a.Store, f, "log-corruption-worker")
			switch kind {
			case "signature":
				mustHistoryExec(t, a.Store.DB, `UPDATE v3_configuration_applications SET state_proof='private-invalid-proof' WHERE id=$1`, j.ID)
			case "log-code":
				mustHistoryExec(t, a.Store.DB, `UPDATE v3_configuration_application_logs SET code='private-log-payload' WHERE job=$1 AND cursor=1`, j.ID)
			case "log-phase":
				mustHistoryExec(t, a.Store.DB, `UPDATE v3_configuration_application_logs SET phase='private-path-payload' WHERE job=$1 AND cursor=1`, j.ID)
			case "log-gap":
				mustHistoryExec(t, a.Store.DB, `DELETE FROM v3_configuration_application_logs WHERE job=$1 AND cursor=1`, j.ID)
			case "log-upper-gap":
				mustHistoryExec(t, a.Store.DB, `DELETE FROM v3_configuration_application_logs WHERE job=$1 AND cursor=2`, j.ID)
			}
			w := restoreAPICall(a, "GET", "configuration-applications/"+j.ID+"/logs", "", sessions["admin"], "", "", true)
			if w.Code != 503 || strings.Contains(w.Body.String(), "private-") || strings.Contains(w.Body.String(), f.f.root) {
				t.Fatal("corruption appeared as valid logs", w.Code, w.Body.String())
			}
			if kind == "signature" {
				for _, path := range []string{"configuration-applications", "configuration-applications/" + j.ID} {
					w = restoreAPICall(a, "GET", path, "", sessions["admin"], "", "", true)
					if w.Code != 503 {
						t.Fatal("unverified journal escaped", w.Code)
					}
				}
			}
		})
	}
}

func TestConfigurationApplicationAPIKeysAreLazyAndDatabaseErrorsSafe(t *testing.T) {
	a, f, j, sessions := applicationAPIFixture(t)
	if err := os.Rename(f.c.DeploymentTrust.VaultKeyFile, f.c.DeploymentTrust.VaultKeyFile+".held"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"configuration-applications", "configuration-applications/" + j.ID, "configuration-applications/" + j.ID + "/logs"} {
		w := restoreAPICall(a, "GET", path, "", sessions["admin"], "", "", true)
		if w.Code != 503 || strings.Contains(w.Body.String(), f.f.root) {
			t.Fatal("missing vault accepted or leaked path", w.Code)
		}
	}
	// An empty/filter-excluded page needs no application decryption key.
	for _, path := range []string{"configuration-applications?stage=" + strings.Repeat("f", 64), "configuration-applications?cursor=" + (retentionCursor{j.Created, j.ID}).encode()} {
		w := restoreAPICall(a, "GET", path, "", sessions["admin"], "", "", true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
			t.Fatal("empty page unnecessarily requires key", w.Code)
		}
	}
	a.Store.DB.Close()
	w := restoreAPICall(a, "GET", "configuration-applications", "", sessions["admin"], "", "", true)
	if w.Code != 503 || strings.Contains(w.Body.String(), "private-") {
		t.Fatal("database failure looked like logout", w.Code)
	}
}

func TestConfigurationApplicationReadDecimalCursorPrecision(t *testing.T) {
	s, f, j := workerSavedFixture(t, false)
	// Large signed cursors must survive JSON and cursor arithmetic exactly.
	p := privateApplicationForTest(t, s, f.v, j.ID)
	p.LogCursor = 9007199254740993
	proof, err := applicationStateProof(f.v, f.v.active, p)
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET log_cursor=$2,state_proof=$3 WHERE id=$1`, j.ID, p.LogCursor, proof)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_configuration_application_logs(job,cursor,direction,phase,code) VALUES($1,$2,'forward','environment','claimed')`, j.ID, p.LogCursor)
	_, logs, err := s.configurationApplicationLogs(context.Background(), f.v, "admin", j.ID, p.LogCursor-1, 1)
	if err != nil || len(logs) != 1 || logs[0].Cursor != p.LogCursor {
		t.Fatal("large cursor lost precision", err)
	}
	raw, err := json.Marshal(logs)
	if err != nil || !strings.Contains(string(raw), fmt.Sprintf(`"cursor":"%d"`, p.LogCursor)) {
		t.Fatal("cursor encoded as unsafe number")
	}
}
