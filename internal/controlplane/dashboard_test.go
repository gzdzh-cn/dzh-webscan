package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardSnapshotCountsPrivacyAndUnknownEvidence(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for _, id := range []string{"active", "disabled", "unknown"} {
		n := nodeFixture(id)
		n.Enabled = id != "disabled"
		if err := s.PutNode(ctx, n, 0, 256); err != nil {
			t.Fatal(err)
		}
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_node_status(node,sampled_at,metrics,info) VALUES('active',(extract(epoch FROM clock_timestamp())*1000)::bigint,'{"cpu_percent":0,"memory_percent":50,"secret":"private-metric"}','{"agent_version":"v3.local","agent_mode":"native","private_key":"private-info"}')`)
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{"email":{"enabled":false,"password":"private-smtp","host":"private-address"}}'`)
	active := savedSite(t, s, "active-site")
	paused := savedSite(t, s, "paused-site")
	mustHistoryExec(t, s.DB, `UPDATE v3_websites SET state='{"status":"down"}' WHERE id IN($1,$2)`, active.ID, paused.ID)
	mustHistoryExec(t, s.DB, `UPDATE v3_websites SET paused=true WHERE id=$1`, paused.ID)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_events(node,id,received_at,operation,security,payload) VALUES('active','file',clock_timestamp(),'write',false,'{}'),('active','scan',clock_timestamp(),'scan',true,'{}'),('active','probe',clock_timestamp(),'probe',false,'{}')`)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_notifications(node,event_id,channel,payload) VALUES('active','file','email','{"password":"private-payload"}')`)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_website_incidents(site,kind,started,reason) VALUES($1,'certificate',1,'fixture'),($2,'outage',1,'fixture')`, active.ID, paused.ID)
	before := tableCount(t, s, "v3_audit")
	v, err := s.dashboardSnapshot(ctx, dashboardSnapshot{}, 30)
	if err != nil || v.Servers == nil || *v.Servers != 3 || *v.Fresh != 1 || *v.Unknown != 1 {
		t.Fatal("wrong node summary", err)
	}
	if len(v.Sections) != 11 {
		t.Fatal("missing sections")
	}
	for name, section := range v.Sections {
		if section.Error != "" || section.UpdatedAt == nil || len(section.Data) == 0 {
			t.Fatal(name, section.Error)
		}
	}
	var events struct{ Total, Security int }
	if json.Unmarshal(v.Sections["events"].Data, &events) != nil || events.Total != 2 || events.Security != 1 {
		t.Fatal("probe counted")
	}
	var alerts struct {
		Total int
		Items []any
	}
	if json.Unmarshal(v.Sections["alerts"].Data, &alerts) != nil || alerts.Total != 1 || len(alerts.Items) != 1 {
		t.Fatal("paused website counted")
	}
	var resources struct {
		Items []struct {
			CPU  *float64 `json:"cpu_percent"`
			Disk *float64 `json:"disk_percent"`
		} `json:"items"`
	}
	if json.Unmarshal(v.Sections["resources"].Data, &resources) != nil || len(resources.Items) != 2 || resources.Items[0].CPU == nil || *resources.Items[0].CPU != 0 || resources.Items[0].Disk != nil {
		t.Fatal("missing value replaced by zero")
	}
	raw, _ := json.Marshal(v)
	for _, secret := range []string{"private-metric", "private-info", "private-smtp", "private-address", "private-payload", "private_key"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private data in summary")
		}
	}
	if tableCount(t, s, "v3_audit") != before || tableCount(t, s, "v3_deployment_jobs") != 0 {
		t.Fatal("summary caused a mutation")
	}
}

func TestDashboardSavedIntentDoesNotHideRuntimeEvidence(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("running")
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_node_status(node,sampled_at,metrics) VALUES('running',(extract(epoch FROM clock_timestamp())*1000)::bigint,'{"cpu_percent":25}')`)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_health_rules(key,node,kind,phase,since,last,recovery,reminder,payload) VALUES('running-memory','running','memory','firing',1,1,0,0,'{}')`)
	n.Enabled = false
	n.Name = "draft-name"
	if _, err := s.SaveNode(ctx, "admin", "save-disable", n, 1, 256); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveNode(ctx, "admin", "save-unregistered", nodeFixture("unregistered"), 0, 256); err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.dashboardSnapshot(ctx, dashboardSnapshot{}, 30)
	if err != nil || snapshot.CurrentAlerts == nil || *snapshot.CurrentAlerts != 1 || *snapshot.Fresh != 1 || *snapshot.Unknown != 1 {
		t.Fatal("saved drafts changed live summary", err)
	}
	var alerts struct{ Total int }
	if err = json.Unmarshal(snapshot.Sections["alerts"].Data, &alerts); err != nil || alerts.Total != 1 {
		t.Fatal("draft hid runtime alarm", err)
	}
	var resources struct{ Items []struct{ ID, Name string } }
	if err = json.Unmarshal(snapshot.Sections["resources"].Data, &resources); err != nil || len(resources.Items) != 1 || resources.Items[0].Name == "draft-name" {
		t.Fatal("resources use saved draft", err)
	}
}

func TestDashboardSnapshotSectionFailureRetainsPriorObservation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	previous, err := s.dashboardSnapshot(ctx, dashboardSnapshot{}, 30)
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `ALTER TABLE v3_websites RENAME TO unavailable_websites`)
	failed, err := s.dashboardSnapshot(ctx, previous, 30)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"websites", "alerts"} {
		v := failed.Sections[name]
		if v.Error == "" || !v.UpdatedAt.Equal(*previous.Sections[name].UpdatedAt) || string(v.Data) != string(previous.Sections[name].Data) {
			t.Fatal("failure discarded data or renewed its timestamp", name)
		}
	}
	if failed.Sections["events"].Error != "" {
		t.Fatal("independent section failed")
	}
	cold, err := s.dashboardSnapshot(ctx, dashboardSnapshot{}, 30)
	if err != nil || cold.Sections["alerts"].Data != nil || cold.Sections["alerts"].UpdatedAt != nil || cold.Sections["alerts"].Error == "" {
		t.Fatal("cold failure reported as no alerts", err)
	}
	mustHistoryExec(t, s.DB, `ALTER TABLE unavailable_websites RENAME TO v3_websites`)
	recovered, err := s.dashboardSnapshot(ctx, failed, 30)
	if err != nil || recovered.Sections["alerts"].Error != "" {
		t.Fatal("recovery did not clear error", err)
	}
}

func TestDashboardAPIUsesOnlyPrecomputedSnapshot(t *testing.T) {
	s := testStore(t)
	api := &API{Store: s}
	session := historyAPISession(t, s, "viewer", "viewer")
	call := func(cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/v3/dashboard", nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: cookie})
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	if w := call(""); w.Code != 401 {
		t.Fatal("anonymous summary", w.Code)
	}
	if w := call(session); w.Code != 503 {
		t.Fatal("missing cache became empty summary", w.Code)
	}
	v, err := s.dashboardSnapshot(context.Background(), dashboardSnapshot{}, 30)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(v)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_dashboard VALUES(1,$1,clock_timestamp()-interval '2 minutes','')`, raw)
	mustHistoryExec(t, s.DB, `ALTER TABLE v3_nodes RENAME TO unavailable_nodes`)
	w := call(session)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"stale":true`) {
		t.Fatal("HTTP recalculated nodes instead of cache", w.Code, w.Body.String())
	}
	s.DB.Close()
	if w := call(session); w.Code != 503 {
		t.Fatal("database outage became logout", w.Code)
	}
}

func TestDashboardRankingsUseAllNodesAndConfiguredFreshness(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	// The maximum is deliberately outside the resource table's first page.
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "z-best", "zz-future"} {
		if err := s.PutNode(ctx, nodeFixture(id), 0, 256); err != nil {
			t.Fatal(err)
		}
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_node_status(node,sampled_at,metrics) SELECT id,(extract(epoch FROM clock_timestamp()-interval '5 minutes')*1000)::bigint,'{"cpu_percent":20,"memory_percent":null,"disk_percent":"private-string"}'::jsonb FROM v3_nodes`)
	mustHistoryExec(t, s.DB, `UPDATE v3_node_status SET metrics='{"cpu_percent":99}' WHERE node='z-best'`)
	mustHistoryExec(t, s.DB, `UPDATE v3_node_status SET sampled_at=(extract(epoch FROM clock_timestamp()+interval '1 day')*1000)::bigint,metrics='{"cpu_percent":100}' WHERE node='zz-future'`)
	read := func(interval int) struct {
		Items    []struct{ ID string }
		Rankings map[string][]struct {
			ID    string
			Value float64
		}
	} {
		v, err := s.dashboardSnapshot(ctx, dashboardSnapshot{}, interval)
		if err != nil || v.Sections["resources"].Error != "" {
			t.Fatal(err, v.Sections["resources"].Error)
		}
		var result struct {
			Items    []struct{ ID string }
			Rankings map[string][]struct {
				ID    string
				Value float64
			}
		}
		if json.Unmarshal(v.Sections["resources"].Data, &result) != nil {
			t.Fatal("invalid resource snapshot")
		}
		return result
	}
	current := read(300)
	if len(current.Items) != 20 || len(current.Rankings["cpu_percent"]) != 10 || current.Rankings["cpu_percent"][0].ID != "z-best" || current.Rankings["cpu_percent"][0].Value != 99 || len(current.Rankings["disk_percent"]) != 0 {
		t.Fatal("rankings came from first page, future sample or invalid metric")
	}
	if len(read(30).Rankings["cpu_percent"]) != 0 {
		t.Fatal("stale sample presented as fresh")
	}
	raw, err := s.summaryWithFreshness(ctx, 900)
	var summary struct{ Fresh, Abnormal int }
	if err != nil || json.Unmarshal(raw, &summary) != nil || summary.Fresh != 23 || summary.Abnormal != 1 {
		t.Fatal("freshness counts disagree", err, string(raw))
	}
}
