package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAlertReadModelsWebsiteFiltersAndActiveExclusions(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	active := savedSite(t, s, "active")
	other := savedSite(t, s, "other")
	paused := savedSite(t, s, "paused")
	deleted := savedSite(t, s, "deleted")
	migrating := savedSite(t, s, "migrating")
	mustHistoryExec(t, s.DB, "UPDATE v3_websites SET node='node-a'")
	mustHistoryExec(t, s.DB, "UPDATE v3_websites SET node='node-b' WHERE id=$1", other.ID)
	mustHistoryExec(t, s.DB, "UPDATE v3_websites SET paused=true WHERE id=$1", paused.ID)
	mustHistoryExec(t, s.DB, "UPDATE v3_websites SET deleted=true WHERE id=$1", deleted.ID)
	mustHistoryExec(t, s.DB, "UPDATE v3_websites SET migration_pending=true WHERE id=$1", migrating.ID)
	now := time.Now().Unix()
	for _, id := range []int64{active.ID, other.ID, paused.ID, deleted.ID, migrating.ID} {
		started := now - 3600
		if id == active.ID {
			started = now - 40*86400
		}
		mustHistoryExec(t, s.DB, "INSERT INTO v3_website_incidents(site,kind,started,reason) VALUES($1,'outage',$2,'synthetic active incident')", id, started)
	}
	mustHistoryExec(t, s.DB, "INSERT INTO v3_website_incidents(site,kind,started,ended,reason) VALUES($1,'certificate',$2,$3,'synthetic closed incident')", active.ID, now-2*86400, now-86400)
	all, err := s.SiteIncidents(ctx, 0, 0, 20)
	if err != nil || len(all) != 6 {
		t.Fatal("legacy default changed", len(all), err)
	}
	current, err := s.FilteredSiteIncidents(ctx, SiteIncidentFilter{Current: true, Limit: 20})
	if err != nil || len(current) != 2 {
		t.Fatal(current, err)
	}
	for _, v := range current {
		if v.CanDelete || v.DeleteReason == "" {
			t.Fatal("active selectable", v)
		}
	}
	own, err := s.FilteredSiteIncidents(ctx, SiteIncidentFilter{Current: true, Limit: 20, Node: "node-a"})
	if err != nil || len(own) != 1 || own[0].Site != active.ID || own[0].SiteName != "active" || own[0].Started != now-40*86400 {
		t.Fatal("active incident was silently time-limited", own, err)
	}
	recent, err := s.FilteredSiteIncidents(ctx, SiteIncidentFilter{Limit: 20, Node: "node-a", Start: time.Unix(now-3*86400, 0), End: time.Unix(now+1, 0)})
	if err != nil || len(recent) != 4 {
		t.Fatal("history lost paused/deleted migration records", recent, err)
	}
	api := &API{Store: s}
	reader := historyAPISession(t, s, "reader", "viewer")
	call := func(target string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", target, nil)
		if authenticated {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: reader})
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	if w := call("/api/v3/incidents?current=true", false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	var first struct {
		Items []SiteIncident `json:"items"`
		Next  string         `json:"next_cursor"`
	}
	w := call("/api/v3/incidents?current=true&limit=1", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &first) != nil || len(first.Items) != 1 || first.Next == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	w = call("/api/v3/incidents?current=true&limit=1&cursor="+url.QueryEscape(first.Next), true)
	var second struct {
		Items []SiteIncident `json:"items"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &second) != nil || len(second.Items) != 1 || first.Items[0].ID == second.Items[0].ID {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, target := range []string{"/api/v3/incidents?node=bad/path", "/api/v3/incidents?current=unknown", "/api/v3/incidents?start=invalid", "/api/v3/incidents?start=2000-01-01T00:00:00Z"} {
		if w := call(target, true); w.Code != 400 {
			t.Fatal(target, w.Code, w.Body.String())
		}
	}
	if w := call("/api/v3/incidents?current=false&node=node-a", true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestAlertReadModelsNotificationStatesNeverExposePrivateResults(t *testing.T) {
	s := testStore(t)
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{"email":{"enabled":true},"feishu":{"enabled":false}}'`)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_notifications(id,node,event_id,channel,recipient,payload,result,done_at,attempts,lease_owner,lease_until,migration_pending) VALUES
 (1,'node-a','completed','email','completed@example.test','{"secret":"PRIVATE-payload"}','PRIVATE-result',clock_timestamp(),1,NULL,NULL,false),
 (2,'node-a','pending','email','pending@example.test','{}','',NULL,0,NULL,NULL,false),
 (3,'node-a','retry','email','retry@example.test','{}','PRIVATE-result',NULL,2,NULL,NULL,false),
 (4,'node-a','sending','email','sending@example.test','{}','',NULL,1,'synthetic',clock_timestamp()+interval '1 hour',false),
 (5,'node-a','older','email','order@example.test','{}','',NULL,0,NULL,NULL,false),
 (6,'node-a','waiting','email','order@example.test','{}','',NULL,0,NULL,NULL,false),
 (7,'node-a','migrating','email','migration@example.test','{}','',NULL,1,NULL,NULL,true),
 (8,'node-a','paused','feishu','','{}','PRIVATE-result',NULL,2,NULL,NULL,false),
 (9,'node-a','no-owner','email','no-owner@example.test','{}','',NULL,0,NULL,clock_timestamp()+interval '1 hour',false)`)
	expected := map[string]string{"completed": "completed", "pending": "pending", "retry": "retrying", "sending": "sending", "older": "pending", "waiting": "waiting", "migrating": "migration_pending", "no-owner": "pending"}
	now := time.Now()
	items, err := s.NotificationHistory(context.Background(), "email", "", "", now.Add(-time.Hour), now.Add(time.Hour), notificationCursor{}, 20)
	if err != nil || len(items) != len(expected) {
		t.Fatal(items, err)
	}
	for _, v := range items {
		if v.State != expected[v.Event] || (v.NextTry == nil) != (v.Completed != nil) {
			t.Fatal(v)
		}
		raw, _ := json.Marshal(v)
		if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "lease_owner") {
			t.Fatal(string(raw))
		}
	}
	paused, err := s.NotificationHistory(context.Background(), "feishu", "", "pending", now.Add(-time.Hour), now.Add(time.Hour), notificationCursor{}, 20)
	if err != nil || len(paused) != 1 || paused[0].State != "paused" || paused[0].CanDelete {
		t.Fatal(paused, err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{}'`)
	items, err = s.NotificationHistory(context.Background(), "email", "", "pending", now.Add(-time.Hour), now.Add(time.Hour), notificationCursor{}, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range items {
		if v.State != "paused" && v.State != "migration_pending" {
			t.Fatal("missing enabled setting was considered enabled", v)
		}
	}
}

func TestWebsiteStatusSummaryAndFilterUseDisplayedState(t *testing.T) {
	s := testStore(t)
	for _, name := range []string{"normal", "down", "pending", "unknown", "paused", "migrating"} {
		site := savedSite(t, s, name)
		mustHistoryExec(t, s.DB, "UPDATE v3_websites SET state=jsonb_build_object('status',$2::text),paused=$3,migration_pending=$4 WHERE id=$1", site.ID, name, name == "paused", name == "migrating")
	}
	// Stored pre-migration normal evidence must not count as currently normal.
	mustHistoryExec(t, s.DB, "UPDATE v3_websites SET state='{\"status\":\"normal\"}' WHERE migration_pending OR paused")
	raw, err := s.WebsiteSummary(context.Background())
	var summary map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &summary) != nil {
		t.Fatal(string(raw), err)
	}
	for _, key := range []string{"normal", "down", "pending", "unknown", "paused", "migration_pending"} {
		if string(summary[key]) != "1" {
			t.Fatal(key, string(raw))
		}
		items, err := s.Sites(context.Background(), SiteFilter{Status: key, Limit: 20})
		if err != nil || len(items) != 1 {
			t.Fatal(key, items, err)
		}
		if key == "normal" && items[0].Name != "normal" || key == "migration_pending" && items[0].Name != "migrating" {
			t.Fatal(key, items)
		}
	}
	if string(summary["total"]) != "6" {
		t.Fatal(string(raw))
	}
}
