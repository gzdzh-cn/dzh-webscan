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

func TestNotificationHistoryMetadataProtectionAndPagination(t *testing.T) {
	s := testStore(t)
	api := &API{Store: s}
	value := historyAPISession(t, s, "reader", "viewer")
	now := time.Now()
	mustHistoryExec(t, s.DB, `INSERT INTO v3_notifications(id,node,event_id,channel,recipient,payload,result,created_at,done_at) VALUES(9007199254740993,'node-a','a','email','a@example.test','{"password":"PRIVATE"}','PRIVATE provider response',$1,$1),(9007199254740994,'node-a','b','email','b@example.test','{}','',$1,$1),(9007199254740995,'node-a','c','email','c@example.test','{}','',$1,NULL),(9007199254740996,'node-a','d','feishu','','{}','',$1,$1)`, now.Add(-20*24*time.Hour))
	call := func(query, token string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v3/notifications?"+query, nil)
		if token != "" {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: token})
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	if w := call("channel=email", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	query := url.Values{"channel": {"email"}, "start": {now.Add(-25 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)}, "end": {now.UTC().Format(time.RFC3339Nano)}, "limit": {"1"}}
	next := ""
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		if next != "" {
			query.Set("cursor", next)
		}
		w := call(query.Encode(), value)
		var p struct {
			Items []NotificationRecord `json:"items"`
			Next  string               `json:"next_cursor"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || len(p.Items) != 1 || strings.Contains(w.Body.String(), "PRIVATE") || strings.Contains(w.Body.String(), "payload") {
			t.Fatal(w.Code, w.Body.String())
		}
		v := p.Items[0]
		if seen[v.ID] || v.RecordKey != "notification:"+v.ID || v.CanDelete != (v.Completed != nil) || !v.CanDelete && v.DeleteReason == "" {
			t.Fatal("identity/protection lost", v)
		}
		seen[v.ID] = true
		next = p.Next
	}
	if len(seen) != 3 || !seen["9007199254740993"] {
		t.Fatal("large notification IDs rounded", seen)
	}
	for _, q := range []string{"", "channel=bad", "channel=email&state=bad", "channel=email&cursor=bad", "channel=email&limit=201", "channel=email&node=%00"} {
		if w := call(q, value); w.Code != 400 {
			t.Fatal(q, w.Code, w.Body.String())
		}
	}
}

func TestNotificationHistoryFiltersUseVerifiedProjectionBeforeLimit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	projectedNotificationFixture(t, s, 1, "event", `{"operation":"modify","path":"/srv/Needle%_literal.php","message":"PRIVATE"}`)
	projectedNotificationFixture(t, s, 2, "website", `{"notice_kind":"outage","site_ids":[1],"message":"PRIVATE"}`)
	projectedNotificationFixture(t, s, 3, "test", `{}`)
	projectedNotificationFixture(t, s, 4, "event", `{"operation":"create","path":"/srv/stale.php"}`)
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{"email":{"enabled":true}}';UPDATE v3_notifications SET recipient='b@example.test' WHERE id=2;UPDATE v3_notifications SET payload='{"operation":"create","path":"PRIVATE"}' WHERE id=4`)
	mustHistoryExec(t, s.DB, `UPDATE v3_notifications SET created_at=$1`, now.Add(-time.Minute))
	mustHistoryExec(t, s.DB, `UPDATE v3_notifications SET done_at=$1 WHERE id=1`, now.Add(-time.Minute))
	base := NotificationFilter{Channel: "email", Start: now.Add(-time.Hour), End: now, Limit: 1}
	for _, tc := range []struct {
		name string
		set  func(*NotificationFilter)
		want string
	}{
		{"source", func(f *NotificationFilter) { f.Source = "website" }, "2"},
		{"recipient exact", func(f *NotificationFilter) { f.Recipient = "b@example.test" }, "2"},
		{"public literal search", func(f *NotificationFilter) { f.Q = "needle%_literal" }, "1"},
		{"legacy completed state", func(f *NotificationFilter) { f.State = "completed" }, "1"},
		{"delivery completed", func(f *NotificationFilter) { f.DeliveryState = "completed" }, "1"},
		{"unknown stale source", func(f *NotificationFilter) { f.Source = "unknown" }, "4"},
	} {
		f := base
		tc.set(&f)
		items, err := s.NotificationHistoryFiltered(ctx, f)
		if err != nil || len(items) != 1 || items[0].ID != tc.want {
			t.Fatal(tc.name, items, err)
		}
	}
	for _, q := range []string{"PRIVATE", "stale.php"} {
		f := base
		f.Q = q
		items, err := s.NotificationHistoryFiltered(ctx, f)
		if err != nil || len(items) != 0 {
			t.Fatal("unverified/raw content searchable", q, items, err)
		}
	}
	f := base
	f.Recipient = "example.test"
	if items, err := s.NotificationHistoryFiltered(ctx, f); err != nil || len(items) != 0 {
		t.Fatal("recipient substring unexpectedly matched", items, err)
	}
	for _, alter := range []func(*NotificationFilter){
		func(f *NotificationFilter) { f.Q = strings.Repeat("a", 201) },
		func(f *NotificationFilter) { f.Q = "\x00" },
		func(f *NotificationFilter) { f.Recipient = strings.Repeat("a", 255) },
		func(f *NotificationFilter) { f.Source = "spoofed" },
		func(f *NotificationFilter) { f.DeliveryState = "failed" },
		func(f *NotificationFilter) { f.Start = now.Add(-32 * 24 * time.Hour) },
		func(f *NotificationFilter) { f.Limit = 201 },
		func(f *NotificationFilter) { f.Before = notificationCursor{Time: now, ID: "01"} },
	} {
		f := base
		alter(&f)
		if _, err := s.NotificationHistoryFiltered(ctx, f); err != ErrHistoryInput {
			t.Fatal("invalid filter accepted", f, err)
		}
	}
}
