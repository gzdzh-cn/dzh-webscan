package controlplane

import (
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
