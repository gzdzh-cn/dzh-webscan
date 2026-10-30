package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func historyAPISession(t *testing.T, s *Store, user, role string) string {
	t.Helper()
	if err := s.Provision(context.Background(), user, "isolated-history-password"); err != nil {
		t.Fatal(err)
	}
	value := token()
	mustHistoryExec(t, s.DB, "UPDATE v3_accounts SET role=$2 WHERE username=$1", user, role)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,$2,1,'history-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(value)), user)
	return value
}

func TestManualHistoryAPIAuthenticationOwnerCSRFAndPagination(t *testing.T) {
	s := testStore(t)
	s.ExportDirectory = privateTestDir(t)
	api := &API{Store: s}
	admin := historyAPISession(t, s, "admin", "admin")
	other := historyAPISession(t, s, "other", "operator")
	viewer := historyAPISession(t, s, "viewer", "viewer")
	call := func(method, path, body, value, csrf, key string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "/api/v3/retention/"+path, strings.NewReader(body))
		if value != "" {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: value})
		}
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	for _, p := range []string{"preview", "cleanup", "export", "jobs?kind=manual", "jobs/" + strings.Repeat("a", 64), "jobs/" + strings.Repeat("a", 64) + "/download"} {
		method := "POST"
		if strings.HasPrefix(p, "jobs") {
			method = "GET"
		}
		if w := call(method, p, "{}", "", "", ""); w.Code != 401 {
			t.Fatal(p, w.Code)
		}
	}
	oldEvent(t, s, "http-event", false, 40, nil)
	body := `{"categories":["events"]}`
	if w := call("POST", "preview", `{"categories":["events"],"records":[]}`, admin, "history-csrf", ""); w.Code != 400 {
		t.Fatal("empty selection expanded into a range", w.Code)
	}
	for _, v := range []struct {
		value, csrf string
		code        int
	}{{admin, "", 403}, {viewer, "history-csrf", 403}} {
		if w := call("POST", "preview", body, v.value, v.csrf, ""); w.Code != v.code {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w := call("POST", "preview", body, admin, "history-csrf", "")
	var p HistoryPreview
	if json.Unmarshal(w.Body.Bytes(), &p) != nil || w.Code != 200 || p.Eligible != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	submit := `{"token":"` + p.Token + `"}`
	if w = call("POST", "export", submit, other, "history-csrf", "foreign"); w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = call("POST", "cleanup", submit, admin, "history-csrf", "unconfirmed"); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w = call("POST", "export", submit, admin, "history-csrf", ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	w = call("POST", "export", submit, admin, "history-csrf", "http-export")
	var j HistoryJob
	if json.Unmarshal(w.Body.Bytes(), &j) != nil || w.Code != 200 || j.ID == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	w = call("POST", "export", submit, admin, "history-csrf", "http-export")
	var repeat HistoryJob
	if json.Unmarshal(w.Body.Bytes(), &repeat) != nil || w.Code != 200 || repeat.ID != j.ID {
		t.Fatal("not idempotent", w.Code)
	}
	for _, suffix := range []string{"", "/download"} {
		if w = call("GET", "jobs/"+j.ID+suffix, "", other, "", ""); w.Code != 404 {
			t.Fatal("foreign job exposed", w.Code)
		}
	}
	if w = call("GET", "jobs/"+j.ID+"/download", "", admin, "", ""); w.Code != 409 {
		t.Fatal("downloaded unfinished export", w.Code)
	}
	j = finishHistory(t, s, historyLease(t, s), j)
	if w = call("GET", "jobs/"+j.ID+"/download", "", admin, "", ""); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "http-event") || w.Header().Get("Content-Length") != strconv.Itoa(w.Body.Len()) {
		t.Fatal(w.Code, w.Body.String())
	}
	var completed int
	if err := s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE username='admin' AND kind='retention-download-result' AND result->>'completed'='true'`).Scan(&completed); err != nil || completed != 1 {
		t.Fatal("download not audited", completed, err)
	}
	historyJob(t, s, historyPreview(t, s, HistoryScope{Categories: []string{"events"}}), "cleanup", false)
	w = call("GET", "jobs?kind=manual&limit=1", "", admin, "", "")
	var page struct {
		Items []HistoryJob `json:"items"`
		Next  string       `json:"next_cursor"`
	}
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || w.Code != 200 || len(page.Items) != 1 || page.Next == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	first := page.Items[0].ID
	w = call("GET", "jobs?kind=manual&limit=1&cursor="+page.Next, "", admin, "", "")
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || w.Code != 200 || len(page.Items) != 1 || page.Items[0].ID == first {
		t.Fatal("pagination", w.Code, w.Body.String())
	}
	if w = call("GET", "jobs?kind=manual", "", other, "", ""); w.Code != 200 || strings.Contains(w.Body.String(), j.ID) {
		t.Fatal("foreign list exposed", w.Code)
	}
	for _, path := range []string{"jobs?kind=manual&limit=201", "jobs?kind=manual&cursor=bad"} {
		if w = call("GET", path, "", admin, "", ""); w.Code != 400 {
			t.Fatal(path, w.Code)
		}
	}
	mustHistoryExec(t, s.DB, "UPDATE v3_history_jobs SET export_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", j.ID)
	if w = call("GET", "jobs/"+j.ID+"/download", "", admin, "", ""); w.Code != 409 {
		t.Fatal("expired export downloaded", w.Code)
	}
	s.DB.Close()
	if w = call("GET", "jobs?kind=manual", "", admin, "", ""); w.Code != 503 {
		t.Fatal("DB failure treated as logout", w.Code)
	}
}

func TestManualHistoryHTTPDownloadDetectsLaterMissingPart(t *testing.T) {
	s := testStore(t)
	s.ExportDirectory = privateTestDir(t)
	admin := historyAPISession(t, s, "admin", "admin")
	mustHistoryExec(t, s.DB, `INSERT INTO v3_event_keys SELECT 'node-a',g::text,'fixture',clock_timestamp()-interval '40 days' FROM generate_series(1,21) g;INSERT INTO v3_events SELECT node,id,received_at,'write',false,'{}' FROM v3_event_keys`)
	j := finishHistory(t, s, historyLease(t, s), historyJob(t, s, historyPreview(t, s, HistoryScope{Categories: []string{"events"}}), "export", false))
	var last string
	if err := s.DB.QueryRow("SELECT id FROM v3_history_export_parts WHERE job=$1 AND ready ORDER BY ordinal DESC LIMIT 1", j.ID).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.ExportDirectory, last+".jsonl")); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(&API{Store: s})
	defer server.Close()
	r, err := http.NewRequest("GET", server.URL+"/api/v3/retention/jobs/"+j.ID+"/download", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: admin})
	res, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !errors.Is(err, io.ErrUnexpectedEOF) || len(raw) == 0 || int64(len(raw)) >= j.ExportBytes {
		t.Fatal("truncated export appeared complete", res.StatusCode, len(raw), err)
	}
	var completed bool
	if err = s.DB.QueryRow(`SELECT (result->>'completed')::boolean FROM v3_audit WHERE kind='retention-download-result' AND resource=$1 ORDER BY id DESC LIMIT 1`, j.ID).Scan(&completed); err != nil || completed {
		t.Fatal("incomplete download audit", completed, err)
	}
}

func TestManualHistoryPreviewExpiryQuotasAndConcurrentLimit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p := historyPreview(t, s, HistoryScope{Categories: []string{"events"}})
	mustHistoryExec(t, s.DB, "UPDATE v3_history_previews SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", digest([]byte(p.Token)))
	if _, err := s.SubmitHistory(ctx, "admin", "expired", p.Token, "export", false, false); !errors.Is(err, ErrHistoryPreview) {
		t.Fatal("expired token accepted", err)
	}
	for i := 0; i < 5; i++ {
		historyJob(t, s, historyPreview(t, s, HistoryScope{Categories: []string{"events"}}), "cleanup", false)
	}
	p = historyPreview(t, s, HistoryScope{Categories: []string{"events"}})
	if _, err := s.SubmitHistory(ctx, "admin", "queue-limit", p.Token, "export", false, false); !errors.Is(err, ErrHistoryInput) {
		t.Fatal("queue quota ignored", err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_history_previews(id,username,settings_version,scope,cutoff) SELECT md5(g::text),'quota',1,'{}',clock_timestamp()-interval '30 days' FROM generate_series(1,99)g`)
	start := make(chan struct{})
	results := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() {
			<-start
			_, err := s.PreviewHistory(ctx, "quota", HistoryScope{Categories: []string{"events"}})
			results <- err
		}()
	}
	close(start)
	for i := 0; i < 4; i++ {
		<-results
	}
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM v3_history_previews WHERE username='quota'").Scan(&count); err != nil || count != 100 {
		t.Fatal("concurrent preview quota exceeded", count, err)
	}
	// Expired previews are reclaimed, but unexpired ones remain usable.
	l := historyLease(t, s)
	if err := s.HistoryGC(ctx, l); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := s.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM v3_history_previews WHERE id=$1)", digest([]byte(p.Token))).Scan(&exists); err != nil || !exists {
		t.Fatal("active preview reclaimed", err)
	}
}
