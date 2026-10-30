package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"webscan/internal/website"
)

func savedSite(t *testing.T, s *Store, label string) website.Site {
	t.Helper()
	data, err := s.SaveSite(context.Background(), "admin", "create-"+label, SiteInput{Name: label, URL: "https://" + label + ".example.test", Slow: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		ID int64 `json:"id"`
	}
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	site, err := s.Site(context.Background(), result.ID)
	if err != nil {
		t.Fatal(err)
	}
	return site
}
func claimSite(t *testing.T, s *Store, id int64, owner string) WebsiteJob {
	t.Helper()
	if _, err := s.DB.Exec("UPDATE v3_websites SET next_check=clock_timestamp() WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("UPDATE v3_websites SET next_check=clock_timestamp()+interval '1 day' WHERE id<>$1", id); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.ClaimSites(context.Background(), owner, 1)
	if err != nil || len(jobs) != 1 || jobs[0].Site.ID != id {
		t.Fatal(jobs, err)
	}
	return jobs[0]
}
func tableCount(t *testing.T, s *Store, table string) int {
	t.Helper()
	if !identifier.MatchString(table) {
		t.Fatal("invalid fixture table")
	}
	var n int
	if err := s.DB.QueryRow("SELECT count(*) FROM " + quotePG(table)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWebsitePostgresIdempotencyPagingAndSoftDelete(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	input := SiteInput{Name: "中文网站", URL: "https://www.example.test"}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.SaveSite(ctx, "admin", "same-create", input, 0); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if tableCount(t, s, "v3_websites") != 1 || tableCount(t, s, "v3_audit") != 1 {
		t.Fatal("duplicate mutation")
	}
	if _, err := s.SaveSite(ctx, "admin", "same-create", SiteInput{Name: "other", URL: "https://other.example.test"}, 0); !errors.Is(err, ErrRequestConflict) {
		t.Fatal(err)
	}
	if _, err := s.SaveSite(ctx, "admin", "same-url", input, 0); !errors.Is(err, ErrSiteURLExists) {
		t.Fatal(err)
	}
	a := savedSite(t, s, "a")
	b := savedSite(t, s, "b")
	items, err := s.Sites(ctx, SiteFilter{Limit: 2})
	if err != nil || len(items) != 2 {
		t.Fatal(items, err)
	}
	more, err := s.Sites(ctx, SiteFilter{After: items[1].ID, Limit: 2})
	if err != nil || len(more) != 1 || more[0].ID != b.ID {
		t.Fatal(more, err)
	}
	items, err = s.Sites(ctx, SiteFilter{Keyword: "%", Limit: 20})
	if err != nil || len(items) != 0 {
		t.Fatal("wildcard escaped", items, err)
	}
	if _, err = s.DeleteSites(ctx, "admin", "conflict-delete", []SiteVersion{{a.ID, a.Version}, {b.ID, b.Version + 1}}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err = s.Site(ctx, a.ID); err != nil {
		t.Fatal("partial deletion", err)
	}
	job := claimSite(t, s, a.ID, "one")
	if _, err = s.DeleteSites(ctx, "admin", "delete-a", []SiteVersion{{a.ID, a.Version}}); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplySiteResult(ctx, job, website.Result{Time: time.Now().Unix(), OK: true}); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale check wrote after soft delete", err)
	}
	if tableCount(t, s, "v3_websites") != 3 {
		t.Fatal("hard deleted website")
	}
	if _, err = s.SaveSite(ctx, "admin", "replace-deleted", SiteInput{Name: "new a", URL: a.URL}, 0); err != nil {
		t.Fatal("cannot restore deleted URL", err)
	}
}

func TestWebsitePostgresOutageRecoveryAndAtomicOutbox(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	site := savedSite(t, s, "outage")
	if _, err := s.DB.Exec(`UPDATE v3_settings SET payload='{"feishu":{"enabled":true,"notifications":{"health_failures":true,"health_recoveries":true}},"email":{"enabled":true,"recipients":["test@example.test"],"notifications":{"health_failures":true,"health_recoveries":true}}}'`); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Unix() - 60
	for i := range 3 {
		job := claimSite(t, s, site.ID, "one")
		if err := s.ApplySiteResult(ctx, job, website.Result{Time: stamp + int64(i), Reason: "连接失败"}); err != nil {
			t.Fatal(err)
		}
		if err := s.ApplySiteResult(ctx, job, website.Result{Time: stamp + int64(i), Reason: "重复结果"}); !errors.Is(err, ErrLeaseLost) {
			t.Fatal("repeated apply", err)
		}
	}
	state, err := s.Site(ctx, site.ID)
	if err != nil || state.State.Status != "down" || state.State.Failures != 3 {
		t.Fatal(state, err)
	}
	if tableCount(t, s, "v3_website_incidents") != 1 || tableCount(t, s, "v3_website_outbox") != 1 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("outage not persisted with both channels")
	}
	// A fresh Store shares persistent streaks and pending notices.
	other := &Store{DB: s.DB}
	for i := range 2 {
		job := claimSite(t, other, site.ID, "two")
		if err = other.ApplySiteResult(ctx, job, website.Result{Time: stamp + 3 + int64(i), OK: true, HTTP: 200}); err != nil {
			t.Fatal(err)
		}
	}
	state, err = s.Site(ctx, site.ID)
	if err != nil || state.State.Status != "normal" || state.State.Incident != 0 || state.State.Checks != 5 {
		t.Fatal(state, err)
	}
	flushWebsiteFixture(t, s)
	if tableCount(t, s, "v3_notifications") != 4 {
		t.Fatal("recovery missing")
	}
	incidents, err := s.SiteIncidents(ctx, site.ID, 0, 20)
	if err != nil || len(incidents) != 1 || incidents[0].Ended == nil || *incidents[0].Ended != stamp+4 {
		t.Fatal(incidents, err)
	}
	first, err := s.claimNotification(ctx, "feishu", "sender")
	if err != nil || first == nil {
		t.Fatal(first, err)
	}
	var payload map[string]any
	if err = json.Unmarshal(first.Payload, &payload); err != nil || payload["notice_kind"] != "outage" {
		t.Fatal(payload, err)
	}
	blocked, err := s.claimNotification(ctx, "feishu", "sender-two")
	if err != nil || blocked != nil {
		t.Fatal("recovery overtook active outage", blocked, err)
	}
	if err = s.finishNotification(ctx, first, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("UPDATE v3_notification_rates SET history='[]'"); err != nil {
		t.Fatal(err)
	}
	next, err := s.claimNotification(ctx, "feishu", "sender-two")
	if err != nil || next == nil {
		t.Fatal(next, err)
	}
	if err = json.Unmarshal(next.Payload, &payload); err != nil || payload["notice_kind"] != "recovery" {
		t.Fatal(payload, err)
	}
}

func TestWebsiteResultNotificationFailureRollsBackState(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	site := savedSite(t, s, "rollback")
	if _, err := s.DB.Exec(`UPDATE v3_settings SET payload='{"feishu":{"enabled":true,"notifications":{"health_failures":true}}}'`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		job := claimSite(t, s, site.ID, "one")
		if err := s.ApplySiteResult(ctx, job, website.Result{Time: time.Now().Unix(), Reason: "失败"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`CREATE FUNCTION fail_website_notice() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'fixture';END$$;CREATE TRIGGER fail_website_notice BEFORE INSERT ON v3_website_outbox FOR EACH ROW EXECUTE FUNCTION fail_website_notice()`); err != nil {
		t.Fatal(err)
	}
	job := claimSite(t, s, site.ID, "one")
	if err := s.ApplySiteResult(ctx, job, website.Result{Time: time.Now().Unix(), Reason: "失败"}); err == nil {
		t.Fatal("outbox failure accepted")
	}
	state, err := s.Site(ctx, site.ID)
	if err != nil || state.State.Failures != 2 || state.State.Incident != 0 || tableCount(t, s, "v3_website_incidents") != 0 {
		t.Fatal("partial commit", state, err)
	}
	if _, err = s.DB.Exec("DROP TRIGGER fail_website_notice ON v3_website_outbox"); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplySiteResult(ctx, job, website.Result{Time: time.Now().Unix(), Reason: "失败"}); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_website_incidents") != 1 || tableCount(t, s, "v3_website_outbox") != 1 {
		t.Fatal("retry lost transition")
	}
}

func TestWebsiteClaimsTakeoverAndConfigurationFencing(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for i := range 12 {
		savedSite(t, s, fmt.Sprintf("claim-%02d", i))
	}
	results := make(chan []WebsiteJob, 2)
	errs := make(chan error, 2)
	for _, owner := range []string{"one", "two"} {
		go func(owner string) { jobs, err := s.ClaimSites(ctx, owner, 12); results <- jobs; errs <- err }(owner)
	}
	seen := map[int64]WebsiteJob{}
	for range 2 {
		for _, job := range <-results {
			if _, ok := seen[job.Site.ID]; ok {
				t.Fatal("duplicate claim")
			}
			seen[job.Site.ID] = job
		}
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 12 {
		t.Fatal(len(seen))
	}
	if _, err := s.DB.Exec("UPDATE v3_websites SET lease_until=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	newJobs, err := s.ClaimSites(ctx, "three", 12)
	if err != nil || len(newJobs) != 12 {
		t.Fatal(newJobs, err)
	}
	for _, job := range newJobs {
		old := seen[job.Site.ID]
		if job.Epoch <= old.Epoch {
			t.Fatal("epoch not advanced")
		}
		if err = s.ApplySiteResult(ctx, old, website.Result{Time: time.Now().Unix(), OK: true}); !errors.Is(err, ErrLeaseLost) {
			t.Fatal("old worker wrote", err)
		}
	}
	job := newJobs[0]
	if _, err = s.SaveSite(ctx, "admin", "pause-site", SiteInput{ID: job.Site.ID, Name: job.Site.Name, URL: job.Site.URL, Paused: true}, job.Site.Version); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplySiteResult(ctx, job, website.Result{Time: time.Now().Unix(), OK: true}); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("paused task wrote", err)
	}
	if _, err = s.DB.Exec(`UPDATE v3_settings SET payload='{"website_monitor":{"enabled":false}}'`); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.ClaimSites(ctx, "disabled", 12)
	if err != nil || len(jobs) != 0 {
		t.Fatal("disabled scheduler claimed jobs", jobs, err)
	}
}

type countingSiteChecker struct{ calls atomic.Int64 }

func (c *countingSiteChecker) Check(ctx context.Context, site website.Site, timeout time.Duration) website.Result {
	c.calls.Add(1)
	return website.Result{Time: time.Now().Unix(), OK: true, HTTP: 200}
}
func TestWebsiteRunnerUsesPersistentQueueAndStops(t *testing.T) {
	s := testStore(t)
	site := savedSite(t, s, "runner")
	checker := &countingSiteChecker{}
	runner := &WebsiteRunner{Store: s, Instance: "runner-one", Concurrency: 2, Checker: checker}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, err := s.Site(context.Background(), site.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.State.Checks == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runner did not stop")
	}
	current, err := s.Site(context.Background(), site.ID)
	if err != nil || current.State.Checks != 1 || checker.calls.Load() != 1 {
		t.Fatal(current, checker.calls.Load(), err)
	}
}

func TestWebsiteConcurrencyLimitIsSharedAcrossWorkers(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	savedSite(t, s, "limit-one")
	savedSite(t, s, "limit-two")
	if _, err := s.DB.Exec(`UPDATE v3_settings SET payload='{"website_monitor":{"max_concurrent":1}}'`); err != nil {
		t.Fatal(err)
	}
	one, err := s.ClaimSites(ctx, "one", 20)
	if err != nil || len(one) != 1 {
		t.Fatal(one, err)
	}
	two, err := s.ClaimSites(ctx, "two", 20)
	if err != nil || len(two) != 0 {
		t.Fatal("global concurrency exceeded", two, err)
	}
	if err = s.ApplySiteResult(ctx, one[0], website.Result{Time: time.Now().Unix(), OK: true}); err != nil {
		t.Fatal(err)
	}
	two, err = s.ClaimSites(ctx, "two", 20)
	if err != nil || len(two) != 1 || two[0].Site.ID == one[0].Site.ID {
		t.Fatal(two, err)
	}
}

func TestWebsiteAPIValidationCSRFAndReadOnlyRole(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.Provision(ctx, "admin", "test-password-123"); err != nil {
		t.Fatal(err)
	}
	api := &API{Store: s}
	api.Config.Central.PublicURL = "https://monitor.example.test"
	w := httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest("POST", "/api/v3/login", strings.NewReader(`{"username":"admin","password":"test-password-123"}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	var login map[string]string
	json.Unmarshal(w.Body.Bytes(), &login)
	request := func(method, path, body, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", "api-save")
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	body := `{"site":{"id":0,"name":"API 网站","url":"https://api.example.test"},"expected_version":0}`
	if w = request("POST", "/api/v3/websites", body, ""); w.Code != 403 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request("POST", "/api/v3/websites", body, login["csrf"]); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request("GET", "/api/v3/websites?limit=20", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "API 网站") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request("GET", "/api/v3/websites?status=invalid", "", ""); w.Code != 400 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request("GET", "/api/v3/websites/overview", "", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err := s.DB.Exec("UPDATE v3_accounts SET role='viewer'"); err != nil {
		t.Fatal(err)
	}
	if w = request("POST", "/api/v3/websites", body, login["csrf"]); w.Code != 403 {
		t.Fatal("viewer changed site", w.Code)
	}
	if w = request(http.MethodGet, "/api/v3/incidents", "", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}
