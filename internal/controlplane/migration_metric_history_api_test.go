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

func migrationHistoryQuery(session, generation, node string, at int64) url.Values {
	return url.Values{"session": {session}, "generation": {generation}, "node": {node}, "metric": {"cpu_percent"}, "start": {time.Unix(at-300, 0).UTC().Format(time.RFC3339)}, "end": {time.Unix(at+120, 0).UTC().Format(time.RFC3339)}}
}

func TestMigrationMetricHistoryAPIRejectsExpressionsAndUnboundedQueries(t *testing.T) {
	base := migrationHistoryQuery(strings.Repeat("a", 64), strings.Repeat("b", 64), "node-1", time.Now().Unix())
	for _, tc := range []struct {
		name, method, role string
		mutate             func(url.Values)
		status             int
	}{
		{"viewer", "GET", "viewer", nil, 403},
		{"write", "POST", "admin", nil, 405},
		{"missing-start", "GET", "admin", func(q url.Values) { q.Del("start") }, 400},
		{"duplicate-node", "GET", "admin", func(q url.Values) { q.Add("node", "node-2") }, 400},
		{"expression", "GET", "admin", func(q url.Values) { q.Set("metric", "rate(node_cpu_seconds_total[5m])") }, 400},
		{"url", "GET", "admin", func(q url.Values) { q.Set("url", "https://private-target.invalid") }, 400},
		{"window", "GET", "admin", func(q url.Values) { q.Set("start", time.Now().Add(-32*24*time.Hour).UTC().Format(time.RFC3339)) }, 400},
		{"invalid-dimension", "GET", "admin", func(q url.Values) { q.Set("metric", "net_receive"); q.Set("dimension", "eth0\x00invalid") }, 400},
		{"unavailable", "GET", "admin", nil, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{}
			for k, v := range base {
				q[k] = append([]string{}, v...)
			}
			if tc.mutate != nil {
				tc.mutate(q)
			}
			w := httptest.NewRecorder()
			(&API{}).migrationMetricHistory(w, httptest.NewRequest(tc.method, "/api/v3/migration-history?"+q.Encode(), nil), identity{Role: tc.role})
			if w.Code != tc.status || strings.Contains(w.Body.String(), "private-target") {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestMigrationMetricHistoryAPIActualVerifiedGeneration(t *testing.T) {
	f := newMetricHistoryFixture(t)
	ctx := context.Background()
	p, err := f.s.PrepareMigrationMetricHistory(ctx, f.m, f.session.ID, f.session.Version, f.revision.ID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.s.RunMigrationMetricHistory(ctx, f.m, f.session.ID, f.session.Version, p.Generation)
	if err != nil {
		t.Fatal(err)
	}
	a := &API{Store: f.s, Metrics: f.m}
	q := migrationHistoryQuery(f.session.ID, r.Generation, f.node, f.at)
	w := httptest.NewRecorder()
	a.migrationMetricHistory(w, httptest.NewRequest(http.MethodGet, "/api/v3/migration-history?"+q.Encode(), nil), identity{Role: "admin"})
	var view MigrationMetricHistoryView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || len(view.Points) != 4 || view.Points[1].Value == nil || *view.Points[1].Value != 0 || view.Points[2].Value != nil || !view.ReadOnly || view.Interpolated {
		t.Fatal(w.Code, w.Body.String())
	}
	q.Set("generation", strings.Repeat("f", 64))
	w = httptest.NewRecorder()
	a.migrationMetricHistory(w, httptest.NewRequest(http.MethodGet, "/api/v3/migration-history?"+q.Encode(), nil), identity{Role: "admin"})
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
}
