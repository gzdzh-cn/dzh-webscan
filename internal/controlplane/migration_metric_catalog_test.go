package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestMigrationMetricCatalogRejectsPermissionDuplicateAndArbitraryQueries(t *testing.T) {
	base := url.Values{"session": {strings.Repeat("a", 64)}, "generation": {strings.Repeat("b", 64)}}
	for _, tc := range []struct {
		name, method, role string
		change             func(url.Values)
		status             int
	}{
		{"viewer", "GET", "viewer", nil, 403}, {"write", "POST", "admin", nil, 405},
		{"missing-session", "GET", "admin", func(q url.Values) { q.Del("session") }, 400},
		{"duplicate", "GET", "admin", func(q url.Values) { q.Add("node", "n1"); q.Add("node", "n2") }, 400},
		{"unknown-expression", "GET", "admin", func(q url.Values) { q.Set("query", "up") }, 400},
		{"unknown-target", "GET", "admin", func(q url.Values) { q.Set("url", "http://private.invalid") }, 400},
		{"filter-limit", "GET", "admin", func(q url.Values) { q.Set("q", strings.Repeat("x", 129)) }, 400},
		{"filter-nul", "GET", "admin", func(q url.Values) { q.Set("q", "\x00") }, 400},
		{"bad-node", "GET", "admin", func(q url.Values) { q.Set("node", "node|.*") }, 400},
		{"unavailable", "GET", "admin", nil, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{}
			for k, v := range base {
				q[k] = append([]string{}, v...)
			}
			if tc.change != nil {
				tc.change(q)
			}
			w := httptest.NewRecorder()
			(&API{}).migrationMetricCatalog(w, httptest.NewRequest(tc.method, "/api/v3/migration-history/catalog?"+q.Encode(), nil), identity{Role: tc.role})
			if w.Code != tc.status || strings.Contains(w.Body.String(), "private.invalid") {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v3/migration-history/catalog?"+base.Encode(), nil)
	r.URL.RawQuery += "&q=%zz"
	(&API{}).migrationMetricCatalog(w, r, identity{Role: "admin"})
	if w.Code != 400 {
		t.Fatal("malformed percent accepted", w.Code)
	}
}

func TestMigrationMetricCatalogActualVerifiedVMAndReadOnlyDrift(t *testing.T) {
	f := newMetricHistoryFixture(t)
	ctx := context.Background()
	p, err := f.s.PrepareMigrationMetricHistory(ctx, f.m, f.session.ID, f.session.Version, f.revision.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.MigrationMetricCatalog(ctx, f.m, f.session.ID, p.Generation, "", ""); !errors.Is(err, ErrMigrationMetricHistory) {
		t.Fatal("pending catalog", err)
	}
	r, err := f.s.RunMigrationMetricHistory(ctx, f.m, f.session.ID, f.session.Version, p.Generation)
	if err != nil {
		t.Fatal(err)
	}
	before := shadowBusinessSnapshot(t, f.s)
	a := &API{Store: f.s, Metrics: f.m}
	q := url.Values{"session": {f.session.ID}, "generation": {r.Generation}}
	w := httptest.NewRecorder()
	a.migrationMetricCatalog(w, httptest.NewRequest("GET", "/api/v3/migration-history/catalog?"+q.Encode(), nil), identity{Role: "admin"})
	var catalog MigrationMetricCatalog
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &catalog) != nil || !catalog.ReadOnly || catalog.Node != f.node || len(catalog.Nodes) != 1 || catalog.Nodes[0].FirstSample != f.at-300 || catalog.Nodes[0].LastSample != f.at+90 || !reflect.DeepEqual(catalog.Series, []MigrationMetricCatalogSeries{{Metric: "cpu_percent"}, {Metric: "net_receive", Dimension: "eth0"}}) {
		t.Fatal(w.Code, w.Body.String())
	}
	if !reflect.DeepEqual(before, shadowBusinessSnapshot(t, f.s)) {
		t.Fatal("catalog wrote business state")
	}
	empty, err := f.s.MigrationMetricCatalog(ctx, f.m, f.session.ID, r.Generation, "", "%")
	if err != nil || len(empty.Nodes) != 0 || empty.Node != "" || len(empty.Series) != 0 {
		t.Fatal("filter treated as wildcard", empty, err)
	}
	selected, err := f.s.MigrationMetricCatalog(ctx, f.m, f.session.ID, r.Generation, f.node, "literal-not-found")
	if err != nil || selected.Node != f.node || len(selected.Nodes) != 0 || len(selected.Series) != 2 {
		t.Fatal("saved node not independently bound", selected, err)
	}
	if _, err = f.s.MigrationMetricCatalog(ctx, f.m, f.session.ID, r.Generation, "not-in-this-generation", ""); !errors.Is(err, ErrMigrationMetricHistory) {
		t.Fatal("foreign node", err)
	}
	drift := *f.m
	drift.QueryURL += "/changed"
	if _, err = f.s.MigrationMetricCatalog(ctx, &drift, f.session.ID, r.Generation, "", ""); !errors.Is(err, ErrMigrationMetricHistory) {
		t.Fatal("VM drift", err)
	}
	offline := *f.m
	offline.HTTP = &http.Client{Transport: migrationPrometheusRoundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("isolated target unavailable") })}
	if _, err = f.s.MigrationMetricCatalog(ctx, &offline, f.session.ID, r.Generation, "", ""); !errors.Is(err, ErrMigrationMetricHistory) {
		t.Fatal("offline target", err)
	}
	corrupt := *f.m
	corrupt.HTTP = &http.Client{Transport: migrationPrometheusRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}}, nil
	})}
	if _, err = f.s.MigrationMetricCatalog(ctx, &corrupt, f.session.ID, r.Generation, "", ""); !errors.Is(err, ErrMigrationMetricHistory) {
		t.Fatal("VM missing data", err)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_migration_metric_rows SET point='{"time":1,"ok":true,"values":{"cpu_percent":999}}' WHERE run=$1`, r.Generation)
	if _, err = f.s.MigrationMetricCatalog(ctx, f.m, f.session.ID, r.Generation, "", ""); !errors.Is(err, ErrMigrationMetricHistory) {
		t.Fatal("corrupt point receipt", err)
	}
}
