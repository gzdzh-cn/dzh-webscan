package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestConfigurationEnvironmentChecksBothMetricLayersWithoutApplying(t *testing.T) {
	for _, fail := range []string{"", "query", "import"} {
		t.Run(fail, func(t *testing.T) {
			s, f := newSavedConfigurationStore(t)
			history := httptest.NewServer(http.HandlerFunc(environmentMetrics))
			defer history.Close()
			var queries, imports atomic.Int32
			raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				kind := "import"
				if r.Method == "GET" {
					kind = "query"
					queries.Add(1)
				} else {
					imports.Add(1)
				}
				if kind == fail {
					http.Error(w, "private-raw-error", 503)
					return
				}
				environmentMetrics(w, r)
			}))
			defer raw.Close()
			f.c.Metrics.WriteURL, f.c.Metrics.QueryURL, f.c.Metrics.RawURL = history.URL, history.URL, raw.URL
			localWrite(t, f.c.Database.DSNFile, environmentDSN(t, s))
			stage, r := savedRestoreFromDocument(t, s, f, f.document(t))
			result, err := s.commitConfigurationRestoreSaved(context.Background(), f.v, f.c, "admin", "dual-layer-preflight", stage.ID, r.Generation)
			_ = savedReceipt(t, result, err)
			before := settingsStateForTest(t, s)
			tree := localTree(t, f.f.root)
			view, err := s.inspectSavedConfigurationEnvironment(context.Background(), f.v, f.c, "admin", stage.ID)
			if err != nil || view.PreflightPassed != (fail == "") || len(view.Checks) != 5 || queries.Load() != 1 || imports.Load() != 1 {
				t.Fatal(view, err, queries.Load(), imports.Load())
			}
			checks := map[string]string{}
			for _, check := range view.Checks {
				checks[check.Component] = check.Status
			}
			if checks["metrics_query_api"] != "passed" || checks["metrics_write_api"] != "passed" || (checks["raw_metrics_query_api"] == "passed") != (fail != "query") || (checks["raw_metrics_write_api"] == "passed") != (fail != "import") {
				t.Fatal(checks)
			}
			encoded, _ := json.Marshal(view)
			if strings.Contains(string(encoded), raw.URL) || strings.Contains(string(encoded), "private-raw-error") {
				t.Fatal("diagnostic leaked private endpoint")
			}
			if !reflect.DeepEqual(before, settingsStateForTest(t, s)) || !reflect.DeepEqual(tree, localTree(t, f.f.root)) {
				t.Fatal("dual layer diagnostic applied runtime or modified material")
			}
		})
	}
}
