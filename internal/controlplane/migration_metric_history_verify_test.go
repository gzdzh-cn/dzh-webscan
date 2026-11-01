package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestMigrationMetricStoreActualVMCurrentBindingAndPostFinalEvidenceLoss(t *testing.T) {
	f := newMetricHistoryFixture(t)
	ctx := context.Background()
	p, err := f.s.PrepareMigrationMetricHistory(ctx, f.m, f.session.ID, f.session.Version, f.revision.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.RunMigrationMetricHistory(ctx, f.m, f.session.ID, f.session.Version, p.Generation); err != nil {
		t.Fatal(err)
	}
	verify := func(m *Metrics, alter func(*sql.Tx)) (bool, error) {
		tx, e := f.s.DB.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		if alter != nil {
			alter(tx)
		}
		return VerifyMigrationMetricStoreTx(ctx, tx, f.session.ID, f.revision.ID, m)
	}
	if ok, e := verify(f.m, nil); e != nil || !ok {
		t.Fatal("current actual VM evidence", ok, e)
	}
	for _, change := range []struct{ name, query string }{
		{"row-deleted", `DELETE FROM v3_migration_metric_rows WHERE run=$1`},
		{"run-unverified", `UPDATE v3_migration_metric_runs SET state='pending' WHERE id=$1`},
		{"run-target-tampered", `UPDATE v3_migration_metric_runs SET target_sha256=repeat('a',64) WHERE id=$1`},
		{"point-tampered", `UPDATE v3_migration_metric_rows SET point='{"time":1,"ok":true,"values":{"cpu_percent":999}}' WHERE run=$1`},
	} {
		t.Run(change.name, func(t *testing.T) {
			ok, e := verify(f.m, func(tx *sql.Tx) {
				if _, e := tx.Exec(change.query, p.Generation); e != nil {
					t.Fatal(e)
				}
			})
			if e == nil && ok {
				t.Fatal("changed final evidence accepted")
			}
		})
	}
	if ok, e := verify(f.m, func(tx *sql.Tx) {
		if _, e := tx.Exec(`DELETE FROM v3_migration_metric_rows WHERE run=$1`, p.Generation); e != nil {
			t.Fatal(e)
		}
		if _, e := tx.Exec(`DELETE FROM v3_migration_metric_runs WHERE id=$1`, p.Generation); e != nil {
			t.Fatal(e)
		}
	}); e == nil && ok {
		t.Fatal("deleted run accepted")
	}
	drift := *f.m
	drift.QueryURL += "/changed"
	if ok, e := verify(&drift, nil); e == nil && ok {
		t.Fatal("changed current runtime VM accepted")
	}
	offline := *f.m
	offline.HTTP = &http.Client{Transport: migrationPrometheusRoundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("isolated unreachable VM") })}
	if ok, e := verify(&offline, nil); e == nil && ok {
		t.Fatal("unreachable actual VM accepted")
	}
	// Remove only this test's synthetic CPU series from the actual isolated VM;
	// status/network remain, so checking destination reachability or node names
	// without comparing original points cannot satisfy the assertion.
	selector := migrationMetricSelector(map[string]string{"source": "legacy-v2", "generation": p.Generation, "node_id": f.node, "__name__": "webscan_legacy_value", "metric": "cpu_percent"})
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(f.m.QueryURL, "/")+"/api/v1/admin/tsdb/delete_series?"+url.Values{"match[]": {selector}}.Encode(), nil)
	if e != nil {
		t.Fatal(e)
	}
	response, e := f.m.HTTP.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
		t.Fatal("isolated VM deletion unavailable", response.StatusCode)
	}
	if ok, e := verify(f.m, nil); e == nil && ok {
		t.Fatal("VM points deleted after final receipt accepted")
	}
}
