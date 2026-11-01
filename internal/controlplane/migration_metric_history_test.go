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
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"webscan/internal/persist"
	"webscan/internal/telemetry"
)

type metricHistoryFixture struct {
	s        *Store
	session  MigrationSession
	revision MigrationRevisionReport
	m        *Metrics
	at       int64
	node     string
	snapshot string
}

func newMetricHistoryFixture(t *testing.T) metricHistoryFixture {
	t.Helper()
	address := os.Getenv("WEBSCAN_V3_TEST_VM")
	if address == "" {
		t.Skip("set WEBSCAN_V3_TEST_VM for actual isolated VictoriaMetrics history replay")
	}
	f := metricHistoryFixture{s: testStore(t), at: time.Now().Add(-20 * time.Minute).Truncate(5 * time.Minute).Unix(), node: "history-" + token()[:16], m: &Metrics{QueryURL: address, WriteURL: address, HTTP: &http.Client{Timeout: 5 * time.Second}}}
	root := privateTestDir(t)
	db, err := persist.OpenDB(filepath.Join(root, "metrics.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE samples(node TEXT NOT NULL,time INTEGER NOT NULL,resolution INTEGER NOT NULL,payload TEXT NOT NULL,source TEXT NOT NULL DEFAULT 'native',PRIMARY KEY(node,time,resolution)); CREATE TABLE baselines(node TEXT PRIMARY KEY,payload TEXT NOT NULL); CREATE TABLE migrations(id TEXT PRIMARY KEY,payload TEXT); CREATE TABLE import_guards(id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		offset     int64
		resolution int
		origin     string
		point      telemetry.Point
	}{
		{-300, 300, "legacy", telemetry.Point{OK: true, Values: map[string]float64{"cpu_percent": 12, "net_receive:eth0": 123}, Min: map[string]float64{"cpu_percent": 8}, Max: map[string]float64{"cpu_percent": 20}, Count: map[string]int{"cpu_percent": 10}}},
		{0, 0, "native", telemetry.Point{OK: true, Values: map[string]float64{"cpu_percent": 0, "net_receive:eth0": 0}}},
		{30, 0, "native", telemetry.Point{OK: false, Values: map[string]float64{}}},
		{90, 0, "native", telemetry.Point{OK: true, Values: map[string]float64{"cpu_percent": 5, "net_receive:eth0": 400}}},
	} {
		row.point.Time = f.at + row.offset
		raw, _ := json.Marshal(row.point)
		if _, err := db.Exec("INSERT INTO samples VALUES(?,?,?,?,?)", f.node, row.point.Time, row.resolution, string(raw), row.origin); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("INSERT INTO baselines VALUES(?,?)", f.node, `{"Time":123,"Values":{"old_counter":999}}`); err != nil {
		t.Fatal(err)
	}
	f.snapshot = filepath.Join(root, "fixed.sqlite3")
	if err := persist.BackupDB(db, f.snapshot); err != nil {
		t.Fatal(err)
	}
	f.session, err = f.s.BeginMigrationSession(context.Background(), token(), 0, []string{"health"})
	if err != nil {
		t.Fatal(err)
	}
	f.revision, err = f.s.BindMigrationRevision(context.Background(), f.session.ID, f.session.Version, MigrationRevisionInput{Role: "health", SourceID: token(), Snapshot: f.snapshot})
	if err != nil {
		t.Fatal(err)
	}
	f.session, err = f.s.MigrationSession(context.Background(), f.session.ID)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func metricHistoryEvidence(t *testing.T, f metricHistoryFixture) (bool, error) {
	t.Helper()
	tx, err := f.s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	return MigrationMetricHistoryEvidenceTx(context.Background(), tx, f.session.ID, f.revision.ID)
}

func TestMigrationMetricHistoryActualVMReplayPreservesOriginResolutionZeroGapsAndAggregates(t *testing.T) {
	f := newMetricHistoryFixture(t)
	ctx := context.Background()
	if evidence, err := metricHistoryEvidence(t, f); err != nil || evidence {
		t.Fatal("unreplayed history accepted", evidence, err)
	}
	prepared, err := f.s.PrepareMigrationMetricHistory(ctx, f.m, f.session.ID, f.session.Version, f.revision.ID)
	if err != nil || prepared.Records != 4 || prepared.State != "pending" {
		t.Fatal(prepared, err)
	}
	before := shadowBusinessSnapshot(t, f.s)
	// These two independent history tables are the only permitted database writes.
	delete(before, "v3_migration_metric_runs")
	delete(before, "v3_migration_metric_rows")
	report, err := f.s.RunMigrationMetricHistory(ctx, f.m, f.session.ID, f.session.Version, prepared.Generation)
	if err != nil || report.State != "verified" || report.VerifiedRecords != 4 || report.FirstSample != (f.at-300)*1000 || report.LastSample != (f.at+90)*1000 || !releaseDigest(report.ProjectedSHA256) || report.ReadyForCutover {
		t.Fatal(report, err)
	}
	after := shadowBusinessSnapshot(t, f.s)
	delete(after, "v3_migration_metric_runs")
	delete(after, "v3_migration_metric_rows")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("history replay changed live events, notifications, metric cursors, baselines or runtime")
	}
	if evidence, err := metricHistoryEvidence(t, f); err != nil || !evidence {
		t.Fatal("actual VM receipt absent", evidence, err)
	}
	view, err := f.s.MigrationMetricHistory(ctx, f.m, f.session.ID, report.Generation, f.node, "cpu_percent", "", time.Unix(f.at-300, 0), time.Unix(f.at+120, 0))
	if err != nil || len(view.Points) != 4 || view.Interpolated || !view.ReadOnly || view.Source != "legacy-v2" {
		t.Fatal(view, err)
	}
	if view.Points[0].ResolutionSeconds != 300 || view.Points[0].Origin != "legacy" || view.Points[0].Min == nil || *view.Points[0].Min != 8 || view.Points[0].Max == nil || *view.Points[0].Max != 20 || view.Points[0].Count == nil || *view.Points[0].Count != 10 {
		t.Fatal("aggregate statistics were not retained", view)
	}
	if view.Points[1].Value == nil || *view.Points[1].Value != 0 || !view.Points[1].OK || view.Points[2].OK || view.Points[2].Value != nil || view.Points[3].Time != f.at+90 {
		t.Fatal("zero or absent sample was synthesized", view)
	}
	device, err := f.s.MigrationMetricHistory(ctx, f.m, f.session.ID, report.Generation, f.node, "net_receive", "eth0", time.Unix(f.at-300, 0), time.Unix(f.at+120, 0))
	if err != nil || device.Points[3].Value == nil || *device.Points[3].Value != 400 {
		t.Fatal(device, err)
	}
	if _, err := f.s.MigrationMetricHistory(ctx, f.m, f.session.ID, report.Generation, f.node, "rate(node_cpu_seconds_total[5m])", "", time.Unix(f.at, 0), time.Unix(f.at+120, 0)); !errors.Is(err, ErrMigrationMetricHistory) {
		t.Fatal("caller expression accepted", err)
	}
	replayed, err := f.s.RunMigrationMetricHistory(ctx, f.m, f.session.ID, f.session.Version, prepared.Generation)
	if err != nil || replayed.ProjectedSHA256 != report.ProjectedSHA256 || replayed.ProjectedSamples != report.ProjectedSamples {
		t.Fatal("resume was not identical", replayed, err)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_migration_metric_rows SET point='{"time":1,"ok":true,"values":{"cpu_percent":123}}' WHERE run=$1`, report.Generation)
	if evidence, err := metricHistoryEvidence(t, f); err == nil && evidence {
		t.Fatal("tampered receipt accepted")
	}
}

func TestMigrationMetricHistoryLostVMResponseAndPostgresFailureResumeOriginalTimestamps(t *testing.T) {
	f := newMetricHistoryFixture(t)
	ctx := context.Background()
	var fail atomic.Bool
	fail.Store(true)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := http.NewRequestWithContext(r.Context(), r.Method, strings.TrimRight(f.m.QueryURL, "/")+r.URL.RequestURI(), r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		request.Header = r.Header.Clone()
		response, err := f.m.HTTP.Do(request)
		if err != nil {
			http.Error(w, "isolated downstream", 502)
			return
		}
		defer response.Body.Close()
		if strings.HasSuffix(r.URL.Path, "/import") && fail.Swap(false) {
			_, _ = io.Copy(io.Discard, response.Body)
			http.Error(w, "isolated lost response", 503)
			return
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	defer proxy.Close()
	writer := *f.m
	writer.WriteURL = proxy.URL
	prepared, err := f.s.PrepareMigrationMetricHistory(ctx, &writer, f.session.ID, f.session.Version, f.revision.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RunMigrationMetricHistory(ctx, &writer, f.session.ID, f.session.Version, prepared.Generation); !errors.Is(err, ErrMigrationMetricHistory) {
		t.Fatal("lost response accepted", err)
	}
	partial, err := f.s.MigrationMetricHistoryReport(ctx, f.session.ID, prepared.Generation)
	if err != nil || partial.VerifiedRecords != 0 || partial.State != "pending" {
		t.Fatal(partial, err)
	}
	// The next attempt imports the same first row again. Interrupt after the
	// second actual VM write but before its durable PostgreSQL checkpoint.
	mustHistoryExec(t, f.s.DB, `CREATE FUNCTION interrupt_metric_receipt() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.record_key=2 THEN RAISE EXCEPTION 'PRIVATE_HISTORY_FAILURE'; END IF; RETURN NEW; END$$; CREATE TRIGGER interrupt_metric_receipt BEFORE INSERT ON v3_migration_metric_rows FOR EACH ROW EXECUTE FUNCTION interrupt_metric_receipt()`)
	if _, err := f.s.RunMigrationMetricHistory(ctx, &writer, f.session.ID, f.session.Version, prepared.Generation); !errors.Is(err, ErrMigrationMetricHistory) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("unsafe database failure", err)
	}
	partial, err = f.s.MigrationMetricHistoryReport(ctx, f.session.ID, prepared.Generation)
	if err != nil || partial.VerifiedRecords != 1 {
		t.Fatal("failed receipt advanced checkpoint", partial, err)
	}
	mustHistoryExec(t, f.s.DB, "DROP TRIGGER interrupt_metric_receipt ON v3_migration_metric_rows")
	report, err := f.s.RunMigrationMetricHistory(ctx, &writer, f.session.ID, f.session.Version, prepared.Generation)
	if err != nil || report.State != "verified" || report.VerifiedRecords != 4 {
		t.Fatal(report, err)
	}
	view, err := f.s.MigrationMetricHistory(ctx, &writer, f.session.ID, report.Generation, f.node, "cpu_percent", "", time.Unix(f.at-300, 0), time.Unix(f.at+120, 0))
	if err != nil || len(view.Points) != 4 {
		t.Fatal("replayed raw VM timestamps duplicated history", view, err)
	}
}

func TestMigrationMetricHistoryConfigurationArchiveAndMissingProtectionFailClosed(t *testing.T) {
	for _, kind := range []string{"endpoint", "version", "archive", "fence", "unknown-metric"} {
		t.Run(kind, func(t *testing.T) {
			f := newMetricHistoryFixture(t)
			ctx := context.Background()
			prepared, err := f.s.PrepareMigrationMetricHistory(ctx, f.m, f.session.ID, f.session.Version, f.revision.ID)
			if err != nil {
				t.Fatal(err)
			}
			selected := *f.m
			switch kind {
			case "endpoint":
				selected.QueryURL = "http://127.0.0.1:1"
			case "version":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_migration_sessions SET version=version+1")
			case "archive":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_legacy_records SET digest=repeat('a',64) WHERE source=$1 AND table_name='samples'", f.revision.Source)
			case "fence":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_migration_domains SET pending=false")
			case "unknown-metric":
				// Content changes in an immutable snapshot invalidate its revision proof.
				file, err := os.OpenFile(f.snapshot, os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = file.WriteAt([]byte("tampered"), 100)
				file.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err = f.s.RunMigrationMetricHistory(ctx, &selected, f.session.ID, f.session.Version, prepared.Generation)
			if !errors.Is(err, ErrMigrationMetricHistory) {
				t.Fatal("changed binding accepted", err)
			}
		})
	}
}

func TestMigrationMetricHistoryProjectionRejectsUnsupportedOrAmbiguousData(t *testing.T) {
	makeRecord := func(values string) archivedRecord {
		return archivedRecord{"node": {Type: "text", Value: "isolated"}, "time": {Type: "integer", Value: "1700000000"}, "resolution": {Type: "integer", Value: "300"}, "source": {Type: "text", Value: "native"}, "payload": {Type: "text", Value: `{"time":1700000000,"ok":true,"values":` + values + `}`}}
	}
	for _, values := range []string{`{"unknown_history_name":1}`, `{"cpu_percent":null}`, `{"net_receive:eth0\u0000":1}`} {
		_, err := migrationMetricPointFromArchive(makeRecord(values))
		if !errors.Is(err, ErrMigrationMetricHistory) {
			t.Fatal("unsupported projection accepted", err)
		}
	}
	// Exact duplicate samples are idempotent; conflicting values cannot be
	// silently merged by a VM export that contains both replay attempts.
	labels := map[string]string{"__name__": "webscan_legacy_value", "source": "legacy-v2", "generation": token()}
	lines := []migrationMetricLine{{Metric: labels, Values: []float64{1}, Timestamps: []int64{1700000000000}}, {Metric: labels, Values: []float64{2}, Timestamps: []int64{1700000000000}}}
	if _, err := migrationMetricCanonical(lines); !errors.Is(err, ErrMigrationMetricHistory) {
		t.Fatal("conflicting duplicate accepted", err)
	}
}
