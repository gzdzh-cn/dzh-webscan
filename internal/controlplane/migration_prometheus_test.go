package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/telemetry"
)

type migrationPrometheusRoundTrip func(*http.Request) (*http.Response, error)

func (f migrationPrometheusRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func prometheusQueryIndex(t *testing.T, name string) int {
	t.Helper()
	for i, q := range telemetry.HistoricalQueries {
		if q.Name == name {
			return i
		}
	}
	t.Fatal(name)
	return -1
}

type prometheusArchiveFixture struct {
	s                                                                *Store
	session, nodeSource, revision, healthSource, snapshot, directory string
	version, at                                                      int64
	vault                                                            *Vault
}

func newPrometheusArchiveFixture(t *testing.T) prometheusArchiveFixture {
	t.Helper()
	ctx := context.Background()
	f := prometheusArchiveFixture{s: testStore(t), at: time.Now().Add(-time.Hour).Truncate(30 * time.Second).Unix(), directory: privateTestDir(t), healthSource: token()}
	state, e := f.s.BeginMigrationSession(ctx, token(), 0, []string{"central", "health"})
	if e != nil {
		t.Fatalf("fixture step 1: %v", e)
	}
	f.session = state.ID
	if _, e = f.s.DB.Exec(`INSERT INTO v3_cluster VALUES(1,'{"topology":"single","shards":17}')`); e != nil {
		t.Fatal(e)
	}
	root := privateTestDir(t)
	db, e := persist.OpenDB(filepath.Join(root, "source.sqlite3"))
	if e != nil {
		t.Fatalf("fixture step 2: %v", e)
	}
	defer db.Close()
	if _, e = db.Exec(`CREATE TABLE history(id INTEGER PRIMARY KEY,payload TEXT); INSERT INTO history VALUES(1,'central-source')`); e != nil {
		t.Fatalf("fixture step 3: %v", e)
	}
	snapshot := filepath.Join(root, "central.sqlite3")
	if e = persist.BackupDB(db, snapshot); e != nil {
		t.Fatalf("fixture step 4: %v", e)
	}
	source := token()
	r, e := f.s.BindMigrationRevision(ctx, f.session, state.Version, MigrationRevisionInput{Role: "central", SourceID: source, Snapshot: snapshot})
	if e != nil {
		t.Fatalf("fixture step 5: %v", e)
	}
	f.vault, _ = testVault(t)
	m := migrationNodesYAMLFixture(t)
	common.M(m["central"])["monitoring"] = common.Map{"mode": "legacy"}
	mapped, e := f.s.MapLegacyNodes(ctx, f.session, r.SessionVersion, writeLegacySettings(t, m), source, f.vault)
	if e != nil {
		t.Fatalf("fixture step 6: %v", e)
	}
	f.nodeSource = mapped.Source
	health, e := telemetry.Open(filepath.Join(root, "health"), nil, common.Map{})
	if e != nil {
		t.Fatalf("fixture step 7: %v", e)
	}
	defer health.DB.Close()
	point, _ := json.Marshal(telemetry.Point{Time: f.at, OK: true, Values: map[string]float64{"cpu_percent": 17}})
	if _, e = health.DB.Exec(`INSERT INTO samples VALUES('node-202',?,0,?,'native'); INSERT INTO baselines VALUES('node-202','{"saved":true}'); INSERT INTO health_events VALUES('old-event','node-202','cpu','resolved',?,'old event','{}'); INSERT INTO alert_outbox VALUES('old-alert','node-202','cpu','retained',?,NULL)`, f.at, string(point), f.at, f.at); e != nil {
		t.Fatalf("fixture step 8: %v", e)
	}
	f.snapshot = filepath.Join(root, "health.sqlite3")
	if e = persist.BackupDB(health.DB, f.snapshot); e != nil {
		t.Fatalf("fixture step 9: %v", e)
	}
	hr, e := f.s.BindMigrationRevision(ctx, f.session, mapped.SessionVersion, MigrationRevisionInput{Role: "health", SourceID: f.healthSource, Snapshot: f.snapshot})
	if e != nil {
		t.Fatalf("fixture step 10: %v", e)
	}
	f.revision, f.version = hr.ID, hr.SessionVersion
	return f
}
func (f prometheusArchiveFixture) run(t *testing.T, client *http.Client) (MigrationPrometheusReport, error) {
	t.Helper()
	return f.s.archiveMigrationPrometheus(context.Background(), f.vault, f.session, f.version, f.nodeSource, f.revision, time.Unix(f.at, 0), time.Unix(f.at+60, 0), f.directory, client)
}

func TestMigrationPrometheusTransportFixedQueriesAndMissingValues(t *testing.T) {
	nodes := []string{"central", "node-202"}
	task := migrationPrometheusTask{From: 1770000000, Until: 1770000060, NodeUntil: 2, Query: prometheusQueryIndex(t, "cpu_percent")}
	for i, q := range telemetry.HistoricalQueries {
		task.Query = i
		expression, e := migrationPrometheusExpression(task, nodes)
		if e != nil || !strings.Contains(expression, `node_id=~"^(central|node-202)$"`) || strings.Contains(expression, "by(node_id{") {
			t.Fatal(q.Name, expression, e)
		}
	}
	task.Query = prometheusQueryIndex(t, "cpu_percent")
	raw := `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"node_id":"central"},"values":[[1770000000,"0"],[1770000030,"NaN"]]}]}}`
	client := &http.Client{Transport: migrationPrometheusRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "127.0.0.1:19190" || r.URL.Path != "/api/v1/query_range" || r.URL.Query().Get("step") != "30" {
			t.Fatal("arbitrary destination", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: ioNop(raw), Header: http.Header{}}, nil
	})}
	report, e := migrationPrometheusFetch(context.Background(), client, task, nodes)
	if e != nil || len(report.Values) != 1 || report.Values[0].Value != 0 || report.Missing != 1 {
		t.Fatal(report, e)
	}
	for _, bad := range []string{strings.ReplaceAll(raw, "central", "other"), strings.ReplaceAll(raw, "1770000000", "1770000000.5"), strings.ReplaceAll(raw, `"0"`, `"invalid"`)} {
		raw = bad
		if _, e := migrationPrometheusFetch(context.Background(), client, task, nodes); !errors.Is(e, ErrMigrationPrometheus) {
			t.Fatal("unbound or malformed result accepted", e)
		}
	}
}

type prometheusStringBody struct{ *strings.Reader }

func (prometheusStringBody) Close() error { return nil }
func ioNop(s string) prometheusStringBody { return prometheusStringBody{strings.NewReader(s)} }

func TestMigrationPrometheusArchivesWholeHealthDBResumesAndRebinds(t *testing.T) {
	f := newPrometheusArchiveFixture(t)
	ctx := context.Background()
	before := shadowBusinessSnapshot(t, f.s)
	source, e := os.ReadFile(f.snapshot)
	if e != nil {
		t.Fatal(e)
	}
	fail := true
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if fail {
			fail = false
			w.WriteHeader(503)
			return
		}
		query := r.URL.Query().Get("query")
		if !strings.Contains(query, "node_id=~") || r.URL.Query().Get("step") != "30" {
			t.Error("unbound query")
		}
		at, e := strconv.ParseInt(r.URL.Query().Get("start"), 10, 64)
		if e != nil {
			t.Error(e)
		}
		result := []any{}
		if strings.Contains(query, `mode="idle"`) && strings.HasPrefix(query, "100*(1-") {
			for _, node := range []string{"central", "node-202"} {
				result = append(result, map[string]any{"metric": map[string]string{"node_id": node}, "values": [][]any{{at, "0"}, {at + 30, "NaN"}}})
			}
		}
		if strings.HasPrefix(query, "up{") {
			result = append(result, map[string]any{"metric": map[string]string{"node_id": "central"}, "values": [][]any{{at, "1"}}})
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": result}})
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	client := &http.Client{Transport: migrationPrometheusRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "127.0.0.1:19190" {
			t.Fatal("source changed")
		}
		copy := r.Clone(r.Context())
		u := *r.URL
		u.Host, u.Scheme = target.Host, target.Scheme
		copy.URL = &u
		return http.DefaultTransport.RoundTrip(copy)
	})}
	if _, e := f.run(t, client); !errors.Is(e, ErrMigrationPrometheus) {
		t.Fatal("failed source accepted", e)
	}
	var report MigrationPrometheusReport
	for i := 0; i < 10; i++ {
		report, e = f.run(t, client)
		if e != nil {
			t.Fatal(report, e)
		}
		if report.Complete {
			break
		}
	}
	if !report.Complete || report.ReadyForCutover || report.Nodes != 3 || report.CompletedQueries != int64(len(telemetry.HistoricalQueries)) || report.EvaluationStepSeconds != 30 || report.RateWindowSeconds != 300 || report.MissingValues != 2 || !releaseDigest(report.ArchiveSHA256) {
		t.Fatal(report)
	}
	after := shadowBusinessSnapshot(t, f.s)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("archive mutated current PostgreSQL")
	}
	again, e := os.ReadFile(f.snapshot)
	if e != nil || string(source) != string(again) {
		t.Fatal("source mutated", e)
	}
	archived, e := openMigrationSnapshot(ctx, report.ArchivePath)
	if e != nil {
		t.Fatal(e)
	}
	for table, expected := range map[string]int{"baselines": 1, "health_events": 1, "alert_outbox": 1, "import_guards": 0} {
		var count int
		if e = archived.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); e != nil || count != expected {
			t.Fatal("health state dropped", table, count, e)
		}
	}
	var raw, origin string
	if e = archived.db.QueryRow("SELECT payload,source FROM samples WHERE node='node-202' AND time=?", f.at).Scan(&raw, &origin); e != nil || origin != "native" || !strings.Contains(raw, "17") {
		t.Fatal("native source overwritten", raw, origin, e)
	}
	var point telemetry.Point
	if e = archived.db.QueryRow("SELECT payload FROM samples WHERE node='central' AND time=?", f.at).Scan(&raw); e != nil || json.Unmarshal([]byte(raw), &point) != nil || !point.OK || point.Values["cpu_percent"] != 0 {
		t.Fatal("zero or status changed", point, e)
	}
	archived.close()
	callsBefore := calls
	retry, e := f.run(t, client)
	if e != nil || retry.ArchiveSHA256 != report.ArchiveSHA256 || calls != callsBefore {
		t.Fatal("manifest replay refetched", e)
	}
	if _, e = f.s.archiveMigrationPrometheus(ctx, f.vault, f.session, f.version-1, f.nodeSource, f.revision, time.Unix(f.at, 0), time.Unix(f.at+60, 0), f.directory, client); !errors.Is(e, ErrMigrationPrometheus) || calls != callsBefore {
		t.Fatal("stale version queried", e)
	}
	// New indexed health revision preserves old tables, so final health mapping
	// cannot accidentally replace them with a samples-only Prometheus database.
	bound, e := f.s.BindMigrationRevision(ctx, f.session, f.version, MigrationRevisionInput{Role: "health", SourceID: f.healthSource, Snapshot: report.ArchivePath})
	if e != nil || bound.State != "ready" {
		t.Fatal("archive not indexable", bound, e)
	}
	path := filepath.Join(filepath.Dir(report.ArchivePath), "manifest.json")
	if e = os.WriteFile(path, []byte(`{"proof":"changed"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = f.run(t, client); !errors.Is(e, ErrMigrationPrometheus) {
		t.Fatal("manifest tamper accepted", e)
	}
}

func TestMigrationPrometheusSplitAndConflictAreBounded(t *testing.T) {
	task := migrationPrometheusTask{From: 300, Until: 360, NodeUntil: 2, Query: 0}
	children, e := migrationPrometheusTaskChildren(task)
	if e != nil || len(children) != 2 || children[0].Until != 330 || children[1].From != 330 {
		t.Fatal(children, e)
	}
	task.Until = 330
	children, e = migrationPrometheusTaskChildren(task)
	if e != nil || children[0].NodeUntil != 1 {
		t.Fatal(children, e)
	}
	task.NodeUntil = 1
	if _, e = migrationPrometheusTaskChildren(task); !errors.Is(e, ErrMigrationPrometheus) {
		t.Fatal("unbounded split")
	}
	// Failed import and its receipt commit together; there is no half checkpoint.
	root := privateTestDir(t)
	store, e := telemetry.Open(root, nil, common.Map{})
	if e != nil {
		t.Fatal(e)
	}
	defer store.DB.Close()
	task.Query = prometheusQueryIndex(t, "cpu_percent")
	good := migrationPrometheusResponse{SHA256: digest([]byte("fixed")), Values: []migrationPrometheusValue{{Node: "central", Key: "cpu_percent", At: 300, Value: 1}}}
	if e = migrationPrometheusImportTask(context.Background(), store.DB, "job", task, good); e != nil {
		t.Fatal(e)
	}
	task.From = 330
	good.Values[0].Value = 2
	if e = migrationPrometheusImportTask(context.Background(), store.DB, "job", task, good); !errors.Is(e, ErrMigrationPrometheus) {
		t.Fatal("conflicting history overwritten", e)
	}
	var count int
	store.DB.QueryRow("SELECT count(*) FROM migrations").Scan(&count)
	if count != 1 {
		t.Fatal(fmt.Sprint("failed receipt saved ", count))
	}
}

func TestMigrationPrometheusActualTSDBArchiveToVM(t *testing.T) {
	address := os.Getenv("WEBSCAN_V3_TEST_PROMETHEUS")
	if address == "" {
		t.Skip("set isolated actual Prometheus endpoint")
	}
	vm := os.Getenv("WEBSCAN_V3_TEST_VM")
	if vm == "" {
		t.Fatal("actual VM fixture required")
	}
	at, e := strconv.ParseInt(os.Getenv("WEBSCAN_V3_TEST_PROMETHEUS_START"), 10, 64)
	if e != nil || at%30 != 0 {
		t.Fatal("fixed aligned actual TSDB start required")
	}
	f := newPrometheusArchiveFixture(t)
	// Build a new immutable source snapshot at the fixed actual TSDB timestamp;
	// no running production file or source revision is ever edited.
	source, e := openMigrationSnapshot(context.Background(), f.snapshot)
	if e != nil {
		t.Fatal(e)
	}
	working := filepath.Join(privateTestDir(t), "fixture.sqlite3")
	e = persist.BackupDB(source.db, working)
	source.close()
	if e != nil {
		t.Fatal(e)
	}
	db, e := persist.OpenDB(working)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(telemetry.Point{Time: at, OK: true, Values: map[string]float64{"cpu_percent": 17}})
	if _, e = db.Exec("UPDATE samples SET time=?,payload=?", at, string(raw)); e != nil {
		t.Fatal(e)
	}
	fixed := filepath.Join(privateTestDir(t), "fixture-fixed.sqlite3")
	if e = persist.BackupDB(db, fixed); e != nil {
		t.Fatal(e)
	}
	db.Close()
	revision, e := f.s.BindMigrationRevision(context.Background(), f.session, f.version, MigrationRevisionInput{Role: "health", SourceID: f.healthSource, Snapshot: fixed})
	if e != nil {
		t.Fatal(e)
	}
	f.version, f.revision, f.snapshot, f.at = revision.SessionVersion, revision.ID, fixed, at
	target, e := url.Parse(address)
	if e != nil || target.Scheme != "http" || !strings.HasPrefix(target.Host, "127.0.0.1:") {
		t.Fatal("isolated loopback fixture only")
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: migrationPrometheusRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "127.0.0.1:19190" {
			t.Fatal("product source changed")
		}
		copy := r.Clone(r.Context())
		u := *r.URL
		u.Host, u.Scheme = target.Host, target.Scheme
		copy.URL = &u
		return http.DefaultTransport.RoundTrip(copy)
	})}
	var report MigrationPrometheusReport
	for range 10 {
		report, e = f.run(t, client)
		if e != nil {
			t.Fatal(report, e)
		}
		if report.Complete {
			break
		}
	}
	if !report.Complete || report.ReturnedValues == 0 || report.ReadyForCutover {
		t.Fatal(report)
	}
	archived, e := openMigrationSnapshot(context.Background(), report.ArchivePath)
	if e != nil {
		t.Fatal(e)
	}
	var payload string
	if e = archived.db.QueryRow("SELECT payload FROM samples WHERE node='node-202' AND time=?", at).Scan(&payload); e != nil || !strings.Contains(payload, "17") {
		t.Fatal("native overwritten", payload, e)
	}
	var point telemetry.Point
	if e = archived.db.QueryRow("SELECT payload FROM samples WHERE node='central' AND time=?", at).Scan(&payload); e != nil || json.Unmarshal([]byte(payload), &point) != nil || point.Values["cpu_percent"] != 0 || !point.OK {
		t.Fatal("real zero missing", point, e)
	}
	archived.close()
	bound, e := f.s.BindMigrationRevision(context.Background(), f.session, f.version, MigrationRevisionInput{Role: "health", SourceID: f.healthSource, Snapshot: report.ArchivePath})
	if e != nil {
		t.Fatal(e)
	}
	f.version = bound.SessionVersion
	metrics := &Metrics{QueryURL: vm, WriteURL: vm, HTTP: &http.Client{Timeout: 15 * time.Second}}
	prepared, e := f.s.PrepareMigrationMetricHistory(context.Background(), metrics, f.session, f.version, bound.ID)
	if e != nil {
		t.Fatal(e)
	}
	var replay MigrationMetricHistoryReport
	for range 10 {
		replay, e = f.s.RunMigrationMetricHistory(context.Background(), metrics, f.session, f.version, prepared.Generation)
		if e != nil {
			t.Fatal(e)
		}
		if replay.State == "verified" {
			break
		}
	}
	if replay.State != "verified" {
		t.Fatal(replay)
	}
	view, e := f.s.MigrationMetricHistory(context.Background(), metrics, f.session, replay.Generation, "central", "cpu_percent", "", time.Unix(at, 0), time.Unix(at+60, 0))
	if e != nil || len(view.Points) == 0 || view.Points[0].Value == nil || *view.Points[0].Value != 0 || view.Interpolated || view.Points[0].Origin != "legacy" {
		t.Fatal(view, e)
	}
	t.Logf("actual Prometheus whitelist=%d returned_values=%d missing_values=%d; immutable health rows=%d; VM projected_samples=%d verified; zero/native/alerts retained", len(telemetry.HistoricalQueries), report.ReturnedValues, report.MissingValues, bound.Records, replay.ProjectedSamples)
}
