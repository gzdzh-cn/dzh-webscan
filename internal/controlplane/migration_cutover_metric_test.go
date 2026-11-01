package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/telemetry"
)

// Both SQLite sources, archive indexing, final mapping, reverse baseline, PG
// journal and VM replay use their production paths. Only the stopped legacy
// writer observer is synthetic; this does not claim host/kernel freeze proof.
func migrationCutoverMetricFixture(t *testing.T) (*Store, string, MigrationCutoverInput, migrationFreezeObserver, int64, string, string) {
	t.Helper()
	ctx := context.Background()
	address := os.Getenv("WEBSCAN_V3_TEST_VM")
	if address == "" {
		t.Skip("actual isolated VM required")
	}
	s := testStore(t)
	session := token()
	centralSource, healthSource := token(), token()
	node := "cutover-metric-" + token()[:16]
	state, e := s.BeginMigrationSession(ctx, session, 0, []string{"central", "health"})
	if e != nil {
		t.Fatal(e)
	}
	central, _, _ := legacyWebsiteFixture(t, 1)
	var centralPath string
	if e = central.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&centralPath); e != nil {
		t.Fatal(e)
	}
	root := privateTestDir(t)
	healthPath := filepath.Join(root, "health.sqlite3")
	health, e := persist.OpenDB(healthPath)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { health.Close() })
	if _, e = health.Exec(`CREATE TABLE samples(node TEXT NOT NULL,time INTEGER NOT NULL,resolution INTEGER NOT NULL,payload TEXT NOT NULL,source TEXT NOT NULL DEFAULT 'native',PRIMARY KEY(node,time,resolution)); CREATE TABLE baselines(node TEXT PRIMARY KEY,payload TEXT NOT NULL); CREATE TABLE migrations(id TEXT PRIMARY KEY,payload TEXT); CREATE TABLE import_guards(id TEXT PRIMARY KEY)`); e != nil {
		t.Fatal(e)
	}
	at := time.Now().Add(-20 * time.Minute).Unix()
	for i, value := range []float64{0, 12} {
		p := telemetry.Point{Time: at + int64(i)*30, OK: true, Values: map[string]float64{"cpu_percent": value}}
		if _, e = health.Exec(`INSERT INTO samples VALUES(?,?,0,?,'native')`, node, p.Time, string(common.JSON(p))); e != nil {
			t.Fatal(e)
		}
	}
	centralSnapshot := filepath.Join(root, "central-fixed.sqlite3")
	healthSnapshot := filepath.Join(root, "health-fixed.sqlite3")
	if e = persist.BackupDB(central, centralSnapshot); e != nil {
		t.Fatal(e)
	}
	if e = persist.BackupDB(health, healthSnapshot); e != nil {
		t.Fatal(e)
	}
	cr, e := s.BindMigrationRevision(ctx, session, state.Version, MigrationRevisionInput{Role: "central", SourceID: centralSource, Snapshot: centralSnapshot})
	if e != nil {
		t.Fatal(e)
	}
	hr, e := s.BindMigrationRevision(ctx, session, cr.SessionVersion, MigrationRevisionInput{Role: "health", SourceID: healthSource, Snapshot: healthSnapshot})
	if e != nil {
		t.Fatal(e)
	}
	v, _ := testVault(t)
	version := migrationBindLegacyYAMLFixture(t, s, session, centralSource, hr.SessionVersion, v)
	manifest := MigrationFreezeManifest{Format: 1, Session: session, Sources: []MigrationFreezeSource{
		{Role: "central", SourceID: centralSource, SQLite: centralPath, Writers: []MigrationFreezeWriter{{Kind: "systemd", ID: "webscan-test-metric-central.service", Role: "central"}}},
		{Role: "health", SourceID: healthSource, SQLite: healthPath, Writers: []MigrationFreezeWriter{{Kind: "systemd", ID: "webscan-test-metric-health.service", Role: "health"}}},
	}}
	manifestPath := filepath.Join(root, "freeze.json")
	if e = os.WriteFile(manifestPath, common.JSON(manifest), 0600); e != nil {
		t.Fatal(e)
	}
	migrationBindFrozenYAMLFixture(t, s, session, manifestPath, v)
	observer := func(context.Context, MigrationFreezeSource) (string, error) {
		return digest([]byte("isolated-cutover-metric-stopped-writer")), nil
	}
	frozen, e := s.freezeMigrationSession(ctx, session, version, manifestPath, filepath.Join(root, "freeze"), observer)
	if e != nil {
		t.Fatal(e)
	}
	var revision string
	if e = s.DB.QueryRow(`SELECT id FROM v3_migration_revisions WHERE session=$1 AND role='health' ORDER BY sequence DESC LIMIT 1`, session).Scan(&revision); e != nil {
		t.Fatal(e)
	}
	metrics := &Metrics{QueryURL: address, WriteURL: address, HTTP: &http.Client{Timeout: 5 * time.Second}}
	prepared, e := s.PrepareMigrationMetricHistory(ctx, metrics, session, frozen.Version, revision)
	if e != nil {
		t.Fatal(e)
	}
	replayed, e := s.RunMigrationMetricHistory(ctx, metrics, session, frozen.Version, prepared.Generation)
	if e != nil || replayed.State != "verified" || replayed.VerifiedRecords != 2 {
		t.Fatal(replayed, e)
	}
	mapped, e := s.MapMigrationFinalDomains(ctx, session, frozen.Version, MigrationFinalMappingInput{}, v)
	if e != nil || !mapped.Complete {
		t.Fatal(mapped, e)
	}
	sources := map[string]string{}
	for _, role := range []string{"central", "health"} {
		var path string
		if e = s.DB.QueryRow(`SELECT snapshot FROM v3_migration_revisions WHERE session=$1 AND role=$2 ORDER BY sequence DESC LIMIT 1`, session, role).Scan(&path); e != nil {
			t.Fatal(e)
		}
		sources[role] = path
	}
	sink, e := s.PrepareMigrationLegacySink(ctx, session, mapped.SessionVersion, sources, filepath.Join(root, "reverse"), v)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { sink.Close() })
	journal, e := s.ArmMigrationTargetJournal(ctx, session, mapped.SessionVersion)
	if e != nil {
		t.Fatal(e)
	}
	evidence, e := s.ProjectMigrationLegacyBaseline(ctx, session, journal.SessionVersion, "metric_legacy", sink, v)
	if e != nil || !evidence.Verified {
		t.Fatal(evidence, e)
	}
	return s, session, MigrationCutoverInput{FreezeManifest: manifestPath, Consumer: "metric_legacy", LegacySink: sink, LegacyEvidence: evidence, Vault: v, Metrics: metrics}, observer, journal.SessionVersion, prepared.Generation, node
}

func migrationCutoverMetricImportOriginal(t *testing.T, s *Store, m *Metrics, generation string) {
	t.Helper()
	rows, e := s.DB.Query(`SELECT node,sampled,resolution,origin,point FROM v3_migration_metric_rows WHERE run=$1 ORDER BY record_key`, generation)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	for rows.Next() {
		var p migrationMetricPoint
		if e = rows.Scan(&p.Node, &p.Sampled, &p.Resolution, &p.Origin, &p.Raw); e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(p.Raw, &p.Point); e != nil {
			t.Fatal(e)
		}
		raw, _, e := p.project(generation)
		if e != nil {
			t.Fatal(e)
		}
		req, e := http.NewRequest("POST", strings.TrimRight(m.WriteURL, "/")+"/api/v1/import", bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		response, e := m.HTTP.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 200 && response.StatusCode != 204 {
			t.Fatal("synthetic exact-timestamp restoration", response.StatusCode)
		}
	}
	if e = rows.Err(); e != nil {
		t.Fatal(e)
	}
}

func TestMigrationCutoverActualVMRechecksAfterFinalMappingAndBeforeActivation(t *testing.T) {
	ctx := context.Background()
	s, id, in, observer, version, generation, node := migrationCutoverMetricFixture(t)
	healthy, e := s.reconcileMigrationSessionWithEvidence(ctx, id, version, in, observer)
	if e != nil || !healthy.ReadyForCutover || !healthy.Protected {
		t.Fatal("intact actual metric evidence", healthy, e)
	}
	version = healthy.SessionVersion
	assertHeld := func(name string, altered MigrationCutoverInput) {
		t.Helper()
		r, e := s.reconcileMigrationSessionWithEvidence(ctx, id, version, altered, observer)
		if e == nil && r.ReadyForCutover {
			t.Fatal(name, "reconcile accepted stale metrics")
		}
		if e = s.migrationCutover(ctx, id, version, altered, "activate", observer); e == nil {
			t.Fatal(name, "activate accepted stale metrics")
		}
		state, e := s.MigrationSession(ctx, id)
		if e != nil || !state.Protected || state.Phase == "active" {
			t.Fatal(name, "released protection", state, e)
		}
		var notices int
		if e = s.DB.QueryRow(`SELECT count(*) FROM v3_migration_cutovers WHERE session=$1`, id).Scan(&notices); e != nil || notices != 0 {
			t.Fatal(name, "recorded false activation", notices, e)
		}
	}
	drift := *in.Metrics
	drift.QueryURL += "/changed-runtime-target"
	changed := in
	changed.Metrics = &drift
	assertHeld("current-target-changed", changed)
	mustHistoryExec(t, s.DB, `UPDATE v3_migration_metric_runs SET state='pending' WHERE id=$1`, generation)
	assertHeld("run-no-longer-verified", in)
	mustHistoryExec(t, s.DB, `UPDATE v3_migration_metric_runs SET state='verified' WHERE id=$1`, generation)
	var key int64
	var projected string
	if e = s.DB.QueryRow(`SELECT record_key,projected_digest FROM v3_migration_metric_rows WHERE run=$1 ORDER BY record_key LIMIT 1`, generation).Scan(&key, &projected); e != nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_migration_metric_rows SET projected_digest=repeat('0',64) WHERE run=$1 AND record_key=$2`, generation, key)
	assertHeld("projected-row-changed", in)
	mustHistoryExec(t, s.DB, `UPDATE v3_migration_metric_rows SET projected_digest=$3 WHERE run=$1 AND record_key=$2`, generation, key, projected)
	selector := migrationMetricSelector(map[string]string{"source": "legacy-v2", "generation": generation, "node_id": node, "__name__": "webscan_legacy_value", "metric": "cpu_percent"})
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(in.Metrics.QueryURL, "/")+"/api/v1/admin/tsdb/delete_series?"+url.Values{"match[]": {selector}}.Encode(), nil)
	if e != nil {
		t.Fatal(e)
	}
	response, e := in.Metrics.HTTP.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 && response.StatusCode != 204 {
		t.Fatal("isolated synthetic-series removal", response.StatusCode)
	}
	assertHeld("actual-vm-points-lost-after-final", in)
	// Test-only repair imports the same authenticated original samples. Product
	// reconciliation itself never replays or silently repairs missing history.
	migrationCutoverMetricImportOriginal(t, s, in.Metrics, generation)
	deadline := time.Now().Add(8 * time.Second)
	for {
		healthy, e = s.reconcileMigrationSessionWithEvidence(ctx, id, version, in, observer)
		if e == nil && healthy.ReadyForCutover {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restored exact evidence unavailable", healthy, e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e = s.migrationCutover(ctx, id, healthy.SessionVersion, in, "activate", observer); e != nil {
		t.Fatal("intact verified history cannot activate", e)
	}
	state, e := s.MigrationSession(ctx, id)
	if e != nil || state.Protected || state.Phase != "active" {
		t.Fatal("activation did not complete", state, e)
	}
}
