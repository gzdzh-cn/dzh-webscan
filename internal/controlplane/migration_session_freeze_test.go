package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func migrationFreezeTestManifest(t *testing.T, id, source, sqlite string) string {
	t.Helper()
	m := MigrationFreezeManifest{Format: 1, Session: id, Sources: []MigrationFreezeSource{{Role: "central", SourceID: source, SQLite: sqlite, Writers: []MigrationFreezeWriter{{Kind: "systemd", ID: "webscan-synthetic-legacy.service", Role: "central"}}}}}
	path := filepath.Join(privateTestDir(t), "freeze.json")
	raw, _ := json.Marshal(m)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return path
}

func TestMigrationSessionFreezeAllowsInitialCollectingAndRejectsTerminal(t *testing.T) {
	s, id, source, db, _ := migrationSessionFixture(t)
	ctx := context.Background()
	var sqlite string
	if err := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&sqlite); err != nil {
		t.Fatal(err)
	}
	manifest := migrationFreezeTestManifest(t, id, source, sqlite)
	observer := func(context.Context, MigrationFreezeSource) (string, error) {
		return digest([]byte("fixed-stopped-writer")), nil
	}
	frozen, err := s.freezeMigrationSession(ctx, id, 1, manifest, privateTestDir(t), observer)
	if err != nil || frozen.Phase != "frozen" || len(frozen.Revisions) != 1 {
		t.Fatal("initial collecting session could not freeze", frozen, err)
	}
	for _, phase := range []string{"active", "rolled_back"} {
		if _, err := s.DB.Exec(`UPDATE v3_migration_sessions SET phase=$2 WHERE id=$1`, id, phase); err != nil {
			t.Fatal(err)
		}
		if _, err := s.freezeMigrationSession(ctx, id, frozen.Version, manifest, privateTestDir(t), observer); !errors.Is(err, ErrMigrationSession) {
			t.Fatal("terminal session froze again", phase, err)
		}
	}
}
func TestMigrationSessionFreezeFinalSnapshotReconcileAndRestoreHold(t *testing.T) {
	s, id, source, db, snapshot := migrationSessionFixture(t)
	ctx := context.Background()
	b, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, snapshot()})
	if e != nil {
		t.Fatal(e)
	}
	var sqlite string
	if e = db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&sqlite); e != nil {
		t.Fatal(e)
	}
	manifest := migrationFreezeTestManifest(t, id, source, sqlite)
	var observations atomic.Int32
	observer := func(context.Context, MigrationFreezeSource) (string, error) {
		observations.Add(1)
		return digest([]byte("synthetic-stopped-disabled-writer")), nil
	}
	if _, e = db.Exec(`UPDATE history SET value='final-update' WHERE id=1; DELETE FROM history WHERE id=2; INSERT INTO history VALUES(10000,'final-add',NULL,NULL)`); e != nil {
		t.Fatal(e)
	}
	frozen, e := s.freezeMigrationSession(ctx, id, b.SessionVersion, manifest, privateTestDir(t), observer)
	if e != nil || frozen.Phase != "frozen" || !releaseDigest(frozen.FreezeDigest) || len(frozen.Revisions) != 2 || observations.Load() != 2 {
		t.Fatal(frozen, e, observations.Load())
	}
	replay, e := s.freezeMigrationSession(ctx, id, b.SessionVersion, manifest, privateTestDir(t), observer)
	if e != nil || replay.Version != frozen.Version || replay.FreezeDigest != frozen.FreezeDigest {
		t.Fatal(replay, e)
	}
	latest := frozen.Revisions[1]
	delta, e := s.CompareMigrationRevisions(ctx, id, frozen.Version, b.ID, latest.ID)
	if e != nil || delta.Added != 1 || delta.Deleted != 1 || delta.Modified != 1 {
		t.Fatal(delta, e)
	}
	report, e := s.ReconcileMigrationSession(ctx, id, delta.SessionVersion)
	if e != nil || !report.Protected || report.ReadyForCutover || len(report.Roles) != 1 || report.Roles[0].Records != 507 || report.Roles[0].Archived != 507 || report.Roles[0].Delta == nil || report.SHA256 != migrationReconciliationDigest(report) {
		t.Fatal(report, e)
	}
	if len(report.Conflicts) != 2 {
		t.Fatal("final mapper limitations omitted", report.Conflicts)
	}
	again, e := s.ReconcileMigrationSession(ctx, id, delta.SessionVersion)
	if e != nil || again.SHA256 != report.SHA256 {
		t.Fatal(again, e)
	}
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), sqlite) || strings.Contains(string(raw), "final-update") {
		t.Fatal("private receipt leaked")
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_sessions SET recovery_hold=true,phase='indexed',freeze_digest='',freeze_at=NULL WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	held, e := s.MigrationSession(ctx, id)
	if e != nil || !held.RecoveryHold {
		t.Fatal(held, e)
	}
	checks := []func() error{
		func() error { _, e := s.BeginMigrationSession(ctx, id, 0, []string{"central"}); return e },
		func() error {
			_, e := s.BindMigrationRevision(ctx, id, held.Version, MigrationRevisionInput{"central", source, snapshot()})
			return e
		},
		func() error { _, e := s.ResumeMigrationRevision(ctx, id, held.Version, b.ID); return e },
		func() error { _, e := s.CompareMigrationRevisions(ctx, id, held.Version, b.ID, latest.ID); return e },
		func() error { _, e := s.ResumeMigrationDelta(ctx, id, held.Version, delta.ID); return e },
		func() error {
			_, e := s.freezeMigrationSession(ctx, id, held.Version, manifest, privateTestDir(t), observer)
			return e
		},
		func() error { _, e := s.ReconcileMigrationSession(ctx, id, held.Version); return e },
	}
	for i, check := range checks {
		if e := check(); !errors.Is(e, ErrMigrationSession) {
			t.Fatalf("restore hold bypass %d: %v", i, e)
		}
	}
}
func TestMigrationSessionFreezeStopsBeforeBackupOnUnverifiedOrChangingWriter(t *testing.T) {
	s, id, source, db, _ := migrationSessionFixture(t)
	ctx := context.Background()
	var sqlite string
	if e := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&sqlite); e != nil {
		t.Fatal(e)
	}
	manifest := migrationFreezeTestManifest(t, id, source, sqlite)
	denied := func(context.Context, MigrationFreezeSource) (string, error) { return "", ErrMigrationSession }
	if _, e := s.freezeMigrationSession(ctx, id, 1, manifest, privateTestDir(t), denied); !errors.Is(e, ErrMigrationSession) {
		t.Fatal(e)
	}
	state, e := s.MigrationSession(ctx, id)
	if e != nil || state.Version != 1 || len(state.Revisions) != 0 {
		t.Fatal("unverified writer advanced state", state, e)
	}
	var attempts int
	changed := func(context.Context, MigrationFreezeSource) (string, error) {
		attempts++
		return digest([]byte(string(rune('a' + attempts)))), nil
	}
	if _, e = s.freezeMigrationSession(ctx, id, 1, manifest, privateTestDir(t), changed); !errors.Is(e, ErrMigrationSession) {
		t.Fatal(e)
	}
	state, e = s.MigrationSession(ctx, id)
	if e != nil || state.Phase == "frozen" || state.FreezeDigest != "" || !state.Protected {
		t.Fatal("changed writer accepted", state, e)
	}
	if _, e = s.ReconcileMigrationSession(ctx, id, state.Version); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("unfrozen session reconciled", e)
	}
}
func TestMigrationSessionFreezeManifestAndConfiguredSourceAreStrict(t *testing.T) {
	root := privateTestDir(t)
	path := filepath.Join(root, "runtime.json")
	raw := []byte(`{"data_dir":"` + root + `"}`)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	w := MigrationFreezeWriter{Kind: "systemd", Role: "central", ConfigFile: path, ConfigSHA256: digest(raw)}
	config, e := migrationWriterConfiguration(w)
	if e != nil {
		t.Fatal(e)
	}
	source, e := migrationWriterDatabase(config, w, "central")
	if e != nil || source != filepath.Join(root, "events-v1.sqlite3") {
		t.Fatal(source, e)
	}
	if _, e = migrationWriterDatabase(config, w, "host-manager"); e == nil {
		t.Fatal("central claims manager")
	}
	w.ConfigSHA256 = strings.Repeat("a", 64)
	if _, e = migrationWriterConfiguration(w); e == nil {
		t.Fatal("config identity not bound")
	}
	if _, _, e = readMigrationFreezeManifest(path, digest([]byte("session"))); e == nil {
		t.Fatal("non-manifest accepted")
	}
	if e = os.WriteFile(path, []byte(`{"format":1,"format":1}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = readMigrationFreezeManifest(path, digest([]byte("session"))); e == nil {
		t.Fatal("duplicate manifest fields accepted")
	}
}
