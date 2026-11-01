package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"webscan/internal/persist"
)

func migrationSessionTestStore(t *testing.T) *Store {
	t.Helper()
	s := testStore(t)
	var exists bool
	if e := s.DB.QueryRow(`SELECT to_regclass('v3_migration_sessions') IS NOT NULL`).Scan(&exists); e != nil {
		t.Fatal(e)
	}
	if !exists {
		if _, e := s.DB.Exec(migrationSessionSchema); e != nil {
			t.Fatal(e)
		}
	}
	return s
}
func migrationSessionFixture(t *testing.T) (*Store, string, string, *sql.DB, func() string) {
	t.Helper()
	s := migrationSessionTestStore(t)
	ctx := context.Background()
	id := digest([]byte(t.Name()))
	source := digest([]byte("synthetic-source"))
	if _, e := s.BeginMigrationSession(ctx, id, 0, []string{"central"}); e != nil {
		t.Fatal(e)
	}
	root := privateTestDir(t)
	db, e := persist.OpenDB(filepath.Join(root, "source.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Exec(`CREATE TABLE history(id INTEGER PRIMARY KEY,value TEXT,large INTEGER,bytes BLOB); WITH RECURSIVE n(i) AS(SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<505) INSERT INTO history SELECT i,'synthetic-'||i,9007199254740993,x'00FF' FROM n; INSERT INTO history VALUES(-9223372036854775808,'minimum',NULL,NULL),(9007199254740993,'large',NULL,NULL); CREATE TABLE empty_table(value TEXT)`); e != nil {
		t.Fatal(e)
	}
	snapshot := func() string {
		path := filepath.Join(root, "snapshot-"+token()+".sqlite3")
		if e := persist.BackupDB(db, path); e != nil {
			t.Fatal(e)
		}
		return path
	}
	return s, id, source, db, snapshot
}
func TestMigrationSessionVersionProtectionAndSafePublicErrors(t *testing.T) {
	s := migrationSessionTestStore(t)
	ctx := context.Background()
	id := digest([]byte(t.Name()))
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := s.BeginMigrationSession(ctx, id, 0, []string{"health", "central"})
			if e != nil || r.Version != 1 || !r.Protected {
				t.Errorf("create=%+v %v", r, e)
			}
		}()
	}
	wg.Wait()
	if _, e := s.BeginMigrationSession(ctx, id, 1, []string{"central"}); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if _, e := s.BeginMigrationSession(ctx, id, 0, []string{"central"}); !errors.Is(e, ErrMigrationSession) {
		t.Fatal(e)
	}
	for _, operation := range []func(context.Context, string, int64) error{s.ActivateMigrationSession, s.RollbackMigrationSession} {
		if !errors.Is(operation(ctx, id, 1), ErrMigrationCutoverProtected) {
			t.Fatal("migration fence cleared")
		}
	}
	r, e := s.MigrationSession(ctx, id)
	if e != nil || !r.Protected || r.Phase != "collecting" {
		t.Fatal(r, e)
	}
	if _, e = s.DB.Exec(`CREATE FUNCTION migration_private_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'PRIVATE_SYNTHETIC_PASSWORD'; END$$; CREATE TRIGGER migration_private_failure BEFORE INSERT ON v3_migration_sessions FOR EACH ROW EXECUTE FUNCTION migration_private_failure()`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.BeginMigrationSession(ctx, digest([]byte("other")), 0, []string{"central"}); !errors.Is(e, ErrMigrationSession) || strings.Contains(e.Error(), "PRIVATE") {
		t.Fatal("unsafe failure", e)
	}
}

func TestMigrationSessionTerminalPhasesRejectRevisionAndDeltaReplay(t *testing.T) {
	for _, phase := range []string{"active", "rolled_back"} {
		t.Run(phase, func(t *testing.T) {
			s, id, source, db, snapshot := migrationSessionFixture(t)
			ctx := context.Background()
			first := snapshot()
			base, err := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, first})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`UPDATE history SET value='terminal-test' WHERE id=1`); err != nil {
				t.Fatal(err)
			}
			target, err := s.BindMigrationRevision(ctx, id, base.SessionVersion, MigrationRevisionInput{"central", source, snapshot()})
			if err != nil {
				t.Fatal(err)
			}
			delta, err := s.CompareMigrationRevisions(ctx, id, target.SessionVersion, base.ID, target.ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.DB.Exec(`UPDATE v3_migration_sessions SET phase=$2 WHERE id=$1`, id, phase); err != nil {
				t.Fatal(err)
			}
			for _, operation := range []func() error{
				func() error { _, e := s.BeginMigrationSession(ctx, id, 0, []string{"central"}); return e },
				func() error {
					_, e := s.BindMigrationRevision(ctx, id, delta.SessionVersion, MigrationRevisionInput{"central", source, first})
					return e
				},
				func() error { _, e := s.ResumeMigrationRevision(ctx, id, delta.SessionVersion, base.ID); return e },
				func() error {
					_, e := s.CompareMigrationRevisions(ctx, id, delta.SessionVersion, base.ID, target.ID)
					return e
				},
				func() error { _, e := s.ResumeMigrationDelta(ctx, id, delta.SessionVersion, delta.ID); return e },
			} {
				if e := operation(); !errors.Is(e, ErrMigrationSession) {
					t.Fatal("terminal session accepted replay", e)
				}
			}
			current, err := s.MigrationSession(ctx, id)
			if err != nil || current.Phase != phase || current.Version != delta.SessionVersion {
				t.Fatal("terminal state mutated", current, err)
			}
		})
	}
}
func TestMigrationSessionRevisionDeltaResumePreservesUpdateDeleteAndLargeKeys(t *testing.T) {
	s, id, source, db, snapshot := migrationSessionFixture(t)
	ctx := context.Background()
	first := snapshot()
	if _, e := s.DB.Exec(`CREATE FUNCTION interrupt_revision() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.record_key=501 THEN RAISE EXCEPTION 'PRIVATE_INDEX_FAILURE'; END IF; RETURN NEW; END$$; CREATE TRIGGER interrupt_revision BEFORE INSERT ON v3_migration_revision_rows FOR EACH ROW EXECUTE FUNCTION interrupt_revision()`); e != nil {
		t.Fatal(e)
	}
	if r, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, first}); !errors.Is(e, ErrMigrationSession) || r.Records != 0 {
		t.Fatal("failed batch reported uncommitted progress", r, e)
	}
	state, e := s.MigrationSession(ctx, id)
	if e != nil || state.Version != 2 || len(state.Revisions) != 1 || state.Revisions[0].Records != 500 {
		t.Fatal(state, e)
	}
	baseID := state.Revisions[0].ID
	if _, e = s.DB.Exec(`DROP TRIGGER interrupt_revision ON v3_migration_revision_rows`); e != nil {
		t.Fatal(e)
	}
	base, e := s.ResumeMigrationRevision(ctx, id, 2, baseID)
	if e != nil || base.State != "ready" || base.Records != 507 || base.SessionVersion != 3 {
		t.Fatal(base, e)
	}
	again, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, first})
	if e != nil || again.Digest != base.Digest || again.SessionVersion != 3 {
		t.Fatal("lost-response retry", again, e)
	}
	if _, e = db.Exec(`UPDATE history SET value='updated-old-row' WHERE id=1; DELETE FROM history WHERE id=2; INSERT INTO history VALUES(10000,'new',NULL,NULL); ALTER TABLE empty_table ADD COLUMN extra INTEGER`); e != nil {
		t.Fatal(e)
	}
	target, e := s.BindMigrationRevision(ctx, id, 3, MigrationRevisionInput{"central", source, snapshot()})
	if e != nil || target.SessionVersion != 5 {
		t.Fatal(target, e)
	}
	if _, e = s.DB.Exec(`CREATE FUNCTION interrupt_delta() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.record_key=501 THEN RAISE EXCEPTION 'PRIVATE_DELTA_FAILURE'; END IF; RETURN NEW; END$$; CREATE TRIGGER interrupt_delta BEFORE INSERT ON v3_migration_delta_rows FOR EACH ROW EXECUTE FUNCTION interrupt_delta()`); e != nil {
		t.Fatal(e)
	}
	if r, e := s.CompareMigrationRevisions(ctx, id, 5, base.ID, target.ID); !errors.Is(e, ErrMigrationSession) || r.Added != 0 {
		t.Fatal(r, e)
	}
	var delta string
	var done int64
	if e = s.DB.QueryRow(`SELECT id,added+modified+deleted+unchanged FROM v3_migration_deltas WHERE session=$1`, id).Scan(&delta, &done); e != nil || done != 500 {
		t.Fatal(done, e)
	}
	if _, e = s.DB.Exec(`DROP TRIGGER interrupt_delta ON v3_migration_delta_rows`); e != nil {
		t.Fatal(e)
	}
	diff, e := s.ResumeMigrationDelta(ctx, id, 6, delta)
	if e != nil || diff.State != "ready" || diff.Added != 1 || diff.Modified != 1 || diff.Deleted != 1 || diff.Unchanged != 505 || diff.SchemaChanges != 1 || diff.SessionVersion != 7 {
		t.Fatal(diff, e)
	}
	retry, e := s.CompareMigrationRevisions(ctx, id, 5, base.ID, target.ID)
	if e != nil || retry.Digest != diff.Digest {
		t.Fatal(retry, e)
	}
	raw, _ := json.Marshal(state)
	if strings.Contains(string(raw), first) || strings.Contains(string(raw), "updated-old-row") {
		t.Fatal("private source exposed")
	}
	var keys int
	if e = s.DB.QueryRow(`SELECT count(*) FROM v3_migration_revision_rows WHERE revision=$1 AND record_key IN (-9223372036854775808,9007199254740993)`, target.ID).Scan(&keys); e != nil || keys != 2 {
		t.Fatal("wide rowid lost", keys, e)
	}
}
func TestMigrationSessionRejectsMutableSourceCheckpointAndForeignIdentity(t *testing.T) {
	s, id, source, db, snapshot := migrationSessionFixture(t)
	ctx := context.Background()
	first := snapshot()
	base, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, first})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`UPDATE history SET value='change' WHERE id=1`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.BindMigrationRevision(ctx, id, 3, MigrationRevisionInput{"central", digest([]byte("foreign")), snapshot()}); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("source identity changed", e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_revision_rows SET digest=repeat('a',64) WHERE revision=$1 AND record_key=1`, base.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ResumeMigrationRevision(ctx, id, 3, base.ID); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("tampered ready checkpoint accepted", e)
	}
	// A live WAL or a changed snapshot is never accepted as an immutable revision.
	if e = os.WriteFile(first+"-wal", []byte("synthetic"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ResumeMigrationRevision(ctx, id, 3, base.ID); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("live snapshot accepted", e)
	}
	if e = os.Remove(first + "-wal"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(first, []byte("not sqlite"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ResumeMigrationRevision(ctx, id, 3, base.ID); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("changed snapshot accepted", e)
	}
}
func TestMigrationSessionDeltaTamperAndVersionConflict(t *testing.T) {
	s, id, source, db, snapshot := migrationSessionFixture(t)
	ctx := context.Background()
	b, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, snapshot()})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`UPDATE history SET value='change' WHERE id=1`); e != nil {
		t.Fatal(e)
	}
	target, e := s.BindMigrationRevision(ctx, id, 3, MigrationRevisionInput{"central", source, snapshot()})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.CompareMigrationRevisions(ctx, id, 3, b.ID, target.ID); !errors.Is(e, ErrConflict) {
		t.Fatal("stale expected accepted", e)
	}
	d, e := s.CompareMigrationRevisions(ctx, id, 5, b.ID, target.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_delta_rows SET operation='DELETE' WHERE delta=$1 AND record_key=1`, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ResumeMigrationDelta(ctx, id, 7, d.ID); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("tampered delta accepted", e)
	}
}
