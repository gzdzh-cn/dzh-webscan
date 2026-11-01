package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"webscan/internal/common"
	"webscan/internal/persist"
)

func migrationFinalFixture(t *testing.T) (*Store, string, string, *sql.DB, func() string, *Vault) {
	t.Helper()
	s := migrationSessionTestStore(t)
	var exists bool
	if e := s.DB.QueryRow(`SELECT to_regclass('v3_migration_final_batches') IS NOT NULL`).Scan(&exists); e != nil {
		t.Fatal(e)
	}
	if !exists {
		if _, e := s.DB.Exec(migrationFinalMappingSchema); e != nil {
			t.Fatal(e)
		}
	}
	ctx := context.Background()
	id := digest([]byte(t.Name()))
	source := digest([]byte("central-source"))
	if _, e := s.BeginMigrationSession(ctx, id, 0, []string{"central"}); e != nil {
		t.Fatal(e)
	}
	db, _, _ := legacyWebsiteFixture(t, 3)
	root := privateTestDir(t)
	snapshot := func() string {
		path := filepath.Join(root, "snapshot-"+token()+".sqlite3")
		if e := persist.BackupDB(db, path); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(path, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	v, _ := testVault(t)
	return s, id, source, db, snapshot, v
}

func TestMigrationFinalQueueHealthDeltaPreservesIDsAndAtomicAssociations(t *testing.T) {
	ctx := context.Background()
	s := migrationSessionTestStore(t)
	var exists bool
	if e := s.DB.QueryRow(`SELECT to_regclass('v3_migration_final_batches') IS NOT NULL`).Scan(&exists); e != nil {
		t.Fatal(e)
	}
	if !exists {
		if _, e := s.DB.Exec(migrationFinalMappingSchema); e != nil {
			t.Fatal(e)
		}
	}
	id := digest([]byte(t.Name()))
	state, e := s.BeginMigrationSession(ctx, id, 0, []string{"central", "health"})
	if e != nil {
		t.Fatal(e)
	}
	f := legacyHistoryFixture(t)
	f.event(t, "old-event", "node-old", "memory", "original-batch", nil)
	f.task(t, 41, "native:original-batch", "feishu", common.Map{"source": "health", "node_id": "node-old", "notice_kind": "firing", "message": "原告警 old-event"}, float64(f.at)+.5)
	seedLegacyFile(t, f, "native-receipt", legacyFilePayload("node-old", "native-receipt"))
	root := privateTestDir(t)
	snapshot := func(db *sql.DB) string {
		path := filepath.Join(root, "snapshot-"+token()+".sqlite3")
		if e := persist.BackupDB(db, path); e != nil {
			t.Fatal(e)
		}
		return path
	}
	r, e := s.BindMigrationRevision(ctx, id, state.Version, MigrationRevisionInput{"central", digest([]byte("central")), snapshot(f.queue)})
	if e != nil {
		t.Fatal(e)
	}
	r, e = s.BindMigrationRevision(ctx, id, r.SessionVersion, MigrationRevisionInput{"health", digest([]byte("health")), snapshot(f.health)})
	if e != nil {
		t.Fatal(e)
	}
	v, _ := testVault(t)
	mapped, e := s.MapMigrationFinalDomains(ctx, id, r.SessionVersion, MigrationFinalMappingInput{}, v)
	if e != nil || !mapped.Complete {
		t.Fatal(mapped, e)
	}
	var notice int64
	var done bool
	if e = s.DB.QueryRow(`SELECT id FROM v3_notifications`).Scan(&notice); e != nil {
		t.Fatal(e)
	}
	if e = s.DB.QueryRow(`SELECT done_at IS NOT NULL FROM v3_health_batches WHERE id='original-batch'`).Scan(&done); e != nil || !done {
		t.Fatal(done, e)
	}
	if _, e = f.queue.Exec(`UPDATE tasks SET result='original-updated',attempts=attempts+1 WHERE id=41`); e != nil {
		t.Fatal(e)
	}
	r, e = s.BindMigrationRevision(ctx, id, mapped.SessionVersion, MigrationRevisionInput{"central", digest([]byte("central")), snapshot(f.queue)})
	if e != nil {
		t.Fatal(e)
	}
	mapped, e = s.MapMigrationFinalDomains(ctx, id, r.SessionVersion, MigrationFinalMappingInput{}, v)
	if e != nil || !mapped.Complete {
		t.Fatal(mapped, e)
	}
	var again int64
	if e = s.DB.QueryRow(`SELECT id FROM v3_notifications`).Scan(&again); e != nil || again != notice {
		t.Fatal(again, notice, e)
	}
	if _, e = f.queue.Exec(`DELETE FROM tasks WHERE id=41;DELETE FROM events`); e != nil {
		t.Fatal(e)
	}
	r, e = s.BindMigrationRevision(ctx, id, mapped.SessionVersion, MigrationRevisionInput{"central", digest([]byte("central")), snapshot(f.queue)})
	if e != nil {
		t.Fatal(e)
	}
	mapped, e = s.MapMigrationFinalDomains(ctx, id, r.SessionVersion, MigrationFinalMappingInput{}, v)
	if e != nil || !mapped.Complete {
		t.Fatal(mapped, e)
	}
	for _, table := range []string{"v3_notifications", "v3_notification_public", "v3_events", "v3_event_keys"} {
		if tableCount(t, s, table) != 0 {
			t.Fatalf("stale rows in %s", table)
		}
	}
}

func TestMigrationFinalRealWebsiteDeltaAndOwnedCAS(t *testing.T) {
	s, id, source, db, snapshot, v := migrationFinalFixture(t)
	ctx := context.Background()
	rev, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, snapshot()})
	if e != nil {
		t.Fatal(e)
	}
	first, e := s.MapMigrationFinalDomains(ctx, id, rev.SessionVersion, MigrationFinalMappingInput{}, v)
	if e != nil || !first.Complete || first.Added != 6 || first.ReadyForCutover || !first.Protected {
		t.Fatal(first, e)
	}
	again, e := s.MapMigrationFinalDomains(ctx, id, rev.SessionVersion, MigrationFinalMappingInput{}, v)
	if e != nil || again.Batch != first.Batch || again.SessionVersion != first.SessionVersion {
		t.Fatal(again, e)
	}
	if _, e = db.Exec(`UPDATE websites SET name='最终名称',version=version+1 WHERE id=1; DELETE FROM websites WHERE id=3; INSERT INTO websites VALUES(4,'新增网站','https://added.example.test/','node-old','',1,0,0,1,'{}')`); e != nil {
		t.Fatal(e)
	}
	rev, e = s.BindMigrationRevision(ctx, id, first.SessionVersion, MigrationRevisionInput{"central", source, snapshot()})
	if e != nil {
		t.Fatal(e)
	}
	next, e := s.MapMigrationFinalDomains(ctx, id, rev.SessionVersion, MigrationFinalMappingInput{}, v)
	if e != nil || next.Added != 1 || next.Modified != 1 || next.Deleted != 1 || !next.Complete {
		t.Fatal(next, e)
	}
	var name string
	if e = s.DB.QueryRow(`SELECT name FROM v3_websites WHERE id=1`).Scan(&name); e != nil || name != "最终名称" {
		t.Fatal(name, e)
	}
	var n int
	if e = s.DB.QueryRow(`SELECT count(*) FROM v3_websites WHERE id=3`).Scan(&n); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_websites SET name='foreign-edit' WHERE id=1`); e != nil {
		t.Fatal(e)
	}
	conflict, e := s.MapMigrationFinalDomains(ctx, id, next.SessionVersion, MigrationFinalMappingInput{}, v)
	if !errors.Is(e, ErrConflict) || len(conflict.Conflicts) != 1 {
		t.Fatal(conflict, e)
	}
	if e = s.DB.QueryRow(`SELECT name FROM v3_websites WHERE id=1`).Scan(&name); e != nil || name != "foreign-edit" {
		t.Fatal(name, e)
	}
}
func TestMigrationFinalForeignSameContentNeverAdoptedAndFailureAtomic(t *testing.T) {
	s, id, source, _, snapshot, v := migrationFinalFixture(t)
	ctx := context.Background()
	rev, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, snapshot()})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`INSERT INTO v3_accounts(username,password_hash,revision,role) VALUES('original-admin','foreign-hash',7,'admin')`); e != nil {
		t.Fatal(e)
	}
	r, e := s.MapMigrationFinalDomains(ctx, id, rev.SessionVersion, MigrationFinalMappingInput{}, v)
	if !errors.Is(e, ErrConflict) || len(r.Conflicts) != 1 {
		t.Fatal(r, e)
	}
	var count int
	if e = s.DB.QueryRow(`SELECT count(*) FROM v3_migration_final_owned`).Scan(&count); e != nil || count != 0 {
		t.Fatal(count, e)
	}
	if _, e = s.DB.Exec(`DELETE FROM v3_accounts;CREATE FUNCTION final_mapping_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic'; END$$;CREATE TRIGGER final_mapping_fail BEFORE INSERT ON v3_websites FOR EACH ROW EXECUTE FUNCTION final_mapping_fail()`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.MapMigrationFinalDomains(ctx, id, rev.SessionVersion, MigrationFinalMappingInput{}, v); e == nil {
		t.Fatal("injected failure accepted")
	}
	if e = s.DB.QueryRow(`SELECT (SELECT count(*) FROM v3_accounts)+(SELECT count(*) FROM v3_migration_final_batches)`).Scan(&count); e != nil || count != 0 {
		t.Fatal(count, e)
	}
}

func TestMigrationFinalRechecksMetricEvidenceOnReadinessAndReceiptRetry(t *testing.T) {
	f := newMetricHistoryFixture(t)
	ctx := context.Background()
	v, _ := testVault(t)
	var e error
	var source string
	if e = f.s.DB.QueryRow(`SELECT source_id FROM v3_migration_revisions WHERE id=$1`, f.revision.ID).Scan(&source); e != nil {
		t.Fatal(e)
	}
	manifest := migrationFreezeTestManifest(t, f.session.ID, source, f.snapshot)
	parsed, _, e := readMigrationFreezeManifest(manifest, f.session.ID)
	if e != nil {
		t.Fatal(e)
	}
	parsed.Sources[0].Role = "health"
	if e = os.WriteFile(manifest, common.JSON(parsed), 0600); e != nil {
		t.Fatal(e)
	}
	frozen, e := f.s.freezeMigrationSession(ctx, f.session.ID, f.session.Version, manifest, privateTestDir(t), func(context.Context, MigrationFreezeSource) (string, error) {
		return digest([]byte("isolated stopped writer")), nil
	})
	if e != nil {
		t.Fatal(e)
	}
	var revision string
	if e = f.s.DB.QueryRow(`SELECT id FROM v3_migration_revisions WHERE session=$1 AND role='health' ORDER BY sequence DESC LIMIT 1`, f.session.ID).Scan(&revision); e != nil {
		t.Fatal(e)
	}
	prepared, e := f.s.PrepareMigrationMetricHistory(ctx, f.m, f.session.ID, frozen.Version, revision)
	if e != nil {
		t.Fatal(e)
	}
	run, e := f.s.RunMigrationMetricHistory(ctx, f.m, f.session.ID, frozen.Version, prepared.Generation)
	if e != nil || run.State != "verified" {
		t.Fatal(run, e)
	}
	mapped, e := f.s.MapMigrationFinalDomains(ctx, f.session.ID, frozen.Version, MigrationFinalMappingInput{}, v)
	if e != nil || !mapped.Complete {
		t.Fatal(mapped, e)
	}
	frozen.Version = mapped.SessionVersion
	verify := func() (bool, error) {
		tx, e := f.s.DB.Begin()
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		return VerifyMigrationFinalDomainsTx(ctx, tx, f.session.ID, v)
	}
	if ok, e := verify(); e != nil || !ok {
		t.Fatal("valid mapped history rejected", ok, e)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_migration_metric_runs SET state='pending' WHERE id=$1`, run.Generation)
	if ok, e := verify(); e == nil && ok {
		t.Fatal("stale final receipt bypassed revoked metric proof")
	}
	if _, e = f.s.MapMigrationFinalDomains(ctx, f.session.ID, frozen.Version, MigrationFinalMappingInput{}, v); e == nil {
		t.Fatal("final receipt retry bypassed revoked metric proof")
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_migration_metric_runs SET state='verified' WHERE id=$1`, run.Generation)
	if ok, e := verify(); e != nil || !ok {
		t.Fatal("restored authenticated proof rejected", ok, e)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_migration_metric_rows SET projected_digest=repeat('0',64) WHERE run=$1`, run.Generation)
	if ok, e := verify(); e == nil && ok {
		t.Fatal("changed metric rows bypassed final readiness")
	}
}
