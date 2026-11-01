package controlplane

import (
	"context"
	"errors"
	"testing"
)

func installMigrationTargetTestRecoveryGuard(t *testing.T, s *Store) error {
	t.Helper()
	ctx := context.Background()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(773376002)`); e != nil {
		return e
	}
	if e = installMigrationTargetRecoveryGuardsTx(ctx, tx); e != nil {
		return e
	}
	return tx.Commit()
}

func TestMigrationTargetJournalRecoveryGuardRejectsUnheldAndProtectsDirectWrites(t *testing.T) {
	s, id := migrationTargetJournalFixture(t)
	ctx := context.Background()
	if _, e := s.ArmMigrationTargetJournal(ctx, id, 1); e != nil {
		t.Fatal(e)
	}
	if e := installMigrationTargetTestRecoveryGuard(t, s); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("non-recovery database guarded", e)
	}
	// Restore does not carry the dynamic capture function; remove it here to
	// prove that the independent guard, rather than capture, stops direct SQL.
	if _, e := s.DB.Exec(`DROP FUNCTION v3_migration_capture_change() CASCADE`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec(`UPDATE v3_migration_sessions SET recovery_hold=true WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	if e := installMigrationTargetTestRecoveryGuard(t, s); e != nil {
		t.Fatal(e)
	}
	if e := installMigrationTargetTestRecoveryGuard(t, s); e != nil {
		t.Fatal("guard reinstall must verify", e)
	}
	for _, query := range []string{
		`INSERT INTO v3_accounts(username,password_hash,role) VALUES('bypass','synthetic','viewer')`,
		`UPDATE v3_accounts SET role='viewer'`,
		`DELETE FROM v3_accounts`,
		`TRUNCATE v3_accounts CASCADE`,
		`INSERT INTO v3_events_default(node,id,received_at,operation,payload) VALUES('synthetic','partition-direct',clock_timestamp(),'modify','{}')`,
		`TRUNCATE v3_events_default`,
	} {
		if _, e := s.DB.Exec(query); e == nil {
			t.Fatal("un-gated write bypassed recovery guard")
		}
	}
	if _, e := s.DB.Exec(`UPDATE v3_migration_sessions SET recovery_hold=false WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec(`INSERT INTO v3_accounts(username,password_hash,role) VALUES('hold-cleared','synthetic','viewer')`); e == nil {
		t.Fatal("clearing recovery_hold enabled unjournaled writes")
	}
}

func TestMigrationTargetJournalLogicalRestoreRetainsEvidenceAndWriteGuard(t *testing.T) {
	s, id := migrationTargetJournalFixture(t)
	ctx := context.Background()
	if _, e := s.ArmMigrationTargetJournal(ctx, id, 1); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec(`INSERT INTO v3_accounts(username,password_hash,role) VALUES('post-switch','synthetic','viewer')`); e != nil {
		t.Fatal(e)
	}
	path, e := s.BackupPostgres(ctx, privateTestDir(t))
	if e != nil {
		t.Fatal(e)
	}
	target := emptyTestStore(t)
	if e = target.RestorePostgres(ctx, path); e != nil {
		t.Fatal(e)
	}
	// The restore caller installs the helper last in its transaction. Keeping
	// this explicit invocation also verifies idempotence after integration.
	if e = installMigrationTargetTestRecoveryGuard(t, target); e != nil {
		t.Fatal(e)
	}
	var held bool
	var preserved int
	if e = target.DB.QueryRow(`SELECT recovery_hold FROM v3_migration_sessions WHERE id=$1`, id).Scan(&held); e != nil || !held {
		t.Fatal("restored session not held", e)
	}
	if e = target.DB.QueryRow(`SELECT count(*) FROM v3_migration_target_changes WHERE session=$1 AND table_name='v3_accounts' AND after_key->>'username'='post-switch'`, id).Scan(&preserved); e != nil || preserved != 1 {
		t.Fatal("post-switch change evidence lost", e)
	}
	if _, e = target.DB.Exec(`DELETE FROM v3_accounts WHERE username='post-switch'`); e == nil {
		t.Fatal("restored direct write accepted")
	}
	if _, e = target.DB.Exec(`TRUNCATE v3_events CASCADE`); e == nil {
		t.Fatal("restored truncate accepted")
	}
}
