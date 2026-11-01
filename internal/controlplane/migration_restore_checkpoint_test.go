package controlplane

import (
	"context"
	"errors"
	"testing"
)

func TestLegacyPostgresRestoreUpgradeRetainsRecoveryHold(t *testing.T) {
	ctx := context.Background()
	// A real schema-v1 archive has neither recovery tables nor the newly
	// introduced restore checkpoint. It must still acquire the global hold.
	s := emptyTestStore(t)
	mustHistoryExec(t, s.DB, Schema)
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	header, err := inspectPGBackup(path)
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	var consumed bool
	if err = target.DB.QueryRow(`SELECT consumed FROM v3_migration_restore_checkpoint WHERE id=1`).Scan(&consumed); err != nil || consumed {
		t.Fatal(consumed, err)
	}
	if err = target.Migrate(ctx); err == nil {
		t.Fatal("upgraded restored old schema without backup")
	}
	if err = target.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	var generation, sha, phase string
	if err = target.DB.QueryRow(`SELECT generation,backup_sha256,phase FROM v3_migration_recovery_state WHERE id=1`).Scan(&generation, &sha, &phase); err != nil || sha != header.SHA256 || phase != "held" {
		t.Fatal(sha, phase, err)
	}
	if _, err = target.SaveSite(ctx, "admin", "restore-blocked", SiteInput{Name: "blocked", URL: "https://restore-blocked.example.test"}, 0); !errors.Is(err, ErrMigrationPending) {
		t.Fatal("old archive escaped restore fence", err)
	}
	if err = target.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var again string
	if err = target.DB.QueryRow(`SELECT generation FROM v3_migration_recovery_state WHERE id=1`).Scan(&again); err != nil || again != generation {
		t.Fatal("startup rearmed consumed checkpoint", err)
	}
	if err = target.DB.QueryRow(`SELECT consumed FROM v3_migration_restore_checkpoint WHERE id=1`).Scan(&consumed); err != nil || !consumed {
		t.Fatal(consumed, err)
	}
	// Re-archive the restored old shape before Upgrade: the checkpoint itself
	// is data in that old-version archive, but must be replaced by its new
	// verified outer archive rather than authorizing the older generation.
	old := emptyTestStore(t)
	if err = old.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	rebackup, err := old.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	newTarget := emptyTestStore(t)
	if err = newTarget.RestorePostgres(ctx, rebackup); err != nil {
		t.Fatal(err)
	}
	if err = newTarget.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	outer, _ := inspectPGBackup(rebackup)
	if err = newTarget.DB.QueryRow(`SELECT backup_sha256 FROM v3_migration_recovery_state WHERE id=1`).Scan(&sha); err != nil || sha != outer.SHA256 {
		t.Fatal("nested restore trusted stale checkpoint", err)
	}
}
