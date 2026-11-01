package controlplane

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestMigrationReverseMetricJournalUpgradeDoesNotInventSealTime(t *testing.T) {
	ctx := context.Background()
	s, id := migrationTargetJournalFixture(t)
	armed, err := s.ArmMigrationTargetJournal(ctx, id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SealMigrationTargetJournal(ctx, id, armed.SessionVersion); err != nil {
		t.Fatal(err)
	}
	var created time.Time
	if err = s.DB.QueryRow(`SELECT created_at FROM v3_migration_target_journals WHERE session=$1`, id).Scan(&created); err != nil {
		t.Fatal(err)
	}
	// Reconstruct the actual prior private schema. Its existing creation time
	// is evidence; a missing historical seal time is not.
	mustHistoryExec(t, s.DB, `DROP TABLE v3_migration_reverse_metric_receipts;
ALTER TABLE v3_migration_target_journals DROP COLUMN began_at;
ALTER TABLE v3_migration_target_journals DROP COLUMN sealed_at;
DELETE FROM v3_schema WHERE version=52;`)
	if err = s.Migrate(ctx); err == nil {
		t.Fatal("schema upgrade skipped required backup")
	}
	if err = s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	var began time.Time
	var sealed sql.NullTime
	if err = s.DB.QueryRow(`SELECT began_at,sealed_at FROM v3_migration_target_journals WHERE session=$1`, id).Scan(&began, &sealed); err != nil || !began.Equal(created) || sealed.Valid {
		t.Fatal("upgrade manufactured timing evidence", began, sealed, err)
	}
	backup, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if err = target.DB.QueryRow(`SELECT began_at,sealed_at FROM v3_migration_target_journals WHERE session=$1`, id).Scan(&began, &sealed); err != nil || !began.Equal(created) || sealed.Valid {
		t.Fatal("restore manufactured timing evidence", began, sealed, err)
	}
}

func TestMigrationReverseMetricJournalSealTimestampSurvivesLostReply(t *testing.T) {
	ctx := context.Background()
	s, id := migrationTargetJournalFixture(t)
	armed, err := s.ArmMigrationTargetJournal(ctx, id, 1)
	if err != nil {
		t.Fatal(err)
	}
	var began time.Time
	var before sql.NullTime
	if err = s.DB.QueryRow(`SELECT began_at,sealed_at FROM v3_migration_target_journals WHERE session=$1`, id).Scan(&began, &before); err != nil || began.IsZero() || before.Valid {
		t.Fatal(began, before, err)
	}
	sealed, err := s.SealMigrationTargetJournal(ctx, id, armed.SessionVersion)
	if err != nil {
		t.Fatal(err)
	}
	var stamp time.Time
	if err = s.DB.QueryRow(`SELECT sealed_at FROM v3_migration_target_journals WHERE session=$1`, id).Scan(&stamp); err != nil || stamp.Before(began) {
		t.Fatal(stamp, began, err)
	}
	if _, err = s.SealMigrationTargetJournal(ctx, id, armed.SessionVersion); err != nil {
		t.Fatal(err)
	}
	var again time.Time
	if err = s.DB.QueryRow(`SELECT sealed_at FROM v3_migration_target_journals WHERE session=$1`, id).Scan(&again); err != nil || !again.Equal(stamp) {
		t.Fatal("lost reply moved metric cutoff", sealed, again, stamp, err)
	}
}
