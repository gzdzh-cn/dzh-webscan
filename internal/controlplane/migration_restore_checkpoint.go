package controlplane

import (
	"context"
	"database/sql"
	"time"
)

// Independent of the archive schema version: even a v1 backup restored by the
// current executable carries its actual restore checkpoint into Upgrade. This
// table is private recovery evidence, never business data or a live lease.
const migrationRestoreCheckpointSchema = `
CREATE TABLE IF NOT EXISTS v3_migration_restore_checkpoint(
 id integer PRIMARY KEY CHECK(id=1),backup_sha256 text NOT NULL,
 backup_at timestamptz,consumed boolean NOT NULL DEFAULT false
);`

func recordMigrationRestoreCheckpointTx(ctx context.Context, tx *sql.Tx, header pgBackupLine) error {
	if !releaseDigest(header.SHA256) {
		return ErrMigrationRecovery
	}
	if _, err := tx.ExecContext(ctx, migrationRestoreCheckpointSchema); err != nil {
		return err
	}
	var at any
	if !header.SnapshotAt.IsZero() {
		at = header.SnapshotAt.UTC()
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO v3_migration_restore_checkpoint(id,backup_sha256,backup_at,consumed) VALUES(1,$1,$2,false) ON CONFLICT(id) DO UPDATE SET backup_sha256=excluded.backup_sha256,backup_at=excluded.backup_at,consumed=false`, header.SHA256, at)
	return err
}

func consumeMigrationRestoreCheckpointTx(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, migrationRestoreCheckpointSchema); err != nil {
		return err
	}
	var sha string
	var at sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT backup_sha256,backup_at FROM v3_migration_restore_checkpoint WHERE id=1 AND NOT consumed FOR UPDATE`).Scan(&sha, &at)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	var stamp time.Time
	if at.Valid {
		stamp = at.Time
	}
	if err := HoldMigrationRecoveryTx(ctx, tx, sha, stamp); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE v3_migration_restore_checkpoint SET consumed=true WHERE id=1`)
	return err
}
