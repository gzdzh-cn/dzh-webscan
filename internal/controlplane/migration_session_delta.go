package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
)

func migrationDeltaSeed(base, target MigrationRevisionReport) string {
	raw, _ := json.Marshal([]string{"webscan-v3/migration-delta/v1", base.ID, base.Digest, target.ID, target.Digest})
	return digest(raw)
}
func migrationDeltaStep(prior, table string, key int64, operation, before, after string) string {
	raw, _ := json.Marshal([]any{prior, table, key, operation, before, after})
	return digest(raw)
}
func migrationDeltaTx(ctx context.Context, tx *sql.Tx, id string) (MigrationDeltaReport, error) {
	var r MigrationDeltaReport
	e := tx.QueryRowContext(ctx, `SELECT d.id,r.role,d.base,d.target,d.state,d.added,d.modified,d.deleted,d.unchanged,d.schema_changes,d.digest FROM v3_migration_deltas d JOIN v3_migration_revisions r ON r.id=d.target WHERE d.id=$1`, id).Scan(&r.ID, &r.Role, &r.Base, &r.Target, &r.State, &r.Added, &r.Modified, &r.Deleted, &r.Unchanged, &r.SchemaChanges, &r.Digest)
	return r, e
}
func (s *Store) compareMigrationRevisions(ctx context.Context, id string, expected int64, base, target string) (MigrationDeltaReport, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return MigrationDeltaReport{}, e
	}
	defer tx.Rollback()
	if e = migrationSessionLock(ctx, tx, id); e != nil {
		return MigrationDeltaReport{}, e
	}
	session, e := migrationSessionTx(ctx, tx, id)
	if e != nil {
		return MigrationDeltaReport{}, e
	}
	if session.RecoveryHold || session.Phase != "collecting" && session.Phase != "indexed" && session.Phase != "frozen" {
		return MigrationDeltaReport{}, ErrMigrationSession
	}
	delta := digest([]byte(id + ":" + base + ":" + target))
	var original, finished int64
	e = tx.QueryRowContext(ctx, `SELECT request_version,finished_version FROM v3_migration_deltas WHERE id=$1 AND session=$2`, delta, id).Scan(&original, &finished)
	if e == nil {
		if expected != session.Version && (expected != original || session.Version != finished) {
			return MigrationDeltaReport{}, ErrConflict
		}
		r, e := migrationDeltaTx(ctx, tx, delta)
		if e != nil {
			return r, e
		}
		if session.RecoveryHold || session.Phase != "collecting" && session.Phase != "indexed" && session.Phase != "frozen" {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		r.SessionVersion = session.Version
		if e = tx.Commit(); e != nil {
			return r, e
		}
		return s.ResumeMigrationDelta(ctx, id, session.Version, delta)
	}
	if e != sql.ErrNoRows {
		return MigrationDeltaReport{}, ErrMigrationSession
	}
	if session.Version != expected {
		return MigrationDeltaReport{}, ErrConflict
	}
	if session.Phase != "indexed" && session.Phase != "collecting" && session.Phase != "frozen" {
		return MigrationDeltaReport{}, ErrMigrationSession
	}
	b, e := migrationRevisionTx(ctx, tx, base)
	if e != nil {
		return MigrationDeltaReport{}, ErrMigrationSession
	}
	t, e := migrationRevisionTx(ctx, tx, target)
	if e != nil || b.Role != t.Role || b.Sequence >= t.Sequence {
		return MigrationDeltaReport{}, ErrMigrationSession
	}
	if session.Phase == "frozen" {
		var authorized bool
		if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_migration_freezes WHERE session=$1 AND role=$2 AND revision=$3)`, id, t.Role, target).Scan(&authorized) != nil || !authorized {
			return MigrationDeltaReport{}, ErrMigrationSession
		}
	}
	var belongs bool
	if tx.QueryRowContext(ctx, `SELECT (SELECT session=$3 FROM v3_migration_revisions WHERE id=$1) AND (SELECT session=$3 FROM v3_migration_revisions WHERE id=$2) AND (SELECT source_id FROM v3_migration_revisions WHERE id=$1)=(SELECT source_id FROM v3_migration_revisions WHERE id=$2)`, base, target, id).Scan(&belongs) != nil || !belongs {
		return MigrationDeltaReport{}, ErrMigrationSession
	}
	if e = verifyMigrationRevisionIndex(ctx, tx, base); e != nil {
		return MigrationDeltaReport{}, ErrMigrationSession
	}
	if e = verifyMigrationRevisionIndex(ctx, tx, target); e != nil {
		return MigrationDeltaReport{}, ErrMigrationSession
	}
	var busy bool
	if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_migration_revisions WHERE session=$1 AND state='indexing') OR EXISTS(SELECT 1 FROM v3_migration_deltas WHERE session=$1 AND state='comparing')`, id).Scan(&busy) != nil || busy {
		return MigrationDeltaReport{}, ErrMigrationSession
	}
	var schemas int64
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT table_name,schema_digest FROM v3_migration_revision_tables WHERE revision=$1) b FULL JOIN (SELECT table_name,schema_digest FROM v3_migration_revision_tables WHERE revision=$2) t USING(table_name) WHERE b.schema_digest IS DISTINCT FROM t.schema_digest`, base, target).Scan(&schemas) != nil {
		return MigrationDeltaReport{}, ErrMigrationSession
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_deltas(id,session,base,target,request_version,schema_changes,digest) VALUES($1,$2,$3,$4,$5,$6,$7)`, delta, id, base, target, expected, schemas, migrationDeltaSeed(b, t)); e != nil {
		return MigrationDeltaReport{}, ErrMigrationSession
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,updated_at=clock_timestamp() WHERE id=$1`, id); e != nil {
		return MigrationDeltaReport{}, e
	}
	if e = tx.Commit(); e != nil {
		return MigrationDeltaReport{}, e
	}
	return s.ResumeMigrationDelta(ctx, id, expected+1, delta)
}
func (s *Store) resumeMigrationDelta(ctx context.Context, id string, expected int64, delta string) (MigrationDeltaReport, error) {
	// Verify both immutable indexes before resuming a durable comparison.
	verified := false
	for {
		tx, e := s.DB.BeginTx(ctx, nil)
		if e != nil {
			return MigrationDeltaReport{}, e
		}
		if e = migrationSessionLock(ctx, tx, id); e != nil {
			tx.Rollback()
			return MigrationDeltaReport{}, e
		}
		session, e := migrationSessionTx(ctx, tx, id)
		if e != nil {
			tx.Rollback()
			return MigrationDeltaReport{}, e
		}
		r, e := migrationDeltaTx(ctx, tx, delta)
		if e != nil {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		if session.RecoveryHold || session.Phase != "collecting" && session.Phase != "indexed" && session.Phase != "frozen" {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		r.SessionVersion = session.Version
		var original, finished int64
		var cursorTable string
		var cursor sql.NullInt64
		var belongs bool
		if tx.QueryRowContext(ctx, `SELECT session=$2,request_version,finished_version,cursor_table,cursor_key FROM v3_migration_deltas WHERE id=$1`, delta, id).Scan(&belongs, &original, &finished, &cursorTable, &cursor) != nil || !belongs {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		if !verified {
			if verifyMigrationRevisionIndex(ctx, tx, r.Base) != nil || verifyMigrationRevisionIndex(ctx, tx, r.Target) != nil || verifyMigrationDeltaCheckpoint(ctx, tx, r) != nil {
				tx.Rollback()
				return r, ErrMigrationSession
			}
			verified = true
		}
		if r.State == "ready" {
			tx.Rollback()
			if expected != session.Version && (expected != original+1 || session.Version != finished) {
				return r, ErrConflict
			}
			return r, nil
		}
		if session.Version != expected || session.Phase != "indexed" && session.Phase != "collecting" && session.Phase != "frozen" {
			tx.Rollback()
			return r, ErrConflict
		}
		rows, e := tx.QueryContext(ctx, `SELECT coalesce(b.table_name,t.table_name),coalesce(b.record_key,t.record_key),coalesce(b.digest,''),coalesce(t.digest,'') FROM (SELECT table_name,record_key,digest FROM v3_migration_revision_rows WHERE revision=$1) b FULL JOIN (SELECT table_name,record_key,digest FROM v3_migration_revision_rows WHERE revision=$2) t USING(table_name,record_key) WHERE $3='' OR coalesce(b.table_name,t.table_name) COLLATE "C">$3 COLLATE "C" OR (coalesce(b.table_name,t.table_name)=$3 AND coalesce(b.record_key,t.record_key)>$4) ORDER BY coalesce(b.table_name,t.table_name) COLLATE "C",coalesce(b.record_key,t.record_key) LIMIT 500`, r.Base, r.Target, cursorTable, cursor)
		if e != nil {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		type item struct {
			table, before, after string
			key                  int64
		}
		items := []item{}
		for rows.Next() {
			var i item
			if e = rows.Scan(&i.table, &i.key, &i.before, &i.after); e != nil {
				break
			}
			items = append(items, i)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		for _, i := range items {
			operation := "UNCHANGED"
			switch {
			case i.before == "":
				operation = "ADD"
				r.Added++
			case i.after == "":
				operation = "DELETE"
				r.Deleted++
			case i.before != i.after:
				operation = "UPDATE"
				r.Modified++
			default:
				r.Unchanged++
			}
			if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_delta_rows(delta,table_name,record_key,operation,before_digest,after_digest) VALUES($1,$2,$3,$4,$5,$6)`, delta, i.table, i.key, operation, i.before, i.after); e != nil {
				tx.Rollback()
				return r, ErrMigrationSession
			}
			r.Digest = migrationDeltaStep(r.Digest, i.table, i.key, operation, i.before, i.after)
			cursorTable = i.table
			cursor = sql.NullInt64{Int64: i.key, Valid: true}
		}
		ready := len(items) < 500
		state := "comparing"
		if ready {
			state = "ready"
			finished = expected + 1
		}
		if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_deltas SET cursor_table=$2,cursor_key=$3,added=$4,modified=$5,deleted=$6,unchanged=$7,digest=$8,state=$9,finished_version=$10 WHERE id=$1`, delta, cursorTable, cursor, r.Added, r.Modified, r.Deleted, r.Unchanged, r.Digest, state, finished); e != nil {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		if ready {
			if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,updated_at=clock_timestamp() WHERE id=$1`, id); e != nil {
				tx.Rollback()
				return r, e
			}
		}
		if e = tx.Commit(); e != nil {
			return r, e
		}
		if ready {
			r.State, r.SessionVersion = "ready", expected+1
			return r, nil
		}
	}
}
