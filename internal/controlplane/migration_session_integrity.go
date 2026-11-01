package controlplane

import (
	"context"
	"database/sql"
)

// A ready revision is checked from its immutable local snapshot. A resume also
// proves that the saved prefix is complete, rather than trusting a max(rowid).
func verifyMigrationRevisionIndex(ctx context.Context, tx *sql.Tx, id string) error {
	var path string
	var state string
	if tx.QueryRowContext(ctx, `SELECT snapshot,state FROM v3_migration_revisions WHERE id=$1`, id).Scan(&path, &state) != nil || state != "ready" {
		return ErrMigrationSession
	}
	snap, e := openMigrationSnapshot(ctx, path)
	if e != nil {
		return ErrMigrationSession
	}
	defer snap.close()
	return verifyMigrationRevisionCheckpoint(ctx, tx, id, snap)
}
func verifyMigrationRevisionCheckpoint(ctx context.Context, tx *sql.Tx, id string, snap *migrationSnapshot) error {
	r, e := migrationRevisionTx(ctx, tx, id)
	if e != nil || r.Source != snap.sha {
		return ErrMigrationSession
	}
	var table string
	var cursor sql.NullInt64
	var done bool
	if tx.QueryRowContext(ctx, `SELECT cursor_table,cursor_key,cursor_done FROM v3_migration_revisions WHERE id=$1`, id).Scan(&table, &cursor, &done) != nil {
		return ErrMigrationSession
	}
	rows, e := tx.QueryContext(ctx, `SELECT table_name,records,schema_digest FROM v3_migration_revision_tables WHERE revision=$1 ORDER BY table_name COLLATE "C"`, id)
	if e != nil {
		return e
	}
	i := 0
	for rows.Next() {
		var name, hash string
		var count int64
		if e = rows.Scan(&name, &count, &hash); e != nil {
			break
		}
		if i >= len(snap.tables) || name != snap.tables[i].Name || count != snap.tables[i].Count || hash != snap.schemas[name] {
			e = ErrMigrationSession
			break
		}
		i++
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil || i != len(snap.tables) {
		return ErrMigrationSession
	}
	hash := migrationIndexSeed(snap.tables, snap.schemas)
	counts := map[string]int64{}
	var count int64
	var lastTable string
	var lastKey int64
	rows, e = tx.QueryContext(ctx, `SELECT i.table_name,i.record_key,i.digest,coalesce(a.digest,'') FROM v3_migration_revision_rows i LEFT JOIN v3_legacy_records a ON a.source=$2 AND a.table_name=i.table_name AND a.record_key=i.record_key::text WHERE i.revision=$1 ORDER BY i.table_name COLLATE "C",i.record_key`, id, snap.sha)
	if e != nil {
		return e
	}
	for rows.Next() {
		var name, digest, archived string
		var key int64
		if e = rows.Scan(&name, &key, &digest, &archived); e != nil {
			break
		}
		if !releaseDigest(digest) || digest != archived {
			e = ErrMigrationSession
			break
		}
		if _, ok := snap.schemas[name]; !ok {
			e = ErrMigrationSession
			break
		}
		hash = migrationIndexStep(hash, name, key, digest)
		counts[name]++
		count++
		lastTable, lastKey = name, key
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil || hash != r.Digest || count != r.Records {
		return ErrMigrationSession
	}
	if table == "" {
		if count != 0 || cursor.Valid || done {
			return ErrMigrationSession
		}
		return nil
	}
	found := false
	for _, t := range snap.tables {
		want := t.Count
		if t.Name == table {
			found = true
			if !done {
				if !cursor.Valid {
					return ErrMigrationSession
				}
				if snap.db.QueryRowContext(ctx, `SELECT count(*) FROM "`+t.Name+`" WHERE rowid<=?`, cursor.Int64).Scan(&want) != nil {
					return ErrMigrationSession
				}
			}
			if cursor.Valid {
				if lastTable != table || lastKey != cursor.Int64 {
					return ErrMigrationSession
				}
			} else if counts[table] != 0 {
				return ErrMigrationSession
			}
		} else if found {
			want = 0
		}
		if counts[t.Name] != want {
			return ErrMigrationSession
		}
	}
	if !found {
		return ErrMigrationSession
	}
	if r.State == "ready" {
		if !done || table != snap.tables[len(snap.tables)-1].Name {
			return ErrMigrationSession
		}
		for _, t := range snap.tables {
			if counts[t.Name] != t.Count {
				return ErrMigrationSession
			}
		}
	}
	if !snap.unchanged() {
		return ErrMigrationSession
	}
	return nil
}
func migrationDeltaOperation(before, after string) string {
	if before == "" {
		return "ADD"
	}
	if after == "" {
		return "DELETE"
	}
	if before != after {
		return "UPDATE"
	}
	return "UNCHANGED"
}
func verifyMigrationDeltaCheckpoint(ctx context.Context, tx *sql.Tx, r MigrationDeltaReport) error {
	b, e := migrationRevisionTx(ctx, tx, r.Base)
	if e != nil {
		return e
	}
	t, e := migrationRevisionTx(ctx, tx, r.Target)
	if e != nil {
		return e
	}
	hash := migrationDeltaSeed(b, t)
	counts := map[string]int64{}
	var count int64
	var lastTable string
	var lastKey int64
	rows, e := tx.QueryContext(ctx, `SELECT d.table_name,d.record_key,d.operation,d.before_digest,d.after_digest,coalesce(b.digest,''),coalesce(t.digest,'') FROM v3_migration_delta_rows d LEFT JOIN v3_migration_revision_rows b ON b.revision=$2 AND b.table_name=d.table_name AND b.record_key=d.record_key LEFT JOIN v3_migration_revision_rows t ON t.revision=$3 AND t.table_name=d.table_name AND t.record_key=d.record_key WHERE d.delta=$1 ORDER BY d.table_name COLLATE "C",d.record_key`, r.ID, r.Base, r.Target)
	if e != nil {
		return e
	}
	for rows.Next() {
		var table, op, before, after, actualBefore, actualAfter string
		var key int64
		if e = rows.Scan(&table, &key, &op, &before, &after, &actualBefore, &actualAfter); e != nil {
			break
		}
		if before != actualBefore || after != actualAfter || before == "" && after == "" || op != migrationDeltaOperation(before, after) {
			e = ErrMigrationSession
			break
		}
		hash = migrationDeltaStep(hash, table, key, op, before, after)
		counts[op]++
		count++
		lastTable, lastKey = table, key
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil || hash != r.Digest || counts["ADD"] != r.Added || counts["UPDATE"] != r.Modified || counts["DELETE"] != r.Deleted || counts["UNCHANGED"] != r.Unchanged {
		return ErrMigrationSession
	}
	var cursorTable string
	var cursor sql.NullInt64
	if tx.QueryRowContext(ctx, `SELECT cursor_table,cursor_key FROM v3_migration_deltas WHERE id=$1`, r.ID).Scan(&cursorTable, &cursor) != nil {
		return ErrMigrationSession
	}
	if count == 0 {
		if cursorTable != "" || cursor.Valid {
			return ErrMigrationSession
		}
	} else if !cursor.Valid || cursorTable != lastTable || cursor.Int64 != lastKey {
		return ErrMigrationSession
	}
	var want int64
	query := `SELECT count(*) FROM (SELECT coalesce(b.table_name,t.table_name) table_name,coalesce(b.record_key,t.record_key) record_key FROM (SELECT table_name,record_key FROM v3_migration_revision_rows WHERE revision=$1) b FULL JOIN (SELECT table_name,record_key FROM v3_migration_revision_rows WHERE revision=$2) t USING(table_name,record_key)) q`
	args := []any{r.Base, r.Target}
	if r.State != "ready" {
		query += ` WHERE $3<>'' AND (table_name COLLATE "C"<$3 COLLATE "C" OR table_name=$3 AND record_key<=$4)`
		args = append(args, cursorTable, cursor)
	}
	if tx.QueryRowContext(ctx, query, args...).Scan(&want) != nil || count != want {
		return ErrMigrationSession
	}
	var schemas int64
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT table_name,schema_digest FROM v3_migration_revision_tables WHERE revision=$1) b FULL JOIN (SELECT table_name,schema_digest FROM v3_migration_revision_tables WHERE revision=$2) t USING(table_name) WHERE b.schema_digest IS DISTINCT FROM t.schema_digest`, r.Base, r.Target).Scan(&schemas) != nil || schemas != r.SchemaChanges {
		return ErrMigrationSession
	}
	return nil
}
