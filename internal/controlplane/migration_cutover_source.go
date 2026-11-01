package controlplane

import (
	"context"
	"database/sql"
	"os"

	"webscan/internal/persist"
)

// Compare the current frozen source's logical SQLite contents (including WAL)
// with the indexed final generation. File hashes alone cannot compare a WAL
// source with its compact consistent-backup copy.
func migrationVerifySourceContents(ctx context.Context, pg *sql.Tx, revision, path string) error {
	f, err := openTrustFile(path, true, 1<<40)
	if err != nil {
		return ErrMigrationSession
	}
	defer f.Close()
	db, err := persist.OpenReadOnly(path)
	if err != nil {
		return ErrMigrationSession
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ErrMigrationSession
	}
	defer tx.Rollback()
	var integrity string
	if tx.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity) != nil || integrity != "ok" {
		return ErrMigrationSession
	}
	rows, err := tx.QueryContext(ctx, `SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return ErrMigrationSession
	}
	tables := []TableInventory{}
	schemas := map[string]string{}
	for rows.Next() {
		var name, ddl string
		if err = rows.Scan(&name, &ddl); err != nil || !identifier.MatchString(name) {
			rows.Close()
			return ErrMigrationSession
		}
		tables = append(tables, TableInventory{Name: name})
		schemas[name] = digest([]byte(ddl))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ErrMigrationSession
	}
	for i := range tables {
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM `+quotePG(tables[i].Name)).Scan(&tables[i].Count) != nil {
			return ErrMigrationSession
		}
	}
	hash := migrationIndexSeed(tables, schemas)
	var count int64
	for _, table := range tables {
		rows, err = tx.QueryContext(ctx, `SELECT rowid,* FROM `+quotePG(table.Name)+` ORDER BY rowid`)
		if err != nil {
			return ErrMigrationSession
		}
		cols, e := rows.Columns()
		if e != nil {
			rows.Close()
			return ErrMigrationSession
		}
		for rows.Next() {
			values := make([]any, len(cols))
			dest := make([]any, len(cols))
			for i := range values {
				dest[i] = &values[i]
			}
			if err = rows.Scan(dest...); err != nil {
				rows.Close()
				return ErrMigrationSession
			}
			key, raw, e := migrationArchiveRow(cols, values)
			if e != nil {
				rows.Close()
				return ErrMigrationSession
			}
			hash = migrationIndexStep(hash, table.Name, key, digest(raw))
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return ErrMigrationSession
		}
	}
	r, err := migrationRevisionTx(ctx, pg, revision)
	if err != nil || r.Digest != hash || r.Records != count {
		return ErrMigrationSession
	}
	opened, err := f.Stat()
	current, e := os.Lstat(path)
	if err != nil || e != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return ErrMigrationSession
	}
	return tx.Commit()
}
