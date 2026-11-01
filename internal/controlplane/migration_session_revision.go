package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"webscan/internal/persist"
)

type migrationSnapshot struct {
	file      *os.File
	db        *sql.DB
	path, sha string
	tables    []TableInventory
	schemas   map[string]string
}

func migrationFileDigest(f *os.File) (string, error) {
	if _, e := f.Seek(0, 0); e != nil {
		return "", e
	}
	h := sha256.New()
	if _, e := io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func openMigrationSnapshot(ctx context.Context, path string) (*migrationSnapshot, error) {
	f, e := openTrustFile(path, true, 1<<40)
	if e != nil {
		return nil, ErrMigrationSession
	}
	fail := func() (*migrationSnapshot, error) { f.Close(); return nil, ErrMigrationSession }
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, e := os.Lstat(path + suffix); !os.IsNotExist(e) {
			return fail()
		}
	}
	sha, e := migrationFileDigest(f)
	if e != nil {
		return fail()
	}
	db, e := persist.OpenReadOnly(path)
	if e != nil {
		return fail()
	}
	var integrity string
	if db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity) != nil || integrity != "ok" {
		db.Close()
		return fail()
	}
	tables, e := inventory(ctx, db)
	if e != nil {
		db.Close()
		return fail()
	}
	schemas := map[string]string{}
	for _, table := range tables {
		var definition string
		if e = db.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table.Name).Scan(&definition); e != nil {
			db.Close()
			return fail()
		}
		schemas[table.Name] = digest([]byte(definition))
	}
	return &migrationSnapshot{file: f, db: db, path: path, sha: sha, tables: tables, schemas: schemas}, nil
}
func (m *migrationSnapshot) close() { m.db.Close(); m.file.Close() }
func (m *migrationSnapshot) unchanged() bool {
	opened, e := m.file.Stat()
	now, ne := os.Lstat(m.path)
	hash, he := migrationFileDigest(m.file)
	return e == nil && ne == nil && he == nil && now.Mode().IsRegular() && os.SameFile(opened, now) && hash == m.sha
}
func migrationIndexSeed(tables []TableInventory, schemas map[string]string) string {
	raw, _ := json.Marshal(struct {
		Tables  []TableInventory
		Schemas map[string]string
	}{tables, schemas})
	return digest(append([]byte("webscan-v3/migration-index/v1\x00"), raw...))
}
func migrationIndexStep(prior, table string, key int64, hash string) string {
	raw, _ := json.Marshal([]string{prior, table, strconv.FormatInt(key, 10), hash})
	return digest(raw)
}
func migrationArchiveRow(columns []string, values []any) (int64, []byte, error) {
	key, ok := values[0].(int64)
	if !ok {
		return 0, nil, ErrMigrationSession
	}
	payload := map[string]any{}
	for i, name := range columns[1:] {
		var field map[string]any
		switch v := values[i+1].(type) {
		case nil:
			field = map[string]any{"type": "null"}
		case int64:
			field = map[string]any{"type": "integer", "value": strconv.FormatInt(v, 10)}
		case float64:
			field = map[string]any{"type": "real", "value": strconv.FormatFloat(v, 'g', -1, 64)}
		case []byte:
			field = map[string]any{"type": "blob", "value": base64.StdEncoding.EncodeToString(v)}
		case string:
			if !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
				return 0, nil, ErrMigrationSession
			}
			field = map[string]any{"type": "text", "value": v}
		default:
			return 0, nil, ErrMigrationSession
		}
		payload[name] = field
	}
	raw, e := json.Marshal(payload)
	if e != nil || len(raw) > 8<<20 {
		return 0, nil, ErrMigrationSession
	}
	return key, raw, nil
}
func migrationRevisionTx(ctx context.Context, tx *sql.Tx, id string) (MigrationRevisionReport, error) {
	var r MigrationRevisionReport
	e := tx.QueryRowContext(ctx, `SELECT id,role,snapshot_sha256,sequence,state,records,index_digest FROM v3_migration_revisions WHERE id=$1`, id).Scan(&r.ID, &r.Role, &r.Source, &r.Sequence, &r.State, &r.Records, &r.Digest)
	return r, e
}
func (s *Store) bindMigrationRevision(ctx context.Context, id string, expected int64, in MigrationRevisionInput) (MigrationRevisionReport, error) {
	if !validArchiveSource(in.SourceID) {
		return MigrationRevisionReport{}, ErrMigrationSession
	}
	session, e := s.MigrationSession(ctx, id)
	if e != nil {
		return MigrationRevisionReport{}, ErrMigrationSession
	}
	if session.RecoveryHold || !migrationSessionRole(session, in.Role) || session.Phase != "collecting" && session.Phase != "indexed" {
		return MigrationRevisionReport{}, ErrMigrationSession
	}
	snapshot, e := openMigrationSnapshot(ctx, in.Snapshot)
	if e != nil {
		return MigrationRevisionReport{}, e
	}
	defer snapshot.close()
	revision := digest([]byte(id + ":" + in.Role + ":" + snapshot.sha))
	// Staging archives are immutable and private. A concurrent change can leave
	// a reusable staged snapshot, but cannot mutate an authorized session.
	archived, e := s.ArchiveSnapshot(ctx, in.Snapshot)
	if e != nil || archived.Source != snapshot.sha || !snapshot.unchanged() {
		return MigrationRevisionReport{}, ErrMigrationSession
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return MigrationRevisionReport{}, e
	}
	defer tx.Rollback()
	if e = migrationSessionLock(ctx, tx, id); e != nil {
		return MigrationRevisionReport{}, e
	}
	session, e = migrationSessionTx(ctx, tx, id)
	if e != nil {
		return MigrationRevisionReport{}, e
	}
	if session.RecoveryHold || session.Phase != "collecting" && session.Phase != "indexed" {
		return MigrationRevisionReport{}, ErrMigrationSession
	}
	var original, finished int64
	var storedSource string
	e = tx.QueryRowContext(ctx, `SELECT request_version,finished_version,source_id FROM v3_migration_revisions WHERE id=$1 AND session=$2`, revision, id).Scan(&original, &finished, &storedSource)
	if e == nil {
		if storedSource != in.SourceID || expected != session.Version && (expected != original || session.Version != finished) {
			return MigrationRevisionReport{}, ErrConflict
		}
		r, e := migrationRevisionTx(ctx, tx, revision)
		if e != nil {
			return r, e
		}
		if session.RecoveryHold || session.Phase != "collecting" && session.Phase != "indexed" {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		r.SessionVersion = session.Version
		if r.State == "ready" && verifyMigrationRevisionIndex(ctx, tx, revision) != nil {
			return r, ErrMigrationSession
		}
		if e = tx.Commit(); e != nil {
			return r, e
		}
		if r.State == "ready" {
			return r, nil
		}
		return s.ResumeMigrationRevision(ctx, id, session.Version, revision)
	}
	if e != sql.ErrNoRows {
		return MigrationRevisionReport{}, ErrMigrationSession
	}
	if session.Version != expected {
		return MigrationRevisionReport{}, ErrConflict
	}
	if session.Phase != "collecting" && session.Phase != "indexed" {
		return MigrationRevisionReport{}, ErrMigrationSession
	}
	var prior string
	e = tx.QueryRowContext(ctx, `SELECT source_id FROM v3_migration_revisions WHERE session=$1 AND role=$2 ORDER BY sequence DESC LIMIT 1`, id, in.Role).Scan(&prior)
	if e != nil && e != sql.ErrNoRows || e == nil && prior != in.SourceID {
		return MigrationRevisionReport{}, ErrMigrationSession
	}
	var busy bool
	if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_migration_revisions WHERE session=$1 AND state='indexing') OR EXISTS(SELECT 1 FROM v3_migration_deltas WHERE session=$1 AND state='comparing')`, id).Scan(&busy) != nil || busy {
		return MigrationRevisionReport{}, ErrMigrationSession
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_revisions(id,session,role,source_id,snapshot,snapshot_sha256,sequence,request_version,index_digest) SELECT $1,$2,$3,$4,$5,$6,coalesce(max(sequence),0)+1,$7,$8 FROM v3_migration_revisions WHERE session=$2 AND role=$3`, revision, id, in.Role, in.SourceID, in.Snapshot, snapshot.sha, expected, migrationIndexSeed(snapshot.tables, snapshot.schemas))
	if e != nil {
		return MigrationRevisionReport{}, ErrMigrationSession
	}
	for _, table := range snapshot.tables {
		if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_revision_tables(revision,table_name,records,schema_digest) VALUES($1,$2,$3,$4)`, revision, table.Name, table.Count, snapshot.schemas[table.Name]); e != nil {
			return MigrationRevisionReport{}, ErrMigrationSession
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,phase='collecting',updated_at=clock_timestamp() WHERE id=$1`, id); e != nil {
		return MigrationRevisionReport{}, e
	}
	if e = tx.Commit(); e != nil {
		return MigrationRevisionReport{}, e
	}
	return s.ResumeMigrationRevision(ctx, id, expected+1, revision)
}
func (s *Store) resumeMigrationRevision(ctx context.Context, id string, expected int64, revision string) (MigrationRevisionReport, error) {
	var path, sha string
	if s.DB.QueryRowContext(ctx, `SELECT snapshot,snapshot_sha256 FROM v3_migration_revisions WHERE id=$1 AND session=$2`, revision, id).Scan(&path, &sha) != nil {
		return MigrationRevisionReport{}, ErrMigrationSession
	}
	snapshot, e := openMigrationSnapshot(ctx, path)
	if e != nil {
		return MigrationRevisionReport{}, e
	}
	defer snapshot.close()
	if snapshot.sha != sha {
		return MigrationRevisionReport{}, ErrMigrationSession
	}
	verified := false
	for {
		if e = ctx.Err(); e != nil {
			return MigrationRevisionReport{}, ErrMigrationSession
		}
		tx, e := s.DB.BeginTx(ctx, nil)
		if e != nil {
			return MigrationRevisionReport{}, e
		}
		if e = migrationSessionLock(ctx, tx, id); e != nil {
			tx.Rollback()
			return MigrationRevisionReport{}, e
		}
		session, e := migrationSessionTx(ctx, tx, id)
		if e != nil {
			tx.Rollback()
			return MigrationRevisionReport{}, e
		}
		r, e := migrationRevisionTx(ctx, tx, revision)
		if e != nil {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		if session.RecoveryHold || session.Phase != "collecting" && session.Phase != "indexed" {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		r.SessionVersion = session.Version
		if !verified {
			if verifyMigrationRevisionCheckpoint(ctx, tx, revision, snapshot) != nil {
				tx.Rollback()
				return r, ErrMigrationSession
			}
			verified = true
		}
		if r.State == "ready" {
			var start, finished int64
			e = tx.QueryRowContext(ctx, `SELECT request_version,finished_version FROM v3_migration_revisions WHERE id=$1`, revision).Scan(&start, &finished)
			tx.Rollback()
			if e != nil || expected != session.Version && (expected != start+1 || session.Version != finished) {
				return r, ErrConflict
			}
			return r, nil
		}
		if session.Version != expected || session.Phase != "collecting" {
			tx.Rollback()
			return r, ErrConflict
		}
		var cursorTable string
		var cursor sql.NullInt64
		var done bool
		if tx.QueryRowContext(ctx, `SELECT cursor_table,cursor_key,cursor_done FROM v3_migration_revisions WHERE id=$1`, revision).Scan(&cursorTable, &cursor, &done) != nil {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		tableIndex := 0
		for tableIndex < len(snapshot.tables) && snapshot.tables[tableIndex].Name != cursorTable && cursorTable != "" {
			tableIndex++
		}
		if done {
			tableIndex++
			cursor = sql.NullInt64{}
		}
		if tableIndex >= len(snapshot.tables) {
			var actual, want int64
			if tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM v3_migration_revision_rows WHERE revision=$1),coalesce(sum(records),0) FROM v3_migration_revision_tables WHERE revision=$1`, revision).Scan(&actual, &want) != nil || actual != want || actual != r.Records || !snapshot.unchanged() {
				tx.Rollback()
				return r, ErrMigrationSession
			}
			if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_revisions SET state='ready',finished_version=$2 WHERE id=$1`, revision, expected+1); e == nil {
				_, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,phase=CASE WHEN (SELECT count(DISTINCT role) FROM v3_migration_revisions WHERE session=$1 AND state='ready')=jsonb_array_length(roles) THEN 'indexed' ELSE 'collecting' END,updated_at=clock_timestamp() WHERE id=$1`, id)
			}
			if e != nil {
				tx.Rollback()
				return r, ErrMigrationSession
			}
			if e = tx.Commit(); e != nil {
				return r, e
			}
			r.State, r.SessionVersion = "ready", expected+1
			return r, nil
		}
		table := snapshot.tables[tableIndex].Name
		query := `SELECT rowid,* FROM "` + table + `"`
		args := []any{}
		if cursor.Valid {
			query += " WHERE rowid>?"
			args = append(args, cursor.Int64)
		}
		rows, e := snapshot.db.QueryContext(ctx, query+" ORDER BY rowid LIMIT 500", args...)
		if e != nil {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		columns, e := rows.Columns()
		if e != nil {
			rows.Close()
			tx.Rollback()
			return r, ErrMigrationSession
		}
		copied := 0
		for rows.Next() {
			values := make([]any, len(columns))
			ptr := make([]any, len(columns))
			for i := range ptr {
				ptr[i] = &values[i]
			}
			if e = rows.Scan(ptr...); e != nil {
				break
			}
			var key int64
			var raw []byte
			key, raw, e = migrationArchiveRow(columns, values)
			if e != nil {
				break
			}
			hash := digest(raw)
			var archived string
			if e = tx.QueryRowContext(ctx, `SELECT digest FROM v3_legacy_records WHERE source=$1 AND table_name=$2 AND record_key=$3`, sha, table, strconv.FormatInt(key, 10)).Scan(&archived); e != nil || archived != hash {
				e = ErrMigrationSession
				break
			}
			if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_revision_rows(revision,table_name,record_key,digest) VALUES($1,$2,$3,$4)`, revision, table, key, hash); e != nil {
				break
			}
			r.Digest = migrationIndexStep(r.Digest, table, key, hash)
			r.Records++
			cursor = sql.NullInt64{Int64: key, Valid: true}
			copied++
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_revisions SET cursor_table=$2,cursor_key=$3,cursor_done=$4,records=$5,index_digest=$6 WHERE id=$1`, revision, table, cursor, copied < 500, r.Records, r.Digest); e != nil {
			tx.Rollback()
			return r, ErrMigrationSession
		}
		if e = tx.Commit(); e != nil {
			return r, e
		}
	}
}
