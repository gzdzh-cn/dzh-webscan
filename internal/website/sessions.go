package website

import (
	"context"
	"database/sql"
	"time"
	"webscan/internal/persist"
)

const sessionLifetime = 12 * time.Hour
const sessionSchema = `CREATE TABLE IF NOT EXISTS website_sessions(token_hash TEXT PRIMARY KEY,revision INTEGER NOT NULL,csrf TEXT NOT NULL,expires INTEGER NOT NULL,created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS website_sessions_expiry ON website_sessions(expires);`

func (m *Monitor) readSession(ctx context.Context, hash string) (session, error) {
	var s session
	var expires int64
	err := m.DB.QueryRowContext(ctx, "SELECT revision,csrf,expires FROM website_sessions WHERE token_hash=? AND expires>?", hash, time.Now().Unix()).Scan(&s.Revision, &s.CSRF, &expires)
	s.Expires = time.Unix(expires, 0)
	return s, err
}

// Store only a hash of the bearer cookie, with a fixed expiry across restarts.
func (m *Monitor) storeSession(ctx context.Context, hash string, s session) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := persist.BeginWrite(ctx, m.DB)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var revision int64
	if err = tx.QueryRowContext(ctx, "SELECT revision FROM website_admin WHERE id=1").Scan(&revision); err != nil {
		return false, err
	}
	if revision != s.Revision {
		return false, nil
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM website_sessions WHERE expires<=? OR revision<>?", time.Now().Unix(), revision); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM website_sessions WHERE token_hash IN (SELECT token_hash FROM website_sessions ORDER BY created,token_hash LIMIT MAX(0,(SELECT COUNT(*) FROM website_sessions)-99))"); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO website_sessions VALUES(?,?,?,?,?)", hash, s.Revision, s.CSRF, s.Expires.Unix(), time.Now().UnixNano()); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func replacePassword(ctx context.Context, db *sql.DB, hash string, expected *int64) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := persist.BeginWrite(ctx, db)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	query := "UPDATE website_admin SET password_hash=?,revision=revision+1,modified=? WHERE id=1"
	args := []any{hash, time.Now().Unix()}
	if expected != nil {
		query += " AND revision=?"
		args = append(args, *expected)
	}
	r, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	if err != nil || n != 1 {
		return false, err
	}
	// The terminal command also supports databases created before this migration.
	var exists int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE name='website_sessions' AND type='table'").Scan(&exists); err != nil {
		return false, err
	}
	if exists != 0 {
		if _, err = tx.ExecContext(ctx, "DELETE FROM website_sessions"); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}
