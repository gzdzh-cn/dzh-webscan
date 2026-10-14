//go:build linux

package agent

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"webscan/internal/common"
	"webscan/internal/persist"
)

func importLegacyLogs(ctx context.Context, db *sql.DB, logs string) error {
	files, e := filepath.Glob(filepath.Join(logs, "events-*.jsonl"))
	if e != nil {
		return e
	}
	for _, path := range files {
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 65536), 2<<20)
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			f.Close()
			return e
		}
		for scanner.Scan() {
			v, e := common.Decode(scanner.Bytes())
			if e != nil {
				tx.Rollback()
				f.Close()
				return fmt.Errorf("legacy JSONL invalid: %s", filepath.Base(path))
			}
			p := common.M(v)
			id := common.S(p["event_id"])
			if id == "" {
				tx.Rollback()
				f.Close()
				return fmt.Errorf("legacy event ID missing")
			}
			if _, e = tx.Exec("INSERT OR IGNORE INTO events(id,payload,created,exported) VALUES(?,?,?,?)", id, string(scanner.Bytes()), common.Now(), path); e != nil {
				tx.Rollback()
				f.Close()
				return e
			}
		}
		e = scanner.Err()
		f.Close()
		if e != nil {
			tx.Rollback()
			return e
		}
		if _, e = tx.Exec("INSERT OR IGNORE INTO logfiles VALUES(?,?)", path, common.Now()); e != nil {
			tx.Rollback()
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
	}
	return nil
}

// PrepareLegacyDelivery exports all unconfirmed records, including quarantined
// records, before an old image is restored. Current SQLite is never overwritten.
func PrepareLegacyDelivery(ctx context.Context, data, logs string) error {
	db, e := persist.OpenDB(filepath.Join(data, "agent.sqlite3"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	defer db.Close()
	rows, e := db.QueryContext(ctx, "SELECT id,payload FROM events WHERE accepted IS NULL ORDER BY created,id")
	if e != nil {
		return e
	}
	defer rows.Close()
	if e = os.MkdirAll(logs, 0700); e != nil {
		return e
	}
	path := filepath.Join(logs, "events-rollback-"+common.ID()+".jsonl")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	ids := []string{}
	for rows.Next() {
		var id, raw string
		if e = rows.Scan(&id, &raw); e != nil {
			return e
		}
		if _, e = f.WriteString(raw + "\n"); e != nil {
			return e
		}
		ids = append(ids, id)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	rows.Close()
	if e = f.Sync(); e != nil {
		return e
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("INSERT INTO logfiles VALUES(?,?)", path, common.Now()); e != nil {
		return e
	}
	for _, id := range ids {
		if _, e = tx.Exec("UPDATE events SET exported=? WHERE id=? AND accepted IS NULL", path, id); e != nil {
			return e
		}
	}
	return tx.Commit()
}
