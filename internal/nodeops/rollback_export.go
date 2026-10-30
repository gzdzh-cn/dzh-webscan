package nodeops

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"webscan/internal/persist"
)

const rollbackBatchBytes = 4 << 20
const rollbackEventBytes = 2 << 20

type rollbackEvent struct{ id, raw string }

// exportRollbackPending is a private step for the eventual restore driver. It
// proves the target is stopped and holds the Agent's lifetime lock throughout.
// The old snapshot is evidence only: live SQLite, baseline, scans, acknowledgments
// and the persistent revocation floor are never replaced with that snapshot.
func (b *transitionBackup) exportRollbackPending(ctx context.Context, r Request, current Installation) (int64, error) {
	if r.Validate() != nil || r.Operation != "apply" || r.Phase != "restore" || !current.valid(r.Node) || b.host == nil || ctx.Err() != nil {
		return 0, errors.New("invalid-rollback-request")
	}
	ctx, release, err := acquireServiceOperation(ctx, b.root)
	if err != nil {
		return 0, err
	}
	defer release()
	databaseExpected, _, err := b.recoveryBase(ctx, r)
	if err != nil {
		return 0, err
	}
	stopped, err := b.rollbackStopped(ctx, r, current)
	if err != nil || !stopped {
		return 0, errors.New("node-writers-not-stopped")
	}
	lock, err := b.agentLock()
	if err != nil {
		return 0, err
	}
	defer lock.Close()
	dbfile := filepath.Join(b.data, "agent.sqlite3")
	if _, err := os.Lstat(dbfile); os.IsNotExist(err) {
		if databaseExpected {
			return 0, errors.New("live-agent-database-missing")
		}
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	for _, name := range []string{"agent.sqlite3", "agent.sqlite3-wal", "agent.sqlite3-shm"} {
		if err := privateFile(filepath.Join(b.data, name), name != "agent.sqlite3"); err != nil {
			return 0, err
		}
	}
	if err := ensurePrivateDirectory(b.logs); err != nil {
		return 0, err
	}
	db, err := persist.OpenDB(dbfile)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var count int64
	cursor := ""
	for {
		next, n, err := exportRollbackBatch(ctx, db, b.logs, r.Node, r.Job, cursor)
		if err != nil {
			return count, err
		}
		count += int64(n)
		if n == 0 {
			return count, nil
		}
		cursor = next
	}
}

func exportRollbackBatch(ctx context.Context, db *sql.DB, logs, node, job, cursor string) (string, int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return cursor, 0, err
	}
	defer tx.Rollback()
	// Fetch lengths first. A corrupt, enormous payload must not be materialized
	// before enforcing the bound. Cursor order does not depend on wall clock.
	rows, err := tx.QueryContext(ctx, "SELECT id,length(CAST(payload AS BLOB)) FROM events WHERE accepted IS NULL AND (?='' OR id>?) ORDER BY id LIMIT 100", cursor, cursor)
	if err != nil {
		return cursor, 0, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		var size sql.NullInt64
		if err = rows.Scan(&id, &size); err != nil {
			break
		}
		if id == "" || len(id) > 1024 || strings.ContainsAny(id, "\x00\r\n") || !size.Valid || size.Int64 < 1 || size.Int64 > rollbackEventBytes {
			err = errors.New("invalid-rollback-event")
			break
		}
		ids = append(ids, id)
	}
	scanErr := rows.Err()
	rows.Close()
	if err != nil {
		return cursor, 0, err
	}
	if scanErr != nil {
		return cursor, 0, scanErr
	}
	if len(ids) == 0 {
		return cursor, 0, nil
	}
	var output bytes.Buffer
	items := []rollbackEvent{}
	for _, id := range ids {
		var raw string
		if err := tx.QueryRowContext(ctx, "SELECT payload FROM events WHERE id=? AND accepted IS NULL", id).Scan(&raw); err != nil {
			return cursor, 0, err
		}
		line, err := rollbackLine(raw, id, node)
		if err != nil {
			return cursor, 0, err
		}
		if output.Len()+len(line)+1 > rollbackBatchBytes && len(items) > 0 {
			break
		}
		output.Write(line)
		output.WriteByte('\n')
		items = append(items, rollbackEvent{id, raw})
	}
	raw := output.Bytes()
	// Content-addressed files make a response/commit loss retry harmless. The
	// fixed prefix is readable by legacy Vector; temporary files are not JSONL.
	filename := "events-v3-rollback-" + sha([]byte(job))[:16] + "-" + sha(raw) + ".jsonl"
	path := filepath.Join(logs, filename)
	if err := publishRollbackLog(ctx, path, raw); err != nil {
		return cursor, 0, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO logfiles(path,created) VALUES(?,?)", path, float64(time.Now().UnixNano())/1e9); err != nil {
		return cursor, 0, err
	}
	for _, item := range items {
		result, err := tx.ExecContext(ctx, "UPDATE events SET exported=? WHERE id=? AND payload=? AND accepted IS NULL", path, item.id, item.raw)
		if err != nil {
			return cursor, 0, err
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return cursor, 0, errors.New("rollback-event-changed")
		}
	}
	if err := tx.Commit(); err != nil {
		return cursor, 0, err
	}
	return items[len(items)-1].id, len(items), nil
}
func rollbackLine(raw, id, node string) ([]byte, error) {
	if len(raw) > rollbackEventBytes {
		return nil, errors.New("invalid-rollback-event")
	}
	var object map[string]json.RawMessage
	// JSON objects with duplicate identity fields are ambiguous across decoders.
	decoder := json.NewDecoder(strings.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid-rollback-event")
	}
	object = map[string]json.RawMessage{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return nil, errors.New("invalid-rollback-event")
		}
		if _, duplicate := object[name]; duplicate {
			return nil, errors.New("invalid-rollback-event")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("invalid-rollback-event")
		}
		object[name] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid-rollback-event")
	}
	var eventID, nodeID string
	if json.Unmarshal(object["event_id"], &eventID) != nil || eventID != id || json.Unmarshal(object["node_id"], &nodeID) != nil || nodeID != node {
		return nil, errors.New("rollback-event-identity-mismatch")
	}
	var compact bytes.Buffer
	if json.Compact(&compact, []byte(raw)) != nil {
		return nil, errors.New("invalid-rollback-event")
	}
	return compact.Bytes(), nil
}
func publishRollbackLog(ctx context.Context, path string, raw []byte) error {
	want := backupFile{Path: filepath.Base(path), Bytes: int64(len(raw)), SHA256: sha(raw), Mode: 0600}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		if err := verifyBackupFile(ctx, path, want); err != nil {
			return err
		}
		// A previous process may have died after rename but before directory
		// fsync. Re-establish durability before recording SQLite references.
		return syncDirectory(filepath.Dir(path))
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".rollback-")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := renameNoReplace(temp, path); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return verifyBackupFile(ctx, path, want)
}
