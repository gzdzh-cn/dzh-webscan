package nodeops

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"webscan/internal/persist"
)

// Private migration state, never an API input. The immutable pre-switch snapshot
// is the only source; Vector's private buffer is neither parsed nor discarded.
// Cursor and event inserts commit together, so a lost response cannot skip a line.
const legacyImportSchema = `CREATE TABLE IF NOT EXISTS nodeops_legacy_imports(
 job TEXT NOT NULL, file TEXT NOT NULL, binding TEXT NOT NULL, snapshot TEXT NOT NULL,
 digest TEXT NOT NULL, bytes INTEGER NOT NULL, offset INTEGER NOT NULL,
 records INTEGER NOT NULL, inserted INTEGER NOT NULL,
 PRIMARY KEY(job,file));`

type legacyImportReceipt struct {
	Format         int               `json:"format"`
	Binding        transitionBinding `json:"binding"`
	SnapshotSHA256 string            `json:"snapshot_sha256"`
	Files          int               `json:"files"`
	Records        int64             `json:"records"`
	Inserted       int64             `json:"inserted"`
}

func (b *transitionBackup) legacyReceiptPath(i backupIntent) string {
	return filepath.Join(b.root, "transitions", i.Binding.Job, "activation", "legacy-import.json")
}

func legacyInputFiles(s backupSnapshot) []backupFile {
	files := []backupFile{}
	for _, f := range s.Logs {
		// This is precisely the old Vector file source, not every JSONL saved by
		// the backup. Other diagnostics and nested files remain in the snapshot.
		if filepath.Dir(f.Path) == "logs" && strings.HasPrefix(filepath.Base(f.Path), "events-") && strings.HasSuffix(f.Path, ".jsonl") {
			files = append(files, f)
		}
	}
	return files
}

func (b *transitionBackup) verifyLegacyReconciliation(i backupIntent, snapshot string) error {
	if i.Installed.Generation != "v2" {
		return nil
	}
	var receipt legacyImportReceipt
	_, err := decodePrivateJSON(b.legacyReceiptPath(i), &receipt, 4096)
	if err != nil || receipt.Format != 1 || receipt.Binding != i.Binding || receipt.SnapshotSHA256 != snapshot || receipt.Files < 0 || receipt.Files > 100000 || receipt.Records < 0 || receipt.Inserted < 0 || receipt.Inserted > receipt.Records || receipt.Files == 0 && receipt.Records != 0 {
		return errors.New("legacy-import-not-proven")
	}
	return nil
}

// Called with both service-operation.lock and the Agent lifetime lock held,
// after proving every original service stopped and before enabling any target.
// It never changes an existing event, confirmation, baseline or scan task.
func (b *transitionBackup) reconcileLegacyLogsLocked(ctx context.Context, r Request) error {
	if r.Validate() != nil || r.Operation != "apply" || r.Phase != "activate" || ctx.Err() != nil {
		return errors.New("invalid-legacy-import")
	}
	if held, ok := ctx.Value(serviceOperationKey{}).(serviceOperation); !ok || held.file == nil {
		return errors.New("service-operation-lock-required")
	}
	i, err := b.readIntent(ctx, r)
	if err != nil || i.Installed.Generation != "v2" {
		return err
	}
	s, err := b.verify(ctx, r)
	if err != nil {
		return err
	}
	raw, err := readPrivate(filepath.Join(b.directory(r), "snapshot", "receipt.json"), 16<<20)
	if err != nil {
		return err
	}
	snapshot := sha(raw)
	files := legacyInputFiles(s)
	// Even a zero-log migration cannot silently replace a database which existed
	// at backup time. The check also applies when a completed receipt is replayed.
	if s.Database != nil {
		for _, name := range []string{"agent.sqlite3", "agent.sqlite3-wal", "agent.sqlite3-shm"} {
			if err := privateFile(filepath.Join(b.data, name), name != "agent.sqlite3"); err != nil {
				return errors.New("legacy-import-database-unavailable")
			}
		}
	} else if len(files) > 0 {
		return errors.New("legacy-import-database-missing")
	}
	if _, err := os.Lstat(b.legacyReceiptPath(i)); err == nil {
		return b.verifyLegacyReconciliation(i, snapshot)
	} else if !os.IsNotExist(err) {
		return err
	}
	receipt := legacyImportReceipt{Format: 1, Binding: i.Binding, SnapshotSHA256: snapshot, Files: len(files)}
	if len(files) > 0 {
		db, err := persist.OpenDB(filepath.Join(b.data, "agent.sqlite3"))
		if err != nil {
			return errors.New("legacy-import-database-unavailable")
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		original, err := persist.OpenReadOnly(filepath.Join(b.directory(r), "snapshot", "agent.sqlite3"))
		if err != nil {
			return errors.New("legacy-import-snapshot-unavailable")
		}
		defer original.Close()
		if _, err := db.ExecContext(ctx, legacyImportSchema); err != nil {
			return errors.New("legacy-import-database-unavailable")
		}
		for _, file := range files {
			records, inserted, err := b.reconcileLegacyFile(ctx, db, original, i, snapshot, file)
			if err != nil {
				return err
			}
			receipt.Records += records
			receipt.Inserted += inserted
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.New("legacy-import-interrupted")
	}
	if err := ensurePrivateDirectory(filepath.Dir(b.legacyReceiptPath(i))); err != nil {
		return err
	}
	raw, err = json.Marshal(receipt)
	if err != nil {
		return err
	}
	return replacePrivateFile(b.legacyReceiptPath(i), raw, nil)
}

func (b *transitionBackup) reconcileLegacyFile(ctx context.Context, db, original *sql.DB, i backupIntent, snapshot string, info backupFile) (int64, int64, error) {
	path := filepath.Join(b.root, "transitions", i.Binding.Job, "snapshot", info.Path)
	f, err := openPrivateFile(path)
	if err != nil {
		return 0, 0, errors.New("legacy-import-file-unavailable")
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || stat.Size() != info.Bytes || uint32(stat.Mode().Perm()) != info.Mode {
		return 0, 0, errors.New("legacy-import-source-changed")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, &contextReader{ctx, f})
	if ctx.Err() != nil {
		return 0, 0, errors.New("legacy-import-interrupted")
	}
	if err != nil || size != info.Bytes || hex.EncodeToString(hash.Sum(nil)) != info.SHA256 {
		return 0, 0, errors.New("legacy-import-source-changed")
	}
	bindingRaw, _ := json.Marshal(i.Binding)
	proof := sha(bindingRaw)
	_, err = db.ExecContext(ctx, `INSERT INTO nodeops_legacy_imports(job,file,binding,snapshot,digest,bytes,offset,records,inserted)
 VALUES(?,?,?,?,?,?,0,0,0) ON CONFLICT(job,file) DO NOTHING`, i.Binding.Job, info.Path, proof, snapshot, info.SHA256, info.Bytes)
	if err != nil {
		return 0, 0, errors.New("legacy-import-checkpoint-unavailable")
	}
	var binding, savedSnapshot, digest string
	var length, offset, records, inserted int64
	err = db.QueryRowContext(ctx, `SELECT binding,snapshot,digest,bytes,offset,records,inserted FROM nodeops_legacy_imports WHERE job=? AND file=?`, i.Binding.Job, info.Path).Scan(&binding, &savedSnapshot, &digest, &length, &offset, &records, &inserted)
	if err != nil || binding != proof || savedSnapshot != snapshot || digest != info.SHA256 || length != info.Bytes || offset < 0 || offset > length || records < 0 || inserted < 0 || inserted > records || offset == 0 && records != 0 || offset > 0 && records == 0 {
		return 0, 0, errors.New("legacy-import-checkpoint-changed")
	}
	if offset > 0 && offset < length {
		var previous [1]byte
		if _, err := f.ReadAt(previous[:], offset-1); err != nil || previous[0] != '\n' {
			return 0, 0, errors.New("legacy-import-checkpoint-changed")
		}
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, 0, errors.New("legacy-import-file-unavailable")
	}
	reader := bufio.NewReaderSize(&contextReader{ctx, f}, 64<<10)
	for offset < length {
		// Short transactions bound both memory and locks; no giant-file transaction.
		items := []rollbackEvent{}
		start, consumed := offset, int64(0)
		for len(items) < 100 && offset+consumed < length && consumed < rollbackBatchBytes-rollbackEventBytes-2 {
			line, n, err := legacyJSONLine(reader)
			if err != nil {
				return records, inserted, err
			}
			id, compact, err := legacyEvent(line, i.Binding.Node)
			if err != nil {
				return records, inserted, err
			}
			items = append(items, rollbackEvent{id, string(compact)})
			consumed += n
		}
		if offset+consumed > length {
			return records, inserted, errors.New("legacy-import-source-changed")
		}
		added, err := importLegacyBatch(ctx, db, original, i.Binding.Job, info.Path, start, consumed, items)
		if err != nil {
			return records, inserted, err
		}
		offset += consumed
		records += int64(len(items))
		inserted += added
	}
	return records, inserted, nil
}

// ReadSlice bounds a single line even without a newline; ReadString would
// allocate an arbitrary damaged input. A final complete JSON object may lack LF.
func legacyJSONLine(reader *bufio.Reader) ([]byte, int64, error) {
	line := []byte{}
	for {
		part, err := reader.ReadSlice('\n')
		if len(line)+len(part) > rollbackEventBytes+2 {
			return nil, 0, errors.New("legacy-import-event-too-large")
		}
		line = append(line, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, 0, errors.New("legacy-import-interrupted")
		}
		if err != nil && err != io.EOF || len(line) == 0 {
			return nil, 0, errors.New("legacy-import-line-invalid")
		}
		n := int64(len(line))
		return bytes.TrimSuffix(bytes.TrimSuffix(line, []byte{'\n'}), []byte{'\r'}), n, nil
	}
}

func legacyEvent(raw []byte, node string) (string, []byte, error) {
	var identity struct {
		ID string `json:"event_id"`
	}
	if !utf8.Valid(raw) || !json.Valid(raw) || json.Unmarshal(raw, &identity) != nil || identity.ID == "" || len(identity.ID) > 1024 || strings.ContainsAny(identity.ID, "\x00\r\n") {
		return "", nil, errors.New("legacy-import-event-invalid")
	}
	compact, err := rollbackLine(string(raw), identity.ID, node)
	if err != nil {
		return "", nil, errors.New("legacy-import-event-invalid")
	}
	return identity.ID, compact, nil
}

func importLegacyBatch(ctx context.Context, db, original *sql.DB, job, file string, offset, consumed int64, items []rollbackEvent) (int64, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, errors.New("legacy-import-transaction-failed")
	}
	defer tx.Rollback()
	var inserted int64
	for _, item := range items {
		// SQLite remains authoritative for already-known IDs, including pending
		// scans, confirmations and permanent rejection. Never replace those rows.
		result, err := tx.ExecContext(ctx, `INSERT INTO events(id,payload,created,exported,accepted) VALUES(?,?,?,NULL,NULL) ON CONFLICT(id) DO NOTHING`, item.id, item.raw, float64(time.Now().UnixMilli())/1000)
		if err != nil {
			return 0, errors.New("legacy-import-write-failed")
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, errors.New("legacy-import-write-failed")
		}
		if n == 0 {
			// The captured SQLite is authoritative. For IDs absent there, two
			// conflicting JSONL bodies must not be silently reduced to one event.
			var known bool
			if err := original.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE id=?)`, item.id).Scan(&known); err != nil {
				return 0, errors.New("legacy-import-snapshot-unavailable")
			}
			if !known {
				var size int64
				var payload string
				if err := tx.QueryRowContext(ctx, `SELECT length(CAST(payload AS BLOB)) FROM events WHERE id=?`, item.id).Scan(&size); err != nil || size < 1 || size > rollbackEventBytes {
					return 0, errors.New("legacy-import-id-conflict")
				}
				if err := tx.QueryRowContext(ctx, `SELECT payload FROM events WHERE id=?`, item.id).Scan(&payload); err != nil || !equivalentLegacyJSON(payload, item.raw) {
					return 0, errors.New("legacy-import-id-conflict")
				}
			}
		}
		inserted += n
	}
	result, err := tx.ExecContext(ctx, `UPDATE nodeops_legacy_imports SET offset=offset+?,records=records+?,inserted=inserted+? WHERE job=? AND file=? AND offset=?`, consumed, len(items), inserted, job, file, offset)
	if err != nil {
		return 0, errors.New("legacy-import-checkpoint-failed")
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return 0, errors.New("legacy-import-checkpoint-changed")
	}
	if err := tx.Commit(); err != nil {
		return 0, errors.New("legacy-import-commit-failed")
	}
	return inserted, nil
}

func equivalentLegacyJSON(a, b string) bool {
	canonical := func(raw string) []byte {
		if !json.Valid([]byte(raw)) {
			return nil
		}
		d := json.NewDecoder(strings.NewReader(raw))
		d.UseNumber()
		var value any
		if d.Decode(&value) != nil {
			return nil
		}
		out, _ := json.Marshal(value)
		return out
	}
	x, y := canonical(a), canonical(b)
	return x != nil && y != nil && bytes.Equal(x, y)
}
