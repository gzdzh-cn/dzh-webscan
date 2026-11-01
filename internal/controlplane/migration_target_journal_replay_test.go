package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webscan/internal/persist"
)

// This is an explicitly opaque mirror for testing delivery and checkpoint
// semantics. It is not the production v2 mapper and never releases cutover.
type migrationTestMirror struct {
	db   *sql.DB
	lose bool
}

func newMigrationTestMirror(t *testing.T, path string) *migrationTestMirror {
	t.Helper()
	db, e := persist.OpenDB(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Exec(`CREATE TABLE IF NOT EXISTS mirrored(table_name TEXT,record_key TEXT,payload TEXT,PRIMARY KEY(table_name,record_key));CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY,hash TEXT,rows INTEGER)`); e != nil {
		t.Fatal(e)
	}
	return &migrationTestMirror{db: db}
}
func (m *migrationTestMirror) ApplyMigrationJournal(ctx context.Context, b MigrationTargetReplayBatch) (MigrationTargetReplayReceipt, error) {
	receipt := MigrationTargetReplayReceipt{b.ID, b.SHA256, int64(len(b.Rows))}
	tx, e := persist.BeginWrite(ctx, m.db)
	if e != nil {
		return receipt, e
	}
	defer tx.Rollback()
	var hash string
	var count int64
	e = tx.QueryRowContext(ctx, `SELECT hash,rows FROM receipts WHERE id=?`, b.ID).Scan(&hash, &count)
	if e == nil {
		if hash != b.SHA256 || count != receipt.Rows {
			return receipt, ErrConflict
		}
		return receipt, nil
	}
	if e != sql.ErrNoRows {
		return receipt, e
	}
	for _, r := range b.Rows {
		if r.Operation == "UPDATE" || r.Operation == "DELETE" {
			var before string
			if e = tx.QueryRowContext(ctx, `SELECT payload FROM mirrored WHERE table_name=? AND record_key=?`, r.Table, string(r.BeforeKey)).Scan(&before); e != nil || before != string(r.Before) {
				return receipt, errors.New("PRIVATE_SINK_CONFLICT")
			}
			if _, e = tx.ExecContext(ctx, `DELETE FROM mirrored WHERE table_name=? AND record_key=?`, r.Table, string(r.BeforeKey)); e != nil {
				return receipt, e
			}
		}
		if r.Operation != "DELETE" {
			if _, e = tx.ExecContext(ctx, `INSERT INTO mirrored VALUES(?,?,?)`, r.Table, string(r.AfterKey), string(r.After)); e != nil {
				return receipt, e
			}
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO receipts VALUES(?,?,?)`, b.ID, b.SHA256, receipt.Rows); e != nil {
		return receipt, e
	}
	if e = tx.Commit(); e != nil {
		return receipt, e
	}
	if m.lose {
		m.lose = false
		return receipt, errors.New("PRIVATE_SINK_REPLY_LOST")
	}
	return receipt, nil
}
func TestMigrationTargetJournalSQLiteReplayKeepsUpdatesDeletesAndLostAcknowledgement(t *testing.T) {
	s, id := migrationTargetJournalFixture(t)
	ctx := context.Background()
	if _, e := s.DB.Exec(`INSERT INTO v3_accounts(username,password_hash,role) VALUES('baseline-a','PRIVATE_BASELINE','admin'),('baseline-b','PRIVATE_DELETE','viewer')`); e != nil {
		t.Fatal(e)
	}
	armed, e := s.ArmMigrationTargetJournal(ctx, id, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`INSERT INTO v3_accounts(username,password_hash,role) VALUES('new','PRIVATE_NEW','viewer');UPDATE v3_accounts SET username='changed-a',password_hash='PRIVATE_CHANGED',role='operator' WHERE username='baseline-a';DELETE FROM v3_accounts WHERE username='baseline-b'`); e != nil {
		t.Fatal(e)
	}
	sealed, e := s.SealMigrationTargetJournal(ctx, id, armed.SessionVersion)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(privateTestDir(t), "isolated-private-mirror.sqlite3")
	mirror := newMigrationTestMirror(t, path)
	mirror.lose = true
	if report, e := s.ReplayMigrationTargetJournal(ctx, id, sealed.SessionVersion, "v2-rollback-test-v1", mirror); !errors.Is(e, ErrMigrationSession) || report.Rows != 0 || strings.Contains(e.Error(), "PRIVATE") {
		t.Fatal("lost reply not protected", report, e)
	}
	state, e := s.MigrationTargetReplay(ctx, id, "v2-rollback-test-v1")
	if e != nil || state.State != "baseline" || state.Rows != 0 {
		t.Fatal("PG advanced before receipt", state, e)
	}
	var receipts int
	if e = mirror.db.QueryRow(`SELECT count(*) FROM receipts`).Scan(&receipts); e != nil || receipts != 1 {
		t.Fatal("SQLite durable acknowledgement missing", receipts, e)
	}
	mirror.db.Close()
	mirror = newMigrationTestMirror(t, path)
	report, e := s.ReplayMigrationTargetJournal(ctx, id, sealed.SessionVersion, "v2-rollback-test-v1", mirror)
	if e != nil || report.State != "complete" || report.Rows != sealed.BaselineRows+sealed.Changes {
		t.Fatal(report, e)
	}
	var payload string
	if e = mirror.db.QueryRow(`SELECT payload FROM mirrored WHERE table_name='v3_accounts' AND record_key=?`, `{"username": "changed-a"}`).Scan(&payload); e != nil || !strings.Contains(payload, "PRIVATE_CHANGED") {
		t.Fatal("updated row not kept", e)
	}
	var deleted int
	if e = mirror.db.QueryRow(`SELECT count(*) FROM mirrored WHERE table_name='v3_accounts' AND record_key=?`, `{"username": "baseline-b"}`).Scan(&deleted); e != nil || deleted != 0 {
		t.Fatal("deleted row resurrected", deleted, e)
	}
	replay, e := s.ReplayMigrationTargetJournal(ctx, id, sealed.SessionVersion, "v2-rollback-test-v1", mirror)
	if e != nil || replay.SHA256 != report.SHA256 {
		t.Fatal(replay, e)
	}
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "changed-a") {
		t.Fatal("private result leaked")
	}
	raw, _ = json.Marshal(MigrationTargetReplayBatch{Rows: []MigrationTargetReplayRow{{After: json.RawMessage(`{"secret":"PRIVATE"}`)}}})
	if strings.Contains(string(raw), "PRIVATE") {
		t.Fatal("private batch accidentally serializes")
	}
	st, e := os.Stat(path)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("private mirror permissions", e)
	}
}
func TestMigrationTargetJournalReplayRejectsTamperedCheckpointAndUnsealedJournal(t *testing.T) {
	s, id := migrationTargetJournalFixture(t)
	ctx := context.Background()
	armed, e := s.ArmMigrationTargetJournal(ctx, id, 1)
	if e != nil {
		t.Fatal(e)
	}
	mirror := newMigrationTestMirror(t, filepath.Join(privateTestDir(t), "mirror.sqlite3"))
	if _, e = s.ReplayMigrationTargetJournal(ctx, id, armed.SessionVersion, "v2-rollback-test-v1", mirror); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("unsealed replay", e)
	}
	sealed, e := s.SealMigrationTargetJournal(ctx, id, armed.SessionVersion)
	if e != nil {
		t.Fatal(e)
	}
	mirror.lose = true
	if _, e = s.ReplayMigrationTargetJournal(ctx, id, sealed.SessionVersion, "v2-rollback-test-v1", mirror); !errors.Is(e, ErrMigrationSession) {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_target_replays SET rows=1 WHERE session=$1`, id); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReplayMigrationTargetJournal(ctx, id, sealed.SessionVersion, "v2-rollback-test-v1", mirror); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("tampered progress replayed", e)
	}
}
