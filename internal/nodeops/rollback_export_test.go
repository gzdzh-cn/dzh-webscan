package nodeops

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rollbackFixture(t *testing.T) (*transitionBackup, Request, *backupHostFixture, *sql.DB) {
	t.Helper()
	b, r, h, db := backupFixture(t)
	if _, err := db.Exec(`ALTER TABLE events ADD COLUMN created REAL DEFAULT 0; ALTER TABLE events ADD COLUMN exported TEXT; CREATE TABLE logfiles(path TEXT PRIMARY KEY,created REAL); UPDATE events SET payload='{"event_id":"original-id","node_id":"node-one","counter":9007199254740993}'`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.run(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r.Phase = "restore"
	return b, r, h, db
}
func insertRollbackEvent(t *testing.T, db *sql.DB, id string, accepted any) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"event_id": id, "node_id": "node-one", "operation": "modify"})
	if _, err := db.Exec("INSERT INTO events(id,payload,created,accepted) VALUES(?,?,?,?)", id, string(raw), 0, accepted); err != nil {
		t.Fatal(err)
	}
}
func rollbackLogs(t *testing.T, b *transitionBackup) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(b.logs, "events-v3-rollback-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	result := map[string][]byte{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		result[p] = raw
	}
	return result
}
func TestRollbackExportRetainsPostSwitchEventsAndAcknowledgments(t *testing.T) {
	b, r, h, db := rollbackFixture(t)
	for i := 0; i < 240; i++ {
		insertRollbackEvent(t, db, fmt.Sprintf("new-%03d", i), nil)
	}
	insertRollbackEvent(t, db, "already-confirmed", 42)
	if _, err := db.Exec(`CREATE TABLE delivery_failures(id TEXT PRIMARY KEY,error TEXT); INSERT INTO delivery_failures VALUES('new-001','permanent-reject-fixture')`); err != nil {
		t.Fatal(err)
	}
	n, err := b.exportRollbackPending(context.Background(), r, h.installed)
	if err != nil || n != 241 {
		t.Fatal("pending events missing", n, err)
	}
	logs := rollbackLogs(t, b)
	if len(logs) != 3 {
		t.Fatal("expected bounded batches", len(logs))
	}
	ids := map[string]bool{}
	for p, raw := range logs {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0600 || len(raw) > rollbackBatchBytes {
			t.Fatal("unsafe rollback file", err)
		}
		scan := bufio.NewScanner(strings.NewReader(string(raw)))
		scan.Buffer(make([]byte, 1024), rollbackEventBytes)
		for scan.Scan() {
			var item map[string]json.RawMessage
			if err := json.Unmarshal(scan.Bytes(), &item); err != nil {
				t.Fatal(err)
			}
			var id string
			json.Unmarshal(item["event_id"], &id)
			if ids[id] || id == "already-confirmed" {
				t.Fatal("duplicate/confirmed export", id)
			}
			ids[id] = true
			if id == "original-id" && string(item["counter"]) != "9007199254740993" {
				t.Fatal("integer changed")
			}
		}
		if err := scan.Err(); err != nil {
			t.Fatal(err)
		}
	}
	if len(ids) != 241 || !ids["original-id"] || !ids["new-239"] || !ids["new-001"] {
		t.Fatal("rollback dropped old, new or quarantined event")
	}
	var ack sql.NullFloat64
	var exported sql.NullString
	if err := db.QueryRow("SELECT accepted,exported FROM events WHERE id='already-confirmed'").Scan(&ack, &exported); err != nil || !ack.Valid || ack.Float64 != 42 || exported.Valid {
		t.Fatal("confirmation changed", err)
	}
	var pending int
	if err := db.QueryRow("SELECT count(*) FROM events WHERE accepted IS NULL AND exported IS NOT NULL").Scan(&pending); err != nil || pending != 241 {
		t.Fatal("missing publication records", err, pending)
	}
	if n, err := b.exportRollbackPending(context.Background(), r, h.installed); err != nil || n != 241 {
		t.Fatal("replay failed", n, err)
	}
	again := rollbackLogs(t, b)
	if len(again) != len(logs) {
		t.Fatal("replay created duplicates")
	}
	for p, raw := range logs {
		if string(again[p]) != string(raw) {
			t.Fatal("replay overwrote file")
		}
	}
	// The original snapshot still has one event. Live state retains all 242.
	assertBackupRows(t, filepath.Join(b.directory(r), "snapshot", "agent.sqlite3"), 1)
	assertBackupRows(t, filepath.Join(b.data, "agent.sqlite3"), 242)
}
func TestRollbackExportLostCommitReusesDurableFile(t *testing.T) {
	b, r, h, db := rollbackFixture(t)
	insertRollbackEvent(t, db, "post-switch", nil)
	if _, err := db.Exec(`CREATE TRIGGER fail_export BEFORE INSERT ON logfiles BEGIN SELECT RAISE(ABORT,'injected-commit-failure'); END`); err != nil {
		t.Fatal(err)
	}
	if n, err := b.exportRollbackPending(context.Background(), r, h.installed); err == nil || n != 0 {
		t.Fatal("failed transaction reported success", n, err)
	}
	logs := rollbackLogs(t, b)
	if len(logs) != 1 {
		t.Fatal("fsynced file not retained for recovery")
	}
	var n int
	db.QueryRow("SELECT count(*) FROM events WHERE exported IS NOT NULL").Scan(&n)
	if n != 0 {
		t.Fatal("failed transaction changed SQLite")
	}
	if _, err := db.Exec("DROP TRIGGER fail_export"); err != nil {
		t.Fatal(err)
	}
	if n, err := b.exportRollbackPending(context.Background(), r, h.installed); err != nil || n != 2 {
		t.Fatal("durable file could not reconcile", n, err)
	}
	if len(rollbackLogs(t, b)) != 1 {
		t.Fatal("lost response produced another file")
	}
}
func TestRollbackExportReportsCompletedBatchesOnPartialFailure(t *testing.T) {
	b, r, h, db := rollbackFixture(t)
	for i := 0; i < 200; i++ {
		insertRollbackEvent(t, db, fmt.Sprintf("a-%03d", i), nil)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_second_batch BEFORE UPDATE OF exported ON events WHEN NEW.id='a-100' BEGIN SELECT RAISE(ABORT,'second-batch-failed'); END`); err != nil {
		t.Fatal(err)
	}
	n, err := b.exportRollbackPending(context.Background(), r, h.installed)
	if err == nil || n != 100 {
		t.Fatal("partial completion not reported", n, err)
	}
	var count int
	db.QueryRow("SELECT count(*) FROM events WHERE exported IS NOT NULL").Scan(&count)
	if count != 100 {
		t.Fatal("partial database state inaccurate", count)
	}
	db.Exec("DROP TRIGGER fail_second_batch")
	if n, err := b.exportRollbackPending(context.Background(), r, h.installed); err != nil || n != 201 {
		t.Fatal("retry failed", n, err)
	}
}
func TestRollbackExportRefusesActiveWriterOrMissingDatabase(t *testing.T) {
	for _, kind := range []string{"running", "lock", "missing", "wrong-node", "wrong-phase"} {
		t.Run(kind, func(t *testing.T) {
			b, r, h, db := rollbackFixture(t)
			current := h.installed
			var unlock func()
			switch kind {
			case "running":
				h.isStopped = false
			case "lock":
				f, err := b.agentLock()
				if err != nil {
					t.Fatal(err)
				}
				unlock = func() { f.Close() }
			case "missing":
				db.Close()
				os.Remove(filepath.Join(b.data, "agent.sqlite3"))
			case "wrong-node":
				current.Node = "another"
			case "wrong-phase":
				r.Phase = "backup"
			}
			if unlock != nil {
				defer unlock()
			}
			if _, err := b.exportRollbackPending(context.Background(), r, current); err == nil {
				t.Fatal("unsafe rollback accepted")
			}
			if len(rollbackLogs(t, b)) != 0 {
				t.Fatal("unsafe request wrote export")
			}
		})
	}
}
func TestRollbackExportRejectsMalformedOrAmbiguousIdentity(t *testing.T) {
	for _, raw := range []string{`{"event_id":"different","node_id":"node-one"}`, `{"event_id":"original-id","node_id":"another"}`, `{"event_id":"original-id","event_id":"spoof","node_id":"node-one"}`, `{bad`, `{"event_id":"original-id","node_id":"node-one"} {}`, strings.Repeat("x", rollbackEventBytes+1)} {
		t.Run(fmt.Sprint(len(raw), sha([]byte(raw))[:8]), func(t *testing.T) {
			b, r, h, db := rollbackFixture(t)
			if _, err := db.Exec("UPDATE events SET payload=? WHERE id='original-id'", raw); err != nil {
				t.Fatal(err)
			}
			if _, err := b.exportRollbackPending(context.Background(), r, h.installed); err == nil {
				t.Fatal("malformed event published")
			}
			if len(rollbackLogs(t, b)) != 0 {
				t.Fatal("malformed file created")
			}
			var got string
			db.QueryRow("SELECT payload FROM events WHERE id='original-id'").Scan(&got)
			if got != raw {
				t.Fatal("invalid event was deleted or rewritten")
			}
		})
	}
}
func TestRollbackFilePublicationRejectsReplacementAndLinks(t *testing.T) {
	b, r, h, db := rollbackFixture(t)
	if _, err := b.exportRollbackPending(context.Background(), r, h.installed); err != nil {
		t.Fatal(err)
	}
	var path string
	if err := db.QueryRow("SELECT exported FROM events WHERE id='original-id'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.exportRollbackPending(context.Background(), r, h.installed); err == nil {
		t.Fatal("changed file accepted")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "tampered" {
		t.Fatal("unverified export overwritten")
	}
}
