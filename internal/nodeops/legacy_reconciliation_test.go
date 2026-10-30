package nodeops

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webscan/internal/persist"
)

func legacyImportData(t *testing.T, b *transitionBackup, files map[string]string) *sql.DB {
	t.Helper()
	for _, dir := range []string{b.data, b.logs} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := persist.OpenDB(filepath.Join(b.data, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE manifest(path TEXT PRIMARY KEY,hash TEXT);
 CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT,created REAL,exported TEXT,accepted REAL);
 CREATE TABLE jobs(id INTEGER PRIMARY KEY,path TEXT); CREATE TABLE scans(id INTEGER PRIMARY KEY,path TEXT);
 CREATE TABLE logfiles(path TEXT PRIMARY KEY,created REAL);
 CREATE TABLE delivery_failures(id TEXT PRIMARY KEY,error TEXT NOT NULL,created REAL NOT NULL);
 INSERT INTO manifest VALUES('/site/keep','baseline'); INSERT INTO jobs VALUES(1,'/site/task'); INSERT INTO scans VALUES(1,'/site/scan');
 INSERT INTO events VALUES('known','{"event_id":"known","node_id":"node-one","scan":{"status":"pending"}}',1,'original-log',NULL);
 INSERT INTO events VALUES('confirmed','{"event_id":"confirmed","node_id":"node-one"}',2,'confirmed-log',42);
 INSERT INTO events VALUES('rejected','{"event_id":"rejected","node_id":"node-one"}',3,NULL,NULL);
 INSERT INTO delivery_failures VALUES('rejected','retained-rejection',3);`); err != nil {
		t.Fatal(err)
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(b.logs, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func legacyImportEvent(id string) string {
	return fmt.Sprintf(`{"event_id":%q,"node_id":"node-one","sequence":9007199254740993}`, id)
}

func TestLegacyReconciliationImportsMissingIDsAndPreservesSQLiteAuthority(t *testing.T) {
	var db *sql.DB
	files := map[string]string{
		"events-a.jsonl":   legacyImportEvent("new") + "\r\n" + legacyImportEvent("known") + "\n" + legacyImportEvent("confirmed") + "\n" + legacyImportEvent("rejected") + "\n",
		"events-b.jsonl":   legacyImportEvent("new") + "\n" + legacyImportEvent("last-without-newline"),
		"diagnostic.jsonl": "unrelated diagnostic, not the Vector source\n",
	}
	a := dockerActivationFixture(t, false, func(b *transitionBackup) { db = legacyImportData(t, b, files) })
	if err := a.activation.run(context.Background(), a.request); err != nil {
		t.Fatal(err)
	}
	var receipt legacyImportReceipt
	i, err := a.activation.backup.readIntent(context.Background(), a.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePrivateJSON(a.activation.backup.legacyReceiptPath(i), &receipt, 4096); err != nil || receipt.Files != 2 || receipt.Records != 6 || receipt.Inserted != 2 {
		t.Fatal("incorrect import receipt", receipt, err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE id IN ('new','last-without-newline') AND accepted IS NULL AND exported IS NULL AND payload LIKE '%9007199254740993%'`).Scan(&n); err != nil || n != 2 {
		t.Fatal("missing IDs or changed integer digits", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE id='known' AND created=1 AND exported='original-log' AND accepted IS NULL AND payload LIKE '%pending%'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("existing pending scan overwritten", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE id='confirmed' AND accepted=42 AND exported='confirmed-log'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("confirmation overwritten", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM delivery_failures WHERE id='rejected' AND error='retained-rejection'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("quarantine changed", n, err)
	}
	assertBackupRows(t, filepath.Join(a.activation.backup.data, "agent.sqlite3"), 5)
	assertBackupRows(t, filepath.Join(a.activation.backup.directory(a.request), "snapshot", "agent.sqlite3"), 3)
	for name, contents := range files {
		raw, err := os.ReadFile(filepath.Join(a.activation.backup.logs, name))
		if err != nil || string(raw) != contents {
			t.Fatal("original logs changed", name, err)
		}
	}
	if err := a.activation.run(context.Background(), a.request); err != nil || a.creates != 1 || a.starts != 1 {
		t.Fatal("activation replay duplicated target", err)
	}
	assertBackupRows(t, filepath.Join(a.activation.backup.data, "agent.sqlite3"), 5)
}

func TestLegacyReconciliationCommitsBoundedBatchesAndResumesAfterWriteFailure(t *testing.T) {
	var db *sql.DB
	var source strings.Builder
	for index := 0; index < 251; index++ {
		source.WriteString(legacyImportEvent(fmt.Sprintf("legacy-%03d", index)) + "\n")
	}
	a := dockerActivationFixture(t, false, func(b *transitionBackup) {
		db = legacyImportData(t, b, map[string]string{"events-batches.jsonl": source.String()})
		if _, err := db.Exec(`CREATE TRIGGER import_failure BEFORE INSERT ON events WHEN NEW.id='legacy-150' BEGIN SELECT RAISE(ABORT,'private disk failure fixture'); END`); err != nil {
			t.Fatal(err)
		}
	})
	err := a.activation.run(context.Background(), a.request)
	if err == nil || err.Error() != "legacy-import-write-failed" || a.creates != 0 || a.starts != 0 {
		t.Fatal("import failure enabled a writer or leaked error", err)
	}
	var count, records, inserted int
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE id LIKE 'legacy-%'`).Scan(&count); err != nil || count != 100 {
		t.Fatal("partial batch committed", count, err)
	}
	if err := db.QueryRow(`SELECT records,inserted FROM nodeops_legacy_imports`).Scan(&records, &inserted); err != nil || records != 100 || inserted != 100 {
		t.Fatal("event inserts and checkpoint separated", records, inserted, err)
	}
	// The snapshot is fixed; only the local write error is repaired, then a new
	// executor generation continues the committed cursor and original IDs.
	if _, err := db.Exec(`DROP TRIGGER import_failure`); err != nil {
		t.Fatal(err)
	}
	a.request.Epoch++
	if err := a.activation.run(context.Background(), a.request); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE id LIKE 'legacy-%'`).Scan(&count); err != nil || count != 251 || a.creates != 1 || a.starts != 1 {
		t.Fatal("resume lost or duplicated events", count, err)
	}
	if err := db.QueryRow(`SELECT records,inserted FROM nodeops_legacy_imports`).Scan(&records, &inserted); err != nil || records != 251 || inserted != 251 {
		t.Fatal("resume did not continue checkpoint", records, inserted, err)
	}
}

func TestLegacyReconciliationRejectsConflictingLogOnlyIDs(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			var db *sql.DB
			second := ` { "sequence":9007199254740993, "node_id":"node-one", "event_id":"log-only" }` + "\r\n"
			if changed {
				second = strings.Replace(second, "9007199254740993", "9007199254740994", 1)
			}
			a := dockerActivationFixture(t, false, func(b *transitionBackup) {
				db = legacyImportData(t, b, map[string]string{"events-a.jsonl": legacyImportEvent("log-only") + "\n", "events-b.jsonl": second})
			})
			err := a.activation.run(context.Background(), a.request)
			if changed {
				if err == nil || err.Error() != "legacy-import-id-conflict" || a.starts != 0 || a.creates != 0 {
					t.Fatal("conflicting ID discarded", err)
				}
				r := a.request
				r.Phase = "restore"
				if err := a.activation.restore(context.Background(), r); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal("equivalent JSON rejected", err)
			}
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM events WHERE id='log-only' AND payload LIKE '%9007199254740993%'`).Scan(&n); err != nil || n != 1 {
				t.Fatal("original log event changed", n, err)
			}
		})
	}
}

func TestLegacyReconciliationRejectsMalformedInputBeforeActivation(t *testing.T) {
	for name, contents := range map[string]string{
		"invalid-json":   "{",
		"missing-id":     `{"node_id":"node-one"}`,
		"empty-id":       `{"event_id":"","node_id":"node-one"}`,
		"other-node":     `{"event_id":"other","node_id":"node-two"}`,
		"duplicate-node": `{"event_id":"other","node_id":"node-two","node_id":"node-one"}`,
		"duplicate-id":   `{"event_id":"first","event_id":"last","node_id":"node-one"}`,
		"trailing-json":  legacyImportEvent("first") + " {}",
		"blank-line":     "\n",
		"invalid-utf8":   "{\"event_id\":\"bad\",\"node_id\":\"node-one\",\"data\":\"\xff\"}",
		"oversize":       `{"event_id":"huge","node_id":"node-one","data":"` + strings.Repeat("a", rollbackEventBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var db *sql.DB
			a := dockerActivationFixture(t, false, func(b *transitionBackup) {
				db = legacyImportData(t, b, map[string]string{"events-bad.jsonl": contents})
			})
			err := a.activation.run(context.Background(), a.request)
			if err == nil || !strings.HasPrefix(err.Error(), "legacy-import-") || a.starts != 0 || a.creates != 0 {
				t.Fatal("unsafe source accepted", err)
			}
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM events`).Scan(&n); err != nil || n != 3 {
				t.Fatal("bad file changed existing data", n, err)
			}
			// Failure must remain recoverable without replacing the current DB.
			r := a.request
			r.Phase = "restore"
			if err := a.activation.restore(context.Background(), r); err != nil {
				t.Fatal("failed import cannot roll back", err)
			}
		})
	}
}

func TestLegacyReconciliationContinuesCommittedImportWithoutCompletionReceipt(t *testing.T) {
	var db *sql.DB
	a := dockerActivationFixture(t, false, func(b *transitionBackup) {
		db = legacyImportData(t, b, map[string]string{"events-complete.jsonl": legacyImportEvent("complete")})
	})
	b := a.activation.backup
	ctx, release, err := acquireServiceOperation(context.Background(), b.root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := b.agentLock()
	if err != nil {
		release()
		t.Fatal(err)
	}
	err = b.reconcileLegacyLogsLocked(ctx, a.request)
	lock.Close()
	release()
	if err != nil {
		t.Fatal(err)
	}
	i, err := b.readIntent(context.Background(), a.request)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(b.legacyReceiptPath(i)); err != nil {
		t.Fatal(err)
	}
	// Simulate the last file transaction committing before receipt publication.
	if err := a.activation.run(context.Background(), a.request); err != nil {
		t.Fatal(err)
	}
	var receipt legacyImportReceipt
	if _, err := decodePrivateJSON(b.legacyReceiptPath(i), &receipt, 4096); err != nil || receipt.Records != 1 || receipt.Inserted != 1 {
		t.Fatal("lost final response changed progress", receipt, err)
	}
	assertBackupRows(t, filepath.Join(b.data, "agent.sqlite3"), 4)
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM nodeops_legacy_imports WHERE records=1 AND inserted=1 AND offset=bytes`).Scan(&n); err != nil || n != 1 {
		t.Fatal("completed file was imported twice", n, err)
	}
}

func TestLegacyReconciliationRejectsMissingLiveDatabaseAndDoesNotCreateIt(t *testing.T) {
	for _, kind := range []string{"original-missing", "live-missing", "zero-logs-live-missing"} {
		t.Run(kind, func(t *testing.T) {
			var db *sql.DB
			a := dockerActivationFixture(t, false, func(b *transitionBackup) {
				files := map[string]string{}
				if kind != "zero-logs-live-missing" {
					files["events-source.jsonl"] = legacyImportEvent("missing-db")
				}
				db = legacyImportData(t, b, files)
				if kind == "original-missing" {
					db.Close()
					if err := os.Remove(filepath.Join(b.data, "agent.sqlite3")); err != nil {
						t.Fatal(err)
					}
				}
			})
			if kind != "original-missing" {
				db.Close()
				if err := os.Remove(filepath.Join(a.activation.backup.data, "agent.sqlite3")); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.activation.run(context.Background(), a.request); err == nil || a.starts != 0 || a.creates != 0 {
				t.Fatal("missing DB accepted", err)
			}
			if _, err := os.Lstat(filepath.Join(a.activation.backup.data, "agent.sqlite3")); !os.IsNotExist(err) {
				t.Fatal("missing DB silently created", err)
			}
		})
	}
}

func TestLegacyReconciliationRollbackRetainsPartiallyImportedEvents(t *testing.T) {
	var db *sql.DB
	var source strings.Builder
	for index := 0; index < 100; index++ {
		source.WriteString(legacyImportEvent(fmt.Sprintf("legacy-%03d", index)) + "\n")
	}
	source.WriteString(`{"event_id":"bad","node_id":"foreign"}`)
	a := dockerActivationFixture(t, false, func(b *transitionBackup) {
		db = legacyImportData(t, b, map[string]string{"events-partial.jsonl": source.String()})
	})
	if err := a.activation.run(context.Background(), a.request); err == nil {
		t.Fatal("bad input accepted")
	}
	r := a.request
	r.Phase = "restore"
	if err := a.activation.restore(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE id LIKE 'legacy-%' AND accepted IS NULL AND exported IS NOT NULL`).Scan(&count); err != nil || count != 100 {
		t.Fatal("rollback lost successfully imported events", count, err)
	}
	assertBackupRows(t, filepath.Join(a.activation.backup.data, "agent.sqlite3"), 103)
}

func TestLegacyReconciliationDoesNotTrustChangedSourceCheckpointOrReceipt(t *testing.T) {
	for _, kind := range []string{"snapshot", "source-link", "live-db-link", "receipt", "cursor", "binding", "digest", "snapshot-binding", "lock"} {
		t.Run(kind, func(t *testing.T) {
			var db *sql.DB
			a := dockerActivationFixture(t, false, func(b *transitionBackup) {
				db = legacyImportData(t, b, map[string]string{"events-source.jsonl": legacyImportEvent("new") + "\n"})
			})
			b := a.activation.backup
			i, err := b.readIntent(context.Background(), a.request)
			if err != nil {
				t.Fatal(err)
			}
			var unlock func()
			switch kind {
			case "snapshot", "source-link":
				path := filepath.Join(b.directory(a.request), "snapshot", "logs", "events-source.jsonl")
				if kind == "snapshot" {
					err = os.WriteFile(path, []byte("changed"), 0600)
				} else {
					err = os.Remove(path)
					if err == nil {
						err = os.Symlink(filepath.Join(b.logs, "events-source.jsonl"), path)
					}
				}
			case "live-db-link":
				db.Close()
				path := filepath.Join(b.data, "agent.sqlite3")
				err = os.Rename(path, path+".keep")
				if err == nil {
					err = os.Symlink(path+".keep", path)
				}
			case "receipt":
				err = os.MkdirAll(filepath.Dir(b.legacyReceiptPath(i)), 0700)
				if err == nil {
					err = os.WriteFile(b.legacyReceiptPath(i), []byte("damaged"), 0600)
				}
			case "lock":
				var lock *os.File
				lock, err = b.agentLock()
				if err == nil {
					unlock = func() { lock.Close() }
				}
			default:
				// Seed a real completed checkpoint by importing with both locks;
				// remove only the completion receipt, then corrupt the SQLite cursor.
				ctx, release, lockErr := acquireServiceOperation(context.Background(), b.root)
				if lockErr != nil {
					t.Fatal(lockErr)
				}
				lock, lockErr := b.agentLock()
				if lockErr != nil {
					release()
					t.Fatal(lockErr)
				}
				err = b.reconcileLegacyLogsLocked(ctx, a.request)
				lock.Close()
				release()
				if err == nil {
					err = os.Remove(b.legacyReceiptPath(i))
				}
				if err == nil {
					query := map[string]string{"cursor": "offset=1", "binding": "binding='changed'", "digest": "digest='changed'", "snapshot-binding": "snapshot='changed'"}[kind]
					_, err = db.Exec(`UPDATE nodeops_legacy_imports SET ` + query)
				}
			}
			if unlock != nil {
				defer unlock()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := a.activation.run(context.Background(), a.request); err == nil || a.starts != 0 || a.creates != 0 {
				t.Fatal("changed migration evidence enabled target", err)
			}
		})
	}
}

func TestLegacyReconciliationIsRequiredForNativeActivation(t *testing.T) {
	a := nativeActivationFixture(t, false)
	b := a.activation.backup
	db := legacyImportData(t, b, map[string]string{"events-native.jsonl": legacyImportEvent("native-log-only") + "\n"})
	r := a.request
	r.Job = "native-legacy-import"
	r.Phase = "backup"
	if _, err := b.run(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r.Phase = "activate"
	if err := a.activation.run(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE id='native-log-only' AND exported IS NULL AND accepted IS NULL`).Scan(&n); err != nil || n != 1 {
		t.Fatal("native skipped reconciliation", n, err)
	}
	i, err := b.readIntent(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.legacyReceiptPath(i), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.activation.run(context.Background(), r); err == nil || a.starts != 1 {
		t.Fatal("running native target accepted lost reconciliation proof", err)
	}
}

func TestLegacyReconciliationValidatesCompletedReceiptOnReplay(t *testing.T) {
	a := dockerActivationFixture(t, false)
	if err := a.activation.run(context.Background(), a.request); err != nil {
		t.Fatal(err)
	}
	i, err := a.activation.backup.readIntent(context.Background(), a.request)
	if err != nil {
		t.Fatal(err)
	}
	path := a.activation.backup.legacyReceiptPath(i)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt legacyImportReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.Binding.Job = "another-job"
	changed, _ := json.Marshal(receipt)
	if bytes.Equal(raw, changed) {
		t.Fatal("fixture unchanged")
	}
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.activation.run(context.Background(), a.request); err == nil || a.creates != 1 || a.starts != 1 {
		t.Fatal("invalid receipt accepted on running target", err)
	}
}
