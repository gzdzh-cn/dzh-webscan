package nodeops

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webscan/internal/persist"
)

func restorationData(t *testing.T, a *activationMachine) *sql.DB {
	t.Helper()
	db, err := persist.OpenDB(filepath.Join(a.activation.backup.data, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE manifest(path TEXT PRIMARY KEY,hash TEXT); CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT,created REAL,exported TEXT,accepted REAL); CREATE TABLE jobs(id INTEGER PRIMARY KEY,path TEXT); CREATE TABLE scans(id INTEGER PRIMARY KEY,path TEXT); CREATE TABLE logfiles(path TEXT PRIMARY KEY,created REAL); INSERT INTO manifest VALUES('/site/keep','baseline'); INSERT INTO jobs VALUES(1,'/site/task'); INSERT INTO scans VALUES(1,'/site/scan'); INSERT INTO events VALUES('after-snapshot','{"event_id":"after-snapshot","node_id":"node-one"}',1,NULL,NULL); INSERT INTO events VALUES('confirmed','{"event_id":"confirmed","node_id":"node-one"}',0,NULL,42);`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}
func TestNativeRestoreBeforeAndAfterActivationRetainsCurrentData(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		for _, activated := range []bool{false, true} {
			name := "existing"
			if fresh {
				name = "fresh"
			}
			if activated {
				name += "-activated"
			} else {
				name += "-backup-only"
			}
			t.Run(name, func(t *testing.T) {
				a := nativeActivationFixture(t, fresh)
				ctx := context.Background()
				if activated {
					if err := a.activation.run(ctx, a.request); err != nil {
						t.Fatal(err)
					}
				}
				db := restorationData(t, a)
				pki := filepath.Join(a.activation.backup.data, "pki-trust")
				if err := os.Mkdir(pki, 0700); err != nil {
					t.Fatal(err)
				}
				floor := filepath.Join(pki, "floor.json")
				if err := os.WriteFile(floor, []byte("new-revocation-floor"), 0600); err != nil {
					t.Fatal(err)
				}
				identity := filepath.Join(a.activation.backup.data, "pki-identity", "active.pem")
				if err := os.MkdirAll(filepath.Dir(identity), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(identity, []byte("post-switch-renewed-identity"), 0600); err != nil {
					t.Fatal(err)
				}
				r := a.request
				r.Phase = "restore"
				if err := a.activation.restore(ctx, r); err != nil {
					t.Fatal(err)
				}
				p, err := a.activation.restorePlan(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				if err := a.activation.confirmRestored(ctx, p); err != nil {
					t.Fatal(err)
				}
				if a.machine.nativeRunning == fresh || a.machine.nativeEnabled == fresh {
					t.Fatal("original service state not restored")
				}
				var n int
				if err := db.QueryRow("SELECT count(*) FROM events WHERE id='after-snapshot' AND accepted IS NULL AND exported IS NOT NULL").Scan(&n); err != nil || n != 1 {
					t.Fatal("new event lost", n, err)
				}
				if err := db.QueryRow("SELECT count(*) FROM events WHERE id='confirmed' AND accepted=42 AND exported IS NULL").Scan(&n); err != nil || n != 1 {
					t.Fatal("confirmation overwritten", n, err)
				}
				assertBackupRows(t, filepath.Join(a.activation.backup.data, "agent.sqlite3"), 2)
				raw, _ := os.ReadFile(floor)
				if string(raw) != "new-revocation-floor" {
					t.Fatal("revocation floor rolled back")
				}
				if raw, err := os.ReadFile(identity); err != nil || string(raw) != "post-switch-renewed-identity" {
					t.Fatal("renewed node identity rolled back", err)
				}
				starts := a.starts
				if err := a.activation.restore(ctx, r); err != nil {
					t.Fatal("replayed restore failed", err)
				}
				if a.starts != starts {
					t.Fatal("lost restore receipt restarted old writer")
				}
				if err := a.activation.run(ctx, a.request); err == nil || err.Error() != "rollback-already-started" {
					t.Fatal("forward activation allowed after rollback", err)
				}
			})
		}
	}
}
func TestNativeRestoreContinuesAfterServiceResponseLoss(t *testing.T) {
	for _, op := range []string{"disable", "daemon-reload", "start"} {
		t.Run(op, func(t *testing.T) {
			a := nativeActivationFixture(t, false)
			ctx := context.Background()
			if err := a.activation.run(ctx, a.request); err != nil {
				t.Fatal(err)
			}
			restorationData(t, a)
			r := a.request
			r.Phase = "restore"
			a.crashAfter = op
			if err := a.activation.restore(ctx, r); err == nil {
				t.Fatal("response loss hidden")
			}
			a.crashAfter = ""
			r.Epoch++
			if err := a.activation.restore(ctx, r); err != nil {
				t.Fatal("restore could not continue", err)
			}
			if a.starts != 2 {
				t.Fatal("target/original started repeatedly", a.starts)
			}
		})
	}
}
func TestNativeRestoreCanUndoDamagedNewRuntime(t *testing.T) {
	a := nativeActivationFixture(t, false)
	ctx := context.Background()
	if err := a.activation.run(ctx, a.request); err != nil {
		t.Fatal(err)
	}
	restorationData(t, a)
	// New configuration/binary damage must not invalidate the original recovery
	// evidence. The generated unit is retained in the activation intent itself.
	w := a.activation.runtime
	for _, path := range []string{filepath.Join(w.configurationDir(a.request.Spec), "runtime.json"), filepath.Join(w.configurationDir(a.request.Spec), nativeServiceName), filepath.Join(w.releaseDir(a.request.Spec), "webscan")} {
		if err := os.WriteFile(path, []byte("damaged-target"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := a.request
	r.Phase = "restore"
	if err := a.activation.restore(ctx, r); err != nil {
		t.Fatal("damaged target prevented data-preserving rollback", err)
	}
	if err := a.activation.restore(ctx, r); err != nil {
		t.Fatal("restored original still depends on target artifact", err)
	}
}
func TestNativeRestoreRejectsForeignStateAndPreservesData(t *testing.T) {
	for _, kind := range []string{"unit", "pointer", "intent", "export-receipt", "original-config", "writer-lock", "scope"} {
		t.Run(kind, func(t *testing.T) {
			a := nativeActivationFixture(t, false)
			ctx := context.Background()
			if err := a.activation.run(ctx, a.request); err != nil {
				t.Fatal(err)
			}
			db := restorationData(t, a)
			r := a.request
			r.Phase = "restore"
			var unlock func()
			switch kind {
			case "unit":
				os.WriteFile(a.machine.host.unitPath, []byte("foreign service"), 0600)
			case "pointer":
				os.WriteFile(filepath.Join(a.activation.runtime.root, "active.json"), []byte("foreign pointer"), 0600)
			case "intent":
				os.WriteFile(a.activation.intentPath(r), []byte("corrupted receipt"), 0600)
			case "export-receipt":
				p, err := a.activation.restorePlan(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := a.activation.restoreIntent(r, p); err != nil {
					t.Fatal(err)
				}
				os.WriteFile(filepath.Join(a.activation.restoreDirectory(r), "export.json"), []byte("{}"), 0600)
			case "original-config":
				os.WriteFile(filepath.Join(a.machine.host.configRoot, "runtime.json"), []byte("new outside config"), 0600)
			case "writer-lock":
				lock, err := a.activation.backup.agentLock()
				if err != nil {
					t.Fatal(err)
				}
				unlock = func() { lock.Close() }
			case "scope":
				r.PlanDigest = strings.Repeat("f", 64)
			}
			if unlock != nil {
				defer unlock()
			}
			if err := a.activation.restore(ctx, r); err == nil {
				t.Fatal("unsafe restore accepted")
			}
			var n int
			if err := db.QueryRow("SELECT count(*) FROM events").Scan(&n); err != nil || n != 2 {
				t.Fatal("failure destroyed current events", err)
			}
		})
	}
}
func TestNativeRestoreOriginalStartLossDoesNotStopItAgain(t *testing.T) {
	a := nativeActivationFixture(t, false)
	ctx := context.Background()
	if err := a.activation.run(ctx, a.request); err != nil {
		t.Fatal(err)
	}
	restorationData(t, a)
	r := a.request
	r.Phase = "restore"
	base := a.activation.host.command
	a.activation.host.command = func(ctx context.Context, p string, args ...string) (string, error) {
		raw, err := base(ctx, p, args...)
		if p == "systemctl" && args[0] == "start" {
			return raw, errors.New("start response lost")
		}
		return raw, err
	}
	if err := a.activation.restore(ctx, r); err == nil {
		t.Fatal("loss not reported")
	}
	a.activation.host.command = base
	before := len(a.machine.calls)
	if err := a.activation.restore(ctx, r); err != nil {
		t.Fatal(err)
	}
	for _, call := range a.machine.calls[before:] {
		if strings.Contains(call, " disable ") || strings.Contains(call, " start ") {
			t.Fatal("already-restored original touched again", call)
		}
	}
}

func TestNativeRestorePreservesOriginallyStoppedAndDisabledStates(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, running := range []bool{false, true} {
			a := nativeActivationFixture(t, false, [2]bool{enabled, running})
			ctx := context.Background()
			if err := a.activation.run(ctx, a.request); err != nil {
				t.Fatal(err)
			}
			r := a.request
			r.Phase = "restore"
			if err := a.activation.restore(ctx, r); err != nil {
				t.Fatal(err)
			}
			if a.machine.nativeEnabled != enabled || a.machine.nativeRunning != running {
				t.Fatal("original enabled/running state lost", enabled, running)
			}
			wantStarts := 1
			if running {
				wantStarts++
			}
			if a.starts != wantStarts {
				t.Fatal("unrequested original service started", a.starts, wantStarts)
			}
		}
	}
}

func TestNativeRestoreSameReleaseAndConfigurationUsesOriginalTaskPointer(t *testing.T) {
	a := nativeActivationFixture(t, true)
	ctx := context.Background()
	if err := a.activation.run(ctx, a.request); err != nil {
		t.Fatal(err)
	}
	oldPointer, err := os.ReadFile(filepath.Join(a.activation.runtime.root, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := a.request
	r.Job += "-same-config"
	r.PlanDigest = strings.Repeat("d", 64)
	r.Phase = "backup"
	if _, err := a.activation.backup.run(ctx, r); err != nil {
		t.Fatal("v3 source backup failed", err)
	}
	r.Phase = "activate"
	if err := a.activation.run(ctx, r); err != nil {
		t.Fatal("same-config activation failed", err)
	}
	current, err := os.ReadFile(filepath.Join(a.activation.runtime.root, "active.json"))
	if err != nil || string(current) == string(oldPointer) {
		t.Fatal("new task identity not published", err)
	}
	r.Phase = "restore"
	if err := a.activation.restore(ctx, r); err != nil {
		t.Fatal("same-config rollback failed", err)
	}
	current, err = os.ReadFile(filepath.Join(a.activation.runtime.root, "active.json"))
	if err != nil || string(current) != string(oldPointer) {
		t.Fatal("original task pointer not restored", err)
	}
	starts := a.starts
	if err := a.activation.restore(ctx, r); err != nil || a.starts != starts {
		t.Fatal("replayed same-config rollback restarted writer", err)
	}
}

func TestNativeRestoreRevalidatesExportBeforeRestartingStoppedOriginal(t *testing.T) {
	for _, damaged := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "corrupt"}[damaged], func(t *testing.T) {
			a := nativeActivationFixture(t, false)
			ctx := context.Background()
			if err := a.activation.run(ctx, a.request); err != nil {
				t.Fatal(err)
			}
			db := restorationData(t, a)
			r := a.request
			r.Phase = "restore"
			a.fail = "start"
			if err := a.activation.restore(ctx, r); err == nil {
				t.Fatal("missing start failure")
			}
			var path string
			if err := db.QueryRow("SELECT exported FROM events WHERE id='after-snapshot'").Scan(&path); err != nil {
				t.Fatal(err)
			}
			if damaged {
				if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			a.fail = ""
			err := a.activation.restore(ctx, r)
			if damaged {
				if err == nil || a.machine.nativeRunning {
					t.Fatal("corrupt export allowed service restart", err)
				}
			} else {
				if err != nil || !a.machine.nativeRunning {
					t.Fatal("missing export was not safely recreated", err)
				}
				raw, err := os.ReadFile(path)
				if err != nil || !strings.Contains(string(raw), "after-snapshot") {
					t.Fatal("pending event not restored to log", err)
				}
			}
			var n int
			if err := db.QueryRow("SELECT count(*) FROM events WHERE id='after-snapshot' AND accepted IS NULL").Scan(&n); err != nil || n != 1 {
				t.Fatal("pending event lost", err)
			}
		})
	}
}

func TestNativeRestoreBeforeSnapshotPublicationPreservesOriginalAndCurrentDB(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing", true: "fresh"}[fresh], func(t *testing.T) {
			a := nativeActivationFixture(t, fresh)
			ctx := context.Background()
			db := restorationData(t, a)
			// A new job starts with the original running state, then encounters a
			// writer-lock failure after disabling/stopping the captured service.
			a.machine.nativeRunning, a.machine.nativeEnabled = !fresh, !fresh
			r := a.request
			r.Job += "-interrupted-backup"
			r.Phase = "backup"
			lock, err := a.activation.backup.agentLock()
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.activation.backup.run(ctx, r)
			lock.Close()
			if err == nil {
				t.Fatal("backup did not fail at held writer lock")
			}
			if _, err := os.Lstat(filepath.Join(a.activation.backup.directory(r), "snapshot")); !os.IsNotExist(err) {
				t.Fatal("snapshot unexpectedly exists", err)
			}
			intent, err := a.activation.backup.readIntent(ctx, r)
			if err != nil || intent.DatabasePresent == nil || !*intent.DatabasePresent {
				t.Fatal("pre-stop database presence not recorded", err)
			}
			r.Phase = "restore"
			if err := a.activation.restore(ctx, r); err != nil {
				t.Fatal("interrupted backup cannot restore original", err)
			}
			if a.machine.nativeRunning == fresh || a.machine.nativeEnabled == fresh {
				t.Fatal("original running state lost")
			}
			var n int
			if err := db.QueryRow("SELECT count(*) FROM events WHERE id='after-snapshot' AND accepted IS NULL AND exported IS NOT NULL").Scan(&n); err != nil || n != 1 {
				t.Fatal("current pending data not preserved", err)
			}
			if err := a.activation.restore(ctx, r); err != nil {
				t.Fatal("capture-only restoration not repeatable", err)
			}
			r.Phase = "backup"
			if _, err := a.activation.backup.run(ctx, r); err == nil || err.Error() != "rollback-already-started" {
				t.Fatal("backup stopped a restored original", err)
			}
		})
	}
}

func TestNativeRestoreRefusesMissingSnapshotAfterActivation(t *testing.T) {
	a := nativeActivationFixture(t, false)
	ctx := context.Background()
	if err := a.activation.run(ctx, a.request); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(a.activation.backup.directory(a.request), "snapshot")); err != nil {
		t.Fatal(err)
	}
	r := a.request
	r.Phase = "restore"
	before := len(a.machine.calls)
	if err := a.activation.restore(ctx, r); err == nil || err.Error() != "activated-snapshot-missing" {
		t.Fatal("missing activated snapshot silently bypassed", err)
	}
	if len(a.machine.calls) != before {
		t.Fatal("unproved recovery changed service state")
	}
}
