package nodeops

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webscan/internal/persist"
)

func dockerRestorationData(t *testing.T, a *dockerActivationMachine) *sql.DB {
	t.Helper()
	db, err := persist.OpenDB(filepath.Join(a.activation.backup.data, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE manifest(path TEXT PRIMARY KEY,hash TEXT); CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT,created REAL,exported TEXT,accepted REAL); CREATE TABLE jobs(id INTEGER PRIMARY KEY,path TEXT); CREATE TABLE scans(id INTEGER PRIMARY KEY,path TEXT); CREATE TABLE logfiles(path TEXT PRIMARY KEY,created REAL); INSERT INTO manifest VALUES('/site/keep','baseline'); INSERT INTO jobs VALUES(1,'/site/task'); INSERT INTO scans VALUES(1,'/site/scan'); INSERT INTO events VALUES('after-snapshot','{"event_id":"after-snapshot","node_id":"node-one"}',1,NULL,NULL); INSERT INTO events VALUES('confirmed','{"event_id":"confirmed","node_id":"node-one"}',0,NULL,42);`); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestDockerRestoreRetainsCurrentDataAndOriginalContainer(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		for _, activated := range []bool{false, true} {
			t.Run(fmt.Sprintf("fresh=%v/activated=%v", fresh, activated), func(t *testing.T) {
				a := dockerActivationFixture(t, fresh)
				if activated {
					if err := a.activation.run(context.Background(), a.request); err != nil {
						t.Fatal(err)
					}
				}
				db := dockerRestorationData(t, a)
				floor := filepath.Join(a.activation.backup.data, "pki-trust", "floor.json")
				if err := os.MkdirAll(filepath.Dir(floor), 0700); err != nil {
					t.Fatal(err)
				}
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
				if err := a.activation.restore(context.Background(), r); err != nil {
					t.Fatal(err)
				}
				if !fresh {
					c, ok := a.machine.containers[strings.Repeat("1", 64)]
					if !ok || c.Name != "/"+agentContainerName || c.Status != "running" || c.Restart != "unless-stopped" {
						t.Fatal("original not restored", c)
					}
				}
				if activated {
					c, ok := a.machine.containers[a.target.ID]
					if !ok || c.Status == "running" || c.Restart != "no" || !strings.HasPrefix(c.Name, "/webscan-failed-") {
						t.Fatal("failed target lost or active", c)
					}
				}
				assertBackupRows(t, filepath.Join(a.activation.backup.data, "agent.sqlite3"), 2)
				var n int
				if err := db.QueryRow("SELECT count(*) FROM events WHERE id='after-snapshot' AND accepted IS NULL AND exported IS NOT NULL").Scan(&n); err != nil || n != 1 {
					t.Fatal("new event not exported", n, err)
				}
				if err := db.QueryRow("SELECT count(*) FROM events WHERE id='confirmed' AND accepted=42 AND exported IS NULL").Scan(&n); err != nil || n != 1 {
					t.Fatal("confirmation lost", n, err)
				}
				if raw, err := os.ReadFile(floor); err != nil || string(raw) != "new-revocation-floor" {
					t.Fatal("trust state rolled back", err)
				}
				if raw, err := os.ReadFile(identity); err != nil || string(raw) != "post-switch-renewed-identity" {
					t.Fatal("renewed node identity rolled back", err)
				}
				starts := a.starts
				if err := a.activation.restore(context.Background(), r); err != nil || a.starts != starts {
					t.Fatal("replayed restore restarted a writer", err, a.starts, starts)
				}
				if err := a.activation.run(context.Background(), a.request); err == nil || err.Error() != "rollback-already-started" {
					t.Fatal("forward replay allowed after recovery", err)
				}
			})
		}
	}
}

func TestDockerRestoreContinuesLostResponsesAndDamagedTarget(t *testing.T) {
	for _, kind := range []string{"stop", "rename", "update", "start", "new-program", "new-config", "new-compose", "create-response"} {
		t.Run(kind, func(t *testing.T) {
			a := dockerActivationFixture(t, false)
			if kind == "create-response" {
				a.failAfter = "compose"
				if err := a.activation.run(context.Background(), a.request); err == nil {
					t.Fatal("injection failed")
				}
				a.failAfter = ""
			} else if err := a.activation.run(context.Background(), a.request); err != nil {
				t.Fatal(err)
			}
			dockerRestorationData(t, a)
			switch kind {
			case "new-program":
				os.WriteFile(filepath.Join(a.activation.runtime.releaseDir(a.request.Spec), "webscan"), []byte("damaged"), 0700)
			case "new-config":
				os.WriteFile(filepath.Join(a.activation.runtime.configurationDir(a.request.Spec), "runtime.json"), []byte("damaged"), 0600)
			case "new-compose":
				os.WriteFile(filepath.Join(a.activation.runtime.configurationDir(a.request.Spec), "compose.json"), []byte("damaged"), 0600)
			case "stop", "rename", "update", "start":
				a.failAfter = kind
			}
			r := a.request
			r.Phase = "restore"
			err := a.activation.restore(context.Background(), r)
			if a.failAfter != "" {
				if err == nil {
					t.Fatal("response loss reported success")
				}
				a.failAfter = ""
				r.Epoch++
				err = a.activation.restore(context.Background(), r)
			}
			if err != nil {
				t.Fatal("cannot restore", err)
			}
			p, err := a.activation.restorePlan(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.activation.confirmRestored(context.Background(), r, p); err != nil {
				t.Fatal(err)
			}
			if a.creates != 1 {
				t.Fatal("created extra container during recovery")
			}
		})
	}
}

func TestDockerRestoreRefusesForeignOrMissingProof(t *testing.T) {
	for _, kind := range []string{"old-missing", "target-missing", "old-changed", "target-changed", "foreign-pointer", "corrupt-receipt", "corrupt-snapshot", "name-collision", "live-lock"} {
		t.Run(kind, func(t *testing.T) {
			a := dockerActivationFixture(t, false)
			if err := a.activation.run(context.Background(), a.request); err != nil {
				t.Fatal(err)
			}
			dockerRestorationData(t, a)
			var unlock func()
			switch kind {
			case "old-missing":
				delete(a.machine.containers, strings.Repeat("1", 64))
			case "target-missing":
				delete(a.machine.containers, a.target.ID)
			case "old-changed":
				c := a.machine.containers[strings.Repeat("1", 64)]
				c.Image = "foreign:latest"
				a.machine.containers[c.ID] = c
			case "target-changed":
				c := a.machine.containers[a.target.ID]
				c.Command = []string{"foreign"}
				a.machine.containers[c.ID] = c
			case "foreign-pointer":
				os.WriteFile(filepath.Join(a.activation.runtime.root, "active.json"), []byte("foreign"), 0600)
			case "corrupt-receipt":
				os.WriteFile(a.activation.createdPath(a.request), []byte("bad"), 0600)
			case "corrupt-snapshot":
				os.WriteFile(filepath.Join(a.activation.backup.directory(a.request), "snapshot/receipt.json"), []byte("bad"), 0600)
			case "name-collision":
				c := a.target
				c.ID = strings.Repeat("7", 64)
				c.Name = "/webscan-failed-" + sha([]byte(a.request.Node + "\x00" + a.request.Job + "\x00" + a.request.PlanDigest))[:24]
				a.machine.containers[c.ID] = c
			case "live-lock":
				_, release, err := acquireServiceOperation(context.Background(), a.activation.runtime.root)
				if err != nil {
					t.Fatal(err)
				}
				unlock = release
			}
			if unlock != nil {
				defer unlock()
			}
			r := a.request
			r.Phase = "restore"
			starts := a.starts
			if err := a.activation.restore(context.Background(), r); err == nil {
				t.Fatal("unproven restoration accepted")
			}
			if a.starts != starts {
				t.Fatal("started original before verification")
			}
		})
	}
}

func TestDockerRestoreNeverReplacesLiveDatabaseWithSnapshot(t *testing.T) {
	var db *sql.DB
	a := dockerActivationFixture(t, false, func(b *transitionBackup) {
		if err := os.MkdirAll(b.data, 0700); err != nil {
			t.Fatal(err)
		}
		var err error
		db, err = persist.OpenDB(filepath.Join(b.data, "agent.sqlite3"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		if _, err := db.Exec(`CREATE TABLE manifest(path TEXT PRIMARY KEY,hash TEXT); CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT,created REAL,exported TEXT,accepted REAL); CREATE TABLE jobs(id INTEGER PRIMARY KEY,path TEXT); CREATE TABLE scans(id INTEGER PRIMARY KEY,path TEXT); CREATE TABLE logfiles(path TEXT PRIMARY KEY,created REAL); INSERT INTO manifest VALUES('/site/keep','old-baseline'); INSERT INTO jobs VALUES(1,'old-task'); INSERT INTO scans VALUES(1,'old-scan'); INSERT INTO events VALUES('old-event','{"event_id":"old-event","node_id":"node-one"}',0,NULL,NULL);`); err != nil {
			t.Fatal(err)
		}
	})
	if err := a.activation.run(context.Background(), a.request); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE manifest SET hash='new-baseline'; UPDATE jobs SET path='new-task'; UPDATE scans SET path='new-scan'; UPDATE events SET accepted=42 WHERE id='old-event'; INSERT INTO events VALUES('new-event','{"event_id":"new-event","node_id":"node-one"}',1,NULL,NULL)`); err != nil {
		t.Fatal(err)
	}
	r := a.request
	r.Phase = "restore"
	if err := a.activation.restore(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	for query, want := range map[string]string{"SELECT hash FROM manifest": "new-baseline", "SELECT path FROM jobs": "new-task", "SELECT path FROM scans": "new-scan"} {
		var got string
		if err := db.QueryRow(query).Scan(&got); err != nil || got != want {
			t.Fatal("restored stale snapshot", got, err)
		}
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM events WHERE id='old-event' AND accepted=42").Scan(&n); err != nil || n != 1 {
		t.Fatal("lost acknowledgement", err)
	}
	if err := db.QueryRow("SELECT count(*) FROM events WHERE id='new-event' AND accepted IS NULL AND exported IS NOT NULL").Scan(&n); err != nil || n != 1 {
		t.Fatal("lost new event", err)
	}
}

func TestDockerCaptureOnlyRecoveryAndOriginalDisabledState(t *testing.T) {
	for _, initial := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprint(initial), func(t *testing.T) {
			a := dockerActivationFixture(t, false)
			// Replace the capture/snapshot in a separate clean backup task so the
			// original state is actually recorded before its services are stopped.
			c := a.machine.containers[strings.Repeat("1", 64)]
			c.Status = "exited"
			if initial[0] {
				c.Status = "running"
			}
			c.Restart = "no"
			if initial[1] {
				c.Restart = "unless-stopped"
			}
			a.machine.containers[c.ID] = c
			r := a.request
			r.Job = "capture-only-state"
			r.Phase = "backup"
			if _, err := a.activation.backup.run(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			// Simulate a snapshot not yet published after quiesce. No activation
			// exists, so recovery must rely on capture without replacing the DB.
			if err := os.RemoveAll(filepath.Join(a.activation.backup.directory(r), "snapshot")); err != nil {
				t.Fatal(err)
			}
			r.Phase = "restore"
			if err := a.activation.restore(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			got := a.machine.containers[c.ID]
			if (got.Status == "running") != initial[0] || got.Restart != c.Restart || a.creates != 0 {
				t.Fatal("original running/restart state changed", got)
			}
		})
	}
}

func TestDockerUpgradeOfV3RestoresExactPreviousTaskObject(t *testing.T) {
	a := dockerActivationFixture(t, false)
	ctx := context.Background()
	if err := a.activation.run(ctx, a.request); err != nil {
		t.Fatal(err)
	}
	previous, err := readPrivate(filepath.Join(a.activation.runtime.root, "active.json"), MaxRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	oldID := a.target.ID
	r := a.request
	r.Job = "second-task"
	r.Phase = "backup"
	if _, err := a.activation.backup.run(ctx, r); err != nil {
		t.Fatal(err)
	}
	// Same program/config hashes still belong to a different installation task.
	// The task's project and retained Docker ID disambiguate recovery.
	a.request = r
	a.target.ID = strings.Repeat("7", 64)
	a.target.Project = dockerProject(ActiveInstallation{Node: r.Node, Job: r.Job, PlanDigest: r.PlanDigest})
	a.runtime.ID = a.target.ID
	r.Phase = "activate"
	if err := a.activation.run(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Phase = "restore"
	if err := a.activation.restore(ctx, r); err != nil {
		t.Fatal(err)
	}
	raw, err := readPrivate(filepath.Join(a.activation.runtime.root, "active.json"), MaxRequestBytes)
	if err != nil || string(raw) != string(previous) {
		t.Fatal("previous active task not restored", err)
	}
	if c := a.machine.containers[oldID]; c.Name != "/"+agentContainerName || c.Status != "running" {
		t.Fatal("recreated or lost previous v3 object", c)
	}
	if a.creates != 2 {
		t.Fatal("unexpected container recreation", a.creates)
	}
}
