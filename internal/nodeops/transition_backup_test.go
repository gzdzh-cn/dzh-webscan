package nodeops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/persist"
)

type backupHostFixture struct {
	installed          Installation
	inventories, stops int
	stopError          error
	afterStop          func()
	isStopped          bool
}

func (h *backupHostFixture) inventory(context.Context, string, string) (Installation, error) {
	h.inventories++
	return h.installed, nil
}
func (h *backupHostFixture) stop(context.Context, Installation) error {
	h.stops++
	if h.stopError != nil {
		return h.stopError
	}
	h.isStopped = true
	if h.afterStop != nil {
		h.afterStop()
	}
	return nil
}
func (h *backupHostFixture) stopped(context.Context, Installation) (bool, error) {
	return h.isStopped, nil
}

func backupFixture(t *testing.T) (*transitionBackup, Request, *backupHostFixture, *sql.DB) {
	t.Helper()
	files := bundleFiles()
	bundleChecksums(files)
	w, r := stageFixture(t, archiveFiles(t, files, nil))
	attachConfiguration(t, w, &r, nil)
	r.Phase = "backup"
	cfg := filepath.Join(w.root, "old-config")
	data := filepath.Join(w.root, "data")
	logs := filepath.Join(w.root, "logs")
	for _, dir := range []string{cfg, data, logs, filepath.Join(cfg, "pki")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	runtime := filepath.Join(cfg, "runtime.json")
	for path, content := range map[string]string{runtime: `{"node_id":"node-one","token":"private-fixture"}`, filepath.Join(cfg, "pki", "identity.key"): "private-key-fixture", filepath.Join(logs, "pending.jsonl"): `{"id":"original-id"}` + "\n", filepath.Join(logs, "unrelated.log"): "not a vector input"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	h := &backupHostFixture{installed: Installation{Node: r.Node, Generation: "v2", Mode: "docker", Runtime: runtime, Services: []ServiceRecord{{Kind: "docker", Name: agentContainerName, ID: strings.Repeat("1", 64), Proof: strings.Repeat("2", 64), Running: true, Enabled: true, Restart: "unless-stopped"}}}}
	b := &transitionBackup{root: w.root, data: data, logs: logs, unit: filepath.Join(w.root, nativeServiceName), host: h}
	db, err := persist.OpenDB(filepath.Join(data, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE manifest(path TEXT PRIMARY KEY,hash TEXT); CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT,accepted INTEGER); CREATE TABLE jobs(id INTEGER PRIMARY KEY,path TEXT); CREATE TABLE scans(id INTEGER PRIMARY KEY,path TEXT); INSERT INTO manifest VALUES('/srv/site/index.php','baseline'); INSERT INTO events VALUES('original-id','{"operation":"modify"}',NULL); INSERT INTO jobs VALUES(1,'/srv/site/task'); INSERT INTO scans VALUES(1,'/srv/site/scan');`); err != nil {
		t.Fatal(err)
	}
	return b, r, h, db
}
func assertBackupRows(t *testing.T, path string, want int) {
	t.Helper()
	db, err := persist.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for table, n := range map[string]int{"events": want, "manifest": 1, "jobs": 1, "scans": 1} {
		var got int
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&got); err != nil || got != n {
			t.Fatalf("%s=%d, expected %d: %v", table, got, n, err)
		}
	}
}
func TestTransitionBackupConsistentAndRetryPreservesOriginalStateAndNewEvents(t *testing.T) {
	b, r, h, db := backupFixture(t)
	ctx := context.Background()
	pki := filepath.Join(b.data, "pki-trust")
	if err := os.Mkdir(pki, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "floor.json"), []byte("revocation-floor"), 0600); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(b.data, "pki-identity", "active.pem")
	if err := os.Mkdir(filepath.Dir(identity), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identity, []byte("private-node-identity"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := b.run(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if first.Database == nil || len(first.Logs) != 1 || len(first.SecurityState) != 1 || len(first.IdentityState) != 2 {
		t.Fatal("incomplete snapshot", first)
	}
	if raw, err := os.ReadFile(filepath.Join(b.directory(r), "snapshot", "identity", "active.pem")); err != nil || string(raw) != "private-node-identity" {
		t.Fatal("private node identity not captured", err)
	}
	snapshot := filepath.Join(b.directory(r), "snapshot", "agent.sqlite3")
	assertBackupRows(t, snapshot, 1)
	if _, err := db.Exec(`INSERT INTO events VALUES('post-switch-id','{"operation":"create"}',0)`); err != nil {
		t.Fatal(err)
	}
	h.installed.Services[0].Running = false
	h.installed.Services[0].Enabled = false
	r.Epoch++ // A legitimate takeover retains the original binding and snapshot.
	again, err := b.run(ctx, r)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("snapshot overwritten on retry", err)
	}
	intent, err := b.readIntent(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if h.inventories != 1 || !intent.Installed.Services[0].Running || !intent.Installed.Services[0].Enabled {
		t.Fatal("original service state lost")
	}
	assertBackupRows(t, snapshot, 1)
	assertBackupRows(t, filepath.Join(b.data, "agent.sqlite3"), 2)
	if raw, _ := os.ReadFile(filepath.Join(b.directory(r), "capture", "config", "pki", "identity.key")); string(raw) != "private-key-fixture" {
		t.Fatal("key not captured")
	}
	if _, err := os.Stat(filepath.Join(b.directory(r), "snapshot", "logs", "unrelated.log")); !os.IsNotExist(err) {
		t.Fatal("unrelated log copied")
	}
}
func TestTransitionBackupFailedStopCanResumeWithoutRecapturing(t *testing.T) {
	b, r, h, _ := backupFixture(t)
	h.stopError = errors.New("fixed-service-stop-failed")
	if _, err := b.run(context.Background(), r); err == nil {
		t.Fatal("failed stop accepted")
	}
	if _, err := os.Stat(filepath.Join(b.directory(r), "snapshot")); !os.IsNotExist(err) {
		t.Fatal("snapshot published before stop")
	}
	h.stopError = nil
	h.installed.Services[0].Running = false
	if _, err := b.run(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	i, err := b.readIntent(context.Background(), r)
	if err != nil || !i.Installed.Services[0].Running || h.inventories != 1 {
		t.Fatal("resume lost old service state", err)
	}
}

func TestRecoveryCaptureRequiresKnownDatabaseAndRejectsMissingLiveData(t *testing.T) {
	for _, kind := range []string{"unknown-presence", "missing-database", "corrupt-published-snapshot"} {
		t.Run(kind, func(t *testing.T) {
			b, r, h, db := backupFixture(t)
			ctx := context.Background()
			if _, err := b.prepareIntent(ctx, r); err != nil {
				t.Fatal(err)
			}
			h.isStopped = true
			switch kind {
			case "unknown-presence":
				i, err := b.readIntent(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				i.DatabasePresent = nil
				raw, err := json.Marshal(i)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(b.directory(r), "capture", "intent.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-database":
				db.Close()
				if err := os.Remove(filepath.Join(b.data, "agent.sqlite3")); err != nil {
					t.Fatal(err)
				}
			case "corrupt-published-snapshot":
				if err := os.Mkdir(filepath.Join(b.directory(r), "snapshot"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			r.Phase = "restore"
			_, err := b.exportRollbackPending(ctx, r, h.installed)
			if err == nil {
				t.Fatal("unproved capture-only recovery accepted")
			}
			if kind == "unknown-presence" && err.Error() != "original-database-presence-unknown" || kind == "missing-database" && err.Error() != "live-agent-database-missing" {
				t.Fatal("failure was not caused by the database evidence", err)
			}
		})
	}
}

func TestTransitionBackupCannotForgetDatabaseLostAfterCapture(t *testing.T) {
	b, r, h, db := backupFixture(t)
	h.afterStop = func() {
		db.Close()
		if err := os.Remove(filepath.Join(b.data, "agent.sqlite3")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.run(context.Background(), r); err == nil || err.Error() != "live-agent-database-missing" {
		t.Fatal("lost original database became an empty successful snapshot", err)
	}
	if _, err := os.Lstat(filepath.Join(b.directory(r), "snapshot")); !os.IsNotExist(err) {
		t.Fatal("invalid empty snapshot published", err)
	}
}
func TestTransitionBackupRefusesUnmanagedWriterAndRecovers(t *testing.T) {
	b, r, _, _ := backupFixture(t)
	lock, err := b.agentLock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.run(context.Background(), r); err == nil || err.Error() != "unmanaged-agent-writer-active" {
		t.Fatal("unmanaged writer was ignored", err)
	}
	if _, err := os.Stat(filepath.Join(b.directory(r), "snapshot")); !os.IsNotExist(err) {
		t.Fatal("snapshot published while writer held lock")
	}
	lock.Close()
	if _, err := b.run(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}
func TestTransitionBackupRejectsUnsafeOrChangedSources(t *testing.T) {
	for _, kind := range []string{"config-permission", "config-symlink", "new-config", "after-stop-change", "lock-symlink", "database-symlink", "logs-symlink", "identity-symlink", "identity-public"} {
		t.Run(kind, func(t *testing.T) {
			b, r, h, _ := backupFixture(t)
			ctx := context.Background()
			config := filepath.Join(filepath.Dir(h.installed.Runtime), "pki", "identity.key")
			beforeStop := false
			switch kind {
			case "config-permission":
				os.Chmod(config, 0644)
				beforeStop = true
			case "config-symlink":
				os.Remove(config)
				os.Symlink(h.installed.Runtime, config)
				beforeStop = true
			case "new-config":
				if _, err := b.prepareIntent(ctx, r); err != nil {
					t.Fatal(err)
				}
				os.WriteFile(filepath.Join(filepath.Dir(h.installed.Runtime), "unexpected.key"), []byte("new"), 0600)
				beforeStop = true
			case "after-stop-change":
				h.afterStop = func() { os.WriteFile(config, []byte("replacement"), 0600) }
			case "lock-symlink":
				os.Symlink(config, filepath.Join(b.data, "agent.lock"))
			case "database-symlink":
				os.Rename(filepath.Join(b.data, "agent.sqlite3"), filepath.Join(b.data, "other.sqlite3"))
				os.Symlink(filepath.Join(b.data, "other.sqlite3"), filepath.Join(b.data, "agent.sqlite3"))
				beforeStop = true
			case "identity-symlink":
				os.Symlink(filepath.Dir(h.installed.Runtime), filepath.Join(b.data, "pki-identity"))
				beforeStop = true
			case "identity-public":
				os.Mkdir(filepath.Join(b.data, "pki-identity"), 0700)
				os.WriteFile(filepath.Join(b.data, "pki-identity", "active.pem"), []byte("private-key"), 0644)
				beforeStop = true
			case "logs-symlink":
				os.Remove(filepath.Join(b.logs, "pending.jsonl"))
				os.Symlink(config, filepath.Join(b.logs, "pending.jsonl"))
				beforeStop = true
			}
			if _, err := b.run(ctx, r); err == nil {
				t.Fatal("unsafe backup accepted")
			}
			if beforeStop && h.stops != 0 {
				t.Fatal("unsafe source stopped service")
			}
			if _, err := os.Stat(filepath.Join(b.directory(r), "snapshot")); !os.IsNotExist(err) {
				t.Fatal("unsafe snapshot published")
			}
		})
	}
}
func TestTransitionBackupManifestTamperingAndBinding(t *testing.T) {
	for _, kind := range []string{"snapshot-data", "snapshot-extra", "capture-extra", "receipt", "job", "plan", "spec"} {
		t.Run(kind, func(t *testing.T) {
			b, r, _, _ := backupFixture(t)
			if _, err := b.run(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "snapshot-data":
				os.WriteFile(filepath.Join(b.directory(r), "snapshot", "logs", "pending.jsonl"), []byte("changed"), 0600)
			case "snapshot-extra":
				os.WriteFile(filepath.Join(b.directory(r), "snapshot", "unverified.key"), []byte("extra"), 0600)
			case "capture-extra":
				os.WriteFile(filepath.Join(b.directory(r), "capture", "unverified.key"), []byte("extra"), 0600)
			case "receipt":
				p := filepath.Join(b.directory(r), "snapshot", "receipt.json")
				raw, _ := os.ReadFile(p)
				os.WriteFile(p, append(raw, '\n'), 0600)
			case "job":
				r.Job = "another-job"
			case "plan":
				r.PlanDigest = strings.Repeat("f", 64)
			case "spec":
				r.Spec.MetricsPort++
			}
			if _, err := b.verify(context.Background(), r); err == nil {
				t.Fatal("tampered snapshot accepted")
			}
		})
	}
}
func TestTransitionBackupValidatesPhaseAndCancellationBeforeMutation(t *testing.T) {
	for _, kind := range []string{"inspect", "stage", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			b, r, h, _ := backupFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "inspect":
				r.Operation = "inspect"
			case "stage":
				r.Phase = "stage"
			case "cancel":
				cancel()
			}
			if _, err := b.run(ctx, r); err == nil || h.inventories != 0 || h.stops != 0 {
				t.Fatal("invalid operation reached host", err)
			}
		})
	}
}
func TestTransitionBackupInsufficientSpaceDoesNotStopService(t *testing.T) {
	b, r, h, _ := backupFixture(t)
	var fs unix.Statfs_t
	if err := unix.Statfs(b.root, &fs); err != nil {
		t.Fatal(err)
	}
	// Free space can rise while other concurrent fixtures are cleaned up.
	// A sparse logical file larger than the entire filesystem cannot become
	// affordable between this setup and the pre-stop capacity check.
	capacity := uint64(fs.Blocks) * uint64(fs.Bsize)
	if fs.Bsize <= 0 || uint64(fs.Blocks) > uint64(1<<63-2)/uint64(fs.Bsize) {
		t.Fatal("filesystem capacity cannot be represented")
	}
	f, err := os.OpenFile(filepath.Join(b.logs, "oversized.jsonl"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(int64(capacity) + 1)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := b.run(ctx, r); err == nil || err.Error() != "insufficient-backup-space" || h.stops != 0 {
		t.Fatal("space failure stopped service", err, h.stops)
	}
}
func TestBackupFileDigestHandlesMaximumSizeAndRejectsTrailingBytes(t *testing.T) {
	p := filepath.Join(testRoot(t), "file")
	raw := []byte("nonempty snapshot")
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := describePrivateFile(context.Background(), p, "file", 1<<63-1)
	if err != nil || f.SHA256 != sha(raw) {
		t.Fatal("overflow silently hashed empty file", err)
	}
	if _, err := fileDigest(context.Background(), strings.NewReader("ab"), 1); err == nil {
		t.Fatal("excess data accepted")
	}
	if _, err := fileDigest(context.Background(), strings.NewReader(""), -1); err == nil {
		t.Fatal("negative limit accepted")
	}
}
func TestTransitionBackupCopiesOnlyOnceAfterInterruptedPublication(t *testing.T) {
	b, r, h, _ := backupFixture(t)
	ctx := context.Background()
	if _, err := b.prepareIntent(ctx, r); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(b.directory(r), ".snapshot-interrupted")
	if err := os.Mkdir(partial, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, "partial"), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.run(ctx, r); err != nil {
		t.Fatal(err)
	}
	if h.inventories != 1 {
		t.Fatal("intent recaptured")
	}
	if _, err := b.verify(ctx, r); err != nil {
		t.Fatal(err)
	}
}
func TestTransitionBackupAgentLockDoesNotReplaceForeignFile(t *testing.T) {
	b, _, _, _ := backupFixture(t)
	target := filepath.Join(b.data, "agent.lock")
	if err := os.WriteFile(target, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	if f, err := b.agentLock(); err == nil {
		f.Close()
		t.Fatal("public lock accepted")
	}
	raw, _ := os.ReadFile(target)
	if string(raw) != "keep" {
		t.Fatal("foreign lock overwritten")
	}
	var stat unix.Stat_t
	if err := unix.Lstat(target, &stat); err != nil || stat.Mode&0777 != 0644 {
		t.Fatal("foreign lock permissions changed")
	}
}
