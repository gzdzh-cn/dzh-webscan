package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/persist"
)

func TestSystemHostObservationRequiresFreshPrivateEvidence(t *testing.T) {
	ctx := context.Background()
	s := &Store{}
	check := func(configured, available, fresh bool) systemHostObservation {
		t.Helper()
		raw, err := s.hostObservation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out systemHostObservation
		if json.Unmarshal(raw, &out) != nil || out.Configured != configured || out.Available != available || out.Fresh != fresh {
			t.Fatalf("unexpected observation: %s", raw)
		}
		if strings.Contains(string(raw), "PRIVATE_SYNTHETIC_TOKEN") {
			t.Fatal("secret in observation")
		}
		return out
	}
	check(false, false, false)
	f := newWatchdogFixture(t)
	f.activate(t, watchdogSettings())
	s.HostQuota = f.client(t, nil)
	check(true, true, false)
	if err := f.store.recordSnapshot(ctx, []HostWatchdogCheck{{Component: "api", State: "abnormal", ObservedAt: time.Now()}}, HostWatchdogEnvironment{OS: "linux"}); err != nil {
		t.Fatal(err)
	}
	out := check(true, true, true)
	if out.Status == nil || len(out.Status.Checks) != 1 || out.Status.Checks[0].State != "abnormal" {
		t.Fatal("invented health")
	}
	for _, at := range []time.Time{time.Now().Add(-time.Minute), time.Now().Add(time.Minute)} {
		raw, _ := json.Marshal(map[string]any{"at": at, "checks": []HostWatchdogCheck{}})
		if _, err := f.store.db.Exec(`UPDATE observations SET payload=? WHERE id=1`, raw); err != nil {
			t.Fatal(err)
		}
		check(true, true, false)
	}
	s.HostQuota.http = &http.Client{Timeout: time.Millisecond}
	check(true, false, false)
}

func TestSingleBackupIncludesLiveWatchdogAndOfflineFrozenRestore(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	p, _ := newSingleBackupFixtureOptions(t, "", 3, false, true)
	c := p.config
	vault, err := OpenVault(c.DeploymentTrust.VaultKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := loadHostSpec(c.HostWatchdog.SpecFile, vault)
	if err != nil {
		t.Fatal(err)
	}
	wd, err := openHostWatchdogStore(spec, vault)
	if err != nil {
		t.Fatal(err)
	}
	defer wd.db.Close()
	f := watchdogFixture{store: wd, vault: vault, spec: spec}
	f.activate(t, watchdogSettings())
	slot, err := wd.reserve(ctx, hostQuotaInput{Channel: "email", AttemptKey: "backup-test-one", RuntimeVersion: 1})
	if err != nil || !slot.New {
		t.Fatal(err)
	}
	if err := wd.recordSnapshot(ctx, nil, HostWatchdogEnvironment{OS: "linux"}); err != nil {
		t.Fatal(err)
	}
	result, err := s.backupSingle(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := verifySingleBackup(ctx, result.Directory, result.ManifestSHA256)
	if err != nil || manifest.HostWatchdog == nil {
		t.Fatal("watchdog not verified", err)
	}
	for _, file := range manifest.Files {
		if strings.HasSuffix(file.Path, "-wal") || strings.HasSuffix(file.Path, "-shm") {
			t.Fatal("copied live WAL", file.Path)
		}
	}
	recovery := filepath.Join(filepath.Dir(p.output), "offline-recovery")
	if err := restoreSingleBackupOffline(ctx, p.output, result.ManifestSHA256, recovery); err != nil {
		t.Fatal(err)
	}
	frozen := c
	frozen.HostWatchdog.StateDirectory = spec.StateDirectory + "-restored"
	t.Cleanup(func() { os.RemoveAll(frozen.HostWatchdog.StateDirectory) })
	snapshot := filepath.Join(recovery, "watchdog", "watchdog.sqlite3")
	if err := RestoreHostWatchdog(ctx, frozen, snapshot); err != nil {
		t.Fatal(err)
	}
	db, err := persist.OpenReadOnly(filepath.Join(frozen.HostWatchdog.StateDirectory, "watchdog.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var paused bool
	var consumed, observed int
	if err := db.QueryRow(`SELECT frozen FROM host_state WHERE id=1`).Scan(&paused); err != nil || !paused {
		t.Fatal("restore not frozen", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM quota WHERE attempt_key='backup-test-one'`).Scan(&consumed); err != nil || consumed != 1 {
		t.Fatal("quota lost", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM observations`).Scan(&observed); err != nil || observed != 0 {
		t.Fatal("stale health retained", err)
	}
	if err := ensureSingleHostWatchdog(ctx, p.spec); err != nil {
		t.Fatal("resume changed original support", err)
	}
	localWrite(t, c.HostWatchdog.SpecFile, []byte(`{"format":1}`))
	if err := ensureSingleHostWatchdog(ctx, p.spec); err == nil {
		t.Fatal("accepted tampered overlay")
	}
}
