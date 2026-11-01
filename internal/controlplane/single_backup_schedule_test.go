package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func singleBackupScheduleFixture(t *testing.T) (*Store, singleBackupSchedule, singleBackupPlan, []byte) {
	t.Helper()
	s := testStore(t)
	plan, _ := newSingleBackupFixture(t)
	directory := filepath.Join(filepath.Dir(plan.spec.Root), "scheduled-backups")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	p := singleBackupSchedule{Format: 1, Spec: singleBackupScheduleSpec{Format: 1, Directory: directory, Keep: 2, Request: plan.request}, Helper: plan.config.DeploymentTrust.HelperFile, Hash: plan.bindings[plan.config.DeploymentTrust.HelperFile]}
	trust, err := loadDeploymentTrust(context.Background(), plan.config.DeploymentTrust)
	if err != nil {
		t.Fatal(err)
	}
	p.Release = trust.release.manifest.Release
	raw, _ := json.Marshal(p)
	if err := s.configureSingleBackup(context.Background(), plan.spec.Instance, raw); err != nil {
		t.Fatal(err)
	}
	return s, p, plan, raw
}

func TestSingleBackupScheduleCapturesAndRetainsOnlyOwnedVerifiedArchives(t *testing.T) {
	s, p, plan, raw := singleBackupScheduleFixture(t)
	ctx := context.Background()
	foreign := filepath.Join(p.Spec.Directory, "unrelated-backup")
	if err := os.Mkdir(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	localWrite(t, filepath.Join(foreign, "keep"), []byte("unrelated data"))
	var receipts []singleBackupRunResult
	for i := 0; i < 3; i++ {
		r, err := s.runSingleBackupSchedule(ctx, p, plan, raw)
		if err != nil || r.State != "captured" || r.Receipt == nil || r.Receipt.RestoreTested {
			t.Fatal(r, err)
		}
		receipts = append(receipts, r)
		if i == 0 {
			notDue, err := s.runSingleBackupSchedule(ctx, p, plan, raw)
			if err != nil || notDue.State != "not-due" || tableCount(t, s, "v3_single_backup_runs") != 1 {
				t.Fatal(notDue, err)
			}
		}
		if _, err := s.DB.Exec(`UPDATE v3_single_backup_runs SET created_at=created_at-interval '25 hours' WHERE status='captured'`); err != nil {
			t.Fatal(err)
		}
	}
	var captured, expired int
	if err := s.DB.QueryRow(`SELECT count(*) FILTER(WHERE status='captured'),count(*) FILTER(WHERE status='expired') FROM v3_single_backup_runs`).Scan(&captured, &expired); err != nil || captured != 2 || expired != 1 {
		t.Fatal(captured, expired, err)
	}
	if _, err := os.Stat(receipts[0].Receipt.Directory); !os.IsNotExist(err) {
		t.Fatal("old owned backup was not removed", err)
	}
	for _, r := range receipts[1:] {
		if _, err := verifySingleBackup(ctx, r.Receipt.Directory, r.Receipt.ManifestSHA256); err != nil {
			t.Fatal("retained backup damaged", err)
		}
	}
	if content, err := os.ReadFile(filepath.Join(foreign, "keep")); err != nil || string(content) != "unrelated data" {
		t.Fatal("foreign path changed", err)
	}
	archiveDir := t.TempDir()
	if err := os.Chmod(archiveDir, 0700); err != nil {
		t.Fatal(err)
	}
	archive, err := s.BackupPostgres(ctx, archiveDir)
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err := restored.RestorePostgres(ctx, archive); err != nil {
		t.Fatal(err)
	}
	var enabled bool
	if err := restored.DB.QueryRow(`SELECT enabled FROM v3_single_backup_policies`).Scan(&enabled); err != nil || enabled {
		t.Fatal("disaster recovery reenabled automatic host deletion", err)
	}
}

func TestSingleBackupSchedulePreservesPolicyAndInterruptedArchives(t *testing.T) {
	s, p, plan, raw := singleBackupScheduleFixture(t)
	ctx := context.Background()
	changed := p
	changed.Spec.Keep = 7
	other, _ := json.Marshal(changed)
	if err := s.configureSingleBackup(ctx, plan.spec.Instance, other); err == nil {
		t.Fatal("existing retention silently reset")
	}
	id := token()
	dir := filepath.Join(p.Spec.Directory, "backup-"+id)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	localWrite(t, filepath.Join(dir, "incomplete"), []byte("preserve for inspection"))
	if _, err := s.DB.Exec(`INSERT INTO v3_single_backup_runs(id,instance,policy_sha256,status,directory) VALUES($1,$2,$3,'running',$4)`, id, plan.spec.Instance, digest(raw), dir); err != nil {
		t.Fatal(err)
	}
	r, err := s.runSingleBackupSchedule(ctx, p, plan, raw)
	if err != nil || r.State != "captured" {
		t.Fatal(r, err)
	}
	var state string
	if err := s.DB.QueryRow(`SELECT status FROM v3_single_backup_runs WHERE id=$1`, id).Scan(&state); err != nil || state != "interrupted" {
		t.Fatal(state, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "incomplete")); err != nil {
		t.Fatal("interrupted archive removed", err)
	}
	if _, err := s.DB.Exec(`UPDATE v3_single_backup_policies SET enabled=false`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.runSingleBackupSchedule(ctx, p, plan, raw); err == nil {
		t.Fatal("disabled policy executed")
	}
}

func TestSingleBackupScheduleRejectsConcurrentRunnerAndRecordsFailure(t *testing.T) {
	s, p, plan, raw := singleBackupScheduleFixture(t)
	ctx := context.Background()
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	resource := "single-backup:" + plan.spec.Instance
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtextextended($1,0))`, resource); err != nil {
		t.Fatal(err)
	}
	if _, err := s.runSingleBackupSchedule(ctx, p, plan, raw); err == nil || tableCount(t, s, "v3_single_backup_runs") != 0 {
		t.Fatal("concurrent runner created a task", err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, resource); err != nil {
		t.Fatal(err)
	}
	plan.metrics.URL = "http://127.0.0.1:1"
	r, err := s.runSingleBackupSchedule(ctx, p, plan, raw)
	if err == nil || r.State != "failed" {
		t.Fatal(r, err)
	}
	var reason string
	if err := s.DB.QueryRow(`SELECT reason FROM v3_single_backup_runs WHERE id=$1`, r.ID).Scan(&reason); err != nil || reason == "" || strings.Contains(reason, "127.0.0.1") {
		t.Fatal("missing or sensitive task reason", reason, err)
	}
}

func TestSingleBackupScheduleRefusesCorruptRetentionCandidate(t *testing.T) {
	s, p, plan, raw := singleBackupScheduleFixture(t)
	ctx := context.Background()
	r, err := s.runSingleBackupSchedule(ctx, p, plan, raw)
	if err != nil {
		t.Fatal(err)
	}
	localWrite(t, filepath.Join(r.Receipt.Directory, "backup.json"), []byte("corrupt"))
	p.Spec.Keep = 0 // direct internal retention invocation: selects all candidates
	if err := s.pruneSingleBackups(ctx, p, plan.spec.Instance, digest(raw)); err == nil {
		t.Fatal("corrupted archive accepted for deletion")
	}
	if _, err := os.Stat(r.Receipt.Directory); err != nil {
		t.Fatal("failed verification deleted archive", err)
	}
}

func TestSingleBackupScheduleDefaultsAndAuthenticatedHelper(t *testing.T) {
	plan, _ := newSingleBackupFixture(t)
	directory := filepath.Join(filepath.Dir(plan.spec.Root), "archives")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(filepath.Dir(plan.spec.Root), "backup-policy")
	p := singleBackupScheduleSpec{Format: 1, Directory: directory, Request: plan.request}
	if err := prepareSingleBackupSchedule(context.Background(), p, output); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(output, "schedule.json")
	policy, _, _, err := readSingleBackupSchedule(context.Background(), source, "", "")
	if err != nil || policy.Spec.Keep != 7 {
		t.Fatal(policy, err)
	}
	if _, _, _, err := readSingleBackupSchedule(context.Background(), source, policy.Helper, "wrong-version"); err == nil {
		t.Fatal("wrong executing helper version accepted")
	}
	if err := prepareSingleBackupSchedule(context.Background(), p, output); err == nil {
		t.Fatal("existing policy files overwritten")
	}
	service, timer := singleBackupScheduleUnits(policy, source)
	if !bytes.Contains(timer, []byte("OnCalendar=*-*-* *:*:00")) || !bytes.Contains(timer, []byte("Persistent=true")) || bytes.Contains(service, []byte("Requires=")) || bytes.Contains(service, []byte("PartOf=")) {
		t.Fatal("unsafe timer/stack coupling")
	}
}

func TestSingleBackupScheduleNewInstallFilesAreImmutableAndOldFormatUnchanged(t *testing.T) {
	s := singleSpecFixture(t)
	f := newTrustToolFixture(t)
	c := f.config()
	s.Format, s.ReleaseTrust, s.RulesFile = 3, &c, filepath.Join(f.root, "rules.yar")
	localWrite(t, s.RulesFile, []byte("rule isolated { condition: false }"))
	s.Backup = &singleInstallBackupPolicy{Directory: s.Root + "-backups", Keep: 7}
	helper, err := os.ReadFile(f.helper)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	if err := prepareSingleInstallation(context.Background(), s, helper, "backup-default-fixture-123", "/usr/bin/docker"); err != nil {
		t.Fatal(err)
	}
	if _, err := readSingleInstallation(s, digest(helper)); err != nil {
		t.Fatal("new backup files broke immutable install binding", err)
	}
	var policy singleBackupSchedule
	raw, err := os.ReadFile(filepath.Join(s.Root, "backup-schedule.json"))
	if err != nil || json.Unmarshal(raw, &policy) != nil || policy.Spec.Keep != 7 || policy.Helper != filepath.Join(s.Root, "webscan") {
		t.Fatal("new install policy omitted defaults", err)
	}
	localWrite(t, filepath.Join(s.Root, "backup.timer"), []byte("changed timer"))
	if _, err := readSingleInstallation(s, digest(helper)); err == nil {
		t.Fatal("modified timer accepted under original installation")
	}
	old, _ := prepareSingleFixture(t)
	if _, err := os.Stat(filepath.Join(old.Root, "backup-schedule.json")); !os.IsNotExist(err) {
		t.Fatal("legacy immutable installation unexpectedly gained a backup policy")
	}
}

func TestSingleBackupSchedulePurgeNeverFollowsLinks(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{parent, target} {
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	localWrite(t, filepath.Join(target, "business"), []byte("do not remove"))
	if err := os.Symlink(target, filepath.Join(parent, "backup-test")); err != nil {
		t.Fatal(err)
	}
	if err := removeScheduledBackup(parent, "backup-test"); err == nil {
		t.Fatal("symlink backup root accepted")
	}
	if _, err := os.Stat(filepath.Join(target, "business")); err != nil {
		t.Fatal("followed a symlink", err)
	}
	if err := removeScheduledBackup(parent, "missing"); err != nil {
		t.Fatal("interrupted removal not idempotent", err)
	}
}
