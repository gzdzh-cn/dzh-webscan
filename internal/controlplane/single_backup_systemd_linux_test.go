//go:build linux

package controlplane

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireBackupSystemdGuest(t *testing.T) {
	t.Helper()
	marker, err := os.ReadFile("/v3-tests/kernel-guest")
	pid, pe := os.Readlink("/proc/1/exe")
	interfaces, ne := os.ReadDir("/sys/class/net")
	if os.Geteuid() != 0 || err != nil || string(marker) != "webscan-v3-networkless-kernel-guest\n" || pe != nil || pid != "/usr/lib/systemd/systemd" || ne != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("refusing backup timer activation outside dedicated networkless kernel guest")
	}
}

// This uses the production activation path and real PID 1. The installation
// is synthetic, while the signed service, PG, VM and resulting backup are real.
// It proves neither machine reboot nor a complete fresh Docker installation.
func verifySingleBackupSystemdActivation(t *testing.T, ctx context.Context, p singleBackupPlan, s *Store) {
	t.Helper()
	requireBackupSystemdGuest(t)
	if p.spec.Backup == nil || p.spec.Backup.Keep != 7 {
		t.Fatal("default backup policy not generated")
	}
	name := singleProject(p.spec.Root) + "-backup"
	command := func(args ...string) []byte {
		t.Helper()
		raw, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("real backup systemd %v failed: %v %s", args, err, raw)
		}
		return raw
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = exec.CommandContext(cleanup, "systemctl", "disable", "--now", name+".timer").Run()
		_ = exec.CommandContext(cleanup, "systemctl", "stop", name+".service").Run()
		for _, suffix := range []string{"timer", "service"} {
			_ = os.Remove(filepath.Join("/etc/systemd/system", name+"."+suffix))
		}
		_ = exec.CommandContext(cleanup, "systemctl", "daemon-reload").Run()
	})
	for _, binary := range []string{filepath.Join(p.spec.Root, "webscan"), p.config.DeploymentTrust.HelperFile} {
		if err := os.Chmod(binary, 0700); err != nil {
			t.Fatal(err)
		}
	}
	i := newSingleInstaller()
	if err := i.activateSingleBackup(ctx, p.spec); err != nil {
		t.Fatal("production backup activation failed", err)
	}
	command("is-enabled", "--quiet", name+".timer")
	command("is-active", "--quiet", name+".timer")
	if output := string(command("show", name+".timer", "--property=NextElapseUSecRealtime", "--value")); strings.TrimSpace(output) == "" || strings.TrimSpace(output) == "n/a" {
		t.Fatal("timer has no real next firing time")
	}
	// Trigger the installed signed service immediately rather than waiting for
	// 03:00. Production dedup still applies to the timer's eventual invocation.
	command("start", name+".service")
	if result := strings.TrimSpace(string(command("show", name+".service", "--property=Result", "--value"))); result != "success" {
		t.Fatal("systemd backup service did not complete successfully", result)
	}
	var archive, hash, state string
	if err := s.DB.QueryRowContext(ctx, `SELECT directory,manifest_sha256,status FROM v3_single_backup_runs ORDER BY created_at DESC LIMIT 1`).Scan(&archive, &hash, &state); err != nil || state != "captured" {
		t.Fatal("timer service did not commit captured archive", err)
	}
	if _, err := verifySingleBackup(ctx, archive, hash); err != nil {
		t.Fatal("timer service archive invalid", err)
	}
	command("restart", name+".timer")
	command("is-active", "--quiet", name+".timer")
	command("start", name+".service")
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM v3_single_backup_runs`).Scan(&count); err != nil || count != 1 {
		t.Fatal("timer/service restart duplicated daily backup", count, err)
	}
	var policy singleBackupSchedule
	raw, err := os.ReadFile(filepath.Join(p.spec.Root, "backup-schedule.json"))
	if err != nil || json.Unmarshal(raw, &policy) != nil || policy.Spec.Keep != 7 || policy.Helper != filepath.Join(p.spec.Root, "webscan") {
		t.Fatal("installed default policy binding differs", err)
	}
	t.Log("actual systemd default daily timer enabled/active, signed service backup verified, timer/service restart deduplicated; full installation and machine reboot are separate gates")
}
