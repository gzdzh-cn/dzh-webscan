//go:build linux

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/deploy"
)

// The original installation and its earlier signed helper are synthetic. The
// upgraded executable, systemd activation, PG and source/restored VM engines
// are real.
// This does not claim to run a previous released binary or reboot a machine.
func TestSingleBackupUpgradeKernelSignedHelperSystemdAndFullRestore(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_BACKUP_UPGRADE_KERNEL") != "1" {
		t.Skip("requires explicitly enabled isolated backup upgrade kernel guest")
	}
	requireBackupSystemdGuest(t)
	helper, vm := os.Getenv("WEBSCAN_V3_TEST_BACKUP_HELPER"), os.Getenv("WEBSCAN_V3_TEST_VM_EXECUTABLE")
	if helper != "/v3-tests/webscan" || vm != "/v3-tests/victoria-metrics-prod" {
		t.Fatal("explicit controlled executables required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	raw, e := exec.CommandContext(ctx, helper, "version").CombinedOutput()
	if e != nil || strings.TrimSpace(string(raw)) != deploy.Release {
		t.Fatal("actual upgraded helper version differs from test source")
	}
	s := testStore(t)
	if e = s.Provision(ctx, "admin", "isolated-backup-upgrade-123"); e != nil {
		t.Fatal(e)
	}
	p, f := newSingleBackupFixture(t)
	f.server.Close()
	if e = os.RemoveAll(p.metrics.Directory); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(p.metrics.Directory, 0700); e != nil {
		t.Fatal(e)
	}
	endpoint := singleBackupTestVM(t, ctx, vm, p.metrics.Directory, p.metrics.URL)
	if e = os.Rename(p.metrics.Directory+".log", filepath.Join(filepath.Dir(p.spec.Root), "upgrade-source-vm.log")); e != nil {
		t.Fatal(e)
	}
	p = singleBackupUpgradeBindTestDatabase(t, s, p)
	_, original, request, output := singleBackupUpgradeFixture(t, p)
	current := newTrustToolFixture(t)
	actual, e := os.ReadFile(helper)
	if e != nil {
		t.Fatal(e)
	}
	localWrite(t, current.helper, actual)
	if e = os.Chmod(current.helper, 0700); e != nil {
		t.Fatal(e)
	}
	current.sign.Output += "-actual-backup-upgrade"
	current.sign.Release = deploy.Release
	if e = ReleaseCommand(ctx, current.sign, io.Discard); e != nil {
		t.Fatal(e)
	}
	current.signed = current.sign.Output
	for _, path := range []string{request.Backup.HostConfig, request.Backup.APIConfig} {
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		c, e := decodeSingleBackupConfig(raw)
		if e != nil {
			t.Fatal(e)
		}
		c.DeploymentTrust = current.config()
		c.DeploymentTrust.VaultKeyFile = p.config.DeploymentTrust.VaultKeyFile
		c.DeploymentTrust.PreviousKeyFiles = p.config.DeploymentTrust.PreviousKeyFiles
		if path == request.Backup.APIConfig {
			c.DeploymentTrust.HelperFile, c.DeploymentTrust.NativeBundleFile, c.DeploymentTrust.ImageArchiveFile = "", "", ""
		}
		raw, _ = yaml.Marshal(c)
		localWrite(t, path, raw)
	}
	if e = s.configureSingleBackup(ctx, p.spec.Instance, original); e != nil {
		t.Fatal(e)
	}
	// A runtime schedule at midnight is due for today's date regardless of the
	// guest clock. The original immutable host policy is never rewritten.
	if _, e = s.DB.Exec(`UPDATE v3_settings SET payload='{"backup":{"enabled":true,"time":"00:00","timezone":"UTC","keep_days":7}}',version=version+1`); e != nil {
		t.Fatal(e)
	}
	before := map[string][]byte{}
	for _, path := range []string{request.ScheduleFile, p.request.Installation, filepath.Join(p.spec.Root, "journal.json"), p.config.DeploymentTrust.VaultKeyFile, filepath.Join(p.spec.Root, "authority", "ca.key")} {
		before[path], e = os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
	}
	call := func(action, source, output string) []byte {
		t.Helper()
		args := []string{"control-v3", "--action", action, "--source", source}
		if output != "" {
			args = append(args, "--output", output)
		}
		raw, e := exec.CommandContext(ctx, current.helper, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("actual upgraded backup action %s failed: %v %s", action, e, raw)
		}
		return raw
	}
	requestFile := filepath.Join(filepath.Dir(output), "actual-upgrade-request.json")
	raw, _ = json.Marshal(request)
	localWrite(t, requestFile, raw)
	call("prepare-single-backup-upgrade", requestFile, output)
	source := filepath.Join(output, "upgrade.json")
	var checked struct {
		State           string `json:"state"`
		PolicyEnabled   bool   `json:"policy_enabled"`
		DatabaseChecked bool   `json:"database_checked"`
	}
	if json.Unmarshal(call("check-single-backup-upgrade", source, ""), &checked) != nil || checked.State != "verified" || !checked.PolicyEnabled || !checked.DatabaseChecked {
		t.Fatal("actual helper did not verify original database policy")
	}
	unit := "webscan-backup-upgrade-kernel-" + token()[:10]
	for _, suffix := range []string{"service", "timer"} {
		raw, e := os.ReadFile(filepath.Join(output, "backup."+suffix))
		if e != nil {
			t.Fatal(e)
		}
		localWrite(t, filepath.Join("/etc/systemd/system", unit+"."+suffix), raw)
	}
	t.Cleanup(func() {
		exec.Command("systemctl", "disable", "--now", unit+".timer").Run()
		exec.Command("systemctl", "stop", unit+".service").Run()
		for _, suffix := range []string{"service", "timer"} {
			os.Remove(filepath.Join("/etc/systemd/system", unit+"."+suffix))
		}
		exec.Command("systemctl", "daemon-reload").Run()
	})
	hostWatchdogKernelCommand(t, ctx, "systemctl", "daemon-reload")
	if _, e = s.DB.Exec(`UPDATE v3_single_backup_policies SET enabled=false`); e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(call("check-single-backup-upgrade", source, ""), &checked) != nil || checked.PolicyEnabled {
		t.Fatal("check silently enabled disabled backup policy")
	}
	if e = exec.CommandContext(ctx, "systemctl", "start", unit+".service").Run(); e == nil || tableCount(t, s, "v3_single_backup_runs") != 0 {
		t.Fatal("disabled policy unexpectedly archived")
	}
	call("enable-single-backup-upgrade", source, "")
	hostWatchdogKernelCommand(t, ctx, "systemctl", "reset-failed", unit+".service")
	client := &http.Client{Timeout: 5 * time.Second}
	response, e := client.Post(endpoint+"/api/v1/import/prometheus", "text/plain", strings.NewReader("webscan_backup_upgrade_probe{node_id=\"isolated-upgrade\"} 37\n"))
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 204 && response.StatusCode != 200 {
		t.Fatal("actual VM synthetic write rejected")
	}
	hostWatchdogKernelCommand(t, ctx, "systemctl", "start", unit+".service")
	hostWatchdogKernelCommand(t, ctx, "systemctl", "enable", "--now", unit+".timer")
	hostWatchdogKernelCommand(t, ctx, "systemctl", "is-active", "--quiet", unit+".timer")
	var archive, hash, state string
	if e = s.DB.QueryRow(`SELECT directory,manifest_sha256,status FROM v3_single_backup_runs`).Scan(&archive, &hash, &state); e != nil || state != "captured" {
		t.Fatal("actual upgraded service did not capture full archive", e)
	}
	hostWatchdogKernelCommand(t, ctx, "systemctl", "restart", unit+".timer")
	hostWatchdogKernelCommand(t, ctx, "systemctl", "start", unit+".service")
	if tableCount(t, s, "v3_single_backup_runs") != 1 {
		t.Fatal("upgraded timer restart repeated daily archive")
	}
	for path, old := range before {
		now, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(old, now) {
			t.Fatal("upgrade changed original immutable material")
		}
	}
	verifyFile := filepath.Join(filepath.Dir(output), "actual-upgrade-verify.json")
	raw, _ = json.Marshal(metricsSnapshotRestoreSpec{Format: 1, Directory: archive, ManifestSHA256: hash})
	localWrite(t, verifyFile, raw)
	call("verify-single-backup", verifyFile, "")
	restored := filepath.Join(filepath.Dir(output), "actual-upgrade-restored")
	call("restore-single-offline", verifyFile, restored)
	m, e := verifySingleBackup(ctx, archive, hash)
	if e != nil {
		t.Fatal(e)
	}
	target := emptyTestStore(t)
	if e = target.RestorePostgres(ctx, filepath.Join(restored, m.Postgres)); e != nil {
		t.Fatal(e)
	}
	var enabled bool
	if e = target.DB.QueryRow(`SELECT enabled FROM v3_single_backup_policies`).Scan(&enabled); e != nil || enabled {
		t.Fatal("restored backup policy must require explicit enable", e)
	}
	restoredVM := singleBackupTestVM(t, ctx, vm, filepath.Join(restored, "metrics"), "")
	response, e = client.Get(restoredVM + "/api/v1/query?" + url.Values{"query": {`webscan_backup_upgrade_probe{node_id="isolated-upgrade"}`}, "nocache": {"1"}}.Encode())
	if e != nil {
		t.Fatal(e)
	}
	raw, e = io.ReadAll(io.LimitReader(response.Body, 1<<20))
	response.Body.Close()
	if e != nil || !bytes.Contains(raw, []byte(`"37"`)) {
		t.Fatal("upgraded full backup did not recover real VM sample")
	}
	t.Log("actual signed upgraded helper and systemd backup completed; immutable policy/keys unchanged, explicit enable enforced, restart deduplicated, PG and VM restored in isolation")
}
