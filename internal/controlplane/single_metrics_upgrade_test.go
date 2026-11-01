package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func singleMetricsUpgradeFixture(t *testing.T) (singleBackupPlan, singleMetricsUpgradeSpec, string) {
	t.Helper()
	p, _ := newSingleBackupFixture(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	r := singleMetricsUpgradeSpec{Format: 1, Backup: p.request, StateDirectory: p.spec.Root + "-dual-state", BackupDirectory: p.spec.Root + "-dual-backups", RawMetricsPort: port, RawMetricsHours: 48, HistoryMetricsDays: 15}
	return p, r, p.spec.Root + "-dual-overlay"
}

func publishSingleMetricsUpgradeFixture(t *testing.T, r singleMetricsUpgradeSpec, output string) singleMetricsUpgradeManifest {
	t.Helper()
	files, m, err := singleMetricsUpgradeFiles(context.Background(), r, output)
	if err != nil {
		t.Fatal("cannot plan explicit overlay", err)
	}
	if err := publishTrustFiles(context.Background(), output, files); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSingleMetricsUpgradeAuthenticatesOverlayPreservesOriginalAndStorage(t *testing.T) {
	p, r, output := singleMetricsUpgradeFixture(t)
	before := map[string][]byte{}
	for _, path := range []string{r.Backup.Installation, r.Backup.HostConfig, r.Backup.APIConfig, r.Backup.ComposeFile, p.config.DeploymentTrust.VaultKeyFile, filepath.Join(p.spec.Root, "authority", "ca.key"), filepath.Join(p.spec.Root, "journal.json")} {
		before[path], _ = os.ReadFile(path)
	}
	files, m, err := singleMetricsUpgradeFiles(context.Background(), r, output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("preview wrote output")
	}
	var old, next struct{ Services map[string]any }
	if yaml.Unmarshal(before[r.Backup.ComposeFile], &old) != nil || yaml.Unmarshal(files["compose.yaml"], &next) != nil || len(next.Services) != 4 {
		t.Fatal("bad compose overlay")
	}
	for _, name := range []string{"postgres", "metrics"} {
		if !reflect.DeepEqual(old.Services[name], next.Services[name]) {
			t.Fatal("existing storage service changed", name)
		}
	}
	if err := publishTrustFiles(context.Background(), output, files); err != nil {
		t.Fatal(err)
	}
	authenticated, err := readSingleMetricsUpgrade(context.Background(), filepath.Join(output, "upgrade.json"))
	if err != nil || !reflect.DeepEqual(authenticated, m) {
		t.Fatal("overlay authentication failed", err)
	}
	plan, err := planSingleBackup(context.Background(), singleMetricsUpgradeBackupRequest(m), p.spec.Root+"-verify-backup")
	if err != nil || plan.rawMetrics == nil || !plan.spec.MetricsRetention || plan.installation != p.installation {
		t.Fatal("effective backup did not include both stores", err)
	}
	policy, err := singleMetricsUpgradeRetention(context.Background(), m)
	if err != nil || validateMetricsRetentionSpec(policy) != nil {
		t.Fatal("effective retention binding failed", err)
	}
	for path, want := range before {
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, want) {
			t.Fatal("immutable source changed", path)
		}
	}
}

func TestSingleMetricsUpgradeRejectsTamperedReboundOrNestedMaterial(t *testing.T) {
	for _, change := range []string{"manifest", "host", "compose", "old-config", "nested", "port", "retention", "state"} {
		t.Run(change, func(t *testing.T) {
			p, r, output := singleMetricsUpgradeFixture(t)
			if change == "nested" {
				r.Backup.MetricsUpgrade = "/private/untrusted/upgrade.json"
			}
			if change == "port" {
				r.RawMetricsPort = p.spec.MetricsPort
			}
			if change == "retention" {
				r.HistoryMetricsDays = 14
			}
			if change == "state" {
				r.StateDirectory = filepath.Join(p.spec.Root, "state")
			}
			if change == "nested" || change == "port" || change == "retention" || change == "state" {
				if _, _, err := singleMetricsUpgradeFiles(context.Background(), r, output); err == nil {
					t.Fatal("invalid change accepted")
				}
				return
			}
			publishSingleMetricsUpgradeFixture(t, r, output)
			switch change {
			case "manifest":
				raw, _ := os.ReadFile(filepath.Join(output, "upgrade.json"))
				var m singleMetricsUpgradeManifest
				json.Unmarshal(raw, &m)
				m.Effective.RawMetricsHours = 72
				raw, _ = json.Marshal(m)
				localWrite(t, filepath.Join(output, "upgrade.json"), raw)
			case "host":
				localWrite(t, filepath.Join(output, "executor.yaml"), []byte("central: {}"))
			case "compose":
				localWrite(t, filepath.Join(output, "compose.yaml"), []byte("services: {}"))
			case "old-config":
				raw, _ := os.ReadFile(r.Backup.HostConfig)
				localWrite(t, r.Backup.HostConfig, append(raw, '\n'))
			}
			if _, err := readSingleMetricsUpgrade(context.Background(), filepath.Join(output, "upgrade.json")); err == nil {
				t.Fatal("tampered overlay accepted")
			}
		})
	}
}

func TestSingleMetricsUpgradeRawOwnershipAndKnownUnitReplacement(t *testing.T) {
	_, r, output := singleMetricsUpgradeFixture(t)
	m := publishSingleMetricsUpgradeFixture(t, r, output)
	hash := digest([]byte("fixed-task"))
	if err := singleMetricsUpgradeRawDirectory(m, hash, false); err != nil {
		t.Fatal(err)
	}
	if err := singleMetricsUpgradeRawDirectory(m, hash, true); err != nil {
		t.Fatal("first marker failed", err)
	}
	if err := singleMetricsUpgradeRawDirectory(m, hash, true); err != nil {
		t.Fatal("marker replay failed", err)
	}
	if err := singleMetricsUpgradeRawDirectory(m, digest([]byte("other-task")), true); err == nil {
		t.Fatal("foreign raw data adopted")
	}
	i := newSingleInstaller()
	i.unitDirectory = privateTestDir(t)
	name := "webscan-isolated.service"
	old, next := []byte("[Service]\nExecStart=/old\n"), []byte("[Service]\nExecStart=/next\n")
	localWrite(t, filepath.Join(i.unitDirectory, name), old)
	if err := singleMetricsUpgradeUnit(i, name, []byte("unknown"), next); err == nil {
		t.Fatal("unknown unit replaced")
	}
	if err := singleMetricsUpgradeUnit(i, name, old, next); err != nil {
		t.Fatal("known unit not replaced", err)
	}
	if err := singleMetricsUpgradeUnit(i, name, old, next); err != nil {
		t.Fatal("unit replay failed", err)
	}
	localWrite(t, filepath.Join(i.unitDirectory, "other.service"), old)
	if err := singleMetricsUpgradeUnit(i, "other.service", nil, next); err == nil {
		t.Fatal("unknown pre-existing unit accepted")
	}
}

func TestSingleMetricsUpgradePreservesOriginalBackupScheduleAcrossOverlay(t *testing.T) {
	p, r, output := singleMetricsUpgradeFixture(t)
	policy, raw, oldUpgrade, _ := singleBackupUpgradeFixture(t, p)
	r.BackupSchedule, r.BackupUpgradeDirectory = oldUpgrade.ScheduleFile, p.spec.Root+"-dual-backup-maintenance"
	m := publishSingleMetricsUpgradeFixture(t, r, output)
	request := singleBackupUpgradeSpec{Format: 1, ScheduleFile: r.BackupSchedule, Backup: singleMetricsUpgradeBackupRequest(m)}
	if _, err := readSingleMetricsUpgrade(context.Background(), filepath.Join(output, "upgrade.json")); err != nil {
		t.Fatal("metrics manifest rejected", err)
	}
	if _, err := planSingleBackup(context.Background(), request.Backup, p.spec.Root+"-new-helper-plan-check"); err != nil {
		t.Fatal("effective backup rejected", err)
	}
	if _, _, err := singleMetricsUpgradeOriginalSchedule(context.Background(), r); err != nil {
		t.Fatal("original maintenance bridge rejected", err)
	}
	files, err := singleBackupUpgradeFiles(context.Background(), request, r.BackupUpgradeDirectory)
	if err != nil {
		t.Fatal("backup overlay rejected", err)
	}
	if err := publishTrustFiles(context.Background(), r.BackupUpgradeDirectory, files); err != nil {
		t.Fatal(err)
	}
	actual, _, next, saved, _, err := readSingleBackupUpgrade(context.Background(), filepath.Join(r.BackupUpgradeDirectory, "upgrade.json"), "", "")
	if err != nil || !bytes.Equal(saved, raw) || actual.Spec.Keep != policy.Spec.Keep || actual.Spec.Directory != policy.Spec.Directory || next.rawMetrics == nil {
		t.Fatal("policy drift or raw data omitted", err)
	}
	localWrite(t, r.BackupSchedule, append(raw, '\n'))
	if _, err := readSingleMetricsUpgrade(context.Background(), filepath.Join(output, "upgrade.json")); err == nil {
		t.Fatal("changed source schedule accepted")
	}
}

func TestSingleMetricsUpgradeUsesNewSignedHelperWhilePreservingOldPolicyMaterials(t *testing.T) {
	p, r, output := singleMetricsUpgradeFixture(t)
	_, original, baseUpgrade, _ := singleBackupUpgradeFixture(t, p)
	r.Backup, r.BackupSchedule, r.BackupUpgradeDirectory = baseUpgrade.Backup, baseUpgrade.ScheduleFile, p.spec.Root+"-new-helper-dual-backup"
	m := publishSingleMetricsUpgradeFixture(t, r, output)
	if m.HelperFile == p.config.DeploymentTrust.HelperFile || len(m.PreviousSources) == 0 || m.Dependencies[p.config.DeploymentTrust.HelperFile] == "" {
		t.Fatal("new helper or original recovery bindings missing")
	}
	request := singleBackupUpgradeSpec{Format: 1, ScheduleFile: r.BackupSchedule, Backup: singleMetricsUpgradeBackupRequest(m)}
	if _, err := readSingleMetricsUpgrade(context.Background(), filepath.Join(output, "upgrade.json")); err != nil {
		t.Fatal("new-helper metrics manifest rejected", err)
	}
	if _, err := planSingleBackup(context.Background(), request.Backup, p.spec.Root+"-new-helper-plan-check"); err != nil {
		t.Fatal("new-helper effective backup rejected", err)
	}
	if _, _, err := singleMetricsUpgradeOriginalSchedule(context.Background(), r); err != nil {
		t.Fatal("original maintenance bridge rejected", err)
	}
	files, err := singleBackupUpgradeFiles(context.Background(), request, r.BackupUpgradeDirectory)
	if err != nil {
		t.Fatal("new helper plus raw layer could not retain original policy", err)
	}
	if err := publishTrustFiles(context.Background(), r.BackupUpgradeDirectory, files); err != nil {
		t.Fatal(err)
	}
	_, _, next, saved, upgraded, err := readSingleBackupUpgrade(context.Background(), filepath.Join(r.BackupUpgradeDirectory, "upgrade.json"), "", "")
	if err != nil || !bytes.Equal(saved, original) || next.rawMetrics == nil || upgraded.Helper != m.HelperFile || next.bindings[p.config.DeploymentTrust.HelperFile] == "" {
		t.Fatal("new helper lost old policy material", err)
	}
	if actual := mustReadSingleMetricsTestFile(t, r.BackupSchedule); !bytes.Equal(actual, original) {
		t.Fatal("old schedule overwritten")
	}
}

func TestSingleMetricsUpgradeDatabasePolicyAndLostBackupResponse(t *testing.T) {
	s := testStore(t)
	p, r, output := singleMetricsUpgradeFixture(t)
	p = singleBackupUpgradeBindTestDatabase(t, s, p)
	r.Backup = p.request
	_, raw, oldUpgrade, _ := singleBackupUpgradeFixture(t, p)
	if err := s.configureSingleBackup(context.Background(), p.spec.Instance, raw); err != nil {
		t.Fatal(err)
	}
	m := publishSingleMetricsUpgradeFixture(t, r, output)
	if err := singleMetricsUpgradeCheckBackupPolicy(context.Background(), s, m); err == nil {
		t.Fatal("active backup policy silently omitted")
	}
	r.BackupSchedule, r.BackupUpgradeDirectory = oldUpgrade.ScheduleFile, p.spec.Root+"-dual-backup-maintenance"
	output += "-with-backup"
	m = publishSingleMetricsUpgradeFixture(t, r, output)
	if err := singleMetricsUpgradeCheckBackupPolicy(context.Background(), s, m); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE v3_single_backup_policies SET enabled=false WHERE instance=$1`, p.spec.Instance); err != nil {
		t.Fatal(err)
	}
	i := newSingleInstaller()
	i.unitDirectory = privateTestDir(t)
	commands := []string{}
	i.run = func(_ context.Context, command string, args ...string) ([]byte, error) {
		commands = append(commands, command+" "+strings.Join(args, " "))
		return nil, nil
	}
	if err := singleMetricsUpgradeBackupMaintenance(context.Background(), i, m); err != nil {
		t.Fatal("cannot update disabled policy's fixed executor", err)
	}
	var enabled bool
	var savedHash string
	if err := s.DB.QueryRow(`SELECT enabled,sha256 FROM v3_single_backup_policies WHERE instance=$1`, p.spec.Instance).Scan(&enabled, &savedHash); err != nil || enabled || savedHash != digest(raw) {
		t.Fatal("disabled policy changed", err)
	}
	if !strings.Contains(strings.Join(commands, "\n"), "disable --now "+singleProject(p.spec.Root)+"-backup.timer") {
		t.Fatal("disabled timer enabled")
	}
	p.output = p.spec.Root + "-response-loss-backup"
	receipt, err := s.backupSingle(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	recovered, found, err := singleMetricsUpgradeRecoverBackup(context.Background(), p)
	if err != nil || !found || recovered.ManifestSHA256 != receipt.ManifestSHA256 {
		t.Fatal("completed fixed backup could not be resumed", err)
	}
	localWrite(t, p.request.HostConfig, append(mustReadSingleMetricsTestFile(t, p.request.HostConfig), '\n'))
	p.bindings[p.request.HostConfig] = digest(mustReadSingleMetricsTestFile(t, p.request.HostConfig))
	if _, _, err := singleMetricsUpgradeRecoverBackup(context.Background(), p); err == nil {
		t.Fatal("backup of different runtime bindings adopted")
	}
}

func mustReadSingleMetricsTestFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
