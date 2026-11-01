//go:build linux

package controlplane

import (
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

// Real signed CLI, original owned PG/VM/application containers, systemd and
// archived-TSDB Docker verification. Source installation is newly made from
// this source. This is not an old-release-binary or machine-reboot acceptance.
// Agent replay and epoch behavior are exercised by the separate actual mTLS
// tests; this kernel case intentionally has no enrolled Agent.
func TestMigrationRecoveryHostKernelSignedArchiveAndActualIsolation(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_RECOVERY_HOST_KERNEL") != "1" {
		t.Skip("requires explicit isolated networkless kernel guest")
	}
	requireBackupSystemdGuest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	const helper = "/v3-tests/webscan"
	const vm = "/v3-tests/victoria-metrics-prod"
	if e := os.Chmod(helper, 0700); e != nil {
		t.Fatal(e)
	}
	root := "/v3-tests/recovery-host-" + token()[:8]
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	command := func(program string, args ...string) []byte {
		t.Helper()
		raw, e := exec.CommandContext(ctx, program, args...).CombinedOutput()
		if e != nil {
			_ = os.WriteFile(root+"/command-failure.log", raw, 0600)
			t.Fatalf("isolated recovery command %s failed: %v", filepath.Base(program), e)
		}
		return raw
	}
	var images map[string]string
	raw, e := os.ReadFile("/v3-tests/single-images.json")
	if e != nil || json.Unmarshal(raw, &images) != nil || len(images) != 4 {
		t.Fatal("explicit pinned images required", e)
	}
	signing, release := root+"/signing", root+"/release"
	if e = ReleaseCommand(ctx, ReleaseOptions{Action: "init-key", Output: signing}, io.Discard); e != nil {
		t.Fatal(e)
	}
	if e = ReleaseCommand(ctx, ReleaseOptions{Action: "sign", Output: release, KeyFile: signing + "/signing.key", Release: deploy.Release, Helper: helper, NativeBundle: "/v3-tests/agent-native.tar.gz", AgentImage: images["agent"]}, io.Discard); e != nil {
		t.Fatal(e)
	}
	localWrite(t, root+"/rules.yar", []byte("rule recovery_host { condition: false }"))
	spec := singleInstallSpec{Format: 3, Root: root + "/original", Instance: "kernel-recovery-host", PublicURL: "https://recovery-host.example.test", Username: "admin", APIPort: 19445, PostgresPort: 15432, MetricsPort: 18428, RawMetricsPort: 18429, MetricsLayers: true, RuntimeImage: images["central"], PostgresImage: images["postgres"], MetricsImage: images["metrics"], RulesFile: root + "/rules.yar", ReleaseTrust: &DeploymentTrustConfig{VaultKeyFile: root + "/original/vault.key", PublicKeyFile: signing + "/signing.pub", ManifestFile: release + "/release.json", SignatureFile: release + "/release.sig", HelperFile: helper, NativeBundleFile: "/v3-tests/agent-native.tar.gz"}}
	// Preserve an explicitly prepared no-watchdog/no-retention historical shape.
	// This makes source isolation independently observable without relying on
	// replay authorization or rewriting any immutable manifest.
	if e = spec.validate(); e != nil {
		t.Fatal(e)
	}
	binary, e := os.ReadFile(helper)
	if e != nil {
		t.Fatal(e)
	}
	docker, e := exec.LookPath("docker")
	if e != nil {
		t.Fatal(e)
	}
	if e = prepareSingleInstallation(ctx, spec, binary, "isolated-recovery-host-123", docker); e != nil {
		t.Fatal(e)
	}
	request := root + "/installation-request.json"
	writeProvisioningInput(t, request, spec)
	command(helper, "control-v3", "--action", "resume-single-install", "--source", request)
	config, e := LoadConfig(spec.Root + "/executor.yaml")
	if e != nil {
		t.Fatal(e)
	}
	source, e := Open(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer source.DB.Close()
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	for _, layer := range []string{config.Metrics.QueryURL, config.Metrics.RawURL} {
		response, e := client.Post(layer+"/api/v1/import/prometheus", "text/plain", strings.NewReader("webscan_recovery_host_archive_probe 83\n"))
		if e != nil {
			t.Fatal(e)
		}
		response.Body.Close()
		if response.StatusCode != 200 && response.StatusCode != 204 {
			t.Fatal("actual source metrics write failed")
		}
	}
	original := singleBackupSpec{Format: 1, Installation: spec.Root + "/install.json", HostConfig: spec.Root + "/executor.yaml", APIConfig: spec.Root + "/config.yaml", ComposeFile: spec.Root + "/compose.yaml"}
	backupRequest := root + "/backup-request.json"
	writeProvisioningInput(t, backupRequest, original)
	archive := root + "/archive"
	var receipt singleBackupReceipt
	if json.Unmarshal(command(helper, "control-v3", "--action", "backup-single", "--source", backupRequest, "--output", archive), &receipt) != nil || receipt.ManifestSHA256 == "" {
		t.Fatal("actual full archive receipt missing")
	}
	staged := root + "/staged"
	restoreInput := root + "/restore.json"
	writeProvisioningInput(t, restoreInput, metricsSnapshotRestoreSpec{Format: 1, Directory: receipt.Directory, ManifestSHA256: receipt.ManifestSHA256})
	command(helper, "control-v3", "--action", "restore-single-offline", "--source", restoreInput, "--output", staged)
	manifest, e := verifySingleBackup(ctx, receipt.Directory, receipt.ManifestSHA256)
	if e != nil {
		t.Fatal(e)
	}
	// Restore into a distinct real PG schema on the original owned engine.
	// A separate namespace is necessary even when the engine is shared.
	sourceDSN, e := readTrustData(config.Database.DSNFile, true, 64<<10)
	if e != nil {
		t.Fatal(e)
	}
	t.Setenv("WEBSCAN_V3_TEST_DSN", string(sourceDSN))
	target := emptyTestStore(t)
	if e = target.RestorePostgres(ctx, filepath.Join(staged, manifest.Postgres)); e != nil {
		t.Fatal(e)
	}
	var generation, schema string
	if e = target.DB.QueryRow(`SELECT generation FROM v3_migration_recovery_state WHERE id=1`).Scan(&generation); e != nil {
		t.Fatal(e)
	}
	if _, e = target.BeginMigrationRecovery(ctx, generation); e != nil {
		t.Fatal(e)
	}
	if e = target.DB.QueryRow(`SELECT current_schema()`).Scan(&schema); e != nil {
		t.Fatal(e)
	}
	targetConfig := config
	dsn, e := url.Parse(string(sourceDSN))
	if e != nil {
		t.Fatal(e)
	}
	q := dsn.Query()
	q.Set("search_path", schema)
	dsn.RawQuery = q.Encode()
	targetConfig.Database.DSNFile = root + "/target.dsn"
	localWrite(t, targetConfig.Database.DSNFile, []byte(dsn.String()))
	targetConfig.Metrics.QueryURL = singleBackupTestVM(t, ctx, vm, staged+"/metrics", "")
	targetConfig.Metrics.WriteURL = targetConfig.Metrics.QueryURL
	targetConfig.Metrics.RawURL = singleBackupTestVM(t, ctx, vm, staged+"/metrics-raw", "")
	targetFile := root + "/target.yaml"
	raw, _ = yaml.Marshal(targetConfig)
	localWrite(t, targetFile, raw)
	recovery := MigrationRecoveryHostRequest{Format: 1, Generation: generation, Backup: receipt.Directory, ManifestSHA256: receipt.ManifestSHA256, Staged: staged, Original: original, WorkDirectory: root + "/verify-work"}
	recoveryFile := root + "/recovery.json"
	writeProvisioningInput(t, recoveryFile, recovery)
	invoke := func(action string) ([]byte, error) {
		return exec.CommandContext(ctx, helper, "control-v3", "--action", action, "--config", targetFile, "--source", recoveryFile).CombinedOutput()
	}
	held := func() {
		t.Helper()
		var phase, proof string
		if e := target.DB.QueryRow(`SELECT phase,metrics_sha256 FROM v3_migration_recovery_state WHERE id=1`).Scan(&phase, &proof); e != nil || phase != "reconciling" || proof != "" {
			t.Fatal("failed check changed DR hold", phase, e)
		}
	}
	if _, e = invoke("activate-migration-recovery-host"); e == nil {
		t.Fatal("running source writer activated recovery")
	}
	held()
	project := singleProject(spec.Root)
	// Explicit test-root action, outside the checking/activation command: stop
	// only these owned project writers. PG and VM remain available for evidence.
	for _, unit := range []string{project + "-pki.timer", project + "-executor.service"} {
		command("systemctl", "disable", "--now", unit)
	}
	command("systemctl", "stop", project+"-pki.service")
	command("systemctl", "disable", project+".service")
	id := strings.TrimSpace(string(command("docker", "compose", "--project-name", project, "--file", original.ComposeFile, "ps", "--quiet", "central")))
	if len(id) != 64 {
		t.Fatal("actual source central missing")
	}
	command("docker", "update", "--restart=no", id)
	command("docker", "stop", id)
	// New source authority after the archive cannot be silently discarded.
	if _, e = source.DB.Exec(`INSERT INTO v3_nodes(id,name,endpoint,server_name,mode,shard) VALUES('new-after-backup','new','192.0.2.1:19100','192.0.2.1','docker',1)`); e != nil {
		t.Fatal(e)
	}
	if _, e = invoke("activate-migration-recovery-host"); e == nil {
		t.Fatal("new source identity discarded")
	}
	held()
	if _, e = source.DB.Exec(`DELETE FROM v3_nodes WHERE id='new-after-backup'`); e != nil {
		t.Fatal(e)
	}
	// A modified independent staged PG artifact never grants authority.
	pg := filepath.Join(staged, manifest.Postgres)
	saved, e := os.ReadFile(pg)
	if e != nil {
		t.Fatal(e)
	}
	localWrite(t, pg, append(saved, '\n'))
	if _, e = invoke("activate-migration-recovery-host"); e == nil {
		t.Fatal("modified stage accepted")
	}
	held()
	localWrite(t, pg, saved)
	checked, e := invoke("check-migration-recovery-host")
	if e != nil {
		_ = os.WriteFile(root+"/check-failure.log", checked, 0600)
		t.Fatal("actual signed recovery check failed", e)
	}
	var report MigrationRecoveryHostReport
	if json.Unmarshal(checked, &report) != nil || report.State != "verified" || report.CutoverAuthorized || report.Samples < 2 {
		t.Fatal("actual archived raw/history comparison missing")
	}
	held()
	activated, e := invoke("activate-migration-recovery-host")
	if e != nil {
		_ = os.WriteFile(root+"/activation-failure.log", activated, 0600)
		t.Fatal("actual signed activation failed", e)
	}
	if json.Unmarshal(activated, &report) != nil || report.State != "complete" || !report.CutoverAuthorized {
		t.Fatal("activation not complete")
	}
	var pending bool
	if e = target.DB.QueryRow(`SELECT pending FROM v3_migration_domains WHERE domain='disaster-recovery'`).Scan(&pending); e != nil || pending {
		t.Fatal("activation did not release only its DR hold", e)
	}
	if _, e = invoke("activate-migration-recovery-host"); e == nil {
		t.Fatal("completed generation reauthorized")
	}
	t.Log("real signed CLI/owned PG and application/systemd isolation/full raw+history archive verification completed; running writer, latest identity and modified stage failed closed; check retained hold; atomic activation completed. No machine reboot or enrolled Agent is claimed by this kernel case")
}
