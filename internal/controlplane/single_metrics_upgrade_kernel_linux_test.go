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

	"webscan/internal/deploy"
)

// Runs the real CLI, signed helper, Docker/Compose, API, PostgreSQL, VM and
// systemd. The original single-store installation is newly made from this
// source; this does not pretend to execute an unavailable old release binary.
func TestSingleMetricsUpgradeKernelPreservesOldServicesAndActiveBootOverlay(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_METRICS_UPGRADE_KERNEL") != "1" {
		t.Skip("requires explicitly enabled networkless single-stack kernel guest")
	}
	requireBackupSystemdGuest(t)
	// The networkless guest executes Docker amd64 through TCG on ARM hosts.
	// Keep the whole multi-service acceptance budget separate from production
	// command timeouts, and retain stage timings when the guest is slow.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	const binary = "/v3-tests/webscan"
	if err := os.Chmod(binary, 0700); err != nil {
		t.Fatal(err)
	}
	root := "/v3-tests/metrics-upgrade-" + token()[:8]
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	var images map[string]string
	raw, err := os.ReadFile("/v3-tests/single-images.json")
	if err != nil || json.Unmarshal(raw, &images) != nil || len(images) != 4 {
		t.Fatal("explicit single-stack images required", err)
	}
	signing, signed := root+"/signing", root+"/release"
	if err := ReleaseCommand(ctx, ReleaseOptions{Action: "init-key", Output: signing}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := ReleaseCommand(ctx, ReleaseOptions{Action: "sign", Output: signed, KeyFile: signing + "/signing.key", Release: deploy.Release, Helper: binary, NativeBundle: "/v3-tests/agent-native.tar.gz", AgentImage: images["agent"]}, io.Discard); err != nil {
		t.Fatal(err)
	}
	rules := root + "/rules.yar"
	localWrite(t, rules, []byte("rule metrics_upgrade { condition: false }"))
	spec := singleInstallSpec{Format: 3, Root: root + "/installation", Instance: "kernel-metrics-upgrade", PublicURL: "https://metrics-upgrade.example.test", Username: "admin", APIPort: 19445, PostgresPort: 15432, MetricsPort: 18428, RuntimeImage: images["central"], PostgresImage: images["postgres"], MetricsImage: images["metrics"], RulesFile: rules, ReleaseTrust: &DeploymentTrustConfig{VaultKeyFile: root + "/installation/vault.key", PublicKeyFile: signing + "/signing.pub", ManifestFile: signed + "/release.json", SignatureFile: signed + "/release.sig", HelperFile: binary, NativeBundleFile: "/v3-tests/agent-native.tar.gz"}}
	spec.Backup = &singleInstallBackupPolicy{Directory: spec.Root + "-backups", Keep: 7}
	if err := spec.validate(); err != nil {
		t.Fatal(err)
	}
	call := func(action, source, output string) []byte {
		t.Helper()
		started := time.Now()
		t.Log("starting signed CLI action", action)
		args := []string{"control-v3", "--action", action, "--source", source}
		if output != "" {
			args = append(args, "--output", output)
		}
		if action == "install-single" {
			args = append(args, "--password-file", root+"/password")
		}
		raw, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if err != nil {
			os.WriteFile(root+"/failure.log", raw, 0600)
			t.Fatalf("actual signed metrics upgrade action %s failed: %v %s", action, err, raw)
		}
		t.Log("completed signed CLI action", action, time.Since(started))
		return raw
	}
	command := func(program string, args ...string) []byte {
		t.Helper()
		raw, err := exec.CommandContext(ctx, program, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("isolated service command %s failed: %v %s", program, err, raw)
		}
		return raw
	}
	request := root + "/install-request.json"
	writeProvisioningInput(t, request, spec)
	localWrite(t, root+"/password", []byte("isolated-metrics-upgrade-password-123"))
	// Explicitly create the authenticated historical single-store shape. New
	// public installs deliberately default to dual stores; resume preserves the
	// old immutable manifest and exercises the real installation lifecycle.
	binaryRaw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareSingleInstallation(ctx, spec, binaryRaw, "isolated-metrics-upgrade-password-123", dockerPath); err != nil {
		t.Fatal(err)
	}
	call("resume-single-install", request, "")
	c, err := LoadConfig(spec.Root + "/executor.yaml")
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	login, _ := http.NewRequestWithContext(ctx, "POST", "http://"+c.Central.Listen+"/api/v3/login", strings.NewReader(`{"username":"admin","password":"isolated-metrics-upgrade-password-123"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("X-Forwarded-Proto", "https")
	response, err := client.Do(login)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		CSRF string `json:"csrf"`
	}
	err = json.NewDecoder(response.Body).Decode(&body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || len(response.Cookies()) != 1 || body.CSRF == "" {
		t.Fatal("initial session unavailable", err)
	}
	cookie := response.Cookies()[0].Value
	project := singleProject(spec.Root)
	ids := map[string]string{}
	for _, service := range []string{"central", "postgres", "metrics"} {
		ids[service] = strings.TrimSpace(string(command("docker", "compose", "--project-name", project, "--file", spec.Root+"/compose.yaml", "ps", "--quiet", service)))
		if len(ids[service]) != 64 {
			t.Fatal("missing old service", service)
		}
	}
	before := map[string][]byte{}
	for _, path := range []string{spec.Root + "/install.json", spec.Root + "/journal.json", spec.Root + "/vault.key", spec.Root + "/authority/ca.key", spec.Root + "/backup-schedule.json"} {
		before[path] = mustReadSingleMetricsTestFile(t, path)
	}
	resp, err := client.Post(c.Metrics.WriteURL+"/api/v1/import/prometheus", "text/plain", strings.NewReader("webscan_pre_upgrade 73\n"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		t.Fatal("old metrics write failed")
	}
	historyProbeTime := time.Now().Add(10 * time.Second).UTC().Format(time.RFC3339)
	u := singleMetricsUpgradeSpec{Format: 1, Backup: singleBackupSpec{Format: 1, Installation: spec.Root + "/install.json", HostConfig: spec.Root + "/executor.yaml", APIConfig: spec.Root + "/config.yaml", ComposeFile: spec.Root + "/compose.yaml"}, StateDirectory: root + "/upgrade-state", BackupDirectory: root + "/upgrade-backups", RawMetricsPort: 18429, RawMetricsHours: 48, HistoryMetricsDays: 15, BackupSchedule: spec.Root + "/backup-schedule.json", BackupUpgradeDirectory: root + "/backup-upgrade"}
	upgradeRequest, output := root+"/upgrade-request.json", root+"/upgrade"
	writeProvisioningInput(t, upgradeRequest, u)
	call("preview-single-metrics-upgrade", upgradeRequest, output)
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("preview changed stack")
	}
	call("prepare-single-metrics-upgrade", upgradeRequest, output)
	source := output + "/upgrade.json"
	call("run-single-metrics-upgrade", source, "")
	call("resume-single-metrics-upgrade", source, "")
	resp, err = client.Post("http://127.0.0.1:18429/api/v1/import/prometheus", "text/plain", strings.NewReader("webscan_raw_upgrade 91\n"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		t.Fatal("raw metrics write failed")
	}
	rawProbeTime := time.Now().Add(10 * time.Second).UTC().Format(time.RFC3339)
	for _, service := range []string{"postgres", "metrics"} {
		now := strings.TrimSpace(string(command("docker", "compose", "--project-name", project, "--file", output+"/compose.yaml", "ps", "--quiet", service)))
		if now != ids[service] {
			t.Fatal("original storage container recreated", service)
		}
	}
	nowCentral := strings.TrimSpace(string(command("docker", "compose", "--project-name", project, "--file", output+"/compose.yaml", "ps", "--quiet", "central")))
	if nowCentral == ids["central"] || len(nowCentral) != 64 {
		t.Fatal("application config was not explicitly switched")
	}
	for path, want := range before {
		if !bytes.Equal(mustReadSingleMetricsTestFile(t, path), want) {
			t.Fatal("original installation changed", filepath.Base(path))
		}
	}
	requestSession, _ := http.NewRequestWithContext(ctx, "GET", "http://"+c.Central.Listen+"/api/v3/session", nil)
	requestSession.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: cookie})
	response, err = client.Do(requestSession)
	if err != nil {
		t.Fatal(err)
	}
	var session struct {
		CSRF string `json:"csrf"`
	}
	err = json.NewDecoder(response.Body).Decode(&session)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || session.CSRF != body.CSRF {
		t.Fatal("explicit upgrade lost session", err)
	}
	// Exercise changed retention and the installed boot action. A later boot
	// must never return the engines to the initial 48h/15d command line.
	singleKernelApplyRetention(t, ctx, client, c, singleKernelBootReceipt{Cookie: cookie, CSRF: body.CSRF})
	command("systemctl", "start", project+"-metrics-retention.service")
	call("start-single-metrics-upgrade-stack", source, "")
	command("systemctl", "restart", project+".service")
	if _, err := store.DB.ExecContext(ctx, `UPDATE v3_settings SET payload=jsonb_set(payload,'{backup}','{"enabled":true,"time":"00:00","timezone":"UTC","keep_days":7}'::jsonb,true),version=version+1`); err != nil {
		t.Fatal(err)
	}
	command("systemctl", "start", project+"-backup.service")
	var directory, hash string
	if err := store.DB.QueryRowContext(ctx, `SELECT directory,manifest_sha256 FROM v3_single_backup_runs WHERE status='captured' ORDER BY created_at DESC LIMIT 1`).Scan(&directory, &hash); err != nil {
		t.Fatal("upgraded schedule did not capture", err)
	}
	manifest, err := verifySingleBackup(ctx, directory, hash)
	if err != nil || manifest.RawMetrics == "" {
		t.Fatal("daily backup omitted raw layer", err)
	}
	restored := root + "/restored"
	if err := restoreSingleBackupOffline(ctx, directory, hash, restored); err != nil {
		t.Fatal(err)
	}
	dsn, err := readTrustData(c.Database.DSNFile, true, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("WEBSCAN_V3_TEST_DSN", strings.TrimSpace(string(dsn)))
	target := emptyTestStore(t)
	if err := target.RestorePostgres(ctx, filepath.Join(restored, manifest.Postgres)); err != nil {
		t.Fatal("isolated upgraded database restore", err)
	}
	for _, probe := range []struct{ name, metric, value, when string }{{"metrics", "webscan_pre_upgrade", "73", historyProbeTime}, {"metrics-raw", "webscan_raw_upgrade", "91", rawProbeTime}} {
		address := hostWatchdogKernelPort(t)
		id := strings.TrimSpace(string(command("docker", "run", "-d", "--network", "host", "--label", "io.webscan.test=metrics-upgrade-restore", "--mount", "type=bind,source="+filepath.Join(restored, probe.name)+",target=/storage", images["metrics"], "-storageDataPath=/storage", "-httpListenAddr="+address, "-retentionPeriod=15d", "-search.latencyOffset=0s")))
		if !validArchiveSource(id) {
			t.Fatal("invalid owned restore VM")
		}
		t.Cleanup(func() { exec.Command("docker", "rm", "-f", id).Run() })
		hostWatchdogKernelWait(t, ctx, 30*time.Second, func() bool { return singleHTTPHealth(ctx, "http://"+address+"/health") == nil }, "isolated restored metrics engine")
		r, err := client.Get("http://" + address + "/api/v1/query?" + url.Values{"query": {probe.metric}, "time": {probe.when}, "nocache": {"1"}}.Encode())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if err != nil || !bytes.Contains(raw, []byte(`"`+probe.value+`"`)) {
			t.Fatal("restored layer lost actual sample", probe.name, err)
		}
	}
	var statusRaw []byte
	if err := store.DB.QueryRowContext(ctx, `SELECT details FROM v3_role_status WHERE role='metrics-retention' AND instance=$1 AND error=''`, spec.Instance).Scan(&statusRaw); err != nil {
		t.Fatal(err)
	}
	var status MetricsRetentionStatus
	if json.Unmarshal(statusRaw, &status) != nil || status.State != "confirmed" || status.Effective == nil || status.Effective.RawHours != 36 || status.Effective.HistoryDays != 14 {
		t.Fatal("retention changed after stack startup")
	}
	t.Log("real signed single-to-dual upgrade, original PG/history IDs, durable login, changed retention, installed systemd startup and upgraded two-layer backup passed")
}
