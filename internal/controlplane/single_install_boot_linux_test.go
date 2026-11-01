//go:build linux

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
)

type singleKernelBootReceipt struct {
	BootID, Cookie, CSRF, Backup, BackupSHA256 string
	Containers                                 map[string]string
}

func TestSingleInstallActualKernelBootRecovery(t *testing.T) {
	phase := os.Getenv("WEBSCAN_V3_SINGLE_KERNEL_PHASE")
	if phase != "before" && phase != "after" && phase != "inspect" {
		t.Skip("requires explicit boot or diagnostic phase in networkless kernel guest")
	}
	requireBackupSystemdGuest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	const parent = "/v3-tests/fresh-single"
	const binary = "/v3-tests/webscan"
	const specification = parent + "/request.json"
	const receiptFile = parent + "/boot-receipt.json"
	const password = parent + "/admin-password"
	if phase == "inspect" {
		var manifest singleInstallManifest
		raw, err := readTrustData(parent+"/installation/install.json", true, 64<<10)
		if err != nil || singleDecode(raw, &manifest) != nil || manifest.Spec.validate() != nil {
			t.Fatal("existing isolated installation manifest unavailable", err)
		}
		if err := singleKernelReadinessDiagnostic(t, ctx, manifest.Spec); err != nil {
			t.Fatal("read-only diagnostic failed; not an installation acceptance", err)
		}
		return
	}
	var images map[string]string
	imageRaw, err := os.ReadFile("/v3-tests/single-images.json")
	if err != nil || json.Unmarshal(imageRaw, &images) != nil || len(images) != 4 {
		t.Fatal("explicit immutable single-stack images required", err)
	}
	command := func(program string, args ...string) []byte {
		t.Helper()
		raw, err := exec.CommandContext(ctx, program, args...).CombinedOutput()
		if err != nil {
			// Never print input files, Docker environments or secret material.
			_ = os.WriteFile(parent+"/command-failure.log", raw, 0600)
			if program == binary && phase == "before" && len(args) > 2 && args[2] == "install-single" {
				// A failed public installation is not retried or marked successful.
				// Collect read-only timings to distinguish a slow engine from an
				// identity/configuration failure without exposing tool arguments.
				var manifest singleInstallManifest
				if input, e := readTrustData(parent+"/installation/install.json", true, 64<<10); e == nil && singleDecode(input, &manifest) == nil && manifest.Spec.validate() == nil {
					e := singleKernelReadinessDiagnostic(t, ctx, manifest.Spec)
					t.Logf("read-only failed-install check result=%v", e)
				}
			}
			t.Fatalf("isolated boot command %s failed: %v", filepath.Base(program), err)
		}
		return raw
	}
	if phase == "before" {
		if err := os.Mkdir(parent, 0700); err != nil {
			t.Fatal("refusing existing installation", err)
		}
		if err := os.Chmod(binary, 0700); err != nil {
			t.Fatal(err)
		}
		signing, signed := parent+"/signing", parent+"/release"
		if err := ReleaseCommand(ctx, ReleaseOptions{Action: "init-key", Output: signing}, io.Discard); err != nil {
			t.Fatal(err)
		}
		if err := ReleaseCommand(ctx, ReleaseOptions{Action: "sign", Output: signed, KeyFile: signing + "/signing.key", Release: deploymentFixtureRelease(t), Helper: binary, NativeBundle: "/v3-tests/agent-native.tar.gz", AgentImage: images["agent"]}, io.Discard); err != nil {
			t.Fatal(err)
		}
		rules := parent + "/rules.yar"
		localWrite(t, rules, []byte("rule isolated_boot { condition: false }"))
		s := singleInstallSpec{Format: 3, Root: parent + "/installation", Instance: "kernel-single", PublicURL: "https://kernel-single.example.test", Username: "admin", APIPort: 19445, PostgresPort: 15432, MetricsPort: 18428, RawMetricsPort: 18429, HostWatchdog: true, MetricsLayers: true, MetricsRetention: true, RuntimeImage: images["central"], PostgresImage: images["postgres"], MetricsImage: images["metrics"], RulesFile: rules,
			ReleaseTrust: &DeploymentTrustConfig{VaultKeyFile: parent + "/installation/vault.key", PublicKeyFile: signing + "/signing.pub", ManifestFile: signed + "/release.json", SignatureFile: signed + "/release.sig", HelperFile: binary, NativeBundleFile: "/v3-tests/agent-native.tar.gz"}}
		if err := s.validate(); err != nil {
			t.Fatal(err)
		}
		writeProvisioningInput(t, specification, s)
		localWrite(t, password, []byte("isolated-boot-only-password-123"))
		command(binary, "control-v3", "--action", "preview-single-install", "--source", specification, "--password-file", password)
		if _, err := os.Stat(s.Root); !os.IsNotExist(err) {
			t.Fatal("preview installed services")
		}
		command(binary, "control-v3", "--action", "install-single", "--source", specification, "--password-file", password)
	}
	c, err := LoadConfig(parent + "/installation/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	wait := func(label string, check func() bool) {
		t.Helper()
		for end := time.Now().Add(2 * time.Minute); time.Now().Before(end); {
			if check() {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-time.After(time.Second):
			}
		}
		t.Fatal("boot recovery timed out", label)
	}
	// The engine socket becomes ready before its autostart containers finish
	// database recovery. Wait for a REAL connection, under the same bounded
	// boot acceptance deadline, rather than treating connection refusal in the
	// first few milliseconds as a completed recovery attempt.
	var store *Store
	wait("actual PostgreSQL boot readiness", func() bool {
		store, err = Open(ctx, c)
		return err == nil
	})
	defer store.DB.Close()
	wait("actual API readiness", func() bool {
		r, e := client.Get("http://" + c.Central.Listen + "/healthz")
		if e != nil {
			return false
		}
		r.Body.Close()
		return r.StatusCode == 200
	})
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(bytes.TrimSpace(boot)) == 0 {
		t.Fatal("actual boot identity unavailable", err)
	}
	ids := map[string]string{}
	for _, service := range []string{"central", "postgres", "metrics", "metrics-raw"} {
		id := strings.TrimSpace(string(command("docker", "compose", "--project-name", singleProject(parent+"/installation"), "--file", parent+"/installation/compose.yaml", "ps", "--quiet", service)))
		if len(id) != 64 {
			t.Fatal("installed stack service unavailable", service)
		}
		ids[service] = id
	}
	project := singleProject(parent + "/installation")
	for _, unit := range []string{project + ".service", project + "-executor.service", project + "-pki.timer", project + "-backup.timer", project + "-watchdog.service", project + "-metrics-retention.timer"} {
		command("systemctl", "is-enabled", "--quiet", unit)
		command("systemctl", "is-active", "--quiet", unit)
	}
	var receipt singleKernelBootReceipt
	if phase == "before" {
		request, _ := http.NewRequestWithContext(ctx, "POST", "http://"+c.Central.Listen+"/api/v3/login", strings.NewReader(`{"username":"admin","password":"isolated-boot-only-password-123"}`))
		request.Header.Set("X-Forwarded-Proto", "https")
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			CSRF string `json:"csrf"`
		}
		err = json.NewDecoder(response.Body).Decode(&body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || len(response.Cookies()) != 1 || body.CSRF == "" {
			t.Fatal("actual installed login failed", err)
		}
		receipt = singleKernelBootReceipt{BootID: strings.TrimSpace(string(boot)), Cookie: response.Cookies()[0].Value, CSRF: body.CSRF, Containers: ids}
		singleKernelApplyRetention(t, ctx, client, c, receipt)
		centralBefore := command("docker", "inspect", "--format", "{{.Id}}/{{.State.Pid}}/{{.State.StartedAt}}", ids["central"])
		command("systemctl", "start", project+"-metrics-retention.service")
		if !bytes.Equal(centralBefore, command("docker", "inspect", "--format", "{{.Id}}/{{.State.Pid}}/{{.State.StartedAt}}", ids["central"])) {
			t.Fatal("metrics retention restarted the main process")
		}
		var actual MetricsRetentionStatus
		var details []byte
		if err := store.DB.QueryRowContext(ctx, `SELECT details FROM v3_role_status WHERE role='metrics-retention' AND instance=$1 AND error=''`, c.Central.Instance).Scan(&details); err != nil || json.Unmarshal(details, &actual) != nil || actual.State != "confirmed" || actual.Effective == nil || actual.Effective.RawHours != 36 || actual.Effective.HistoryDays != 14 {
			t.Fatal("actual engines not confirmed after explicit retention application", err)
		}
		for _, service := range []string{"metrics", "metrics-raw"} {
			ids[service] = strings.TrimSpace(string(command("docker", "compose", "--project-name", project, "--file", parent+"/installation/compose.yaml", "ps", "--quiet", service)))
		}
		receipt.Containers = ids
		mustHistoryExec(t, store.DB, `INSERT INTO v3_audit(username,kind,resource,result) VALUES('admin','kernel-boot','durable-marker','{}')`)
		for _, target := range []string{c.Metrics.WriteURL, c.Metrics.RawURL} {
			response, err = client.Post(target+"/api/v1/import/prometheus", "text/plain", strings.NewReader("webscan_boot_acceptance 17\n"))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 204 && response.StatusCode != 200 {
				t.Fatal("actual VM write failed")
			}
		}
		centralState := []string{"inspect", "--format", "{{.State.Running}}/{{.State.StartedAt}}/{{.RestartCount}}", ids["central"]}
		beforeBackup := command("docker", centralState...)
		command("systemctl", "start", project+"-backup.service")
		if !bytes.Equal(beforeBackup, command("docker", centralState...)) || !bytes.HasPrefix(beforeBackup, []byte("true/")) {
			t.Fatal("full backup stopped or restarted the actual central container")
		}
		if err := store.DB.QueryRowContext(ctx, `SELECT directory,manifest_sha256 FROM v3_single_backup_runs WHERE status='captured' ORDER BY created_at DESC LIMIT 1`).Scan(&receipt.Backup, &receipt.BackupSHA256); err != nil {
			t.Fatal("fresh installation did not run its signed backup service", err)
		}
		if manifest, err := verifySingleBackup(ctx, receipt.Backup, receipt.BackupSHA256); err != nil || manifest.RawMetrics == "" {
			t.Fatal(err)
		}
		writeProvisioningInput(t, receiptFile, receipt)
		t.Log("fresh signed single-center installation, actual systemd services/default backup, PG17, VM, login and durable reboot receipt passed; awaiting real machine reboot")
		return
	}
	raw, err := os.ReadFile(receiptFile)
	if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.BootID == strings.TrimSpace(string(boot)) {
		t.Fatal("machine did not actually reboot", err)
	}
	for service, id := range ids {
		if receipt.Containers[service] != id {
			t.Fatal("boot recreated service container", service)
		}
	}
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://"+c.Central.Listen+"/api/v3/session", nil)
	request.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: receipt.Cookie})
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var session struct {
		CSRF string `json:"csrf"`
	}
	err = json.NewDecoder(response.Body).Decode(&session)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || session.CSRF != receipt.CSRF {
		t.Fatal("boot lost login/CSRF", err)
	}
	var count int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM v3_audit WHERE kind='kernel-boot' AND resource='durable-marker'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("PG boot continuity", err)
	}
	for _, target := range []string{c.Metrics.QueryURL, c.Metrics.RawURL} {
		wait("VM durable sample", func() bool {
			response, err := client.Get(target + "/api/v1/query?query=webscan_boot_acceptance&nocache=1")
			if err != nil {
				return false
			}
			raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			response.Body.Close()
			return err == nil && response.StatusCode == 200 && bytes.Contains(raw, []byte(`"17"`))
		})
	}
	for service, period := range map[string]string{"metrics": "-retentionPeriod=14d", "metrics-raw": "-retentionPeriod=36h"} {
		if !bytes.Contains(command("docker", "inspect", "--format", "{{json .Config.Cmd}}", ids[service]), []byte(period)) {
			t.Fatal("reboot lost the authenticated retention overlay", service)
		}
	}
	if _, err := verifySingleBackup(ctx, receipt.Backup, receipt.BackupSHA256); err != nil {
		t.Fatal("boot backup integrity", err)
	}
	command(binary, "control-v3", "--action", "resume-single-install", "--source", specification, "--password-file", password)
	t.Log("actual new kernel boot ID, unchanged container IDs, API/executor/PKI/watchdog/backup/retention autostart, PG and both VM durability, authenticated applied retention overlay, retained session/CSRF and signed dual-layer backup integrity passed")
}

func singleKernelApplyRetention(t *testing.T, ctx context.Context, client *http.Client, c Config, receipt singleKernelBootReceipt) {
	t.Helper()
	call := func(method, path string, input any, output any) {
		t.Helper()
		var body io.Reader
		if input != nil {
			body = bytes.NewReader(common.JSON(input))
		}
		r, err := http.NewRequestWithContext(ctx, method, "http://"+c.Central.Listen+"/api/v3/settings"+path, body)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-CSRF-Token", receipt.CSRF)
		key := "kernel-retention-" + strings.TrimPrefix(path, "/")
		if in, ok := input.(settingsEditorRequest); ok {
			key += "-" + in.Action
		}
		r.Header.Set("Idempotency-Key", key)
		r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: receipt.Cookie})
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			var failure struct {
				Code string `json:"code"`
			}
			_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&failure)
			t.Fatal("actual settings operation rejected", method, path, response.StatusCode, failure.Code)
		}
		if output != nil && json.NewDecoder(response.Body).Decode(output) != nil {
			t.Fatal("invalid settings response")
		}
	}
	for _, action := range []string{"save", "apply"} {
		var view settingsEditorView
		call("GET", "", nil, &view)
		if !view.MetricsRetention.Available {
			t.Fatal("fresh coordinator unavailable to actual API")
		}
		in := settingsEditorRequest{Action: action, ExpectedGeneration: view.State.Generation, ExpectedRuntime: view.State.RuntimeVersion, Edit: settingsEdit{}}
		if action == "save" {
			// Exercise the real settings workflow while making today's backup
			// due in every guest timezone/hour. The shipped default remains 03:00
			// UTC; starting its service before that time must correctly do nothing.
			in.Edit.Values = map[string]json.RawMessage{"monitoring.raw_hours": json.RawMessage(`36`), "monitoring.history_days": json.RawMessage(`14`), "backup.enabled": json.RawMessage(`true`), "backup.time": json.RawMessage(`"00:00"`), "backup.timezone": json.RawMessage(`"UTC"`)}
		}
		var preview settingsEditorPreview
		call("POST", "/preview", in, &preview)
		in.Preview = preview.Token
		// Save and apply have different durable request identities.
		call("POST", "/confirm", in, nil)
	}
}

func singleKernelReadinessDiagnostic(t *testing.T, ctx context.Context, spec singleInstallSpec) error {
	t.Helper()
	installer := newSingleInstaller()
	run := installer.run
	installer.run = func(op context.Context, executable string, arguments ...string) ([]byte, error) {
		began := time.Now()
		result, err := run(op, executable, arguments...)
		// All classifications are fixed strings, never arbitrary arguments or
		// output from a service, credential file or container environment.
		kind := "other"
		for _, value := range arguments {
			switch value {
			case "compose", "config", "ps", "inspect", "image", "is-enabled", "is-active":
				kind = value
			}
		}
		t.Logf("read-only install check executable=%s kind=%s elapsed=%s failed=%t context=%v", filepath.Base(executable), kind, time.Since(began).Round(time.Millisecond), err != nil, op.Err())
		return result, err
	}
	return installer.verify(ctx, spec)
}
