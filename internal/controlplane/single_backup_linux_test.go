package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/deploy"
	"webscan/internal/nodepki"
)

func singleBackupTestVM(t *testing.T, ctx context.Context, binary, directory, endpoint string) string {
	t.Helper()
	address := ""
	if endpoint != "" {
		u, err := url.Parse(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		address = u.Host
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address = listener.Addr().String()
		listener.Close()
		endpoint = "http://" + address
	}
	log, err := os.OpenFile(directory+".log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	child, stop := context.WithCancel(ctx)
	command := exec.CommandContext(child, binary, "-storageDataPath="+directory, "-httpListenAddr="+address, "-retentionPeriod=15d", "-search.latencyOffset=0s")
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		stop()
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(); _ = command.Wait(); log.Close() })
	client := &http.Client{Timeout: time.Second}
	for attempt := 0; attempt < 100; attempt++ {
		response, err := client.Get(endpoint + "/health")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				return endpoint
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("isolated VM start timed out")
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("isolated VM did not become healthy")
	return ""
}

// This is a real compiled signed helper + PG17 + VM v1.128.0 recovery. The
// runner's network is isolated and contains synthetic business data only.
func TestSingleBackupActualSignedHelperAndEnginesLinux(t *testing.T) {
	helper, vm := os.Getenv("WEBSCAN_V3_TEST_BACKUP_HELPER"), os.Getenv("WEBSCAN_V3_TEST_VM_EXECUTABLE")
	if helper == "" || vm == "" {
		t.Skip("explicit current Linux helper and VM executable required")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		t.Fatal("isolated Linux amd64 root runner required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	version, err := exec.CommandContext(ctx, helper, "version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(version)) != deploy.Release {
		t.Fatal("actual helper version differs from the tested source")
	}
	s := testStore(t)
	if err := s.Provision(ctx, "admin", "isolated-full-backup-123"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutNode(ctx, nodeFixture("node-a"), 0, 256); err != nil {
		t.Fatal(err)
	}
	realTimer := os.Getenv("WEBSCAN_V3_TEST_BACKUP_SYSTEMD") == "1"
	if realTimer {
		requireBackupSystemdGuest(t)
	}
	p, f := newSingleBackupFixtureOptions(t, helper, 3, realTimer)
	f.server.Close()
	// The synthetic snapshot tree is solely this fixture's newly created
	// directory. Replace it with a real VM storage engine before taking a
	// production-path backup. No unrelated Docker volume or host path is used.
	if err := os.RemoveAll(p.metrics.Directory); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.metrics.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	// Logs are outside the source installation: a live log cannot be part of
	// the frozen host material. The actual listener retains the installed URL.
	endpoint := singleBackupTestVM(t, ctx, vm, p.metrics.Directory, p.metrics.URL)
	// Move the test process log out of the installation's recovery inventory.
	if err := os.Rename(p.metrics.Directory+".log", filepath.Join(filepath.Dir(p.spec.Root), "source-vm.log")); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := s.DB.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("WEBSCAN_V3_TEST_DSN"))
	if err != nil || dsn.Scheme != "postgres" && dsn.Scheme != "postgresql" {
		t.Fatal("invalid isolated DSN")
	}
	query := dsn.Query()
	query.Set("search_path", schema)
	dsn.RawQuery = query.Encode()
	// Bind a freshly-created TEST installation before using it. This is not a
	// supported way to alter an existing immutable production installation.
	localDSN := []byte(dsn.String())
	localWrite(t, p.config.Database.DSNFile, localDSN)
	raw, _ := os.ReadFile(p.request.Installation)
	var install singleInstallManifest
	if json.Unmarshal(raw, &install) != nil {
		t.Fatal("invalid isolated installation")
	}
	install.Files["postgres.dsn"] = digest(localDSN)
	raw, _ = json.Marshal(install)
	localWrite(t, p.request.Installation, raw)
	j := singleInstallJournal{Format: 1, Manifest: digest(raw), Step: 6}
	if err := saveSingleJournal(p.spec.Root, j); err != nil {
		t.Fatal(err)
	}
	vault, err := OpenVault(p.config.DeploymentTrust.VaultKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	credential := addCredential(t, s, vault, "node-a")
	verifyWork := seedSingleBackupPendingWork(t, ctx, s, credential)
	if realTimer {
		verifySingleBackupSystemdActivation(t, ctx, p, s)
	}
	stamp := time.Now().Add(-time.Minute).UnixMilli()
	client := &http.Client{Timeout: 5 * time.Second}
	write := func(name, value string) {
		t.Helper()
		response, err := client.Post(endpoint+"/api/v1/import/prometheus", "text/plain", strings.NewReader(fmt.Sprintf("%s{node_id=\"isolated-full-backup\"} %s %d\n", name, value, stamp)))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != 204 && response.StatusCode != 200 {
			t.Fatal("isolated metric write failed")
		}
	}
	write("webscan_full_backup_probe", "12.5")
	// Exercise the production scheduler through its actual signed helper too;
	// API/SQL fixtures cannot substitute for the executing-path/version check.
	if !realTimer {
		scheduledDirectory := filepath.Join(filepath.Dir(p.spec.Root), "scheduled-archives")
		if err := os.Mkdir(scheduledDirectory, 0700); err != nil {
			t.Fatal(err)
		}
		policyRequest := singleBackupScheduleSpec{Format: 1, Directory: scheduledDirectory, Keep: 7, Request: p.request}
		policyRequestFile := filepath.Join(filepath.Dir(p.spec.Root), "backup-policy-request.json")
		policyRaw, _ := json.Marshal(policyRequest)
		localWrite(t, policyRequestFile, policyRaw)
		policyDirectory := filepath.Join(filepath.Dir(p.spec.Root), "backup-policy")
		if err := os.Chmod(p.config.DeploymentTrust.HelperFile, 0700); err != nil {
			t.Fatal(err)
		}
		invokePolicy := func(binary, action, source, output string) []byte {
			t.Helper()
			args := []string{"control-v3", "--action", action, "--source", source}
			if output != "" {
				args = append(args, "--output", output)
			}
			raw, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("actual signed schedule %s: %v %s", action, err, raw)
			}
			return raw
		}
		invokePolicy(helper, "prepare-single-backup-schedule", policyRequestFile, policyDirectory)
		policyFile := filepath.Join(policyDirectory, "schedule.json")
		invokePolicy(p.config.DeploymentTrust.HelperFile, "configure-single-backup-schedule", policyFile, "")
		var scheduled singleBackupRunResult
		if json.Unmarshal(invokePolicy(p.config.DeploymentTrust.HelperFile, "run-single-backup", policyFile, ""), &scheduled) != nil || scheduled.State != "captured" || scheduled.Receipt == nil {
			t.Fatal("actual scheduled archive failed")
		}
		if _, err := verifySingleBackup(ctx, scheduled.Receipt.Directory, scheduled.Receipt.ManifestSHA256); err != nil {
			t.Fatal(err)
		}
		var notDue singleBackupRunResult
		if json.Unmarshal(invokePolicy(p.config.DeploymentTrust.HelperFile, "run-single-backup", policyFile, ""), &notDue) != nil || notDue.State != "not-due" {
			t.Fatal("actual scheduler duplicated an archive")
		}
	}
	requestFile := filepath.Join(filepath.Dir(p.output), "backup-request.json")
	requestRaw, _ := json.Marshal(p.request)
	localWrite(t, requestFile, requestRaw)
	call := func(action, source, output string) []byte {
		t.Helper()
		args := []string{"control-v3", "--action", action, "--source", source}
		if output != "" {
			args = append(args, "--output", output)
		}
		command := exec.CommandContext(ctx, helper, args...)
		raw, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated signed helper %s failed: %v %s", action, err, raw)
		}
		return raw
	}
	var receipt singleBackupReceipt
	if json.Unmarshal(call("backup-single", requestFile, p.output), &receipt) != nil || receipt.State != "captured" || receipt.RestoreTested || receipt.PendingSnapshot != "" {
		t.Fatal("invalid captured backup receipt")
	}
	write("webscan_after_full_backup", "99")
	verifyFile := filepath.Join(filepath.Dir(p.output), "verify-request.json")
	verifyRaw, _ := json.Marshal(metricsSnapshotRestoreSpec{Format: 1, Directory: p.output, ManifestSHA256: receipt.ManifestSHA256})
	localWrite(t, verifyFile, verifyRaw)
	call("verify-single-backup", verifyFile, "")
	restored := filepath.Join(filepath.Dir(p.output), "isolated-restore")
	call("restore-single-offline", verifyFile, restored)
	manifest, err := verifySingleBackup(ctx, p.output, receipt.ManifestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err := target.RestorePostgres(ctx, filepath.Join(restored, manifest.Postgres)); err != nil {
		t.Fatal("actual isolated PG restore failed", err)
	}
	verifyWork(target)
	var hostRoot string
	for _, source := range manifest.Sources {
		if source.Path == p.spec.Root {
			hostRoot = filepath.Join(restored, source.Destination)
		}
	}
	restoredVault, err := OpenVault(filepath.Join(hostRoot, "vault.key"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := target.ReadCredential(ctx, restoredVault, credential, "node-a")
	if err != nil || got != credentialFixture() {
		t.Fatal("restored Vault could not decrypt original credential")
	}
	ca, err := readTrustData(filepath.Join(hostRoot, "authority", "ca.crt"), true, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	key, err := readTrustData(filepath.Join(hostRoot, "authority", "ca.key"), true, 64<<10)
	defer clear(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.ParseAuthority(ca, key, time.Now().UTC()); err != nil {
		t.Fatal("restored CA unusable", err)
	}
	identity, _, err := nodepki.ReadIdentity(filepath.Join(hostRoot, "collector-pki", "ca.crt"), filepath.Join(hostRoot, "collector-pki", "collector.pem"), nodepki.Collector, p.spec.Instance, time.Now().UTC())
	defer clear(identity.Key)
	if err != nil {
		t.Fatal("restored collector identity unusable", err)
	}
	restoredEndpoint := singleBackupTestVM(t, ctx, vm, filepath.Join(restored, "metrics"), "")
	for _, metric := range []string{"webscan_full_backup_probe", "webscan_after_full_backup"} {
		values := url.Values{"query": {metric + `{node_id="isolated-full-backup"}`}, "time": {strconv.FormatInt(stamp/1000+1, 10)}, "nocache": {"1"}}
		response, err := client.Get(restoredEndpoint + "/api/v1/query?" + values.Encode())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		var result struct {
			Status string `json:"status"`
			Data   struct {
				Result []json.RawMessage `json:"result"`
			} `json:"data"`
		}
		if err != nil || json.Unmarshal(raw, &result) != nil || result.Status != "success" {
			t.Fatal("restored VM query failed")
		}
		if metric == "webscan_full_backup_probe" && (len(result.Data.Result) != 1 || !bytes.Contains(result.Data.Result[0], []byte(`"12.5"`))) || metric == "webscan_after_full_backup" && len(result.Data.Result) != 0 {
			t.Fatal("actual VM snapshot contents differ from captured boundary")
		}
	}
	verifySingleBackupRestoredAPI(t, ctx, helper, p, manifest, restored, target, restoredEndpoint)
	t.Logf("signed Linux scheduled/manual backup, isolated PostgreSQL decryption, CA/collector continuity, real VM query and restored API login/restart passed; files=%d bytes=%d; no production service or DR cutover was authorized", receipt.Files, receipt.Bytes)
}

type backupReceiptSender struct{ keys []string }

func (s *backupReceiptSender) Send(_ context.Context, n *Notification) error {
	key := n.DeliveryKey
	if key == "" {
		// Normal v3 notices use the sender's ID/recipient fallback; migrated
		// notices may carry a retained v2 key. Both must survive restoration.
		key = digest([]byte(fmt.Sprintf("%d:%s", n.ID, n.Recipient)))
	}
	s.keys = append(s.keys, key)
	return nil // No HTTP, SMTP or business destination is used.
}

// Pending deployment records are preserved, never executed by this restore
// test. Real SSH lifecycle acceptance is a separate gate. Notification replay
// uses the actual outbox claims/receipts with an explicitly injected sender.
func seedSingleBackupPendingWork(t *testing.T, ctx context.Context, source *Store, credential string) func(*Store) {
	t.Helper()
	job := createDeployment(t, source, DeploymentRequest{Node: "node-a", Kind: "install", Expected: 1, Credential: credential, Release: deploymentFixtureRelease(t), SHA256: strings.Repeat("a", 64)}, "backup-pending-deployment")
	claimed := claimDeployment(t, source, "backup-source-worker")
	if claimed.ID != job.ID || source.FailDeployment(ctx, claimed, "interrupted") != nil {
		t.Fatal("could not seed interrupted deployment")
	}
	job = reloadDeployment(t, source, job.ID)
	notificationSettings(t, source)
	enqueueNotification(t, source, "node-a", "already-delivered", "email", "isolated@example.test")
	done, err := source.claimNotification(ctx, "email", "backup-source-sender")
	sender := &backupReceiptSender{}
	if err != nil || done == nil || sender.Send(ctx, done) != nil || source.finishNotification(ctx, done, false) != nil {
		t.Fatal("could not seed delivered receipt", err)
	}
	enqueueNotification(t, source, "node-a", "pending-at-backup", "email", "isolated@example.test")
	var pendingID int64
	var pendingKey string
	if err := source.DB.QueryRowContext(ctx, `SELECT id,delivery_key FROM v3_notifications WHERE event_id='pending-at-backup'`).Scan(&pendingID, &pendingKey); err != nil {
		t.Fatal(err)
	}
	disable := func(s *Store) {
		mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=jsonb_set(jsonb_set(payload,'{email,enabled}','false'),'{feishu,enabled}','false')`)
	}
	disable(source)
	return func(target *Store) {
		t.Helper()
		restored, err := target.Deployment(ctx, job.ID)
		if err != nil || restored.PlanDigest != job.PlanDigest || restored.Status != job.Status || restored.Step != job.Step || restored.LogCursor != job.LogCursor {
			t.Fatal("restore lost immutable interrupted task/checkpoint", err)
		}
		blocked, err := target.claimNotification(ctx, "email", "backup-restored-sender")
		if err != nil || blocked != nil {
			t.Fatal("disabled restored notification channel executed", err)
		}
		notificationSettings(t, target) // Explicit isolated activation, mock only.
		pending, err := target.claimNotification(ctx, "email", "backup-restored-sender")
		mock := &backupReceiptSender{}
		if err != nil || pending == nil || pending.ID != pendingID || pending.DeliveryKey != pendingKey || mock.Send(ctx, pending) != nil || target.finishNotification(ctx, pending, false) != nil {
			t.Fatal("pending outbox did not preserve identity and receipt", err)
		}
		again, err := target.claimNotification(ctx, "email", "backup-restored-replacement")
		if err != nil || again != nil || len(mock.keys) != 1 || mock.keys[0] == sender.keys[0] || mock.keys[0] != digest([]byte(fmt.Sprintf("%d:%s", pendingID, pending.Recipient))) {
			t.Fatal("completed backup receipt was replayed", err)
		}
		var receipts int
		if err := target.DB.QueryRowContext(ctx, `SELECT count(*) FROM v3_notification_attempts WHERE success`).Scan(&receipts); err != nil || receipts != 2 {
			t.Fatal("outbox receipts lost or duplicated", err)
		}
		disable(target) // Actual restored API below has no live notification path.
		t.Log("signed backup preserved interrupted task/checkpoint and outbox IDs; explicit mock replay sent only pending work, retained completed receipt and stable delivery key")
	}
}

// Only the explicitly isolated test schema is activated. Rebased local paths
// are a test recovery overlay, not permission to activate an archive's DSN,
// source host paths, SSH executor or business notification destinations.
func verifySingleBackupRestoredAPI(t *testing.T, ctx context.Context, helper string, p singleBackupPlan, m singleBackupManifest, restored string, target *Store, metrics string) {
	t.Helper()
	rebase := func(original string) string {
		if original == "" {
			return ""
		}
		for _, source := range m.Sources {
			if source.Directory && singleBackupContains(source.Path, original) {
				relative, err := filepath.Rel(source.Path, original)
				if err != nil {
					t.Fatal(err)
				}
				return filepath.Join(restored, source.Destination, relative)
			}
			if !source.Directory && source.Path == original {
				return filepath.Join(restored, source.Destination)
			}
		}
		t.Fatal("missing restored path binding")
		return ""
	}
	c := p.config
	c.Executor = ExecutorConfig{}
	c.NodePKI = NodePKIConfig{}
	c.DeploymentTrust = DeploymentTrustConfig{}
	c.Central.ExportDirectory = rebase(c.Central.ExportDirectory)
	c.Metrics.SpoolDir = rebase(c.Metrics.SpoolDir)
	c.Metrics.WriteURL, c.Metrics.QueryURL = metrics, metrics
	c.Collector.CAFile = rebase(c.Collector.CAFile)
	c.Collector.IdentityFile = rebase(c.Collector.IdentityFile)
	c.Collector.RevocationFile = rebase(c.Collector.RevocationFile)
	c.Collector.RevocationStateDirectory = rebase(c.Collector.RevocationStateDirectory)
	var schema string
	if err := target.DB.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("WEBSCAN_V3_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	q := dsn.Query()
	q.Set("search_path", schema)
	dsn.RawQuery = q.Encode()
	c.Database.DSNFile = filepath.Join(filepath.Dir(restored), "restored-api.dsn")
	localWrite(t, c.Database.DSNFile, []byte(dsn.String()))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.Central.Listen = listener.Addr().String()
	listener.Close()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(filepath.Dir(restored), "restored-api.yaml")
	raw, _ := yaml.Marshal(c)
	localWrite(t, configFile, raw)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	var cookie *http.Cookie
	for attempt := 0; attempt < 2; attempt++ {
		child, cancel := context.WithCancel(ctx)
		command := exec.CommandContext(child, helper, "control-v3", "--action", "run", "--role", "all", "--config", configFile)
		logFile := filepath.Join(filepath.Dir(restored), fmt.Sprintf("restored-api-%d.log", attempt))
		log, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		command.Stdout, command.Stderr = log, log
		if err := command.Start(); err != nil {
			cancel()
			log.Close()
			t.Fatal(err)
		}
		// Register cleanup before every assertion, including failed readiness.
		var finished bool
		t.Cleanup(func() {
			if !finished {
				cancel()
				_ = command.Wait()
				log.Close()
			}
		})
		for probe := 0; probe < 100; probe++ {
			response, err := client.Get("http://" + c.Central.Listen + "/healthz")
			if err == nil {
				response.Body.Close()
				if response.StatusCode == 200 {
					break
				}
			}
			if probe == 99 {
				t.Fatal("restored real API did not become healthy; inspect isolated API log")
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
		endpoint := "/api/v3/login"
		method, body := "POST", `{"username":"admin","password":"isolated-full-backup-123"}`
		if attempt == 1 {
			endpoint, method, body = "/api/v3/session", "GET", ""
		}
		request, _ := http.NewRequestWithContext(ctx, method, "http://"+c.Central.Listen+endpoint, strings.NewReader(body))
		request.Header.Set("X-Forwarded-Proto", "https")
		request.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			request.AddCookie(cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != 200 {
			t.Fatalf("restored API login/session failed: %d", response.StatusCode)
		}
		if attempt == 0 {
			cookies := response.Cookies()
			if len(cookies) != 1 {
				t.Fatal("restored login did not issue a session")
			}
			cookie = cookies[0]
		}
		cancel()
		_ = command.Wait()
		log.Close()
		finished = true
	}
}
