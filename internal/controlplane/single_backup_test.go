package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"webscan/internal/progress"
)

type singleBackupTransport struct {
	base   http.RoundTripper
	mutate func()
}

func (t singleBackupTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(r)
	if r.URL.Path == "/snapshot/create" && err == nil {
		t.mutate()
	}
	return response, err
}

func singleBackupMutatingClient(original *http.Client, mutate func()) *http.Client {
	client := *original
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = singleBackupTransport{base: base, mutate: mutate}
	return &client
}

func TestSingleBackupKeepsAuthenticatedProcessHeartbeatWhileFencingBusinessWrites(t *testing.T) {
	s := testStore(t)
	p, f := newSingleBackupFixture(t)
	v, err := OpenVault(p.config.DeploymentTrust.VaultKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	process, err := s.touchBootstrapProcess(ctx, v, bootstrapProcess{Instance: "backup-live-api", Member: p.config.Central.Instance, Role: "api", LaunchDigest: "launch", RuntimeDigest: "runtime"})
	if err != nil {
		t.Fatal(err)
	}
	observed := false
	p.metrics.HTTP = singleBackupMutatingClient(f.store.HTTP, func() {
		op, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		next, err := s.touchBootstrapProcess(op, v, process)
		if err != nil || !validProcess(v, next) || !next.Started.Equal(process.Started) || !next.Heartbeat.After(process.Heartbeat) {
			t.Fatal("backup prevented actual authenticated API heartbeat", err)
		}
		write, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		defer stop()
		_, err = s.DB.ExecContext(write, `UPDATE v3_settings SET version=version+1 WHERE id=1`)
		if err == nil || !errors.Is(write.Err(), context.DeadlineExceeded) {
			t.Fatal("business write escaped backup fence", err)
		}
		observed = true
	})
	if _, err := s.backupSingle(ctx, p); err != nil || !observed {
		t.Fatal("live heartbeat backup acceptance", err)
	}
}

func newSingleBackupFixture(t *testing.T) (singleBackupPlan, *metricsSnapshotFixture) {
	return newSingleBackupFixtureWithHelper(t, "")
}

func newSingleBackupFixtureWithHelper(t *testing.T, actualHelper string) (singleBackupPlan, *metricsSnapshotFixture) {
	return newSingleBackupFixtureFormat(t, actualHelper, 3)
}

func newSingleBackupFixtureFormat(t *testing.T, actualHelper string, format int) (singleBackupPlan, *metricsSnapshotFixture) {
	return newSingleBackupFixtureOptions(t, actualHelper, format, false)
}

func newSingleBackupFixtureOptions(t *testing.T, actualHelper string, format int, defaultBackup bool, watchdog ...bool) (singleBackupPlan, *metricsSnapshotFixture) {
	t.Helper()
	ctx := context.Background()
	metrics := newMetricsSnapshotFixture(t)
	s := singleSpecFixture(t)
	if len(watchdog) > 0 && watchdog[0] {
		parent, err := os.MkdirTemp("/tmp", "ws-wd-")
		if err != nil {
			t.Fatal(err)
		}
		parent, err = filepath.EvalSymlinks(parent)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(parent) })
		s.Root, s.HostWatchdog = filepath.Join(parent, "single"), true
	}
	trust := newTrustToolFixture(t)
	if actualHelper != "" {
		raw, err := os.ReadFile(actualHelper)
		if err != nil {
			t.Fatal(err)
		}
		localWrite(t, trust.helper, raw)
		trust.sign.Output += "-current-helper"
		if err := ReleaseCommand(ctx, trust.sign, io.Discard); err != nil {
			t.Fatal(err)
		}
		trust.signed = trust.sign.Output
	}
	c := trust.config()
	var rawMetrics *metricsSnapshotFixture
	if len(watchdog) > 1 && watchdog[1] {
		rawMetrics = newMetricsSnapshotFixture(t)
		u, _ := url.Parse(rawMetrics.store.URL)
		s.RawMetricsPort, _ = strconv.Atoi(u.Port())
		s.MetricsLayers = true
	}
	s.Format, s.ReleaseTrust = format, &c
	if defaultBackup {
		s.Backup = &singleInstallBackupPolicy{Directory: s.Root + "-backups", Keep: 7}
	}
	u, _ := url.Parse(metrics.store.URL)
	s.MetricsPort, _ = strconv.Atoi(u.Port())
	s.RulesFile = filepath.Join(trust.root, "rules.yar")
	localWrite(t, s.RulesFile, []byte("rule isolated { condition: false }"))
	if format == 2 {
		s.ReleaseTrust, s.RulesFile = nil, ""
	}
	helper, err := os.ReadFile(trust.helper)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	if err := prepareSingleInstallation(ctx, s, helper, "isolated-backup-password-123", "/usr/bin/docker"); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"state", "state/exports", "state/metrics-spool", "state/node-configurations", "postgres-data"} {
		if err := os.MkdirAll(filepath.Join(s.Root, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := initializeSinglePKI(ctx, s, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	// A physical database directory is never copied, regardless of its owner
	// or content. Only the transactionally exported application tables qualify.
	localWrite(t, filepath.Join(s.Root, "postgres-data", "do-not-copy"), []byte("unrelated physical engine data"))
	if err := os.Rename(metrics.store.Directory, filepath.Join(s.Root, "metrics-data")); err != nil {
		t.Fatal(err)
	}
	metrics.store.Directory = filepath.Join(s.Root, "metrics-data")
	if rawMetrics != nil {
		if err := os.Rename(rawMetrics.store.Directory, filepath.Join(s.Root, "raw-metrics-data")); err != nil {
			t.Fatal(err)
		}
		rawMetrics.store.Directory = filepath.Join(s.Root, "raw-metrics-data")
		localWrite(t, filepath.Join(rawMetrics.store.Directory, "raw-live-do-not-copy"), []byte("not a snapshot"))
	}
	j, err := readSingleInstallation(s, digest(helper))
	if err != nil {
		t.Fatal(err)
	}
	j.Step = 6
	if err := saveSingleJournal(s.Root, j); err != nil {
		t.Fatal(err)
	}
	request := singleBackupSpec{Format: 1, Installation: filepath.Join(s.Root, "install.json"), HostConfig: filepath.Join(s.Root, "executor.yaml"), APIConfig: filepath.Join(s.Root, "config.yaml"), ComposeFile: filepath.Join(s.Root, "compose.yaml")}
	if format == 2 {
		overlay := filepath.Join(filepath.Dir(s.Root), "web-upgrade")
		if err := os.Mkdir(overlay, 0700); err != nil {
			t.Fatal(err)
		}
		host := s.configuration()
		host.DeploymentTrust = c
		host.Executor = ExecutorConfig{Enabled: true, Mode: "embedded", ConfigurationDirectory: filepath.Join(s.Root, "state", "node-configurations"), RulesFile: filepath.Join(trust.root, "rules.yar")}
		host.NodePKI = NodePKIConfig{Enabled: true, AuthorityDirectory: filepath.Join(s.Root, "authority")}
		api := host
		api.NodePKI = NodePKIConfig{}
		api.Executor = ExecutorConfig{Enabled: true, Mode: "external"}
		api.DeploymentTrust.HelperFile, api.DeploymentTrust.NativeBundleFile, api.DeploymentTrust.ImageArchiveFile = "", "", ""
		request.HostConfig, request.APIConfig = filepath.Join(overlay, "executor.yaml"), filepath.Join(overlay, "config.yaml")
		hostRaw, _ := yaml.Marshal(host)
		apiRaw, _ := yaml.Marshal(api)
		localWrite(t, request.HostConfig, hostRaw)
		localWrite(t, request.APIConfig, apiRaw)
	}
	plan, err := planSingleBackup(ctx, request, filepath.Join(filepath.Dir(s.Root), "full-backup"))
	if err != nil {
		t.Fatal("cannot prepare bound backup", err)
	}
	return plan, metrics
}

func TestSingleBackupSupportsImmutableFormat2AndExternalWebOverlay(t *testing.T) {
	s := testStore(t)
	p, _ := newSingleBackupFixtureFormat(t, "", 2)
	before, _ := os.ReadFile(p.request.Installation)
	ctx := context.Background()
	r, err := s.backupSingle(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := verifySingleBackup(ctx, p.output, r.ManifestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range []string{p.request.HostConfig, p.request.APIConfig, p.config.DeploymentTrust.VaultKeyFile, p.config.DeploymentTrust.HelperFile} {
		found := false
		for _, source := range manifest.Sources {
			found = found || source.Path == original
		}
		if !found {
			t.Fatal("omitted external upgraded dependency")
		}
	}
	after, _ := os.ReadFile(p.request.Installation)
	if !bytes.Equal(before, after) {
		t.Fatal("rewrote original installation for backup compatibility")
	}
}

func TestSingleBackupCapturesPrivateHostDatabaseAndMetrics(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p, f := newSingleBackupFixture(t)
	if err := s.Provision(ctx, "admin", "backup-test-password-123"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutNode(ctx, nodeFixture("node-a"), 0, 256); err != nil {
		t.Fatal(err)
	}
	vault, err := OpenVault(p.config.DeploymentTrust.VaultKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	credential := SSHCredential{Host: "192.0.2.1", Port: 22, Fingerprint: "SHA256:" + strings.Repeat("A", 43), Password: "isolated-private-password"}
	if _, err := s.AddCredential(ctx, vault, "admin", "backup-credential", "node-a", 1, credential); err != nil {
		t.Fatal(err)
	}
	r, err := s.backupSingle(ctx, p)
	if err != nil || r.State != "captured" || r.RestoreTested || r.RuntimeStarted || r.Files < 20 || r.Bytes < 1 || !releaseDigest(r.ManifestSHA256) {
		t.Fatal(r, err)
	}
	manifest, err := verifySingleBackup(ctx, r.Directory, r.ManifestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	var archivedVault, archivedCA bool
	for _, file := range manifest.Files {
		if strings.Contains(file.Path, "postgres-data") || strings.Contains(file.Path, "metrics-data") || strings.HasSuffix(file.Path, "/.lock") {
			t.Fatal("archived live engine or lock", file.Path)
		}
		archivedVault = archivedVault || strings.HasSuffix(file.Path, "/vault.key")
		archivedCA = archivedCA || strings.HasSuffix(file.Path, "/authority/ca.key")
	}
	if !archivedVault || !archivedCA || len(f.requests) != 3 {
		t.Fatal("omitted private recovery dependency or cleanup", archivedVault, archivedCA, f.requests)
	}
	encoded, _ := json.Marshal(r)
	if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, []byte("isolated-private-password")) {
		t.Fatal("public receipt leaked credentials")
	}
	output := filepath.Join(filepath.Dir(p.output), "offline-recovery")
	if err := restoreSingleBackupOffline(ctx, p.output, r.ManifestSHA256, output); err != nil {
		t.Fatal("offline staging", err)
	}
	target := emptyTestStore(t)
	if err := target.RestorePostgres(ctx, filepath.Join(output, manifest.Postgres)); err != nil {
		t.Fatal("isolated PG import", err)
	}
	if tableCount(t, target, "v3_accounts") != 1 || tableCount(t, target, "v3_credentials") != 1 || tableCount(t, target, "v3_nodes") != 1 {
		t.Fatal("lost business rows")
	}
	var hostRoot string
	for _, source := range manifest.Sources {
		if source.Path == p.spec.Root {
			hostRoot = filepath.Join(output, source.Destination)
		}
	}
	restoredVault, err := OpenVault(filepath.Join(hostRoot, "vault.key"))
	if err != nil || restoredVault.active != vault.active {
		t.Fatal("Vault changed during backup/recovery", err)
	}
	if err := target.vaultAvailable(ctx, restoredVault); err != nil {
		t.Fatal("restored encrypted records no longer usable", err)
	}
	for _, name := range []string{"authority/ca.key", "collector-pki/collector.pem", "state/collector-trust/ca.crl", "install.json", "journal.json"} {
		original, e1 := os.ReadFile(filepath.Join(p.spec.Root, name))
		restored, e2 := os.ReadFile(filepath.Join(hostRoot, name))
		if e1 != nil || e2 != nil || !bytes.Equal(original, restored) {
			t.Fatal("lost identity/floor/installation material", name, e1, e2)
		}
	}
	if _, err := os.Stat(filepath.Join(output, "metrics", "snapshot.json")); !os.IsNotExist(err) {
		t.Fatal("backup metadata copied into VM data")
	}
	for _, destination := range []string{output, p.spec.Root, filepath.Join(p.spec.Root, "restore"), filepath.Join(p.output, "restore")} {
		if restoreSingleBackupOffline(ctx, p.output, r.ManifestSHA256, destination) == nil {
			t.Fatal("restored over existing/live/backup path", destination)
		}
	}
	if _, err := s.backupSingle(ctx, p); err == nil || len(f.requests) != 3 {
		t.Fatal("existing output was overwritten or contacted VM")
	}
}

func TestSingleBackupRejectsIncompleteUnsafeAndChangedHost(t *testing.T) {
	for _, scenario := range []string{"source-changed", "source-link", "source-hardlink", "source-fifo", "source-writable", "engine-link", "missing-vault", "old-schema", "unknown-key", "VM-failed", "VM-cleanup-failed", "host-changed-during-copy", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			s := testStore(t)
			p, f := newSingleBackupFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			file := filepath.Join(p.spec.Root, "state", "recovery-state")
			localWrite(t, file, []byte("original recovery evidence"))
			switch scenario {
			case "source-changed":
				localWrite(t, p.request.HostConfig, []byte("changed-private-runtime-config"))
			case "source-link":
				os.Symlink(filepath.Join(p.spec.Root, "vault.key"), file+".link")
			case "source-hardlink":
				os.Link(file, file+".hardlink")
			case "source-fifo":
				if err := unix.Mkfifo(file+".fifo", 0600); err != nil {
					t.Fatal(err)
				}
			case "source-writable":
				os.Chmod(file, 0666)
			case "engine-link":
				os.Rename(filepath.Join(p.spec.Root, "postgres-data"), filepath.Join(p.spec.Root, "postgres-data-original"))
				os.Symlink(filepath.Join(p.spec.Root, "postgres-data-original"), filepath.Join(p.spec.Root, "postgres-data"))
			case "missing-vault":
				os.Remove(p.config.DeploymentTrust.VaultKeyFile)
			case "old-schema":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_schema WHERE version=$1`, SchemaVersion)
			case "unknown-key":
				mustHistoryExec(t, s.DB, `INSERT INTO v3_configuration_backups(id,source,created_by,document_created_at,settings_version,node_count,needs_completion,key_id,revision,nonce,ciphertext_bytes) VALUES('unknown-key','manual','admin',clock_timestamp()::text,1,0,false,'missing-vault-key',1,'x',17)`)
			case "VM-failed":
				f.create = `{"status":"error","secret":"must-not-escape"}`
			case "VM-cleanup-failed":
				f.cleanup = `{"status":"error","secret":"must-not-escape"}`
			case "host-changed-during-copy":
				p.metrics.HTTP = f.store.HTTP
				p.metrics.HTTP = singleBackupMutatingClient(f.store.HTTP, func() { localWrite(t, file, []byte("different recovery evidence")) })
			case "canceled":
				cancel()
			}
			_, err := s.backupSingle(ctx, p)
			if err == nil || strings.Contains(err.Error(), "must-not-escape") {
				t.Fatal("incomplete backup accepted or leaked upstream error", err)
			}
			switch scenario {
			case "VM-failed":
				if !errors.Is(err, errMetricsSnapshotCreateUnknown) || len(f.requests) != 2 {
					t.Fatal("did not exercise VM creation failure", err, f.requests)
				}
			case "VM-cleanup-failed":
				if !errors.Is(err, errMetricsSnapshotCleanup) || len(f.requests) != 3 {
					t.Fatal("did not exercise VM cleanup failure", err, f.requests)
				}
			case "host-changed-during-copy":
				if !strings.HasPrefix(err.Error(), "host-recheck:") || len(f.requests) != 3 {
					t.Fatal("did not reach post-snapshot consistency check", err, f.requests)
				}
			}
			if _, err := os.Lstat(p.output); !os.IsNotExist(err) {
				t.Fatal("published failed backup", err)
			}
			// The read fence and all local locks must release after failure.
			if _, err := s.DB.ExecContext(context.Background(), `UPDATE v3_settings SET version=version WHERE id=1`); err != nil {
				t.Fatal("checkpoint left writes blocked", err)
			}
		})
	}
}

func TestSingleBackupRejectsTamperingAndUnsafeVerificationInput(t *testing.T) {
	s := testStore(t)
	p, _ := newSingleBackupFixture(t)
	r, err := s.backupSingle(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := verifySingleBackup(context.Background(), p.output, r.ManifestSHA256)
	for _, scenario := range []string{"extra", "missing", "corrupt", "link", "public", "manifest-digest", "manifest-duplicate", "invalid-mode"} {
		t.Run(scenario, func(t *testing.T) {
			file := filepath.Join(p.output, manifest.Files[0].Path)
			original, _ := os.ReadFile(file)
			originalManifest, _ := os.ReadFile(filepath.Join(p.output, "backup.json"))
			defer func() {
				os.Remove(file)
				localWrite(t, file, original)
				localWrite(t, filepath.Join(p.output, "backup.json"), originalManifest)
				os.Remove(filepath.Join(p.output, "extra"))
			}()
			hash := r.ManifestSHA256
			switch scenario {
			case "extra":
				localWrite(t, filepath.Join(p.output, "extra"), []byte("extra"))
			case "missing":
				os.Remove(file)
			case "corrupt":
				localWrite(t, file, []byte("corrupted-private-file"))
			case "link":
				os.Remove(file)
				os.Symlink(p.request.HostConfig, file)
			case "public":
				os.Chmod(file, 0644)
			case "manifest-digest":
				hash = strings.Repeat("f", 64)
			case "manifest-duplicate":
				localWrite(t, filepath.Join(p.output, "backup.json"), append([]byte(`{"format":1,`), originalManifest[1:]...))
			case "invalid-mode":
				changed := manifest
				changed.Modes = append([]singleBackupMode{}, manifest.Modes...)
				changed.Modes[0].Mode = 0777
				raw, _ := json.Marshal(changed)
				localWrite(t, filepath.Join(p.output, "backup.json"), raw)
				hash = digest(raw)
			}
			if _, err := verifySingleBackup(context.Background(), p.output, hash); err == nil {
				t.Fatal("tampered backup verified", scenario)
			}
		})
	}
	request, _ := json.Marshal(metricsSnapshotRestoreSpec{Format: 1, Directory: p.output, ManifestSHA256: strings.Repeat("f", 64)})
	source := filepath.Join(filepath.Dir(p.output), "verify.json")
	localWrite(t, source, request)
	var out bytes.Buffer
	if err := Command(context.Background(), Options{Action: "verify-single-backup", Source: source}, nil, &out); err == nil || out.Len() != 0 || progress.Explain(err) != errSingleBackup.Error() {
		t.Fatal("failed command leaked private paths or reported success", err, out.String())
	}
}

func TestSingleBackupCommandRejectsUnsupportedHostBeforeInput(t *testing.T) {
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Geteuid() == 0 {
		return
	}
	for _, action := range []string{"backup-single", "restore-single-offline"} {
		var out bytes.Buffer
		err := Command(context.Background(), Options{Action: action, Source: "/absent/private-input"}, nil, &out)
		var failure *progress.Failure
		if !errors.As(err, &failure) || failure.Code != "single_backup_host_required" || out.Len() != 0 {
			t.Fatal("host guard was bypassed", action, err)
		}
	}
}

func TestSingleBackupHostInspectionRejectsSpecialEntries(t *testing.T) {
	parent := privateTestDir(t)
	localWrite(t, filepath.Join(parent, "regular"), []byte("isolated recovery data"))
	if err := os.Symlink(filepath.Join(parent, "regular"), filepath.Join(parent, "link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(parent, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	directory, err := trustDirectory(parent, true)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if st, err := singleBackupInfo(directory, "regular"); err != nil || !singleBackupHostFile(st) {
		t.Fatal("descriptor-relative ordinary file rejected", err)
	}
	for _, name := range []string{"fifo", "link", "absent"} {
		if _, err := singleBackupInfo(directory, name); err == nil {
			t.Fatal("unsafe entry accepted", name)
		}
	}
}
