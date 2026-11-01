package controlplane

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/deploy"
)

type singleMetricsUpgradeJournal struct {
	Format       int                  `json:"format"`
	SourceSHA256 string               `json:"source_sha256"`
	ID           string               `json:"id"`
	Phase        int                  `json:"phase"`
	Postgres     string               `json:"postgres"`
	History      string               `json:"history"`
	Backup       *singleBackupReceipt `json:"backup,omitempty"`
	DualBackup   *singleBackupReceipt `json:"dual_backup,omitempty"`
	KeyID        string               `json:"key_id"`
	Proof        string               `json:"proof"`
}

func singleMetricsUpgradeInstaller(i singleInstaller, s singleInstallSpec, compose, overlay string) singleInstaller {
	base := i.run
	i.run = func(ctx context.Context, command string, args ...string) ([]byte, error) {
		if command == i.docker && len(args) >= 5 && args[0] == "compose" && args[1] == "--project-name" && args[2] == singleProject(s.Root) && args[3] == "--file" && args[4] == filepath.Join(s.Root, "compose.yaml") {
			next := append([]string{}, args...)
			next[4] = compose
			if overlay != "" {
				next = append(append(append([]string{}, next[:5]...), "--file", overlay), next[5:]...)
			}
			args = next
		}
		return base(ctx, command, args...)
	}
	return i
}

func singleMetricsUpgradeContainerID(ctx context.Context, i singleInstaller, s singleInstallSpec, service string) (string, error) {
	raw, e := i.compose(ctx, s, "ps", "--all", "--quiet", service)
	id := strings.TrimSpace(string(raw))
	if e != nil || !validArchiveSource(id) {
		return "", errSingleMetricsUpgrade
	}
	return id, nil
}

func readSingleMetricsUpgradeJournal(m singleMetricsUpgradeManifest, sourceHash string, v *Vault) (singleMetricsUpgradeJournal, error) {
	var j singleMetricsUpgradeJournal
	path := filepath.Join(m.Request.StateDirectory, "journal.json")
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return j, nil
	}
	raw, e := readTrustData(path, true, 64<<10)
	if e != nil || singleDecode(raw, &j) != nil || j.Format != 1 || j.SourceSHA256 != sourceHash || !validArchiveSource(j.ID) || j.Phase < 0 || j.Phase > 5 || !validArchiveSource(j.Postgres) || !validArchiveSource(j.History) {
		return j, errSingleMetricsUpgrade
	}
	proof := j.Proof
	j.Proof = ""
	expected, e := metricsRetentionMAC(v, j.KeyID, "single-to-dual-journal", j)
	j.Proof = proof
	if e != nil || !hmac.Equal([]byte(proof), []byte(expected)) {
		return j, errSingleMetricsUpgrade
	}
	return j, nil
}
func writeSingleMetricsUpgradeJournal(m singleMetricsUpgradeManifest, v *Vault, j *singleMetricsUpgradeJournal) error {
	j.KeyID, j.Proof = v.active, ""
	proof, e := metricsRetentionMAC(v, j.KeyID, "single-to-dual-journal", *j)
	if e != nil {
		return errSingleMetricsUpgrade
	}
	j.Proof = proof
	raw, _ := json.Marshal(j)
	return metricsRetentionAtomicFile(m.Request.StateDirectory, "journal.json", raw)
}

func singleMetricsUpgradeBackupRequest(m singleMetricsUpgradeManifest) singleBackupSpec {
	p := m.Request.Backup
	p.HostConfig, p.APIConfig, p.ComposeFile = filepath.Join(m.Directory, "executor.yaml"), filepath.Join(m.Directory, "config.yaml"), filepath.Join(m.Directory, "compose.yaml")
	p.MetricsUpgrade = filepath.Join(m.Directory, "upgrade.json")
	p.RecoveryDirectories = append(append([]string{}, p.RecoveryDirectories...), m.Directory, m.Request.StateDirectory, singleMetricsStateDirectory(m.Effective))
	for _, source := range m.PreviousSources {
		if source.Directory && source.Path != m.Effective.Root && !containsPath(p.RecoveryDirectories, source.Path) {
			p.RecoveryDirectories = append(p.RecoveryDirectories, source.Path)
		}
	}
	return p
}

func singleMetricsUpgradeRetention(ctx context.Context, m singleMetricsUpgradeManifest) (MetricsRetentionSpec, error) {
	r := singleMetricsUpgradeBackupRequest(m)
	p := MetricsRetentionSpec{Format: 1, Instance: m.Effective.Instance, Root: m.Effective.Root, InstallationFile: r.Installation, HostConfigFile: r.HostConfig, ComposeFile: r.ComposeFile, HelperFile: m.HelperFile, StateDirectory: singleMetricsStateDirectory(m.Effective), BackupDirectory: m.Request.BackupDirectory, BackupRequest: r}
	for _, item := range []struct {
		path string
		hash *string
	}{{p.InstallationFile, &p.InstallationSHA256}, {p.HostConfigFile, &p.HostConfigSHA256}, {p.ComposeFile, &p.ComposeSHA256}, {p.HelperFile, &p.HelperSHA256}} {
		a, e := hashTrustArtifact(ctx, item.path, 256<<20)
		if e != nil {
			return p, errSingleMetricsUpgrade
		}
		*item.hash = a.SHA256
	}
	return p, nil
}

func prepareSingleMetricsUpgradeRetention(ctx context.Context, m singleMetricsUpgradeManifest) error {
	if e := ensureSingleMetricsDirectories(m.Effective); e != nil {
		return e
	}
	p, e := singleMetricsUpgradeRetention(ctx, m)
	if e != nil {
		return e
	}
	source := m.Effective.configuration().Metrics.PolicyFile
	if _, e := os.Lstat(filepath.Dir(source)); os.IsNotExist(e) {
		return prepareMetricsRetentionRuntime(ctx, p, filepath.Dir(source))
	}
	actual, _, _, e := readMetricsRetentionRuntime(ctx, source)
	if e != nil {
		return e
	}
	actual.KeyID, actual.Proof = "", ""
	p.KeyID, p.Proof = "", ""
	a, _ := json.Marshal(actual)
	b, _ := json.Marshal(p)
	if !hmac.Equal(a, b) {
		return errSingleMetricsUpgrade
	}
	return nil
}

func runSingleMetricsUpgradeCommand(ctx context.Context, o Options, out io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 || o.Output != "" {
		return errSingleMetricsUpgrade
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	m, e := readSingleMetricsUpgrade(ctx, o.Source)
	if e != nil {
		return e
	}
	executable, e := os.Executable()
	if e != nil {
		return errSingleMetricsUpgrade
	}
	executable, e = filepath.EvalSymlinks(executable)
	if e != nil || executable != m.HelperFile || deploy.Release != m.Release {
		return errSingleMetricsUpgrade
	}
	a, e := hashTrustArtifact(ctx, executable, 256<<20)
	if e != nil || a.SHA256 != m.HelperSHA256 {
		return errSingleMetricsUpgrade
	}
	p, _, e := planSingleMetricsUpgrade(ctx, m.Request, m.Directory)
	if e != nil {
		return e
	}
	v, e := OpenVault(p.config.DeploymentTrust.VaultKeyFile, p.config.DeploymentTrust.PreviousKeyFiles...)
	if e != nil {
		return errSingleMetricsUpgrade
	}
	for _, path := range []string{m.Request.StateDirectory, m.Request.BackupDirectory} {
		if e := os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
			return errSingleMetricsUpgrade
		}
		d, e := trustDirectory(path, true)
		if e != nil {
			return errSingleMetricsUpgrade
		}
		d.Close()
	}
	d, e := trustDirectory(m.Request.StateDirectory, true)
	if e != nil {
		return e
	}
	fd, e := unix.Openat(int(d.Fd()), "coordinator.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	d.Close()
	if e != nil {
		return errSingleMetricsUpgrade
	}
	lock := os.NewFile(uintptr(fd), "coordinator.lock")
	defer lock.Close()
	if !singlePrivateFile(lock) || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errSingleMetricsUpgrade
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	sourceRaw, e := readTrustData(o.Source, true, 512<<10)
	if e != nil {
		return errSingleMetricsUpgrade
	}
	j, e := readSingleMetricsUpgradeJournal(m, digest(sourceRaw), v)
	if e != nil {
		return e
	}
	i := newSingleInstaller()
	i.docker, e = exec.LookPath("docker")
	if e != nil {
		return errSingleMetricsUpgrade
	}
	old := singleMetricsUpgradeInstaller(i, m.Effective, m.Request.Backup.ComposeFile, "")
	next := singleMetricsUpgradeInstaller(i, m.Effective, filepath.Join(m.Directory, "compose.yaml"), "")
	if o.Action == "start-single-metrics-upgrade-stack" {
		// Phase 4 already proves both stores and the switched API are healthy.
		// The stack unit may have been atomically replaced immediately before a
		// power loss, while backup-unit installation still awaits resume.
		if j.Phase < 4 {
			return errSingleMetricsUpgrade
		}
		base := singleMetricsUpgradeInstaller(i, m.Effective, filepath.Join(m.Directory, "compose.yaml"), "")
		active, unlock, e := singleMetricsActiveInstaller(ctx, m.Effective, base)
		if e != nil {
			return e
		}
		defer unlock()
		if e := active.checkContainers(ctx, m.Effective, m.Effective.serviceNames(), false); e != nil {
			return e
		}
		if _, e := active.compose(ctx, m.Effective, "up", "-d", "--no-recreate", "--pull", "never"); e != nil {
			return errSingleMetricsUpgrade
		}
		if e := active.checkContainers(ctx, m.Effective, m.Effective.serviceNames(), true); e != nil {
			return e
		}
		for _, endpoint := range []string{m.Effective.configuration().Metrics.RawURL, p.config.Metrics.QueryURL} {
			if e := singleWait(ctx, func(ctx context.Context) error { return singleHTTPHealth(ctx, endpoint+"/health") }); e != nil {
				return e
			}
		}
		return json.NewEncoder(out).Encode(map[string]any{"state": "started", "effective_overlay": true})
	}
	if o.Action != "run-single-metrics-upgrade" && o.Action != "resume-single-metrics-upgrade" {
		return errSingleMetricsUpgrade
	}
	store, e := Open(ctx, p.config)
	if e != nil {
		return errSingleMetricsUpgrade
	}
	defer store.DB.Close()
	version, e := currentSchema(ctx, store.DB)
	if e != nil || version != SchemaVersion {
		return errSingleMetricsUpgrade
	}
	// A pre-existing approved startup handoff or saved bootstrap draft has its
	// own authenticated runtime baseline. This explicit overlay must not bypass
	// it, erase pending center changes or launch a config it would reject.
	var startupBinding bool
	if store.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_bootstrap_drafts WHERE instance=$1) OR EXISTS(SELECT 1 FROM v3_bootstrap_handoffs WHERE member=$1)`, p.config.Central.Instance).Scan(&startupBinding) != nil {
		return errSingleMetricsUpgrade
	}
	if startupBinding {
		return fmt.Errorf("%w：存在已保存的中心启动配置或交接任务，需要先使用专门的启动配置迁移流程；未覆盖待应用修改", errSingleMetricsUpgrade)
	}
	if j.Phase < 4 {
		target, e := store.metricsRetentionDesired(ctx, m.Effective)
		if e != nil || target.RawHours != m.Effective.RawMetricsHours || target.HistoryDays != m.Effective.HistoryMetricsDays {
			return errSingleMetricsUpgrade
		}
	}
	if e := singleMetricsUpgradeCheckBackupPolicy(ctx, store, m); e != nil {
		return e
	}
	if e := singleMetricsUpgradeRawDirectory(m, digest(sourceRaw), false); e != nil {
		return e
	}
	if e := prepareSingleMetricsUpgradeRetention(ctx, m); e != nil {
		return e
	}
	if e := singleMetricsUpgradeUnitsAllowed(ctx, i, m); e != nil {
		return e
	}
	if j.ID == "" {
		if e := old.checkContainers(ctx, m.Effective, []string{"postgres", "metrics", "central"}, true); e != nil {
			return e
		}
		if e := next.checkContainers(ctx, m.Effective, []string{"metrics-raw"}, false); e != nil {
			return e
		}
		listener, e := net.Listen("tcp", m.Effective.configuration().Metrics.RawURL[len("http://"):])
		if e != nil {
			return errSingleMetricsUpgrade
		}
		listener.Close()
		pg, e := singleMetricsUpgradeContainerID(ctx, old, m.Effective, "postgres")
		if e != nil {
			return e
		}
		history, e := singleMetricsUpgradeContainerID(ctx, old, m.Effective, "metrics")
		if e != nil {
			return e
		}
		j = singleMetricsUpgradeJournal{Format: 1, ID: token(), SourceSHA256: digest(sourceRaw), Postgres: pg, History: history}
		if e := writeSingleMetricsUpgradeJournal(m, v, &j); e != nil {
			return e
		}
	}
	unchanged := func() error {
		for service, want := range map[string]string{"postgres": j.Postgres, "metrics": j.History} {
			got, e := singleMetricsUpgradeContainerID(ctx, old, m.Effective, service)
			if e != nil || got != want {
				return errSingleMetricsUpgrade
			}
		}
		return old.checkContainers(ctx, m.Effective, []string{"postgres", "metrics"}, true)
	}
	if j.Phase < 4 && unchanged() != nil {
		return errSingleMetricsUpgrade
	}
	advance := func(phase int) error { j.Phase = phase; return writeSingleMetricsUpgradeJournal(m, v, &j) }
	if j.Phase == 0 {
		p.output = filepath.Join(m.Request.BackupDirectory, "before-dual-"+j.ID)
		receipt, found, e := singleMetricsUpgradeRecoverBackup(ctx, p)
		if e != nil {
			return e
		}
		if !found {
			receipt, e = store.backupSingle(ctx, p)
		}
		if e != nil {
			return errSingleMetricsUpgrade
		}
		j.Backup = &receipt
		if e = advance(1); e != nil {
			return e
		}
	}
	if j.Backup == nil {
		return errSingleMetricsUpgrade
	}
	if _, e := verifySingleBackup(ctx, j.Backup.Directory, j.Backup.ManifestSHA256); e != nil {
		return errSingleMetricsUpgrade
	}
	if j.Phase == 1 {
		if e := singleMetricsUpgradeRawDirectory(m, digest(sourceRaw), true); e != nil {
			return e
		}
		if e := ensureSingleMetricsDirectories(m.Effective); e != nil {
			return e
		}
		if e := next.checkContainers(ctx, m.Effective, []string{"metrics-raw"}, false); e != nil {
			return e
		}
		if _, e := next.compose(ctx, m.Effective, "up", "-d", "--no-deps", "--no-recreate", "--pull", "never", "metrics-raw"); e != nil {
			return errSingleMetricsUpgrade
		}
		if e := singleWait(ctx, func(ctx context.Context) error {
			return singleHTTPHealth(ctx, m.Effective.configuration().Metrics.RawURL+"/health")
		}); e != nil {
			return e
		}
		if e := metricsRetentionCheckActual(ctx, next, m.Effective, "", []string{"metrics-raw"}, true); e != nil {
			return e
		}
		if e := advance(2); e != nil {
			return e
		}
	}
	if j.Phase == 2 {
		if e := prepareSingleMetricsUpgradeRetention(ctx, m); e != nil {
			return e
		}
		if e := next.checkContainers(ctx, m.Effective, []string{"central"}, true); e != nil {
			if e := old.checkContainers(ctx, m.Effective, []string{"central"}, true); e != nil {
				return e
			}
			if _, e := next.compose(ctx, m.Effective, "up", "-d", "--no-deps", "--force-recreate", "--pull", "never", "central"); e != nil {
				return errSingleMetricsUpgrade
			}
		}
		if e := singleWait(ctx, func(ctx context.Context) error {
			return singleHTTPHealth(ctx, "http://"+p.config.Central.Listen+"/healthz")
		}); e != nil {
			return e
		}
		if e := unchanged(); e != nil {
			return e
		}
		if e := advance(3); e != nil {
			return e
		}
	}
	if j.Phase == 3 {
		policy := m.Effective.configuration().Metrics.PolicyFile
		for _, suffix := range []string{"service", "timer"} {
			raw, e := readTrustData(filepath.Join(filepath.Dir(policy), "retention."+suffix), true, 64<<10)
			if e != nil {
				return e
			}
			if e := singleMetricsUpgradeUnit(i, singleProject(m.Effective.Root)+"-metrics-retention."+suffix, nil, raw); e != nil {
				return e
			}
		}
		if _, e := i.run(ctx, "systemctl", "daemon-reload"); e != nil {
			return errSingleMetricsUpgrade
		}
		if _, e := i.run(ctx, "systemctl", "start", singleProject(m.Effective.Root)+"-metrics-retention.service"); e != nil {
			return errSingleMetricsUpgrade
		}
		if _, e := i.run(ctx, "systemctl", "enable", "--now", singleProject(m.Effective.Root)+"-metrics-retention.timer"); e != nil {
			return errSingleMetricsUpgrade
		}
		if e := unchanged(); e != nil {
			return e
		}
		if e := singleMetricsUpgradeRetentionConfirmed(ctx, store, m); e != nil {
			return e
		}
		if e := advance(4); e != nil {
			return e
		}
	}
	if j.Phase == 4 {
		dual, e := planSingleBackup(ctx, singleMetricsUpgradeBackupRequest(m), filepath.Join(m.Request.BackupDirectory, "after-dual-"+j.ID))
		if e != nil {
			return e
		}
		if j.DualBackup == nil {
			receipt, found, e := singleMetricsUpgradeRecoverBackup(ctx, dual)
			if e != nil {
				return e
			}
			if !found {
				receipt, e = store.backupSingle(ctx, dual)
			}
			if e != nil {
				return errSingleMetricsUpgrade
			}
			j.DualBackup = &receipt
			if e := writeSingleMetricsUpgradeJournal(m, v, &j); e != nil {
				return e
			}
		}
		if _, e := verifySingleBackup(ctx, j.DualBackup.Directory, j.DualBackup.ManifestSHA256); e != nil {
			return errSingleMetricsUpgrade
		}
		raw, e := readTrustData(filepath.Join(m.Directory, "stack.service"), true, 64<<10)
		if e != nil {
			return e
		}
		previous, e := readTrustData(filepath.Join(m.Effective.Root, "stack.service"), true, 64<<10)
		if e != nil {
			return e
		}
		if e := singleMetricsUpgradeUnit(i, singleProject(m.Effective.Root)+".service", previous, raw); e != nil {
			return e
		}
		if _, e := i.run(ctx, "systemctl", "daemon-reload"); e != nil {
			return errSingleMetricsUpgrade
		}
		if _, e := i.run(ctx, "systemctl", "enable", singleProject(m.Effective.Root)+".service"); e != nil {
			return errSingleMetricsUpgrade
		}
		if e := singleMetricsUpgradeBackupMaintenance(ctx, i, m); e != nil {
			return e
		}
		if e := advance(5); e != nil {
			return e
		}
	}
	active, unlock, e := singleMetricsActiveInstaller(ctx, m.Effective, next)
	if e != nil {
		return e
	}
	defer unlock()
	if e := active.checkContainers(ctx, m.Effective, m.Effective.serviceNames(), true); e != nil {
		return e
	}
	for _, url := range []string{m.Effective.configuration().Metrics.RawURL, p.config.Metrics.QueryURL} {
		if e := singleHTTPHealth(ctx, url+"/health"); e != nil {
			return e
		}
	}
	return json.NewEncoder(out).Encode(map[string]any{"state": "completed", "raw_metrics_enabled": true, "original_installation_unchanged": true, "historical_data_preserved": true, "application_restarted": true})
}
