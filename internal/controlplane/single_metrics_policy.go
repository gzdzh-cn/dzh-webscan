package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"

	"golang.org/x/sys/unix"
)

func singleMetricsStateDirectory(s singleInstallSpec) string { return s.Root + "-metrics-policy-state" }

func singleMetricsBackupRequest(s singleInstallSpec) singleBackupSpec {
	p := singleBackupSpec{Format: 1, Installation: filepath.Join(s.Root, "install.json"), HostConfig: filepath.Join(s.Root, "executor.yaml"), APIConfig: filepath.Join(s.Root, "config.yaml"), ComposeFile: filepath.Join(s.Root, "compose.yaml")}
	if s.MetricsRetention {
		p.RecoveryDirectories = []string{singleMetricsStateDirectory(s)}
	}
	return p
}

// Mount only the immutable support parent into the API. The mutable host
// journal, coordinator lock and Docker access never enter that container.
func ensureSingleMetricsDirectories(s singleInstallSpec) error {
	if !s.MetricsRetention {
		return nil
	}
	for _, path := range []string{filepath.Join(s.Root, "metrics-support"), singleMetricsStateDirectory(s)} {
		if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return errMetricsRetentionRuntime
		}
		d, err := trustDirectory(path, true)
		if err != nil {
			return errMetricsRetentionRuntime
		}
		d.Close()
	}
	return nil
}

func singleMetricsRetentionSpec(ctx context.Context, s singleInstallSpec) (MetricsRetentionSpec, error) {
	p := MetricsRetentionSpec{Format: 1, Instance: s.Instance, Root: s.Root, InstallationFile: filepath.Join(s.Root, "install.json"), HostConfigFile: filepath.Join(s.Root, "executor.yaml"), ComposeFile: filepath.Join(s.Root, "compose.yaml"), StateDirectory: singleMetricsStateDirectory(s), BackupDirectory: s.Root + "-metrics-policy-backups", BackupRequest: singleMetricsBackupRequest(s)}
	host, err := LoadConfig(p.HostConfigFile)
	if err != nil || !s.MetricsRetention || host.Metrics.PolicyFile != s.configuration().Metrics.PolicyFile {
		return p, errMetricsRetentionRuntime
	}
	p.HelperFile = host.DeploymentTrust.HelperFile
	for _, item := range []struct {
		path string
		hash *string
	}{{p.InstallationFile, &p.InstallationSHA256}, {p.HostConfigFile, &p.HostConfigSHA256}, {p.ComposeFile, &p.ComposeSHA256}, {p.HelperFile, &p.HelperSHA256}} {
		a, err := hashTrustArtifact(ctx, item.path, 256<<20)
		if err != nil {
			return p, errMetricsRetentionRuntime
		}
		*item.hash = a.SHA256
	}
	return p, nil
}

func (i singleInstaller) activateSingleMetricsRetention(ctx context.Context, s singleInstallSpec) error {
	p, err := singleMetricsRetentionSpec(ctx, s)
	if err != nil {
		return err
	}
	if err := os.Mkdir(p.BackupDirectory, 0700); err != nil && !os.IsExist(err) {
		return errMetricsRetentionRuntime
	}
	d, err := trustDirectory(p.BackupDirectory, true)
	if err != nil {
		return errMetricsRetentionRuntime
	}
	d.Close()
	source := s.configuration().Metrics.PolicyFile
	if _, err := os.Lstat(filepath.Dir(source)); os.IsNotExist(err) {
		if err := prepareMetricsRetentionRuntime(ctx, p, filepath.Dir(source)); err != nil {
			return err
		}
	} else {
		existing, _, _, err := readMetricsRetentionRuntime(ctx, source)
		if err != nil {
			return err
		}
		// Historical Vault receipt keys remain valid. Resume authenticates exact
		// semantic bindings, without replacing policy or resetting its journal.
		existing.KeyID, existing.Proof = "", ""
		if !reflect.DeepEqual(existing, p) {
			return errMetricsRetentionRuntime
		}
	}
	for _, suffix := range []string{"service", "timer"} {
		unit, err := readTrustData(filepath.Join(filepath.Dir(source), "retention."+suffix), true, 64<<10)
		if err != nil {
			return err
		}
		if err := i.publishSingleUnit(singleProject(s.Root)+"-metrics-retention."+suffix, unit); err != nil {
			return err
		}
	}
	if _, err := i.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return errMetricsRetentionRuntime
	}
	if _, err := i.run(ctx, "systemctl", "start", singleProject(s.Root)+"-metrics-retention.service"); err != nil {
		return errMetricsRetentionRuntime
	}
	if _, err := i.run(ctx, "systemctl", "enable", "--now", singleProject(s.Root)+"-metrics-retention.timer"); err != nil {
		return errMetricsRetentionRuntime
	}
	// A successful systemctl invocation is not engine confirmation.
	store, err := Open(ctx, s.configuration())
	if err != nil {
		return err
	}
	defer store.DB.Close()
	var raw []byte
	if err := store.DB.QueryRowContext(ctx, `SELECT details FROM v3_role_status WHERE role='metrics-retention' AND instance=$1 AND error='' AND heartbeat > clock_timestamp()-interval '2 minutes' AND heartbeat <= clock_timestamp()+interval '5 seconds'`, s.Instance).Scan(&raw); err != nil {
		return errMetricsRetentionRuntime
	}
	var status MetricsRetentionStatus
	if json.Unmarshal(raw, &status) != nil || status.State != "confirmed" || status.Effective == nil {
		return errMetricsRetentionRuntime
	}
	return nil
}

// Retention applies with an exclusive lock. Stack boot holds a shared lock
// until its compose operation completes, so it cannot use a stale overlay
// during a concurrent change. Installation already owns its separate lock.
func singleMetricsActiveInstaller(ctx context.Context, s singleInstallSpec, installer singleInstaller) (singleInstaller, func(), error) {
	noop := func() {}
	if !s.MetricsRetention {
		return installer, noop, nil
	}
	d, err := trustDirectory(singleMetricsStateDirectory(s), true)
	if err != nil {
		return installer, noop, errMetricsRetentionRuntime
	}
	fd, err := unix.Openat(int(d.Fd()), "coordinator.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	d.Close()
	if err != nil {
		return installer, noop, errMetricsRetentionRuntime
	}
	f := os.NewFile(uintptr(fd), "coordinator.lock")
	if !singlePrivateFile(f) || unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB) != nil {
		f.Close()
		return installer, noop, errMetricsRetentionRuntime
	}
	unlock := func() { _ = unix.Flock(fd, unix.LOCK_UN); f.Close() }
	source := s.configuration().Metrics.PolicyFile
	if _, err := os.Lstat(source); os.IsNotExist(err) {
		if _, stateErr := os.Lstat(filepath.Join(singleMetricsStateDirectory(s), "journal.json")); os.IsNotExist(stateErr) {
			// Before first activation both engines still use the authenticated
			// immutable installation. A missing policy cannot adopt any journal.
			return installer, unlock, nil
		}
		unlock()
		return installer, noop, errMetricsRetentionRuntime
	}
	p, _, v, err := readMetricsRetentionRuntime(ctx, source)
	if err != nil {
		unlock()
		return installer, noop, err
	}
	overlay, err := metricsRetentionActiveOverlay(p, v)
	if err != nil {
		unlock()
		return installer, noop, err
	}
	return metricsRetentionInstaller(installer, s, overlay), unlock, nil
}

func startSingleMetricsStackCommand(ctx context.Context, o Options, out io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return errMetricsRetentionRuntime
	}
	m, _, _, err := singlePKIUpgradeInstallation(o.Source)
	if err != nil || !m.Spec.MetricsRetention {
		return errMetricsRetentionRuntime
	}
	executable, err := os.Executable()
	if err != nil {
		return errMetricsRetentionRuntime
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil || executable != filepath.Join(m.Spec.Root, "webscan") {
		return errMetricsRetentionRuntime
	}
	i := newSingleInstaller()
	i.docker, err = exec.LookPath("docker")
	if err != nil {
		return errMetricsRetentionRuntime
	}
	i, unlock, err := singleMetricsActiveInstaller(ctx, m.Spec, i)
	if err != nil {
		return err
	}
	defer unlock()
	if err := i.checkContainers(ctx, m.Spec, m.Spec.serviceNames(), false); err != nil {
		return err
	}
	if _, err := i.compose(ctx, m.Spec, "up", "-d", "--no-recreate", "--pull", "never"); err != nil {
		return errMetricsRetentionRuntime
	}
	return json.NewEncoder(out).Encode(map[string]string{"state": "started"})
}
