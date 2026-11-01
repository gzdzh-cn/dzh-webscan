package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type migrationRecoveryHostRuntime struct {
	command       func(context.Context, string, ...string) ([]byte, error)
	processes     func(context.Context, singleBackupPlan) (string, error)
	metrics       func(context.Context, migrationRecoveryHostPlan) (string, int64, error)
	unitDirectory string
	localSource   func(context.Context, singleBackupPlan, *sql.Tx) (string, error)
}

func newMigrationRecoveryHostRuntime() migrationRecoveryHostRuntime {
	return migrationRecoveryHostRuntime{command: migrationRecoveryHostExec, processes: migrationRecoveryHostProcesses, metrics: migrationRecoveryHostVerifyMetrics, unitDirectory: "/etc/systemd/system", localSource: migrationRecoveryHostLocalSource}
}

// Only callers in this file construct verbs and flags. Tool names and paths
// never come from a request, PATH, database row or archive entry.
func migrationRecoveryHostExec(ctx context.Context, tool string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if tool != "docker" && tool != "systemctl" {
		return nil, ErrMigrationRecovery
	}
	for _, path := range []string{"/usr/bin/" + tool, "/usr/local/bin/" + tool} {
		if _, e := os.Lstat(path); os.IsNotExist(e) {
			continue
		}
		f, e := openTrustFile(path, false, 512<<20)
		if e != nil {
			return nil, ErrMigrationRecovery
		}
		f.Close()
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
		var out migrationObserveOutput
		cmd.Stdout = &out
		cmd.Stderr = &out
		if cmd.Run() != nil {
			// systemctl may return nonzero for an absent unit while still
			// returning structured properties. Accept only that exact absence;
			// malformed output and every other command failure remain errors.
			if tool == "systemctl" && len(args) > 0 && args[0] == "show" {
				v, e := migrationRecoveryHostProperties(out.Bytes())
				if e == nil && v["LoadState"] == "not-found" && v["ActiveState"] == "inactive" && v["SubState"] == "dead" && v["MainPID"] == "0" {
					return out.Bytes(), nil
				}
			}
			return nil, ErrMigrationRecovery
		}
		return out.Bytes(), nil
	}
	return nil, ErrMigrationRecovery
}

func migrationRecoveryHostProcesses(ctx context.Context, p singleBackupPlan) (string, error) {
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return "", ErrMigrationRecovery
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return "", ErrMigrationRecovery
		}
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid == os.Getpid() {
			continue
		}
		raw, e := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return "", ErrMigrationRecovery
		}
		args := strings.Split(string(raw), "\x00")
		for _, arg := range args {
			if arg == "" {
				continue
			}
			// Only exact argv paths are examined. Shells which merely display a
			// diagnostic containing a path are not invented into active writers.
			if arg == p.request.HostConfig || arg == p.request.APIConfig || arg == p.request.Installation || arg == filepath.Join(p.spec.Root, "webscan") || arg == p.config.DeploymentTrust.HelperFile {
				return "", ErrMigrationRecovery
			}
		}
	}
	return digest([]byte("proc-original-writer-paths-absent:" + p.installation)), nil
}

func migrationRecoveryHostProperties(raw []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			return nil, ErrMigrationRecovery
		}
		if _, exists := out[k]; exists {
			return nil, ErrMigrationRecovery
		}
		out[k] = v
	}
	return out, nil
}

func (r migrationRecoveryHostRuntime) isolation(ctx context.Context, p singleBackupPlan) (string, error) {
	if r.command == nil || r.processes == nil {
		return "", ErrMigrationRecovery
	}
	if r.unitDirectory == "" {
		return "", ErrMigrationRecovery
	}
	project := singleProject(p.spec.Root)
	units := map[string]string{".service": filepath.Join(p.spec.Root, "stack.service")}
	if p.config.Executor.Enabled && p.config.Executor.Mode == "external" {
		units["-executor.service"] = filepath.Join(filepath.Dir(p.request.HostConfig), "executor.service")
	}
	if p.spec.Format >= 2 {
		units["-pki.service"] = filepath.Join(p.spec.Root, "pki-maintenance.service")
		units["-pki.timer"] = filepath.Join(p.spec.Root, "pki-maintenance.timer")
	}
	if p.spec.Backup != nil {
		units["-backup.service"] = filepath.Join(p.spec.Root, "backup.service")
		units["-backup.timer"] = filepath.Join(p.spec.Root, "backup.timer")
	}
	if p.spec.HostWatchdog {
		units["-watchdog.service"] = filepath.Join(p.spec.Root, "watchdog-support", "watchdog.service")
	}
	if p.spec.MetricsRetention {
		for _, suffix := range []string{"service", "timer"} {
			units["-metrics-retention."+suffix] = filepath.Join(filepath.Dir(p.config.Metrics.PolicyFile), "retention."+suffix)
		}
	}
	// Unknown units at the well-known project names are not ignored merely
	// because the selected immutable version did not have that feature.
	proofs := []string{}
	for _, suffix := range []string{".service", "-executor.service", "-pki.service", "-pki.timer", "-backup.service", "-backup.timer", "-watchdog.service", "-metrics-retention.service", "-metrics-retention.timer"} {
		name := project + suffix
		raw, e := r.command(ctx, "systemctl", "show", "--no-pager", "--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,DropInPaths", name)
		if e != nil {
			return "", ErrMigrationRecovery
		}
		v, e := migrationRecoveryHostProperties(raw)
		if e != nil {
			return "", e
		}
		expected, required := units[suffix]
		if !required {
			if v["LoadState"] != "not-found" || v["MainPID"] != "0" {
				return "", ErrMigrationRecovery
			}
			proofs = append(proofs, name+":absent")
			continue
		}
		stopped := v["ActiveState"] == "inactive" && v["SubState"] == "dead"
		// The oneshot stack can remain exited after disabling it, while its
		// PG/VM containers remain available for read-only reconciliation.
		if suffix == ".service" && v["ActiveState"] == "active" && v["SubState"] == "exited" {
			stopped = true
		}
		static := strings.HasSuffix(suffix, ".service") && suffix != ".service" && suffix != "-executor.service" && suffix != "-watchdog.service" && v["UnitFileState"] == "static"
		if v["LoadState"] != "loaded" || !stopped || v["MainPID"] != "0" || v["DropInPaths"] != "" || (v["UnitFileState"] != "disabled" && v["UnitFileState"] != "masked" && !static) || v["FragmentPath"] != filepath.Join(r.unitDirectory, name) {
			return "", ErrMigrationRecovery
		}
		definition, e := readTrustData(expected, true, 256<<10)
		if e != nil {
			return "", ErrMigrationRecovery
		}
		actual, e := readTrustData(v["FragmentPath"], false, 256<<10)
		if e != nil || string(actual) != string(definition) {
			return "", ErrMigrationRecovery
		}
		// Definitions may only come from an authenticated install/overlay.
		if hash := p.bindings[expected]; hash == "" || hash != digest(definition) {
			return "", ErrMigrationRecovery
		}
		proofs = append(proofs, digest(append(append([]byte(name+":"), raw...), definition...)))
	}
	i := newSingleInstaller()
	i.docker = "docker"
	i.run = func(ctx context.Context, _ string, args ...string) ([]byte, error) {
		return r.command(ctx, "docker", args...)
	}
	if p.request.MetricsUpgrade != "" {
		i = singleMetricsUpgradeInstaller(i, p.spec, p.request.ComposeFile, "")
	}
	if e := i.checkContainers(ctx, p.spec, []string{"central"}, false); e != nil {
		return "", ErrMigrationRecovery
	}
	ids, e := r.command(ctx, "docker", "ps", "-a", "--filter", "label=com.docker.compose.project="+project, "--filter", "label=com.docker.compose.service=central", "--format", "{{.ID}}")
	if e != nil {
		return "", ErrMigrationRecovery
	}
	id := strings.TrimSpace(string(ids))
	if id != "" {
		if !validArchiveSource(id) {
			return "", ErrMigrationRecovery
		}
		raw, e := r.command(ctx, "docker", "inspect", id)
		var containers []migrationObservedContainer
		if e != nil || json.Unmarshal(raw, &containers) != nil || len(containers) != 1 {
			return "", ErrMigrationRecovery
		}
		v := containers[0]
		if v.State.Running || v.State.Paused || v.State.Restarting || v.State.Pid != 0 || (v.State.Status != "exited" && v.State.Status != "dead") || v.HostConfig.RestartPolicy.Name != "no" || v.Config.Labels["com.docker.compose.project"] != project || v.Config.Labels["com.docker.compose.service"] != "central" {
			return "", ErrMigrationRecovery
		}
		proofs = append(proofs, digest(raw))
	} else {
		proofs = append(proofs, "owned-original-central-container-absent")
	}
	processes, e := r.processes(ctx, p)
	if e != nil || !releaseDigest(processes) {
		return "", ErrMigrationRecovery
	}
	proofs = append(proofs, processes)
	sort.Strings(proofs)
	raw, _ := json.Marshal(proofs)
	return digest(raw), nil
}

// Remote source databases cannot prove that this host's process observations
// describe the old writer machine. The supported local case binds the actual
// database connection to the original owned, running PostgreSQL container.
// Unavailable/remote sources remain held until a separate trusted recovery
// mechanism can establish their host isolation.
func migrationRecoveryHostLocalSource(ctx context.Context, p singleBackupPlan, tx *sql.Tx) (string, error) {
	raw, err := readTrustData(p.config.Database.DSNFile, true, 64<<10)
	if err != nil {
		return "", ErrMigrationRecovery
	}
	cfg, err := pgx.ParseConfig(string(raw))
	if err != nil || cfg.Host != "127.0.0.1" || int(cfg.Port) != p.spec.PostgresPort {
		return "", ErrMigrationRecovery
	}
	for _, fallback := range cfg.Fallbacks {
		if fallback.Host != "127.0.0.1" || int(fallback.Port) != p.spec.PostgresPort {
			return "", ErrMigrationRecovery
		}
	}
	var address string
	var port int
	if tx.QueryRowContext(ctx, `SELECT COALESCE(inet_server_addr()::text,''),COALESCE(inet_server_port(),0)`).Scan(&address, &port) != nil || net.ParseIP(address) == nil || !net.ParseIP(address).IsLoopback() || port != p.spec.PostgresPort {
		return "", ErrMigrationRecovery
	}
	i := newSingleInstaller()
	i.docker = "docker"
	i.run = func(ctx context.Context, _ string, args ...string) ([]byte, error) {
		return migrationRecoveryHostExec(ctx, "docker", args...)
	}
	if p.request.MetricsUpgrade != "" {
		i = singleMetricsUpgradeInstaller(i, p.spec, p.request.ComposeFile, "")
	}
	if i.checkContainers(ctx, p.spec, []string{"postgres"}, true) != nil {
		return "", ErrMigrationRecovery
	}
	return digest([]byte("local-original-postgres:" + p.installation + ":" + address + ":" + strconv.Itoa(port))), nil
}
