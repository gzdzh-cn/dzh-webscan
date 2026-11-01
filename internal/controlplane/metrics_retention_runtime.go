package controlplane

// This host-only coordinator never changes the immutable installation or the
// API process. Its authenticated overlay changes exactly two VM commands.
import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

var errMetricsRetentionRuntime = errors.New("指标保留策略尚未生效：请检查已验证双库安装、完整备份和宿主维护任务；未清除数据或重启中心")

type MetricsRetentionSpec struct {
	Format             int              `json:"format"`
	Instance           string           `json:"instance"`
	Root               string           `json:"root"`
	InstallationFile   string           `json:"installation_file"`
	InstallationSHA256 string           `json:"installation_sha256"`
	HostConfigFile     string           `json:"host_config_file"`
	HostConfigSHA256   string           `json:"host_config_sha256"`
	ComposeFile        string           `json:"compose_file"`
	ComposeSHA256      string           `json:"compose_sha256"`
	HelperFile         string           `json:"helper_file"`
	HelperSHA256       string           `json:"helper_sha256"`
	StateDirectory     string           `json:"state_directory"`
	BackupDirectory    string           `json:"backup_directory"`
	BackupRequest      singleBackupSpec `json:"backup_request"`
	KeyID              string           `json:"key_id"`
	Proof              string           `json:"proof"`
}

type metricsRetentionTarget struct {
	RawHours    int   `json:"raw_hours"`
	HistoryDays int   `json:"history_days"`
	Version     int64 `json:"settings_version"`
}

type metricsRetentionJournal struct {
	Format          int                    `json:"format"`
	SpecSHA256      string                 `json:"spec_sha256"`
	ID              string                 `json:"id"`
	Phase           string                 `json:"phase"`
	Target          metricsRetentionTarget `json:"target"`
	Overlay         string                 `json:"overlay"`
	OverlaySHA256   string                 `json:"overlay_sha256"`
	PreviousOverlay string                 `json:"previous_overlay,omitempty"`
	PreviousSHA256  string                 `json:"previous_sha256,omitempty"`
	Backup          *singleBackupReceipt   `json:"backup,omitempty"`
	ConfirmedAt     time.Time              `json:"confirmed_at,omitempty"`
	KeyID           string                 `json:"key_id"`
	Proof           string                 `json:"proof"`
}

type MetricsRetentionStatus struct {
	PolicySHA256 string                  `json:"policy_sha256"`
	State        string                  `json:"state"`
	TaskID       string                  `json:"task_id,omitempty"`
	Desired      *metricsRetentionTarget `json:"desired,omitempty"`
	Effective    *metricsRetentionTarget `json:"effective,omitempty"`
	Observed     time.Time               `json:"observed_at"`
}

func metricsRetentionMAC(v *Vault, keyID, domain string, value any) (string, error) {
	key := v.receiptKeys[keyID]
	if len(key) == 0 {
		return "", errMetricsRetentionRuntime
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", errMetricsRetentionRuntime
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("webscan-v3/metrics-retention/" + domain + "/v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validateMetricsRetentionSpec(p MetricsRetentionSpec) error {
	if p.Format != 1 || !identifier.MatchString(p.Instance) || p.Root == "/" || p.InstallationFile != filepath.Join(p.Root, "install.json") || p.BackupRequest.Installation != p.InstallationFile || p.BackupRequest.HostConfig != p.HostConfigFile || p.BackupRequest.ComposeFile != p.ComposeFile {
		return errMetricsRetentionRuntime
	}
	if p.BackupRequest.MetricsUpgrade == "" && p.ComposeFile != filepath.Join(p.Root, "compose.yaml") {
		return errMetricsRetentionRuntime
	}
	for _, path := range []string{p.Root, p.InstallationFile, p.HostConfigFile, p.ComposeFile, p.HelperFile, p.StateDirectory, p.BackupDirectory} {
		if !snapshotAbsolutePath(path) {
			return errMetricsRetentionRuntime
		}
	}
	for _, hash := range []string{p.InstallationSHA256, p.HostConfigSHA256, p.ComposeSHA256, p.HelperSHA256} {
		if !releaseDigest(hash) {
			return errMetricsRetentionRuntime
		}
	}
	for _, pair := range [][2]string{{p.Root, p.StateDirectory}, {p.Root, p.BackupDirectory}, {p.StateDirectory, p.BackupDirectory}} {
		if singleBackupContains(pair[0], pair[1]) || singleBackupContains(pair[1], pair[0]) {
			return errMetricsRetentionRuntime
		}
	}
	if !containsPath(p.BackupRequest.RecoveryDirectories, p.StateDirectory) {
		return errMetricsRetentionRuntime
	}
	return nil
}

func containsPath(paths []string, path string) bool {
	for _, value := range paths {
		if value == path {
			return true
		}
	}
	return false
}

func metricsRetentionPlan(ctx context.Context, p MetricsRetentionSpec) (singleBackupPlan, *Vault, error) {
	if validateMetricsRetentionSpec(p) != nil {
		return singleBackupPlan{}, nil, errMetricsRetentionRuntime
	}
	for _, item := range []struct{ path, hash string }{{p.InstallationFile, p.InstallationSHA256}, {p.HostConfigFile, p.HostConfigSHA256}, {p.ComposeFile, p.ComposeSHA256}, {p.HelperFile, p.HelperSHA256}} {
		a, err := hashTrustArtifact(ctx, item.path, 256<<20)
		if err != nil || a.SHA256 != item.hash {
			return singleBackupPlan{}, nil, errMetricsRetentionRuntime
		}
	}
	plan, err := planSingleBackup(ctx, p.BackupRequest, filepath.Join(p.BackupDirectory, "binding-check"))
	if err != nil || plan.spec.Root != p.Root || plan.spec.Instance != p.Instance || !plan.spec.MetricsLayers || plan.rawMetrics == nil || plan.config.Metrics.RawURL == "" || plan.config.DeploymentTrust.HelperFile != p.HelperFile || plan.bindings[p.HelperFile] != p.HelperSHA256 {
		return plan, nil, errMetricsRetentionRuntime
	}
	trust, err := loadDeploymentTrust(ctx, plan.config.DeploymentTrust)
	if err != nil || trust.release.manifest.Helper.SHA256 != p.HelperSHA256 {
		return plan, nil, errMetricsRetentionRuntime
	}
	v, err := OpenVault(plan.config.DeploymentTrust.VaultKeyFile, plan.config.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		return plan, nil, errMetricsRetentionRuntime
	}
	return plan, v, nil
}

// output is an immutable, private support directory, separate from state and
// backups. Installer/explicit host upgrade owns activating these system units.
func prepareMetricsRetentionRuntime(ctx context.Context, p MetricsRetentionSpec, output string) error {
	plan, v, err := metricsRetentionPlan(ctx, p)
	if err != nil || !snapshotAbsolutePath(output) || singleBackupContains(p.StateDirectory, output) || singleBackupContains(output, p.StateDirectory) || singleBackupContains(p.BackupDirectory, output) || singleBackupContains(output, p.BackupDirectory) {
		return errMetricsRetentionRuntime
	}
	if plan.config.Metrics.PolicyFile != filepath.Join(output, "policy.json") {
		return errMetricsRetentionRuntime
	}
	p.KeyID, p.Proof = v.active, ""
	p.Proof, err = metricsRetentionMAC(v, p.KeyID, "spec", p)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(p)
	service := []byte("[Unit]\nDescription=Webscan verified metrics retention coordinator\nAfter=network-online.target\n\n[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=540\nNoNewPrivileges=yes\nExecStart=" + strconv.Quote(p.HelperFile) + " control-v3 --action run-metrics-retention --source " + strconv.Quote(filepath.Join(output, "policy.json")) + "\n")
	timer := []byte("[Unit]\nDescription=Webscan metrics retention check\n\n[Timer]\nOnCalendar=*-*-* *:*:00\nAccuracySec=1s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n")
	return publishTrustFiles(ctx, output, map[string][]byte{"policy.json": raw, "retention.service": service, "retention.timer": timer})
}

func readMetricsRetentionRuntime(ctx context.Context, source string) (MetricsRetentionSpec, singleBackupPlan, *Vault, error) {
	var p MetricsRetentionSpec
	raw, err := readTrustData(source, true, 64<<10)
	if err != nil || singleDecode(raw, &p) != nil {
		return p, singleBackupPlan{}, nil, errMetricsRetentionRuntime
	}
	plan, v, err := metricsRetentionPlan(ctx, p)
	if err != nil {
		return p, plan, nil, err
	}
	proof := p.Proof
	p.Proof = ""
	expected, err := metricsRetentionMAC(v, p.KeyID, "spec", p)
	p.Proof = proof
	if err != nil || !hmac.Equal([]byte(proof), []byte(expected)) || plan.config.Metrics.PolicyFile != source {
		return p, plan, nil, errMetricsRetentionRuntime
	}
	return p, plan, v, nil
}

func runMetricsRetentionCommand(ctx context.Context, o Options, out io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return errSingleBackupHost
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	p, plan, v, err := readMetricsRetentionRuntime(ctx, o.Source)
	if err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return errMetricsRetentionRuntime
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil || binary != p.HelperFile {
		return errMetricsRetentionRuntime
	}
	s, err := Open(ctx, plan.config)
	if err != nil {
		return err
	}
	defer s.DB.Close()
	status, err := s.runMetricsRetentionRuntime(ctx, p, plan, v, newSingleInstaller())
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(status)
}

func (s *Store) metricsRetentionDesired(ctx context.Context, spec singleInstallSpec) (metricsRetentionTarget, error) {
	out := metricsRetentionTarget{RawHours: spec.RawMetricsHours, HistoryDays: spec.HistoryMetricsDays}
	var raw []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT version,payload FROM v3_settings WHERE id=1`).Scan(&out.Version, &raw); err != nil {
		return out, err
	}
	var root configurationValues
	if decodeConfigurationObject(raw, &root) != nil {
		return out, errMetricsRetentionRuntime
	}
	for _, field := range []struct {
		path     string
		min, max int
		value    *int
	}{{"monitoring.raw_hours", 24, 168, &out.RawHours}, {"monitoring.history_days", 1, 90, &out.HistoryDays}} {
		if value, ok := settingsPath(root, field.path); ok {
			if !(settingsField{Kind: "integer", Min: field.min, Max: field.max}).valid(value) {
				return out, errMetricsRetentionRuntime
			}
			*field.value, _ = strconv.Atoi(value.(json.Number).String())
		}
	}
	if out.RawHours < 24 || out.RawHours > 168 || out.HistoryDays < 1 || out.HistoryDays > 90 {
		return out, errMetricsRetentionRuntime
	}
	return out, nil
}

func metricsRetentionOverlay(spec singleInstallSpec, target metricsRetentionTarget) []byte {
	raw, _ := yaml.Marshal(map[string]any{"services": map[string]any{
		"metrics":     map[string]any{"command": []string{"-httpListenAddr=127.0.0.1:" + strconv.Itoa(spec.MetricsPort), "-storageDataPath=/storage", "-retentionPeriod=" + strconv.Itoa(target.HistoryDays) + "d"}},
		"metrics-raw": map[string]any{"command": []string{"-httpListenAddr=127.0.0.1:" + strconv.Itoa(spec.RawMetricsPort), "-storageDataPath=/storage", "-retentionPeriod=" + strconv.Itoa(target.RawHours) + "h"}},
	}})
	return raw
}

func metricsRetentionInstaller(i singleInstaller, spec singleInstallSpec, overlay string) singleInstaller {
	if overlay == "" {
		return i
	}
	base := i.run
	i.run = func(ctx context.Context, command string, args ...string) ([]byte, error) {
		if command == i.docker && len(args) >= 5 && args[0] == "compose" && args[1] == "--project-name" && args[2] == singleProject(spec.Root) && args[3] == "--file" && args[4] == filepath.Join(spec.Root, "compose.yaml") {
			next := append([]string{}, args[:5]...)
			next = append(next, "--file", overlay)
			args = append(next, args[5:]...)
		}
		return base(ctx, command, args...)
	}
	return i
}

// Boot and an operator's explicit stack start use the same authenticated
// pointer as maintenance. Never boot the base compose in the middle of apply.
func metricsRetentionActiveOverlay(p MetricsRetentionSpec, v *Vault) (string, error) {
	j, err := readMetricsRetentionJournal(p, v)
	if err != nil || j.Phase == "applying" {
		return "", errMetricsRetentionRuntime
	}
	if j.ID == "" {
		return "", nil
	}
	if j.Phase == "confirmed" {
		return j.Overlay, nil
	}
	return j.PreviousOverlay, nil
}

func metricsRetentionExpectedCommands(spec singleInstallSpec, overlay string) (map[string][]string, error) {
	target := metricsRetentionTarget{RawHours: spec.RawMetricsHours, HistoryDays: spec.HistoryMetricsDays}
	body := metricsRetentionOverlay(spec, target)
	if overlay != "" {
		var err error
		body, err = readTrustData(overlay, true, 64<<10)
		if err != nil {
			return nil, errMetricsRetentionRuntime
		}
	}
	var doc struct {
		Services map[string]struct{ Command []string }
	}
	if yaml.Unmarshal(body, &doc) != nil || len(doc.Services) != 2 {
		return nil, errMetricsRetentionRuntime
	}
	commands := map[string][]string{}
	for _, service := range []string{"metrics", "metrics-raw"} {
		command := doc.Services[service].Command
		port, suffix := spec.MetricsPort, "d"
		if service == "metrics-raw" {
			port, suffix = spec.RawMetricsPort, "h"
		}
		if len(command) != 3 || command[0] != "-httpListenAddr=127.0.0.1:"+strconv.Itoa(port) || command[1] != "-storageDataPath=/storage" || !strings.HasPrefix(command[2], "-retentionPeriod=") || !strings.HasSuffix(command[2], suffix) {
			return nil, errMetricsRetentionRuntime
		}
		n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(command[2], "-retentionPeriod="), suffix))
		if err != nil || service == "metrics" && (n < 1 || n > 90) || service == "metrics-raw" && (n < 24 || n > 168) {
			return nil, errMetricsRetentionRuntime
		}
		if service == "metrics" {
			target.HistoryDays = n
		} else {
			target.RawHours = n
		}
		commands[service] = command
	}
	if !bytes.Equal(body, metricsRetentionOverlay(spec, target)) {
		return nil, errMetricsRetentionRuntime
	}
	return commands, nil
}

func metricsRetentionCheckActual(ctx context.Context, i singleInstaller, spec singleInstallSpec, overlay string, services []string, required bool) error {
	if err := i.checkContainers(ctx, spec, services, required); err != nil {
		return errMetricsRetentionRuntime
	}
	commands, err := metricsRetentionExpectedCommands(spec, overlay)
	if err != nil {
		return err
	}
	for _, service := range services {
		if service != "metrics" && service != "metrics-raw" {
			return errMetricsRetentionRuntime
		}
		raw, err := i.compose(ctx, spec, "ps", "--all", "--quiet", service)
		id := strings.TrimSpace(string(raw))
		if err != nil {
			return errMetricsRetentionRuntime
		}
		if id == "" && !required {
			continue
		}
		raw, err = i.run(ctx, i.docker, "inspect", id)
		var containers []struct{ Config struct{ Cmd []string } }
		if err != nil || json.Unmarshal(raw, &containers) != nil || len(containers) != 1 || !reflect.DeepEqual(containers[0].Config.Cmd, commands[service]) {
			return errMetricsRetentionRuntime
		}
	}
	return nil
}

func metricsRetentionAtomicFile(directory, name string, raw []byte) error {
	d, err := trustDirectory(directory, true)
	if err != nil || filepath.Base(name) != name {
		return errMetricsRetentionRuntime
	}
	defer d.Close()
	temporary := ".retention-" + token()
	fd, err := unix.Openat(int(d.Fd()), temporary, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errMetricsRetentionRuntime
	}
	f := os.NewFile(uintptr(fd), temporary)
	defer func() { f.Close(); _ = unix.Unlinkat(int(d.Fd()), temporary, 0) }()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = unix.Renameat(int(d.Fd()), temporary, int(d.Fd()), name); err != nil {
		return err
	}
	return d.Sync()
}

func writeMetricsRetentionJournal(p MetricsRetentionSpec, v *Vault, j *metricsRetentionJournal) error {
	j.KeyID, j.Proof = v.active, ""
	proof, err := metricsRetentionMAC(v, j.KeyID, "journal", *j)
	if err != nil {
		return err
	}
	j.Proof = proof
	raw, _ := json.Marshal(j)
	return metricsRetentionAtomicFile(p.StateDirectory, "journal.json", raw)
}

func readMetricsRetentionJournal(p MetricsRetentionSpec, v *Vault) (metricsRetentionJournal, error) {
	var j metricsRetentionJournal
	path := filepath.Join(p.StateDirectory, "journal.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return j, nil
	}
	raw, err := readTrustData(path, true, 64<<10)
	if err != nil || singleDecode(raw, &j) != nil {
		return j, errMetricsRetentionRuntime
	}
	proof := j.Proof
	j.Proof = ""
	expected, err := metricsRetentionMAC(v, j.KeyID, "journal", j)
	j.Proof = proof
	policy, _ := json.Marshal(p)
	if err != nil || !hmac.Equal([]byte(proof), []byte(expected)) || j.Format != 1 || j.SpecSHA256 != digest(policy) || !releaseDigest(j.ID) || j.Overlay != filepath.Join(p.StateDirectory, j.ID+".yaml") || !releaseDigest(j.OverlaySHA256) || j.Target.RawHours < 24 || j.Target.RawHours > 168 || j.Target.HistoryDays < 1 || j.Target.HistoryDays > 90 || j.Target.Version <= 0 {
		return j, errMetricsRetentionRuntime
	}
	if j.Phase != "prepared" && j.Phase != "backed_up" && j.Phase != "applying" && j.Phase != "confirmed" && j.Phase != "canceled" {
		return j, errMetricsRetentionRuntime
	}
	for _, item := range []struct{ path, hash string }{{j.Overlay, j.OverlaySHA256}, {j.PreviousOverlay, j.PreviousSHA256}} {
		if item.path == "" && item.hash == "" {
			continue
		}
		if filepath.Dir(item.path) != p.StateDirectory || filepath.Ext(item.path) != ".yaml" || !releaseDigest(strings.TrimSuffix(filepath.Base(item.path), ".yaml")) || !releaseDigest(item.hash) {
			return j, errMetricsRetentionRuntime
		}
		body, err := readTrustData(item.path, true, 64<<10)
		if err != nil || digest(body) != item.hash {
			return j, errMetricsRetentionRuntime
		}
	}
	return j, nil
}

func (s *Store) runMetricsRetentionRuntime(ctx context.Context, p MetricsRetentionSpec, plan singleBackupPlan, v *Vault, installer singleInstaller) (status MetricsRetentionStatus, result error) {
	if p.BackupRequest.MetricsUpgrade != "" {
		installer = singleMetricsUpgradeInstaller(installer, plan.spec, p.ComposeFile, "")
	}
	status.State = "unknown"
	policyBytes, _ := json.Marshal(p)
	policyDigest := digest(policyBytes)
	defer func() {
		status.PolicySHA256 = policyDigest
		status.Observed = time.Now().UTC()
		reason := ""
		if result != nil {
			reason = errMetricsRetentionRuntime.Error()
			status.State = "failed"
		}
		details, _ := json.Marshal(status)
		op, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_, _ = s.DB.ExecContext(op, `INSERT INTO v3_role_status(role,instance,heartbeat,error,details) VALUES('metrics-retention',$1,clock_timestamp(),$2,$3) ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error,details=excluded.details`, p.Instance, reason, details)
	}()
	if validateMetricsRetentionSpec(p) != nil || plan.spec.Root != p.Root || !plan.spec.MetricsLayers || plan.rawMetrics == nil {
		return status, errMetricsRetentionRuntime
	}
	d, err := trustDirectory(p.StateDirectory, true)
	if err != nil {
		return status, errMetricsRetentionRuntime
	}
	defer d.Close()
	fd, err := unix.Openat(int(d.Fd()), "coordinator.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return status, errMetricsRetentionRuntime
	}
	lock := os.NewFile(uintptr(fd), "coordinator.lock")
	defer lock.Close()
	if !singlePrivateFile(lock) || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return status, errMetricsRetentionRuntime
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return status, err
	}
	defer conn.Close()
	var locked bool
	resource := "metrics-retention:" + p.Instance
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, resource).Scan(&locked); err != nil || !locked {
		return status, errMetricsRetentionRuntime
	}
	defer func() {
		op, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if _, err := conn.ExecContext(op, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, resource); err != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	target, err := s.metricsRetentionDesired(ctx, plan.spec)
	if err != nil {
		return status, err
	}
	status.Desired = &target
	j, err := readMetricsRetentionJournal(p, v)
	if err != nil {
		return status, err
	}
	if j.ID != "" {
		body, err := readTrustData(j.Overlay, true, 64<<10)
		if err != nil || !bytes.Equal(body, metricsRetentionOverlay(plan.spec, j.Target)) {
			return status, errMetricsRetentionRuntime
		}
	}
	previous, previousHash := "", ""
	if j.ID != "" {
		status.TaskID = j.ID
		if j.Phase == "confirmed" {
			checked := metricsRetentionInstaller(installer, plan.spec, j.Overlay)
			if err := metricsRetentionCheckActual(ctx, checked, plan.spec, j.Overlay, []string{"metrics", "metrics-raw"}, true); err != nil {
				return status, errMetricsRetentionRuntime
			}
			effective := j.Target
			status.Effective = &effective
			previous, previousHash = j.Overlay, j.OverlaySHA256
			if target.RawHours == j.Target.RawHours && target.HistoryDays == j.Target.HistoryDays {
				if singleHTTPHealth(ctx, plan.config.Metrics.QueryURL+"/health") != nil || singleHTTPHealth(ctx, plan.config.Metrics.RawURL+"/health") != nil {
					return status, errMetricsRetentionRuntime
				}
				status.State = "confirmed"
				return status, nil
			}
		} else if j.Phase != "applying" {
			previous, previousHash = j.PreviousOverlay, j.PreviousSHA256
			if j.Target != target {
				j.Phase = "canceled"
				if err := writeMetricsRetentionJournal(p, v, &j); err != nil {
					return status, err
				}
				previous, previousHash = j.PreviousOverlay, j.PreviousSHA256
				j = metricsRetentionJournal{}
			}
		}
	}
	if j.ID == "" || j.Phase == "confirmed" || j.Phase == "canceled" {
		current := metricsRetentionInstaller(installer, plan.spec, previous)
		if err := metricsRetentionCheckActual(ctx, current, plan.spec, previous, []string{"metrics", "metrics-raw"}, true); err != nil {
			return status, errMetricsRetentionRuntime
		}
		if previous == "" && target.RawHours == plan.spec.RawMetricsHours && target.HistoryDays == plan.spec.HistoryMetricsDays {
			if singleHTTPHealth(ctx, plan.config.Metrics.QueryURL+"/health") != nil || singleHTTPHealth(ctx, plan.config.Metrics.RawURL+"/health") != nil {
				return status, errMetricsRetentionRuntime
			}
			status.State, status.Effective = "confirmed", &target
			return status, nil
		}
		policy, _ := json.Marshal(p)
		j = metricsRetentionJournal{Format: 1, SpecSHA256: digest(policy), ID: token(), Phase: "prepared", Target: target, PreviousOverlay: previous, PreviousSHA256: previousHash}
		j.Overlay = filepath.Join(p.StateDirectory, j.ID+".yaml")
		body := metricsRetentionOverlay(plan.spec, target)
		j.OverlaySHA256 = digest(body)
		if err := metricsRetentionAtomicFile(p.StateDirectory, filepath.Base(j.Overlay), body); err != nil {
			return status, err
		}
		if err := writeMetricsRetentionJournal(p, v, &j); err != nil {
			return status, err
		}
	}
	status.TaskID = j.ID
	if j.Phase == "prepared" {
		backupPlan := plan
		backupPlan.output = filepath.Join(p.BackupDirectory, "metrics-retention-"+j.ID)
		if _, err := os.Lstat(backupPlan.output); err == nil {
			// A crash before receipt publication keeps its archive for inspection;
			// never adopt an uncommitted directory or overwrite it on retry.
			backupPlan.output += "-" + token()
		}
		receipt, err := s.backupSingle(ctx, backupPlan)
		if err != nil {
			return status, errMetricsRetentionRuntime
		}
		if _, err := verifySingleBackup(ctx, receipt.Directory, receipt.ManifestSHA256); err != nil {
			return status, errMetricsRetentionRuntime
		}
		j.Backup, j.Phase = &receipt, "backed_up"
		if err := writeMetricsRetentionJournal(p, v, &j); err != nil {
			return status, err
		}
	}
	if j.Backup == nil || !singleBackupContains(p.BackupDirectory, j.Backup.Directory) || j.Backup.Directory == p.BackupDirectory {
		return status, errMetricsRetentionRuntime
	}
	if _, err := verifySingleBackup(ctx, j.Backup.Directory, j.Backup.ManifestSHA256); err != nil {
		return status, errMetricsRetentionRuntime
	}
	if j.Phase == "backed_up" {
		latest, err := s.metricsRetentionDesired(ctx, plan.spec)
		if err != nil || latest != j.Target {
			return status, errMetricsRetentionRuntime
		}
		j.Phase = "applying"
		if err := writeMetricsRetentionJournal(p, v, &j); err != nil {
			return status, err
		}
	}
	if j.Phase != "applying" {
		return status, errMetricsRetentionRuntime
	}
	selected := metricsRetentionInstaller(installer, plan.spec, j.Overlay)
	if metricsRetentionCheckActual(ctx, selected, plan.spec, j.Overlay, []string{"metrics", "metrics-raw"}, true) != nil {
		old := metricsRetentionInstaller(installer, plan.spec, j.PreviousOverlay)
		// A lost response can leave either service at either authenticated hash.
		// Validate each independently before reissuing the same fixed target.
		for _, service := range []string{"metrics", "metrics-raw"} {
			if metricsRetentionCheckActual(ctx, selected, plan.spec, j.Overlay, []string{service}, false) != nil && metricsRetentionCheckActual(ctx, old, plan.spec, j.PreviousOverlay, []string{service}, false) != nil {
				return status, errMetricsRetentionRuntime
			}
		}
		if _, err := selected.compose(ctx, plan.spec, "up", "--detach", "--no-deps", "--force-recreate", "metrics", "metrics-raw"); err != nil {
			return status, errMetricsRetentionRuntime
		}
	}
	if err := metricsRetentionCheckActual(ctx, selected, plan.spec, j.Overlay, []string{"metrics", "metrics-raw"}, true); err != nil {
		return status, errMetricsRetentionRuntime
	}
	if singleHTTPHealth(ctx, plan.config.Metrics.QueryURL+"/health") != nil || singleHTTPHealth(ctx, plan.config.Metrics.RawURL+"/health") != nil {
		return status, errMetricsRetentionRuntime
	}
	j.Phase, j.ConfirmedAt = "confirmed", time.Now().UTC()
	if err := writeMetricsRetentionJournal(p, v, &j); err != nil {
		return status, err
	}
	status.State, status.Effective = "confirmed", &j.Target
	return status, nil
}
