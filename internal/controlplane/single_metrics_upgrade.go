package controlplane

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var errSingleMetricsUpgrade = errors.New("单库到双库升级资料、备份或运行证据不完整；原安装、数据库、历史指标和密钥保持保留，请使用原任务继续")

type singleMetricsUpgradeSpec struct {
	Format                 int              `json:"format"`
	Backup                 singleBackupSpec `json:"backup"`
	StateDirectory         string           `json:"state_directory"`
	BackupDirectory        string           `json:"backup_directory"`
	BackupSchedule         string           `json:"backup_schedule,omitempty"`
	BackupUpgradeDirectory string           `json:"backup_upgrade_directory,omitempty"`
	RawMetricsPort         int              `json:"raw_metrics_port"`
	RawMetricsHours        int              `json:"raw_metrics_hours"`
	HistoryMetricsDays     int              `json:"history_metrics_days"`
}

// Effective describes a separate overlay, never a replacement install.json.
// Dependencies authenticate the untouched old configuration and trust material.
type singleMetricsUpgradeManifest struct {
	Format             int                      `json:"format"`
	Schema             int                      `json:"schema_version"`
	Directory          string                   `json:"directory"`
	InstallationSHA256 string                   `json:"installation_sha256"`
	Request            singleMetricsUpgradeSpec `json:"request"`
	Effective          singleInstallSpec        `json:"effective"`
	HelperFile         string                   `json:"helper_file"`
	HelperSHA256       string                   `json:"helper_sha256"`
	Release            string                   `json:"release"`
	Dependencies       map[string]string        `json:"dependencies"`
	PreviousSources    []singleBackupSource     `json:"previous_recovery_sources,omitempty"`
	Files              map[string]string        `json:"files"`
	KeyID              string                   `json:"key_id"`
	Proof              string                   `json:"proof"`
}

func singleMetricsUpgradeProof(v *Vault, m singleMetricsUpgradeManifest) (string, error) {
	m.Proof = ""
	return metricsRetentionMAC(v, m.KeyID, "single-to-dual-overlay", m)
}

// Authenticate a new signed helper/configuration against the immutable old
// backup policy, using the same identity and material checks as maintenance
// upgrades. The schedule itself and its original recovery material remain.
func singleMetricsUpgradeOriginalSchedule(ctx context.Context, r singleMetricsUpgradeSpec) (singleBackupSchedule, singleBackupPlan, error) {
	p, old, _, _, err := planSingleBackupUpgrade(ctx, singleBackupUpgradeSpec{Format: 1, ScheduleFile: r.BackupSchedule, Backup: r.Backup}, r.BackupUpgradeDirectory)
	if err != nil {
		return p, old, errSingleMetricsUpgrade
	}
	return p, old, nil
}

func planSingleMetricsUpgrade(ctx context.Context, request singleMetricsUpgradeSpec, output string) (singleBackupPlan, singleInstallSpec, error) {
	var empty singleBackupPlan
	var effective singleInstallSpec
	if request.Format != 1 || !singlePKIUpgradePath(output) || !singlePKIUpgradePath(request.StateDirectory) || !singlePKIUpgradePath(request.BackupDirectory) {
		return empty, effective, errSingleMetricsUpgrade
	}
	// The old plan is independently authenticated. No nested upgrade may be
	// used to launder an already transformed installation into another task.
	if request.Backup.MetricsUpgrade != "" {
		return empty, effective, errSingleMetricsUpgrade
	}
	p, e := planSingleBackup(ctx, request.Backup, filepath.Join(request.BackupDirectory, "binding-check"))
	if e != nil || p.spec.MetricsLayers || p.spec.MetricsRetention || p.config.Metrics.RawURL != "" || p.config.Metrics.PolicyFile != "" || request.HistoryMetricsDays != p.spec.historyDays() {
		return empty, effective, errSingleMetricsUpgrade
	}
	if (request.BackupSchedule == "") != (request.BackupUpgradeDirectory == "") {
		return empty, effective, errSingleMetricsUpgrade
	}
	if request.BackupSchedule != "" {
		if !singlePKIUpgradePath(request.BackupSchedule) || !singlePKIUpgradePath(request.BackupUpgradeDirectory) {
			return empty, effective, errSingleMetricsUpgrade
		}
		_, old, err := singleMetricsUpgradeOriginalSchedule(ctx, request)
		if err != nil || old.installation != p.installation {
			return empty, effective, errSingleMetricsUpgrade
		}
	}
	for _, a := range []string{output, request.StateDirectory, request.BackupDirectory, singleMetricsStateDirectory(p.spec)} {
		for _, b := range []string{p.spec.Root, request.Backup.Installation, request.Backup.HostConfig, request.Backup.APIConfig, request.Backup.ComposeFile} {
			if singleBackupContains(a, b) || singleBackupContains(b, a) {
				return empty, effective, errSingleMetricsUpgrade
			}
		}
	}
	paths := []string{output, request.StateDirectory, request.BackupDirectory, singleMetricsStateDirectory(p.spec)}
	if request.BackupUpgradeDirectory != "" {
		paths = append(paths, request.BackupUpgradeDirectory)
	}
	for _, path := range paths {
		if singleBackupContains(p.spec.Root, path) || singleBackupContains(path, p.spec.Root) {
			return empty, effective, errSingleMetricsUpgrade
		}
	}
	for i, a := range paths {
		for _, b := range paths[i+1:] {
			if singleBackupContains(a, b) || singleBackupContains(b, a) {
				return empty, effective, errSingleMetricsUpgrade
			}
		}
	}
	for _, source := range p.sources {
		for _, path := range paths {
			if singleBackupContains(source.Path, path) || singleBackupContains(path, source.Path) {
				return empty, effective, errSingleMetricsUpgrade
			}
		}
	}
	effective = p.spec
	effective.Format, effective.MetricsLayers, effective.MetricsRetention = 3, true, true
	effective.RawMetricsPort, effective.RawMetricsHours, effective.HistoryMetricsDays = request.RawMetricsPort, request.RawMetricsHours, request.HistoryMetricsDays
	trust := p.config.DeploymentTrust
	effective.ReleaseTrust, effective.RulesFile = &trust, p.config.Executor.RulesFile
	if effective.validate() != nil || effective.RawMetricsPort != request.RawMetricsPort || effective.RawMetricsHours != request.RawMetricsHours {
		return empty, effective, errSingleMetricsUpgrade
	}
	return p, effective, nil
}

func singleMetricsUpgradeFiles(ctx context.Context, request singleMetricsUpgradeSpec, output string) (map[string][]byte, singleMetricsUpgradeManifest, error) {
	p, effective, e := planSingleMetricsUpgrade(ctx, request, output)
	var m singleMetricsUpgradeManifest
	if e != nil {
		return nil, m, e
	}
	trust, e := loadDeploymentTrust(ctx, p.config.DeploymentTrust)
	if e != nil {
		return nil, m, errSingleMetricsUpgrade
	}
	host := p.config
	apiRaw, e := readTrustData(request.Backup.APIConfig, true, 2<<20)
	if e != nil {
		return nil, m, errSingleMetricsUpgrade
	}
	api, e := decodeSingleBackupConfig(apiRaw)
	if e != nil {
		return nil, m, errSingleMetricsUpgrade
	}
	for _, c := range []*Config{&host, &api} {
		c.Metrics.RawURL = effective.configuration().Metrics.RawURL
		c.Metrics.PolicyFile = effective.configuration().Metrics.PolicyFile
		if c.Validate() != nil {
			return nil, m, errSingleMetricsUpgrade
		}
	}
	composeRaw, e := readTrustData(request.Backup.ComposeFile, true, 2<<20)
	var compose map[string]any
	if e != nil || yaml.Unmarshal(composeRaw, &compose) != nil {
		return nil, m, errSingleMetricsUpgrade
	}
	services, ok := compose["services"].(map[string]any)
	if !ok || len(services) != 3 {
		return nil, m, errSingleMetricsUpgrade
	}
	metrics, ok := services["metrics"].(map[string]any)
	if !ok || metrics["image"] != effective.MetricsImage || metrics["network_mode"] != "host" {
		return nil, m, errSingleMetricsUpgrade
	}
	central, ok := services["central"].(map[string]any)
	if !ok || central["network_mode"] != "host" {
		return nil, m, errSingleMetricsUpgrade
	}
	image, ok := central["image"].(string)
	if !ok {
		return nil, m, errSingleMetricsUpgrade
	}
	effective.RuntimeImage = image
	if effective.validate() != nil {
		return nil, m, errSingleMetricsUpgrade
	}
	// Decode a generated raw service independently. The old PG/history service
	// maps remain byte-equivalent in meaning; neither is recreated by apply.
	var generated map[string]any
	if yaml.Unmarshal(singleCompose(effective, "unused"), &generated) != nil {
		return nil, m, errSingleMetricsUpgrade
	}
	rawVM := generated["services"].(map[string]any)["metrics-raw"].(map[string]any)
	rawVM["labels"] = metrics["labels"]
	services["metrics-raw"] = rawVM
	central["command"] = []string{"control-v3", "--config", filepath.Join(output, "config.yaml"), "--action", "run", "--role", "all"}
	volumes, ok := central["volumes"].([]any)
	if !ok {
		return nil, m, errSingleMetricsUpgrade
	}
	for _, path := range []string{filepath.Join(output, "config.yaml"), filepath.Join(effective.Root, "metrics-support")} {
		volumes = append(volumes, map[string]any{"type": "bind", "source": path, "target": path, "read_only": true, "bind": map[string]any{"create_host_path": false}})
	}
	central["volumes"] = volumes
	files := map[string][]byte{}
	files["config.yaml"], _ = yaml.Marshal(api)
	files["executor.yaml"], _ = yaml.Marshal(host)
	files["compose.yaml"], _ = yaml.Marshal(compose)
	files["stack.service"] = []byte("[Unit]\nDescription=Webscan explicit upgraded single-center metrics stack\nRequires=docker.service\nAfter=docker.service network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nUMask=0077\nTimeoutStartSec=180\nExecStart=" + strconv.Quote(p.config.DeploymentTrust.HelperFile) + " control-v3 --action start-single-metrics-upgrade-stack --source " + strconv.Quote(filepath.Join(output, "upgrade.json")) + "\n\n[Install]\nWantedBy=multi-user.target\n")
	m = singleMetricsUpgradeManifest{Format: 1, Schema: SchemaVersion, Directory: output, InstallationSHA256: p.installation, Request: request, Effective: effective, HelperFile: p.config.DeploymentTrust.HelperFile, HelperSHA256: trust.release.manifest.Helper.SHA256, Release: trust.release.manifest.Release, Dependencies: p.bindings, Files: map[string]string{}, KeyID: trust.vault.active}
	if request.BackupSchedule != "" {
		raw, err := readTrustData(request.BackupSchedule, true, 64<<10)
		if err != nil {
			return nil, m, errSingleMetricsUpgrade
		}
		m.Dependencies[request.BackupSchedule] = digest(raw)
		_, old, err := singleMetricsUpgradeOriginalSchedule(ctx, request)
		if err != nil {
			return nil, m, errSingleMetricsUpgrade
		}
		m.PreviousSources = old.sources
		for path, hash := range old.bindings {
			if previous, ok := m.Dependencies[path]; ok && previous != hash {
				return nil, m, errSingleMetricsUpgrade
			}
			m.Dependencies[path] = hash
		}
	}
	for name, data := range files {
		m.Files[name] = digest(data)
	}
	m.Proof, e = singleMetricsUpgradeProof(trust.vault, m)
	if e != nil {
		return nil, m, errSingleMetricsUpgrade
	}
	files["upgrade.json"], _ = json.Marshal(m)
	return files, m, nil
}

func readSingleMetricsUpgrade(ctx context.Context, source string) (singleMetricsUpgradeManifest, error) {
	var m singleMetricsUpgradeManifest
	raw, e := readTrustData(source, true, 512<<10)
	if e != nil || singleDecode(raw, &m) != nil || m.Format != 1 || m.Schema != SchemaVersion || source != filepath.Join(m.Directory, "upgrade.json") || len(m.Files) != 4 || len(m.Dependencies) > 4096 {
		return m, errSingleMetricsUpgrade
	}
	files, expected, e := singleMetricsUpgradeFiles(ctx, m.Request, m.Directory)
	if e != nil {
		return m, errSingleMetricsUpgrade
	}
	p, _, e := planSingleMetricsUpgrade(ctx, m.Request, m.Directory)
	if e != nil {
		return m, errSingleMetricsUpgrade
	}
	v, e := OpenVault(p.config.DeploymentTrust.VaultKeyFile, p.config.DeploymentTrust.PreviousKeyFiles...)
	if e != nil {
		return m, errSingleMetricsUpgrade
	}
	proof, e := singleMetricsUpgradeProof(v, m)
	if e != nil || !hmac.Equal([]byte(proof), []byte(m.Proof)) {
		return m, errSingleMetricsUpgrade
	}
	expected.KeyID, expected.Proof = m.KeyID, m.Proof
	if !reflect.DeepEqual(expected, m) {
		return m, errSingleMetricsUpgrade
	}
	for name, hash := range m.Files {
		actual, e := readTrustData(filepath.Join(m.Directory, name), true, 2<<20)
		if e != nil || !bytes.Equal(actual, files[name]) || digest(actual) != hash {
			return m, errSingleMetricsUpgrade
		}
	}
	return m, nil
}

func singleMetricsUpgradeCommand(ctx context.Context, o Options, out io.Writer) error {
	if o.Action == "preview-single-metrics-upgrade" || o.Action == "prepare-single-metrics-upgrade" {
		var request singleMetricsUpgradeSpec
		raw, e := readTrustData(o.Source, true, 64<<10)
		if e != nil || singleDecode(raw, &request) != nil {
			return errSingleMetricsUpgrade
		}
		files, m, e := singleMetricsUpgradeFiles(ctx, request, o.Output)
		if e != nil {
			return e
		}
		state := "preview"
		if o.Action == "prepare-single-metrics-upgrade" {
			if e = publishTrustFiles(ctx, o.Output, files); e != nil {
				return errSingleMetricsUpgrade
			}
			state = "prepared"
		}
		return json.NewEncoder(out).Encode(map[string]any{"state": state, "raw_url": fmt.Sprintf("http://127.0.0.1:%d", m.Effective.RawMetricsPort), "history_days": m.Effective.historyDays(), "immutable_installation_unchanged": true, "production_changed": false, "application_restart_required": true})
	}
	if strings.HasPrefix(o.Action, "run-single-metrics-upgrade") || o.Action == "resume-single-metrics-upgrade" || o.Action == "start-single-metrics-upgrade-stack" {
		return runSingleMetricsUpgradeCommand(ctx, o, out)
	}
	return errSingleMetricsUpgrade
}
