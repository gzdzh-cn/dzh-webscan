package controlplane

// An upgrade changes the executing, signed helper and active backup inputs,
// never the original schedule bytes or its database policy identity.
import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"time"

	"webscan/internal/deploy"
	"webscan/internal/progress"
)

var errSingleBackupUpgrade = errors.New("备份维护升级资料或数据库绑定校验失败；保留原策略、签名程序、安装记录及密钥，不自动迁移数据库或启动定时器")

type singleBackupUpgradeSpec struct {
	Format       int              `json:"format"`
	ScheduleFile string           `json:"schedule_file"`
	Backup       singleBackupSpec `json:"backup"`
}

type singleBackupUpgradeManifest struct {
	Format          int                     `json:"format"`
	Directory       string                  `json:"directory"`
	Schema          int                     `json:"schema_version"`
	Spec            singleBackupUpgradeSpec `json:"request"`
	ScheduleSHA256  string                  `json:"schedule_sha256"`
	InstallationSHA string                  `json:"installation_sha256"`
	Instance        string                  `json:"instance"`
	Root            string                  `json:"root"`
	BackupDirectory string                  `json:"backup_directory"`
	Keep            int                     `json:"keep"`
	Helper          string                  `json:"helper_file"`
	HelperSHA256    string                  `json:"helper_sha256"`
	Release         string                  `json:"release"`
	ReleaseSHA256   string                  `json:"release_manifest_sha256"`
	Dependencies    map[string]string       `json:"dependencies"`
	Files           map[string]string       `json:"files"`
	KeyID           string                  `json:"key_id"`
	Proof           string                  `json:"proof"`
}

func singleBackupUpgradeProof(v *Vault, m singleBackupUpgradeManifest) (string, error) {
	if v == nil || len(v.receiptKeys[m.KeyID]) == 0 {
		return "", errSingleBackupUpgrade
	}
	m.Proof = ""
	raw, err := json.Marshal(m)
	if err != nil {
		return "", errSingleBackupUpgrade
	}
	h := hmac.New(sha256.New, v.receiptKeys[m.KeyID])
	h.Write([]byte("webscan-v3/single-backup-upgrade/v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func singleBackupUpgradeUnits(helper, source string) ([]byte, []byte) {
	service := []byte("[Unit]\nDescription=Webscan upgraded consistent single-center backup\nAfter=network-online.target\n\n[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=360\nNoNewPrivileges=yes\nNice=10\nIOSchedulingClass=best-effort\nIOSchedulingPriority=7\nExecStart=" + strconv.Quote(helper) + " control-v3 --action run-single-backup-upgrade --source " + strconv.Quote(source) + "\n")
	timer := []byte("[Unit]\nDescription=Webscan upgraded backup schedule check\n\n[Timer]\nOnCalendar=*-*-* *:*:00\nAccuracySec=1s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n")
	return service, timer
}

func planSingleBackupUpgrade(ctx context.Context, request singleBackupUpgradeSpec, output string) (singleBackupSchedule, singleBackupPlan, singleBackupPlan, []byte, error) {
	var p singleBackupSchedule
	var old, next singleBackupPlan
	if request.Format != 1 || !singlePKIUpgradePath(request.ScheduleFile) || !singlePKIUpgradePath(output) {
		return p, old, next, nil, errSingleBackupUpgrade
	}
	p, old, raw, err := readSingleBackupSchedule(ctx, request.ScheduleFile, "", "")
	if err != nil || request.Backup.Installation != old.request.Installation {
		return p, old, next, nil, errSingleBackupUpgrade
	}
	next, err = planSingleBackup(ctx, request.Backup, filepath.Join(p.Spec.Directory, "binding-check"))
	metricsCompatible := reflect.DeepEqual(next.rawMetrics, old.rawMetrics)
	if !metricsCompatible && err == nil && old.rawMetrics == nil && next.rawMetrics != nil && request.Backup.MetricsUpgrade != "" {
		u, e := readSingleMetricsUpgrade(ctx, request.Backup.MetricsUpgrade)
		if e == nil {
			_, bridge, bridgeErr := singleMetricsUpgradeOriginalSchedule(ctx, u.Request)
			metricsCompatible = bridgeErr == nil && reflect.DeepEqual(bridge.request, old.request) && u.InstallationSHA256 == old.installation
		}
	}
	if err != nil || next.spec.Root != old.spec.Root || next.spec.Instance != old.spec.Instance || next.installation != old.installation || next.config.Central.Instance != old.config.Central.Instance || next.config.Central.Instance != old.spec.Instance || next.config.DeploymentTrust.VaultKeyFile != old.config.DeploymentTrust.VaultKeyFile || !reflect.DeepEqual(next.config.DeploymentTrust.PreviousKeyFiles, old.config.DeploymentTrust.PreviousKeyFiles) || next.config.NodePKI.AuthorityDirectory != old.config.NodePKI.AuthorityDirectory || !reflect.DeepEqual(next.metrics, old.metrics) || !metricsCompatible {
		return p, old, next, nil, errSingleBackupUpgrade
	}
	for _, path := range []string{old.spec.Root, p.Spec.Directory, request.ScheduleFile, next.config.DeploymentTrust.HelperFile} {
		if singleBackupContains(path, output) || singleBackupContains(output, path) {
			return p, old, next, nil, errSingleBackupUpgrade
		}
	}
	for _, plan := range []singleBackupPlan{old, next} {
		for _, source := range plan.sources {
			if singleBackupContains(source.Path, output) || singleBackupContains(output, source.Path) {
				return p, old, next, nil, errSingleBackupUpgrade
			}
		}
	}
	return p, old, next, raw, nil
}

func singleBackupUpgradeFiles(ctx context.Context, request singleBackupUpgradeSpec, output string) (map[string][]byte, error) {
	p, old, next, raw, err := planSingleBackupUpgrade(ctx, request, output)
	if err != nil {
		return nil, err
	}
	trust, err := loadDeploymentTrust(ctx, next.config.DeploymentTrust)
	if err != nil {
		return nil, errSingleBackupUpgrade
	}
	m := singleBackupUpgradeManifest{Format: 1, Directory: output, Schema: SchemaVersion, Spec: request, ScheduleSHA256: digest(raw), InstallationSHA: old.installation, Instance: old.spec.Instance, Root: old.spec.Root, BackupDirectory: p.Spec.Directory, Keep: p.Spec.Keep, Helper: next.config.DeploymentTrust.HelperFile, HelperSHA256: trust.release.manifest.Helper.SHA256, Release: trust.release.manifest.Release, ReleaseSHA256: trust.release.SHA256(), Dependencies: map[string]string{}, Files: map[string]string{}, KeyID: trust.vault.active}
	for _, plan := range []singleBackupPlan{old, next} {
		for path, hash := range plan.bindings {
			if prior := m.Dependencies[path]; prior != "" && prior != hash {
				return nil, errSingleBackupUpgrade
			}
			m.Dependencies[path] = hash
		}
	}
	m.Dependencies[request.ScheduleFile] = m.ScheduleSHA256
	service, timer := singleBackupUpgradeUnits(m.Helper, filepath.Join(output, "upgrade.json"))
	files := map[string][]byte{"backup.service": service, "backup.timer": timer}
	for name, data := range files {
		m.Files[name] = digest(data)
	}
	m.Proof, err = singleBackupUpgradeProof(trust.vault, m)
	if err != nil {
		return nil, err
	}
	files["upgrade.json"], err = json.Marshal(m)
	if err != nil {
		return nil, errSingleBackupUpgrade
	}
	return files, nil
}

func readSingleBackupUpgrade(ctx context.Context, source, executable, executingRelease string) (singleBackupSchedule, singleBackupPlan, singleBackupPlan, []byte, singleBackupUpgradeManifest, error) {
	var m singleBackupUpgradeManifest
	var p singleBackupSchedule
	var old, next singleBackupPlan
	raw, err := readTrustData(source, true, 512<<10)
	if err != nil || singleDecode(raw, &m) != nil || m.Format != 1 || m.Schema != SchemaVersion || !singlePKIUpgradePath(m.Directory) || source != filepath.Join(m.Directory, "upgrade.json") || len(m.Dependencies) > 4096 || len(m.Files) != 2 {
		return p, old, next, nil, m, errSingleBackupUpgrade
	}
	directory, err := trustDirectory(m.Directory, true)
	if err != nil {
		return p, old, next, nil, m, errSingleBackupUpgrade
	}
	directory.Close()
	p, old, next, policyRaw, err := planSingleBackupUpgrade(ctx, m.Spec, m.Directory)
	if err != nil {
		return p, old, next, nil, m, errSingleBackupUpgrade
	}
	v, err := OpenVault(old.config.DeploymentTrust.VaultKeyFile, old.config.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		return p, old, next, nil, m, errSingleBackupUpgrade
	}
	proof, err := singleBackupUpgradeProof(v, m)
	if err != nil || !hmac.Equal([]byte(proof), []byte(m.Proof)) {
		return p, old, next, nil, m, errSingleBackupUpgrade
	}
	// Regenerate expected bindings from authenticated source bytes. Historical
	// Vault receipt keys remain valid without rewriting an immutable overlay.
	expectedFiles, err := singleBackupUpgradeFiles(ctx, m.Spec, m.Directory)
	var expected singleBackupUpgradeManifest
	if err != nil || singleDecode(expectedFiles["upgrade.json"], &expected) != nil {
		return p, old, next, nil, m, errSingleBackupUpgrade
	}
	expected.KeyID, expected.Proof = m.KeyID, m.Proof
	if !reflect.DeepEqual(expected, m) {
		return p, old, next, nil, m, errSingleBackupUpgrade
	}
	for _, name := range []string{"backup.service", "backup.timer"} {
		actual, e := readTrustData(filepath.Join(m.Directory, name), true, 64<<10)
		if e != nil || !bytes.Equal(actual, expectedFiles[name]) || digest(actual) != m.Files[name] {
			return p, old, next, nil, m, errSingleBackupUpgrade
		}
	}
	if executable != "" {
		actual, e := filepath.EvalSymlinks(executable)
		if e != nil || actual != m.Helper || !releaseVersion.MatchString(executingRelease) || executingRelease != m.Release {
			return p, old, next, nil, m, errSingleBackupUpgrade
		}
		helper, e := hashTrustArtifact(ctx, actual, 256<<20)
		if e != nil || helper.SHA256 != m.HelperSHA256 {
			return p, old, next, nil, m, errSingleBackupUpgrade
		}
	}
	// A restored overlay must still be able to authenticate the original
	// policy's helper/configuration, including external format-2 material.
	// Merge only already-validated, explicit sources, never a common parent.
	files, directories := []string{m.Spec.ScheduleFile}, []string{m.Directory}
	for _, plan := range []singleBackupPlan{old, next} {
		for _, item := range plan.sources {
			if item.Directory {
				directories = append(directories, item.Path)
			} else {
				files = append(files, item.Path)
			}
		}
	}
	next.sources, err = normalizeSingleBackupSources(next.spec.Root, files, directories, next.output)
	if err != nil {
		return p, old, next, nil, m, errSingleBackupUpgrade
	}
	next.bindings = make(map[string]string, len(m.Dependencies)+3)
	for path, hash := range m.Dependencies {
		next.bindings[path] = hash
	}
	next.bindings[source] = digest(raw)
	for name, hash := range m.Files {
		next.bindings[filepath.Join(m.Directory, name)] = hash
	}
	return p, old, next, policyRaw, m, nil
}

func singleBackupUpgradeDatabaseIdentity(ctx context.Context, db *sql.DB) (string, error) {
	var database, schema, server, cluster string
	var port int
	err := db.QueryRowContext(ctx, `SELECT current_database(),current_schema(),COALESCE(inet_server_addr()::text,'local-socket'),COALESCE(inet_server_port(),current_setting('port')::integer),(SELECT payload::text FROM v3_cluster WHERE id=1)`).Scan(&database, &schema, &server, &port, &cluster)
	if err != nil || database == "" || schema == "" || cluster == "" {
		return "", errSingleBackupUpgrade
	}
	raw, _ := json.Marshal([]any{server, port, database, schema, cluster})
	return digest(raw), nil
}

func checkSingleBackupUpgradeStore(ctx context.Context, old, next singleBackupPlan, raw []byte) (*Store, bool, error) {
	previous, err := Open(ctx, old.config)
	if err != nil {
		return nil, false, errSingleBackupUpgrade
	}
	defer previous.DB.Close()
	current, err := Open(ctx, next.config)
	if err != nil {
		return nil, false, errSingleBackupUpgrade
	}
	fail := func() (*Store, bool, error) { current.DB.Close(); return nil, false, errSingleBackupUpgrade }
	for _, s := range []*Store{previous, current} {
		version, err := currentSchema(ctx, s.DB)
		if err != nil || version != SchemaVersion {
			return fail()
		}
	}
	before, err := singleBackupUpgradeDatabaseIdentity(ctx, previous.DB)
	if err != nil {
		return fail()
	}
	after, err := singleBackupUpgradeDatabaseIdentity(ctx, current.DB)
	if err != nil || before != after {
		return fail()
	}
	var saved []byte
	var hash string
	var enabled bool
	if err = current.DB.QueryRowContext(ctx, `SELECT sha256,policy,enabled FROM v3_single_backup_policies WHERE instance=$1`, old.spec.Instance).Scan(&hash, &saved, &enabled); err != nil || hash != digest(raw) {
		return fail()
	}
	var actual, expected singleBackupSchedule
	if singleDecode(saved, &actual) != nil || singleDecode(raw, &expected) != nil || !reflect.DeepEqual(actual, expected) {
		return fail()
	}
	return current, enabled, nil
}

func enableSingleBackupUpgradePolicy(ctx context.Context, s *Store, instance string, raw []byte) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE v3_single_backup_policies SET enabled=true WHERE instance=$1 AND sha256=$2`, instance, digest(raw))
	if err != nil {
		return errSingleBackupUpgrade
	}
	count, err := res.RowsAffected()
	if err != nil || count != 1 {
		return errSingleBackupUpgrade
	}
	return nil
}

func singleBackupUpgradeCommand(ctx context.Context, o Options, out io.Writer) (result error) {
	defer func() {
		if result != nil {
			result = &progress.Failure{Code: "single_backup_upgrade_failed", Message: errSingleBackupUpgrade.Error()}
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if o.Action == "preview-single-backup-upgrade" || o.Action == "prepare-single-backup-upgrade" {
		var request singleBackupUpgradeSpec
		raw, err := readTrustData(o.Source, true, 64<<10)
		if err != nil || singleDecode(raw, &request) != nil {
			return errSingleBackupUpgrade
		}
		files, err := singleBackupUpgradeFiles(ctx, request, o.Output)
		if err != nil {
			return err
		}
		state := "preview"
		if o.Action == "prepare-single-backup-upgrade" {
			if err = publishTrustFiles(ctx, o.Output, files); err != nil {
				return errSingleBackupUpgrade
			}
			state = "prepared"
		}
		return json.NewEncoder(out).Encode(map[string]any{"state": state, "directory": o.Output, "schema_version": SchemaVersion, "database_checked": false, "activated": false, "policy_unchanged": true, "immutable_installation_unchanged": true})
	}
	if o.Action != "check-single-backup-upgrade" && o.Action != "run-single-backup-upgrade" && o.Action != "enable-single-backup-upgrade" || o.Output != "" {
		return errSingleBackupUpgrade
	}
	if o.Action != "check-single-backup-upgrade" && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0) {
		return errSingleBackupHost
	}
	executable, err := os.Executable()
	if err != nil {
		return errSingleBackupUpgrade
	}
	p, old, next, raw, manifest, err := readSingleBackupUpgrade(ctx, o.Source, executable, deploy.Release)
	if err != nil {
		return err
	}
	s, enabled, err := checkSingleBackupUpgradeStore(ctx, old, next, raw)
	if err != nil {
		return err
	}
	defer s.DB.Close()
	if o.Action == "check-single-backup-upgrade" {
		return json.NewEncoder(out).Encode(map[string]any{"state": "verified", "schema_version": SchemaVersion, "release_manifest_sha256": manifest.ReleaseSHA256, "database_checked": true, "policy_enabled": enabled, "policy_unchanged": true, "activated": false})
	}
	if o.Action == "enable-single-backup-upgrade" {
		if err := enableSingleBackupUpgradePolicy(ctx, s, old.spec.Instance, raw); err != nil {
			return errSingleBackupUpgrade
		}
		return json.NewEncoder(out).Encode(map[string]any{"state": "enabled", "activated": false, "policy_unchanged": true})
	}
	r, err := s.runSingleBackupScheduleMode(ctx, p, next, raw, true)
	if encode := json.NewEncoder(out).Encode(r); encode != nil {
		return encode
	}
	return err
}
