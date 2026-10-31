package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"webscan/internal/nodepki"
)

// The host-local request pins the existing runtime and optional signed PKI
// overlay. Additional private recovery directories are explicit; no public API
// accepts this request or an arbitrary host path.
type singleBackupSpec struct {
	Format              int      `json:"format"`
	Installation        string   `json:"installation"`
	HostConfig          string   `json:"host_config"`
	APIConfig           string   `json:"api_config"`
	ComposeFile         string   `json:"compose_file"`
	PKIMaintenance      string   `json:"pki_maintenance,omitempty"`
	RecoveryDirectories []string `json:"recovery_directories,omitempty"`
}

type singleBackupPlan struct {
	spec         singleInstallSpec
	config       Config
	metrics      metricsSnapshotStore
	sources      []singleBackupSource
	installation string
	request      singleBackupSpec
	output       string
	bindings     map[string]string
}

type singleBackupManifest struct {
	Format       int                   `json:"format"`
	Instance     string                `json:"instance"`
	Schema       int                   `json:"schema_version"`
	Installation string                `json:"installation_sha256"`
	Started      time.Time             `json:"started_at"`
	Completed    time.Time             `json:"completed_at"`
	Sources      []singleBackupSource  `json:"host_sources"`
	Modes        []singleBackupMode    `json:"host_file_modes"`
	Directories  []string              `json:"directories"`
	Files        []metricsSnapshotFile `json:"files"`
	Postgres     string                `json:"postgres_archive"`
	Metrics      string                `json:"metrics_manifest_sha256"`
	// Engine snapshots are taken within a recorded interval, not a fictional
	// cross-engine ACID timestamp. DR activation requires separate epoch and
	// latest-retirement reconciliation; this archive never authorizes cutover.
	Consistency string `json:"consistency"`
}

type singleBackupReceipt struct {
	State           string `json:"state"`
	Directory       string `json:"directory"`
	ManifestSHA256  string `json:"manifest_sha256"`
	Files           int    `json:"files"`
	Bytes           int64  `json:"bytes"`
	RuntimeStarted  bool   `json:"runtime_started"`
	RestoreTested   bool   `json:"isolated_restore_validated"`
	PendingSnapshot string `json:"pending_temporary_snapshot,omitempty"`
}

func planSingleBackup(ctx context.Context, request singleBackupSpec, output string) (singleBackupPlan, error) {
	var empty singleBackupPlan
	if request.Format != 1 || len(request.RecoveryDirectories) > 32 {
		return empty, errSingleBackup
	}
	m, raw, j, err := singlePKIUpgradeInstallation(request.Installation)
	if err != nil || j.Step != 6 || m.Spec.Format < 2 {
		return empty, errSingleBackup
	}
	metrics, err := metricsSnapshotInstallation(Options{Source: request.Installation, Config: request.HostConfig})
	if err != nil {
		return empty, errSingleBackup
	}
	parsedHashes := map[string]string{}
	readConfig := func(file string) (Config, error) {
		raw, err := readTrustData(file, true, 2<<20)
		if err != nil {
			return Config{}, err
		}
		parsedHashes[file] = digest(raw)
		return decodeSingleBackupConfig(raw)
	}
	c, err := readConfig(request.HostConfig)
	if err != nil || !c.NodePKI.Enabled || c.NodePKI.AuthorityDirectory != filepath.Join(m.Spec.Root, "authority") || c.Collector.IdentityFile != m.Spec.configuration().Collector.IdentityFile || c.Collector.RevocationStateDirectory != m.Spec.configuration().Collector.RevocationStateDirectory || c.Collector.CAFile != m.Spec.configuration().Collector.CAFile || c.Collector.RevocationFile != m.Spec.configuration().Collector.RevocationFile {
		return empty, errSingleBackup
	}
	api, err := readConfig(request.APIConfig)
	if err != nil || api.Central.Topology != "single" || api.Central.Instance != c.Central.Instance || api.Database.DSNFile != c.Database.DSNFile || api.Metrics.QueryURL != c.Metrics.QueryURL || api.DeploymentTrust.VaultKeyFile != c.DeploymentTrust.VaultKeyFile || !reflect.DeepEqual(api.DeploymentTrust.PreviousKeyFiles, c.DeploymentTrust.PreviousKeyFiles) {
		return empty, errSingleBackup
	}
	if _, err := readTrustData(request.ComposeFile, true, 2<<20); err != nil || verifySinglePKI(m.Spec, time.Now().UTC()) != nil {
		return empty, errSingleBackup
	}
	files := []string{request.HostConfig, request.APIConfig, request.ComposeFile, c.Database.DSNFile,
		c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PublicKeyFile, c.DeploymentTrust.ManifestFile, c.DeploymentTrust.SignatureFile,
		c.DeploymentTrust.HelperFile, c.DeploymentTrust.NativeBundleFile}
	files = append(files, c.DeploymentTrust.PreviousKeyFiles...)
	if c.DeploymentTrust.ImageArchiveFile != "" {
		files = append(files, c.DeploymentTrust.ImageArchiveFile)
	}
	for _, file := range []string{api.DeploymentTrust.PublicKeyFile, api.DeploymentTrust.ManifestFile, api.DeploymentTrust.SignatureFile, c.Executor.RulesFile, c.Central.CertFile, c.Central.KeyFile, api.Central.CertFile, api.Central.KeyFile} {
		if file != "" {
			files = append(files, file)
		}
	}
	directories := append([]string{}, request.RecoveryDirectories...)
	for _, directory := range []string{c.Central.ExportDirectory, c.Metrics.SpoolDir} {
		if directory != "" {
			directories = append(directories, directory)
		}
	}
	for _, directory := range []string{api.Central.ExportDirectory, api.Metrics.SpoolDir, c.Executor.ConfigurationDirectory} {
		if directory != "" {
			directories = append(directories, directory)
		}
	}
	if request.PKIMaintenance != "" {
		maintenanceRaw, err := readTrustData(request.PKIMaintenance, true, 64<<10)
		var maintenance singlePKIUpgradeManifest
		if err != nil || singleDecode(maintenanceRaw, &maintenance) != nil {
			return empty, errSingleBackup
		}
		spec, _, err := readSinglePKIUpgrade(ctx, request.PKIMaintenance, "", "")
		if err != nil || spec.Root != m.Spec.Root {
			return empty, errSingleBackup
		}
		directories = append(directories, filepath.Dir(request.PKIMaintenance))
		files = append(files, maintenance.PublicKeyFile)
	}
	sources, err := normalizeSingleBackupSources(m.Spec.Root, files, directories, output)
	if err != nil {
		return empty, err
	}
	bindings := map[string]string{}
	for file, hash := range parsedHashes {
		bindings[file] = hash
	}
	for name, hash := range m.Files {
		file := filepath.Join(m.Spec.Root, name)
		if existing, ok := bindings[file]; ok && existing != hash {
			return empty, errSingleBackup
		}
		bindings[file] = hash
	}
	files = append(files, request.Installation)
	if request.PKIMaintenance != "" {
		files = append(files, request.PKIMaintenance)
	}
	for _, file := range files {
		artifact, err := hashTrustArtifact(ctx, file, uint64(metricsSnapshotMaxBytes))
		if err != nil {
			return empty, errSingleBackup
		}
		if expected, exists := bindings[file]; exists && expected != artifact.SHA256 {
			return empty, errSingleBackup
		}
		bindings[file] = artifact.SHA256
	}
	trust, err := loadDeploymentTrust(ctx, c.DeploymentTrust)
	if err != nil || trust.release.SHA256() != bindings[c.DeploymentTrust.ManifestFile] || trust.release.manifest.Helper.SHA256 != bindings[c.DeploymentTrust.HelperFile] || trust.release.manifest.Native.SHA256 != bindings[c.DeploymentTrust.NativeBundleFile] {
		return empty, errSingleBackup
	}
	apiTrust, err := loadDeploymentMetadata(ctx, api.DeploymentTrust)
	if err != nil || apiTrust.release.SHA256() != trust.release.SHA256() {
		return empty, errSingleBackup
	}
	// Bind the same bytes that were authenticated above, including Vault and
	// trust anchors. Refuse an administrator's concurrent source replacement.
	for file, expected := range bindings {
		artifact, err := hashTrustArtifact(ctx, file, uint64(metricsSnapshotMaxBytes))
		if err != nil || artifact.SHA256 != expected {
			return empty, errSingleBackup
		}
	}
	return singleBackupPlan{spec: m.Spec, config: c, metrics: metrics, sources: sources, installation: digest(raw), request: request, output: output, bindings: bindings}, nil
}

func decodeSingleBackupConfig(raw []byte) (Config, error) {
	var c Config
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || c.Validate() != nil {
		return c, errSingleBackup
	}
	return c, nil
}

func verifySingleBackupBindings(p singleBackupPlan, captured metricsSnapshotManifest) error {
	files := map[string]string{}
	for _, file := range captured.Files {
		files[file.Path] = file.SHA256
	}
	for original, expected := range p.bindings {
		archived := ""
		for _, source := range p.sources {
			if source.Directory && singleBackupContains(source.Path, original) {
				relative, err := filepath.Rel(source.Path, original)
				if err != nil {
					return errSingleBackup
				}
				archived = source.Destination + "/" + filepath.ToSlash(relative)
				break
			} else if !source.Directory && source.Path == original {
				archived = source.Destination
				break
			}
		}
		if archived == "" || files[archived] != expected {
			return errSingleBackup
		}
	}
	return nil
}

func (s *Store) backupSingle(ctx context.Context, p singleBackupPlan) (singleBackupReceipt, error) {
	var receipt singleBackupReceipt
	stage, err := newMetricsSnapshotStage(p.output)
	if err != nil {
		return receipt, errSingleBackup
	}
	defer stage.close()
	lock, err := singlePKILock(ctx, p.spec)
	if err != nil {
		return receipt, errSingleBackup
	}
	defer lock.Close()
	phase := "local-locks"
	// No services are stopped. The bounded database freeze is intentionally
	// explicit: a lock timeout/cancellation fails without publishing an archive.
	err = nodepki.WithMaintenanceSnapshot(ctx, p.config.NodePKI.AuthorityDirectory, p.config.Collector.RevocationStateDirectory, filepath.Dir(p.config.Collector.IdentityFile), func() error {
		phase = "database-checkpoint"
		tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
		if err != nil {
			return errSingleBackup
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='5s'; SELECT pg_advisory_xact_lock(773376001)`); err != nil {
			return errSingleBackup
		}
		tables, err := postgresTables(ctx, tx)
		if err != nil || len(tables) == 0 {
			return errSingleBackup
		}
		quoted := make([]string, 0, len(tables))
		for _, table := range tables {
			// This authenticated liveness evidence is always discarded during
			// restore. Freezing it can expire the API's observer and restart the
			// central process during a slow backup. Business/configuration and
			// handoff tables remain fenced; no archived heartbeat authorizes work.
			if table == "v3_bootstrap_processes" {
				continue
			}
			quoted = append(quoted, quotePG(table))
		}
		if _, err := tx.ExecContext(ctx, "LOCK TABLE "+strings.Join(quoted, ",")+" IN SHARE MODE"); err != nil {
			return errSingleBackup
		}
		version, err := currentSchema(ctx, tx)
		if err != nil || version != SchemaVersion {
			return errSingleBackup
		}
		if err := verifySingleBackupVaultTx(ctx, tx, p.config.DeploymentTrust); err != nil {
			return err
		}
		manifest := singleBackupManifest{Format: 1, Instance: p.spec.Instance, Schema: version, Installation: p.installation, Started: time.Now().UTC(), Sources: p.sources, Consistency: "database-write-fenced-host-stable-metrics-interval"}
		phase = "host-capture"
		for _, name := range []string{"host", "postgres"} {
			if unix.Mkdirat(int(stage.directory.Fd()), name, 0700) != nil {
				return errSingleBackup
			}
		}
		host, err := openSnapshotDirectory(stage.directory, "host")
		if err != nil {
			return errSingleBackup
		}
		defer host.Close()
		captured, modes, err := captureSingleBackupHost(ctx, p.spec.Root, p.sources, host)
		if err != nil {
			return err
		}
		phase = "host-bindings"
		if verifySingleBackupBindings(p, captured) != nil {
			return errSingleBackup
		}
		phase = "database-export"
		postgres, err := backupPostgres(ctx, tx, version, filepath.Join(stage.path, "postgres"))
		if err != nil {
			return errSingleBackup
		}
		manifest.Postgres = "postgres/" + filepath.Base(postgres)
		phase = "metrics-snapshot"
		metrics, err := p.metrics.backup(ctx, filepath.Join(stage.path, "metrics"))
		if err != nil {
			if !metrics.SnapshotClean && metrics.Snapshot != "" {
				// A failed outer archive is removed; retain only the exact public
				// snapshot name required for deliberate cleanup, never host keys.
				receipt.State, receipt.PendingSnapshot = "failed", metrics.Snapshot
			}
			return err
		}
		if !metrics.SnapshotClean {
			return errMetricsSnapshotCleanup
		}
		manifest.Metrics = metrics.ManifestSHA256
		phase = "host-recheck"
		current, currentModes, err := captureSingleBackupHost(ctx, p.spec.Root, p.sources, nil)
		if err != nil || !sameSingleBackupHost(captured, current, modes, currentModes) {
			return errSingleBackup
		}
		manifest.Modes = modes
		phase = "archive-verification"
		actual, err := inspectSingleBackupTree(ctx, stage.directory)
		if err != nil {
			return err
		}
		manifest.Files, manifest.Directories = actual.Files, actual.Directories
		manifest.Completed = time.Now().UTC()
		raw, err := writeSingleBackupJSON(stage.directory, "backup.json", manifest)
		if err != nil {
			return err
		}
		if _, err := verifySingleBackup(ctx, stage.path, digest(raw)); err != nil {
			return err
		}
		// Release a successful read checkpoint before publication. A failed
		// transaction cannot leave a published artifact claiming a checkpoint.
		if err := tx.Commit(); err != nil {
			return errSingleBackup
		}
		phase = "archive-publication"
		if err := stage.publish(ctx); err != nil {
			return errSingleBackup
		}
		receipt = singleBackupReceipt{State: "captured", Directory: p.output, ManifestSHA256: digest(raw), Files: len(manifest.Files)}
		for _, file := range manifest.Files {
			receipt.Bytes += file.Bytes
		}
		return nil
	})
	if err != nil {
		return receipt, fmt.Errorf("%s: %w", phase, err)
	}
	return receipt, err
}

func verifySingleBackupVaultTx(ctx context.Context, tx *sql.Tx, config DeploymentTrustConfig) error {
	vault, err := OpenVault(config.VaultKeyFile, config.PreviousKeyFiles...)
	if err != nil {
		return errSingleBackup
	}
	// Include future encrypted tables as well as the currently known ones.
	// The catalog and all application tables are protected by the checkpoint.
	rows, err := tx.QueryContext(ctx, `SELECT c.relname,a.attname FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid WHERE c.relnamespace=current_schema()::regnamespace AND c.relname LIKE 'v3\_%' ESCAPE '\' AND c.relkind IN ('r','p') AND NOT c.relispartition AND a.attnum>0 AND NOT a.attisdropped AND (a.attname='key_id' OR a.attname LIKE '%\_key_id' ESCAPE '\') ORDER BY c.relname,a.attname`)
	if err != nil {
		return errSingleBackup
	}
	var columns [][2]string
	for rows.Next() {
		var table, column string
		if rows.Scan(&table, &column) != nil || !identifier.MatchString(table) || !identifier.MatchString(column) {
			rows.Close()
			return errSingleBackup
		}
		columns = append(columns, [2]string{table, column})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return errSingleBackup
	}
	for _, pair := range columns {
		rows, err := tx.QueryContext(ctx, "SELECT DISTINCT "+quotePG(pair[1])+" FROM "+quotePG(pair[0])+" WHERE "+quotePG(pair[1])+" IS NOT NULL AND "+quotePG(pair[1])+"<>'' LIMIT 10")
		if err != nil {
			return errSingleBackup
		}
		for rows.Next() {
			var key string
			if rows.Scan(&key) != nil || vault.keys[key] == nil {
				rows.Close()
				return errSingleBackup
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return errSingleBackup
		}
	}
	return nil
}

func inspectSingleBackupTree(ctx context.Context, root *os.File) (metricsSnapshotManifest, error) {
	actual := metricsSnapshotManifest{Files: []metricsSnapshotFile{}, Directories: []string{}}
	var total int64
	entries, err := snapshotEntries(root)
	if err != nil || len(entries) < 3 || len(entries) > 4 {
		return actual, errSingleBackup
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.Name() == "backup.json" {
			continue
		}
		if entry.Name() != "host" && entry.Name() != "postgres" && entry.Name() != "metrics" {
			return actual, errSingleBackup
		}
		seen[entry.Name()] = true
		from, err := openSnapshotDirectory(root, entry.Name())
		if err != nil {
			return actual, errSingleBackup
		}
		err = walkMetricsSnapshot(ctx, from, nil, entry.Name(), true, &actual, &total)
		from.Close()
		if err != nil {
			return actual, errSingleBackup
		}
	}
	if len(seen) != 3 {
		return actual, errSingleBackup
	}
	sort.Strings(actual.Directories)
	sort.Slice(actual.Files, func(i, j int) bool { return actual.Files[i].Path < actual.Files[j].Path })
	return actual, nil
}

func verifySingleBackup(ctx context.Context, directory, expected string) (singleBackupManifest, error) {
	var manifest singleBackupManifest
	raw, err := readTrustData(filepath.Join(directory, "backup.json"), true, 64<<20)
	if err != nil || !releaseDigest(expected) || digest(raw) != expected || singleDecode(raw, &manifest) != nil || manifest.Format != 1 || !identifier.MatchString(manifest.Instance) || manifest.Schema < 1 || manifest.Schema > SchemaVersion || !releaseDigest(manifest.Installation) || !releaseDigest(manifest.Metrics) || manifest.Started.IsZero() || manifest.Completed.Before(manifest.Started) || manifest.Consistency != "database-write-fenced-host-stable-metrics-interval" || !validSnapshotRelative(manifest.Postgres) || filepath.Dir(manifest.Postgres) != "postgres" {
		return manifest, errSingleBackup
	}
	dir, err := trustDirectory(directory, true)
	if err != nil {
		return manifest, errSingleBackup
	}
	defer dir.Close()
	actual, err := inspectSingleBackupTree(ctx, dir)
	if err != nil || !reflect.DeepEqual(manifest.Files, actual.Files) || !reflect.DeepEqual(manifest.Directories, actual.Directories) {
		return manifest, errSingleBackup
	}
	if _, err := verifyMetricsSnapshot(ctx, filepath.Join(directory, "metrics"), manifest.Metrics); err != nil {
		return manifest, errSingleBackup
	}
	header, err := inspectPGBackup(filepath.Join(directory, manifest.Postgres))
	if err != nil || header.Version != manifest.Schema {
		return manifest, errSingleBackup
	}
	if len(manifest.Sources) < 1 || len(manifest.Sources) > 128 || len(manifest.Modes) > metricsSnapshotMaxFiles {
		return manifest, errSingleBackup
	}
	files := map[string]bool{}
	directories := map[string]bool{}
	for _, file := range manifest.Files {
		files[file.Path] = true
	}
	for _, directory := range manifest.Directories {
		directories[directory] = true
	}
	seenSources := map[string]bool{}
	for _, source := range manifest.Sources {
		if !snapshotAbsolutePath(source.Path) || !validSnapshotRelative(source.Destination) || filepath.Dir(source.Destination) != "host" || seenSources[source.Destination] || source.Directory && !directories[source.Destination] || !source.Directory && !files[source.Destination] {
			return manifest, errSingleBackup
		}
		seenSources[source.Destination] = true
	}
	seenModes := map[string]bool{}
	for _, mode := range manifest.Modes {
		if !strings.HasPrefix(mode.Path, "host/") || !files[mode.Path] || seenModes[mode.Path] || mode.Mode > 0777 || mode.Mode&0022 != 0 || mode.Mode&0400 == 0 {
			return manifest, errSingleBackup
		}
		seenModes[mode.Path] = true
	}
	for file := range files {
		if strings.HasPrefix(file, "host/") && !seenModes[file] {
			return manifest, errSingleBackup
		}
	}
	return manifest, nil
}
