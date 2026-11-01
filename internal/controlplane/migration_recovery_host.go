package controlplane

// The disaster-recovery handoff is a private host operation. None of these
// inputs is accepted by an HTTP route, and a report never grants authority to a
// later operation: activation repeats observations in its own transaction.
import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type MigrationRecoveryHostRequest struct {
	Format         int              `json:"format"`
	Generation     string           `json:"generation"`
	Backup         string           `json:"backup_directory"`
	ManifestSHA256 string           `json:"manifest_sha256"`
	Staged         string           `json:"staged_directory"`
	Original       singleBackupSpec `json:"original"`
	WorkDirectory  string           `json:"work_directory"`
}

type MigrationRecoveryHostReport struct {
	State             string `json:"state"`
	Generation        string `json:"generation"`
	BackupSHA256      string `json:"backup_manifest_sha256"`
	PostgresSHA256    string `json:"postgres_body_sha256"`
	MetricsSHA256     string `json:"metrics_restore_sha256"`
	IsolationSHA256   string `json:"isolation_sha256"`
	AuthoritySHA256   string `json:"latest_authority_sha256"`
	Samples           int64  `json:"verified_samples"`
	CutoverAuthorized bool   `json:"cutover_authorized"`
}

type migrationRecoveryHostPlan struct {
	request    MigrationRecoveryHostRequest
	manifest   singleBackupManifest
	header     pgBackupLine
	original   singleBackupPlan
	target     Config
	configFile string
	sourceFile string
	sourceSHA  string
}

func migrationRecoveryHostLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return false
	}
	host, port, err := net.SplitHostPort(u.Host)
	ip := net.ParseIP(host)
	n, parseErr := strconv.Atoi(port)
	return err == nil && parseErr == nil && n > 0 && n <= 65535 && ip != nil && ip.IsLoopback()
}

func planMigrationRecoveryHost(ctx context.Context, r MigrationRecoveryHostRequest, c Config) (migrationRecoveryHostPlan, error) {
	p := migrationRecoveryHostPlan{request: r, target: c}
	if r.Format != 1 || !validArchiveSource(r.Generation) || !releaseDigest(r.ManifestSHA256) || c.Validate() != nil || c.Central.Topology != "single" {
		return p, ErrMigrationRecovery
	}
	paths := []string{r.Backup, r.Staged, r.WorkDirectory}
	for i, path := range paths {
		if !singlePKIUpgradePath(path) {
			return p, ErrMigrationRecovery
		}
		for _, other := range paths[i+1:] {
			if singleBackupContains(path, other) || singleBackupContains(other, path) {
				return p, ErrMigrationRecovery
			}
		}
	}
	m, err := verifySingleBackup(ctx, r.Backup, r.ManifestSHA256)
	if err != nil || m.Schema < 49 || m.Schema != SchemaVersion || c.Central.Instance != m.Instance {
		return p, ErrMigrationRecovery
	}
	p.manifest = m
	p.header, err = inspectPGBackup(filepath.Join(r.Backup, m.Postgres))
	if err != nil || !releaseDigest(p.header.SHA256) || p.header.SnapshotAt.IsZero() || p.header.SnapshotAt.After(m.Completed) {
		return p, ErrMigrationRecovery
	}
	p.original, err = planSingleBackup(ctx, r.Original, filepath.Join(r.WorkDirectory, "original-binding-check"))
	if err != nil || p.original.installation != m.Installation || p.original.spec.Instance != m.Instance {
		return p, ErrMigrationRecovery
	}
	// Auxiliary generated units (watchdog/retention) may live outside the
	// immutable installation's file map. Bind them to authenticated full-
	// archive bytes as well; an unbound root-owned definition is insufficient.
	for _, source := range p.original.sources {
		for _, file := range m.Files {
			if !source.Directory || !strings.HasPrefix(file.Path, source.Destination+"/") {
				continue
			}
			rel := strings.TrimPrefix(file.Path, source.Destination+"/")
			if strings.HasSuffix(rel, ".service") || strings.HasSuffix(rel, ".timer") {
				path := filepath.Join(source.Path, filepath.FromSlash(rel))
				if !singleBackupContains(source.Path, path) {
					return p, ErrMigrationRecovery
				}
				if prior := p.original.bindings[path]; prior != "" && prior != file.SHA256 {
					return p, ErrMigrationRecovery
				}
				p.original.bindings[path] = file.SHA256
			}
		}
	}
	for _, path := range paths {
		for _, source := range p.original.sources {
			if singleBackupContains(path, source.Path) || singleBackupContains(source.Path, path) {
				return p, ErrMigrationRecovery
			}
		}
	}
	if !migrationRecoveryHostLoopback(c.Metrics.QueryURL) || c.Metrics.QueryURL != c.Metrics.WriteURL || (m.RawMetrics != "") != (c.Metrics.RawURL != "") || c.Metrics.RawURL != "" && (!migrationRecoveryHostLoopback(c.Metrics.RawURL) || c.Metrics.RawURL == c.Metrics.QueryURL) || c.Metrics.QueryURL == p.original.config.Metrics.QueryURL || c.Metrics.RawURL != "" && c.Metrics.RawURL == p.original.config.Metrics.RawURL {
		return p, ErrMigrationRecovery
	}
	if err := migrationRecoveryHostVerifyStage(ctx, p); err != nil {
		return p, err
	}
	return p, nil
}

// Verify all staged host and PostgreSQL bytes against the independently
// verified archive. Recovery metadata must still say that staging alone never
// authorized an import or cutover. The live target is checked separately.
func migrationRecoveryHostVerifyStage(ctx context.Context, p migrationRecoveryHostPlan) error {
	raw, err := readTrustData(filepath.Join(p.request.Staged, "recovery-manifest.json"), true, 64<<20)
	var m singleBackupManifest
	if err != nil || singleDecode(raw, &m) != nil || !reflect.DeepEqual(m, p.manifest) {
		return ErrMigrationRecovery
	}
	var state struct {
		Backup     string    `json:"backup_manifest_sha256"`
		Staged     time.Time `json:"staged_at"`
		Started    bool      `json:"runtime_started"`
		Imported   bool      `json:"postgres_imported"`
		Authorized bool      `json:"cutover_authorized"`
		Epoch      bool      `json:"requires_node_epoch_reconciliation"`
		Retirement bool      `json:"requires_latest_retirement_reconciliation"`
		Watchdog   bool      `json:"requires_watchdog_reconciliation"`
	}
	raw, err = readTrustData(filepath.Join(p.request.Staged, "recovery-state.json"), true, 64<<10)
	if err != nil || singleDecode(raw, &state) != nil || state.Backup != p.request.ManifestSHA256 || state.Staged.IsZero() || state.Started || state.Imported || state.Authorized || !state.Epoch || !state.Retirement || state.Watchdog != (p.manifest.HostWatchdog != nil) {
		return ErrMigrationRecovery
	}
	for _, file := range p.manifest.Files {
		if !strings.HasPrefix(file.Path, "host/") && !strings.HasPrefix(file.Path, "postgres/") && !strings.HasPrefix(file.Path, "watchdog/") {
			continue
		}
		actual, err := hashTrustArtifact(ctx, filepath.Join(p.request.Staged, file.Path), uint64(metricsSnapshotMaxBytes))
		if err != nil || actual.SHA256 != file.SHA256 || file.Bytes < 0 || actual.Bytes != uint64(file.Bytes) {
			return ErrMigrationRecovery
		}
	}
	header, err := inspectPGBackup(filepath.Join(p.request.Staged, p.manifest.Postgres))
	if err != nil || header.SHA256 != p.header.SHA256 || !header.SnapshotAt.Equal(p.header.SnapshotAt) {
		return ErrMigrationRecovery
	}
	return nil
}

func migrationRecoveryHostMetrics(c Config) *Metrics {
	return &Metrics{QueryURL: c.Metrics.QueryURL, WriteURL: c.Metrics.WriteURL, RawURL: c.Metrics.RawURL, HTTP: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func migrationRecoveryHostCommand(ctx context.Context, o Options, out io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 || o.Output != "" || (o.Action != "check-migration-recovery-host" && o.Action != "activate-migration-recovery-host") {
		return ErrMigrationRecovery
	}
	raw, err := readTrustData(o.Source, true, 64<<10)
	var r MigrationRecoveryHostRequest
	if err != nil || singleDecode(raw, &r) != nil {
		return ErrMigrationRecovery
	}
	c, err := LoadConfig(o.Config)
	if err != nil {
		return ErrMigrationRecovery
	}
	p, err := planMigrationRecoveryHost(ctx, r, c)
	if err != nil {
		return err
	}
	p.configFile, p.sourceFile, p.sourceSHA = o.Config, o.Source, digest(raw)
	s, err := Open(ctx, c)
	if err != nil {
		return ErrMigrationRecovery
	}
	defer s.DB.Close()
	report, err := s.migrationRecoveryHost(ctx, p, o.Action == "activate-migration-recovery-host", newMigrationRecoveryHostRuntime())
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}

func migrationRecoveryHostSameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func migrationRecoveryHostVerifyBinding(ctx context.Context, p migrationRecoveryHostPlan) error {
	current, err := planSingleBackup(ctx, p.request.Original, filepath.Join(p.request.WorkDirectory, "original-binding-check"))
	if err != nil || current.installation != p.original.installation || !migrationRecoveryHostSameJSON(current.spec, p.original.spec) || !migrationRecoveryHostSameJSON(current.config, p.original.config) || !migrationRecoveryHostSameJSON(current.sources, p.original.sources) {
		return ErrMigrationRecovery
	}
	if p.configFile != "" {
		c, err := LoadConfig(p.configFile)
		if err != nil || !migrationRecoveryHostSameJSON(c, p.target) {
			return ErrMigrationRecovery
		}
		raw, err := readTrustData(p.sourceFile, true, 64<<10)
		if err != nil || digest(raw) != p.sourceSHA {
			return ErrMigrationRecovery
		}
	}
	return migrationRecoveryHostVerifyStage(ctx, p)
}
