// Package nodeconfig builds the bounded v3 pull Agent configuration artifact.
// Seed artifacts contain a node key and only travel through private files/SSH.
// They are not deployment status, audit or HTTP response models.
package nodeconfig

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"webscan/internal/common"
	"webscan/internal/nodepki"
)

const MaxBytes = 2 << 20

var ErrInvalid = errors.New("节点运行配置、证书、规则或资源参数不正确")
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var release = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?$`)

type Reconciliation struct {
	IntervalHours       int `json:"interval_hours"`
	StartJitterMinutes  int `json:"start_jitter_minutes"`
	MaxReadMiBPerSecond int `json:"max_read_mib_per_second"`
	Nice                int `json:"nice"`
	IOClass             int `json:"ionice_class"`
}
type Monitor struct {
	Roots              []string       `json:"roots"`
	ExcludePaths       []string       `json:"exclude_paths"`
	Extensions         []string       `json:"extensions"`
	ImportantFilenames []string       `json:"important_filenames"`
	CriticalPaths      []string       `json:"critical_paths"`
	SiteNameMode       string         `json:"site_name_mode"`
	Reconciliation     Reconciliation `json:"reconciliation"`
}
type Engine struct {
	Enabled        bool `json:"enabled"`
	Workers        int  `json:"workers"`
	TimeoutSeconds int  `json:"timeout_seconds"`
	MaxFileMiB     int  `json:"max_file_mib"`
}
type Scan struct {
	YARA   Engine `json:"yara"`
	ClamAV Engine `json:"clamav"`
	AuditD struct {
		Enabled      bool     `json:"enabled"`
		WatchedPaths []string `json:"watched_paths"`
	} `json:"auditd"`
}
type Resources struct {
	MemoryMiB       int     `json:"agent_memory_mib"`
	GoMemoryMiB     int     `json:"go_memory_mib"`
	CPUs            float64 `json:"cpus"`
	GoMaxProcs      int     `json:"gomaxprocs"`
	FileDescriptors int     `json:"file_descriptors"`
}
type Transport struct {
	QueueMiB              int `json:"local_event_queue_max_mib"`
	LogsMiB               int `json:"local_log_max_mib"`
	RequestTimeoutSeconds int `json:"request_timeout_seconds"`
	VectorBufferMiB       int `json:"vector_buffer_mib,omitempty"`
}
type Settings struct {
	Monitor         Monitor   `json:"monitor"`
	Scan            Scan      `json:"scan"`
	Resources       Resources `json:"resources"`
	Transport       Transport `json:"transport"`
	ProbeDirectory  string    `json:"probe_directory"`
	ProbeSeconds    int       `json:"probe_seconds"`
	RetentionDays   int       `json:"retention_days"`
	MetricsSourceIP string    `json:"metrics_source_ip,omitempty"`
}

func DefaultSettings() Settings {
	s := Settings{Monitor: Monitor{Roots: []string{"/www/wwwroot"}, ExcludePaths: []string{}, Extensions: []string{".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".phar", ".pht", ".inc"}, ImportantFilenames: []string{".user.ini", ".htaccess"}, CriticalPaths: []string{}, SiteNameMode: "first_directory", Reconciliation: Reconciliation{6, 30, 5, 15, 3}},
		Scan: Scan{YARA: Engine{true, 1, 15, 20}, ClamAV: Engine{false, 1, 30, 100}}, Resources: Resources{256, 64, 1, 2, 65536}, Transport: Transport{1024, 1024, 10, 0}, ProbeDirectory: "/www/wwwroot/.webscan-probe", ProbeSeconds: 60, RetentionDays: 7}
	s.Scan.AuditD.WatchedPaths = []string{}
	return s
}
func Digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func ValidDigest(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}

func (s Settings) Validate() error {
	raw, err := json.Marshal(s.Monitor)
	if err != nil {
		return ErrInvalid
	}
	var monitor common.Map
	if json.Unmarshal(raw, &monitor) != nil {
		return ErrInvalid
	}
	policy, err := common.NewPolicy(monitor)
	if err != nil {
		return ErrInvalid
	}
	if len(s.Monitor.Roots) < 1 || len(s.Monitor.Roots) > 64 || s.Monitor.SiteNameMode != "first_directory" {
		return ErrInvalid
	}
	reserved := filepath.Join("/var/lib/webscan-v1", common.ScannerReadinessSubdirectory)
	for _, path := range append(append([]string{}, s.Monitor.Roots...), s.Monitor.CriticalPaths...) {
		if common.Inside(path, reserved) {
			return ErrInvalid
		}
	}
	if common.Inside(s.ProbeDirectory, reserved) || common.Inside(reserved, s.ProbeDirectory) {
		return ErrInvalid
	}
	for _, list := range [][]string{s.Monitor.Roots, s.Monitor.ExcludePaths, s.Monitor.CriticalPaths} {
		for _, p := range list {
			if filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
				return ErrInvalid
			}
		}
	}
	r := s.Resources
	if r.MemoryMiB < 128 || r.MemoryMiB > 8192 || r.GoMemoryMiB < 32 || r.GoMemoryMiB > r.MemoryMiB-32 || math.IsNaN(r.CPUs) || math.IsInf(r.CPUs, 0) || r.CPUs < 0.1 || r.CPUs > 16 || r.GoMaxProcs < 1 || r.GoMaxProcs > 32 || r.FileDescriptors < 1024 || r.FileDescriptors > 1048576 {
		return ErrInvalid
	}
	rec := s.Monitor.Reconciliation
	if rec.IntervalHours < 1 || rec.IntervalHours > 8760 || rec.StartJitterMinutes < 0 || rec.StartJitterMinutes > 1440 || rec.MaxReadMiBPerSecond < 1 || rec.MaxReadMiBPerSecond > 1048576 || rec.Nice < 0 || rec.Nice > 19 || rec.IOClass < 1 || rec.IOClass > 3 {
		return ErrInvalid
	}
	for _, engine := range []Engine{s.Scan.YARA, s.Scan.ClamAV} {
		if engine.Workers < 1 || engine.Workers > 16 || engine.TimeoutSeconds < 1 || engine.TimeoutSeconds > 600 || engine.MaxFileMiB < 1 || engine.MaxFileMiB > 1024 {
			return ErrInvalid
		}
	}
	// Auditd is not consumed by this one-service Agent. Do not silently claim
	// coverage when a legacy config requests an unsupported external engine.
	if s.Scan.AuditD.Enabled {
		return ErrInvalid
	}
	if s.Transport.QueueMiB < 1 || s.Transport.QueueMiB > 1048576 || s.Transport.LogsMiB < 1 || s.Transport.LogsMiB > 1048576 || s.Transport.RequestTimeoutSeconds < 1 || s.Transport.RequestTimeoutSeconds > 600 || s.Transport.VectorBufferMiB < 0 {
		return ErrInvalid
	}
	if !filepath.IsAbs(s.ProbeDirectory) || filepath.Clean(s.ProbeDirectory) != s.ProbeDirectory || strings.ContainsAny(s.ProbeDirectory, "\x00\r\n") || s.ProbeDirectory == "/" || s.ProbeSeconds < 10 || s.ProbeSeconds > 3600 || s.RetentionDays < 1 || s.RetentionDays > 3650 {
		return ErrInvalid
	}
	covered := false
	for _, root := range policy.Roots {
		covered = covered || common.Inside(s.ProbeDirectory, root)
	}
	if !covered || policy.Excluded(s.ProbeDirectory) {
		return ErrInvalid
	}
	if s.MetricsSourceIP != "" && net.ParseIP(s.MetricsSourceIP) == nil {
		return ErrInvalid
	}
	return nil
}

// Material is a PRIVATE file format; it must never enter a task JSON column or
// be marshaled by an API. Only its byte length/SHA256 are stored in job plans.
type Material struct {
	Format       int      `json:"format"`
	Node         string   `json:"node"`
	Version      int64    `json:"version"`
	SourceSHA256 string   `json:"source_sha256"`
	Mode         string   `json:"mode"`
	Release      string   `json:"release"`
	BundleSHA256 string   `json:"bundle_sha256"`
	ServerName   string   `json:"server_name"`
	MetricsPort  int      `json:"metrics_port"`
	Collectors   []string `json:"collectors"`
	Settings     Settings `json:"settings"`
	CA           []byte   `json:"ca"`
	Certificate  []byte   `json:"certificate"`
	Key          []byte   `json:"key"`
	CRL          []byte   `json:"crl"`
	YARA         []byte   `json:"yara"`
}

func (m Material) Validate(now time.Time) error {
	if (m.Format != 1 && m.Format != 2 && m.Format != 3) || !identifier.MatchString(m.Node) || m.Version < 1 || !ValidDigest(m.SourceSHA256) || !ValidDigest(m.BundleSHA256) || !release.MatchString(m.Release) || len(m.Release) > 128 || (m.Mode != "native" && m.Mode != "docker") || m.MetricsPort < 1024 || m.MetricsPort > 65535 || m.ServerName == "" || len(m.ServerName) > 253 || strings.ContainsAny(m.ServerName, "/\\\x00\r\n \t") || len(m.Collectors) < 1 || len(m.Collectors) > 256 || len(m.YARA) < 1 || len(m.YARA) > 512<<10 || len(m.CA) > 64<<10 || len(m.Certificate) > 64<<10 || len(m.Key) > 64<<10 || len(m.CRL) > 1<<20 {
		return ErrInvalid
	}
	if err := m.Settings.Validate(); err != nil {
		return err
	}
	trust, err := nodepki.NewTrust(m.CA, m.CRL, now)
	if err != nil {
		return ErrInvalid
	}
	if m.Format == 3 {
		// An upgrade carries public trust only. The node must prove its live
		// managed identity before stopping the previous installation.
		if len(m.Certificate) != 0 || len(m.Key) != 0 {
			return ErrInvalid
		}
	} else {
		pair, err := tls.X509KeyPair(m.Certificate, m.Key)
		if err != nil || len(pair.Certificate) != 1 {
			return ErrInvalid
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || cert.VerifyHostname(m.ServerName) != nil || trust.Verify(cert, nodepki.Node, m.Node, now) != nil {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, collector := range m.Collectors {
		canonical, err := nodepki.Identity(nodepki.Collector, collector)
		if err != nil || seen[canonical] {
			return ErrInvalid
		}
		seen[canonical] = true
	}
	return nil
}
func Decode(raw []byte, now time.Time) (Material, error) {
	m, err := decodeCanonical(raw)
	if err != nil || m.Validate(now) != nil {
		return Material{}, ErrInvalid
	}
	return m, nil
}

func decodeCanonical(raw []byte) (Material, error) {
	var m Material
	if len(raw) == 0 || len(raw) > MaxBytes {
		return m, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return Material{}, ErrInvalid
	}
	canonical, err := json.Marshal(m)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(raw)) {
		return Material{}, ErrInvalid
	}
	return m, nil
}

// DecodeManagedRuntime is exclusively for resuming an immutable managed-node
// configuration using a newer durable CRL. It is NOT provisioning validation
// or online peer authentication. Its caller MUST independently validate the
// current node-local private identity against this live CRL before use.
// The original bytes/format are retained so task hashes and rollback evidence
// remain stable even after the initial seed has expired or been revoked.
func DecodeManagedRuntime(raw []byte, now time.Time, liveCRL []byte) (Material, error) {
	m, err := decodeCanonical(raw)
	if err != nil || (m.Format != 2 && m.Format != 3) || nodepki.ValidateCRLAdvance(m.CA, m.CRL, liveCRL, now) != nil {
		return Material{}, ErrInvalid
	}
	public := m
	public.Format, public.CRL, public.Certificate, public.Key = 3, liveCRL, nil, nil
	if public.Validate(now) != nil {
		return Material{}, ErrInvalid
	}
	if m.Format == 3 {
		if len(m.Certificate) != 0 || len(m.Key) != 0 {
			return Material{}, ErrInvalid
		}
		return m, nil
	}
	pair, err := tls.X509KeyPair(m.Certificate, m.Key)
	if err != nil || len(pair.Certificate) != 1 {
		return Material{}, ErrInvalid
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || cert.VerifyHostname(m.ServerName) != nil {
		return Material{}, ErrInvalid
	}
	identity, err := nodepki.Identity(nodepki.Node, m.Node)
	if err != nil || cert.IsCA || len(cert.URIs) != 1 || cert.URIs[0].String() != identity || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return Material{}, ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(m.CA) {
		return Material{}, ErrInvalid
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: cert.NotBefore.Add(time.Second), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return Material{}, ErrInvalid
	}
	return m, nil
}

// DecodeManagedRootRuntime authenticates an immutable pre-rotation package
// against its original issuer history. The replacement authorization and live
// successor CRL must be valid NOW. The old CRL is used only as historical
// evidence; it never admits a peer or replaces the node-local active identity.
// Callers must independently validate that identity and the installed runtime.
func DecodeManagedRootRuntime(raw []byte, now time.Time, roots nodepki.RootSetSnapshot) (Material, error) {
	m, err := decodeCanonical(raw)
	if err != nil || (m.Format != 2 && m.Format != 3) {
		return Material{}, ErrInvalid
	}
	if _, err := nodepki.NewRootSet(m.CA, roots, now); err != nil {
		return Material{}, ErrInvalid
	}
	block, rest := pem.Decode(roots.OldCRL)
	if block == nil || block.Type != "X509 CRL" || len(bytes.TrimSpace(rest)) != 0 {
		return Material{}, ErrInvalid
	}
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil || list.ThisUpdate.After(now) {
		return Material{}, ErrInvalid
	}
	// DecodeManagedRuntime checks the signature, monotonic CRL advance,
	// original leaf identity/SANs and all non-PKI settings at this signed time.
	return DecodeManagedRuntime(raw, list.ThisUpdate, roots.OldCRL)
}

// Runtime contains only generated paths and validated task parameters; no
// browser-submitted command, key path or center notification secret is copied.
func (m Material) Runtime(directory, releaseDirectory string) (common.Map, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !filepath.IsAbs(releaseDirectory) || filepath.Clean(releaseDirectory) != releaseDirectory {
		return nil, ErrInvalid
	}
	raw, _ := json.Marshal(m.Settings)
	var s common.Map
	json.Unmarshal(raw, &s)
	identities := []string{}
	for _, id := range m.Collectors {
		identity, err := nodepki.Identity(nodepki.Collector, id)
		if err != nil {
			return nil, ErrInvalid
		}
		identities = append(identities, identity)
	}
	host := common.Map{"proc": "/proc", "sys": "/sys", "root": "/"}
	if m.Mode == "docker" {
		host = common.Map{"proc": "/host/proc", "sys": "/host/sys", "root": "/rootfs"}
	}
	runtime := common.Map{"node_id": m.Node, "release": m.Release, "deployment_mode": m.Mode, "transport_mode": "pull", "direct_transport": true, "data_dir": "/var/lib/webscan-v1", "log_dir": "/var/log/webscan-v1", "metrics_file": "/var/lib/webscan-v1/textfile/agent.prom", "probe_directory": m.Settings.ProbeDirectory, "probe_seconds": m.Settings.ProbeSeconds, "retention_days": m.Settings.RetentionDays,
		"config_version": m.Version, "config_sha256": m.SourceSHA256, "monitor": s["monitor"], "scan": s["scan"], "transport": s["transport"], "host_metrics": host, "central_ca_file": "", "yara_rules": filepath.Join(directory, "rules.yar"), "clamav_config": filepath.Join(directory, "clamd.conf"), "scanner_tools": common.Map{"yara": filepath.Join(releaseDirectory, "tools/bin/yara"), "clamav": filepath.Join(releaseDirectory, "tools/bin/clamdscan")},
		"pull": common.Map{"collector_identities": identities, "revocation_file": filepath.Join(directory, "ca.crl"), "revocation_state_directory": "/var/lib/webscan-v1/pki-trust", "revocation_updates": true}, "metrics": common.Map{"enabled": true, "port": m.MetricsPort, "tls_enabled": true, "allowed_source_ip": m.Settings.MetricsSourceIP, "ca_file": filepath.Join(directory, "ca.crt"), "cert_file": filepath.Join(directory, "identity.crt"), "key_file": filepath.Join(directory, "identity.key")}}
	if m.Format == 2 || m.Format == 3 {
		common.M(runtime["pull"])["identity_renewal"] = true
		metrics := common.M(runtime["metrics"])
		delete(metrics, "cert_file")
		delete(metrics, "key_file")
		metrics["identity_file"] = "/var/lib/webscan-v1/pki-identity/active.pem"
		if m.Format == 2 {
			metrics["identity_seed_directory"] = directory
		}
	}
	return runtime, nil
}
