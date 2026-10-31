package controlplane

// VictoriaMetrics snapshots contain three intentional directory symlinks and
// hard-linked immutable parts. Copy only those known snapshot targets, never
// live storage, into an independent, hashed tree. This is a backup component;
// it is not an atomic checkpoint of PostgreSQL and the host's PKI/credentials.
import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var errMetricsSnapshot = errors.New("时序快照备份校验失败；请检查本机时序服务、存储目录、权限和空间，原数据未修改")
var errMetricsSnapshotCleanup = errors.New("本次临时时序快照清理未确认；请核对回执中的快照，未清理其他快照")
var errMetricsSnapshotCreateUnknown = errors.New("时序快照创建回执未确认，可能遗留临时快照；请在本机核对，未自动删除历史快照")

const metricsSnapshotMaxFiles = 200000
const metricsSnapshotMaxBytes int64 = 1 << 40

var metricsSnapshotName = regexp.MustCompile(`^[0-9]{14}-[0-9a-fA-F]{1,32}$`)

type metricsSnapshotStore struct {
	URL, Directory string
	HTTP           *http.Client
}

type metricsSnapshotFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type metricsSnapshotManifest struct {
	Format       int                   `json:"format"`
	Engine       string                `json:"engine"`
	Snapshot     string                `json:"snapshot"`
	Started      time.Time             `json:"started_at"`
	Completed    time.Time             `json:"completed_at"`
	Directories  []string              `json:"directories"`
	Files        []metricsSnapshotFile `json:"files"`
	encodedBytes int
}

type metricsSnapshotReceipt struct {
	Directory      string `json:"directory"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Snapshot       string `json:"snapshot"`
	SnapshotClean  bool   `json:"snapshot_cleaned"`
	Files          int    `json:"files"`
	Bytes          int64  `json:"bytes"`
}

func validMetricsSnapshotName(name string) bool {
	if !metricsSnapshotName.MatchString(name) {
		return false
	}
	_, err := time.Parse("20060102150405", name[:14])
	return err == nil
}

// Only the configured single-server loopback endpoint is eligible. Redirects
// cannot turn a local privileged backup into a request to another service.
func (v metricsSnapshotStore) request(ctx context.Context, action, snapshot string) ([]byte, error) {
	u, err := url.Parse(v.URL)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" ||
		(u.Scheme != "http" && u.Scheme != "https") || (u.Path != "" && u.Path != "/") ||
		net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() {
		return nil, errMetricsSnapshot
	}
	switch action {
	case "create", "list":
		if snapshot != "" {
			return nil, errMetricsSnapshot
		}
	case "delete":
		if !validMetricsSnapshotName(snapshot) {
			return nil, errMetricsSnapshot
		}
		u.RawQuery = url.Values{"snapshot": {snapshot}}.Encode()
	default:
		return nil, errMetricsSnapshot
	}
	u.Path = "/snapshot/" + action
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errMetricsSnapshot
	}
	client := http.Client{Timeout: 30 * time.Second}
	if v.HTTP != nil {
		client = *v.HTTP
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	operation, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := client.Do(request.WithContext(operation))
	if err != nil {
		return nil, errMetricsSnapshot
	}
	defer response.Body.Close()
	const limit = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || response.StatusCode != http.StatusOK || len(raw) > limit {
		return nil, errMetricsSnapshot
	}
	// Never return server-supplied error bodies: proxy credentials and internal
	// paths must not escape via a failed backup's public status or logs.
	return raw, nil
}

func snapshotStatus(raw []byte, result any) error {
	var status struct {
		Status string `json:"status"`
	}
	if uniqueBackupJSON(json.NewDecoder(strings.NewReader(string(raw))), 0) != nil || json.Unmarshal(raw, &status) != nil || status.Status != "ok" || json.Unmarshal(raw, result) != nil {
		return errMetricsSnapshot
	}
	return nil
}

func (v metricsSnapshotStore) create(ctx context.Context) (string, error) {
	raw, err := v.request(ctx, "list", "")
	var before struct {
		Snapshots []string `json:"snapshots"`
	}
	if err != nil || snapshotStatus(raw, &before) != nil || before.Snapshots == nil {
		return "", errMetricsSnapshot
	}
	raw, err = v.request(ctx, "create", "")
	var created struct {
		Snapshot string `json:"snapshot"`
	}
	if err != nil || snapshotStatus(raw, &created) != nil || !validMetricsSnapshotName(created.Snapshot) {
		// A lost create response may leave an unknown snapshot. Never guess a
		// name, retry creation, or use delete_all to hide that uncertainty.
		return "", errMetricsSnapshotCreateUnknown
	}
	for _, existing := range before.Snapshots {
		if existing == created.Snapshot {
			return "", errMetricsSnapshot
		}
	}
	return created.Snapshot, nil
}

func (v metricsSnapshotStore) remove(ctx context.Context, name string) error {
	raw, err := v.request(ctx, "delete", name)
	var result struct{}
	if err != nil || snapshotStatus(raw, &result) != nil {
		return errMetricsSnapshotCleanup
	}
	return nil
}

func (v metricsSnapshotStore) backup(ctx context.Context, output string) (receipt metricsSnapshotReceipt, result error) {
	if !snapshotAbsolutePath(v.Directory) || !snapshotAbsolutePath(output) || output == v.Directory || strings.HasPrefix(output, v.Directory+"/") || strings.HasPrefix(v.Directory, output+"/") {
		return receipt, errMetricsSnapshot
	}
	source, err := trustDirectory(v.Directory, false)
	if err != nil {
		return receipt, errMetricsSnapshot
	}
	defer source.Close()
	stage, err := newMetricsSnapshotStage(output)
	if err != nil {
		return receipt, err
	}
	defer stage.close()
	started := time.Now().UTC()
	name, err := v.create(ctx)
	if err != nil {
		return receipt, err
	}
	receipt.Snapshot = name
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := v.remove(cleanup, name); err != nil {
			result = errors.Join(result, err)
			return
		}
		receipt.SnapshotClean = true
	}()
	manifest := metricsSnapshotManifest{Format: 1, Engine: "victoriametrics-single", Snapshot: name, Started: started, Files: []metricsSnapshotFile{}}
	if err := captureMetricsSnapshot(ctx, source, stage.directory, name, &manifest); err != nil {
		return receipt, err
	}
	manifest.Completed = time.Now().UTC()
	raw, err := json.Marshal(manifest)
	if err != nil || len(raw) > 64<<20 {
		return receipt, errMetricsSnapshot
	}
	if err := stage.writeManifest(raw); err != nil {
		return receipt, err
	}
	if _, err := verifyMetricsSnapshot(ctx, stage.path, digest(raw)); err != nil {
		return receipt, err
	}
	if err := stage.publish(ctx); err != nil {
		return receipt, err
	}
	receipt = metricsSnapshotReceipt{Directory: output, Snapshot: name, ManifestSHA256: digest(raw), Files: len(manifest.Files)}
	for _, file := range manifest.Files {
		receipt.Bytes += file.Bytes
	}
	return receipt, nil
}

func snapshotAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsAny(path, "\x00\r\n")
}
