package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// This intentionally fails closed beyond its explicit comparison budget. A
// truncated export or memory budget exhaustion is never reported as equality.
const migrationRecoveryHostMaxSamples = 1000000
const migrationRecoveryHostMaxExport = 64 << 20

func migrationRecoveryHostMetricMap(lines []migrationMetricLine) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range lines {
		if !metricName(line.Metric["__name__"]) || len(line.Metric) > 64 || len(line.Values) == 0 || len(line.Values) != len(line.Timestamps) {
			return nil, ErrMigrationRecovery
		}
		for k, v := range line.Metric {
			if !metricName(k) || len(v) > 4096 {
				return nil, ErrMigrationRecovery
			}
		}
		labels, _ := json.Marshal(line.Metric)
		for i, value := range line.Values {
			if math.IsNaN(value) || math.IsInf(value, 0) || line.Timestamps[i] < 1 {
				return nil, ErrMigrationRecovery
			}
			if value == 0 {
				value = 0
			}
			key := string(labels) + ":" + strconv.FormatInt(line.Timestamps[i], 10)
			canonical := strconv.FormatFloat(value, 'g', -1, 64)
			if prior, ok := out[key]; ok && prior != canonical {
				return nil, ErrMigrationRecovery
			}
			out[key] = canonical
			if len(out) > migrationRecoveryHostMaxSamples {
				return nil, ErrMigrationRecovery
			}
		}
	}
	return out, nil
}

func migrationRecoveryHostExport(ctx context.Context, m *Metrics, end time.Time) (map[string]string, error) {
	if m == nil || !migrationRecoveryHostLoopback(m.QueryURL) {
		return nil, ErrMigrationRecovery
	}
	q := url.Values{"match[]": {`{__name__!=""}`}, "start": {"0"}, "end": {strconv.FormatInt(end.Unix()+1, 10)}, "max_rows_per_line": {"1000"}, "reduce_mem_usage": {"1"}}
	req, e := http.NewRequestWithContext(ctx, "GET", m.QueryURL+"/api/v1/export?"+q.Encode(), nil)
	if e != nil {
		return nil, ErrMigrationRecovery
	}
	response, e := m.HTTP.Do(req)
	if e != nil {
		return nil, ErrMigrationRecovery
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, ErrMigrationRecovery
	}
	reader := &io.LimitedReader{R: response.Body, N: migrationRecoveryHostMaxExport + 1}
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	all := map[string]string{}
	for {
		var line migrationMetricLine
		e := decoder.Decode(&line)
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, ErrMigrationRecovery
		}
		part, e := migrationRecoveryHostMetricMap([]migrationMetricLine{line})
		if e != nil {
			return nil, e
		}
		for key, value := range part {
			if old, exists := all[key]; exists && old != value {
				return nil, ErrMigrationRecovery
			}
			all[key] = value
		}
		if len(all) > migrationRecoveryHostMaxSamples {
			return nil, ErrMigrationRecovery
		}
	}
	if reader.N <= 0 {
		return nil, ErrMigrationRecovery
	}
	return all, nil
}

func migrationRecoveryHostMetricDigest(samples map[string]string) string {
	keys := make([]string, 0, len(samples))
	for key := range samples {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, key := range keys {
		canonical.WriteString(key)
		canonical.WriteByte('=')
		canonical.WriteString(samples[key])
		canonical.WriteByte('\n')
	}
	return digest([]byte(canonical.String()))
}

func migrationRecoveryHostReadOnly(ctx context.Context, m *Metrics) bool {
	req, e := http.NewRequestWithContext(ctx, "GET", m.QueryURL+"/metrics", nil)
	if e != nil {
		return false
	}
	response, e := m.HTTP.Do(req)
	if e != nil {
		return false
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if e != nil || response.StatusCode != 200 {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.SplitN(fields[0], "{", 2)[0] == "vm_storage_is_read_only" && fields[1] == "1" {
			return true
		}
	}
	return false
}

// A fresh, owned copy of an authenticated archived TSDB is opened by the exact
// image pinned in the original installation. The original archive and staged
// restore are never mounted. The verification engine refuses ingestion (its
// free-space threshold deliberately exceeds the host), is loopback-only, has a
// read-only root filesystem and is queried exclusively through GET requests.
// Compaction/lock files may only change the disposable private copy.
func migrationRecoveryHostVerifyMetrics(ctx context.Context, p migrationRecoveryHostPlan) (proof string, count int64, result error) {
	d, e := privateDirectory(p.request.WorkDirectory)
	if e != nil {
		return "", 0, ErrMigrationRecovery
	}
	d.Close()
	var free unix.Statfs_t
	if unix.Statfs(p.request.WorkDirectory, &free) != nil {
		return "", 0, ErrMigrationRecovery
	}
	var needed int64 = 512 << 20
	for _, f := range p.manifest.Files {
		if strings.HasPrefix(f.Path, "metrics/") || strings.HasPrefix(f.Path, "metrics-raw/") {
			needed += f.Bytes
		}
	}
	if uint64(needed) > free.Bavail*uint64(free.Bsize) {
		return "", 0, ErrMigrationRecovery
	}
	work, e := os.MkdirTemp(p.request.WorkDirectory, "dr-verify-")
	if e != nil {
		return "", 0, ErrMigrationRecovery
	}
	defer func() {
		if result == nil {
			if e := os.RemoveAll(work); e != nil {
				result = ErrMigrationRecovery
			}
		}
	}()
	proofs := []string{}
	for _, layer := range []struct{ name, sha, target string }{{"metrics", p.manifest.Metrics, p.target.Metrics.QueryURL}, {"metrics-raw", p.manifest.RawMetrics, p.target.Metrics.RawURL}} {
		if layer.sha == "" {
			continue
		}
		data := filepath.Join(work, layer.name)
		if e := restoreMetricsSnapshot(ctx, filepath.Join(p.request.Backup, layer.name), layer.sha, data); e != nil {
			return "", 0, ErrMigrationRecovery
		}
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return "", 0, ErrMigrationRecovery
		}
		address := listener.Addr().String()
		listener.Close()
		owner := token()
		name := "webscan-dr-verify-" + owner[:16]
		raw, e := migrationRecoveryHostExec(ctx, "docker", "run", "--detach", "--name", name, "--label", "io.webscan.dr-verification="+owner, "--network", "host", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "0:0", "--memory", "512m", "--cpus", "1", "--mount", "type=bind,source="+data+",target=/storage", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", p.original.spec.MetricsImage, "-httpListenAddr="+address, "-storageDataPath=/storage", "-retentionPeriod=100y", "-storage.minFreeDiskSpaceBytes=1152921504606846976", "-search.latencyOffset=0s")
		id := strings.TrimSpace(string(raw))
		stop := func() error {
			return migrationRecoveryHostCleanupContainer(ctx, migrationRecoveryHostExec, name, owner)
		}
		if e != nil || len(id) != 64 || !validArchiveSource(id) {
			// A lost docker-run response can still have created the fixed owned
			// container. Cleanup proves its name and owner before removal.
			_ = stop()
			return "", 0, ErrMigrationRecovery
		}
		func() {
			defer func() {
				if e := stop(); e != nil {
					result = ErrMigrationRecovery
				}
			}()
			c := p.target
			c.Metrics.QueryURL, c.Metrics.WriteURL, c.Metrics.RawURL = "http://"+address, "http://"+address, ""
			archive := migrationRecoveryHostMetrics(c)
			ready, stopWait := context.WithTimeout(ctx, 45*time.Second)
			defer stopWait()
			for !migrationRecoveryHostReadOnly(ready, archive) {
				select {
				case <-ready.Done():
					result = ErrMigrationRecovery
					return
				case <-time.After(100 * time.Millisecond):
				}
			}
			want, e := migrationRecoveryHostExport(ctx, archive, p.manifest.Completed)
			if e != nil {
				result = ErrMigrationRecovery
				return
			}
			c.Metrics.QueryURL, c.Metrics.WriteURL = layer.target, layer.target
			actual, e := migrationRecoveryHostExport(ctx, migrationRecoveryHostMetrics(c), p.manifest.Completed)
			if e != nil || !migrationRecoveryMetricContains(actual, want, true) {
				result = ErrMigrationRecovery
				return
			}
			// An actually empty archive is meaningful only after both engines
			// have completed real successful export responses.
			proofs = append(proofs, digest([]byte(layer.name+":"+layer.sha+":"+layer.target+":"+migrationRecoveryHostMetricDigest(want))))
			count += int64(len(want))
		}()
		if result != nil {
			return "", 0, result
		}
	}
	raw, _ := json.Marshal(proofs)
	return digest(raw), count, nil
}

// Cleanup uses a fresh bounded context even after a canceled verification.
// A name alone never authorizes removal: both the generated owner label and
// exact inspected name/ID must match. Unknown responses retain the directory.
func migrationRecoveryHostCleanupContainer(ctx context.Context, command func(context.Context, string, ...string) ([]byte, error), name, owner string) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	raw, err := command(cleanup, "docker", "ps", "--all", "--no-trunc", "--filter", "name=^/"+name+"$", "--format", "{{.ID}}")
	id := strings.TrimSpace(string(raw))
	if err != nil {
		return ErrMigrationRecovery
	}
	if id == "" {
		return nil
	}
	if len(id) != 64 || !validArchiveSource(id) {
		return ErrMigrationRecovery
	}
	raw, err = command(cleanup, "docker", "inspect", id)
	var observed []struct {
		ID     string `json:"Id"`
		Name   string
		Config struct{ Labels map[string]string }
	}
	if err != nil || json.Unmarshal(raw, &observed) != nil || len(observed) != 1 || observed[0].ID != id || observed[0].Name != "/"+name || observed[0].Config.Labels["io.webscan.dr-verification"] != owner {
		return ErrMigrationRecovery
	}
	if _, err = command(cleanup, "docker", "rm", "--force", id); err != nil {
		return ErrMigrationRecovery
	}
	return nil
}
