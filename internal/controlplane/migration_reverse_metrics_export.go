package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"webscan/internal/common"
)

const migrationReverseMetricsMaxChunks = 65536
const migrationReverseMetricsMaxBytes int64 = 32 << 30

func migrationReverseMetricsLayers(c Config) []struct {
	name    string
	metrics *Metrics
} {
	m := migrationRecoveryHostMetrics(c)
	out := []struct {
		name    string
		metrics *Metrics
	}{{"history", m}}
	if m.RawURL != "" {
		copy := *m
		copy.QueryURL, copy.WriteURL, copy.RawURL = m.RawURL, m.RawURL, ""
		out = append(out, struct {
			name    string
			metrics *Metrics
		}{"raw", &copy})
	}
	return out
}

// The selector is constructed here from a fixed label name. No expression,
// source address or matcher is supplied by the administrator or an archive.
func migrationReverseMetricsInventory(ctx context.Context, m *Metrics, end int64, known []string) ([]string, error) {
	if _, e := migrationMetricTarget(m); e != nil {
		return nil, ErrMigrationSession
	}
	q := url.Values{"match[]": {`{__name__!="",node_id!=""}`}, "start": {"0"}, "end": {strconv.FormatInt((end+999)/1000, 10)}}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(m.QueryURL, "/")+"/api/v1/label/node_id/values?"+q.Encode(), nil)
	if e != nil {
		return nil, ErrMigrationSession
	}
	resp, e := m.HTTP.Do(req)
	if e != nil {
		return nil, ErrMigrationSession
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if e != nil || resp.StatusCode != 200 || len(raw) > 4<<20 {
		return nil, ErrMigrationSession
	}
	var result struct {
		Status string   `json:"status"`
		Data   []string `json:"data"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Status != "success" || len(result.Data) > 20000 {
		return nil, ErrMigrationSession
	}
	allowed := map[string]bool{}
	for _, node := range known {
		allowed[node] = true
	}
	seen := map[string]bool{}
	for _, node := range result.Data {
		if !identifier.MatchString(node) || !allowed[node] || seen[node] {
			return nil, ErrMigrationSession
		}
		seen[node] = true
	}
	sort.Strings(result.Data)
	// Missing node identities cannot be silently left outside the backup. The
	// trusted project VM stores only project data, so these rows are blockers.
	missing, e := migrationMetricExport(ctx, m, []string{`{__name__!="",node_id=""}`}, 0, (end+999)/1000)
	if e != nil || len(missing) != 0 {
		return nil, ErrMigrationSession
	}
	return result.Data, nil
}

type migrationReverseMetricsValue struct {
	at    int64
	value float64
}

// Preserve the actual VM values, all labels, millisecond timestamps and
// multiplicity. Ordering alone is normalized; no tolerance, rate derivation,
// rounding or timestamp truncation is applied to the stored values.
func migrationReverseMetricsEncode(lines []migrationMetricLine, node string, start, end int64) ([]byte, int, int64, error) {
	labels := map[string]map[string]string{}
	series := map[string][]migrationReverseMetricsValue{}
	var count int64
	for _, line := range lines {
		if len(line.Metric) == 0 || len(line.Metric) > 64 || line.Metric["node_id"] != node || !identifier.MatchString(node) || !metricName(line.Metric["__name__"]) || len(line.Values) != len(line.Timestamps) || len(line.Values) > 1000 {
			return nil, 0, 0, ErrMigrationSession
		}
		for key, value := range line.Metric {
			if !migrationReverseMetricsLabel(key) || len(value) > 4096 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
				return nil, 0, 0, ErrMigrationSession
			}
		}
		key := string(common.JSON(line.Metric))
		for i, at := range line.Timestamps {
			if at < 1 || math.IsNaN(line.Values[i]) || math.IsInf(line.Values[i], 0) {
				return nil, 0, 0, ErrMigrationSession
			}
			if at < start || at > end {
				continue
			}
			labels[key] = line.Metric
			series[key] = append(series[key], migrationReverseMetricsValue{at, line.Values[i]})
			count++
			if count > 240000 {
				return nil, 0, 0, ErrMigrationSession
			}
		}
	}
	keys := make([]string, 0, len(series))
	for key := range series {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out bytes.Buffer
	for _, key := range keys {
		points := series[key]
		sort.Slice(points, func(i, j int) bool {
			if points[i].at != points[j].at {
				return points[i].at < points[j].at
			}
			return strconv.FormatFloat(points[i].value, 'g', -1, 64) < strconv.FormatFloat(points[j].value, 'g', -1, 64)
		})
		for begin := 0; begin < len(points); begin += 1000 {
			finish := min(begin+1000, len(points))
			line := migrationMetricLine{Metric: labels[key], Values: make([]float64, 0, finish-begin), Timestamps: make([]int64, 0, finish-begin)}
			for _, p := range points[begin:finish] {
				line.Values = append(line.Values, p.value)
				line.Timestamps = append(line.Timestamps, p.at)
			}
			if json.NewEncoder(&out).Encode(line) != nil || out.Len() > 16<<20 {
				return nil, 0, 0, ErrMigrationSession
			}
		}
	}
	if out.Len() == 0 {
		out.WriteByte('\n')
	}
	return out.Bytes(), len(keys), count, nil
}
func migrationReverseMetricsLabel(key string) bool {
	if len(key) == 0 || len(key) > 128 {
		return false
	}
	for i, r := range key {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func migrationReverseMetricsFetch(ctx context.Context, m *Metrics, node string, start, end int64) ([]byte, int, int64, error) {
	lines, e := migrationMetricExport(ctx, m, []string{`{node_id=` + strconv.Quote(node) + `}`}, start/1000, (end+999)/1000)
	if e != nil {
		return nil, 0, 0, ErrMigrationSession
	}
	return migrationReverseMetricsEncode(lines, node, start, end)
}

func migrationReverseMetricsCapture(ctx context.Context, c Config, sink *MigrationLegacySink, known []string, end int64) ([]migrationReverseMetricsLayer, error) {
	var total int64
	attempts, chunks := 0, 0
	all := []migrationReverseMetricsLayer{}
	for _, layer := range migrationReverseMetricsLayers(c) {
		nodes, e := migrationReverseMetricsInventory(ctx, layer.metrics, end, known)
		if e != nil {
			return nil, e
		}
		result := migrationReverseMetricsLayer{Name: layer.name, Nodes: nodes, Chunks: []migrationReverseMetricsChunk{}}
		var capture func(string, int64, int64) error
		capture = func(node string, start, finish int64) error {
			attempts++
			if ctx.Err() != nil || attempts > 100000 || chunks >= migrationReverseMetricsMaxChunks {
				return ErrMigrationSession
			}
			raw, fragments, points, e := migrationReverseMetricsFetch(ctx, layer.metrics, node, start, finish)
			if e != nil {
				if finish-start < 1000 {
					return ErrMigrationSession
				}
				middle := start + (finish-start)/2
				if e = capture(node, start, middle); e != nil {
					return e
				}
				return capture(node, middle+1, finish)
			}
			total += int64(len(raw))
			if total > migrationReverseMetricsMaxBytes {
				return ErrMigrationSession
			}
			hash := digest(raw)
			file := "chunk-" + hash + ".jsonl"
			if e = migrationReverseMetricsWriteFile(sink, file, raw); e != nil {
				return e
			}
			chunks++
			result.Chunks = append(result.Chunks, migrationReverseMetricsChunk{node, start, finish, file, hash, len(raw), fragments, points})
			return nil
		}
		for _, node := range nodes {
			if capture(node, 1, end) != nil {
				return nil, ErrMigrationSession
			}
		}
		all = append(all, result)
	}
	return all, nil
}

func migrationReverseMetricsVerifyActual(ctx context.Context, c Config, m migrationReverseMetricsManifest) error {
	layers := migrationReverseMetricsLayers(c)
	if len(layers) != len(m.Layers) {
		return ErrMigrationSession
	}
	for i, layer := range layers {
		expected := m.Layers[i]
		if layer.name != expected.Name {
			return ErrMigrationSession
		}
		nodes, e := migrationReverseMetricsInventory(ctx, layer.metrics, m.End, m.Nodes)
		if e != nil || string(common.JSON(nodes)) != string(common.JSON(expected.Nodes)) {
			return ErrMigrationSession
		}
		var total int64
		for _, chunk := range expected.Chunks {
			raw, fragments, points, e := migrationReverseMetricsFetch(ctx, layer.metrics, chunk.Node, chunk.Start, chunk.End)
			if e != nil || len(raw) != chunk.Bytes || digest(raw) != chunk.SHA256 || fragments != chunk.Fragments || points != chunk.Points {
				return ErrMigrationSession
			}
			total += int64(len(raw))
			if total > migrationReverseMetricsMaxBytes {
				return ErrMigrationSession
			}
		}
	}
	return nil
}
