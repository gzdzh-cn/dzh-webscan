package controlplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"webscan/internal/telemetry"
)

type migrationMetricPoint struct {
	Node       string
	Sampled    int64
	Resolution int
	Origin     string
	Point      telemetry.Point
	Raw        json.RawMessage
}

type migrationMetricLine struct {
	Metric     map[string]string `json:"metric"`
	Values     []float64         `json:"values"`
	Timestamps []int64           `json:"timestamps"`
}

func migrationLegacyMetric(key string) (string, string, string, bool) {
	name, dimension, _ := strings.Cut(key, ":")
	if !metricName(name) || len(dimension) > 256 || !utf8.ValidString(dimension) || strings.ContainsRune(dimension, 0) {
		return "", "", "", false
	}
	for _, q := range telemetry.HistoricalQueries {
		if name == q.Name {
			if dimension != "" && q.Dimension == "" {
				return "", "", "", false
			}
			return name, q.Dimension, dimension, true
		}
	}
	// Native telemetry includes these historical scalars as well as the fixed
	// legacy-Prometheus whitelist. None is a raw counter reconstructed from rates.
	for _, scalar := range []string{"disk_read_bytes", "disk_write_bytes", "disk_read_ops", "disk_write_ops", "net_receive_bytes", "net_transmit_bytes", "cpu_idle_percent", "memory_used_percent", "swap_used", "swap_free", "disk_free", "disk_used", "webscan_probe_loki_seconds"} {
		if name == scalar && dimension == "" {
			return name, "", "", true
		}
	}
	for _, scalar := range []string{"cpu_nice_percent", "cpu_irq_percent", "cpu_softirq_percent", "cpu_steal_percent", "cpu_guest_percent", "cpu_guest_nice_percent", "timex_sync_status", "timex_offset_seconds"} {
		if name == scalar && dimension == "" {
			return name, "", "", true
		}
	}
	if name == "webscan_host_collector_error" && dimension != "" {
		return name, "collector", dimension, true
	}
	if dimension == "" && (strings.HasPrefix(name, "webscan_") || strings.HasPrefix(name, "vector_")) {
		return name, "", "", true
	}
	return "", "", "", false
}

func migrationMetricPointFromArchive(r archivedRecord) (migrationMetricPoint, error) {
	var out migrationMetricPoint
	var err error
	out.Node, err = r.text("node")
	if err != nil || !identifier.MatchString(out.Node) {
		return out, ErrMigrationMetricHistory
	}
	out.Sampled, err = r.integer("time")
	if err != nil || out.Sampled < 1 || out.Sampled > time.Now().Add(5*time.Minute).Unix() {
		return out, ErrMigrationMetricHistory
	}
	resolution, err := r.integer("resolution")
	if err != nil || resolution != 0 && resolution != 300 {
		return out, ErrMigrationMetricHistory
	}
	out.Resolution = int(resolution)
	out.Origin, err = r.text("source")
	if err != nil || out.Origin != "native" && out.Origin != "legacy" {
		return out, ErrMigrationMetricHistory
	}
	raw, err := r.text("payload")
	if err != nil || len(raw) > 1<<20 || json.Unmarshal([]byte(raw), &out.Point) != nil || out.Point.Time != out.Sampled || len(out.Point.Values) > 4096 {
		return out, ErrMigrationMetricHistory
	}
	// encoding/json turns a null float into zero. Preserve missing data by
	// rejecting null numeric members before decoding any historical values.
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &fields) != nil || string(fields["ok"]) != "true" && string(fields["ok"]) != "false" {
		return out, ErrMigrationMetricHistory
	}
	for _, field := range []string{"values", "min", "max", "count"} {
		var numbers map[string]json.RawMessage
		if part, ok := fields[field]; ok {
			if json.Unmarshal(part, &numbers) != nil || field == "values" && out.Point.OK && numbers == nil {
				return out, ErrMigrationMetricHistory
			}
			for _, number := range numbers {
				if _, err := strconv.ParseFloat(string(number), 64); err != nil {
					return out, ErrMigrationMetricHistory
				}
			}
		}
	}
	out.Raw = json.RawMessage(raw)
	for key, value := range out.Point.Values {
		if _, _, _, ok := migrationLegacyMetric(key); !ok || math.IsNaN(value) || math.IsInf(value, 0) {
			return out, ErrMigrationMetricHistory
		}
		if min, ok := out.Point.Min[key]; ok && (math.IsNaN(min) || math.IsInf(min, 0) || min > value) {
			return out, ErrMigrationMetricHistory
		}
		if max, ok := out.Point.Max[key]; ok && (math.IsNaN(max) || math.IsInf(max, 0) || max < value) {
			return out, ErrMigrationMetricHistory
		}
		if count, ok := out.Point.Count[key]; ok && (count < 1 || int64(count) > 1<<53) {
			return out, ErrMigrationMetricHistory
		}
	}
	for key := range out.Point.Min {
		if _, ok := out.Point.Values[key]; !ok {
			return out, ErrMigrationMetricHistory
		}
	}
	for key := range out.Point.Max {
		if _, ok := out.Point.Values[key]; !ok {
			return out, ErrMigrationMetricHistory
		}
	}
	for key := range out.Point.Count {
		if _, ok := out.Point.Values[key]; !ok {
			return out, ErrMigrationMetricHistory
		}
	}
	return out, nil
}

func (p migrationMetricPoint) labels(generation string) map[string]string {
	return map[string]string{"source": "legacy-v2", "generation": generation, "node_id": p.Node, "origin": p.Origin, "resolution_seconds": strconv.Itoa(p.Resolution)}
}
func migrationMetricSelector(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("{")
	for i, key := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(strconv.Quote(labels[key]))
	}
	b.WriteString("}")
	return b.String()
}
func (p migrationMetricPoint) selector(generation string) string {
	return migrationMetricSelector(p.labels(generation))
}

func (p migrationMetricPoint) project(generation string) ([]byte, []migrationMetricLine, error) {
	if !validArchiveSource(generation) {
		return nil, nil, ErrMigrationMetricHistory
	}
	lines := []migrationMetricLine{}
	add := func(name, stat string, value float64, dimensionName, dimension string) {
		labels := p.labels(generation)
		labels["__name__"] = "webscan_legacy_value"
		labels["metric"], labels["statistic"] = name, stat
		if name == "" {
			labels["__name__"] = "webscan_legacy_status"
			delete(labels, "metric")
			delete(labels, "statistic")
		}
		if dimension != "" {
			labels[dimensionName] = dimension
		}
		lines = append(lines, migrationMetricLine{Metric: labels, Values: []float64{value}, Timestamps: []int64{p.Sampled * 1000}})
	}
	status := float64(0)
	if p.Point.OK {
		status = 1
	}
	add("", "", status, "", "")
	keys := make([]string, 0, len(p.Point.Values))
	for key := range p.Point.Values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		name, dimensionName, dimension, ok := migrationLegacyMetric(key)
		if !ok {
			return nil, nil, ErrMigrationMetricHistory
		}
		add(name, "value", p.Point.Values[key], dimensionName, dimension)
		if v, ok := p.Point.Min[key]; ok {
			add(name, "min", v, dimensionName, dimension)
		}
		if v, ok := p.Point.Max[key]; ok {
			add(name, "max", v, dimensionName, dimension)
		}
		if v, ok := p.Point.Count[key]; ok {
			add(name, "count", float64(v), dimensionName, dimension)
		}
	}
	var b bytes.Buffer
	for _, line := range lines {
		if err := json.NewEncoder(&b).Encode(line); err != nil {
			return nil, nil, ErrMigrationMetricHistory
		}
	}
	if b.Len() > 8<<20 {
		return nil, nil, ErrMigrationMetricHistory
	}
	return b.Bytes(), lines, nil
}

func migrationMetricCanonical(lines []migrationMetricLine) (string, error) {
	samples := map[string]string{}
	for _, line := range lines {
		if len(line.Values) != len(line.Timestamps) || len(line.Values) == 0 || line.Metric["source"] != "legacy-v2" || !releaseDigest(line.Metric["generation"]) {
			return "", ErrMigrationMetricHistory
		}
		if line.Metric["__name__"] != "webscan_legacy_value" && line.Metric["__name__"] != "webscan_legacy_status" {
			return "", ErrMigrationMetricHistory
		}
		labels, _ := json.Marshal(line.Metric)
		for i, value := range line.Values {
			if math.IsNaN(value) || math.IsInf(value, 0) || line.Timestamps[i] < 1 {
				return "", ErrMigrationMetricHistory
			}
			if value == 0 {
				value = 0 // VictoriaMetrics normalizes IEEE negative zero.
			}
			key := string(labels) + ":" + strconv.FormatInt(line.Timestamps[i], 10)
			actual := fmt.Sprintf("%.17g", value)
			if old, ok := samples[key]; ok && old != actual {
				return "", ErrMigrationMetricHistory
			}
			samples[key] = actual
		}
	}
	keys := make([]string, 0, len(samples))
	for key := range samples {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(samples[key])
		b.WriteByte('\n')
	}
	return digest([]byte(b.String())), nil
}
