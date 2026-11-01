package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"webscan/internal/telemetry"
	agentv1 "webscan/sdk/agent/v1"
)

type Metrics struct {
	WriteURL, QueryURL, RawURL string
	HTTP                       *http.Client
}

// derivedSamples preserves raw history and adds bounded scalar series computed
// with the same reset/missing-sample rules as the existing center. Device
// rates use a fixed separate namespace; paths and event identifiers are never labels.
func derivedSamples(samples []*agentv1.MetricsSample, baseline telemetry.Baseline) ([]*agentv1.MetricsSample, error) {
	result := make([]*agentv1.MetricsSample, 0, len(samples))
	for _, sample := range samples {
		if sample == nil {
			return nil, errors.New("指标样本为空")
		}
		ms, err := telemetry.Parse(string(sample.PrometheusText))
		if err != nil {
			return nil, err
		}
		// Never derive a second trusted series from an agent-provided central
		// namespace. Removing only its original line would still let telemetry
		// derive a newly prefixed value from an untrusted webscan_* metric.
		filtered := ms[:0]
		for _, metric := range ms {
			if !reservedCentralMetric(metric.Name) {
				filtered = append(filtered, metric)
			}
		}
		ms = filtered
		snapshot, next := telemetry.Derive(ms, sample.UnixMillis/1000, baseline)
		deviceMarkers, deviceRates := deviceDerivedState(ms, sample.UnixMillis, baseline, &next)
		baseline = next
		keys := make([]string, 0, len(snapshot.Values))
		for key := range snapshot.Values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var raw bytes.Buffer
		// Reserve the derived device namespace for the central calculation.
		for _, line := range strings.Split(string(sample.PrometheusText), "\n") {
			if reservedCentralMetric(strings.TrimSpace(line)) {
				continue
			}
			raw.WriteString(line)
			raw.WriteByte('\n')
		}

		for _, key := range keys {
			value := snapshot.Values[key]
			if strings.Contains(key, ":") || !metricName("webscan_derived_"+key) || math.IsNaN(value) || math.IsInf(value, 0) || key == "cpu_cores" && value == 0 {
				continue
			}
			fmt.Fprintf(&raw, "webscan_derived_%s{source=\"central\"} %s\n", key, strconv.FormatFloat(value, 'g', -1, 64))
		}
		markerKeys := make([]string, 0, len(deviceMarkers))
		for key := range deviceMarkers {
			markerKeys = append(markerKeys, key)
		}
		sort.Strings(markerKeys)
		for _, id := range markerKeys {
			kind, name, _ := decodeConsoleDeviceID(id)
			fmt.Fprintf(&raw, "webscan_device_%s_sample_time_seconds{source=\"central\",device=%s} %s\n", kind, strconv.Quote(name), strconv.FormatFloat(float64(sample.UnixMillis)/1000, 'g', -1, 64))
		}
		if deviceRates {
			for _, key := range keys {
				metric, name, ok := strings.Cut(key, ":")
				if !ok || !validConsoleDeviceName(name) {
					continue
				}
				for _, candidate := range consoleDeviceMetrics {
					if candidate.Metric != metric {
						continue
					}
					value := snapshot.Values[key]
					if value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0) {
						fmt.Fprintf(&raw, "webscan_device_%s{source=\"central\",device=%s} %s\n", metric, strconv.Quote(name), strconv.FormatFloat(value, 'g', -1, 64))
					}
					break
				}
			}
		}
		result = append(result, &agentv1.MetricsSample{UnixMillis: sample.UnixMillis, PrometheusText: raw.Bytes()})
	}
	return result, nil
}

// Record only bounded, validated device identities in the cursor. Retaining the
// immediately previous presence permits an explicit missing-sample marker.
func deviceDerivedState(ms []telemetry.Metric, at int64, previous telemetry.Baseline, next *telemetry.Baseline) (map[string]bool, bool) {
	const seenPrefix = "webscan_device_seen:"
	const bootKey = "webscan_device_boot_time"
	markers := map[string]bool{}
	for key := range previous.Values {
		if strings.HasPrefix(key, seenPrefix) {
			id := strings.TrimPrefix(key, seenPrefix)
			if _, _, ok := decodeConsoleDeviceID(id); ok {
				markers[id] = true
			}
		}
	}
	boot := float64(0)
	for _, m := range ms {
		if m.Name == "node_boot_time_seconds" && m.Value > 0 {
			boot = m.Value
		}
		if !validConsoleDeviceName(m.Labels["device"]) {
			continue
		}
		for _, candidate := range consoleDeviceMetrics {
			if candidate.Raw == m.Name {
				id := consoleDeviceID(candidate.Kind, m.Labels["device"])
				markers[id] = true
				next.Values[seenPrefix+id] = 1
				break
			}
		}
	}
	previousBoot := previous.Values[bootKey]
	if boot > 0 {
		next.Values[bootKey] = boot
	} else if previousBoot > 0 {
		next.Values[bootKey] = previousBoot
	}
	valid := previous.Time > 0 && at/1000 > previous.Time && at/1000-previous.Time <= 60
	if previousBoot != boot && (previousBoot > 0 || boot > 0) {
		valid = false
	}
	return markers, valid
}

var allowedLabels = map[string]bool{"cpu": true, "mode": true, "device": true, "mountpoint": true, "fstype": true, "operstate": true, "sysname": true, "release": true, "version": true, "machine": true, "nodename": true, "domainname": true, "state": true, "status": true, "kind": true, "collector": true, "type": true, "name": true, "source": true}

// BuildMetrics normalizes labels and fixes node identity at the collector.
// The timestamp is the Agent's original sample time, including replayed data.
func BuildMetrics(node string, samples []*agentv1.MetricsSample) ([]byte, error) {
	if !identifier.MatchString(node) || len(samples) > 120 {
		return nil, errors.New("节点身份或指标样本数量不正确")
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	last := int64(0)
	for _, sample := range samples {
		if sample == nil || sample.UnixMillis <= last || sample.UnixMillis > time.Now().Add(5*time.Minute).UnixMilli() {
			return nil, errors.New("指标时间无效或没有递增")
		}
		last = sample.UnixMillis
		ms, e := telemetry.Parse(string(sample.PrometheusText))
		if e != nil {
			return nil, e
		}
		if len(ms) > 2000 {
			return nil, errors.New("节点活跃时序超过 2000 条限制")
		}
		for _, m := range ms {
			if !metricName(m.Name) {
				return nil, errors.New("指标名称不正确")
			}
			labels := map[string]string{"__name__": m.Name, "node_id": node}
			skip := false
			for k, v := range m.Labels {
				if !allowedLabels[k] || len(v) > 256 {
					skip = true
					break
				}
				labels[k] = v
			}
			if skip || len(labels) > 18 {
				continue
			}
			if e = encoder.Encode(struct {
				Metric     map[string]string `json:"metric"`
				Values     []float64         `json:"values"`
				Timestamps []int64           `json:"timestamps"`
			}{labels, []float64{m.Value}, []int64{sample.UnixMillis}}); e != nil {
				return nil, e
			}
			if out.Len() > 16<<20 {
				return nil, errors.New("指标批次超限")
			}
		}
	}
	return out.Bytes(), nil
}
func metricName(v string) bool {
	if len(v) == 0 || len(v) > 128 || v[0] >= '0' && v[0] <= '9' {
		return false
	}
	for _, r := range v {
		if !(r == '_' || r == ':' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func (m *Metrics) Write(ctx context.Context, node string, samples []*agentv1.MetricsSample) error {
	raw, e := BuildMetrics(node, samples)
	if e != nil {
		return e
	}
	if len(raw) == 0 {
		return nil
	}
	if m.RawURL == "" {
		return m.writeMetricPayload(ctx, m.WriteURL, raw)
	}
	history, original, e := splitMetricLayers(raw)
	if e != nil {
		return e
	}
	// A partially acknowledged write is replayed with exactly the Agent's
	// original timestamps; the collector cannot commit its PG cursor until
	// BOTH layers acknowledge the complete batch.
	if e = m.writeMetricPayload(ctx, m.RawURL, original); e != nil {
		return e
	}
	return m.writeMetricPayload(ctx, m.WriteURL, history)
}
func (m *Metrics) Range(ctx context.Context, node, name string, start, end time.Time) (json.RawMessage, error) {
	if !identifier.MatchString(node) || !metricName(name) || !end.After(start) || end.Sub(start) > 31*24*time.Hour {
		return nil, errors.New("指标查询参数不正确，最多查询 31 天")
	}
	step := max(30, int(math.Ceil(end.Sub(start).Seconds()/999)))
	q := url.Values{"query": {name + `{node_id=` + strconv.Quote(node) + `}`}, "start": {strconv.FormatInt(start.Unix(), 10)}, "end": {strconv.FormatInt(end.Unix(), 10)}, "step": {strconv.Itoa(step)}}
	r, e := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(m.QueryURL, "/")+"/api/v1/query_range?"+q.Encode(), nil)
	if e != nil {
		return nil, e
	}
	resp, e := m.HTTP.Do(r)
	if e != nil {
		return nil, errors.New("时序库查询失败")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("时序库查询失败")
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if e != nil || len(raw) > 8<<20 || !json.Valid(raw) {
		return nil, errors.New("时序库响应无效或超限")
	}
	return raw, nil
}

func (s *Store) MetricCursor(ctx context.Context, node string) (int64, telemetry.Baseline, error) {
	var at int64
	var b telemetry.Baseline
	var raw []byte
	e := s.DB.QueryRowContext(ctx, "SELECT sampled_at,baseline FROM v3_metric_cursors WHERE node=$1", node).Scan(&at, &raw)
	if e == sql.ErrNoRows {
		return 0, b, nil
	}
	if e != nil {
		return 0, b, e
	}
	e = json.Unmarshal(raw, &b)
	return at, b, e
}
func (s *Store) CommitMetrics(ctx context.Context, n Node, l Lease, b *agentv1.MetricsBatch, previous telemetry.Baseline) error {
	return s.commitMetrics(ctx, n, l, b, previous, 0)
}

func (s *Store) commitMetrics(ctx context.Context, n Node, l Lease, b *agentv1.MetricsBatch, previous telemetry.Baseline, interval int) error {
	if b == nil || b.NodeId != n.ID || len(b.Samples) > 120 {
		return errors.New("节点指标身份不匹配")
	}
	if len(b.Samples) == 0 {
		return nil
	}
	var snap telemetry.Snapshot
	lastSample := int64(0)
	for _, p := range b.Samples {
		if p == nil || p.UnixMillis <= lastSample || p.UnixMillis > time.Now().Add(5*time.Minute).UnixMilli() {
			return errors.New("指标时间无效或没有递增")
		}
		lastSample = p.UnixMillis
		ms, e := telemetry.Parse(string(p.PrometheusText))
		if e != nil {
			return e
		}
		var next telemetry.Baseline
		snap, next = telemetry.Derive(ms, p.UnixMillis/1000, previous)
		deviceDerivedState(ms, p.UnixMillis, previous, &next)
		previous = next
		canonicalDeploymentHealth(ms, snap.Values)
	}
	last := b.Samples[len(b.Samples)-1].UnixMillis
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = s.FenceNode(ctx, tx, n, l); e != nil {
		return e
	}
	baseline, e := json.Marshal(previous)
	if e != nil {
		return e
	}
	values, e := json.Marshal(snap.Values)
	if e != nil {
		return e
	}
	info, e := json.Marshal(snap.Info)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO v3_metric_cursors VALUES($1,$2,$3) ON CONFLICT(node) DO UPDATE SET sampled_at=excluded.sampled_at,baseline=excluded.baseline WHERE v3_metric_cursors.sampled_at<excluded.sampled_at", n.ID, last, baseline); e != nil {
		return e
	}
	result, e := tx.ExecContext(ctx, "INSERT INTO v3_node_status(node,sampled_at,metrics,info,error) VALUES($1,$2,$3,$4,'') ON CONFLICT(node) DO UPDATE SET sampled_at=excluded.sampled_at,metrics=excluded.metrics,info=excluded.info,metrics_error='',error=concat_ws('；',nullif(v3_node_status.events_error,''),nullif(v3_node_status.protocol_error,'')),updated_at=clock_timestamp() WHERE v3_node_status.sampled_at IS NULL OR v3_node_status.sampled_at<excluded.sampled_at", n.ID, last, values, info)
	if e != nil {
		return e
	}
	count, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if count == 1 {
		if e = s.observeMetricHealth(ctx, tx, n, snap, last, interval); e != nil {
			return e
		}
	}
	return tx.Commit()
}

func assigned(shard int, members []string, self string) bool {
	if len(members) == 0 {
		return false
	}
	members = append([]string(nil), members...)
	sort.Strings(members)
	return members[shard%len(members)] == self
}
func shardResource(shard int) string { return fmt.Sprintf("collect/%d", shard) }
