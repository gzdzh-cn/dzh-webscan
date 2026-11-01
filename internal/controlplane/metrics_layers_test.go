package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"webscan/internal/telemetry"
	agentv1 "webscan/sdk/agent/v1"
)

func TestMetricLayersStripAgentNamespacesAndSplitTrustedHistory(t *testing.T) {
	at := time.Now().Add(-time.Minute).Truncate(time.Second)
	first, second := deviceSample(at, 100, 1, true, ""), deviceSample(at.Add(30*time.Second), 200, 1, true, "")
	for _, sample := range []*agentv1.MetricsSample{first, second} {
		sample.PrometheusText = append(sample.PrometheusText, []byte("webscan_legacy_impersonated 987654\nwebscan_derived_impersonated{source=\"central\"} 987654\nwebscan_device_impersonated{source=\"central\",device=\"sda\"} 987654\n")...)
	}
	prepared, err := derivedSamples([]*agentv1.MetricsSample{first, second}, telemetry.Baseline{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := BuildMetrics("layers-node", prepared)
	if err != nil {
		t.Fatal(err)
	}
	history, raw, err := splitMetricLayers(payload)
	if err != nil || len(history) == 0 || len(raw) == 0 || bytes.Contains(payload, []byte("impersonated")) {
		t.Fatal("agent spoofed derived history", err)
	}
	for _, tc := range []struct {
		body    []byte
		derived bool
	}{{history, true}, {raw, false}} {
		decoder := json.NewDecoder(bytes.NewReader(tc.body))
		for {
			var line struct {
				Metric     map[string]string `json:"metric"`
				Timestamps []int64           `json:"timestamps"`
			}
			if err := decoder.Decode(&line); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			if reservedCentralMetric(line.Metric["__name__"]) != tc.derived || line.Metric["node_id"] != "layers-node" || tc.derived && line.Metric["source"] != "central" {
				t.Fatal("metric crossed layer/identity boundary", line)
			}
			if len(line.Timestamps) != 1 || line.Timestamps[0] != first.UnixMillis && line.Timestamps[0] != second.UnixMillis {
				t.Fatal("replay timestamp rewritten", line.Timestamps)
			}
		}
	}
	if _, _, err := splitMetricLayers([]byte(`{"metric":{"__name__":"webscan_derived_forged","source":"node"},"values":[1],"timestamps":[1]}`)); err == nil {
		t.Fatal("untrusted source entered history")
	}
}

func TestMetricLayersLegacySingleWriteAndExplicitRawQueryCompatibility(t *testing.T) {
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/import" {
			body, _ := io.ReadAll(r.Body)
			if !bytes.Contains(body, []byte("node_disk_read_bytes_total")) || !bytes.Contains(body, []byte("webscan_device_")) {
				t.Error("legacy payload was split")
			}
			writes.Add(1)
			w.WriteHeader(204)
			return
		}
		_ = json.NewEncoder(w).Encode(deviceVMMatrix(nil))
	}))
	defer server.Close()
	m := &Metrics{WriteURL: server.URL, QueryURL: server.URL, HTTP: server.Client()}
	at := time.Now().Add(-time.Minute).Truncate(time.Second)
	prepared, err := derivedSamples([]*agentv1.MetricsSample{deviceSample(at, 100, 1, true, "")}, telemetry.Baseline{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Write(context.Background(), "legacy-layer", prepared); err != nil || writes.Load() != 1 {
		t.Fatal(err, writes.Load())
	}
	if _, err := m.RangeLayer(context.Background(), "legacy-layer", "node_disk_read_bytes_total", "raw", at, at.Add(time.Minute)); err != nil {
		t.Fatal("legacy single URL cannot read raw explicitly", err)
	}
	for _, tc := range []struct{ name, layer string }{{"node_disk_read_bytes_total", "unknown"}, {`up} or vector(1)`, "raw"}, {"webscan_device_disk_read", "raw"}} {
		if _, err := m.RangeLayer(context.Background(), "legacy-layer", tc.name, tc.layer, at, at.Add(time.Minute)); err == nil {
			t.Fatal("unbounded/invalid layer query accepted", tc)
		}
	}
}

func TestMetricLayersBothAcknowledgementsRequiredBeforePGCursor(t *testing.T) {
	for _, mode := range []string{"raw-failure", "history-failure", "history-response-lost"} {
		t.Run(mode, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			node := nodeFixture("layers-node")
			if err := s.PutNode(ctx, node, 0, 256); err != nil {
				t.Fatal(err)
			}
			lease, err := s.Acquire(ctx, shardResource(node.Shard), "layers-worker")
			if err != nil {
				t.Fatal(err)
			}
			var failed atomic.Bool
			failed.Store(true)
			var mu sync.Mutex
			bodies := map[string][][]byte{}
			makeServer := func(layer string) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					mu.Lock()
					bodies[layer] = append(bodies[layer], body)
					mu.Unlock()
					if failed.Load() && mode == layer+"-failure" {
						w.WriteHeader(503)
						return
					}
					if failed.Load() && layer == "history" && mode == "history-response-lost" {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
						} else {
							_ = conn.Close()
						}
						return
					}
					w.WriteHeader(204)
				}))
			}
			history, raw := makeServer("history"), makeServer("raw")
			defer history.Close()
			defer raw.Close()
			at := time.Now().Add(-time.Minute).Truncate(time.Second)
			batch := &agentv1.MetricsBatch{NodeId: node.ID, Samples: []*agentv1.MetricsSample{deviceSample(at, 100, 1, true, ""), deviceSample(at.Add(30*time.Second), 200, 1, true, "")}}
			c := &Collector{Store: s, Metrics: &Metrics{WriteURL: history.URL, QueryURL: history.URL, RawURL: raw.URL, HTTP: history.Client()}}
			c.Config.Collector.IntervalSeconds = 30
			if err := c.collect(ctx, node, lease, metricClient{batch: batch}); err == nil {
				t.Fatal("failed layer acknowledged collection")
			}
			cursor, baseline, err := s.MetricCursor(ctx, node.ID)
			if err != nil || cursor != 0 || baseline.Time != 0 {
				t.Fatal("partial write advanced durable cursor", cursor, baseline, err)
			}
			failed.Store(false)
			if err := c.collect(ctx, node, lease, metricClient{batch: batch}); err != nil {
				t.Fatal(err)
			}
			cursor, _, err = s.MetricCursor(ctx, node.ID)
			if err != nil || cursor != batch.Samples[1].UnixMillis {
				t.Fatal(cursor, err)
			}
			mu.Lock()
			defer mu.Unlock()
			for layer, requests := range bodies {
				if len(requests) > 1 && !bytes.Equal(requests[0], requests[1]) {
					t.Fatal("retry changed original timestamps/payload", layer)
				}
				if layer == "raw" && bytes.Contains(requests[len(requests)-1], []byte("webscan_device_")) {
					t.Fatal("derived data leaked to raw layer")
				}
				if layer == "history" && bytes.Contains(requests[len(requests)-1], []byte("node_disk_read_bytes_total")) {
					t.Fatal("raw data leaked to history")
				}
			}
		})
	}
}

func metricLayerSeriesCount(t *testing.T, raw []byte) int {
	t.Helper()
	var result struct {
		Data struct {
			Result []json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &result) != nil {
		t.Fatal("invalid VM layer response")
	}
	return len(result.Data.Result)
}

func TestMetricLayersVictoriaMetricsActualIsolationAndLostResponseReplay(t *testing.T) {
	historyURL, rawURL := os.Getenv("WEBSCAN_V3_TEST_VM"), os.Getenv("WEBSCAN_V3_TEST_RAW_VM")
	if historyURL == "" || rawURL == "" {
		t.Skip("set isolated history and raw VictoriaMetrics URLs")
	}
	if historyURL == rawURL {
		t.Fatal("two independent VictoriaMetrics stores required")
	}
	s := testStore(t)
	ctx := context.Background()
	node := nodeFixture("layers-vm-" + token()[:12])
	if err := s.PutNode(ctx, node, 0, 256); err != nil {
		t.Fatal(err)
	}
	lease, err := s.Acquire(ctx, shardResource(node.Shard), "layers-vm-worker")
	if err != nil {
		t.Fatal(err)
	}
	var lost atomic.Bool
	lost.Store(true)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := http.NewRequestWithContext(r.Context(), "POST", historyURL+"/api/v1/import", r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(502)
			return
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Error("isolated history VM failed")
			w.WriteHeader(502)
			return
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		if lost.Load() {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
			} else {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(response.StatusCode)
	}))
	defer proxy.Close()
	m := &Metrics{WriteURL: proxy.URL, QueryURL: historyURL, RawURL: rawURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
	c := &Collector{Store: s, Metrics: m}
	c.Config.Collector.IntervalSeconds = 30
	base := time.Now().Add(-20 * time.Minute).Truncate(time.Second)
	batch := &agentv1.MetricsBatch{NodeId: node.ID, Samples: []*agentv1.MetricsSample{deviceSample(base, 100, 1, true, ""), deviceSample(base.Add(30*time.Second), 200, 1, true, "")}}
	if err := c.collect(ctx, node, lease, metricClient{batch: batch}); err == nil {
		t.Fatal("actual VM lost acknowledgement treated as success")
	}
	if cursor, _, err := s.MetricCursor(ctx, node.ID); err != nil || cursor != 0 {
		t.Fatal("actual partial VM acknowledgement advanced PG", cursor, err)
	}
	lost.Store(false)
	if err := c.collect(ctx, node, lease, metricClient{batch: batch}); err != nil {
		t.Fatal(err)
	}
	if cursor, _, err := s.MetricCursor(ctx, node.ID); err != nil || cursor != batch.Samples[1].UnixMillis {
		t.Fatal(cursor, err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		raw, rawErr := m.RangeLayer(ctx, node.ID, "node_disk_read_bytes_total", "raw", base, base.Add(30*time.Second))
		history, historyErr := m.RangeLayer(ctx, node.ID, "webscan_device_disk_read", "history", base, base.Add(30*time.Second))
		if rawErr == nil && historyErr == nil && metricLayerSeriesCount(t, raw) == 1 && metricLayerSeriesCount(t, history) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual VM layers did not expose replayed samples", rawErr, historyErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
	historyOnly := *m
	historyOnly.QueryURL = historyURL
	rawOnly := *m
	rawOnly.QueryURL = rawURL
	for _, tc := range []struct {
		view   *Metrics
		metric string
	}{{&historyOnly, "node_disk_read_bytes_total"}, {&rawOnly, "webscan_device_disk_read"}} {
		body, err := tc.view.Range(ctx, node.ID, tc.metric, base, base.Add(time.Minute))
		if err != nil || metricLayerSeriesCount(t, body) != 0 {
			t.Fatal("actual VM store contains other layer", tc.metric, err)
		}
	}
	// A raw-only historical device is merged without inventing a derived rate.
	if err := m.Write(ctx, node.ID, []*agentv1.MetricsSample{{UnixMillis: base.UnixMilli(), PrometheusText: []byte("node_disk_read_bytes_total{device=\"legacy-raw\"} 1\n")}}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(20 * time.Second)
	for {
		devices, err := m.consoleDeviceInventory(ctx, node.ID, base, base.Add(time.Minute))
		if err == nil && len(devices.Items) == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dual actual inventory missing raw/history identity", devices, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestMetricLayersConfigurationRequiresIndependentAddressesAndPrivatePolicyPath(t *testing.T) {
	base := configurationBootstrapFixture(t)
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, rawURL := range []string{"http://127.0.0.1:18429", "https://metrics-raw.test"} {
		c := base
		c.Metrics.RawURL = rawURL
		c.Metrics.PolicyFile = "/var/lib/webscan/metrics-policy.json"
		if err := c.Validate(); err != nil {
			t.Fatal("valid dual metrics rejected", err)
		}
	}
	for _, rawURL := range []string{base.Metrics.WriteURL, base.Metrics.QueryURL + "/", "file:///tmp/metrics", "http://user:secret@raw.test", "http://raw.test?query=secret"} {
		c := base
		c.Metrics.RawURL = rawURL
		if err := c.Validate(); err == nil {
			t.Fatal("invalid/identical raw store accepted", strings.Split(rawURL, "?")[0])
		}
	}
	for _, path := range []string{"relative.json", "/tmp/../policy.json", "/tmp/policy\nfile"} {
		c := base
		c.Metrics.PolicyFile = path
		if err := c.Validate(); err == nil {
			t.Fatal("uncontrolled policy path accepted")
		}
	}
}
