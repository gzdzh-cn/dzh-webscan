package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"webscan/internal/telemetry"

	"google.golang.org/grpc"
	agentv1 "webscan/sdk/agent/v1"
)

type metricClient struct {
	agentv1.AgentServiceClient
	batch *agentv1.MetricsBatch
}

func TestDerivedHistoryDoesNotFillUnknownOrResetRatesWithZero(t *testing.T) {
	at := time.Now().Add(-time.Minute).UnixMilli()
	samples := []*agentv1.MetricsSample{
		{UnixMillis: at, PrometheusText: []byte("node_cpu_seconds_total{cpu=\"0\",mode=\"idle\"} 50\nnode_cpu_seconds_total{cpu=\"0\",mode=\"user\"} 50\n")},
		{UnixMillis: at + 30000, PrometheusText: []byte("node_cpu_seconds_total{cpu=\"0\",mode=\"idle\"} 65\nnode_cpu_seconds_total{cpu=\"0\",mode=\"user\"} 65\n")},
		{UnixMillis: at + 60000, PrometheusText: []byte("node_cpu_seconds_total{cpu=\"0\",mode=\"idle\"} 1\nnode_cpu_seconds_total{cpu=\"0\",mode=\"user\"} 1\n")},
	}
	prepared, err := derivedSamples(samples, telemetry.Baseline{})
	if err != nil {
		t.Fatal(err)
	}
	for i, sample := range prepared {
		present := strings.Contains(string(sample.PrometheusText), "webscan_derived_cpu_percent{")
		if present != (i == 1) {
			t.Fatal("unknown/reset rate published", i, string(sample.PrometheusText))
		}
	}
	if !strings.Contains(string(prepared[1].PrometheusText), "webscan_derived_cpu_percent{source=\"central\"} 50") {
		t.Fatal(string(prepared[1].PrometheusText))
	}
}

func TestMetricsRecoveryDoesNotClearAnEventFailure(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("node-a")
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	l, err := s.Acquire(ctx, shardResource(n.Shard), "one")
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{Store: s}
	c.failure(ctx, n, l, "events", "事件采集失败")
	b := &agentv1.MetricsBatch{NodeId: n.ID, Samples: []*agentv1.MetricsSample{{UnixMillis: time.Now().UnixMilli(), PrometheusText: []byte("node_memory_MemTotal_bytes 1024\n")}}}
	if err = s.CommitMetrics(ctx, n, l, b, telemetry.Baseline{}); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err = s.DB.QueryRow("SELECT error FROM v3_node_status WHERE node=$1", n.ID).Scan(&reason); err != nil || reason != "事件采集失败" {
		t.Fatal(reason, err)
	}
	raw, err := s.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var summary struct{ Abnormal, Fresh int }
	if err = json.Unmarshal(raw, &summary); err != nil || summary.Abnormal != 1 || summary.Fresh != 0 {
		t.Fatal(string(raw), err)
	}
	c.failure(ctx, n, l, "events", "")
	if err = s.DB.QueryRow("SELECT error FROM v3_node_status WHERE node=$1", n.ID).Scan(&reason); err != nil || reason != "" {
		t.Fatal(reason, err)
	}
}

func (m metricClient) ReadMetrics(context.Context, *agentv1.ReadMetricsRequest, ...grpc.CallOption) (*agentv1.MetricsBatch, error) {
	return m.batch, nil
}
func TestMetricCursorWaitsForSuccessfulStorage(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("node-a")
	if e := s.PutNode(ctx, n, 0, 256); e != nil {
		t.Fatal(e)
	}
	l, e := s.Acquire(ctx, shardResource(n.Shard), "one")
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now().UnixMilli()
	client := metricClient{batch: &agentv1.MetricsBatch{NodeId: "node-a", Samples: []*agentv1.MetricsSample{{UnixMillis: at, PrometheusText: []byte("node_memory_MemTotal_bytes 1024\nnode_memory_MemAvailable_bytes 512\n")}}}}
	status := 503
	received := ""
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		received = string(raw)
		w.WriteHeader(status)
	}))
	defer vm.Close()
	c := &Collector{Store: s, Metrics: &Metrics{WriteURL: vm.URL, HTTP: vm.Client()}}
	if e = c.collect(ctx, nodeFixture("node-a"), l, client); e == nil {
		t.Fatal("failed write advanced cursor")
	}
	cursor, _, e := s.MetricCursor(ctx, "node-a")
	if e != nil || cursor != 0 {
		t.Fatal(cursor, e)
	}
	status = 204
	if e = c.collect(ctx, nodeFixture("node-a"), l, client); e != nil {
		t.Fatal(e)
	}
	cursor, _, e = s.MetricCursor(ctx, "node-a")
	if e != nil || cursor != at || !strings.Contains(received, `"node_id":"node-a"`) {
		t.Fatal(cursor, received, e)
	}
	if e = s.Release(ctx, l); e != nil {
		t.Fatal(e)
	}
	client.batch.Samples[0].UnixMillis = at + 1000
	if e = c.collect(ctx, nodeFixture("node-a"), l, client); e != ErrLeaseLost {
		t.Fatal("stale worker advanced metric state", e)
	}
}
func TestVictoriaMetricsImportAndQuery(t *testing.T) {
	base := os.Getenv("WEBSCAN_V3_TEST_VM")
	if base == "" {
		t.Skip("set WEBSCAN_V3_TEST_VM to an isolated VictoriaMetrics instance")
	}
	m := &Metrics{WriteURL: base, QueryURL: base, HTTP: &http.Client{Timeout: 5 * time.Second}}
	ctx := context.Background()
	node := "test-" + token()[:12]
	at := time.Now().Add(-time.Minute).Truncate(time.Second)
	if e := m.Write(ctx, node, []*agentv1.MetricsSample{{UnixMillis: at.UnixMilli(), PrometheusText: []byte("node_memory_MemTotal_bytes 1024\n")}}); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		raw, e := m.Range(ctx, node, "node_memory_MemTotal_bytes", at.Add(-time.Minute), at.Add(time.Minute))
		if e == nil && strings.Contains(string(raw), node) && strings.Contains(string(raw), "1024") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(string(raw), e)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
