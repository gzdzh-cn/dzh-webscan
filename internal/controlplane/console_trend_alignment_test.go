package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "webscan/sdk/agent/v1"
)

// Short range requests do not exercise VictoriaMetrics' cached-range alignment.
// The browser's default one-hour window starts at arbitrary wall-clock seconds.
func TestConsoleTrendVictoriaMetricsUnalignedHour(t *testing.T) {
	address := os.Getenv("WEBSCAN_V3_TEST_VM")
	if address == "" {
		t.Skip("set WEBSCAN_V3_TEST_VM for isolated VictoriaMetrics")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	m := &Metrics{WriteURL: address, QueryURL: address, HTTP: &http.Client{Timeout: 5 * time.Second}}
	node := fmt.Sprintf("unaligned-%d", time.Now().UnixNano())
	start := time.Now().Add(-2 * time.Hour).Truncate(30 * time.Second).Add(7 * time.Second)
	end := start.Add(time.Hour)
	if err := m.Write(ctx, node, []*agentv1.MetricsSample{
		{UnixMillis: start.UnixMilli(), PrometheusText: []byte("webscan_derived_cpu_percent{source=\"central\"} 0\n")},
		{UnixMillis: end.UnixMilli(), PrometheusText: []byte("webscan_derived_cpu_percent{source=\"central\"} 15\n")},
	}); err != nil {
		t.Fatal(err)
	}
	// Publish the finite synthetic fixture before querying it. A continuously
	// collecting node does not depend on the flush timing of this one-off import.
	flush, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(address, "/")+"/internal/force_flush", nil)
	if err != nil {
		t.Fatal(err)
	}
	flushed, err := m.HTTP.Do(flush)
	if err != nil {
		t.Fatal(err)
	}
	flushed.Body.Close()
	if flushed.StatusCode != http.StatusOK {
		t.Fatal("isolated fixture flush failed", flushed.StatusCode)
	}
	// Import acknowledgement precedes index visibility. Observe the exact raw
	// samples before the first range query, rather than caching an empty rollup.
	visible := false
	selector := `{__name__="webscan_derived_cpu_percent",node_id="` + node + `"}`
	for i := 0; i < 40; i++ {
		req, requestErr := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(address, "/")+"/api/v1/export?match%5B%5D="+url.QueryEscape(selector), nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		response, readErr := m.HTTP.Do(req)
		if readErr == nil {
			raw, bodyErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			response.Body.Close()
			if response.StatusCode == http.StatusOK && bodyErr == nil && strings.Contains(string(raw), node) {
				visible = true
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !visible {
		t.Fatal("isolated VM import not visible before range query")
	}
	var result consoleTrend
	for i := 0; i < 40; i++ {
		result, err = m.consoleRange(ctx, node, start, end)
		if err == nil && len(result.Points) == 121 && result.Points[0].OK && result.Points[120].OK {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("unaligned browser window rejected", err)
	}
	if result.Start != start.Unix() || result.End != end.Unix() || result.Resolution != 30 || len(result.Points) != 121 {
		t.Fatal("requested time grid changed", result)
	}
	first, gap, last := result.Points[0], result.Points[60], result.Points[120]
	if !first.OK || first.Time != start.Unix() || first.Values["cpu_percent"] != 0 || gap.OK || len(gap.Values) != 0 || !last.OK || last.Values["cpu_percent"] != 15 {
		t.Fatal("zero, gap or endpoint lost", first, gap, last)
	}
}

type consoleGridTestTransport struct {
	testing *testing.T
	base    http.RoundTripper
}

func (t consoleGridTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/api/v1/query_range" && r.URL.Query().Get("nocache") != "1" {
		t.testing.Error("range request allows VictoriaMetrics to change the time grid")
	}
	return t.base.RoundTrip(r)
}

func TestConsoleTrendRequestsKeepExactGridAndRejectInvalidSamples(t *testing.T) {
	start := time.Unix(1793000007, 0)
	for _, mode := range []string{"valid", "wrong-node", "outside", "off-grid"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				node, stamp := "grid-node", start.Unix()
				if mode == "wrong-node" {
					node = "other-node"
				} else if mode == "outside" {
					stamp -= 30
				} else if mode == "off-grid" {
					stamp++
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": []any{map[string]any{"metric": map[string]string{"__name__": "webscan_derived_cpu_percent", "node_id": node, "source": "central"}, "values": []any{[]any{stamp, "0"}}}}}})
			}))
			defer server.Close()
			client := server.Client()
			client.Transport = consoleGridTestTransport{testing: t, base: client.Transport}
			m := &Metrics{QueryURL: server.URL, HTTP: client}
			_, err := m.consoleRange(context.Background(), "grid-node", start, start.Add(time.Hour))
			if (err == nil) != (mode == "valid") {
				t.Fatal("sample validation changed", mode, err)
			}
		})
	}
}
