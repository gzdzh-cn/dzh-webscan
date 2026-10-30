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

func TestConsoleServerListReadModelAndFilters(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for _, id := range []string{"node-a", "node-b", "node-c"} {
		n := nodeFixture(id)
		n.Config = json.RawMessage(`{"password":"private-node-config"}`)
		if id == "node-b" {
			n.Enabled = false
		}
		if err := s.PutNode(ctx, n, 0, 256); err != nil {
			t.Fatal(err)
		}
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_node_status(node,sampled_at,metrics,info) VALUES('node-a',(extract(epoch FROM clock_timestamp())*1000)::bigint,'{"cpu_percent":0,"memory_percent":42,"disk_percent":"bad","disk_percent:/srv":10,"private_numeric":99,"secret":"private-metric"}','{"agent_version":"v3.test","agent_mode":"docker","password":"private-info"}')`)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_node_status(node,sampled_at,metrics) VALUES('node-c',(extract(epoch FROM clock_timestamp()-interval '10 minutes')*1000)::bigint,'{"cpu_percent":5}')`)
	if _, err := s.consoleNodes(ctx, "", "", "", 20, 30); err != nil {
		t.Fatal(err)
	}
	a := &API{Store: s}
	session := historyAPISession(t, s, "viewer", "viewer")
	call := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: session})
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	w := call("/api/v3/servers?limit=20&status=normal&q=192.0.2")
	var result struct {
		Items []struct {
			ID     string `json:"id"`
			State  string `json:"collection_state"`
			Status struct {
				Metrics map[string]*float64 `json:"metrics"`
			} `json:"status"`
		} `json:"items"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Items) != 1 || result.Items[0].ID != "node-a" || result.Items[0].State != "normal" {
		t.Fatal(w.Code, w.Body.String())
	}
	metrics := result.Items[0].Status.Metrics
	if metrics["cpu_percent"] == nil || *metrics["cpu_percent"] != 0 || metrics["disk_percent"] != nil || metrics["disk_percent:/srv"] == nil {
		t.Fatal("unknown/zero projection", w.Body.String())
	}
	for _, secret := range []string{"private-node-config", "private-info", "private-metric", "private_numeric"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("private metadata leaked", secret)
		}
	}
	for state, id := range map[string]string{"disabled": "node-b", "stale": "node-c"} {
		w := call("/api/v3/servers?status=" + state)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"`+id+`"`) {
			t.Fatal(state, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/api/v3/servers?status=bad", "/api/v3/servers?limit=999", "/api/v3/servers?cursor=not-valid!"} {
		if w := call(path); w.Code != 400 {
			t.Fatal(path, w.Code)
		}
	}
	if w := call("/api/v3/servers?q=%25"); w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal("wildcard not escaped", w.Code, w.Body.String())
	}
}

func TestConsoleTrendRangeBoundedIdentityAndMissingValues(t *testing.T) {
	start := time.Unix(1793000000, 0).UTC()
	end := start.Add(60 * time.Second)
	mode := "good"
	requests := 0
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		q := r.URL.Query()
		if !strings.Contains(q.Get("query"), `node_id="node-a"`) || !strings.Contains(q.Get("query"), `source="central"`) || strings.Contains(q.Get("query"), "password") || q.Get("step") != "30" {
			t.Error("unbounded query", q)
		}
		switch mode {
		case "bad-node":
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"webscan_derived_cpu_percent","node_id":"other","source":"central"},"values":[]}]}}`))
			return
		case "failed":
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": []any{map[string]any{"metric": map[string]string{"__name__": "webscan_derived_cpu_percent", "node_id": "node-a", "source": "central"}, "values": []any{[]any{start.Unix(), "0"}, []any{end.Unix(), "NaN"}}}}}})
	}))
	defer vm.Close()
	m := &Metrics{QueryURL: vm.URL, HTTP: vm.Client()}
	v, err := m.consoleRange(context.Background(), "node-a", start, end)
	if err != nil || len(v.Points) != 3 || v.Points[0].Values["cpu_percent"] != 0 || !v.Points[0].OK || v.Points[1].OK || len(v.Points[1].Values) != 0 || v.Points[2].OK {
		t.Fatal("missing data filled", v, err)
	}
	if _, err = m.consoleRange(context.Background(), `node-a"}`, start, end); err == nil || requests != 1 {
		t.Fatal("identity injection accepted")
	}
	if _, err = m.consoleRange(context.Background(), "node-a", start, start.Add(32*24*time.Hour)); err == nil || requests != 1 {
		t.Fatal("unbounded time accepted")
	}
	mode = "bad-node"
	if _, err = m.consoleRange(context.Background(), "node-a", start, end); err == nil {
		t.Fatal("other node's data accepted")
	}
	mode = "failed"
	if _, err = m.consoleRange(context.Background(), "node-a", start, end); err == nil {
		t.Fatal("failure displayed as success")
	}
}

func TestConsoleServerTrendsAuthenticationReadOnlyAndNodeScope(t *testing.T) {
	s := testStore(t)
	n := nodeFixture("node-a")
	if err := s.PutNode(context.Background(), n, 0, 256); err != nil {
		t.Fatal(err)
	}
	a := &API{Store: s}
	session := historyAPISession(t, s, "viewer", "viewer")
	for _, test := range []struct {
		method, path string
		auth         bool
		want         int
	}{{"GET", "/api/v3/servers/node-a/metrics", false, 401}, {"GET", "/api/v3/servers/missing/metrics", true, 404}, {"GET", "/api/v3/servers/node-a/metrics?start=bad", true, 400}, {"GET", "/api/v3/servers/node-a/metrics", true, 503}, {"POST", "/api/v3/servers/node-a/metrics", true, 403}} {
		r := httptest.NewRequest(test.method, test.path, nil)
		if test.auth {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: session})
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != test.want {
			t.Fatal(test, w.Code, w.Body.String())
		}
	}
}

func TestConsoleTrendVictoriaMetricsRealZeroAndGap(t *testing.T) {
	address := os.Getenv("WEBSCAN_V3_TEST_VM")
	if address == "" {
		t.Skip("set WEBSCAN_V3_TEST_VM for isolated VictoriaMetrics")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	m := &Metrics{WriteURL: address, QueryURL: address, HTTP: &http.Client{Timeout: 5 * time.Second}}
	node := fmt.Sprintf("console-%d", time.Now().UnixNano())
	start := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	samples := []*agentv1.MetricsSample{}
	for _, point := range []struct {
		offset time.Duration
		value  string
	}{{0, "0"}, {30 * time.Second, "10"}, {240 * time.Second, "15"}} {
		samples = append(samples, &agentv1.MetricsSample{UnixMillis: start.Add(point.offset).UnixMilli(), PrometheusText: []byte("webscan_derived_cpu_percent{source=\"central\"} " + point.value + "\n")})
	}
	if err := m.Write(ctx, node, samples); err != nil {
		t.Fatal(err)
	}
	// Import acknowledgement precedes storage visibility. Observe the raw series
	// before the first range query so an empty rollup cache cannot make this test
	// depend on the host speed or VictoriaMetrics' periodic cache invalidation.
	selector := `{__name__="webscan_derived_cpu_percent",node_id="` + node + `"}`
	visible := false
	for i := 0; i < 40; i++ {
		req, requestErr := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(address, "/")+"/api/v1/export?match%5B%5D="+url.QueryEscape(selector), nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		response, readErr := m.HTTP.Do(req)
		if readErr == nil {
			raw, bodyErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			response.Body.Close()
			if response.StatusCode == 200 && bodyErr == nil && strings.Contains(string(raw), node) {
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
	var err error
	for i := 0; i < 24; i++ {
		result, err = m.consoleRange(ctx, node, start, start.Add(240*time.Second))
		if err == nil && len(result.Points) > 0 && result.Points[0].OK {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil || len(result.Points) != 9 || !result.Points[0].OK || result.Points[0].Values["cpu_percent"] != 0 || result.Points[4].OK || !result.Points[8].OK || result.Points[8].Values["cpu_percent"] != 15 {
		t.Fatal("real VM zero/gap read", result, err)
	}
}

func TestConsoleNotificationStatisticsChannelNodeAndProtection(t *testing.T) {
	s := testStore(t)
	enqueueNotification(t, s, "node-a", "one", "email", "test@example.test")
	enqueueNotification(t, s, "node-a", "two", "email", "test@example.test")
	enqueueNotification(t, s, "node-a", "three", "email", "test@example.test")
	enqueueNotification(t, s, "node-b", "four", "email", "test@example.test")
	enqueueNotification(t, s, "node-a", "five", "feishu", "")
	mustHistoryExec(t, s.DB, "UPDATE v3_notifications SET done_at=clock_timestamp() WHERE event_id='one'")
	mustHistoryExec(t, s.DB, "UPDATE v3_notifications SET attempts=2 WHERE event_id='three'")
	a := &API{Store: s}
	session := historyAPISession(t, s, "viewer", "viewer")
	call := func(method, path string, auth bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if auth {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: session})
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/v3/notifications/stats?channel=email&node=node-a", false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := call("GET", "/api/v3/notifications/stats?channel=email&node=node-a", true)
	var response struct {
		Items []struct{ Delivered, Pending, Retrying int }
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response.Items) != 7 {
		t.Fatal(w.Code, w.Body.String())
	}
	total := response.Items[6]
	if total.Delivered != 1 || total.Pending != 1 || total.Retrying != 1 {
		t.Fatal(w.Body.String())
	}
	if strings.Contains(w.Body.String(), "test@example.test") || strings.Contains(w.Body.String(), "payload") {
		t.Fatal("private data in counts")
	}
	if w := call("GET", "/api/v3/notifications/stats?channel=other", true); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "/api/v3/notifications/stats?channel=email", true); w.Code != 403 {
		t.Fatal(w.Code)
	}
}
