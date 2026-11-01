package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConsoleDeviceInventoryMergesBoundedRawAndHistorySources(t *testing.T) {
	start := time.Unix(1700000000, 0)
	end := start.Add(time.Hour)
	var historyCalls, rawCalls atomic.Int32
	history := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		historyCalls.Add(1)
		query := r.URL.Query().Get("query")
		if !strings.Contains(query, "sample_time_seconds") || !strings.Contains(query, `source="central"`) {
			t.Error("history inventory omitted trusted first-sample markers")
		}
		names := []string{}
		if strings.Contains(query, "node_disk_") {
			names = []string{"history-only", "overlap"}
		}
		_ = json.NewEncoder(w).Encode(deviceVMVector("dual-inventory", end.Unix()-30, names...))
	}))
	defer history.Close()
	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawCalls.Add(1)
		query := r.URL.Query().Get("query")
		if strings.Contains(query, "webscan_device_") || !strings.Contains(query, "topk(257,") {
			t.Error("raw inventory selector crossed layers or lost bound")
		}
		names := []string{}
		if strings.Contains(query, "node_disk_") {
			names = []string{"raw-only", "overlap"}
		}
		_ = json.NewEncoder(w).Encode(deviceVMVector("dual-inventory", end.Unix(), names...))
	}))
	defer raw.Close()
	m := &Metrics{QueryURL: history.URL, RawURL: raw.URL, HTTP: history.Client()}
	devices, err := m.consoleDeviceInventory(context.Background(), "dual-inventory", start, end)
	if err != nil || len(devices.Items) != 3 || devices.Truncated || historyCalls.Load() != 2 || rawCalls.Load() != 2 {
		t.Fatal(devices, historyCalls.Load(), rawCalls.Load(), err)
	}
	for _, item := range devices.Items {
		if item.Name == "overlap" && *item.LastSeen != float64(end.Unix()) {
			t.Fatal("inventory discarded newer raw identity", item)
		}
	}
	legacy := *m
	legacy.RawURL = ""
	if _, err := legacy.consoleDeviceInventory(context.Background(), "dual-inventory", start, end); err != nil || historyCalls.Load() != 4 || rawCalls.Load() != 2 {
		t.Fatal("empty RawURL changed legacy request count", err)
	}
}

func TestConsoleDeviceInventoryMergedBudgetAndRawFailureAreExplicit(t *testing.T) {
	start := time.Unix(1700000000, 0)
	end := start.Add(time.Hour)
	var fail atomic.Bool
	server := func(prefix string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if prefix == "raw" && fail.Load() {
				w.WriteHeader(503)
				return
			}
			names := []string{}
			if strings.Contains(r.URL.Query().Get("query"), "node_disk_") {
				for i := 0; i < 200; i++ {
					names = append(names, fmt.Sprintf("%s-%03d", prefix, i))
				}
			}
			_ = json.NewEncoder(w).Encode(deviceVMVector("merged-budget", end.Unix(), names...))
		}))
	}
	history, raw := server("history"), server("raw")
	defer history.Close()
	defer raw.Close()
	m := &Metrics{QueryURL: history.URL, RawURL: raw.URL, HTTP: history.Client()}
	devices, err := m.consoleDeviceInventory(context.Background(), "merged-budget", start, end)
	if err != nil || len(devices.Items) != 256 || !devices.Truncated {
		t.Fatal("merged source budget hidden", len(devices.Items), devices.Truncated, err)
	}
	fail.Store(true)
	if _, err := m.consoleDeviceInventory(context.Background(), "merged-budget", start, end); err == nil {
		t.Fatal("missing raw source presented as a complete inventory")
	}
}

func deviceVMVector(node string, end int64, names ...string) map[string]any {
	rows := []any{}
	for _, name := range names {
		rows = append(rows, map[string]any{"metric": map[string]string{"node_id": node, "device": name}, "value": []any{end, strconv.FormatInt(end, 10)}})
	}
	return map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": rows}}
}
func deviceVMMatrix(rows []any) map[string]any {
	return map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": rows}}
}
func deviceVMSeries(node, metric, name string, values ...any) map[string]any {
	return map[string]any{"metric": map[string]string{"__name__": "webscan_device_" + metric, "node_id": node, "source": "central", "device": name}, "values": values}
}
func deviceMockMetrics(t *testing.T, node string, end int64, matrix func() map[string]any) *Metrics {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.Query().Get("query"), `node_id="`+node+`"`) {
			t.Error("query escaped node scope")
		}
		if r.URL.Path == "/api/v1/query_range" {
			_ = json.NewEncoder(w).Encode(matrix())
			return
		}
		if r.URL.Path != "/api/v1/query" || !strings.Contains(r.URL.Query().Get("query"), "topk(257,") || !strings.Contains(r.URL.Query().Get("query"), "tlast_over_time(") {
			t.Error("unbounded device inventory query")
		}
		name := "sda"
		if strings.Contains(r.URL.Query().Get("query"), "node_network_") {
			name = "eth0"
		}
		_ = json.NewEncoder(w).Encode(deviceVMVector(node, end, name))
	}))
	t.Cleanup(server.Close)
	return &Metrics{QueryURL: server.URL, HTTP: server.Client()}
}
func TestConsoleDeviceInventoryUsesHistoricalFixedAllowlistAndSafeIdentity(t *testing.T) {
	start := time.Unix(1700000000, 0)
	end := start.Add(time.Hour)
	m := deviceMockMetrics(t, "inventory-node", end.Unix(), func() map[string]any { return deviceVMMatrix(nil) })
	result, e := m.consoleDeviceInventory(context.Background(), "inventory-node", start, end)
	if e != nil || len(result.Items) != 2 || result.Truncated {
		t.Fatal(result, e)
	}
	if result.Start != start.Unix() || result.End != end.Unix() || result.Items[0].Kind != "disk" || result.Items[1].Kind != "network" {
		t.Fatal("inventory lost kind/window", result)
	}
	for _, device := range result.Items {
		kind, name, ok := decodeConsoleDeviceID(device.ID)
		if !ok || kind != device.Kind || name != device.Name || device.LastSeen == nil || *device.LastSeen != float64(end.Unix()) {
			t.Fatal("inventory fabricated identity or last seen", device)
		}
	}
	for _, tc := range []struct {
		node       string
		start, end time.Time
	}{{`node"} or vector(1)`, start, end}, {"inventory-node", end, start}, {"inventory-node", start, start.Add(32 * 24 * time.Hour)}} {
		if _, e = m.consoleDeviceInventory(context.Background(), tc.node, tc.start, tc.end); e == nil {
			t.Fatal("unsafe inventory input accepted")
		}
	}
}
func TestConsoleDeviceInventoryCapsResponseAndMarksTruncation(t *testing.T) {
	start := time.Unix(1700000000, 0)
	end := start.Add(time.Hour)
	for _, count := range []int{257, 258} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				names := []string{}
				if strings.Contains(r.URL.Query().Get("query"), "node_disk_") {
					for i := 0; i < count; i++ {
						names = append(names, fmt.Sprintf("disk%03d", i))
					}
				}
				_ = json.NewEncoder(w).Encode(deviceVMVector("cap-node", end.Unix(), names...))
			}))
			defer server.Close()
			m := &Metrics{QueryURL: server.URL, HTTP: server.Client()}
			result, e := m.consoleDeviceInventory(context.Background(), "cap-node", start, end)
			if count == 257 {
				if e != nil || !result.Truncated || len(result.Items) != 256 {
					t.Fatal("inventory truncation hidden", len(result.Items), result.Truncated, e)
				}
			} else if e == nil {
				t.Fatal("upstream ignored server budget")
			}
		})
	}
}
func TestConsoleDeviceInventoryRejectsUntrustedUpstreamShapeAndScope(t *testing.T) {
	start := time.Unix(1700000000, 0)
	end := start.Add(time.Hour)
	for _, mode := range []string{"node", "timestamp", "duplicate", "oversize", "status"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "oversize" {
					_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
					return
				}
				node := "scope-node"
				last := end.Unix()
				names := []string{"sda"}
				if mode == "node" {
					node = "different"
				}
				if mode == "timestamp" {
					last = start.Unix() - 1
				}
				if mode == "duplicate" {
					names = append(names, "sda")
				}
				data := deviceVMVector(node, last, names...)
				if mode == "status" {
					data["status"] = "error"
				}
				_ = json.NewEncoder(w).Encode(data)
			}))
			defer server.Close()
			m := &Metrics{QueryURL: server.URL, HTTP: server.Client()}
			if _, e := m.consoleDeviceInventory(context.Background(), "scope-node", start, end); e == nil {
				t.Fatal("unsafe inventory response accepted", mode)
			}
		})
	}
}
func TestConsoleDeviceInventoryDoesNotExposeInvalidDeviceNames(t *testing.T) {
	start := time.Unix(1700000000, 0)
	end := start.Add(time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(deviceVMVector("safe-node", end.Unix(), `eth0"} or vector(1)`, `/private/site/path`))
	}))
	defer server.Close()
	m := &Metrics{QueryURL: server.URL, HTTP: server.Client()}
	result, e := m.consoleDeviceInventory(context.Background(), "safe-node", start, end)
	if e != nil || len(result.Items) != 0 || !result.Truncated {
		t.Fatal("untrusted device names escaped", result, e)
	}
}
