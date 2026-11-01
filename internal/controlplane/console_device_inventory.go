package controlplane

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var errConsoleDeviceInput = errors.New("设备或时间范围不正确，请从当前历史设备清单中选择最多8个设备")
var errConsoleDeviceUnavailable = errors.New("设备历史读取失败，请检查时序库状态")

const consoleDeviceInventoryLimit = 256

type consoleMetricDevice struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Name     string   `json:"name"`
	LastSeen *float64 `json:"last_seen"`
}
type consoleDeviceInventory struct {
	Start     int64                 `json:"start"`
	End       int64                 `json:"end"`
	Items     []consoleMetricDevice `json:"items"`
	Truncated bool                  `json:"truncated"`
}
type consoleDeviceMetric struct{ Metric, Kind, Raw, Unit string }

var consoleDeviceMetrics = []consoleDeviceMetric{
	{"disk_read", "disk", "node_disk_read_bytes_total", "bytes/s"}, {"disk_write", "disk", "node_disk_written_bytes_total", "bytes/s"},
	{"disk_read_iops", "disk", "node_disk_reads_completed_total", "operations/s"}, {"disk_write_iops", "disk", "node_disk_writes_completed_total", "operations/s"},
	{"net_receive", "network", "node_network_receive_bytes_total", "bytes/s"}, {"net_transmit", "network", "node_network_transmit_bytes_total", "bytes/s"},
	{"net_receive_errors", "network", "node_network_receive_errs_total", "packets/s"}, {"net_transmit_errors", "network", "node_network_transmit_errs_total", "packets/s"},
	{"net_receive_drops", "network", "node_network_receive_drop_total", "packets/s"}, {"net_transmit_drops", "network", "node_network_transmit_drop_total", "packets/s"},
}

func validConsoleDeviceName(name string) bool {
	if len(name) < 1 || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.:@-", r)) {
			return false
		}
	}
	return true
}
func consoleDeviceID(kind, name string) string {
	return kind + ":" + base64.RawURLEncoding.EncodeToString([]byte(name))
}
func decodeConsoleDeviceID(id string) (string, string, bool) {
	kind, encoded, ok := strings.Cut(id, ":")
	if !ok || (kind != "disk" && kind != "network") || len(encoded) > 172 {
		return "", "", false
	}
	raw, e := base64.RawURLEncoding.DecodeString(encoded)
	name := string(raw)
	if e != nil || !validConsoleDeviceName(name) || consoleDeviceID(kind, name) != id {
		return "", "", false
	}
	return kind, name, true
}
func consoleDeviceWindow(node string, start, end time.Time) bool {
	return identifier.MatchString(node) && end.After(start) && end.Sub(start) <= 31*24*time.Hour && end.Unix() > start.Unix()
}
func (m *Metrics) deviceQuery(ctx context.Context, path string, query url.Values, limit int) ([]byte, error) {
	if m == nil || m.QueryURL == "" {
		return nil, errConsoleDeviceUnavailable
	}
	request, e := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(m.QueryURL, "/")+path+"?"+query.Encode(), nil)
	if e != nil {
		return nil, errConsoleDeviceUnavailable
	}
	client := m.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	response, e := client.Do(request)
	if e != nil {
		return nil, errConsoleDeviceUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, errConsoleDeviceUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if e != nil || len(raw) > limit {
		return nil, errConsoleDeviceUnavailable
	}
	return raw, nil
}
func (m *Metrics) consoleDeviceInventory(ctx context.Context, node string, start, end time.Time) (consoleDeviceInventory, error) {
	result := consoleDeviceInventory{Start: start.Unix(), End: end.Unix(), Items: []consoleMetricDevice{}}
	if !consoleDeviceWindow(node, start, end) {
		return result, errConsoleDeviceInput
	}
	for _, kind := range []string{"disk", "network"} {
		rawNames, derivedNames := []string{}, []string{}
		for _, metric := range consoleDeviceMetrics {
			if metric.Kind == kind {
				rawNames = append(rawNames, metric.Raw)
				derivedNames = append(derivedNames, "webscan_device_"+metric.Metric)
			}
		}
		derivedNames = append(derivedNames, "webscan_device_"+kind+"_sample_time_seconds")
		identity := ",node_id=" + strconv.Quote(node)
		rawSelector := `{__name__=~` + strconv.Quote(strings.Join(rawNames, "|")) + identity + `}`
		derivedSelector := `{__name__=~` + strconv.Quote(strings.Join(derivedNames, "|")) + identity + `,source="central"}`
		window := "[" + strconv.FormatInt(result.End-result.Start+1, 10) + "s]"
		// Keep the metric name through the union: counters of one device may
		// have different last sample times, all of which must reach max().
		rawLast := "(tlast_over_time(" + rawSelector + window + ") keep_metric_names)"
		derivedLast := "(tlast_over_time(" + derivedSelector + window + ") keep_metric_names)"
		expression := "topk(257,(max by (node_id,device) (" + rawLast + " or on(__name__,node_id,device,source) " + derivedLast + ") >= " + strconv.FormatInt(result.Start, 10) + "))"
		sources := []struct {
			metrics    *Metrics
			expression string
		}{{m, expression}}
		if m.RawURL != "" {
			original := *m
			original.QueryURL = m.RawURL
			sources = append(sources, struct {
				metrics    *Metrics
				expression string
			}{&original, "topk(257,(max by (node_id,device) (" + rawLast + ") >= " + strconv.FormatInt(result.Start, 10) + "))"})
		}
		merged := map[string]consoleMetricDevice{}
		for _, source := range sources {
			raw, e := source.metrics.deviceQuery(ctx, "/api/v1/query", url.Values{"query": {source.expression}, "time": {strconv.FormatInt(result.End, 10)}}, 1<<20)
			if e != nil {
				return result, e
			}
			items, truncated, e := decodeConsoleDeviceInventory(raw, node, kind, result.Start, result.End)
			if e != nil {
				return result, e
			}
			result.Truncated = result.Truncated || truncated
			for _, item := range items {
				previous, ok := merged[item.Name]
				if !ok || *item.LastSeen > *previous.LastSeen {
					merged[item.Name] = item
				}
			}
		}
		items := make([]consoleMetricDevice, 0, len(merged))
		for _, item := range merged {
			items = append(items, item)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		if len(items) > consoleDeviceInventoryLimit {
			result.Truncated = true
			items = items[:consoleDeviceInventoryLimit]
		}
		result.Items = append(result.Items, items...)
	}
	return result, nil
}

func decodeConsoleDeviceInventory(raw []byte, node, kind string, start, end int64) ([]consoleMetricDevice, bool, error) {
	var data struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string  `json:"metric"`
				Value  [2]json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &data) != nil || data.Status != "success" || data.Data.ResultType != "vector" || len(data.Data.Result) > consoleDeviceInventoryLimit+1 {
		return nil, false, errConsoleDeviceUnavailable
	}
	truncated := len(data.Data.Result) > consoleDeviceInventoryLimit
	seen := map[string]bool{}
	items := []consoleMetricDevice{}
	for _, series := range data.Data.Result {
		if series.Metric["node_id"] != node {
			return nil, false, errConsoleDeviceUnavailable
		}
		name := series.Metric["device"]
		if !validConsoleDeviceName(name) {
			truncated = true
			continue
		}
		if seen[name] {
			return nil, false, errConsoleDeviceUnavailable
		}
		seen[name] = true
		var evaluated float64
		var text string
		if json.Unmarshal(series.Value[0], &evaluated) != nil || math.IsNaN(evaluated) || math.IsInf(evaluated, 0) || json.Unmarshal(series.Value[1], &text) != nil {
			return nil, false, errConsoleDeviceUnavailable
		}
		last, e := strconv.ParseFloat(text, 64)
		if e != nil || math.IsNaN(last) || math.IsInf(last, 0) || last < float64(start) || last > float64(end) {
			return nil, false, errConsoleDeviceUnavailable
		}
		items = append(items, consoleMetricDevice{ID: consoleDeviceID(kind, name), Kind: kind, Name: name, LastSeen: &last})
	}
	return items, truncated, nil
}
func (a *API) deviceRequest(w http.ResponseWriter, r *http.Request, node string, withDevices bool) (context.Context, context.CancelFunc, time.Time, time.Time, bool) {
	noCancel := func() {}
	if r.Method != http.MethodGet {
		failure(w, 405, "method_not_allowed", "请使用GET查询设备历史")
		return nil, noCancel, time.Time{}, time.Time{}, false
	}
	if !identifier.MatchString(node) {
		failure(w, 404, "not_found", "服务器不存在")
		return nil, noCancel, time.Time{}, time.Time{}, false
	}
	for name, values := range r.URL.Query() {
		if (name != "start" && name != "end" && !(withDevices && name == "devices")) || name != "devices" && len(values) != 1 {
			failure(w, 400, "invalid_request", errConsoleDeviceInput.Error())
			return nil, noCancel, time.Time{}, time.Time{}, false
		}
	}
	start, end, e := timeRange(r)
	if e != nil || !consoleDeviceWindow(node, start, end) {
		failure(w, 400, "invalid_time", errConsoleDeviceInput.Error())
		return nil, noCancel, start, end, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	var exists int
	e = a.Store.DB.QueryRowContext(ctx, `SELECT 1 FROM v3_nodes WHERE removed_at IS NULL AND id=$1`, node).Scan(&exists)
	if errors.Is(e, sql.ErrNoRows) {
		cancel()
		failure(w, 404, "not_found", "服务器不存在")
		return nil, noCancel, start, end, false
	}
	if e != nil || a.Metrics == nil {
		cancel()
		failure(w, 503, "metrics_unavailable", errConsoleDeviceUnavailable.Error())
		return nil, noCancel, start, end, false
	}
	return ctx, cancel, start, end, true
}
func (a *API) serverMetricDevices(w http.ResponseWriter, r *http.Request, node string) {
	ctx, cancel, start, end, ok := a.deviceRequest(w, r, node, false)
	if !ok {
		return
	}
	defer cancel()
	result, e := a.Metrics.consoleDeviceInventory(ctx, node, start, end)
	if e != nil {
		failure(w, 503, "metrics_unavailable", errConsoleDeviceUnavailable.Error())
		return
	}
	reply(w, 200, result)
}
