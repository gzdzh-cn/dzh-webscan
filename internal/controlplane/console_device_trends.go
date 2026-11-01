package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type consoleDeviceSeries struct {
	Key      string `json:"key"`
	DeviceID string `json:"device_id"`
	Metric   string `json:"metric"`
	Unit     string `json:"unit"`
}
type consoleDeviceTrend struct {
	Points     []consoleTrendPoint   `json:"points"`
	Resolution int64                 `json:"resolution_seconds"`
	Start      int64                 `json:"start"`
	End        int64                 `json:"end"`
	Devices    []consoleMetricDevice `json:"devices"`
	Series     []consoleDeviceSeries `json:"series"`
}

func (m *Metrics) consoleDeviceRange(ctx context.Context, node string, start, end time.Time, ids []string) (consoleDeviceTrend, error) {
	result := consoleDeviceTrend{Points: []consoleTrendPoint{}, Start: start.Unix(), End: end.Unix(), Devices: []consoleMetricDevice{}, Series: []consoleDeviceSeries{}}
	if !consoleDeviceWindow(node, start, end) || len(ids) < 1 || len(ids) > 8 {
		return result, errConsoleDeviceInput
	}
	requested := map[string]bool{}
	for _, id := range ids {
		if _, _, ok := decodeConsoleDeviceID(id); !ok || requested[id] {
			return result, errConsoleDeviceInput
		}
		requested[id] = true
	}
	inventory, e := m.consoleDeviceInventory(ctx, node, start, end)
	if e != nil {
		return result, e
	}
	names := map[string][]string{}
	selected := map[string]consoleMetricDevice{}
	for _, device := range inventory.Items {
		if requested[device.ID] {
			result.Devices = append(result.Devices, device)
			selected[device.ID] = device
			names[device.Kind] = append(names[device.Kind], regexp.QuoteMeta(device.Name))
		}
	}
	if len(selected) != len(requested) {
		return result, errConsoleDeviceInput
	}
	expressions := []string{}
	allowed := map[string]consoleDeviceSeries{}
	for _, metric := range consoleDeviceMetrics {
		if len(names[metric.Kind]) == 0 {
			continue
		}
		labels := `,node_id=` + strconv.Quote(node) + `,source="central",device=~` + strconv.Quote(strings.Join(names[metric.Kind], "|"))
		selector := `{__name__=` + strconv.Quote("webscan_device_"+metric.Metric) + labels + `}`
		marker := `{__name__=` + strconv.Quote("webscan_device_"+metric.Kind+"_sample_time_seconds") + labels + `}`
		// A current marker invalidates prior rate samples after resets, missing
		// counters or disappearance. Missing data never becomes a synthetic zero.
		// Explicit windows avoid VictoriaMetrics' adaptive lookback varying with
		// the query step or the surrounding series' sampling density. The age
		// predicate still caps the original sample at sixty seconds.
		latest := `(last_over_time(` + selector + `[61s]) keep_metric_names)`
		stamp := `tlast_over_time(` + selector + `[61s])`
		current := `(` + stamp + ` == on(node_id,device) last_over_time(` + marker + `[61s]))`
		expressions = append(expressions, `(`+latest+` and on(node_id,device) `+current+` and (time()-`+stamp+` <= 60))`)
		for _, device := range result.Devices {
			if device.Kind == metric.Kind {
				series := consoleDeviceSeries{Key: device.ID + ":" + metric.Metric, DeviceID: device.ID, Metric: metric.Metric, Unit: metric.Unit}
				result.Series = append(result.Series, series)
				allowed[device.ID+":"+metric.Metric] = series
			}
		}
	}
	if len(result.Series) > 64 {
		return result, errConsoleDeviceInput
	}
	sort.Slice(result.Series, func(i, j int) bool { return result.Series[i].Key < result.Series[j].Key })
	result.Resolution = int64(max(30, int(math.Ceil(float64(result.End-result.Start)/999))))
	query := url.Values{"query": {strings.Join(expressions, " or ")}, "start": {strconv.FormatInt(result.Start, 10)}, "end": {strconv.FormatInt(result.End, 10)}, "step": {strconv.FormatInt(result.Resolution, 10)}}
	raw, e := m.deviceQuery(ctx, "/api/v1/query_range", query, 8<<20)
	if e != nil {
		return result, e
	}
	var data struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string    `json:"metric"`
				Values [][2]json.RawMessage `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &data) != nil || data.Status != "success" || data.Data.ResultType != "matrix" || len(data.Data.Result) > 64 {
		return result, errConsoleDeviceUnavailable
	}
	points := map[int64]map[string]float64{}
	seen := map[string]bool{}
	for _, series := range data.Data.Result {
		metric := strings.TrimPrefix(series.Metric["__name__"], "webscan_device_")
		kind := ""
		for _, candidate := range consoleDeviceMetrics {
			if candidate.Metric == metric {
				kind = candidate.Kind
				break
			}
		}
		name := series.Metric["device"]
		id := consoleDeviceID(kind, name)
		key := id + ":" + metric
		if kind == "" || !validConsoleDeviceName(name) || series.Metric["source"] != "central" || series.Metric["node_id"] != node || allowed[key].Key == "" || seen[key] || len(series.Values) > 1000 {
			return result, errConsoleDeviceUnavailable
		}
		seen[key] = true
		for _, pair := range series.Values {
			var stamp float64
			var text string
			if json.Unmarshal(pair[0], &stamp) != nil || math.IsNaN(stamp) || math.IsInf(stamp, 0) || stamp != math.Trunc(stamp) || json.Unmarshal(pair[1], &text) != nil {
				return result, errConsoleDeviceUnavailable
			}
			at := int64(stamp)
			if at < result.Start || at > result.End || (at-result.Start)%result.Resolution != 0 {
				return result, errConsoleDeviceUnavailable
			}
			value, e := strconv.ParseFloat(text, 64)
			if e != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
				continue
			}
			if points[at] == nil {
				points[at] = map[string]float64{}
			}
			if _, duplicate := points[at][key]; duplicate {
				return result, errConsoleDeviceUnavailable
			}
			points[at][key] = value
		}
	}
	for at := result.Start; at <= result.End; at += result.Resolution {
		values := points[at]
		if values == nil {
			values = map[string]float64{}
		}
		result.Points = append(result.Points, consoleTrendPoint{Time: at, OK: len(values) > 0, Values: values})
	}
	return result, nil
}
func (a *API) serverDeviceMetrics(w http.ResponseWriter, r *http.Request, node string) {
	ctx, cancel, start, end, ok := a.deviceRequest(w, r, node, true)
	if !ok {
		return
	}
	defer cancel()
	result, e := a.Metrics.consoleDeviceRange(ctx, node, start, end, r.URL.Query()["devices"])
	if errors.Is(e, errConsoleDeviceInput) {
		failure(w, 400, "invalid_devices", errConsoleDeviceInput.Error())
		return
	}
	if e != nil {
		failure(w, 503, "metrics_unavailable", errConsoleDeviceUnavailable.Error())
		return
	}
	reply(w, 200, result)
}
