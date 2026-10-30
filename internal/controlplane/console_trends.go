package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var consoleTrendMetrics = strings.Fields("cpu_percent cpu_user_percent cpu_system_percent cpu_iowait_percent memory_used memory_available swap_percent load1 load5 load15 disk_percent disk_read disk_write disk_read_iops disk_write_iops net_receive net_transmit net_receive_errors net_transmit_errors net_receive_drops net_transmit_drops webscan_local_pending_events webscan_pending_scans webscan_agent_heartbeat_seconds webscan_local_probe_seconds webscan_probe_received_seconds webscan_probe_query_seconds")

type consoleTrendPoint struct {
	Time   int64              `json:"time"`
	OK     bool               `json:"ok"`
	Values map[string]float64 `json:"values"`
}
type consoleTrend struct {
	Points     []consoleTrendPoint `json:"points"`
	Resolution int64               `json:"resolution_seconds"`
	Start      int64               `json:"start"`
	End        int64               `json:"end"`
}

// One fixed, node-scoped query replaces a request per chart/series. No caller
// supplied PromQL, upstream URL, label or metric name is accepted here.
func (m *Metrics) consoleRange(ctx context.Context, node string, start, end time.Time) (consoleTrend, error) {
	result := consoleTrend{Points: []consoleTrendPoint{}, Start: start.Unix(), End: end.Unix()}
	if !identifier.MatchString(node) || !end.After(start) || end.Sub(start) > 31*24*time.Hour {
		return result, errors.New("指标查询参数不正确")
	}
	result.Resolution = int64(max(30, int(math.Ceil(end.Sub(start).Seconds()/999))))
	selector := `{__name__=~"webscan_derived_(` + strings.Join(consoleTrendMetrics, "|") + `)",node_id=` + strconv.Quote(node) + `,source="central"}`
	// Bound sample age explicitly: upstream lookback must not turn a disconnected
	// node into a continuous healthy curve. Short gaps remain empty after 60 s.
	query := selector + " and (time() - timestamp(" + selector + ") <= 60)"
	q := url.Values{"query": {query}, "start": {strconv.FormatInt(result.Start, 10)}, "end": {strconv.FormatInt(result.End, 10)}, "step": {strconv.FormatInt(result.Resolution, 10)}}
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(m.QueryURL, "/")+"/api/v1/query_range?"+q.Encode(), nil)
	if err != nil {
		return result, err
	}
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return result, errors.New("时序库查询失败")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return result, errors.New("时序库查询失败")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if err != nil || len(raw) > 8<<20 {
		return result, errors.New("时序库响应超限")
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
		return result, errors.New("时序库响应无效")
	}
	allowed := map[string]bool{}
	for _, name := range consoleTrendMetrics {
		allowed[name] = true
	}
	points := map[int64]map[string]float64{}
	for _, series := range data.Data.Result {
		key := strings.TrimPrefix(series.Metric["__name__"], "webscan_derived_")
		if !allowed[key] || series.Metric["node_id"] != node || series.Metric["source"] != "central" || len(series.Values) > 1000 {
			return result, errors.New("时序库返回了不匹配的指标")
		}
		for _, pair := range series.Values {
			var stamp float64
			var text string
			if json.Unmarshal(pair[0], &stamp) != nil || json.Unmarshal(pair[1], &text) != nil || math.IsNaN(stamp) || math.IsInf(stamp, 0) {
				return result, errors.New("指标样本格式不正确")
			}
			at := int64(stamp)
			if at < result.Start || at > result.End {
				return result, errors.New("指标样本时间不正确")
			}
			v, err := strconv.ParseFloat(text, 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			// Range endpoints use whole seconds and the fixed step above.
			if (at-result.Start)%result.Resolution != 0 {
				return result, errors.New("指标样本步长不正确")
			}
			if points[at] == nil {
				points[at] = map[string]float64{}
			}
			points[at][key] = v
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

func (a *API) serverTrends(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return
	}
	if !identifier.MatchString(id) {
		failure(w, 404, "not_found", "服务器不存在")
		return
	}
	start, end, err := timeRange(r)
	if err != nil {
		failure(w, 400, "invalid_time", "时间范围不正确，最多 31 天")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var exists int
	err = a.Store.DB.QueryRowContext(ctx, "SELECT 1 FROM v3_nodes WHERE removed_at IS NULL AND id=$1", id).Scan(&exists)
	if err == sql.ErrNoRows {
		failure(w, 404, "not_found", "服务器不存在")
		return
	}
	if err != nil {
		failure(w, 503, "query_failed", "服务器暂时不可用")
		return
	}
	if a.Metrics == nil {
		failure(w, 503, "metrics_unavailable", "指标查询暂不可用")
		return
	}
	result, err := a.Metrics.consoleRange(ctx, id, start, end)
	if err != nil {
		failure(w, 503, "metrics_unavailable", "历史指标读取失败，请检查时序库状态")
		return
	}
	reply(w, 200, result)
}
