package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var errMetricsLayer = errors.New("指标存储层、名称或响应不正确，请选择 history 或 raw；不能提交指标表达式")

func reservedCentralMetric(name string) bool {
	return strings.HasPrefix(name, "webscan_derived_") || strings.HasPrefix(name, "webscan_device_") || strings.HasPrefix(name, "webscan_legacy_")
}

func splitMetricLayers(raw []byte) ([]byte, []byte, error) {
	var history, original bytes.Buffer
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	for {
		var line struct {
			Metric     map[string]string `json:"metric"`
			Values     []float64         `json:"values"`
			Timestamps []int64           `json:"timestamps"`
		}
		if err := decoder.Decode(&line); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, errMetricsLayer
		}
		target := &original
		if reservedCentralMetric(line.Metric["__name__"]) {
			if line.Metric["source"] != "central" {
				return nil, nil, errMetricsLayer
			}
			target = &history
		}
		if err := json.NewEncoder(target).Encode(line); err != nil {
			return nil, nil, errMetricsLayer
		}
	}
	return history.Bytes(), original.Bytes(), nil
}

func (m *Metrics) writeMetricPayload(ctx context.Context, address string, raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	r, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(address, "/")+"/api/v1/import", bytes.NewReader(raw))
	if err != nil {
		return errors.New("时序库地址不正确")
	}
	r.Header.Set("Content-Type", "application/stream+json")
	client := m.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(r)
	if err != nil {
		return errors.New("时序库写入失败")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode/100 != 2 {
		return errors.New("时序库拒绝写入")
	}
	return nil
}

// The existing endpoint continues to select history unless its caller
// explicitly requests raw. Names are plain metric identifiers, never PromQL.
func (m *Metrics) RangeLayer(ctx context.Context, node, name, layer string, start, end time.Time) (json.RawMessage, error) {
	if m == nil || layer != "history" && layer != "raw" || !metricName(name) || layer == "raw" && reservedCentralMetric(name) {
		return nil, errMetricsLayer
	}
	selected := *m
	if layer == "raw" && m.RawURL != "" {
		selected.QueryURL = m.RawURL
	}
	if selected.HTTP == nil {
		selected.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	raw, err := selected.Range(ctx, node, name, start, end)
	if err != nil || layer == "history" {
		return raw, err
	}
	if !validRawMetricRange(raw, node, name, start, end) {
		return nil, errMetricsLayer
	}
	return raw, nil
}

func validRawMetricRange(raw []byte, node, name string, start, end time.Time) bool {
	var result struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string    `json:"metric"`
				Values [][2]json.RawMessage `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Status != "success" || result.Data.ResultType != "matrix" || len(result.Data.Result) > 64 {
		return false
	}
	step := int64(max(30, int(math.Ceil(end.Sub(start).Seconds()/999))))
	seen := map[string]bool{}
	for _, series := range result.Data.Result {
		if series.Metric["node_id"] != node || series.Metric["__name__"] != name || len(series.Values) > 1000 {
			return false
		}
		identity, _ := json.Marshal(series.Metric)
		if seen[string(identity)] {
			return false
		}
		seen[string(identity)] = true
		last := int64(-1)
		for _, pair := range series.Values {
			var stamp float64
			var value string
			if json.Unmarshal(pair[0], &stamp) != nil || stamp != math.Trunc(stamp) || math.IsNaN(stamp) || math.IsInf(stamp, 0) || json.Unmarshal(pair[1], &value) != nil {
				return false
			}
			v, err := strconv.ParseFloat(value, 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				return false
			}
			at := int64(stamp)
			if at < start.Unix() || at > end.Unix() || at <= last || (at-start.Unix())%step != 0 {
				return false
			}
			last = at
		}
	}
	return true
}
