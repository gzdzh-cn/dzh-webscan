package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestConsoleDeviceTrendsReturnSeparateSeriesAndLeaveMissingValuesEmpty(t *testing.T) {
	start := time.Unix(1700000000, 0)
	end := start.Add(time.Minute)
	m := deviceMockMetrics(t, "trend-node", end.Unix(), func() map[string]any {
		return deviceVMMatrix([]any{deviceVMSeries("trend-node", "disk_read", "sda", []any{start.Unix() + 30, "12.5"}), deviceVMSeries("trend-node", "net_receive", "eth0", []any{start.Unix() + 30, "0"})})
	})
	result, e := m.consoleDeviceRange(context.Background(), "trend-node", start, end, []string{consoleDeviceID("disk", "sda"), consoleDeviceID("network", "eth0")})
	if e != nil {
		t.Fatal(e)
	}
	if len(result.Points) != 3 || len(result.Devices) != 2 || len(result.Series) != 10 || result.Points[0].OK || len(result.Points[0].Values) != 0 || !result.Points[1].OK || result.Points[2].OK {
		t.Fatal("missing samples filled or separate metadata lost", result)
	}
	if result.Points[1].Values[consoleDeviceID("disk", "sda")+":disk_read"] != 12.5 {
		t.Fatal("device value lost")
	}
	if zero, ok := result.Points[1].Values[consoleDeviceID("network", "eth0")+":net_receive"]; !ok || zero != 0 {
		t.Fatal("real zero counter rate lost")
	}
	for _, series := range result.Series {
		if series.Unit == "" || series.Key != series.DeviceID+":"+series.Metric {
			t.Fatal("ambiguous series metadata", series)
		}
	}
}
func TestConsoleDeviceTrendsValidateSelectionBeforeExecutingExpressions(t *testing.T) {
	start := time.Unix(1700000000, 0)
	end := start.Add(time.Minute)
	m := deviceMockMetrics(t, "selection-node", end.Unix(), func() map[string]any { t.Error("invalid selection executed range query"); return deviceVMMatrix(nil) })
	selections := [][]string{nil, {consoleDeviceID("disk", "unknown")}, {consoleDeviceID("disk", "sda"), consoleDeviceID("disk", "sda")}, {`disk:invalid"} or vector(1)`}}
	many := []string{}
	for i := 0; i < 9; i++ {
		many = append(many, consoleDeviceID("network", fmt.Sprintf("eth%d", i)))
	}
	selections = append(selections, many)
	for _, ids := range selections {
		if _, e := m.consoleDeviceRange(context.Background(), "selection-node", start, end, ids); !errors.Is(e, errConsoleDeviceInput) {
			t.Fatal("invalid selection accepted", ids, e)
		}
	}
}
func TestConsoleDeviceTrendsRejectMismatchedUnboundedAndMalformedSeries(t *testing.T) {
	start := time.Unix(1700000000, 0)
	end := start.Add(time.Minute)
	for _, mode := range []string{"node", "metric", "device", "duplicate-series", "too-many-series", "too-many-points", "fractional-time", "misaligned-time", "outside-time", "missing-source"} {
		t.Run(mode, func(t *testing.T) {
			m := deviceMockMetrics(t, "shape-node", end.Unix(), func() map[string]any {
				node, metric, device := "shape-node", "disk_read", "sda"
				stamp := float64(start.Unix() + 30)
				if mode == "node" {
					node = "other"
				}
				if mode == "metric" {
					metric = "cpu_percent"
				}
				if mode == "device" {
					device = "sdb"
				}
				if mode == "fractional-time" {
					stamp += 0.5
				}
				if mode == "misaligned-time" {
					stamp++
				}
				if mode == "outside-time" {
					stamp = float64(start.Unix() - 30)
				}
				values := []any{[]any{stamp, "1"}}
				if mode == "too-many-points" {
					for len(values) < 1001 {
						values = append(values, []any{stamp, "1"})
					}
				}
				row := deviceVMSeries(node, metric, device, values...)
				if mode == "missing-source" {
					row["metric"].(map[string]string)["source"] = "agent"
				}
				rows := []any{row}
				if mode == "duplicate-series" {
					rows = append(rows, row)
				}
				if mode == "too-many-series" {
					for len(rows) < 65 {
						rows = append(rows, row)
					}
				}
				return deviceVMMatrix(rows)
			})
			if _, e := m.consoleDeviceRange(context.Background(), "shape-node", start, end, []string{consoleDeviceID("disk", "sda")}); !errors.Is(e, errConsoleDeviceUnavailable) {
				t.Fatal("malformed range accepted", mode, e)
			}
		})
	}
}
func TestConsoleDeviceTrendsBound31DayResolution(t *testing.T) {
	start := time.Unix(1700000000, 0)
	end := start.Add(31 * 24 * time.Hour)
	m := deviceMockMetrics(t, "bound-node", end.Unix(), func() map[string]any { return deviceVMMatrix(nil) })
	result, e := m.consoleDeviceRange(context.Background(), "bound-node", start, end, []string{consoleDeviceID("disk", "sda")})
	if e != nil || len(result.Points) > 1000 || len(result.Series) > 64 {
		t.Fatal("range budget exceeded", len(result.Points), e)
	}
}
func TestConsoleDeviceHTTPRequiresSessionAndExistingNodeWithStrictQuery(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	node := nodeFixture("http-device")
	if e := s.PutNode(ctx, node, 0, 256); e != nil {
		t.Fatal(e)
	}
	session := historyAPISession(t, s, "reader", "viewer")
	start := time.Unix(1700000000, 0)
	end := start.Add(time.Minute)
	api := NewAPI(s, Config{})
	api.Metrics = deviceMockMetrics(t, node.ID, end.Unix(), func() map[string]any { return deviceVMMatrix(nil) })
	call := func(method, path, session string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://local/api/v3/servers/"+path, nil)
		if session != "" {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: session})
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	values := url.Values{"start": {start.Format(time.RFC3339)}, "end": {end.Format(time.RFC3339)}}
	query := values.Encode()
	for _, suffix := range []string{"metric-devices", "device-metrics"} {
		if w := call("GET", node.ID+"/"+suffix+"?"+query, ""); w.Code != 401 {
			t.Fatal("anonymous devices visible", w.Code)
		}
		if w := call("GET", "missing/"+suffix+"?"+query, session); w.Code != 404 {
			t.Fatal("missing node queried", w.Code)
		}
	}
	if w := call("GET", node.ID+"/metric-devices?"+query, session); w.Code != 200 {
		t.Fatal("viewer inventory unavailable", w.Code, w.Body.String())
	}
	values.Add("devices", consoleDeviceID("disk", "sda"))
	if w := call("GET", node.ID+"/device-metrics?"+values.Encode(), session); w.Code != 200 {
		t.Fatal("viewer historical devices unavailable", w.Code, w.Body.String())
	}
	for _, extra := range []string{"&query=up", "&start=" + url.QueryEscape(start.Format(time.RFC3339)), "&devices=" + url.QueryEscape(`disk:bad"} or up`)} {
		path := "device-metrics"
		if strings.Contains(extra, "query=") {
			path = "metric-devices"
		}
		if w := call("GET", node.ID+"/"+path+"?"+query+extra, session); w.Code != 400 {
			t.Fatal("noncanonical device query accepted", w.Code, w.Body.String())
		}
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET removed_at=clock_timestamp() WHERE id=$1`, node.ID)
	if w := call("GET", node.ID+"/metric-devices?"+query, session); w.Code != 404 {
		t.Fatal("removed node history inventory visible", w.Code)
	}
}
