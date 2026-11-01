package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"webscan/internal/telemetry"
)

const migrationPrometheusAddress = "http://127.0.0.1:19190"

var migrationPrometheusNames = regexp.MustCompile(`\b(?:node_[A-Za-z0-9_]+|webscan_[A-Za-z0-9_]+|up)\b`)

type migrationPrometheusTask struct {
	From      int64 `json:"from"`
	Until     int64 `json:"until"`
	NodeFrom  int   `json:"node_from"`
	NodeUntil int   `json:"node_until"`
	Query     int   `json:"query"`
}
type migrationPrometheusValue struct {
	Node, Key string
	At        int64
	Value     float64
}
type migrationPrometheusResponse struct {
	Values  []migrationPrometheusValue
	SHA256  string
	Missing int64
}

func migrationPrometheusClient() *http.Client {
	transport := (&http.Transport{MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second}).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "127.0.0.1:19190" {
			return nil, ErrMigrationPrometheus
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrMigrationPrometheus }}
}

func migrationPrometheusExpression(task migrationPrometheusTask, nodes []string) (string, error) {
	if task.Query < 0 || task.Query >= len(telemetry.HistoricalQueries) || task.NodeFrom < 0 || task.NodeUntil > len(nodes) || task.NodeUntil <= task.NodeFrom || task.NodeUntil-task.NodeFrom > 100 {
		return "", ErrMigrationPrometheus
	}
	escaped := []string{}
	for _, node := range nodes[task.NodeFrom:task.NodeUntil] {
		if !identifier.MatchString(node) {
			return "", ErrMigrationPrometheus
		}
		escaped = append(escaped, regexp.QuoteMeta(node))
	}
	filter := "node_id=~" + strconv.Quote("^("+strings.Join(escaped, "|")+")$")
	expression := telemetry.HistoricalQueries[task.Query].Expression
	matches := migrationPrometheusNames.FindAllStringIndex(expression, -1)
	if len(matches) == 0 {
		return "", ErrMigrationPrometheus
	}
	var out strings.Builder
	position := 0
	for _, match := range matches {
		if expression[match[0]:match[1]] == "node_id" {
			continue
		}
		out.WriteString(expression[position:match[1]])
		position = match[1]
		if position < len(expression) && expression[position] == '{' {
			out.WriteByte('{')
			out.WriteString(filter)
			out.WriteByte(',')
			position++
		} else {
			out.WriteByte('{')
			out.WriteString(filter)
			out.WriteByte('}')
		}
	}
	out.WriteString(expression[position:])
	return out.String(), nil
}

func migrationPrometheusFetch(ctx context.Context, client *http.Client, task migrationPrometheusTask, nodes []string) (migrationPrometheusResponse, error) {
	out := migrationPrometheusResponse{}
	expression, err := migrationPrometheusExpression(task, nodes)
	if err != nil {
		return out, err
	}
	if task.From < 1 || task.Until < task.From || task.Until-task.From > 3600 {
		return out, ErrMigrationPrometheus
	}
	q := url.Values{"query": {expression}, "start": {strconv.FormatInt(task.From, 10)}, "end": {strconv.FormatInt(task.Until, 10)}, "step": {"30"}}
	req, err := http.NewRequestWithContext(ctx, "GET", migrationPrometheusAddress+"/api/v1/query_range?"+q.Encode(), nil)
	if err != nil {
		return out, ErrMigrationPrometheus
	}
	response, err := client.Do(req)
	if err != nil {
		return out, ErrMigrationPrometheus
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil || response.StatusCode != 200 {
		return out, ErrMigrationPrometheus
	}
	if len(raw) > 8<<20 {
		return out, telemetry.ErrQueryTooLarge
	}
	var result struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string   `json:"metric"`
				Values [][]json.RawMessage `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Status != "success" || result.Data.ResultType != "matrix" || len(result.Data.Result) > 409600 {
		return out, ErrMigrationPrometheus
	}
	allowed := map[string]bool{}
	for _, node := range nodes[task.NodeFrom:task.NodeUntil] {
		allowed[node] = true
	}
	known := map[string]float64{}
	query := telemetry.HistoricalQueries[task.Query]
	for _, series := range result.Data.Result {
		node := series.Metric["node_id"]
		if !allowed[node] {
			return out, ErrMigrationPrometheus
		}
		name := query.Name
		if query.Dimension != "" {
			dimension := series.Metric[query.Dimension]
			if dimension == "" || len(dimension) > 256 || strings.ContainsRune(dimension, 0) {
				return out, ErrMigrationPrometheus
			}
			name += ":" + dimension
		}
		if _, _, _, ok := migrationLegacyMetric(name); !ok {
			return out, ErrMigrationPrometheus
		}
		for _, sample := range series.Values {
			if len(sample) != 2 {
				return out, ErrMigrationPrometheus
			}
			var number string
			if json.Unmarshal(sample[1], &number) != nil {
				return out, ErrMigrationPrometheus
			}
			at, err := strconv.ParseInt(string(sample[0]), 10, 64)
			if err != nil {
				return out, ErrMigrationPrometheus
			}
			if at < task.From || at > task.Until || (at-task.From)%30 != 0 {
				return out, ErrMigrationPrometheus
			}
			value, err := strconv.ParseFloat(number, 64)
			if err != nil {
				return out, ErrMigrationPrometheus
			}
			if math.IsNaN(value) || math.IsInf(value, 0) {
				out.Missing++
				continue
			}
			if query.Name == "collect_up" && value != 0 && value != 1 {
				return out, ErrMigrationPrometheus
			}
			key := node + "\x00" + strconv.FormatInt(at, 10) + "\x00" + name
			if old, ok := known[key]; ok {
				if old != value {
					return out, ErrMigrationPrometheus
				}
				continue
			}
			known[key] = value
			out.Values = append(out.Values, migrationPrometheusValue{Node: node, Key: name, At: at, Value: value})
		}
	}
	// Include the unmodified API response in the durable receipt's digest. The
	// samples retain returned evaluation timestamps, never fabricated raw counters.
	out.SHA256 = digest(bytes.TrimSpace(raw))
	return out, nil
}
