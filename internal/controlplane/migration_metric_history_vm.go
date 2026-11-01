package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func migrationMetricTarget(m *Metrics) (string, error) {
	if m == nil {
		return "", ErrMigrationMetricHistory
	}
	for _, address := range []string{m.QueryURL, m.WriteURL} {
		u, err := url.Parse(address)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return "", ErrMigrationMetricHistory
		}
	}
	return digest([]byte(strings.TrimRight(m.QueryURL, "/") + "\n" + strings.TrimRight(m.WriteURL, "/"))), nil
}

func migrationMetricExport(ctx context.Context, m *Metrics, selectors []string, start, end int64) ([]migrationMetricLine, error) {
	if _, err := migrationMetricTarget(m); err != nil {
		return nil, err
	}
	q := url.Values{"start": {strconv.FormatInt(start, 10)}, "end": {strconv.FormatInt(end, 10)}, "reduce_mem_usage": {"1"}, "max_rows_per_line": {"1000"}}
	q["match[]"] = selectors
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(m.QueryURL, "/")+"/api/v1/export?"+q.Encode(), nil)
	if err != nil {
		return nil, ErrMigrationMetricHistory
	}
	client := m.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, ErrMigrationMetricHistory
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if err != nil || response.StatusCode != 200 || len(raw) > 16<<20 {
		return nil, ErrMigrationMetricHistory
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	lines := []migrationMetricLine{}
	for {
		var line migrationMetricLine
		err := decoder.Decode(&line)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrMigrationMetricHistory
		}
		for _, timestamp := range line.Timestamps {
			if timestamp < start*1000 || timestamp > end*1000 {
				return nil, ErrMigrationMetricHistory
			}
		}
		lines = append(lines, line)
		if len(lines) > 20000 {
			return nil, ErrMigrationMetricHistory
		}
	}
	return lines, nil
}

func migrationMetricVerifyVM(ctx context.Context, m *Metrics, selector string, start, end int64, expected []migrationMetricLine) error {
	want, err := migrationMetricCanonical(expected)
	if err != nil {
		return err
	}
	for {
		actual, err := migrationMetricExport(ctx, m, []string{selector}, start, end)
		if err == nil {
			got, err := migrationMetricCanonical(actual)
			if err == nil && got == want {
				return nil
			}
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrMigrationMetricHistory
		case <-timer.C:
		}
	}
}
