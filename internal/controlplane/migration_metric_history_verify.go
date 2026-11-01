package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// VerifyMigrationMetricStoreTx rechecks the immutable source, current ledger,
// destination binding and actual VM samples. It never imports, repairs or
// replays data. Callers must supply the current runtime Metrics configuration,
// rather than trusting the destination saved in an old success receipt.
func VerifyMigrationMetricStoreTx(ctx context.Context, tx *sql.Tx, session, revision string, m *Metrics) (bool, error) {
	target, err := migrationMetricTarget(m)
	if err != nil {
		return false, ErrMigrationMetricHistory
	}
	r, count, err := migrationMetricRevisionTx(ctx, tx, session, revision)
	if err != nil {
		return false, ErrMigrationMetricHistory
	}
	evidence, err := MigrationMetricHistoryEvidenceTx(ctx, tx, session, revision)
	if err != nil || !evidence {
		return false, ErrMigrationMetricHistory
	}
	var generation string
	err = tx.QueryRowContext(ctx, "SELECT id FROM v3_migration_metric_runs WHERE session=$1 AND revision=$2", session, revision).Scan(&generation)
	if err == sql.ErrNoRows && count == 0 {
		// No historical samples require no replay record. Still check the current
		// target rather than converting a disconnected time-series store to health.
		selector := migrationMetricSelector(map[string]string{"generation": digest([]byte("legacy-metric-v1:" + session + ":" + revision + ":" + r.Digest)), "source": "legacy-v2"})
		actual, e := migrationMetricExport(ctx, m, []string{selector}, 0, migrationMetricVerificationEnd())
		return e == nil && len(actual) == 0, e
	}
	if err != nil {
		return false, ErrMigrationMetricHistory
	}
	report, err := migrationMetricReportTx(ctx, tx, session, generation)
	if err != nil || report.State != "verified" || report.TargetSHA256 != target || report.Source != r.Source || report.RevisionSHA256 != r.Digest || report.Records != count {
		return false, ErrMigrationMetricHistory
	}
	rows, err := tx.QueryContext(ctx, `SELECT node FROM v3_migration_metric_rows WHERE run=$1 GROUP BY node ORDER BY node COLLATE "C" LIMIT 20001`, generation)
	if err != nil {
		return false, ErrMigrationMetricHistory
	}
	nodes := []string{}
	for rows.Next() {
		var node string
		if rows.Scan(&node) != nil || !identifier.MatchString(node) {
			rows.Close()
			return false, ErrMigrationMetricHistory
		}
		nodes = append(nodes, node)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(nodes) > 20000 {
		return false, ErrMigrationMetricHistory
	}
	if migrationMetricVerifyNodeInventory(ctx, m, generation, nodes) != nil {
		return false, ErrMigrationMetricHistory
	}
	if len(nodes) == 0 {
		selector := migrationMetricSelector(map[string]string{"generation": generation, "source": "legacy-v2"})
		actual, e := migrationMetricExport(ctx, m, []string{selector}, 0, migrationMetricVerificationEnd())
		return e == nil && len(actual) == 0, e
	}
	for _, node := range nodes {
		after := int64(0)
		for {
			rows, err := tx.QueryContext(ctx, `SELECT node,sampled,resolution,origin,point FROM v3_migration_metric_rows WHERE run=$1 AND node=$2 AND sampled>$3 ORDER BY sampled,resolution LIMIT 27`, generation, node, after)
			if err != nil {
				return false, ErrMigrationMetricHistory
			}
			points := []migrationMetricPoint{}
			size := 0
			for rows.Next() {
				var p migrationMetricPoint
				if rows.Scan(&p.Node, &p.Sampled, &p.Resolution, &p.Origin, &p.Raw) != nil || len(p.Raw) > 1<<20 {
					rows.Close()
					return false, ErrMigrationMetricHistory
				}
				size += len(p.Raw)
				if size > 8<<20 {
					rows.Close()
					return false, ErrMigrationMetricHistory
				}
				if json.Unmarshal(p.Raw, &p.Point) != nil || p.Point.Time != p.Sampled {
					rows.Close()
					return false, ErrMigrationMetricHistory
				}
				points = append(points, p)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return false, ErrMigrationMetricHistory
			}
			if len(points) == 0 {
				break
			}
			end := points[min(24, len(points)-1)].Sampled
			n := 0
			for n < len(points) && points[n].Sampled <= end {
				n++
			}
			points = points[:n]
			if err = migrationMetricVerifyPointBatch(ctx, m, generation, points, after+1, end); err != nil {
				return false, ErrMigrationMetricHistory
			}
			after = end
		}
		selector := migrationMetricSelector(map[string]string{"source": "legacy-v2", "generation": generation, "node_id": node})
		extra, err := migrationMetricExport(ctx, m, []string{selector}, after+1, migrationMetricVerificationEnd())
		if err != nil || len(extra) != 0 {
			return false, ErrMigrationMetricHistory
		}
	}
	return true, nil
}

// This is the same maximum future timestamp accepted by the immutable archive
// decoder. Far-future label-index queries can yield empty success responses in
// VM and therefore must not be mistaken for evidence about current samples.
func migrationMetricVerificationEnd() int64 { return time.Now().Add(5 * time.Minute).Unix() }

func migrationMetricVerifyNodeInventory(ctx context.Context, m *Metrics, generation string, expected []string) error {
	selector := migrationMetricSelector(map[string]string{"source": "legacy-v2", "generation": generation})
	q := url.Values{"match[]": {selector}, "start": {"0"}, "end": {strconv.FormatInt(migrationMetricVerificationEnd(), 10)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(m.QueryURL, "/")+"/api/v1/label/node_id/values?"+q.Encode(), nil)
	if err != nil {
		return ErrMigrationMetricHistory
	}
	client := m.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(req)
	if err != nil {
		return ErrMigrationMetricHistory
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	var result struct {
		Status string   `json:"status"`
		Data   []string `json:"data"`
	}
	if err != nil || response.StatusCode != 200 || len(raw) > 8<<20 || json.Unmarshal(raw, &result) != nil || result.Status != "success" || len(result.Data) != len(expected) || len(result.Data) > 20000 {
		return ErrMigrationMetricHistory
	}
	sort.Strings(result.Data)
	for i, node := range result.Data {
		if !identifier.MatchString(node) || node != expected[i] || i > 0 && node == result.Data[i-1] {
			return ErrMigrationMetricHistory
		}
	}
	return nil
}

func migrationMetricVerifyPointBatch(ctx context.Context, m *Metrics, generation string, points []migrationMetricPoint, start, end int64) error {
	if len(points) == 0 {
		return ErrMigrationMetricHistory
	}
	expected := []migrationMetricLine{}
	size := 0
	oversized := false
	for _, p := range points {
		payload, lines, err := p.project(generation)
		if err != nil {
			return ErrMigrationMetricHistory
		}
		size += len(payload)
		if size > 8<<20 || len(expected)+len(lines) > 18000 {
			oversized = true
			break
		}
		expected = append(expected, lines...)
	}
	if oversized {
		// Split only between timestamps, keeping both resolutions together. An
		// indivisible oversized timestamp remains unverified rather than dropping
		// sibling resolutions or hiding data outside a narrower selector.
		middle := len(points) / 2
		for middle < len(points) && middle > 0 && points[middle].Sampled == points[middle-1].Sampled {
			middle++
		}
		if middle > 0 && middle < len(points) {
			boundary := points[middle-1].Sampled
			if migrationMetricVerifyPointBatch(ctx, m, generation, points[:middle], start, boundary) != nil {
				return ErrMigrationMetricHistory
			}
			return migrationMetricVerifyPointBatch(ctx, m, generation, points[middle:], boundary+1, end)
		}
		return ErrMigrationMetricHistory
	}
	labels := map[string]string{"source": "legacy-v2", "generation": generation, "node_id": points[0].Node}
	actual, err := migrationMetricExport(ctx, m, []string{migrationMetricSelector(labels)}, start, end)
	if err != nil {
		return ErrMigrationMetricHistory
	}
	want, we := migrationMetricCanonical(expected)
	got, ge := migrationMetricCanonical(actual)
	if we != nil || ge != nil || want != got {
		return ErrMigrationMetricHistory
	}
	return nil
}
