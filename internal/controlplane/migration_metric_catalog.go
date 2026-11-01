package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type MigrationMetricCatalogNode struct {
	ID          string `json:"id"`
	FirstSample int64  `json:"first_sample"`
	LastSample  int64  `json:"last_sample"`
}
type MigrationMetricCatalogSeries struct {
	Metric    string `json:"metric"`
	Dimension string `json:"dimension"`
}
type MigrationMetricCatalog struct {
	Nodes    []MigrationMetricCatalogNode   `json:"nodes"`
	Series   []MigrationMetricCatalogSeries `json:"series"`
	Node     string                         `json:"node"`
	ReadOnly bool                           `json:"read_only"`
}

func (a *API) migrationMetricCatalog(w http.ResponseWriter, r *http.Request, id identity) {
	if r.Method != http.MethodGet {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return
	}
	if id.Role != "admin" {
		failure(w, 403, "permission_denied", "只有管理员可以核对迁移历史")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	allowed := map[string]bool{"session": true, "generation": true, "node": true, "q": true}
	if err == nil {
		for key, values := range q {
			if !allowed[key] || len(values) != 1 || len(values[0]) > 512 {
				err = ErrMigrationMetricHistory
				break
			}
		}
	}
	if err != nil || !validArchiveSource(q.Get("session")) || !validArchiveSource(q.Get("generation")) || q.Get("node") != "" && !identifier.MatchString(q.Get("node")) || len(q.Get("q")) > 128 || !utf8.ValidString(q.Get("q")) || strings.ContainsRune(q.Get("q"), 0) {
		failure(w, 400, "invalid_migration_history_query", "请选择唯一的迁移会话、已核对批次及节点；筛选仅支持节点编号文本")
		return
	}
	if a.Metrics == nil {
		failure(w, 503, "metrics_unavailable", "历史指标服务暂不可用")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	result, err := a.Store.MigrationMetricCatalog(ctx, a.Metrics, q.Get("session"), q.Get("generation"), q.Get("node"), q.Get("q"))
	if err != nil {
		failure(w, 409, "migration_history_unverified", "旧历史尚未通过一致性核对，或迁移批次、时序库状态已变化")
		return
	}
	reply(w, 200, result)
}

// The catalog is derived from the same immutable points as the chart. Every
// selected-node batch is compared with the actual fixed VM destination; a
// historical success receipt alone cannot make an unavailable target readable.
func (s *Store) MigrationMetricCatalog(ctx context.Context, m *Metrics, session, generation, node, filter string) (MigrationMetricCatalog, error) {
	out := MigrationMetricCatalog{Nodes: []MigrationMetricCatalogNode{}, Series: []MigrationMetricCatalogSeries{}, ReadOnly: true}
	if !validArchiveSource(session) || !validArchiveSource(generation) || node != "" && !identifier.MatchString(node) || len(filter) > 128 || !utf8.ValidString(filter) || strings.ContainsRune(filter, 0) {
		return out, ErrMigrationMetricHistory
	}
	target, err := migrationMetricTarget(m)
	if err != nil {
		return out, ErrMigrationMetricHistory
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, ErrMigrationMetricHistory
	}
	defer tx.Rollback()
	report, err := migrationMetricReportTx(ctx, tx, session, generation)
	if err != nil || report.State != "verified" || report.TargetSHA256 != target {
		return out, ErrMigrationMetricHistory
	}
	verified, err := MigrationMetricHistoryEvidenceTx(ctx, tx, session, report.Revision)
	if err != nil || !verified {
		return out, ErrMigrationMetricHistory
	}
	rows, err := tx.QueryContext(ctx, `SELECT node,min(sampled),max(sampled) FROM v3_migration_metric_rows WHERE run=$1 AND position($2 in node)>0 GROUP BY node ORDER BY node COLLATE "C" LIMIT 100`, generation, filter)
	if err != nil {
		return out, ErrMigrationMetricHistory
	}
	for rows.Next() {
		var n MigrationMetricCatalogNode
		if rows.Scan(&n.ID, &n.FirstSample, &n.LastSample) != nil || !identifier.MatchString(n.ID) || n.FirstSample < 1 || n.LastSample < n.FirstSample {
			rows.Close()
			return out, ErrMigrationMetricHistory
		}
		out.Nodes = append(out.Nodes, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, ErrMigrationMetricHistory
	}
	if node == "" && len(out.Nodes) > 0 {
		node = out.Nodes[0].ID
	}
	if node != "" {
		var exists bool
		if tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_migration_metric_rows WHERE run=$1 AND node=$2)", generation, node).Scan(&exists) != nil || !exists {
			return out, ErrMigrationMetricHistory
		}
	}
	out.Node = node
	// Even an empty filtered result verifies target availability. The selector
	// contains only a server-validated generation and never accepts PromQL.
	if node == "" {
		at := time.Now().Unix()
		selector := migrationMetricSelector(map[string]string{"source": "legacy-v2", "generation": generation, "__name__": "webscan_legacy_status"})
		if _, err = migrationMetricExport(ctx, m, []string{selector}, at, at); err != nil {
			return out, ErrMigrationMetricHistory
		}
		if tx.Commit() != nil {
			return out, ErrMigrationMetricHistory
		}
		return out, nil
	}
	series := map[string]MigrationMetricCatalogSeries{}
	after := int64(0)
	for {
		// A timestamp has at most two rows (native and five-minute aggregate).
		// Fetch two extra rows so a page never cuts that timestamp in half.
		rows, err := tx.QueryContext(ctx, `SELECT node,sampled,resolution,origin,point FROM v3_migration_metric_rows WHERE run=$1 AND node=$2 AND sampled>$3 ORDER BY sampled,resolution LIMIT 27`, generation, node, after)
		if err != nil {
			return out, ErrMigrationMetricHistory
		}
		points := []migrationMetricPoint{}
		size := 0
		for rows.Next() {
			var p migrationMetricPoint
			if rows.Scan(&p.Node, &p.Sampled, &p.Resolution, &p.Origin, &p.Raw) != nil || len(p.Raw) > 1<<20 {
				rows.Close()
				return out, ErrMigrationMetricHistory
			}
			size += len(p.Raw)
			if size > 8<<20 {
				rows.Close()
				return out, ErrMigrationMetricHistory
			}
			points = append(points, p)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, ErrMigrationMetricHistory
		}
		if len(points) == 0 {
			break
		}
		end := points[min(24, len(points)-1)].Sampled
		expected := []migrationMetricLine{}
		for _, p := range points {
			if p.Sampled > end {
				break
			}
			if json.Unmarshal(p.Raw, &p.Point) != nil || p.Point.Time != p.Sampled {
				return out, ErrMigrationMetricHistory
			}
			for _, values := range []map[string]float64{p.Point.Values, p.Point.Min, p.Point.Max} {
				for key := range values {
					name, _, dimension, ok := migrationLegacyMetric(key)
					if !ok {
						return out, ErrMigrationMetricHistory
					}
					series[key] = MigrationMetricCatalogSeries{Metric: name, Dimension: dimension}
					if len(series) > 64 {
						return out, ErrMigrationMetricHistory
					}
				}
			}
			_, lines, err := p.project(generation)
			if err != nil {
				return out, ErrMigrationMetricHistory
			}
			expected = append(expected, lines...)
		}
		selector := migrationMetricSelector(map[string]string{"source": "legacy-v2", "generation": generation, "node_id": node})
		actual, err := migrationMetricExport(ctx, m, []string{selector}, points[0].Sampled, end)
		if err != nil {
			return out, ErrMigrationMetricHistory
		}
		want, werr := migrationMetricCanonical(expected)
		got, gerr := migrationMetricCanonical(actual)
		if werr != nil || gerr != nil || want != got {
			return out, ErrMigrationMetricHistory
		}
		after = end
	}
	for _, item := range series {
		out.Series = append(out.Series, item)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		if out.Series[i].Metric == out.Series[j].Metric {
			return out.Series[i].Dimension < out.Series[j].Dimension
		}
		return out.Series[i].Metric < out.Series[j].Metric
	})
	if tx.Commit() != nil {
		return out, ErrMigrationMetricHistory
	}
	return out, nil
}
