package controlplane

import (
	"context"
	"encoding/json"
	"time"
)

type MigrationMetricHistoryPoint struct {
	Time              int64    `json:"time"`
	ResolutionSeconds int      `json:"resolution_seconds"`
	Origin            string   `json:"origin"`
	OK                bool     `json:"ok"`
	Value             *float64 `json:"value,omitempty"`
	Min               *float64 `json:"min,omitempty"`
	Max               *float64 `json:"max,omitempty"`
	Count             *int     `json:"count,omitempty"`
}

type MigrationMetricHistoryView struct {
	Session      string                        `json:"session"`
	Generation   string                        `json:"generation"`
	Node         string                        `json:"node"`
	Metric       string                        `json:"metric"`
	Dimension    string                        `json:"dimension,omitempty"`
	Source       string                        `json:"source"`
	Points       []MigrationMetricHistoryPoint `json:"points"`
	ReadOnly     bool                          `json:"read_only"`
	Interpolated bool                          `json:"interpolated"`
}

// An administrator explicitly selects a verified generation before cutover.
// The read never blends staged data with live source=central series, resamples
// five-minute aggregates, fills missing values or runs a caller expression.
func (s *Store) MigrationMetricHistory(ctx context.Context, m *Metrics, session, generation, node, metric, dimension string, start, end time.Time) (MigrationMetricHistoryView, error) {
	out := MigrationMetricHistoryView{Session: session, Generation: generation, Node: node, Metric: metric, Dimension: dimension, Source: "legacy-v2", Points: []MigrationMetricHistoryPoint{}, ReadOnly: true}
	if !identifier.MatchString(node) || !end.After(start) || end.Sub(start) > 31*24*time.Hour || start.Unix() < 1 {
		return out, ErrMigrationMetricHistory
	}
	key := metric
	if dimension != "" {
		key += ":" + dimension
	}
	name, dimensionName, dimensionValue, valid := migrationLegacyMetric(key)
	if !valid || name != metric {
		return out, ErrMigrationMetricHistory
	}
	target, err := migrationMetricTarget(m)
	if err != nil {
		return out, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, ErrMigrationMetricHistory
	}
	defer tx.Rollback()
	report, err := migrationMetricReportTx(ctx, tx, session, generation)
	if err != nil || report.State != "verified" || report.TargetSHA256 != target {
		return out, ErrMigrationMetricHistory
	}
	validEvidence, err := MigrationMetricHistoryEvidenceTx(ctx, tx, session, report.Revision)
	if err != nil || !validEvidence {
		return out, ErrMigrationMetricHistory
	}
	rows, err := tx.QueryContext(ctx, `SELECT node,sampled,resolution,origin,point FROM v3_migration_metric_rows WHERE run=$1 AND node=$2 AND sampled>=$3 AND sampled<=$4 ORDER BY sampled,resolution,origin LIMIT 1001`, generation, node, start.Unix(), end.Unix())
	if err != nil {
		return out, ErrMigrationMetricHistory
	}
	expected := []migrationMetricLine{}
	for rows.Next() {
		var p migrationMetricPoint
		if err := rows.Scan(&p.Node, &p.Sampled, &p.Resolution, &p.Origin, &p.Raw); err != nil {
			rows.Close()
			return out, ErrMigrationMetricHistory
		}
		if json.Unmarshal(p.Raw, &p.Point) != nil {
			rows.Close()
			return out, ErrMigrationMetricHistory
		}
		_, lines, err := p.project(generation)
		if err != nil {
			rows.Close()
			return out, ErrMigrationMetricHistory
		}
		point := MigrationMetricHistoryPoint{Time: p.Sampled, ResolutionSeconds: p.Resolution, Origin: p.Origin, OK: p.Point.OK}
		for _, line := range lines {
			isStatus := line.Metric["__name__"] == "webscan_legacy_status"
			if !isStatus && (line.Metric["metric"] != metric || line.Metric[dimensionName] != dimensionValue) {
				continue
			}
			expected = append(expected, line)
		}
		if value, ok := p.Point.Values[key]; ok {
			point.Value = &value
		}
		if value, ok := p.Point.Min[key]; ok {
			point.Min = &value
		}
		if value, ok := p.Point.Max[key]; ok {
			point.Max = &value
		}
		if value, ok := p.Point.Count[key]; ok {
			point.Count = &value
		}
		out.Points = append(out.Points, point)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(out.Points) > 1000 {
		return out, ErrMigrationMetricHistory
	}
	if err := tx.Commit(); err != nil {
		return out, ErrMigrationMetricHistory
	}
	if len(out.Points) == 0 {
		return out, nil
	}
	labels := map[string]string{"__name__": "webscan_legacy_value", "source": "legacy-v2", "generation": generation, "node_id": node, "metric": metric}
	if dimensionValue != "" {
		labels[dimensionName] = dimensionValue
	}
	statusLabels := map[string]string{"__name__": "webscan_legacy_status", "source": "legacy-v2", "generation": generation, "node_id": node}
	actual, err := migrationMetricExport(ctx, m, []string{migrationMetricSelector(labels), migrationMetricSelector(statusLabels)}, start.Unix(), end.Unix())
	if err != nil {
		return MigrationMetricHistoryView{}, ErrMigrationMetricHistory
	}
	// A query for a scalar must not accidentally include per-device variants.
	filtered := actual[:0]
	series := map[string]bool{}
	for _, line := range actual {
		if line.Metric["__name__"] == "webscan_legacy_value" {
			if dimensionValue == "" && (line.Metric["device"] != "" || line.Metric["mountpoint"] != "" || line.Metric["collector"] != "") {
				continue
			}
		}
		labels, _ := json.Marshal(line.Metric)
		series[string(labels)] = true
		filtered = append(filtered, line)
	}
	if len(series) > 64 {
		return MigrationMetricHistoryView{}, ErrMigrationMetricHistory
	}
	want, werr := migrationMetricCanonical(expected)
	got, gerr := migrationMetricCanonical(filtered)
	if werr != nil || gerr != nil || want != got {
		return MigrationMetricHistoryView{}, ErrMigrationMetricHistory
	}
	return out, nil
}
