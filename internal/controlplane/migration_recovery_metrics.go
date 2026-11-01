package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	agentv1 "webscan/sdk/agent/v1"
)

func migrationRecoveryMetricsTarget(m *Metrics) (string, error) {
	target, err := migrationMetricTarget(m)
	if err != nil {
		return "", ErrMigrationRecovery
	}
	if m.RawURL != "" {
		copy := *m
		copy.QueryURL, copy.WriteURL = m.RawURL, m.RawURL
		raw, err := migrationMetricTarget(&copy)
		if err != nil {
			return "", ErrMigrationRecovery
		}
		target = digest([]byte(target + "\n" + raw))
	}
	return target, nil
}
func migrationRecoveryMetricMap(raw []byte) (map[string]string, error) {
	out := map[string]string{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	for {
		var line migrationMetricLine
		err := decoder.Decode(&line)
		if err == io.EOF {
			break
		}
		if err != nil || len(line.Values) == 0 || len(line.Values) != len(line.Timestamps) || !identifier.MatchString(line.Metric["node_id"]) || !metricName(line.Metric["__name__"]) {
			return nil, ErrMigrationRecovery
		}
		labels, _ := json.Marshal(line.Metric)
		for i, value := range line.Values {
			if math.IsNaN(value) || math.IsInf(value, 0) || line.Timestamps[i] < 1 {
				return nil, ErrMigrationRecovery
			}
			if value == 0 {
				value = 0
			}
			key := string(labels) + ":" + strconv.FormatInt(line.Timestamps[i], 10)
			canonical := strconv.FormatFloat(value, 'g', -1, 64)
			if previous, ok := out[key]; ok && previous != canonical {
				return nil, ErrMigrationRecovery
			}
			out[key] = canonical
		}
		if len(out) > 240000 {
			return nil, ErrMigrationRecovery
		}
	}
	return out, nil
}
func migrationRecoveryMetricsExport(ctx context.Context, m *Metrics, node string, start, end int64) (map[string]string, error) {
	lines, err := migrationMetricExport(ctx, m, []string{`{node_id=` + strconv.Quote(node) + `}`}, start/1000, (end+999)/1000)
	if err != nil {
		return nil, ErrMigrationRecovery
	}
	var raw bytes.Buffer
	for _, line := range lines {
		if err := json.NewEncoder(&raw).Encode(line); err != nil {
			return nil, ErrMigrationRecovery
		}
	}
	return migrationRecoveryMetricMap(raw.Bytes())
}
func migrationRecoveryMetricContains(actual, want map[string]string, complete bool) bool {
	for key, value := range want {
		old, exists := actual[key]
		if exists && old != value || complete && !exists {
			return false
		}
	}
	return true
}
func migrationRecoveryVerifyLayer(ctx context.Context, m *Metrics, node string, raw []byte, start, end int64, before bool) error {
	if len(raw) == 0 {
		return nil
	}
	want, err := migrationRecoveryExpectedMetricMap(raw)
	if err != nil {
		return err
	}
	for {
		actual, err := migrationRecoveryMetricsExport(ctx, m, node, start, end)
		if err == nil && migrationRecoveryMetricContains(actual, want, !before) {
			return nil
		}
		if before {
			return ErrMigrationRecovery
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrMigrationRecovery
		case <-timer.C:
		}
	}
}
func (s *Store) migrationRecoveryReadMetricCache(ctx context.Context, c Config, generation string, target migrationRecoveryTarget, m *Metrics) error {
	conn, client, err := migrationRecoveryClient(ctx, c, target)
	if err != nil {
		return err
	}
	defer conn.Close()
	var samples []*agentv1.MetricsSample
	after := int64(0)
	size := 0
	for page := 0; page < 16; page++ {
		batch, err := client.ReadMetrics(ctx, &agentv1.ReadMetricsRequest{AfterUnixMillis: after})
		if err != nil || batch == nil || batch.NodeId != target.Node || len(batch.Samples) > 120 {
			return ErrMigrationRecovery
		}
		if len(batch.Samples) == 0 {
			break
		}
		for _, sample := range batch.Samples {
			if sample == nil || sample.UnixMillis <= after || sample.UnixMillis > time.Now().Add(time.Minute).UnixMilli() {
				return ErrMigrationRecovery
			}
			after = sample.UnixMillis
			size += len(sample.PrometheusText)
			if size > 16<<20 || len(samples) >= 1920 {
				return ErrMigrationRecovery
			}
			samples = append(samples, sample)
		}
		if len(batch.Samples) < 120 {
			break
		}
	}
	if len(samples) == 0 {
		return ErrMigrationRecovery
	}
	raw, err := json.Marshal(samples)
	if err != nil {
		return ErrMigrationRecovery
	}
	targetSHA, err := migrationRecoveryMetricsTarget(m)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrMigrationRecovery
	}
	defer tx.Rollback()
	backupAt, err := migrationRecoveryLock(ctx, tx, generation)
	if err != nil {
		return err
	}
	current, err := migrationRecoveryTargetTx(ctx, tx, target.Node)
	if err != nil || !migrationRecoveryTargetEqual(target, current) {
		return ErrMigrationRecovery
	}
	var restoredAt time.Time
	if tx.QueryRowContext(ctx, "SELECT restored_at FROM v3_migration_recovery_state WHERE id=1").Scan(&restoredAt) != nil {
		return ErrMigrationRecovery
	}
	// Source caches at most one hour. Coverage is proved by actual samples around
	// the backup and restore boundaries, never by an assumed count or fake zero.
	// The Agent metricLoop records every 15 seconds independently of the
	// central pull cadence; a slower collector setting cannot hide cache gaps.
	interval := int64(15)
	gap := 0
	first, last := samples[0].UnixMillis, samples[len(samples)-1].UnixMillis
	left := int64(0)
	if backupAt != nil {
		for _, sample := range samples {
			if sample.UnixMillis <= backupAt.UnixMilli() {
				left = sample.UnixMillis
			}
		}
	}
	if backupAt == nil || backupAt.After(restoredAt) || restoredAt.Sub(*backupAt) > time.Hour || left == 0 || backupAt.UnixMilli()-left > interval*1000 || last < restoredAt.UnixMilli()-interval*1000 {
		gap++
	}
	for i := 1; i < len(samples); i++ {
		if samples[i].UnixMillis-samples[i-1].UnixMillis > interval*1500 && samples[i].UnixMillis >= backupAtOrZero(backupAt) && samples[i-1].UnixMillis <= restoredAt.UnixMilli() {
			gap++
		}
	}
	state := "prepared"
	if gap > 0 {
		state = "gap"
	}
	if _, err := tx.ExecContext(ctx, "UPDATE v3_migration_recovery_nodes SET metrics_state=$3,metrics_target_sha256=$4,metrics_sha256=$5,metrics_cache=$6,metrics_samples=$7,metrics_first=$8,metrics_last=$9,metrics_gaps=$10 WHERE generation=$1 AND node=$2", generation, target.Node, state, targetSHA, digest(raw), raw, len(samples), first, last, gap); err != nil {
		return ErrMigrationRecovery
	}
	if err := tx.Commit(); err != nil {
		return ErrMigrationRecovery
	}
	if gap > 0 {
		return ErrMigrationRecovery
	}
	return nil
}
func backupAtOrZero(at *time.Time) int64 {
	if at == nil {
		return 0
	}
	return at.UnixMilli()
}
func (s *Store) migrationRecoveryReplayMetricNode(ctx context.Context, c Config, generation string, target migrationRecoveryTarget, m *Metrics) error {
	targetSHA, err := migrationRecoveryMetricsTarget(m)
	if err != nil {
		return err
	}
	var state, storedTarget, sha string
	var raw []byte
	if s.DB.QueryRowContext(ctx, "SELECT metrics_state,metrics_target_sha256,metrics_sha256,metrics_cache FROM v3_migration_recovery_nodes WHERE generation=$1 AND node=$2", generation, target.Node).Scan(&state, &storedTarget, &sha, &raw) != nil {
		return ErrMigrationRecovery
	}
	if state == "pending" || state == "failed" && sha == "" {
		if err = s.migrationRecoveryReadMetricCache(ctx, c, generation, target, m); err != nil {
			return err
		}
		if s.DB.QueryRowContext(ctx, "SELECT metrics_state,metrics_target_sha256,metrics_sha256,metrics_cache FROM v3_migration_recovery_nodes WHERE generation=$1 AND node=$2", generation, target.Node).Scan(&state, &storedTarget, &sha, &raw) != nil {
			return ErrMigrationRecovery
		}
	}
	if state == "gap" || storedTarget != targetSHA {
		return ErrMigrationRecovery
	}
	// JSONB formatting is canonicalized by PostgreSQL; the source digest covers
	// the decoded exact samples, including original raw Prometheus bytes.
	var samples []*agentv1.MetricsSample
	if json.Unmarshal(raw, &samples) != nil || len(samples) == 0 {
		return ErrMigrationRecovery
	}
	canonical, _ := json.Marshal(samples)
	if digest(canonical) != sha {
		return ErrMigrationRecovery
	}
	_, baseline, err := s.MetricCursor(ctx, target.Node)
	if err != nil {
		return ErrMigrationRecovery
	}
	if baseline.Time > samples[0].UnixMillis/1000 {
		baseline.Time = 0
		baseline.Values = nil
	}
	derived, err := derivedSamples(samples, baseline)
	if err != nil {
		return ErrMigrationRecovery
	}
	var backupAt, restoredAt time.Time
	if s.DB.QueryRowContext(ctx, "SELECT backup_at,restored_at FROM v3_migration_recovery_state WHERE id=1 AND generation=$1", generation).Scan(&backupAt, &restoredAt) != nil {
		return ErrMigrationRecovery
	}
	selected := derived[:0]
	for _, sample := range derived {
		if sample.UnixMillis > backupAt.UnixMilli() && sample.UnixMillis <= restoredAt.UnixMilli() {
			selected = append(selected, sample)
		}
	}
	derived = selected
	payload, err := migrationRecoveryBuildMetrics(target.Node, derived)
	if err != nil {
		return ErrMigrationRecovery
	}
	history, original := payload, []byte(nil)
	if m.RawURL != "" {
		history, original, err = splitMetricLayers(payload)
		if err != nil {
			return ErrMigrationRecovery
		}
	}
	first, last := samples[0].UnixMillis, samples[len(samples)-1].UnixMillis
	rawLayer := *m
	if m.RawURL != "" {
		rawLayer.WriteURL, rawLayer.QueryURL = m.RawURL, m.RawURL
	}
	if migrationRecoveryVerifyLayer(ctx, m, target.Node, history, first, last, true) != nil || migrationRecoveryVerifyLayer(ctx, &rawLayer, target.Node, original, first, last, true) != nil {
		return ErrMigrationRecovery
	}
	for start := 0; start < len(derived); start += 120 {
		if err := m.Write(ctx, target.Node, derived[start:min(start+120, len(derived))]); err != nil {
			return ErrMigrationRecovery
		}
	}
	if migrationRecoveryVerifyLayer(ctx, m, target.Node, history, first, last, false) != nil || migrationRecoveryVerifyLayer(ctx, &rawLayer, target.Node, original, first, last, false) != nil {
		return ErrMigrationRecovery
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrMigrationRecovery
	}
	defer tx.Rollback()
	if _, err = migrationRecoveryLock(ctx, tx, generation); err != nil {
		return err
	}
	current, err := migrationRecoveryTargetTx(ctx, tx, target.Node)
	if err != nil || !migrationRecoveryTargetEqual(target, current) {
		return ErrMigrationRecovery
	}
	if _, err := tx.ExecContext(ctx, "UPDATE v3_migration_recovery_nodes SET metrics_state='verified' WHERE generation=$1 AND node=$2 AND metrics_sha256=$3 AND metrics_target_sha256=$4", generation, target.Node, sha, targetSHA); err != nil {
		return ErrMigrationRecovery
	}
	if err := tx.Commit(); err != nil {
		return ErrMigrationRecovery
	}
	return nil
}

// Replay is additive with the exact cached timestamps. It does not update live
// cursors/status/health/outboxes and does not replace the original VM restore.
func (s *Store) ReplayMigrationRecoveryMetrics(ctx context.Context, c Config, generation string) (MigrationRecoveryReport, error) {
	report, err := s.MigrationRecoveryReport(ctx, generation)
	if err != nil || report.Phase == "held" || report.Phase == "complete" {
		return report, ErrMigrationRecovery
	}
	m := &Metrics{QueryURL: c.Metrics.QueryURL, WriteURL: c.Metrics.WriteURL, RawURL: c.Metrics.RawURL, HTTP: &http.Client{Timeout: 15 * time.Second}}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	guard, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return report, ErrMigrationRecovery
	}
	defer guard.Rollback()
	var locked bool
	if guard.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended($1,773376049))", generation).Scan(&locked) != nil || !locked {
		return report, ErrMigrationRecovery
	}
	nodes := migrationRecoverySortedNodes(report)
	sort.Strings(nodes)
	for _, node := range nodes {
		target, err := s.migrationRecoverySaved(ctx, generation, node)
		if err == nil {
			nodeCtx, cancelNode := context.WithTimeout(ctx, 60*time.Second)
			err = s.migrationRecoveryReplayMetricNode(nodeCtx, c, generation, target, m)
			cancelNode()
		}
		if err != nil {
			_, _ = s.DB.ExecContext(ctx, "UPDATE v3_migration_recovery_nodes SET metrics_state=CASE WHEN metrics_state='gap' THEN metrics_state ELSE 'failed' END WHERE generation=$1 AND node=$2", generation, node)
		}
	}
	return s.MigrationRecoveryReport(ctx, generation)
}

func migrationRecoveryBuildMetrics(node string, samples []*agentv1.MetricsSample) ([]byte, error) {
	var out bytes.Buffer
	for start := 0; start < len(samples); start += 120 {
		raw, err := BuildMetrics(node, samples[start:min(start+120, len(samples))])
		if err != nil {
			return nil, ErrMigrationRecovery
		}
		out.Write(raw)
		if out.Len() > 16<<20 {
			return nil, ErrMigrationRecovery
		}
	}
	return out.Bytes(), nil
}
