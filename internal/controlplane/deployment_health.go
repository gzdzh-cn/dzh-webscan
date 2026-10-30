package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"time"

	"webscan/internal/telemetry"
)

var deploymentHealthMetrics = []string{
	"webscan_collector_ready", "webscan_coverage_ok", "webscan_runtime_rules_current",
	"webscan_configured_roots", "webscan_covered_roots", "webscan_watches",
	"webscan_agent_heartbeat_seconds", "webscan_scan_heartbeat_seconds",
	"webscan_yara_enabled", "webscan_yara_ready", "webscan_yara_check_seconds",
	"webscan_clamav_enabled", "webscan_clamav_ready", "webscan_clamav_check_seconds",
}

// Do not certify the last of duplicate or labelled readiness scalars. Collection
// remains compatible with old Agents; absent/ambiguous health is simply unknown.
func canonicalDeploymentHealth(metrics []telemetry.Metric, values map[string]float64) {
	for _, name := range deploymentHealthMetrics {
		delete(values, name)
		count := 0
		valid := true
		value := 0.0
		for _, m := range metrics {
			if m.Name != name {
				continue
			}
			count++
			value = m.Value
			valid = valid && len(m.Labels) == 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
		}
		if count == 1 && valid {
			values[name] = value
		}
	}
}

func validDeploymentHealth(config json.RawMessage, values map[string]float64, at int64, now, notBefore time.Time) bool {
	settings, err := nodeRuntimeSettings(config)
	if err != nil || at < 1 || at < now.Add(-60*time.Second).UnixMilli() || at > now.Add(5*time.Second).UnixMilli() {
		return false
	}
	equals := func(name string, want float64) bool { v, ok := values[name]; return ok && v == want }
	fresh := func(name string, age time.Duration) bool {
		value, ok := values[name]
		return ok && !math.IsNaN(value) && !math.IsInf(value, 0) && value > 0 && value >= float64(now.Add(-age).UnixMilli())/1000 && value <= float64(now.Add(5*time.Second).UnixMilli())/1000 && (notBefore.IsZero() || value >= float64(notBefore.Add(-5*time.Second).UnixMilli())/1000)
	}
	roots := float64(len(settings.Monitor.Roots))
	watches, known := values["webscan_watches"]
	if !known || math.IsNaN(watches) || math.IsInf(watches, 0) || watches < roots || watches != math.Trunc(watches) {
		return false
	}
	if !equals("webscan_collector_ready", 1) || !equals("webscan_coverage_ok", 1) || !equals("webscan_runtime_rules_current", 1) || !equals("webscan_configured_roots", roots) || !equals("webscan_covered_roots", roots) || !fresh("webscan_agent_heartbeat_seconds", 90*time.Second) {
		return false
	}
	enabled := false
	timeout := 90 * time.Second
	for _, e := range []struct {
		name    string
		enabled bool
		timeout int
	}{{"yara", settings.Scan.YARA.Enabled, settings.Scan.YARA.TimeoutSeconds}, {"clamav", settings.Scan.ClamAV.Enabled, settings.Scan.ClamAV.TimeoutSeconds}} {
		want := 0.0
		if e.enabled {
			want = 1
		}
		if !equals("webscan_"+e.name+"_enabled", want) {
			return false
		}
		if e.enabled {
			enabled = true
			timeout = max(timeout, time.Duration(e.timeout+30)*time.Second)
			if !equals("webscan_"+e.name+"_ready", 1) || !fresh("webscan_"+e.name+"_check_seconds", 90*time.Second) {
				return false
			}
		}
	}
	return !enabled || fresh("webscan_scan_heartbeat_seconds", timeout)
}

func (s *Store) deploymentHealth(ctx context.Context, tx *sql.Tx, n Node, sampled int64, notBefore time.Time) error {
	var at int64
	var raw []byte
	var reason string
	err := tx.QueryRowContext(ctx, "SELECT sampled_at,metrics,concat_ws('；',nullif(metrics_error,''),nullif(protocol_error,'')) FROM v3_node_status WHERE node=$1 AND sampled_at IS NOT NULL FOR SHARE", n.ID).Scan(&at, &raw, &reason)
	if err == sql.ErrNoRows {
		return ErrDeploymentNotReady
	}
	if err != nil {
		return err
	}
	var values map[string]float64
	if at != sampled && sampled > 0 || reason != "" || json.Unmarshal(raw, &values) != nil || !validDeploymentHealth(n.Config, values, at, time.Now(), notBefore) {
		return ErrDeploymentNotReady
	}
	return nil
}
