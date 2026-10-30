package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"webscan/internal/telemetry"
	agentv1 "webscan/sdk/agent/v1"
)

func healthyDeploymentMetrics(t *testing.T, config json.RawMessage, now time.Time) []byte {
	t.Helper()
	settings, err := nodeRuntimeSettings(config)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{"node_memory_MemTotal_bytes": 2048, "webscan_collector_ready": 1, "webscan_coverage_ok": 1, "webscan_runtime_rules_current": 1, "webscan_configured_roots": float64(len(settings.Monitor.Roots)), "webscan_covered_roots": float64(len(settings.Monitor.Roots)), "webscan_watches": float64(len(settings.Monitor.Roots)), "webscan_agent_heartbeat_seconds": float64(now.UnixMilli()) / 1000, "webscan_scan_heartbeat_seconds": float64(now.UnixMilli()) / 1000}
	for _, e := range []struct {
		name    string
		enabled bool
	}{{"yara", settings.Scan.YARA.Enabled}, {"clamav", settings.Scan.ClamAV.Enabled}} {
		values["webscan_"+e.name+"_enabled"] = 0
		values["webscan_"+e.name+"_ready"] = 0
		values["webscan_"+e.name+"_check_seconds"] = 0
		if e.enabled {
			values["webscan_"+e.name+"_enabled"] = 1
			values["webscan_"+e.name+"_ready"] = 1
			values["webscan_"+e.name+"_check_seconds"] = float64(now.UnixMilli()) / 1000
		}
	}
	var out strings.Builder
	for name, value := range values {
		fmt.Fprintf(&out, "%s %g\n", name, value)
	}
	return []byte(out.String())
}
func healthValues(t *testing.T, raw []byte) map[string]float64 {
	t.Helper()
	metrics, err := telemetry.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	canonicalDeploymentHealth(metrics, values)
	return values
}
func TestDeploymentHealthRequiresActualCoverageAndConfiguredEngines(t *testing.T) {
	now := time.Now()
	config := json.RawMessage(`{"scan":{"yara":{"enabled":true},"clamav":{"enabled":true}}}`)
	for _, change := range []string{"healthy", "missing-ready", "coverage", "rules-changed", "root-count", "covered-count", "watches", "fractional-watches", "nan-watches", "infinite-watches", "insufficient-watches", "agent-stale", "agent-future", "scanner-stale", "yara-disabled", "yara-unready", "clamav-disabled", "clamav-unready", "clamav-never-checked", "clamav-stale", "clamav-future", "before-activation", "old-sample", "future-sample", "nan-heartbeat"} {
		t.Run(change, func(t *testing.T) {
			values := healthValues(t, healthyDeploymentMetrics(t, config, now))
			at := now.UnixMilli()
			before := now.Add(-time.Second)
			switch change {
			case "missing-ready":
				delete(values, "webscan_collector_ready")
			case "coverage":
				values["webscan_coverage_ok"] = 0
			case "rules-changed":
				values["webscan_runtime_rules_current"] = 0
			case "root-count":
				values["webscan_configured_roots"]++
			case "covered-count":
				values["webscan_covered_roots"] = 0
			case "watches":
				delete(values, "webscan_watches")
			case "fractional-watches":
				values["webscan_watches"] += 0.5
			case "nan-watches":
				values["webscan_watches"] = math.NaN()
			case "infinite-watches":
				values["webscan_watches"] = math.Inf(1)
			case "insufficient-watches":
				values["webscan_watches"] = 0
			case "agent-stale":
				values["webscan_agent_heartbeat_seconds"] -= 91
			case "agent-future":
				values["webscan_agent_heartbeat_seconds"] += 6
			case "scanner-stale":
				values["webscan_scan_heartbeat_seconds"] -= 91
			case "yara-disabled":
				values["webscan_yara_enabled"] = 0
			case "yara-unready":
				values["webscan_yara_ready"] = 0
			case "clamav-disabled":
				values["webscan_clamav_enabled"] = 0
			case "clamav-unready":
				values["webscan_clamav_ready"] = 0
			case "clamav-never-checked":
				delete(values, "webscan_clamav_check_seconds")
			case "clamav-stale":
				values["webscan_clamav_check_seconds"] -= 91
			case "clamav-future":
				values["webscan_clamav_check_seconds"] += 6
			case "before-activation":
				values["webscan_yara_check_seconds"] -= 7
			case "old-sample":
				at = now.Add(-61 * time.Second).UnixMilli()
			case "future-sample":
				at = now.Add(6 * time.Second).UnixMilli()
			case "nan-heartbeat":
				values["webscan_agent_heartbeat_seconds"] = math.NaN()
			}
			if got := validDeploymentHealth(config, values, at, now, before); got != (change == "healthy") {
				t.Fatal("wrong readiness decision", got)
			}
		})
	}
}
func TestDeploymentHealthDisabledEnginesDoNotRequireSuccessOrWorkerHeartbeat(t *testing.T) {
	now := time.Now()
	config := json.RawMessage(`{"scan":{"yara":{"enabled":false},"clamav":{"enabled":false}}}`)
	values := healthValues(t, healthyDeploymentMetrics(t, config, now))
	delete(values, "webscan_scan_heartbeat_seconds")
	if !validDeploymentHealth(config, values, now.UnixMilli(), now, time.Time{}) {
		t.Fatal("disabled engine required successful scan")
	}
	values["webscan_clamav_enabled"] = 1
	if validDeploymentHealth(config, values, now.UnixMilli(), now, time.Time{}) {
		t.Fatal("unexpected enabled engine certified")
	}
}
func TestDeploymentHealthRejectsDuplicateAndLabelledScalars(t *testing.T) {
	now := time.Now()
	base := healthyDeploymentMetrics(t, nil, now)
	for _, extra := range []string{"webscan_coverage_ok 1\n", "webscan_coverage_ok{source=\"untrusted\"} 1\n", "webscan_yara_ready{type=\"another\"} 1\n"} {
		values := healthValues(t, append(append([]byte{}, base...), []byte(extra)...))
		if validDeploymentHealth(nil, values, now.UnixMilli(), now, time.Time{}) {
			t.Fatal("ambiguous metric certified", extra)
		}
	}
}

func TestDeploymentCannotFinalizeAfterCoverageOrScannerFailure(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	j := deploymentAtVerification(t, s)
	l := recordDeploymentReady(t, s, j)
	if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, s, j.ID)
	for _, metric := range []string{"webscan_coverage_ok", "webscan_yara_ready", "webscan_runtime_rules_current"} {
		t.Run(metric, func(t *testing.T) {
			recordDeploymentReady(t, s, j)
			if _, err := s.DB.Exec("UPDATE v3_node_status SET metrics=jsonb_set(metrics,ARRAY[$1], '0'::jsonb) WHERE node=$2", metric, j.Node); err != nil {
				t.Fatal(err)
			}
			if err := s.CompleteDeploymentPhase(ctx, j); !errors.Is(err, ErrDeploymentNotReady) {
				t.Fatal("failed health completed deployment", err)
			}
		})
	}
	recordDeploymentReady(t, s, j)
	if _, err := s.DB.Exec("UPDATE v3_node_status SET metrics=jsonb_set(metrics,'{webscan_coverage_ok}','0'::jsonb) WHERE node=$1", j.Node); err != nil {
		t.Fatal(err)
	}
	at, _, err := s.MetricCursor(ctx, j.Node)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.recordNodeReadiness(ctx, runtimeNodeForTest(t, s, j.Node), l, "metrics", readinessCapabilities(j), at); !errors.Is(err, ErrDeploymentNotReady) {
		t.Fatal("stored bad health certified", err)
	}
	recordDeploymentReady(t, s, j)
	if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal("recovered health cannot finalize", err)
	}
}
func TestMetricCommitKeepsCollectionButDoesNotCertifyAmbiguousHealth(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	j := deploymentAtVerification(t, s)
	l := recordDeploymentReady(t, s, j)
	at, baseline, err := s.MetricCursor(ctx, j.Node)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(healthyDeploymentMetrics(t, j.Plan.Node.Config, time.Now()), []byte("webscan_coverage_ok 1\n")...)
	b := &agentv1.MetricsBatch{NodeId: j.Node, Samples: []*agentv1.MetricsSample{{UnixMillis: at + 1, PrometheusText: raw}}}
	if err := s.CommitMetrics(ctx, runtimeNodeForTest(t, s, j.Node), l, b, baseline); err != nil {
		t.Fatal("ambiguous health stopped collection", err)
	}
	var values map[string]float64
	var stored []byte
	if err := s.DB.QueryRow("SELECT metrics FROM v3_node_status WHERE node=$1", j.Node).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(stored, &values) != nil {
		t.Fatal("invalid stored metrics")
	}
	if _, ok := values["webscan_coverage_ok"]; ok {
		t.Fatal("duplicate coverage collapsed into success")
	}
	if err := s.recordNodeReadiness(ctx, runtimeNodeForTest(t, s, j.Node), l, "metrics", readinessCapabilities(j), at+1); !errors.Is(err, ErrDeploymentNotReady) {
		t.Fatal("ambiguous sample certified", err)
	}
}
