//go:build linux

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"webscan/internal/common"
	"webscan/internal/telemetry"
)

func scannerFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scanner")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}
func scannerMetric(t *testing.T, a *Agent, name string) float64 {
	t.Helper()
	ms, err := telemetry.Parse(a.readinessMetrics())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.Name == name {
			return m.Value
		}
	}
	t.Fatal("missing readiness metric", name)
	return 0
}
func enableTestScanner(a *Agent, tool string, path string) {
	scan := common.Clone(common.M(a.C["scan"]))
	engine := common.Clone(common.M(scan[tool]))
	engine["enabled"] = true
	engine["max_file_mib"] = 1
	engine["timeout_seconds"] = 1
	scan[tool] = engine
	a.C["scan"] = scan
	tools := common.Clone(common.M(a.C["scanner_tools"]))
	tools[tool] = path
	a.C["scanner_tools"] = tools
}
func assertNoScannerScratch(t *testing.T, a *Agent) {
	t.Helper()
	files, err := os.ReadDir(a.Data)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "scanner-readiness-") || strings.HasPrefix(f.Name(), "scan-") || strings.HasPrefix(f.Name(), "rules-snapshot-") {
			t.Fatal("scanner scratch left behind", f.Name())
		}
	}
	private, err := os.ReadDir(scannerScratchDirectory(a.Data))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(private) != 0 {
		t.Fatal("private scanner scratch left behind", private)
	}
}

func TestScannerReadinessScratchIsExcludedFromBroadMonitoring(t *testing.T) {
	a, ctx := testAgent(t)
	config := common.Clone(a.C)
	config["transport_mode"] = "pull"
	common.M(config["monitor"])["roots"] = []string{filepath.Dir(a.Data)}
	policy, err := newAgentPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	old := a.rules.Load()
	a.rules.Store(&Rules{policy, old.Yara, policy.Version(old.Yara)})
	if !a.addTree(ctx, filepath.Dir(a.Data), policy) {
		t.Fatal("broad root coverage failed")
	}
	if err := a.Reconcile(ctx, true, true, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(a.Data), "business.php")
	if err := os.WriteFile(path, []byte("<?php /* monitored */"), 0600); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool { return common.Contains(operations(a, path), "create") })
	var before, after int
	if err := a.DB.QueryRow("SELECT count(*) FROM events").Scan(&before); err != nil {
		t.Fatal(err)
	}
	enableTestScanner(a, "yara", scannerFixture(t, "exit 0"))
	a.checkScannerReadiness(ctx)
	if scannerMetric(t, a, "webscan_yara_ready") != 1 {
		t.Fatal("private selftest did not complete")
	}
	if err := a.Reconcile(ctx, false, true, nil); err != nil {
		t.Fatal(err)
	}
	// Explicit processing simulates an already queued inotify job as well as
	// a later reconciliation: both must ignore all private temporary paths.
	for _, name := range []string{"scanner-readiness-x.php", "scan-x.php", "rules-snapshot-x.yar"} {
		private := filepath.Join(scannerScratchDirectory(a.Data), name)
		if err := a.Process(ctx, private, "create", "", false, false); err != nil {
			t.Fatal(err)
		}
		if policy.Tracked(private, a.Probe) || policy.Watches(filepath.Dir(private), a.Probe) {
			t.Fatal("private scratch remains monitored")
		}
	}
	if err := a.DB.QueryRow("SELECT count(*) FROM events").Scan(&after); err != nil || before != after {
		t.Fatal("selftest created monitored events", before, after, err)
	}
	reloaded, err := newAgentPolicy(config)
	if err != nil || !reloaded.Excluded(scannerScratchDirectory(a.Data)) || policy.Version(old.Yara) != reloaded.Version(old.Yara) {
		t.Fatal("reload lost scratch isolation", err)
	}
	assertNoScannerScratch(t, a)
}

func TestScannerReadinessRejectsUnsafeScratch(t *testing.T) {
	for _, kind := range []string{"symlink", "permissions", "regular-file"} {
		t.Run(kind, func(t *testing.T) {
			a, ctx := testAgent(t)
			dir := scannerScratchDirectory(a.Data)
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(t.TempDir(), dir)
			case "permissions":
				err = os.Mkdir(dir, 0755)
			case "regular-file":
				err = os.WriteFile(dir, []byte("untouched"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			enableTestScanner(a, "yara", scannerFixture(t, "exit 0"))
			a.checkScannerReadiness(ctx)
			if scannerMetric(t, a, "webscan_yara_ready") != 0 {
				t.Fatal("unsafe scratch accepted")
			}
		})
	}
}
func TestScannerReadinessUsesConfiguredEnginesAndPreservesEvents(t *testing.T) {
	a, ctx := testAgent(t)
	enableTestScanner(a, "yara", scannerFixture(t, `test "$1" = '-w' && test -s "$2" && test -s "$3" || exit 2
exit 0`))
	enableTestScanner(a, "clamav", scannerFixture(t, `test "$1" = '--fdpass' && test "$2" = '--no-summary' && test -s "$3" || exit 2
exit 1`))
	var before, after int
	if err := a.DB.QueryRow("SELECT count(*) FROM events").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if scannerMetric(t, a, "webscan_yara_ready") != 0 || scannerMetric(t, a, "webscan_yara_check_seconds") != 0 {
		t.Fatal("unverified scanner ready")
	}
	a.checkScannerReadiness(ctx)
	for _, tool := range []string{"yara", "clamav"} {
		if scannerMetric(t, a, "webscan_"+tool+"_ready") != 1 || scannerMetric(t, a, "webscan_"+tool+"_check_seconds") <= 0 {
			t.Fatal("engine not proved", tool)
		}
	}
	if err := a.DB.QueryRow("SELECT count(*) FROM events").Scan(&after); err != nil || before != after {
		t.Fatal("readiness emitted business event", before, after, err)
	}
	assertNoScannerScratch(t, a)
	enableTestScanner(a, "clamav", scannerFixture(t, "exit 2"))
	a.checkScannerReadiness(ctx)
	if scannerMetric(t, a, "webscan_yara_ready") != 1 || scannerMetric(t, a, "webscan_clamav_ready") != 0 {
		t.Fatal("failure disabled or masked other engine")
	}
	assertNoScannerScratch(t, a)
}
func TestScannerReadinessDoesNotTreatDisabledMissingSkippedOrTimedOutAsReady(t *testing.T) {
	a, ctx := testAgent(t)
	for _, kind := range []string{"missing", "failure", "timeout", "skipped"} {
		t.Run(kind, func(t *testing.T) {
			path := "/nonexistent/webscan-readiness-scanner"
			if kind == "failure" {
				path = scannerFixture(t, "exit 2")
			}
			if kind == "timeout" {
				path = scannerFixture(t, "exec sleep 5")
			}
			if kind == "skipped" {
				path = scannerFixture(t, "exit 0")
			}
			enableTestScanner(a, "yara", path)
			if kind == "skipped" {
				common.M(common.M(a.C["scan"])["yara"])["max_file_mib"] = 0
			}
			a.checkScannerReadiness(ctx)
			if scannerMetric(t, a, "webscan_yara_ready") != 0 || scannerMetric(t, a, "webscan_yara_check_seconds") <= 0 {
				t.Fatal("failed/skipped engine ready")
			}
			assertNoScannerScratch(t, a)
		})
	}
	for _, tool := range []string{"yara", "clamav"} {
		common.M(common.M(a.C["scan"])[tool])["enabled"] = false
	}
	a.checkScannerReadiness(ctx)
	for _, tool := range []string{"yara", "clamav"} {
		if scannerMetric(t, a, "webscan_"+tool+"_enabled") != 0 || scannerMetric(t, a, "webscan_"+tool+"_ready") != 0 || scannerMetric(t, a, "webscan_"+tool+"_check_seconds") != 0 {
			t.Fatal("disabled engine claimed ready", tool)
		}
	}
}
func TestScannerReadinessIsBoundToActualRulesAndDoesNotSurviveReset(t *testing.T) {
	a, ctx := testAgent(t)
	enableTestScanner(a, "yara", scannerFixture(t, "exit 0"))
	a.checkScannerReadiness(ctx)
	if scannerMetric(t, a, "webscan_runtime_rules_current") != 1 || scannerMetric(t, a, "webscan_yara_ready") != 1 {
		t.Fatal("initial readiness missing")
	}
	old := a.rules.Load()
	changed := *old
	changed.Version = "different-effective-rules"
	a.rules.Store(&changed)
	if scannerMetric(t, a, "webscan_runtime_rules_current") != 0 || scannerMetric(t, a, "webscan_yara_ready") != 0 {
		t.Fatal("changed rules reused old evidence")
	}
	a.checkScannerReadiness(ctx)
	if scannerMetric(t, a, "webscan_runtime_rules_current") != 0 {
		t.Fatal("selftest certified rules from a different configuration")
	}
	a.rules.Store(old)
	a.scannerReadiness.Store(nil)
	if scannerMetric(t, a, "webscan_yara_ready") != 0 {
		t.Fatal("old scanner evidence survived reset")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	a.checkScannerReadiness(canceled)
	if a.scannerReadiness.Load() != nil {
		t.Fatal("canceled check published evidence")
	}
}
func TestReadinessCountsOnlyConfiguredWatchedRoots(t *testing.T) {
	a, _ := testAgent(t)
	if scannerMetric(t, a, "webscan_configured_roots") != 1 || scannerMetric(t, a, "webscan_covered_roots") != 1 {
		t.Fatal("root watches missing")
	}
	a.watchMu.Lock()
	id, ok := a.byPath[root(a)]
	delete(a.byPath, root(a))
	a.watchMu.Unlock()
	if !ok || scannerMetric(t, a, "webscan_covered_roots") != 0 {
		t.Fatal("unwatched configured root counted")
	}
	a.watchMu.Lock()
	a.byPath[root(a)] = id
	a.watchMu.Unlock()
}
func TestScannerReadinessWithBundledYARA(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_SCANNER") != "1" {
		t.Skip("requires isolated Linux scanner fixture")
	}
	tool, err := exec.LookPath("yara")
	if err != nil {
		t.Fatal("isolated fixture missing YARA", err)
	}
	a, ctx := testAgent(t)
	enableTestScanner(a, "yara", tool)
	common.M(common.M(a.C["scan"])["clamav"])["enabled"] = false
	a.checkScannerReadiness(ctx)
	if scannerMetric(t, a, "webscan_yara_ready") != 1 {
		t.Fatal("actual YARA could not scan a private snapshot")
	}
	assertNoScannerScratch(t, a)
}
