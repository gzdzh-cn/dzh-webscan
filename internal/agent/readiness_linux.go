//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"webscan/internal/common"
)

type scannerReadiness struct {
	Rules        string
	YARA, ClamAV engineReadiness
}
type engineReadiness struct {
	Ready   bool
	Checked float64
}

func scannerScratchDirectory(data string) string {
	return filepath.Join(data, common.ScannerReadinessSubdirectory)
}

// Runtime-owned scratch must never enter the watch/reconciliation pipeline,
// including when a configured root contains the Agent data directory. This
// implicit exclusion does not alter the saved monitoring configuration/hash.
func newAgentPolicy(config common.Map) (*common.Policy, error) {
	p, err := common.NewPolicy(common.M(config["monitor"]))
	if err != nil || common.S(config["transport_mode"]) != "pull" {
		return p, err
	}
	data := common.S(config["data_dir"])
	if !filepath.IsAbs(data) || filepath.Clean(data) != data {
		return nil, errors.New("invalid_scanner_scratch_directory")
	}
	dir := scannerScratchDirectory(data)
	for _, target := range append(append([]string{}, p.Roots...), p.Critical...) {
		if common.Inside(target, dir) {
			return nil, errors.New("scanner_scratch_is_reserved")
		}
	}
	probe := common.S(config["probe_directory"])
	if probe != "" && (common.Inside(probe, dir) || common.Inside(dir, probe)) {
		return nil, errors.New("scanner_scratch_is_reserved")
	}
	p.Exclusions = append(p.Exclusions, common.Exclusion{Prefix: dir})
	return p, nil
}

func (a *Agent) privateScannerScratch() (string, error) {
	parent, err := filepath.EvalSymlinks(a.Data)
	if err != nil || parent != a.Data {
		return "", errors.New("unsafe_scanner_scratch_directory")
	}
	dir := scannerScratchDirectory(a.Data)
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return "", errors.New("unsafe_scanner_scratch_directory")
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || real != dir {
		return "", errors.New("unsafe_scanner_scratch_directory")
	}
	return dir, nil
}

// Run the configured engine against a private, small snapshot. Do not create
// events, use business files or contact notification endpoints. Proof is kept
// in memory, so an old process's persisted counters cannot certify a restart.
func (a *Agent) checkScannerReadiness(ctx context.Context) {
	rules := a.rules.Load()
	proof := &scannerReadiness{Rules: rules.Version}
	for _, tool := range []string{"yara", "clamav"} {
		spec := common.M(common.M(a.C["scan"])[tool])
		if !common.B(spec["enabled"]) {
			continue
		}
		result := engineReadiness{}
		check, cancel := context.WithTimeout(ctx, 10*time.Second)
		result.Ready = a.probeScanner(check, tool, spec, rules.Yara) == nil
		cancel()
		result.Checked = common.Now()
		if tool == "yara" {
			proof.YARA = result
		} else {
			proof.ClamAV = result
		}
	}
	if ctx.Err() == nil {
		a.scannerReadiness.Store(proof)
	}
}
func (a *Agent) probeScanner(ctx context.Context, tool string, spec common.Map, rules []byte) error {
	dir, err := a.privateScannerScratch()
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "scanner-readiness-*.php")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	raw := []byte("<?php /* Webscan scanner readiness " + common.ID() + " */\n")
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	result, err := a.scanEngineIn(ctx, scanTask{Path: path, Hash: common.Hash(raw)}, tool, spec, rules, dir)
	if err != nil {
		return err
	}
	if status := common.S(result["status"]); status != "no_match" && status != "matched" {
		return errors.New("scanner_readiness_incomplete")
	}
	return nil
}
func (a *Agent) scannerReadinessLoop(ctx context.Context) {
	for ctx.Err() == nil {
		a.checkScannerReadiness(ctx)
		if !common.Sleep(ctx, 30*time.Second) {
			return
		}
	}
}

func (a *Agent) readinessMetrics() string {
	current := a.rules.Load()
	rulesCurrent := current.Version == a.configurationRules
	configured, covered := len(current.Policy.Roots), 0
	a.watchMu.Lock()
	for _, root := range current.Policy.Roots {
		if _, ok := a.byPath[root]; ok {
			covered++
		}
	}
	a.watchMu.Unlock()
	var out strings.Builder
	fmt.Fprintf(&out, "webscan_runtime_rules_current %d\nwebscan_configured_roots %d\nwebscan_covered_roots %d\n", boolMetric(rulesCurrent), configured, covered)
	proof := a.scannerReadiness.Load()
	for _, tool := range []string{"yara", "clamav"} {
		enabled := common.B(common.M(common.M(a.C["scan"])[tool])["enabled"])
		result := engineReadiness{}
		if proof != nil && proof.Rules == current.Version && enabled {
			result = proof.YARA
			if tool == "clamav" {
				result = proof.ClamAV
			}
		}
		fmt.Fprintf(&out, "webscan_%s_enabled %d\nwebscan_%s_ready %d\nwebscan_%s_check_seconds %g\n", tool, boolMetric(enabled), tool, boolMetric(result.Ready), tool, result.Checked)
	}
	return out.String()
}
func boolMetric(value bool) int {
	if value {
		return 1
	}
	return 0
}
