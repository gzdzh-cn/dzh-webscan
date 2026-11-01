package controlplane

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"webscan/internal/common"
	"webscan/internal/nodeconfig"
)

// MonitoringRules contains only the rules administrators can edit publicly.
// Runtime-specific scanner, resource and reconciliation tuning stays on the node.
type MonitoringRules struct {
	Roots                       []string `json:"roots"`
	Extensions                  []string `json:"extensions"`
	ImportantFilenames          []string `json:"important_filenames"`
	CriticalPaths               []string `json:"critical_paths"`
	ExcludePaths                []string `json:"exclude_paths"`
	ReconciliationIntervalHours int      `json:"reconciliation_interval_hours"`
}

var errMonitoringRules = errors.New("文件监控规则不正确，请检查目录、文件规则和核对间隔")

func defaultMonitoringRules() MonitoringRules {
	m := nodeconfig.DefaultSettings().Monitor
	return MonitoringRules{
		Roots: append([]string{}, m.Roots...), Extensions: append([]string{}, m.Extensions...),
		ImportantFilenames: append([]string{}, m.ImportantFilenames...), CriticalPaths: append([]string{}, m.CriticalPaths...),
		ExcludePaths: append([]string{}, m.ExcludePaths...), ReconciliationIntervalHours: m.Reconciliation.IntervalHours,
	}
}

func validateMonitoringRules(rules MonitoringRules) error {
	if len(rules.Roots) < 1 || len(rules.Roots) > 64 || rules.ReconciliationIntervalHours < 1 || rules.ReconciliationIntervalHours > 8760 {
		return errMonitoringRules
	}
	total, size := 0, 0
	for index, list := range [][]string{rules.Roots, rules.Extensions, rules.ImportantFilenames, rules.CriticalPaths, rules.ExcludePaths} {
		seen := make(map[string]bool, len(list))
		for _, value := range list {
			total++
			size += len(value)
			if total > 10000 || size > 512<<10 || value == "" || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
				return errMonitoringRules
			}
			key, limit := value, 4096
			switch index {
			case 1:
				key, limit = strings.ToLower(value), 64
			case 2:
				limit = 255
				if value == "." || value == ".." || strings.ContainsAny(value, `/\\`) {
					return errMonitoringRules
				}
			default:
				if !filepath.IsAbs(value) || filepath.Clean(value) != value {
					return errMonitoringRules
				}
			}
			if len(value) > limit || seen[key] {
				return errMonitoringRules
			}
			seen[key] = true
		}
	}
	m := copyMonitoringRules(nodeconfig.DefaultSettings().Monitor, rules)
	return validateMonitoringMonitor(m)
}

// monitorWithRules deliberately retains the advanced fields from the supplied
// node. Independent overrides and inherited public rules use the same merge.
// Every returned slice is owned by the result, never by the request or base.
func monitorWithRules(base nodeconfig.Monitor, rules MonitoringRules) (nodeconfig.Monitor, error) {
	if err := validateMonitoringRules(rules); err != nil {
		return nodeconfig.Monitor{}, err
	}
	m := copyMonitoringRules(base, rules)
	if err := validateMonitoringMonitor(m); err != nil {
		return nodeconfig.Monitor{}, err
	}
	return m, nil
}

func copyMonitoringRules(base nodeconfig.Monitor, rules MonitoringRules) nodeconfig.Monitor {
	base.Roots = append([]string{}, rules.Roots...)
	base.Extensions = append([]string{}, rules.Extensions...)
	base.ImportantFilenames = append([]string{}, rules.ImportantFilenames...)
	base.CriticalPaths = append([]string{}, rules.CriticalPaths...)
	base.ExcludePaths = append([]string{}, rules.ExcludePaths...)
	base.Reconciliation.IntervalHours = rules.ReconciliationIntervalHours
	return base
}

func validateMonitoringMonitor(m nodeconfig.Monitor) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return errMonitoringRules
	}
	var fields common.Map
	if json.Unmarshal(raw, &fields) != nil {
		return errMonitoringRules
	}
	policy, err := common.NewPolicy(fields)
	if err != nil {
		return errMonitoringRules
	}
	s := nodeconfig.DefaultSettings()
	s.Monitor = m
	// This is a monitor-only check. The real node's explicit probe must be
	// checked separately after merging its complete settings. Using an old
	// default probe here would wrongly reject perfectly valid changed roots.
	for _, root := range policy.Roots {
		probe := root
		if root == "/" {
			probe = "/.webscan-monitor-validation"
		}
		if policy.Excluded(probe) {
			continue
		}
		s.ProbeDirectory = probe
		if s.Validate() == nil {
			return nil
		}
	}
	return errMonitoringRules
}
