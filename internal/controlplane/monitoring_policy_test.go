package controlplane

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/nodeconfig"
)

func TestMonitoringRulesDefaultsAndIndependentCopies(t *testing.T) {
	rules := defaultMonitoringRules()
	if err := validateMonitoringRules(rules); err != nil {
		t.Fatal("default rules rejected", err)
	}
	base := nodeconfig.DefaultSettings().Monitor
	base.Reconciliation.StartJitterMinutes = 71
	base.Reconciliation.MaxReadMiBPerSecond = 19
	base.Reconciliation.Nice = 11
	base.Reconciliation.IOClass = 2
	rules.Roots = []string{"/srv/sites", "/srv/static"}
	rules.Extensions = []string{".php", ".PHTML"}
	rules.ImportantFilenames = []string{".htaccess", "config.json"}
	rules.CriticalPaths = []string{"/srv/sites/example/config.php"}
	rules.ExcludePaths = []string{"/srv/sites/**/cache/**"}
	rules.ReconciliationIntervalHours = 24
	got, err := monitorWithRules(base, rules)
	if err != nil {
		t.Fatal(err)
	}
	if got.SiteNameMode != base.SiteNameMode || got.Reconciliation.StartJitterMinutes != 71 || got.Reconciliation.MaxReadMiBPerSecond != 19 || got.Reconciliation.Nice != 11 || got.Reconciliation.IOClass != 2 || got.Reconciliation.IntervalHours != 24 {
		t.Fatal("public rule merge changed advanced node settings", got)
	}
	if !reflect.DeepEqual(got.Roots, rules.Roots) || !reflect.DeepEqual(got.Extensions, rules.Extensions) || !reflect.DeepEqual(got.ImportantFilenames, rules.ImportantFilenames) || !reflect.DeepEqual(got.CriticalPaths, rules.CriticalPaths) || !reflect.DeepEqual(got.ExcludePaths, rules.ExcludePaths) {
		t.Fatal("public rules not copied")
	}
	got.Roots[0], got.Extensions[0], got.ImportantFilenames[0], got.CriticalPaths[0], got.ExcludePaths[0] = "/changed", ".inc", "changed", "/changed/critical", "/changed/cache"
	if rules.Roots[0] != "/srv/sites" || rules.Extensions[0] != ".php" || rules.ImportantFilenames[0] != ".htaccess" || rules.CriticalPaths[0] != "/srv/sites/example/config.php" || rules.ExcludePaths[0] != "/srv/sites/**/cache/**" || base.Roots[0] != "/www/wwwroot" {
		t.Fatal("merged rules alias input")
	}
	rules = defaultMonitoringRules()
	rules.Roots[0] = "/changed"
	if defaultMonitoringRules().Roots[0] != "/www/wwwroot" {
		t.Fatal("default rules share mutable storage")
	}
}

func TestMonitoringRulesRejectInvalidBoundaries(t *testing.T) {
	for name, change := range map[string]func(*MonitoringRules){
		"empty-roots":       func(r *MonitoringRules) { r.Roots = nil },
		"many-roots":        func(r *MonitoringRules) { r.Roots = make([]string, 65) },
		"relative-root":     func(r *MonitoringRules) { r.Roots = []string{"www"} },
		"parent-root":       func(r *MonitoringRules) { r.Roots = []string{"/www/../etc"} },
		"unclean-root":      func(r *MonitoringRules) { r.Roots = []string{"/www//sites"} },
		"control-root":      func(r *MonitoringRules) { r.Roots = []string{"/www/\tcommand"} },
		"unicode-control":   func(r *MonitoringRules) { r.Roots = []string{"/www/\u0085command"} },
		"invalid-utf8":      func(r *MonitoringRules) { r.Roots = []string{"/www/" + string([]byte{0xff})} },
		"long-path":         func(r *MonitoringRules) { r.Roots = []string{"/" + strings.Repeat("a", 4096)} },
		"duplicate-root":    func(r *MonitoringRules) { r.Roots = []string{"/www/wwwroot", "/www/wwwroot"} },
		"relative-critical": func(r *MonitoringRules) { r.CriticalPaths = []string{"relative.php"} },
		"extension-glob":    func(r *MonitoringRules) { r.Extensions = []string{"*.php"} },
		"extension-slash":   func(r *MonitoringRules) { r.Extensions = []string{".php/a"} },
		"empty-extension":   func(r *MonitoringRules) { r.Extensions = []string{""} },
		"long-extension":    func(r *MonitoringRules) { r.Extensions = []string{"." + strings.Repeat("p", 64)} },
		"duplicate-case":    func(r *MonitoringRules) { r.Extensions = []string{".php", ".PHP"} },
		"filename-path":     func(r *MonitoringRules) { r.ImportantFilenames = []string{"../config.php"} },
		"filename-current":  func(r *MonitoringRules) { r.ImportantFilenames = []string{"."} },
		"filename-parent":   func(r *MonitoringRules) { r.ImportantFilenames = []string{".."} },
		"long-filename":     func(r *MonitoringRules) { r.ImportantFilenames = []string{strings.Repeat("a", 256)} },
		"relative-exclude":  func(r *MonitoringRules) { r.ExcludePaths = []string{"cache/**"} },
		"outside-exclude":   func(r *MonitoringRules) { r.ExcludePaths = []string{"/etc/cache/**"} },
		"exclude-root":      func(r *MonitoringRules) { r.ExcludePaths = []string{"/www/wwwroot"} },
		"exclude-critical": func(r *MonitoringRules) {
			r.CriticalPaths, r.ExcludePaths = []string{"/www/wwwroot/site/config.php"}, []string{"/www/wwwroot/site/**"}
		},
		"reserved-root": func(r *MonitoringRules) { r.Roots = []string{"/var/lib/webscan-v1/.scanner-readiness"} },
		"zero-interval": func(r *MonitoringRules) { r.ReconciliationIntervalHours = 0 },
		"long-interval": func(r *MonitoringRules) { r.ReconciliationIntervalHours = 8761 },
		"too-many-items": func(r *MonitoringRules) {
			r.Extensions = make([]string, 10000)
			for i := range r.Extensions {
				r.Extensions[i] = fmt.Sprintf(".e%d", i)
			}
		},
		"too-many-bytes": func(r *MonitoringRules) {
			r.ImportantFilenames = make([]string, 2200)
			for i := range r.ImportantFilenames {
				r.ImportantFilenames[i] = fmt.Sprintf("%0250d", i)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := defaultMonitoringRules()
			change(&r)
			if err := validateMonitoringRules(r); err == nil {
				t.Fatal("invalid public rules accepted")
			} else if err.Error() != errMonitoringRules.Error() {
				t.Fatal("validation error exposed rule content")
			}
		})
	}
}

func TestMonitoringRulesProbeAndAdvancedSettingsAreCheckedAtCorrectLayer(t *testing.T) {
	rules := defaultMonitoringRules()
	rules.Roots = []string{"/srv/customer-site"}
	rules.ExcludePaths = []string{"/srv/customer-site/.webscan-probe"}
	// A different explicit probe is valid. The pure monitor merge must not
	// reject this using the unrelated old default probe directory.
	m, err := monitorWithRules(nodeconfig.DefaultSettings().Monitor, rules)
	if err != nil {
		t.Fatal("valid monitor-only rule merge rejected", err)
	}
	s := nodeconfig.DefaultSettings()
	s.Monitor = m
	if s.Validate() == nil {
		t.Fatal("old probe outside new roots accepted as complete settings")
	}
	s.ProbeDirectory = "/srv/customer-site/.webscan-probe"
	if s.Validate() == nil {
		t.Fatal("excluded explicit probe accepted")
	}
	s.ProbeDirectory = "/srv/customer-site/.approved-probe"
	if err := s.Validate(); err != nil {
		t.Fatal("valid explicit probe rejected", err)
	}
	for name, change := range map[string]func(*nodeconfig.Monitor){
		"unsupported-site-mode": func(m *nodeconfig.Monitor) { m.SiteNameMode = "unsupported" },
		"bad-jitter":            func(m *nodeconfig.Monitor) { m.Reconciliation.StartJitterMinutes = -1 },
		"bad-read-budget":       func(m *nodeconfig.Monitor) { m.Reconciliation.MaxReadMiBPerSecond = 0 },
		"bad-nice":              func(m *nodeconfig.Monitor) { m.Reconciliation.Nice = 20 },
		"bad-io-class":          func(m *nodeconfig.Monitor) { m.Reconciliation.IOClass = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			base := nodeconfig.DefaultSettings().Monitor
			change(&base)
			if _, err := monitorWithRules(base, defaultMonitoringRules()); err == nil {
				t.Fatal("invalid advanced settings silently reset or accepted")
			}
		})
	}
}
