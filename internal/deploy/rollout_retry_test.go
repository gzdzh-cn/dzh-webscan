package deploy

import (
	"os"
	"path/filepath"
	"testing"
	"webscan/internal/common"
)

func rolledBackRolloutFixture(t *testing.T) *Deploy {
	t.Helper()
	c := fixture(t)
	return &Deploy{C: c, O: Options{Install: true}, State: common.Map{
		"run_id": "go-failed", "step": "central-go-ready", "target_release": "v2.0.26", "central_installed": true, "central_runtime_release": "v2.0.26",
		"target_config_hash": common.Hash(common.JSON(Redact(c.Raw))), "active": []string{},
		"last_failure": common.Map{"stage": "rollout", "rollback_confirmed": true},
		"rollout":      common.Map{"accepted": common.Map{}, "prepared": common.Map{}, "previous_active": []string{}},
		"nodes":        common.Map{"node-202": common.Map{"go_run_id": "go-failed", "phase": "go-rolled-back"}},
	}, Secrets: common.Map{}}
}

func TestConfirmedRolloutRetryKeepsJournalAndUsesNewRelease(t *testing.T) {
	previous := StateRoot
	StateRoot = t.TempDir()
	t.Cleanup(func() { StateRoot = previous })
	d := rolledBackRolloutFixture(t)
	old := filepath.Join(StateRoot, "runs", "go-failed", "central", "evidence")
	os.MkdirAll(filepath.Dir(old), 0700)
	os.WriteFile(old, []byte("preserved"), 0600)
	d.selectInstallMode()
	if d.O.Resume || !d.O.Upgrade || !d.canRetryRollout() {
		t.Fatal("confirmed rollback pinned to old resume")
	}
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	if d.RunID == "go-failed" || common.S(d.State["target_release"]) != Release || !common.B(d.State["central_installed"]) || !d.canStageRollout() {
		t.Fatal("new attempt lost main, release or node-first flow")
	}
	if b, err := os.ReadFile(old); err != nil || string(b) != "preserved" {
		t.Fatal("previous evidence overwritten")
	}
}

func TestRolloutRetryRejectsUnconfirmedChangedOrPartiallyAcceptedRuns(t *testing.T) {
	for name, change := range map[string]func(*Deploy){
		"unconfirmed":     func(d *Deploy) { common.M(d.State["last_failure"])["rollback_confirmed"] = false },
		"accepted":        func(d *Deploy) { common.M(common.M(d.State["rollout"])["accepted"])["node-202"] = true },
		"prepared":        func(d *Deploy) { common.M(common.M(d.State["rollout"])["prepared"])["node-202"] = true },
		"main-started":    func(d *Deploy) { common.M(d.State["rollout"])["main_started"] = true },
		"node-running":    func(d *Deploy) { common.M(common.M(d.State["nodes"])["node-202"])["phase"] = "go-switched" },
		"changed-config":  func(d *Deploy) { d.State["target_config_hash"] = "changed" },
		"changed-active":  func(d *Deploy) { d.State["active"] = []string{"node-202"} },
		"different-scope": func(d *Deploy) { d.O.Node = "node-202" },
		"explicit-resume": func(d *Deploy) { d.O.Resume = true },
		"uninstall":       func(d *Deploy) { d.State["central_uninstall_pending"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			d := rolledBackRolloutFixture(t)
			change(d)
			if d.canRetryRollout() {
				t.Fatal("unsafe retry admitted")
			}
		})
	}
}
