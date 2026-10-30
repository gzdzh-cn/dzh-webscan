package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type nativeToDockerMachine struct {
	*dockerActivationMachine
	nativeStarts                      int
	systemFailAfter, systemFailBefore string
	statusTransform                   func(string) string
	oldProgram, oldConfiguration      string
	managerLoaded                     bool
}

// Actual config files, SQLite snapshots/exports and Journal; controlled engine,
// systemd and kernel evidence. This does not certify real systemd installation.
func nativeToDockerJournalFixture(t *testing.T) (*dockerLifecycle, *nativeToDockerMachine, *Journal, *nativeResourceFixture) {
	t.Helper()
	d, base, _, resources := dockerJournalFixture(t, true)
	m := base.machine
	original, _ := json.Marshal(map[string]any{"node_id": base.request.Node, "deployment_mode": "native", "data_dir": agentDataDirectory, "log_dir": agentLogDirectory, "probe_directory": "/srv/site/.webscan-probe"})
	writeResourceFixture(t, filepath.Join(m.host.configRoot, "runtime.json"), string(original))
	m.addNative(t)
	m.nativeRunning, m.nativeEnabled = true, true
	a := &nativeToDockerMachine{dockerActivationMachine: base, managerLoaded: true, oldProgram: "/opt/webscan-go/releases/v2.0.46/webscan", oldConfiguration: filepath.Join(m.host.configRoot, "runtime.json")}
	command := d.activation.host.command
	d.activation.host.processExecutable = func(pid int) (string, error) {
		if m.nativeRunning {
			return a.oldProgram, nil
		}
		return base.target.Entrypoint[0], nil
	}
	d.activation.host.processArguments = func(pid int) ([]string, error) {
		if m.nativeRunning {
			return []string{a.oldProgram, "agent", "--config", a.oldConfiguration}, nil
		}
		return append(append([]string{}, base.target.Entrypoint...), base.target.Command...), nil
	}
	d.activation.host.command = func(ctx context.Context, p string, args ...string) (string, error) {
		if p != "systemctl" {
			return command(ctx, p, args...)
		}
		verb := args[0]
		if verb == a.systemFailBefore {
			return "", errors.New("system-operation-before-failure")
		}
		raw := ""
		var err error
		switch verb {
		case "show":
			_, statErr := os.Lstat(m.host.unitPath)
			if a.managerLoaded {
				raw = m.status()
				if os.IsNotExist(statErr) {
					raw = strings.ReplaceAll(raw, "NeedDaemonReload=no", "NeedDaemonReload=yes")
				}
			} else {
				raw = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=\nJob=0\nMainPID=0\n"
				err = errors.New("not-found")
			}
			if a.statusTransform != nil {
				raw = a.statusTransform(raw)
			}
		case "daemon-reload":
			_, statErr := os.Lstat(m.host.unitPath)
			a.managerLoaded = statErr == nil
		default:
			if verb == "start" && !m.nativeRunning {
				a.nativeStarts++
			}
			raw, err = m.command(ctx, p, args...)
		}
		if err == nil && verb == a.systemFailAfter {
			return raw, errors.New("system-response-lost")
		}
		return raw, err
	}
	d.activation.backup.host = d.activation.host
	return d, a, openTestJournal(t, filepath.Join(d.runtime.root, "native-docker-journal"), d), resources
}

func TestNativeToDockerJournalRetiresUnitAndPreservesNewData(t *testing.T) {
	d, a, j, _ := nativeToDockerJournalFixture(t)
	db := dockerRestorationData(t, a.dockerActivationMachine)
	r := a.request
	finishThrough(t, j, r, "finalize")
	if _, err := os.Lstat(a.machine.host.unitPath); !os.IsNotExist(err) {
		t.Fatal("old unit not retired", err)
	}
	if a.machine.nativeRunning || a.machine.nativeEnabled || a.starts != 1 || a.creates != 1 {
		t.Fatal("wrong writer state")
	}
	for _, phase := range forward {
		r.Phase, r.Operation = phase, "inspect"
		requireResult(t, j.Handle(r), "complete", "ok")
	}
	current, err := d.activation.host.inventory(context.Background(), r.Node, "docker")
	if err != nil || current.Mode != "docker" || len(current.Services) != 1 || current.Services[0].Kind != "docker" {
		t.Fatal(current, err)
	}
	if _, err := db.Exec(`INSERT INTO events VALUES('after-switch','{"event_id":"after-switch","node_id":"node-one"}',3,NULL,NULL)`); err != nil {
		t.Fatal(err)
	}
	r.Phase, r.Operation = "restore", "apply"
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	if !a.machine.nativeRunning || !a.machine.nativeEnabled || a.nativeStarts != 1 || a.starts != 1 {
		t.Fatal("original native not restored")
	}
	unit, err := os.ReadFile(a.machine.host.unitPath)
	if err != nil || string(unit) != string(a.machine.nativeUnit) {
		t.Fatal("original unit changed", err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM events WHERE accepted IS NULL AND exported IS NOT NULL").Scan(&count); err != nil || count != 2 {
		t.Fatal("new events lost", count, err)
	}
	for _, phase := range []string{"restore", "verify-rollback"} {
		r.Phase = phase
		requireResult(t, j.Handle(r), "complete", "ok")
	}
	if a.nativeStarts != 1 {
		t.Fatal("replayed original start")
	}
}

func TestNativeToDockerJournalContinuesLostResponses(t *testing.T) {
	for _, verb := range []string{"daemon-reload", "compose", "update", "start"} {
		t.Run(verb, func(t *testing.T) {
			d, a, j, _ := nativeToDockerJournalFixture(t)
			r := a.request
			finishThrough(t, j, r, "backup")
			if verb == "daemon-reload" {
				a.systemFailAfter = verb
			} else {
				a.failAfter = verb
			}
			r.Phase = "activate"
			requireResult(t, j.Handle(r), "unknown", "activation-failed")
			a.systemFailAfter, a.failAfter = "", ""
			j = openTestJournal(t, j.root, d)
			r.Epoch++
			r.Operation = "inspect"
			state := "absent"
			if verb == "start" {
				state = "complete"
			}
			requireResult(t, j.Handle(r), state, "ok")
			r.Operation = "apply"
			requireResult(t, j.Handle(r), "complete", "ok")
			r.Phase = "verify"
			requireResult(t, j.Handle(r), "complete", "ok")
			if a.starts != 1 || a.creates != 1 || a.nativeStarts != 0 || a.machine.nativeRunning {
				t.Fatal("duplicate writer")
			}
		})
	}
}

func TestNativeToDockerRetirementReloadMustCompleteBeforeCreate(t *testing.T) {
	d, a, j, _ := nativeToDockerJournalFixture(t)
	r := a.request
	finishThrough(t, j, r, "backup")
	a.systemFailBefore = "daemon-reload"
	r.Phase = "activate"
	requireResult(t, j.Handle(r), "unknown", "activation-failed")
	if a.creates != 0 || a.starts != 0 {
		t.Fatal("started before manager retirement")
	}
	r.Operation = "inspect"
	requireResult(t, j.Handle(r), "absent", "ok")
	a.systemFailBefore = ""
	r.Operation = "apply"
	requireResult(t, j.Handle(r), "complete", "ok")
	if err := d.activation.nativeOriginalStopped(context.Background(), r, mustDockerPlan(t, d, r), true); err != nil {
		t.Fatal(err)
	}
}
func mustDockerPlan(t *testing.T, d *dockerLifecycle, r Request) dockerActivationPlan {
	t.Helper()
	p, err := d.activationPlan(context.Background(), r, true)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNativeToDockerRollbackLostResponsesAndInitialStates(t *testing.T) {
	for _, running := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			for _, verb := range []string{"daemon-reload", "enable", "disable", "start", "rename"} {
				if verb == "start" && !running || verb == "enable" && !enabled || verb == "disable" && enabled {
					continue
				}
				t.Run(fmt.Sprint(running, "/", enabled, "/", verb), func(t *testing.T) {
					_, a, j, _ := nativeToDockerJournalFixture(t)
					a.machine.nativeRunning, a.machine.nativeEnabled = running, enabled
					dockerRestorationData(t, a.dockerActivationMachine)
					r := a.request
					finishThrough(t, j, r, "activate")
					if verb == "rename" {
						a.failAfter = verb
					} else {
						a.systemFailAfter = verb
					}
					r.Phase = "restore"
					requireResult(t, j.Handle(r), "unknown", "remote-state-unknown")
					a.systemFailAfter, a.failAfter = "", ""
					r.Epoch++
					requireResult(t, j.Handle(r), "complete", "ok")
					r.Phase = "verify-rollback"
					requireResult(t, j.Handle(r), "complete", "ok")
					wantStarts := 0
					if running {
						wantStarts = 1
					}
					if a.nativeStarts != wantStarts || a.machine.nativeRunning != running || a.machine.nativeEnabled != enabled {
						t.Fatal("old service state changed", a.nativeStarts)
					}
				})
			}
		}
	}
}

func TestNativeToDockerRejectsUnprovenUnitOrConcurrentWriter(t *testing.T) {
	for _, kind := range []string{"missing-unit", "changed-unit", "unit-mode", "unit-link", "dropin", "manager-job", "foreign-fragment", "foreign-program", "foreign-config", "original-enabled-with-target", "original-running-with-target", "reappeared-unit"} {
		t.Run(kind, func(t *testing.T) {
			d, a, j, _ := nativeToDockerJournalFixture(t)
			r := a.request
			finishThrough(t, j, r, "backup")
			r.Phase = "activate"
			if strings.HasSuffix(kind, "with-target") || kind == "reappeared-unit" {
				requireResult(t, j.Handle(r), "complete", "ok")
				writeResourceFixture(t, a.machine.host.unitPath, string(a.machine.nativeUnit))
				a.managerLoaded = true
			}
			switch kind {
			case "missing-unit":
				if err := os.Remove(a.machine.host.unitPath); err != nil {
					t.Fatal(err)
				}
			case "changed-unit":
				writeResourceFixture(t, a.machine.host.unitPath, "foreign")
			case "unit-mode":
				if err := os.Chmod(a.machine.host.unitPath, 0400); err != nil {
					t.Fatal(err)
				}
			case "unit-link":
				if err := os.Remove(a.machine.host.unitPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(a.machine.host.configRoot, "runtime.json"), a.machine.host.unitPath); err != nil {
					t.Fatal(err)
				}
			case "dropin":
				a.statusTransform = func(s string) string { return strings.ReplaceAll(s, "DropInPaths=", "DropInPaths=/etc/foreign.conf") }
			case "manager-job":
				a.statusTransform = func(s string) string { return strings.ReplaceAll(s, "Job=0", "Job=19") }
			case "foreign-fragment":
				a.statusTransform = func(s string) string {
					return strings.ReplaceAll(s, "FragmentPath="+a.machine.host.unitPath, "FragmentPath=/etc/foreign.service")
				}
			case "foreign-program", "foreign-config":
				a.machine.nativeRunning = true
				if kind == "foreign-program" {
					a.oldProgram = "/foreign"
				} else {
					a.oldConfiguration = "/foreign.json"
				}
			case "original-enabled-with-target":
				a.machine.nativeEnabled = true
			case "original-running-with-target":
				a.machine.nativeRunning = true
			}
			creates, starts := a.creates, a.starts
			if err := d.activation.run(context.Background(), r); err == nil {
				t.Fatal("unproven native state accepted")
			}
			if a.creates != creates || a.starts != starts {
				t.Fatal("started before proving native state")
			}
			r.Phase = "restore"
			// An intact, stopped unit reappearing does not prevent safe rollback.
			if kind != "reappeared-unit" {
				if err := d.activation.restore(context.Background(), r); err == nil {
					t.Fatal("unsafe original adopted during rollback")
				}
			}
		})
	}
}

func TestNativeToDockerCannotAdoptRetirementWithoutIntent(t *testing.T) {
	d, a, j, _ := nativeToDockerJournalFixture(t)
	r := a.request
	finishThrough(t, j, r, "backup")
	a.systemFailAfter = "daemon-reload"
	r.Phase = "activate"
	requireResult(t, j.Handle(r), "unknown", "activation-failed")
	a.systemFailAfter = ""
	if err := os.Remove(d.activation.intentPath(r)); err != nil {
		t.Fatal(err)
	}
	state, _, err := d.Reconcile(r)
	if err == nil || state != "unknown" {
		t.Fatal("missing retirement authority accepted", state, err)
	}
	r.Phase = "restore"
	if err := d.activation.restore(context.Background(), r); err == nil {
		t.Fatal("missing intent allowed restoring absent unit")
	}
	if a.starts != 0 || a.nativeStarts != 0 {
		t.Fatal("writer started without authority")
	}
}

func TestNativeToDockerCaptureOnlyAndResourceFailureRollback(t *testing.T) {
	for _, kind := range []string{"capture-only", "resources", "damaged-binary", "damaged-runtime", "damaged-compose"} {
		t.Run(kind, func(t *testing.T) {
			d, a, j, f := nativeToDockerJournalFixture(t)
			db := dockerRestorationData(t, a.dockerActivationMachine)
			r := a.request
			if kind == "capture-only" {
				finishThrough(t, j, r, "stage")
				lock, err := d.activation.backup.agentLock()
				if err != nil {
					t.Fatal(err)
				}
				r.Phase = "backup"
				requireResult(t, j.Handle(r), "unknown", "backup-failed")
				lock.Close()
				if _, err := os.Lstat(filepath.Join(d.activation.backup.directory(r), "snapshot")); !os.IsNotExist(err) {
					t.Fatal("snapshot unexpectedly published")
				}
			} else {
				finishThrough(t, j, r, "activate")
				switch kind {
				case "resources":
					writeResourceFixture(t, f.memory, "max\n")
					r.Phase = "verify"
					requireResult(t, j.Handle(r), "unknown", "verification-failed")
				case "damaged-binary":
					if err := os.Remove(filepath.Join(d.runtime.releaseDir(r.Spec), "webscan")); err != nil {
						t.Fatal(err)
					}
				case "damaged-runtime":
					writeResourceFixture(t, filepath.Join(d.runtime.configurationDir(r.Spec), "runtime.json"), "damaged")
				case "damaged-compose":
					writeResourceFixture(t, filepath.Join(d.runtime.configurationDir(r.Spec), "compose.json"), "damaged")
				}
			}
			r.Phase, r.Operation = "restore", "apply"
			r.Epoch++
			requireResult(t, j.Handle(r), "complete", "ok")
			r.Phase = "verify-rollback"
			requireResult(t, j.Handle(r), "complete", "ok")
			if !a.machine.nativeRunning || !a.machine.nativeEnabled || a.nativeStarts != 1 {
				t.Fatal("native original not restored")
			}
			var count int
			if err := db.QueryRow("SELECT count(*) FROM events WHERE accepted IS NULL AND exported IS NOT NULL").Scan(&count); err != nil || count != 1 {
				t.Fatal("pending data lost", count, err)
			}
		})
	}
}

func TestNativeToDockerRestoresPreviousV3PointerAndUnit(t *testing.T) {
	d, a, j, _ := nativeToDockerJournalFixture(t)
	old := a.request
	old.Spec.Mode = "native"
	old.Spec.AgentImage = ""
	old.Job = "job-previous"
	old.PlanDigest = strings.Repeat("c", 64)
	attachConfiguration(t, d.runtime, &old, nil)
	if err := d.runtime.prepareConfiguration(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	unit, err := readPrivate(filepath.Join(d.runtime.configurationDir(old.Spec), nativeServiceName), 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	a.machine.nativeUnit = unit
	writeResourceFixture(t, a.machine.host.unitPath, string(unit))
	runtime, err := readPrivate(filepath.Join(d.runtime.configurationDir(old.Spec), "runtime.json"), 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	pointer, err := json.Marshal(ActiveInstallation{Format: 1, Node: old.Node, Spec: old.Spec, RuntimeSHA256: sha(runtime), DefinitionSHA256: sha(unit), Job: old.Job, PlanDigest: old.PlanDigest})
	if err != nil {
		t.Fatal(err)
	}
	writeResourceFixture(t, filepath.Join(d.runtime.root, "active.json"), string(pointer))
	a.oldProgram = filepath.Join(d.runtime.releaseDir(old.Spec), "webscan")
	a.oldConfiguration = filepath.Join(d.runtime.configurationDir(old.Spec), "runtime.json")
	db := dockerRestorationData(t, a.dockerActivationMachine)
	r := a.request
	finishThrough(t, j, r, "finalize")
	if _, err := db.Exec(`INSERT INTO events VALUES('v3-new','{"event_id":"v3-new","node_id":"node-one"}',3,NULL,NULL)`); err != nil {
		t.Fatal(err)
	}
	r.Phase = "restore"
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	restored, err := readPrivate(filepath.Join(d.runtime.root, "active.json"), MaxRequestBytes)
	if err != nil || string(restored) != string(pointer) {
		t.Fatal("previous v3 pointer not restored", err)
	}
	current, err := d.activation.host.inventory(context.Background(), r.Node, "native")
	if err != nil || current.Generation != "v3" || current.Mode != "native" || len(current.Services) != 1 || current.Services[0].Configuration != a.oldConfiguration {
		t.Fatal("previous installation not restored", current, err)
	}
	if a.nativeStarts != 1 || a.creates != 1 || a.starts != 1 {
		t.Fatal("recreated original or target")
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM events WHERE accepted IS NULL AND exported IS NOT NULL").Scan(&count); err != nil || count != 2 {
		t.Fatal("new data lost", count, err)
	}
}
