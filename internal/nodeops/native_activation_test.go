package nodeops

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type activationMachine struct {
	machine                *installationMachine
	activation             *nativeActivation
	request                Request
	fail, crashAfter       string
	program, configuration string
	starts                 int
}

func nativeActivationFixture(t *testing.T, fresh bool, originalState ...[2]bool) *activationMachine {
	t.Helper()
	files := bundleFiles()
	bundleChecksums(files)
	w, r := stageFixture(t, archiveFiles(t, files, nil))
	attachConfiguration(t, w, &r, nil)
	if _, err := w.Apply(r); err != nil {
		t.Fatal(err)
	}
	m := installationFixture(t, "native")
	m.host.root = w.root
	if fresh {
		if err := os.Remove(filepath.Join(m.host.configRoot, "runtime.json")); err != nil {
			t.Fatal(err)
		}
		m.nativeRunning = false
		m.nativeEnabled = false
	} else {
		m.addNative(t)
		if len(originalState) > 0 {
			m.nativeEnabled = originalState[0][0]
			m.nativeRunning = originalState[0][1]
		}
	}
	a := &activationMachine{machine: m, request: r, program: "/opt/webscan-go/releases/v2.0.46/webscan", configuration: filepath.Join(m.host.configRoot, "runtime.json")}
	m.host.processExecutable = func(int) (string, error) { return a.program, nil }
	m.host.processArguments = func(int) ([]string, error) { return []string{a.program, "agent", "--config", a.configuration}, nil }
	base := m.command
	m.host.command = func(ctx context.Context, p string, args ...string) (string, error) {
		if p == "systemctl" && args[0] == a.fail {
			return "", errors.New("injected-service-command-failure")
		}
		if p == "systemctl" && args[0] == "show" {
			if _, err := os.Lstat(m.host.unitPath); os.IsNotExist(err) {
				return "LoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=\nJob=0\nMainPID=0\n", errors.New("not-found")
			}
		}
		if p == "systemctl" && args[0] == "daemon-reload" {
			m.calls = append(m.calls, "systemctl daemon-reload")
			if a.crashAfter == args[0] {
				return "", errors.New("injected-response-loss")
			}
			return "", nil
		}
		if p == "systemctl" && args[0] == "start" {
			if !m.nativeRunning {
				a.starts++
			}
			unit, _ := os.ReadFile(m.host.unitPath)
			if bytes.Equal(unit, m.nativeUnit) {
				a.program = "/opt/webscan-go/releases/v2.0.46/webscan"
				a.configuration = filepath.Join(m.host.configRoot, "runtime.json")
			} else {
				a.program = filepath.Join(w.releaseDir(r.Spec), "webscan")
				a.configuration = filepath.Join(w.configurationDir(r.Spec), "runtime.json")
			}
		}
		out, err := base(ctx, p, args...)
		if p == "systemctl" && args[0] == a.crashAfter {
			return out, errors.New("injected-response-loss")
		}
		return out, err
	}
	b := &transitionBackup{root: w.root, data: filepath.Join(w.root, "data"), logs: filepath.Join(w.root, "logs"), unit: m.host.unitPath, host: m.host}
	r.Phase = "backup"
	if _, err := b.run(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	a.activation = &nativeActivation{runtime: w, backup: b, host: m.host}
	r.Phase = "activate"
	a.request = r
	return a
}
func TestNativeActivationFreshAndExistingInstallation(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing", true: "fresh"}[fresh], func(t *testing.T) {
			a := nativeActivationFixture(t, fresh)
			ctx := context.Background()
			if err := a.activation.run(ctx, a.request); err != nil {
				t.Fatal(err)
			}
			if !a.machine.nativeRunning || !a.machine.nativeEnabled || a.starts != 1 {
				t.Fatal("target not activated")
			}
			plan, err := a.activation.plan(ctx, a.request)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.activation.confirm(ctx, plan); err != nil {
				t.Fatal(err)
			}
			current, err := a.activation.host.inventory(ctx, a.request.Node, "native")
			if err != nil || current.Generation != "v3" || len(current.Services) != 1 {
				t.Fatal("activated runtime cannot be inventoried", current, err)
			}
			if current.Services[0].Configuration != plan.target.Configuration {
				t.Fatal("loaded configuration not bound")
			}
			if err := a.activation.run(ctx, a.request); err != nil || a.starts != 1 {
				t.Fatal("retry started another writer", err, a.starts)
			}
		})
	}
}

func TestNativeStatusReloadToleranceIsRestrictedToTransition(t *testing.T) {
	raw := "LoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=\nDropInPaths=\nNeedDaemonReload=yes\nUnitFileState=\nJob=0\nMainPID=0\n"
	if _, err := decodeNativeStatus(raw, true, true); err != nil {
		t.Fatal("fresh unit pending reload not recognized", err)
	}
	for _, flags := range [][2]bool{{false, false}, {false, true}, {true, false}} {
		if _, err := decodeNativeStatus(raw, flags[0], flags[1]); err == nil {
			t.Fatal("pending reload accepted outside explicit fresh transition", flags)
		}
	}
	if _, err := decodeNativeStatus(strings.Replace(raw, "Job=0", "Job=12", 1), true, true); err == nil {
		t.Fatal("pending manager job ignored")
	}
}
func TestNativeActivationContinuesInterruptedStepsWithoutRestartingWriter(t *testing.T) {
	for _, operation := range []string{"daemon-reload", "enable", "start"} {
		t.Run(operation, func(t *testing.T) {
			a := nativeActivationFixture(t, false)
			a.crashAfter = operation
			if err := a.activation.run(context.Background(), a.request); err == nil {
				t.Fatal("lost response reported success")
			}
			a.crashAfter = ""
			a.request.Epoch++
			if err := a.activation.run(context.Background(), a.request); err != nil {
				t.Fatal("interrupted activation could not continue", err)
			}
			if a.starts != 1 || !a.machine.nativeRunning || !a.machine.nativeEnabled {
				t.Fatal("writer started twice or not recovered", a.starts)
			}
		})
	}
}
func TestNativeActivationRejectsChangedFilesBeforeStarting(t *testing.T) {
	for _, kind := range []string{"unit", "pointer", "intent", "backup", "prepared", "wrong-config", "foreign-unit", "writer-lock"} {
		t.Run(kind, func(t *testing.T) {
			a := nativeActivationFixture(t, false)
			ctx := context.Background()
			w := a.activation.runtime
			r := a.request
			var closeLock func()
			switch kind {
			case "unit":
				os.WriteFile(a.machine.host.unitPath, []byte("foreign-unit"), 0600)
			case "pointer":
				os.WriteFile(filepath.Join(w.root, "active.json"), []byte("foreign-pointer"), 0600)
			case "intent":
				p, err := a.activation.plan(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				if err := a.activation.publishIntent(r, p); err != nil {
					t.Fatal(err)
				}
				os.WriteFile(a.activation.intentPath(r), []byte("foreign-intent"), 0600)
			case "backup":
				os.WriteFile(filepath.Join(a.activation.backup.directory(r), "snapshot", "unexpected"), []byte("unverified"), 0600)
			case "prepared":
				os.WriteFile(filepath.Join(w.configurationDir(r.Spec), "runtime.json"), []byte("{}"), 0600)
			case "wrong-config":
				a.machine.nativeRunning = true
				a.configuration = "/etc/foreign.json"
			case "foreign-unit":
				original := a.activation.host.command
				a.activation.host.command = func(ctx context.Context, p string, args ...string) (string, error) {
					raw, err := original(ctx, p, args...)
					if p == "systemctl" && args[0] == "show" {
						raw = strings.ReplaceAll(raw, a.machine.host.unitPath, "/lib/systemd/system/foreign.service")
					}
					return raw, err
				}
			case "writer-lock":
				lock, err := a.activation.backup.agentLock()
				if err != nil {
					t.Fatal(err)
				}
				closeLock = func() { lock.Close() }
			}
			if closeLock != nil {
				defer closeLock()
			}
			if err := a.activation.run(ctx, r); err == nil {
				t.Fatal("unsafe activation accepted")
			}
			if a.starts != 0 {
				t.Fatal("started before proving ownership")
			}
		})
	}
}
func TestNativeActivationDoesNotGuessStartedStateFromCommandSuccess(t *testing.T) {
	a := nativeActivationFixture(t, false)
	old := a.activation.host.command
	a.activation.host.command = func(ctx context.Context, p string, args ...string) (string, error) {
		if p == "systemctl" && args[0] == "start" {
			return "", nil
		}
		return old(ctx, p, args...)
	}
	if err := a.activation.run(context.Background(), a.request); err == nil || err.Error() != "native-activation-not-confirmed" {
		t.Fatal("command success accepted as activation", err)
	}
}
func TestNativeActivationRefusesUnappliedStageAndWrongScope(t *testing.T) {
	for _, kind := range []string{"phase", "inspect", "node", "plan", "config-version"} {
		t.Run(kind, func(t *testing.T) {
			a := nativeActivationFixture(t, true)
			r := a.request
			switch kind {
			case "phase":
				r.Phase = "stage"
			case "inspect":
				r.Operation = "inspect"
			case "node":
				r.Node = "other"
			case "plan":
				r.PlanDigest = strings.Repeat("f", 64)
			case "config-version":
				r.Spec.ConfigVersion++
			}
			if err := a.activation.run(context.Background(), r); err == nil || a.starts != 0 {
				t.Fatal("scope change accepted", err)
			}
		})
	}
}
