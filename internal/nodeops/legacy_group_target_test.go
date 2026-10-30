package nodeops

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type groupTargetMachine struct {
	f         *wrapperGroupMachine
	r         Request
	db        *sql.DB
	n         *nativeActivation
	d         *dockerActivation
	docker    *dockerActivationMachine
	failAfter string
}

// Service-manager and Docker operations are substitutes; snapshot, live DB,
// reconciliation, private provenance and interruption receipts are actual code.
func groupTargetBeforeBackup(t *testing.T, original, target string, setup ...func(*wrapperGroupMachine)) *groupTargetMachine {
	t.Helper()
	f, _, db := wrapperGroupFixture(t, original)
	x := &groupTargetMachine{f: f, db: db}
	if original == "docker" {
		f.m.nativeRunning, f.m.nativeEnabled = false, false
	}
	var w *LocalRuntime
	if target == "native" {
		a := nativeActivationFixture(t, true)
		w, x.r, x.n = a.activation.runtime, a.request, a.activation
	} else {
		a := dockerActivationFixture(t, true)
		w, x.r, x.d, x.docker = a.activation.runtime, a.request, a.activation, a
		a.machine = f.m
	}
	x.r.Job = "group-target"
	x.r.Phase = "backup"
	h := f.g.host
	h.root = w.root
	f.m.host.root = w.root
	baseExe, baseArgs := h.processExecutable, h.processArguments
	program := "/opt/webscan-go/releases/v2.0.46/webscan"
	configuration := filepath.Join(h.configRoot, "runtime.json")
	h.processExecutable = func(pid int) (string, error) {
		if pid == 123 {
			return program, nil
		}
		return baseExe(pid)
	}
	h.processArguments = func(pid int) ([]string, error) {
		if pid == 123 {
			return []string{program, "agent", "--config", configuration}, nil
		}
		return baseArgs(pid)
	}
	f.agentCommand = func(ctx context.Context, cmd string, args ...string) (string, error) {
		var out string
		var err error
		if cmd == "systemctl" {
			switch args[0] {
			case "show":
				if _, err := os.Lstat(h.unitPath); os.IsNotExist(err) {
					return "LoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=\nJob=0\nMainPID=0\n", errors.New("not found")
				}
				return f.m.status(), nil
			case "daemon-reload":
				return "", nil
			case "start":
				unit, _ := os.ReadFile(h.unitPath)
				if bytes.Equal(unit, f.m.nativeUnit) {
					program = "/opt/webscan-go/releases/v2.0.46/webscan"
					configuration = filepath.Join(h.configRoot, "runtime.json")
				} else {
					program = filepath.Join(w.releaseDir(x.r.Spec), "webscan")
					configuration = filepath.Join(w.configurationDir(x.r.Spec), "runtime.json")
				}
			}
			out, err = f.m.command(ctx, cmd, args...)
		} else if x.docker != nil {
			out, err = x.docker.command(ctx, cmd, args...)
			if err == nil && len(args) > 2 && args[2] == "start" && args[len(args)-1] == x.docker.target.ID {
				program = x.docker.target.Entrypoint[0]
				configuration = filepath.Join(w.configurationDir(x.r.Spec), "runtime.json")
			}
		} else if cmd == "docker" && len(args) > 2 && args[2] == "rename" {
			c, ok := f.m.containers[args[3]]
			if !ok {
				return "", errors.New("missing old object")
			}
			c.Name = "/" + args[4]
			f.m.containers[c.ID] = c
		} else {
			out, err = f.m.command(ctx, cmd, args...)
		}
		if err == nil && strings.Contains(cmd+" "+strings.Join(args, " "), x.failAfter) && x.failAfter != "" {
			x.failAfter = ""
			return out, errors.New("lost response")
		}
		return out, err
	}
	f.g.host, f.g.request = h, x.r
	f.g.backup.root = w.root
	for _, m := range f.wrappers {
		m.r, m.w.host = x.r, h
	}
	if x.n != nil {
		x.n.host, x.n.backup = h, f.g.backup
	} else {
		x.d.host, x.d.backup = h, f.g.backup
		x.docker.request = x.r
		x.docker.target.Project = dockerProject(ActiveInstallation{Node: x.r.Node, Job: x.r.Job, PlanDigest: x.r.PlanDigest})
	}
	if _, err := db.Exec(`ALTER TABLE events ADD COLUMN created REAL; ALTER TABLE events ADD COLUMN exported TEXT; CREATE TABLE logfiles(path TEXT PRIMARY KEY,created REAL); CREATE TABLE delivery_failures(id TEXT PRIMARY KEY,error TEXT,created REAL); UPDATE events SET payload='{"event_id":"original-id","node_id":"node-one"}',created=1;`); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.g.backup.logs, "pending.jsonl"), []byte(legacyImportEvent("original-id")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, configure := range setup {
		configure(f)
	}
	return x
}

func groupTargetFixture(t *testing.T, original, target string, setup ...func(*wrapperGroupMachine)) *groupTargetMachine {
	t.Helper()
	x := groupTargetBeforeBackup(t, original, target, setup...)
	if _, err := x.f.g.backup.run(context.Background(), x.r); err != nil {
		t.Fatal(err)
	}
	x.r.Phase = "activate"
	return x
}

func TestLegacyWrapperGroupTargetPreservesIndependentOriginalStates(t *testing.T) {
	for _, old := range []string{"native", "docker"} {
		for _, target := range []string{"native", "docker"} {
			for mask := 0; mask < 4; mask++ {
				t.Run(old+"-to-"+target+"/"+string(rune('0'+mask)), func(t *testing.T) {
					x := groupTargetFixture(t, old, target, func(f *wrapperGroupMachine) {
						for j, m := range f.wrappers {
							m.enabled = (mask&1 != 0) != (j == 1)
							m.running = (mask&2 != 0) != (j == 1)
							m.o.Identity.Status = "exited"
							if m.running {
								m.o.Identity.Status = "running"
							}
						}
						if old == "native" {
							f.m.nativeEnabled = mask&1 != 0
							f.m.nativeRunning = mask&2 != 0
						} else {
							c := f.m.containers[strings.Repeat("1", 64)]
							c.Status = "exited"
							if mask&2 != 0 {
								c.Status = "running"
							}
							c.Restart = "no"
							if mask&1 != 0 {
								c.Restart = "unless-stopped"
							}
							f.m.containers[c.ID] = c
						}
					})
					if err := x.activate(); err != nil {
						t.Fatal(err)
					}
					if err := x.restore(); err != nil {
						t.Fatal(err)
					}
					for j, m := range x.f.wrappers {
						if m.enabled != ((mask&1 != 0) != (j == 1)) || m.running != ((mask&2 != 0) != (j == 1)) {
							t.Fatal("state not restored")
						}
					}
				})
			}
		}
	}
}

func TestLegacyWrapperGroupTargetContinuesInterruptedActivation(t *testing.T) {
	for _, old := range []string{"native", "docker"} {
		for _, target := range []string{"native", "docker"} {
			operations := []string{"systemctl enable " + nativeServiceName, "systemctl start " + nativeServiceName}
			if target == "docker" {
				operations = []string{"rename ", "compose ", "start " + strings.Repeat("9", 64)}
			}
			for _, operation := range operations {
				t.Run(old+"-to-"+target+"/"+operation, func(t *testing.T) {
					x := groupTargetFixture(t, old, target)
					x.failAfter = operation
					if operation == "rename " && old == "native" {
						x.failAfter = "compose "
					}
					if err := x.activate(); err == nil {
						t.Fatal("lost activation response hidden")
					}
					x.r.Epoch++
					if err := x.activate(); err != nil {
						t.Fatal("continue", err)
					}
					if x.docker != nil && (x.docker.creates != 1 || x.docker.starts != 1) {
						t.Fatal("duplicate target", x.docker.creates, x.docker.starts)
					}
					if err := x.restore(); err != nil {
						t.Fatal("restore", err)
					}
				})
			}
		}
	}
}

func (x *groupTargetMachine) activate() error {
	if x.n != nil {
		return x.n.run(context.Background(), x.r)
	}
	return x.d.run(context.Background(), x.r)
}
func (x *groupTargetMachine) restore() error {
	r := x.r
	r.Phase = "restore"
	if x.n != nil {
		return x.n.restore(context.Background(), r)
	}
	return x.d.restore(context.Background(), r)
}

func TestLegacyWrapperGroupTargetActivationAndLosslessRollback(t *testing.T) {
	for _, old := range []string{"native", "docker"} {
		for _, target := range []string{"native", "docker"} {
			t.Run(old+"-to-"+target, func(t *testing.T) {
				x := groupTargetFixture(t, old, target)
				ctx := context.Background()
				i, err := x.f.g.backup.readIntent(ctx, x.r)
				if err != nil {
					t.Fatal(err)
				}
				if len(i.Installed.Wrappers) != 2 {
					t.Fatal("group lost from capture")
				}
				if err := x.activate(); err != nil {
					t.Fatal("activate", err)
				}
				if err := x.activate(); err != nil {
					t.Fatal("replay", err)
				}
				for _, m := range x.f.wrappers {
					if m.running || m.enabled || m.o.Identity.Status == "running" {
						t.Fatal("old wrapper active")
					}
				}
				if _, err := x.db.Exec(`INSERT INTO events VALUES('after-switch','{"event_id":"after-switch","node_id":"node-one"}',NULL,3,NULL)`); err != nil {
					t.Fatal(err)
				}
				if err := x.restore(); err != nil {
					t.Fatal("restore", err)
				}
				for _, m := range x.f.wrappers {
					if !m.running || !m.enabled {
						t.Fatal("wrapper not restored")
					}
				}
				assertBackupRows(t, filepath.Join(x.f.g.backup.data, "agent.sqlite3"), 2)
				var n int
				if err := x.db.QueryRow(`SELECT count(*) FROM events WHERE id='after-switch' AND accepted IS NULL AND exported IS NOT NULL`).Scan(&n); err != nil || n != 1 {
					t.Fatal("new event not exported", n, err)
				}
				before := len(x.f.mutations())
				if err := x.restore(); err != nil {
					t.Fatal("restore replay", err)
				}
				if len(x.f.mutations()) != before {
					t.Fatal("restored group mutated again")
				}
				if err := x.activate(); err == nil {
					t.Fatal("forward allowed after rollback")
				}
			})
		}
	}
}

func TestLegacyWrapperGroupTargetRejectsChangedWrapperBeforeActivation(t *testing.T) {
	for _, target := range []string{"native", "docker"} {
		for _, change := range []string{"running", "enabled", "unit", "object", "authority", "extra"} {
			t.Run(target+"/"+change, func(t *testing.T) {
				x := groupTargetFixture(t, "docker", target)
				m := x.f.wrappers[1]
				switch change {
				case "running":
					m.o.Identity.Status = "running"
				case "enabled":
					m.enabled = true
				case "unit":
					os.WriteFile(m.unit, []byte("foreign"), 0600)
				case "object":
					m.o.Network = "bridge"
				case "authority":
					os.Remove(filepath.Join(x.f.g.host.root, "retained-wrappers", m.name+".json"))
				case "extra":
					os.WriteFile(filepath.Join(filepath.Dir(m.unit), "webscan-agent-v1.service"), []byte("foreign"), 0600)
				}
				before := len(x.f.mutations())
				if err := x.activate(); err == nil {
					t.Fatal("changed wrapper accepted")
				}
				if len(x.f.mutations()) != before {
					t.Fatal("changed group mutated")
				}
			})
		}
	}
}

func TestLegacyWrapperGroupTargetRequiresExplicitCoordinator(t *testing.T) {
	for _, target := range []string{"native", "docker"} {
		t.Run(target, func(t *testing.T) {
			x := groupTargetFixture(t, "docker", target)
			x.f.g.backup.host = x.f.g.host
			if err := x.activate(); err == nil {
				t.Fatal("ungrouped target adopted group")
			}
		})
	}
}

func TestLegacyWrapperGroupTargetResumesPartialRestorationWithoutReexport(t *testing.T) {
	for _, old := range []string{"native", "docker"} {
		for _, target := range []string{"native", "docker"} {
			for _, lost := range []string{"first-start", "second-enable", "agent-start"} {
				t.Run(old+"-to-"+target+"/"+lost, func(t *testing.T) {
					x := groupTargetFixture(t, old, target)
					if err := x.activate(); err != nil {
						t.Fatal(err)
					}
					switch lost {
					case "first-start":
						x.f.wrappers[0].lose = "start"
					case "second-enable":
						x.f.wrappers[1].lose = "enable"
					case "agent-start":
						if old == "native" {
							x.failAfter = "systemctl start " + nativeServiceName
						} else {
							x.failAfter = "start " + strings.Repeat("1", 64)
						}
					}
					if err := x.restore(); err == nil {
						t.Fatal("lost response reported success")
					}
					exportPath := filepath.Join(x.f.g.backup.directory(x.r), "restoration/export.json")
					exportBefore, err := os.ReadFile(exportPath)
					if err != nil {
						t.Fatal(err)
					}
					// Delivery can resume after the first wrapper starts. A durable resume
					// boundary must not rescan/export a now-changing live database.
					if _, err := x.db.Exec(`INSERT INTO events VALUES('after-resume','not-json',NULL,4,NULL); CREATE TRIGGER deny_export BEFORE UPDATE OF exported ON events BEGIN SELECT RAISE(ABORT,'must not reexport'); END`); err != nil {
						t.Fatal(err)
					}
					before := len(x.f.mutations())
					x.r.Epoch++
					if err := x.restore(); err != nil {
						t.Fatal("resume", err)
					}
					for _, call := range x.f.mutations()[before:] {
						if strings.Contains(call, "disable") || strings.Contains(call, " stop ") {
							t.Fatal("stopped a resumed group", call)
						}
					}
					exportAfter, _ := os.ReadFile(exportPath)
					if !bytes.Equal(exportBefore, exportAfter) {
						t.Fatal("export receipt rewritten")
					}
					var n int
					if err := x.db.QueryRow(`SELECT count(*) FROM events WHERE id='after-resume' AND exported IS NULL`).Scan(&n); err != nil || n != 1 {
						t.Fatal("live event changed", err)
					}
				})
			}
		}
	}
}

func TestLegacyWrapperGroupTargetRejectsCorruptResumeBoundary(t *testing.T) {
	for _, target := range []string{"native", "docker"} {
		for _, corruption := range []string{"resume", "export", "pointer", "wrapper", "target"} {
			t.Run(target+"/"+corruption, func(t *testing.T) {
				x := groupTargetFixture(t, "docker", target)
				if err := x.activate(); err != nil {
					t.Fatal(err)
				}
				x.f.wrappers[0].lose = "start"
				if err := x.restore(); err == nil {
					t.Fatal("lost response hidden")
				}
				dir := filepath.Join(x.f.g.backup.directory(x.r), "restoration")
				switch corruption {
				case "resume":
					os.WriteFile(filepath.Join(dir, "group-resume.json"), []byte("{}"), 0600)
				case "export":
					os.Remove(filepath.Join(dir, "export.json"))
				case "pointer":
					os.WriteFile(filepath.Join(x.f.g.host.root, "active.json"), []byte("{}"), 0600)
				case "wrapper":
					os.WriteFile(x.f.wrappers[1].unit, []byte("foreign"), 0600)
				case "target":
					if x.n != nil {
						os.WriteFile(x.f.g.host.unitPath, []byte("foreign"), 0600)
					} else {
						c := x.f.m.containers[x.docker.target.ID]
						c.Status = "running"
						x.f.m.containers[c.ID] = c
					}
				}
				before := len(x.f.mutations())
				if err := x.restore(); err == nil {
					t.Fatal("corrupt resume accepted")
				}
				if len(x.f.mutations()) != before {
					t.Fatal("corrupt resume mutated services")
				}
			})
		}
	}
}

func TestLegacyWrapperGroupTargetRestoreBeforeActivationUsesWholeGroup(t *testing.T) {
	for _, old := range []string{"native", "docker"} {
		for _, target := range []string{"native", "docker"} {
			for _, snapshot := range []bool{false, true} {
				t.Run(old+"-to-"+target+"/snapshot-"+map[bool]string{true: "present", false: "missing"}[snapshot], func(t *testing.T) {
					x := groupTargetFixture(t, old, target)
					if !snapshot {
						if err := os.RemoveAll(filepath.Join(x.f.g.backup.directory(x.r), "snapshot")); err != nil {
							t.Fatal(err)
						}
					}
					if err := x.restore(); err != nil {
						t.Fatal(err)
					}
					for _, m := range x.f.wrappers {
						if !m.running || !m.enabled {
							t.Fatal("lost original wrapper")
						}
					}
					before := len(x.f.mutations())
					if err := x.restore(); err != nil {
						t.Fatal(err)
					}
					if len(x.f.mutations()) != before {
						t.Fatal("replayed before-target restore mutated")
					}
					assertBackupRows(t, filepath.Join(x.f.g.backup.data, "agent.sqlite3"), 1)
					if _, err := os.Lstat(filepath.Join(x.f.g.backup.directory(x.r), "restoration/export.json")); !os.IsNotExist(err) {
						t.Fatal("exported without target")
					}
				})
			}
		}
	}
}
