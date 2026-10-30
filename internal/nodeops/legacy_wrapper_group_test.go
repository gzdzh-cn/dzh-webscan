package nodeops

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Agent and service-manager commands are stateful substitutes. Files, private
// publication, service locks, SQLite backup and preservation use the real code.
type wrapperGroupMachine struct {
	g              *legacyWrapperGroup
	m              *installationMachine
	wrappers       []*wrapperMachine
	calls          []string
	beforeMutation func(string)
	agentCommand   func(context.Context, string, ...string) (string, error)
}

func wrapperGroupFixture(t *testing.T, mode string) (*wrapperGroupMachine, Request, *sql.DB) {
	t.Helper()
	b, r, _, db := backupFixture(t)
	m := installationFixture(t, mode)
	if mode == "native" {
		m.addNative(t)
	} else {
		m.addDocker(t)
	}
	f := &wrapperGroupMachine{m: m}
	h := m.host
	baseExe, baseArgs := h.processExecutable, h.processArguments
	for j, role := range []string{"vector", "exporter"} {
		w := wrapperFixture(t, role, j == 0, true, true)
		w.r = r
		w.w.host = h
		w.o.Identity.ID = strings.Repeat(fmt.Sprint(j+3), 64)
		w.image.ID = "sha256:" + strings.Repeat([]string{"c", "e"}[j], 64)
		w.o.Identity.ImageID = w.image.ID
		w.unit = filepath.Join(filepath.Dir(h.unitPath), w.name)
		if err := os.WriteFile(w.unit, w.loaded, 0644); err != nil {
			t.Fatal(err)
		}
		f.wrappers = append(f.wrappers, w)
	}
	h.processExecutable = func(pid int) (string, error) {
		if pid == 12345 || pid == 12346 {
			return "/usr/bin/docker", nil
		}
		return baseExe(pid)
	}
	h.processArguments = func(pid int) ([]string, error) {
		if pid == 12345 || pid == 12346 {
			return f.wrappers[pid-12345].args, nil
		}
		return baseArgs(pid)
	}
	h.command = f.command
	for _, w := range f.wrappers {
		w.w.host = h
	}
	f.g = newLegacyWrapperGroup(h, r, b.data, b.logs)
	return f, r, db
}

func (f *wrapperGroupMachine) command(ctx context.Context, program string, args ...string) (string, error) {
	call := program + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if serviceMutation(program, args) {
		held, ok := ctx.Value(serviceOperationKey{}).(serviceOperation)
		if !ok || held.root != f.g.host.root || held.file == nil {
			return "", errors.New("missing group lock")
		}
		if f.beforeMutation != nil {
			f.beforeMutation(call)
		}
	}
	if program == "systemctl" && len(args) > 0 {
		if args[0] == "daemon-reload" {
			var first error
			for _, w := range f.wrappers {
				if _, err := w.command(ctx, program, args...); err != nil && first == nil {
					first = err
				}
			}
			if first == nil && f.agentCommand != nil {
				return f.agentCommand(ctx, program, args...)
			}
			return "", first
		}
		for j, w := range f.wrappers {
			if len(args) > 1 && (args[1] == w.name || args[len(args)-1] == w.name) {
				out, err := w.command(ctx, program, args...)
				return strings.ReplaceAll(out, "MainPID=12345", fmt.Sprintf("MainPID=%d", 12345+j)), err
			}
		}
	}
	if program == "docker" && len(args) > 2 {
		a := args[2:]
		for _, w := range f.wrappers {
			if a[0] == "ps" && len(a) > 4 && a[4] == "name=^"+w.o.Identity.Name+"$" || a[0] == "image" && len(a) > 2 && (a[2] == w.u.SourceImage || a[2] == w.image.ID) {
				return w.command(ctx, program, args...)
			}
			if a[0] == "container" && len(a) > 4 && a[2] == w.o.Identity.ID {
				if a[4] == inventoryContainerFormat {
					raw, _ := json.Marshal(w.o.Identity)
					return string(raw), nil
				}
				return w.command(ctx, program, args...)
			}
			if a[0] == "stop" && a[len(a)-1] == w.o.Identity.ID {
				return w.command(ctx, program, args...)
			}
		}
	}
	if f.agentCommand != nil {
		return f.agentCommand(ctx, program, args...)
	}
	return f.m.command(ctx, program, args...)
}

func (f *wrapperGroupMachine) mutations() []string {
	result := []string{}
	for _, call := range f.calls {
		args := strings.Split(call, " ")
		if serviceMutation(args[0], args[1:]) {
			result = append(result, call)
		}
	}
	return result
}

func TestLegacyWrapperGroupBackupAndRecoveryPreserveWholeInstallation(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			f, r, db := wrapperGroupFixture(t, mode)
			f.beforeMutation = func(string) {
				i, err := f.g.backup.readIntent(context.Background(), r)
				if err != nil || len(i.Installed.Wrappers) != 2 || len(i.Installed.Services) != 1 {
					t.Fatalf("mutation before complete durable capture: %v", err)
				}
			}
			snapshot, err := f.g.backup.run(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			i, err := f.g.backup.readIntent(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			if stopped, err := f.g.stopped(context.Background(), i.Installed); err != nil || !stopped {
				t.Fatal("group still running", err)
			}
			if snapshot.Database == nil || len(i.Installed.Wrappers) != 2 || !i.Installed.Services[0].Running {
				t.Fatal("missing original group")
			}
			if supportedNativeOriginal(i.Installed) || supportedDockerOriginal(i.Installed) {
				t.Fatal("single-Agent driver adopted unintegrated group")
			}
			if err := f.g.host.stop(context.Background(), i.Installed); err == nil {
				t.Fatal("ordinary stop ignored wrappers")
			}
			for _, w := range f.wrappers {
				if w.running || w.enabled || w.o.Identity.Status == "running" {
					t.Fatal("wrapper not disabled")
				}
			}
			if _, err := db.Exec(`INSERT INTO events VALUES('after-capture','{"event_id":"after-capture"}',NULL)`); err != nil {
				t.Fatal(err)
			}
			again, err := f.g.backup.run(context.Background(), r)
			if err != nil || !reflect.DeepEqual(snapshot, again) {
				t.Fatal("recaptured backup", err)
			}
			assertBackupRows(t, filepath.Join(f.g.backup.directory(r), "snapshot", "agent.sqlite3"), 1)
			r.Phase = "restore"
			if err := f.g.restoreBeforeActivation(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			for _, w := range f.wrappers {
				if !w.running || !w.enabled {
					t.Fatal("wrapper not restored")
				}
			}
			assertBackupRows(t, filepath.Join(f.g.backup.data, "agent.sqlite3"), 2)
			before := len(f.mutations())
			if err := f.g.restoreBeforeActivation(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			if len(f.mutations()) != before {
				t.Fatal("completed recovery mutated services")
			}
			r.Phase = "backup"
			if _, err := f.g.backup.run(context.Background(), r); err == nil {
				t.Fatal("forward backup after recovery")
			}
		})
	}
}

func TestLegacyWrapperGroupFailureBeforeFirstMutation(t *testing.T) {
	for _, failure := range []string{"second-unit", "second-object", "agent-object", "agent-unit", "runtime", "extra-agent-wrapper", "unclaimed-sidecar"} {
		t.Run(failure, func(t *testing.T) {
			mode := "docker"
			if failure == "agent-unit" {
				mode = "native"
			}
			f, r, _ := wrapperGroupFixture(t, mode)
			switch failure {
			case "second-unit":
				os.WriteFile(f.wrappers[1].unit, []byte("foreign"), 0644)
			case "second-object":
				f.wrappers[1].o.Network = "bridge"
			case "agent-object":
				c := f.m.containers[strings.Repeat("1", 64)]
				c.Project = "unrelated"
				f.m.containers[c.ID] = c
			case "agent-unit":
				os.WriteFile(f.m.host.unitPath, append(f.m.nativeUnit, []byte("ExecStop=/bin/false\n")...), 0600)
			case "runtime":
				os.WriteFile(filepath.Join(f.g.host.configRoot, "runtime.json"), []byte(`{"node_id":"other"}`), 0600)
			case "extra-agent-wrapper":
				os.WriteFile(filepath.Join(filepath.Dir(f.g.host.unitPath), "webscan-agent-v1.service"), []byte("unrecognized"), 0644)
			case "unclaimed-sidecar":
				os.Remove(f.wrappers[1].unit)
				f.m.containers[f.wrappers[1].o.Identity.ID] = f.wrappers[1].o.Identity
				f.wrappers = f.wrappers[:1]
			}
			if _, err := f.g.backup.run(context.Background(), r); err == nil {
				t.Fatal("accepted unsafe group")
			}
			if len(f.mutations()) != 0 {
				t.Fatal("changed service before complete proof", f.mutations())
			}
		})
	}
}

func TestLegacyWrapperGroupRechecksCapturedMembersBeforeStopping(t *testing.T) {
	for _, failure := range []string{"later-unit", "later-object", "later-runtime", "missing-intent", "changed-intent", "agent-name", "new-supervisor", "new-native-agent"} {
		t.Run(failure, func(t *testing.T) {
			f, r, _ := wrapperGroupFixture(t, "docker")
			ctx, release, err := acquireServiceOperation(context.Background(), f.g.host.root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.g.backup.prepareIntent(ctx, r); err != nil {
				t.Fatal(err)
			}
			release()
			switch failure {
			case "later-unit":
				os.WriteFile(f.wrappers[1].unit, []byte("changed"), 0644)
			case "later-object":
				f.wrappers[1].o.Identity.ImageID = "sha256:" + strings.Repeat("a", 64)
			case "later-runtime":
				p := filepath.Join(f.g.host.configRoot, "runtime.json")
				raw, _ := os.ReadFile(p)
				os.WriteFile(p, append(raw, ' '), 0600)
			case "missing-intent":
				p, _ := f.wrappers[1].w.directory(r, f.wrappers[1].name)
				os.Remove(filepath.Join(p, "intent.json"))
			case "changed-intent":
				p, _ := f.wrappers[1].w.directory(r, f.wrappers[1].name)
				os.WriteFile(filepath.Join(p, "intent.json"), []byte("{}"), 0600)
			case "agent-name":
				c := f.m.containers[strings.Repeat("1", 64)]
				c.Name = "/foreign"
				f.m.containers[c.ID] = c
			case "new-supervisor":
				os.WriteFile(filepath.Join(filepath.Dir(f.g.host.unitPath), "webscan-agent-v1.service"), []byte("foreign"), 0644)
			case "new-native-agent":
				os.WriteFile(f.g.host.unitPath, []byte("foreign"), 0600)
			}
			if _, err := f.g.backup.run(context.Background(), r); err == nil {
				t.Fatal("accepted changed group")
			}
			if len(f.mutations()) != 0 {
				t.Fatal("stopped earlier member while later member changed")
			}
		})
	}
}

func TestLegacyWrapperGroupLostStopResponseCanResumeOrRestore(t *testing.T) {
	for _, lostRole := range []int{0, 1} {
		for _, action := range []string{"resume", "restore"} {
			t.Run(fmt.Sprintf("%d-%s", lostRole, action), func(t *testing.T) {
				f, r, _ := wrapperGroupFixture(t, "docker")
				f.wrappers[lostRole].lose = "disable"
				if _, err := f.g.backup.run(context.Background(), r); err == nil {
					t.Fatal("lost response hidden")
				}
				if f.m.containers[strings.Repeat("1", 64)].Status != "running" {
					t.Fatal("Agent stopped despite earlier uncertain wrapper")
				}
				if action == "resume" {
					if _, err := f.g.backup.run(context.Background(), r); err != nil {
						t.Fatal(err)
					}
				} else {
					r.Phase = "restore"
					if err := f.g.restoreBeforeActivation(context.Background(), r); err != nil {
						t.Fatal(err)
					}
					for _, w := range f.wrappers {
						if !w.running || !w.enabled {
							t.Fatal("partial stop not restored")
						}
					}
				}
			})
		}
	}
}

func TestLegacyWrapperGroupRecoveryRefusesNewTargetAndCompletedChanges(t *testing.T) {
	for _, change := range []string{"activation", "pointer", "restored-unit", "restored-stopped", "receipt"} {
		t.Run(change, func(t *testing.T) {
			f, r, _ := wrapperGroupFixture(t, "native")
			if _, err := f.g.backup.run(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			r.Phase = "restore"
			if strings.HasPrefix(change, "restored-") || change == "receipt" {
				if err := f.g.restoreBeforeActivation(context.Background(), r); err != nil {
					t.Fatal(err)
				}
			}
			switch change {
			case "activation":
				os.Mkdir(filepath.Join(f.g.backup.directory(r), "activation"), 0700)
			case "pointer":
				os.WriteFile(filepath.Join(f.g.host.root, "active.json"), []byte(`{}`), 0600)
			case "restored-unit":
				os.WriteFile(f.wrappers[1].unit, f.wrappers[1].u.definition(), 0644)
			case "restored-stopped":
				f.wrappers[1].running = false
				f.wrappers[1].o.Identity.Status = "exited"
			case "receipt":
				os.WriteFile(filepath.Join(f.g.backup.directory(r), "restoration", "group-completed.json"), []byte(`{}`), 0600)
			}
			before := len(f.mutations())
			if err := f.g.restoreBeforeActivation(context.Background(), r); err == nil {
				t.Fatal("accepted unknown target or changed completion")
			}
			if len(f.mutations()) != before {
				t.Fatal("repaired external changes")
			}
		})
	}
}

func TestLegacyWrapperGroupMemberReferencesCannotBeForged(t *testing.T) {
	f, r, _ := wrapperGroupFixture(t, "docker")
	ctx, release, err := acquireServiceOperation(context.Background(), f.g.host.root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	i, err := f.g.backup.prepareIntent(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if !i.Installed.valid(r.Node) {
		t.Fatal("valid group rejected")
	}
	for _, change := range []string{"duplicate", "wrong-name", "wrong-hash", "different-job", "different-spec"} {
		t.Run(change, func(t *testing.T) {
			copy := i.Installed
			copy.Wrappers = append([]legacyWrapperMember(nil), copy.Wrappers...)
			req := r
			switch change {
			case "duplicate":
				copy.Wrappers[1] = copy.Wrappers[0]
			case "wrong-name":
				copy.Wrappers[1].Name = "other.service"
			case "wrong-hash":
				copy.Wrappers[1].IntentSHA256 = strings.Repeat("0", 64)
			case "different-job":
				req.Job = "other-job"
			case "different-spec":
				req.Spec.Release = "v3.0.1"
			}
			if err := f.g.backup.verifyWrapperMembers(req, copy); err == nil {
				t.Fatal("forged reference accepted")
			}
		})
	}
	for _, w := range f.wrappers {
		raw, _ := os.ReadFile(w.unit)
		if !bytes.Equal(raw, w.u.definition()) {
			t.Fatal("capture mutated unit")
		}
	}
	if len(f.mutations()) != 0 {
		t.Fatal("read-only group capture changed services")
	}
}

func TestLegacyWrapperGroupRestoresIndependentRunningAndEnableStates(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, bits := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} {
			t.Run(fmt.Sprintf("%s-%d", mode, bits), func(t *testing.T) {
				f, r, _ := wrapperGroupFixture(t, mode)
				for j, w := range f.wrappers {
					w.running, w.enabled = bits&(1<<(2*j)) != 0, bits&(1<<(2*j+1)) != 0
					w.o.Identity.Status = "exited"
					if w.running {
						w.o.Identity.Status = "running"
					}
				}
				f.m.nativeEnabled, f.m.nativeRunning = bits&1 != 0, bits&2 != 0
				if mode == "docker" {
					c := f.m.containers[strings.Repeat("1", 64)]
					c.Status, c.Restart = "exited", "no"
					if bits&1 != 0 {
						c.Status = "running"
					}
					if bits&2 != 0 {
						c.Restart = "on-failure"
						c.MaxRetries = 3
					}
					f.m.containers[c.ID] = c
				}
				if _, err := f.g.backup.run(context.Background(), r); err != nil {
					t.Fatal(err)
				}
				r.Phase = "restore"
				if err := f.g.restoreBeforeActivation(context.Background(), r); err != nil {
					t.Fatal(err)
				}
				for j, w := range f.wrappers {
					if w.running != (bits&(1<<(2*j)) != 0) || w.enabled != (bits&(1<<(2*j+1)) != 0) {
						t.Fatal("independent wrapper state changed")
					}
				}
			})
		}
	}
}

func TestLegacyWrapperGroupRestoreLostResponseAndLaterConflict(t *testing.T) {
	for _, loss := range []string{"enable", "start"} {
		for _, conflict := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-conflict-%t", loss, conflict), func(t *testing.T) {
				f, r, _ := wrapperGroupFixture(t, "docker")
				if _, err := f.g.backup.run(context.Background(), r); err != nil {
					t.Fatal(err)
				}
				r.Phase = "restore"
				f.wrappers[0].lose = loss
				if err := f.g.restoreBeforeActivation(context.Background(), r); err == nil {
					t.Fatal("lost recovery response hidden")
				}
				if conflict {
					// A late corrupt receipt on the last member must prevent an
					// earlier unfinished member from being started on replay.
					dir, _ := f.wrappers[1].w.directory(r, f.wrappers[1].name)
					if err := os.WriteFile(filepath.Join(dir, "restore.json"), []byte("{}"), 0600); err != nil {
						t.Fatal(err)
					}
					before := len(f.mutations())
					if err := f.g.restoreBeforeActivation(context.Background(), r); err == nil {
						t.Fatal("later conflict accepted")
					}
					if len(f.mutations()) != before {
						t.Fatal("earlier member changed before discovering later conflict")
					}
					return
				}
				if err := f.g.restoreBeforeActivation(context.Background(), r); err != nil {
					t.Fatal(err)
				}
				starts := 0
				for _, call := range f.wrappers[0].calls {
					if call == "systemctl start "+f.wrappers[0].name {
						starts++
					}
				}
				if starts != 1 {
					t.Fatalf("start repeated after lost response: %d", starts)
				}
			})
		}
	}
}
