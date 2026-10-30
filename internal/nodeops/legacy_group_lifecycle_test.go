package nodeops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestLegacyWrapperGroupObservationDoesNotPublishOrMutate(t *testing.T) {
	for _, old := range []string{"native", "docker"} {
		for _, target := range []string{"native", "docker"} {
			t.Run(old+"-to-"+target, func(t *testing.T) {
				x := groupTargetBeforeBackup(t, old, target)
				r := x.r
				r.Phase = "preflight"
				observation, err := x.f.g.host.observeOriginal(context.Background(), r)
				if err != nil || !observation.grouped || len(observation.agent.Wrappers) != 0 || observation.agent.Mode != old {
					t.Fatal("observation", observation, err)
				}
				if len(x.f.mutations()) != 0 {
					t.Fatal("preflight mutated services")
				}
				if _, err := os.Lstat(x.f.g.backup.directory(r)); !os.IsNotExist(err) {
					t.Fatal("preflight published capture")
				}
				for _, m := range x.f.wrappers {
					if !m.running || !m.enabled {
						t.Fatal("preflight stopped wrapper")
					}
				}
			})
		}
	}
}

func groupLifecycleFixture(t *testing.T, old, target string) (*groupTargetMachine, Handler, *Journal) {
	t.Helper()
	x := groupTargetBeforeBackup(t, old, target)
	// The ordinary driver starts ungrouped. Each request must select its own
	// coordinator from a fresh observation or the bound immutable capture.
	x.f.g.backup.host = x.f.g.host
	var handler Handler
	resources := resourceFixture(t, 2)
	if x.n != nil {
		writeResourceFixture(t, resources.cpu, "100000 100000\n")
		resources.properties = strings.ReplaceAll(resources.properties, "1s 250ms", "1s")
		base := x.f.agentCommand
		x.f.agentCommand = func(ctx context.Context, cmd string, args ...string) (string, error) {
			if cmd == "systemctl" && len(args) == 3 && strings.Contains(args[2], "ControlGroup") {
				return resources.properties, nil
			}
			return base(ctx, cmd, args...)
		}
		handler = &nativeLifecycle{runtime: x.n.runtime, activation: x.n, resources: resources.fs, preflight: &testHandler{}}
	} else {
		group := "/docker/" + x.docker.target.ID
		if err := os.MkdirAll(filepath.Dir(filepath.Join(resources.fs.cgroup, group)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(resources.fs.cgroup, resources.group), filepath.Join(resources.fs.cgroup, group)); err != nil {
			t.Fatal(err)
		}
		resources.cpu = strings.Replace(resources.cpu, resources.group, group, 1)
		resources.memory = strings.Replace(resources.memory, resources.group, group, 1)
		writeResourceFixture(t, filepath.Join(resources.fs.proc, "123/cgroup"), "0::"+group+"\n")
		r := x.docker.material.Settings.Resources
		writeResourceFixture(t, resources.cpu, strconv.FormatInt(int64(r.CPUs*100000), 10)+" 100000\n")
		writeResourceFixture(t, resources.memory, strconv.FormatInt(int64(r.MemoryMiB)<<20, 10)+"\n")
		writeResourceFixture(t, filepath.Join(resources.fs.proc, "123/limits"), fmt.Sprintf("Max open files   %d   %d   files\n", r.FileDescriptors, r.FileDescriptors))
		handler = &dockerLifecycle{runtime: x.d.runtime, activation: x.d, resources: resources.fs, preflight: &testHandler{}, stage: &dockerFixtureStage{x.d}}
	}
	j := openTestJournal(t, filepath.Join(x.f.g.host.root, "group-journal"), handler)
	return x, handler, j
}

func TestLegacyWrapperGroupLifecycleCompletesAllLocalPhases(t *testing.T) {
	for _, old := range []string{"native", "docker"} {
		for _, target := range []string{"native", "docker"} {
			t.Run(old+"-to-"+target, func(t *testing.T) {
				x, _, j := groupLifecycleFixture(t, old, target)
				r := x.r
				finishThrough(t, j, r, "finalize")
				for _, phase := range forward {
					r.Operation = "inspect"
					r.Phase = phase
					requireResult(t, j.Handle(r), "complete", "ok")
				}
				x.f.wrappers[1].enabled = true
				r.Phase = "finalize"
				requireResult(t, j.Handle(r), "unknown", "verification-failed")
			})
		}
	}
}

func TestLegacyWrapperGroupLifecycleSelectsDurableCoordinatorAndRecovers(t *testing.T) {
	for _, old := range []string{"native", "docker"} {
		for _, target := range []string{"native", "docker"} {
			for _, activate := range []bool{false, true} {
				t.Run(old+"-to-"+target+"/"+map[bool]string{false: "backup-only", true: "activated"}[activate], func(t *testing.T) {
					x, h, j := groupLifecycleFixture(t, old, target)
					r := x.r
					finishThrough(t, j, r, "backup")
					original, err := x.f.g.backup.readIntent(context.Background(), r)
					if err != nil || len(original.Installed.Wrappers) != 2 {
						t.Fatal("missing group", err)
					}
					if activate {
						r.Phase = "activate"
						requireResult(t, j.Handle(r), "complete", "ok")
					}
					r.Phase = "restore"
					requireResult(t, j.Handle(r), "complete", "ok")
					r.Phase = "verify-rollback"
					requireResult(t, j.Handle(r), "complete", "ok")
					for _, phase := range []string{"restore", "verify-rollback"} {
						r.Phase = phase
						r.Operation = "inspect"
						requireResult(t, j.Handle(r), "complete", "ok")
					}
					// Per-request selection must not replace the original shared host.
					switch d := h.(type) {
					case *nativeLifecycle:
						if _, ok := d.activation.backup.host.(installationHost); !ok {
							t.Fatal("shared native handler mutated")
						}
					case *dockerLifecycle:
						if _, ok := d.activation.backup.host.(installationHost); !ok {
							t.Fatal("shared docker handler mutated")
						}
					}
					r.Operation = "apply"
					after, err := x.f.g.backup.readIntent(context.Background(), r)
					if err != nil || !reflect.DeepEqual(original, after) {
						t.Fatal("capture changed", err)
					}
				})
			}
		}
	}
}

func TestLegacyWrapperGroupLifecycleReconcilesActivationResponseLoss(t *testing.T) {
	for _, target := range []string{"native", "docker"} {
		t.Run(target, func(t *testing.T) {
			x, _, j := groupLifecycleFixture(t, "docker", target)
			r := x.r
			finishThrough(t, j, r, "backup")
			x.failAfter = "systemctl start " + nativeServiceName
			if target == "docker" {
				x.failAfter = "start " + strings.Repeat("9", 64)
			}
			r.Phase = "activate"
			requireResult(t, j.Handle(r), "unknown", "activation-failed")
			r.Epoch++
			r.Operation = "inspect"
			requireResult(t, j.Handle(r), "complete", "ok")
			r.Operation = "apply"
			requireResult(t, j.Handle(r), "complete", "ok")
			r.Phase = "restore"
			requireResult(t, j.Handle(r), "complete", "ok")
		})
	}
}

func TestLegacyWrapperGroupLifecycleReconcilesPartialRecoveryBeforeActivation(t *testing.T) {
	for _, target := range []string{"native", "docker"} {
		t.Run(target, func(t *testing.T) {
			x, _, j := groupLifecycleFixture(t, "docker", target)
			r := x.r
			finishThrough(t, j, r, "backup")
			x.f.wrappers[0].lose = "start"
			r.Phase = "restore"
			requireResult(t, j.Handle(r), "unknown", "remote-state-unknown")
			r.Operation = "inspect"
			r.Epoch++
			requireResult(t, j.Handle(r), "absent", "ok")
			r.Operation = "apply"
			requireResult(t, j.Handle(r), "complete", "ok")
			r.Phase = "verify-rollback"
			requireResult(t, j.Handle(r), "complete", "ok")
		})
	}
}

func TestLegacyWrapperGroupLifecycleRejectsLostBeforeTargetEvidence(t *testing.T) {
	for _, target := range []string{"native", "docker"} {
		for _, lost := range []string{"database", "restore-intent", "wrapper"} {
			t.Run(target+"/"+lost, func(t *testing.T) {
				x, _, j := groupLifecycleFixture(t, "docker", target)
				r := x.r
				finishThrough(t, j, r, "backup")
				if lost != "database" {
					r.Phase = "restore"
					requireResult(t, j.Handle(r), "complete", "ok")
				}
				switch lost {
				case "database":
					x.db.Close()
					os.Remove(filepath.Join(x.f.g.backup.data, "agent.sqlite3"))
				case "restore-intent":
					os.Remove(filepath.Join(x.f.g.backup.directory(r), "restoration/intent.json"))
				case "wrapper":
					x.f.wrappers[1].enabled = false
				}
				before := len(x.f.mutations())
				r.Phase = "restore"
				r.Epoch++
				res := j.Handle(r)
				if res.State == "complete" {
					t.Fatal("lost evidence accepted", res)
				}
				if len(x.f.mutations()) != before {
					t.Fatal("lost evidence mutated services")
				}
			})
		}
	}
}
