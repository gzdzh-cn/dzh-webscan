package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Docker/systemd state uses explicit substitutes here. Real file permissions,
// SQLite, snapshots, event export, journals and private receipts are unchanged.
func convertGroupToCompose(t *testing.T, x *groupTargetMachine) {
	t.Helper()
	f := x.f
	agent := f.m.containers[strings.Repeat("1", 64)]
	services := map[string]any{"agent": map[string]any{"image": agent.Image, "container_name": agentContainerName}}
	for _, side := range f.wrappers {
		if err := os.Remove(side.unit); err != nil {
			t.Fatal(err)
		}
		side.o.Identity.Project, side.o.Identity.Service = agent.Project, side.u.Role
		side.o.Identity.Restart = "unless-stopped"
		f.m.containers[side.o.Identity.ID] = side.o.Identity
		services[side.u.Role] = map[string]any{"image": side.o.Identity.Image, "container_name": strings.TrimPrefix(side.o.Identity.Name, "/")}
	}
	raw, _ := json.Marshal(map[string]any{"name": agent.Project, "services": services})
	if err := os.WriteFile(filepath.Join(f.g.host.configRoot, "compose.yml"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	original := f.g.host.command
	command := func(ctx context.Context, program string, args ...string) (string, error) {
		if program == "docker" && len(args) > 2 {
			a := args[2:]
			for _, side := range f.wrappers {
				c := side.o.Identity
				match := a[0] == "ps" && len(a) > 4 && a[4] == "name=^"+c.Name+"$" || a[0] == "container" && len(a) > 2 && a[2] == c.ID || a[0] == "image" && len(a) > 2 && a[2] == side.image.ID || (a[0] == "start" || a[0] == "stop" || a[0] == "update") && a[len(a)-1] == c.ID
				if !match {
					continue
				}
				if serviceMutation(program, args) {
					held, ok := ctx.Value(serviceOperationKey{}).(serviceOperation)
					if !ok || held.file == nil || held.root != f.g.host.root {
						return "", errors.New("missing compose service lock")
					}
				}
				f.calls = append(f.calls, program+" "+strings.Join(args, " "))
				switch a[0] {
				case "ps":
					return c.ID, nil
				case "container":
					if a[4] == inventoryContainerFormat {
						raw, _ := json.Marshal(c)
						return string(raw), nil
					}
					raw, _ := json.Marshal(side.o)
					return string(raw), nil
				case "image":
					raw, _ := json.Marshal(side.image)
					return string(raw), nil
				case "update":
					policy := strings.TrimPrefix(a[1], "--restart=")
					side.o.Identity.Restart, side.o.Identity.MaxRetries = policy, 0
					if policy == "on-failure:3" {
						side.o.Identity.Restart, side.o.Identity.MaxRetries = "on-failure", 3
					}
				case "start":
					side.o.Identity.Status = "running"
				case "stop":
					side.o.Identity.Status = "exited"
				}
				f.m.containers[c.ID] = side.o.Identity
				if x.failAfter != "" && strings.Contains(program+" "+strings.Join(args, " "), x.failAfter) {
					x.failAfter = ""
					return "", errors.New("lost compose response")
				}
				return "", nil
			}
		}
		return original(ctx, program, args...)
	}
	f.g.host.command = command
	if x.n != nil {
		x.n.host.command = command
	} else {
		x.d.host.command = command
	}
}

func TestLegacyComposeGroupLifecycleRetainsCurrentDataAndIndependentState(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for mask := 0; mask < 4; mask++ {
			t.Run(mode+"/"+string(rune('0'+mask)), func(t *testing.T) {
				x, _, j := groupLifecycleFixture(t, "docker", mode)
				convertGroupToCompose(t, x)
				states := map[string]containerIdentity{}
				for index, s := range x.f.wrappers {
					if (mask&1 != 0) != (index == 1) {
						s.o.Identity.Status = "exited"
					}
					if mask&2 != 0 {
						s.o.Identity.Restart, s.o.Identity.MaxRetries = "on-failure", 3
					}
					x.f.m.containers[s.o.Identity.ID] = s.o.Identity
					states[s.name] = s.o.Identity
				}
				r := x.r
				observed, err := x.f.g.host.observeOriginal(context.Background(), r)
				if err != nil || !observed.grouped || hasLegacyMembers(observed.agent) {
					t.Fatal("compose observation", observed, err)
				}
				if len(x.f.mutations()) != 0 {
					t.Fatal("observation mutated service")
				}
				for _, phase := range forward {
					r.Phase, r.Operation = phase, "apply"
					result := j.Handle(r)
					requireResult(t, result, "complete", "ok")
				}
				for _, side := range x.f.wrappers {
					if side.o.Identity.Status == "running" || side.o.Identity.Restart != "no" {
						t.Fatal("old sidecar not quiescent")
					}
				}
				if _, err := x.db.Exec(`INSERT INTO events(id,payload,created) VALUES('after-compose-switch','{"event_id":"after-compose-switch","node_id":"node-one"}',2)`); err != nil {
					t.Fatal(err)
				}
				for _, phase := range rollback {
					r.Phase, r.Operation = phase, "apply"
					requireResult(t, j.Handle(r), "complete", "ok")
				}
				for _, side := range x.f.wrappers {
					want := states[side.name]
					got := side.o.Identity
					if got.ID != want.ID || (got.Status == "running") != (want.Status == "running") || got.Restart != want.Restart || got.MaxRetries != want.MaxRetries {
						t.Fatal("original independent sidecar state lost")
					}
				}
				var count int
				if err := x.db.QueryRow("SELECT count(*) FROM events WHERE id='after-compose-switch'").Scan(&count); err != nil || count != 1 {
					t.Fatal("live current event lost", err)
				}
				mutations := len(x.f.mutations())
				for _, phase := range rollback {
					r.Phase, r.Operation = phase, "inspect"
					requireResult(t, j.Handle(r), "complete", "ok")
				}
				if len(x.f.mutations()) != mutations {
					t.Fatal("rollback inspect changed services")
				}
			})
		}
	}
}

func TestLegacyComposeGroupRefusesChangedLastMemberBeforeStoppingAgent(t *testing.T) {
	for _, kind := range []string{"command", "mount", "project", "privileged", "missing-image", "supervisor"} {
		t.Run(kind, func(t *testing.T) {
			x, _, j := groupLifecycleFixture(t, "docker", "native")
			convertGroupToCompose(t, x)
			side := x.f.wrappers[1]
			switch kind {
			case "command":
				side.o.Identity.Command = append(side.o.Identity.Command, "--unexpected")
			case "mount":
				side.o.Identity.Mounts[0].RW = true
			case "project":
				side.o.Identity.Project = "other-project"
			case "privileged":
				side.o.Privileged = true
			case "missing-image":
				side.image.ID = "sha256:" + strings.Repeat("0", 64)
			case "supervisor":
				if err := os.WriteFile(side.unit, []byte("foreign supervisor"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			r := x.r
			r.Phase = "backup"
			result := j.Handle(r)
			if result.State == "complete" {
				t.Fatal("changed sidecar accepted")
			}
			if len(x.f.mutations()) != 0 || x.f.m.containers[strings.Repeat("1", 64)].Status != "running" {
				t.Fatal("agent stopped before complete group proof")
			}
		})
	}
}

func TestLegacyComposeGroupResumesLostStopAndStartWithoutChangingIDs(t *testing.T) {
	for _, boundary := range []string{"stop", "start"} {
		t.Run(boundary, func(t *testing.T) {
			x, _, j := groupLifecycleFixture(t, "docker", "native")
			convertGroupToCompose(t, x)
			r := x.r
			finishThrough(t, j, r, "stage")
			if boundary == "stop" {
				x.failAfter = "stop --time 60 " + x.f.wrappers[1].o.Identity.ID
				r.Phase = "backup"
				requireResult(t, j.Handle(r), "unknown", "backup-failed")
				r.Epoch++
				r.Operation = "inspect"
				requireResult(t, j.Handle(r), "absent", "ok")
				r.Operation = "apply"
				requireResult(t, j.Handle(r), "complete", "ok")
			} else {
				finishThrough(t, j, r, "backup")
				x.failAfter = "start " + x.f.wrappers[1].o.Identity.ID
			}
			r.Phase, r.Operation = "restore", "apply"
			result := j.Handle(r)
			if boundary == "start" {
				requireResult(t, result, "unknown", "remote-state-unknown")
				r.Epoch++
				r.Operation = "inspect"
				requireResult(t, j.Handle(r), "absent", "ok")
				r.Operation = "apply"
				requireResult(t, j.Handle(r), "complete", "ok")
			} else {
				requireResult(t, result, "complete", "ok")
			}
			for _, s := range x.f.wrappers {
				if s.o.Identity.Status != "running" || s.o.Identity.Restart != "unless-stopped" {
					t.Fatal("original sidecar not recovered")
				}
			}
		})
	}
}

func TestLegacyComposeRetirementRequiresExactBoundActivation(t *testing.T) {
	for _, corrupt := range []string{"unpublished", "activation", "snapshot", "capture", "definition", "member"} {
		t.Run(corrupt, func(t *testing.T) {
			x, _, j := groupLifecycleFixture(t, "docker", "native")
			convertGroupToCompose(t, x)
			r := x.r
			finishThrough(t, j, r, "backup")
			q := legacyComposeTransition{x.f.g.host}
			name := legacyComposeNames[0]
			i, _, err := q.read(r, name)
			if err != nil {
				t.Fatal(err)
			}
			if corrupt != "unpublished" {
				finishThrough(t, j, r, "activate")
			}
			dir := filepath.Join(q.host.root, "transitions", r.Job)
			path := ""
			switch corrupt {
			case "unpublished":
				if err := os.Remove(filepath.Join(q.host.configRoot, "compose.yml")); err != nil {
					t.Fatal(err)
				}
			case "activation":
				path = filepath.Join(dir, "activation/intent.json")
			case "snapshot":
				path = filepath.Join(dir, "snapshot/receipt.json")
			case "capture":
				path = filepath.Join(dir, "capture/config/compose.yml")
			case "definition":
				path = filepath.Join(q.host.configRoot, "compose.yml")
			case "member":
				i.Object.Identity.ID = strings.Repeat("f", 64)
			}
			if path != "" {
				if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := len(x.f.mutations())
			if _, err := q.state(context.Background(), r, i); err == nil {
				t.Fatal("unproven retirement accepted")
			}
			if len(x.f.mutations()) != before {
				t.Fatal("retirement inspection mutated service")
			}
		})
	}
}

func TestLegacyComposeCompletedRestoreDoesNotRepairDrift(t *testing.T) {
	x, _, j := groupLifecycleFixture(t, "docker", "docker")
	convertGroupToCompose(t, x)
	r := x.r
	finishThrough(t, j, r, "backup")
	r.Phase = "restore"
	requireResult(t, j.Handle(r), "complete", "ok")
	side := x.f.wrappers[0]
	side.o.Identity.Restart = "no"
	x.f.m.containers[side.o.Identity.ID] = side.o.Identity
	before := len(x.f.mutations())
	if err := (legacyComposeTransition{x.f.g.host}).restore(context.Background(), r, legacyComposeNames[0]); err == nil {
		t.Fatal("completed recovery repaired drift")
	}
	if len(x.f.mutations()) != before {
		t.Fatal("completed recovery mutated service")
	}
}

func TestLegacyComposeCanceledRestoreDoesNotPublishCompletion(t *testing.T) {
	x, _, j := groupLifecycleFixture(t, "docker", "docker")
	convertGroupToCompose(t, x)
	r := x.r
	finishThrough(t, j, r, "backup")
	r.Phase = "restore"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := x.f.g.host
	original := h.command
	h.command = func(ctx context.Context, program string, args ...string) (string, error) {
		raw, err := original(ctx, program, args...)
		if program == "docker" && len(args) > 2 && args[2] == "start" {
			cancel()
		}
		return raw, err
	}
	q := legacyComposeTransition{h}
	name := legacyComposeNames[0]
	if err := q.restore(ctx, r, name); err == nil {
		t.Fatal("canceled restore succeeded")
	}
	dir, _ := q.directory(r, name)
	if _, err := os.Lstat(filepath.Join(dir, "restored.json")); !os.IsNotExist(err) {
		t.Fatal("canceled restore published completion", err)
	}
	if err := q.restore(context.Background(), r, name); err != nil {
		t.Fatal("resume after cancellation", err)
	}
}

func TestLegacyComposeParkingSurvivesCapturedSuccessor(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x, _, j := groupLifecycleFixture(t, "docker", mode)
			convertGroupToCompose(t, x)
			r := x.r
			finishThrough(t, j, r, "finalize")
			h := x.f.g.host
			next := r
			next.Job = "compose-next"
			next.PlanDigest = strings.Repeat("e", 64)
			b := *x.f.g.backup
			b.host = h
			if _, err := b.prepareIntent(context.Background(), next); err != nil {
				t.Fatal("capture next v3 installation", err)
			}
			var active ActiveInstallation
			if _, err := decodePrivateJSON(filepath.Join(h.root, "active.json"), &active, MaxRequestBytes); err != nil {
				t.Fatal(err)
			}
			active.Job, active.PlanDigest = next.Job, next.PlanDigest
			capture, err := readPrivate(filepath.Join(b.directory(next), "capture/intent.json"), 4<<20)
			if err != nil {
				t.Fatal(err)
			}
			active.CaptureSHA256 = sha(capture)
			before := len(x.f.mutations())
			proofs, err := h.parkedComposeProofs(context.Background(), &active)
			if err != nil || len(proofs) != 2 {
				t.Fatal("successor lost parked group", err)
			}
			// A stopped old object must not be ignored after an external start,
			// including when the current target is native and has no Compose file.
			side := x.f.wrappers[0]
			side.o.Identity.Status = "running"
			x.f.m.containers[side.o.Identity.ID] = side.o.Identity
			if _, err := h.parkedComposeProofs(context.Background(), &active); err == nil {
				t.Fatal("successor accepted restarted sidecar")
			}
			if _, err := h.inventory(context.Background(), r.Node, mode); err == nil {
				t.Fatal("current inventory ignored restarted sidecar")
			}
			if len(x.f.mutations()) != before {
				t.Fatal("ancestry inspection mutated service")
			}
		})
	}
}

func TestLegacyComposeRetiredProofDoesNotDependOnNewConfiguration(t *testing.T) {
	x, _, j := groupLifecycleFixture(t, "docker", "native")
	convertGroupToCompose(t, x)
	r := x.r
	finishThrough(t, j, r, "activate")
	q := legacyComposeTransition{x.f.g.host}
	i, _, err := q.read(r, legacyComposeNames[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(q.host.root, "configs", r.Spec.RuntimeSHA256)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.state(context.Background(), r, i); err != nil {
		t.Fatal("target damage blocked immutable retirement proof", err)
	}
	for _, phase := range rollback {
		r.Phase, r.Operation = phase, "apply"
		requireResult(t, j.Handle(r), "complete", "ok")
	}
}
