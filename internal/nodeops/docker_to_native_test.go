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

type dockerToNativeMachine struct {
	*activationMachine
	dockerStarts    int
	dockerFailAfter string
}

func dockerToNativeFixture(t *testing.T) *dockerToNativeMachine {
	t.Helper()
	base := nativeActivationFixture(t, true)
	a := &dockerToNativeMachine{activationMachine: base}
	if err := os.RemoveAll(filepath.Join(base.activation.runtime.root, "transitions")); err != nil {
		t.Fatal(err)
	}
	original, _ := json.Marshal(map[string]any{"node_id": base.request.Node, "deployment_mode": "docker", "data_dir": agentDataDirectory, "log_dir": agentLogDirectory, "probe_directory": "/srv/site/.webscan-probe"})
	if err := os.WriteFile(filepath.Join(base.machine.host.configRoot, "runtime.json"), original, 0600); err != nil {
		t.Fatal(err)
	}
	base.machine.addDocker(t)
	command := base.activation.host.command
	base.activation.host.command = func(ctx context.Context, p string, args ...string) (string, error) {
		verb := ""
		if p == "docker" && len(args) > 2 {
			verb = args[2]
		}
		var raw string
		var err error
		if verb == "rename" {
			id, name := args[3], args[4]
			c, ok := base.machine.containers[id]
			if !ok {
				return "", errors.New("missing-id")
			}
			for _, other := range base.machine.containers {
				if other.Name == "/"+name {
					return "", errors.New("name-in-use")
				}
			}
			c.Name = "/" + name
			base.machine.containers[id] = c
		} else {
			if verb == "start" && base.machine.containers[args[3]].Status != "running" {
				a.dockerStarts++
			}
			raw, err = command(ctx, p, args...)
		}
		if err == nil && verb != "" && verb == a.dockerFailAfter {
			return raw, errors.New("lost-docker-response")
		}
		return raw, err
	}
	base.activation.backup.host = base.activation.host
	r := base.request
	r.Phase = "backup"
	if _, err := base.activation.backup.run(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return a
}
func dockerToNativeJournalFixture(t *testing.T) (*nativeLifecycle, *dockerToNativeMachine, *Journal, *nativeResourceFixture) {
	t.Helper()
	a := dockerToNativeFixture(t)
	if err := os.RemoveAll(filepath.Join(a.activation.runtime.root, "transitions")); err != nil {
		t.Fatal(err)
	}
	c := a.machine.containers[strings.Repeat("1", 64)]
	c.Status, c.Restart = "running", "unless-stopped"
	a.machine.containers[c.ID] = c
	f := resourceFixture(t, 2)
	writeResourceFixture(t, f.cpu, "100000 100000\n")
	f.properties = strings.ReplaceAll(f.properties, "1s 250ms", "1s")
	base := a.activation.host.command
	a.activation.host.command = func(ctx context.Context, p string, args ...string) (string, error) {
		if p == "systemctl" && len(args) == 3 && strings.Contains(args[2], "ControlGroup") {
			return f.properties, nil
		}
		return base(ctx, p, args...)
	}
	a.activation.backup.host = a.activation.host
	n := &nativeLifecycle{runtime: a.activation.runtime, activation: a.activation, resources: f.fs, preflight: &testHandler{}}
	j := openTestJournal(t, filepath.Join(n.runtime.root, "journal"), n)
	return n, a, j, f
}
func TestDockerToNativeRetainsOriginalAndCurrentData(t *testing.T) {
	a := dockerToNativeFixture(t)
	db := restorationData(t, a.activationMachine)
	r := a.request
	ctx := context.Background()
	if err := a.activation.run(ctx, r); err != nil {
		t.Fatal(err)
	}
	old := a.machine.containers[strings.Repeat("1", 64)]
	if old.Name != "/"+retiredDockerName(r) || old.Status == "running" || old.Restart != "no" || !a.machine.nativeRunning || a.starts != 1 {
		t.Fatal("writers not switched safely", old, a.starts)
	}
	current, err := a.activation.host.inventory(ctx, r.Node, "native")
	if err != nil || current.Mode != "native" || len(current.Services) != 1 || current.Services[0].Kind != "native" {
		t.Fatal("native cannot be inventoried", current, err)
	}
	if err := a.activation.run(ctx, r); err != nil || a.starts != 1 {
		t.Fatal("replay restarted native", err)
	}
	if _, err := db.Exec(`INSERT INTO events VALUES('after-native','{"event_id":"after-native","node_id":"node-one"}',3,NULL,NULL)`); err != nil {
		t.Fatal(err)
	}
	r.Phase = "restore"
	if err := a.activation.restore(ctx, r); err != nil {
		t.Fatal(err)
	}
	old = a.machine.containers[old.ID]
	if old.Name != "/"+agentContainerName || old.Status != "running" || old.Restart != "unless-stopped" || a.machine.nativeRunning || a.machine.nativeEnabled || a.dockerStarts != 1 {
		t.Fatal("original Docker not restored", old, a.dockerStarts)
	}
	if err := a.activation.restore(ctx, r); err != nil || a.dockerStarts != 1 {
		t.Fatal("restore replay restarted Docker", err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM events WHERE accepted IS NULL AND exported IS NOT NULL").Scan(&count); err != nil || count != 2 {
		t.Fatal("new pending event lost", count, err)
	}
	current, err = a.activation.host.inventory(ctx, r.Node, "docker")
	if err != nil || current.Mode != "docker" || len(current.Services) != 1 || current.Services[0].ID != old.ID {
		t.Fatal("restored original identity missing", current, err)
	}
}
func TestDockerToNativeJournalFinishesAndRollsBack(t *testing.T) {
	n, a, j, _ := dockerToNativeJournalFixture(t)
	restorationData(t, a.activationMachine)
	r := a.request
	finishThrough(t, j, r, "finalize")
	for _, phase := range forward {
		r.Phase, r.Operation = phase, "inspect"
		requireResult(t, j.Handle(r), "complete", "ok")
	}
	r.Operation, r.Phase = "apply", "restore"
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	if a.starts != 1 || a.dockerStarts != 1 || a.machine.nativeRunning {
		t.Fatal("unexpected service restarts", a.starts, a.dockerStarts)
	}
	if err := n.verifyRollback(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}
func TestDockerToNativeJournalReconcilesLostResponses(t *testing.T) {
	for _, verb := range []string{"rename", "daemon-reload", "enable", "start"} {
		t.Run(verb, func(t *testing.T) {
			n, a, j, _ := dockerToNativeJournalFixture(t)
			r := a.request
			finishThrough(t, j, r, "backup")
			if verb == "rename" {
				a.dockerFailAfter = verb
			} else {
				a.crashAfter = verb
			}
			r.Phase = "activate"
			requireResult(t, j.Handle(r), "unknown", "activation-failed")
			a.dockerFailAfter, a.crashAfter = "", ""
			j = openTestJournal(t, j.root, n)
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
			if a.starts != 1 || a.dockerStarts != 0 {
				t.Fatal("lost response started wrong writers", a.starts, a.dockerStarts)
			}
		})
	}
}
func TestDockerToNativeRollbackContinuesAndRetainsState(t *testing.T) {
	for _, activated := range []bool{false, true} {
		for _, verb := range []string{"rename", "update", "start", "disable", "daemon-reload"} {
			t.Run(fmt.Sprint(activated, "/", verb), func(t *testing.T) {
				a := dockerToNativeFixture(t)
				restorationData(t, a.activationMachine)
				r := a.request
				ctx := context.Background()
				if activated {
					if err := a.activation.run(ctx, r); err != nil {
						t.Fatal(err)
					}
				}
				r.Phase = "restore"
				if verb == "disable" || verb == "daemon-reload" {
					a.crashAfter = verb
				} else {
					a.dockerFailAfter = verb
				}
				err := a.activation.restore(ctx, r)
				// Rename is unnecessary before activation; disabling is unnecessary when
				// only a Docker original exists. Exercise only operations actually issued.
				expectedFailure := activated || verb == "update" || verb == "start" || verb == "daemon-reload"
				if expectedFailure && err == nil {
					t.Fatal("response loss not observed")
				}
				a.dockerFailAfter, a.crashAfter = "", ""
				r.Epoch++
				if err := a.activation.restore(ctx, r); err != nil {
					t.Fatal("restore cannot continue", err)
				}
				if a.dockerStarts != 1 || a.machine.nativeRunning || a.machine.nativeEnabled {
					t.Fatal("wrong restored state", a.dockerStarts)
				}
			})
		}
	}
}
func TestDockerToNativeRestoresInitiallyStoppedDockerPolicy(t *testing.T) {
	for _, policy := range []string{"no", "always", "unless-stopped", "on-failure"} {
		t.Run(policy, func(t *testing.T) {
			a := dockerToNativeFixture(t)
			// Re-capture the original stopped policy before this task stops services.
			if err := os.RemoveAll(filepath.Join(a.activation.runtime.root, "transitions")); err != nil {
				t.Fatal(err)
			}
			c := a.machine.containers[strings.Repeat("1", 64)]
			c.Status, c.Restart = "exited", policy
			if policy == "on-failure" {
				c.MaxRetries = 3
			}
			a.machine.containers[c.ID] = c
			r := a.request
			r.Phase = "backup"
			if _, err := a.activation.backup.run(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			r.Phase = "activate"
			if err := a.activation.run(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			r.Phase = "restore"
			if err := a.activation.restore(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			restored := a.machine.containers[c.ID]
			if restored.Status == "running" || restored.Restart != policy || restored.MaxRetries != c.MaxRetries || a.dockerStarts != 0 {
				t.Fatal("initial stopped state changed", restored)
			}
		})
	}
}
func TestDockerToNativeRejectsConflictingOriginals(t *testing.T) {
	for _, kind := range []string{"renamed", "missing", "foreign-retired-name", "foreign-canonical-name", "old-reenabled", "old-running", "changed-command"} {
		t.Run(kind, func(t *testing.T) {
			a := dockerToNativeFixture(t)
			r := a.request
			if kind == "foreign-canonical-name" || kind == "old-reenabled" || kind == "old-running" {
				if err := a.activation.run(context.Background(), r); err != nil {
					t.Fatal(err)
				}
			}
			c := a.machine.containers[strings.Repeat("1", 64)]
			switch kind {
			case "renamed":
				c.Name = "/foreign"
				a.machine.containers[c.ID] = c
			case "missing":
				delete(a.machine.containers, c.ID)
			case "foreign-retired-name", "foreign-canonical-name":
				c.ID = strings.Repeat("7", 64)
				c.Name = "/" + retiredDockerName(r)
				if kind == "foreign-canonical-name" {
					c.Name = "/" + agentContainerName
				}
				a.machine.containers[c.ID] = c
			case "old-reenabled":
				c.Restart = "unless-stopped"
				a.machine.containers[c.ID] = c
			case "old-running":
				c.Status = "running"
				a.machine.containers[c.ID] = c
			case "changed-command":
				c.Command = []string{"foreign"}
				a.machine.containers[c.ID] = c
			}
			starts := a.starts
			if err := a.activation.run(context.Background(), r); err == nil {
				t.Fatal("unsafe original accepted")
			}
			if a.starts != starts {
				t.Fatal("started before proving original")
			}
			r.Phase = "restore"
			if err := a.activation.restore(context.Background(), r); err == nil {
				t.Fatal("unsafe restore accepted")
			}
		})
	}
}
func TestDockerToNativeMissingActivationIntentCannotAdoptRename(t *testing.T) {
	n, a, j, _ := dockerToNativeJournalFixture(t)
	r := a.request
	finishThrough(t, j, r, "backup")
	r.Phase = "activate"
	a.dockerFailAfter = "rename"
	requireResult(t, j.Handle(r), "unknown", "activation-failed")
	a.dockerFailAfter = ""
	if err := os.Remove(a.activation.intentPath(r)); err != nil {
		t.Fatal(err)
	}
	state, _, err := n.Reconcile(r)
	if state != "unknown" || err == nil {
		t.Fatal("unrecorded rename adopted", state, err)
	}
	r.Phase = "restore"
	if err := a.activation.restore(context.Background(), r); err == nil {
		t.Fatal("missing activation intent allowed rename recovery")
	}
}

func TestDockerToNativeRestoresPreviousV3TaskAndExactObject(t *testing.T) {
	d := dockerActivationFixture(t, true)
	ctx := context.Background()
	if err := d.activation.run(ctx, d.request); err != nil {
		t.Fatal(err)
	}
	w := d.activation.runtime
	previous, err := readPrivate(filepath.Join(w.root, "active.json"), MaxRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	r := d.request
	r.Job = "job-native"
	r.PlanDigest = strings.Repeat("b", 64)
	r.Spec.Mode = "native"
	r.Spec.AgentImage = ""
	attachConfiguration(t, w, &r, nil)
	r.Phase = "stage"
	if _, err := w.Apply(r); err != nil {
		t.Fatal(err)
	}
	m := d.machine
	m.nativeRunning, m.nativeEnabled = false, false
	h := d.activation.host
	h.processExecutable = func(int) (string, error) { return filepath.Join(w.releaseDir(r.Spec), "webscan"), nil }
	h.processArguments = func(int) ([]string, error) {
		return []string{filepath.Join(w.releaseDir(r.Spec), "webscan"), "agent", "--config", filepath.Join(w.configurationDir(r.Spec), "runtime.json")}, nil
	}
	nativeStarts := 0
	h.command = func(ctx context.Context, p string, args ...string) (string, error) {
		if p != "systemctl" {
			return d.command(ctx, p, args...)
		}
		switch args[0] {
		case "show":
			if _, err := os.Lstat(h.unitPath); os.IsNotExist(err) {
				return "LoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=\nJob=0\nMainPID=0\n", errors.New("not-found")
			}
		case "daemon-reload":
			return "", nil
		case "start":
			if !m.nativeRunning {
				nativeStarts++
			}
		}
		return m.command(ctx, p, args...)
	}
	b := d.activation.backup
	b.host = h
	a := &nativeActivation{runtime: w, backup: b, host: h}
	r.Phase = "backup"
	if _, err := b.run(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Phase = "activate"
	if err := a.run(ctx, r); err != nil {
		t.Fatal(err)
	}
	if !m.nativeRunning || nativeStarts != 1 {
		t.Fatal("native not started")
	}
	r.Phase = "restore"
	if err := a.restore(ctx, r); err != nil {
		t.Fatal(err)
	}
	raw, err := readPrivate(filepath.Join(w.root, "active.json"), MaxRequestBytes)
	if err != nil || string(raw) != string(previous) {
		t.Fatal("old v3 pointer changed", err)
	}
	old := m.containers[d.target.ID]
	if old.Name != "/"+agentContainerName || old.Status != "running" || old.Restart != "unless-stopped" || d.creates != 1 || d.starts != 2 || m.nativeRunning {
		t.Fatal("old v3 object recreated or not restored", old, d.creates, d.starts)
	}
	current, err := h.inventory(ctx, r.Node, "docker")
	if err != nil || current.Generation != "v3" || len(current.Services) != 1 || current.Services[0].ID != old.ID {
		t.Fatal(current, err)
	}
}
func TestDockerToNativeResourceFailureAndCaptureOnlyRecovery(t *testing.T) {
	for _, phase := range []string{"capture", "resources"} {
		t.Run(phase, func(t *testing.T) {
			_, a, j, f := dockerToNativeJournalFixture(t)
			db := restorationData(t, a.activationMachine)
			r := a.request
			if phase == "capture" {
				finishThrough(t, j, r, "stage")
				lock, err := a.activation.backup.agentLock()
				if err != nil {
					t.Fatal(err)
				}
				r.Phase = "backup"
				requireResult(t, j.Handle(r), "unknown", "backup-failed")
				lock.Close()
				if _, err := os.Lstat(filepath.Join(a.activation.backup.directory(r), "snapshot")); !os.IsNotExist(err) {
					t.Fatal("interruption unexpectedly published snapshot")
				}
			} else {
				finishThrough(t, j, r, "activate")
				writeResourceFixture(t, f.memory, "max\n")
				r.Phase = "verify"
				requireResult(t, j.Handle(r), "unknown", "verification-failed")
			}
			r.Phase = "restore"
			r.Epoch++
			requireResult(t, j.Handle(r), "complete", "ok")
			r.Phase = "verify-rollback"
			requireResult(t, j.Handle(r), "complete", "ok")
			var count int
			if err := db.QueryRow("SELECT count(*) FROM events WHERE accepted IS NULL AND exported IS NOT NULL").Scan(&count); err != nil || count != 1 {
				t.Fatal("rollback lost pending event", count, err)
			}
			if a.dockerStarts != 1 || a.machine.nativeRunning {
				t.Fatal("Docker not restored")
			}
		})
	}
}

func TestDockerToNativeRetiresLegacyComposeButRequiresRetainedDockerProof(t *testing.T) {
	a := dockerToNativeFixture(t)
	r := a.request
	ctx := context.Background()
	compose := filepath.Join(a.machine.host.configRoot, "compose.yml")
	previous, err := readPrivate(compose, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.activation.run(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(compose); !os.IsNotExist(err) {
		t.Fatal("legacy Compose remained active", err)
	}
	capture, err := readPrivate(filepath.Join(a.activation.backup.directory(r), "capture/config/compose.yml"), 2<<20)
	if err != nil || string(capture) != string(previous) {
		t.Fatal("legacy Compose not retained in capture", err)
	}
	h := a.activation.host
	base := h.command
	dockerCalls := 0
	h.command = func(ctx context.Context, p string, args ...string) (string, error) {
		if p == "docker" {
			dockerCalls++
			return "", errors.New("Docker unavailable after native switch")
		}
		return base(ctx, p, args...)
	}
	// The Compose file is retired, but the original Docker object still has
	// recovery duties. Missing engine evidence cannot prove it remains stopped.
	starts, dockerStarts := a.starts, a.dockerStarts
	if _, err := h.inventory(ctx, r.Node, "native"); err == nil || dockerCalls == 0 {
		t.Fatal("native inventory ignored unavailable historical Docker evidence", err, dockerCalls)
	}
	if a.starts != starts || a.dockerStarts != dockerStarts || !a.machine.nativeRunning {
		t.Fatal("failed read-only inspection changed writer")
	}
	if i, err := a.activation.host.inventory(ctx, r.Node, "native"); err != nil || i.Mode != "native" {
		t.Fatal("proven retained Docker object rejected", i, err)
	}
	r.Phase = "restore"
	if err := a.activation.restore(ctx, r); err != nil {
		t.Fatal(err)
	}
	restored, err := readPrivate(compose, 2<<20)
	if err != nil || string(restored) != string(previous) {
		t.Fatal("rollback did not restore exact Compose", err)
	}
}
func TestDockerToNativeRejectsConfigChangesBeforeRetirement(t *testing.T) {
	for _, name := range []string{"compose.yml", "runtime.json"} {
		t.Run(name, func(t *testing.T) {
			a := dockerToNativeFixture(t)
			path := filepath.Join(a.machine.host.configRoot, name)
			writeResourceFixture(t, path, "foreign")
			if err := a.activation.run(context.Background(), a.request); err == nil {
				t.Fatal("modified original config accepted")
			}
			c := a.machine.containers[strings.Repeat("1", 64)]
			if c.Name != "/"+agentContainerName || a.starts != 0 {
				t.Fatal("retired before validating original files")
			}
			raw, err := os.ReadFile(path)
			if err != nil || string(raw) != "foreign" {
				t.Fatal("changed original overwritten")
			}
		})
	}
}
