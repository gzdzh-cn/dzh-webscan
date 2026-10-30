package nodeops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Only the image daemon and service/process evidence are controlled. Release,
// configuration, backup/export files and the SQLite Journal are real. This is
// not proof of an installation against a real Docker daemon.
type dockerFixtureStage struct{ a *dockerActivation }

func (*dockerFixtureStage) Supports(phase string) bool { return phase == "stage" }
func (s *dockerFixtureStage) check(r Request) error {
	ctx := context.Background()
	if err := s.a.runtime.verifyPrepared(ctx, r.Spec); err != nil {
		return err
	}
	if err := s.a.runtime.verifyConfiguration(ctx, r); err != nil {
		return err
	}
	_, err := s.a.imageID(ctx, r.Spec)
	return err
}
func (s *dockerFixtureStage) Apply(r Request) (Outcome, error) {
	if err := s.check(r); err != nil {
		return Outcome{}, Failure{"artifact-invalid"}
	}
	return stageOutcome(r.Spec), nil
}
func (s *dockerFixtureStage) Reconcile(r Request) (string, Outcome, error) {
	out, err := s.Apply(r)
	if err != nil {
		return "unknown", out, err
	}
	return "complete", out, nil
}
func (s *dockerFixtureStage) VerifyCompleted(r Request, _ Outcome) error { return s.check(r) }

func dockerJournalFixture(t *testing.T, fresh bool) (*dockerLifecycle, *dockerActivationMachine, *Journal, *nativeResourceFixture) {
	t.Helper()
	a := dockerActivationFixture(t, fresh)
	if err := os.RemoveAll(filepath.Join(a.activation.runtime.root, "transitions")); err != nil {
		t.Fatal(err)
	}
	for id, c := range a.machine.containers {
		c.Status, c.Restart = "running", "unless-stopped"
		a.machine.containers[id] = c
	}
	f := resourceFixture(t, 2)
	group := "/docker/" + a.target.ID
	if err := os.MkdirAll(filepath.Dir(filepath.Join(f.fs.cgroup, group)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(f.fs.cgroup, f.group), filepath.Join(f.fs.cgroup, group)); err != nil {
		t.Fatal(err)
	}
	f.cpu = strings.Replace(f.cpu, f.group, group, 1)
	f.memory = strings.Replace(f.memory, f.group, group, 1)
	writeResourceFixture(t, filepath.Join(f.fs.proc, "123/cgroup"), "0::"+group+"\n")
	resources := a.material.Settings.Resources
	writeResourceFixture(t, f.cpu, strconv.FormatInt(int64(resources.CPUs*100000), 10)+" 100000\n")
	writeResourceFixture(t, f.memory, strconv.FormatInt(int64(resources.MemoryMiB)<<20, 10)+"\n")
	writeResourceFixture(t, filepath.Join(f.fs.proc, "123/limits"), fmt.Sprintf("Max open files   %d   %d   files\n", resources.FileDescriptors, resources.FileDescriptors))
	a.activation.host.processExecutable = func(int) (string, error) { return a.target.Entrypoint[0], nil }
	a.activation.host.processArguments = func(int) ([]string, error) {
		return append(append([]string{}, a.target.Entrypoint...), a.target.Command...), nil
	}
	d := &dockerLifecycle{runtime: a.activation.runtime, activation: a.activation, resources: f.fs, preflight: &testHandler{}, stage: &dockerFixtureStage{a.activation}}
	j := openTestJournal(t, filepath.Join(d.runtime.root, "journal"), d)
	return d, a, j, f
}

func TestDockerJournalCompletesAndRevalidatesPrivateLifecycle(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(fmt.Sprint(fresh), func(t *testing.T) {
			d, a, j, _ := dockerJournalFixture(t, fresh)
			db := dockerRestorationData(t, a)
			r := a.request
			finishThrough(t, j, r, "finalize")
			if a.creates != 1 || a.starts != 1 {
				t.Fatal("duplicate target", a.creates, a.starts)
			}
			for _, phase := range forward {
				r.Phase, r.Operation = phase, "inspect"
				requireResult(t, j.Handle(r), "complete", "ok")
			}
			var count int
			if err := db.QueryRow("SELECT count(*) FROM events").Scan(&count); err != nil || count != 2 {
				t.Fatal("live DB changed", count, err)
			}
			writeResourceFixture(t, filepath.Join(d.activation.backup.directory(r), "finalized.json"), "{}")
			r.Phase = "finalize"
			requireResult(t, j.Handle(r), "unknown", "verification-failed")
			if a.starts != 1 {
				t.Fatal("inspection restarted target")
			}
		})
	}
}
func TestDockerJournalReopensAndReconcilesActivationResponses(t *testing.T) {
	for _, verb := range []string{"rename", "compose", "update", "start"} {
		t.Run(verb, func(t *testing.T) {
			d, a, j, _ := dockerJournalFixture(t, false)
			r := a.request
			finishThrough(t, j, r, "backup")
			a.failAfter = verb
			r.Phase = "activate"
			requireResult(t, j.Handle(r), "unknown", "activation-failed")
			a.failAfter = ""
			j = openTestJournal(t, j.root, d)
			old := r
			r.Epoch++
			r.Operation = "inspect"
			state := "absent"
			if verb == "start" {
				state = "complete"
			}
			requireResult(t, j.Handle(r), state, "ok")
			requireResult(t, j.Handle(old), "unknown", "fenced")
			r.Operation = "apply"
			requireResult(t, j.Handle(r), "complete", "ok")
			r.Phase = "verify"
			requireResult(t, j.Handle(r), "complete", "ok")
			if a.creates != 1 || a.starts != 1 {
				t.Fatal("response loss duplicated writer", a.creates, a.starts)
			}
		})
	}
}
func TestDockerJournalResourceFailureRollsBackCurrentData(t *testing.T) {
	_, a, j, f := dockerJournalFixture(t, false)
	db := dockerRestorationData(t, a)
	r := a.request
	finishThrough(t, j, r, "activate")
	if _, err := db.Exec(`INSERT INTO events VALUES('post-activation','{"event_id":"post-activation","node_id":"node-one"}',2,NULL,NULL)`); err != nil {
		t.Fatal(err)
	}
	writeResourceFixture(t, f.memory, "max\n")
	r.Phase = "verify"
	requireResult(t, j.Handle(r), "unknown", "verification-failed")
	r.Phase = "restore"
	r.Epoch++
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	var count int
	if err := db.QueryRow("SELECT count(*) FROM events WHERE accepted IS NULL AND exported IS NOT NULL").Scan(&count); err != nil || count != 2 {
		t.Fatal("current pending events lost", count, err)
	}
	old := a.machine.containers[strings.Repeat("1", 64)]
	if old.Status != "running" || old.Name != "/"+agentContainerName {
		t.Fatal("original not restored", old)
	}
	if a.creates != 1 || a.starts != 2 {
		t.Fatal("unexpected writers", a.creates, a.starts)
	}
}
func TestDockerJournalContinuesInterruptedRollback(t *testing.T) {
	for _, verb := range []string{"update", "stop", "rename", "start"} {
		t.Run(verb, func(t *testing.T) {
			d, a, j, _ := dockerJournalFixture(t, false)
			dockerRestorationData(t, a)
			r := a.request
			finishThrough(t, j, r, "activate")
			a.failAfter = verb
			r.Phase = "restore"
			requireResult(t, j.Handle(r), "unknown", "remote-state-unknown")
			a.failAfter = ""
			j = openTestJournal(t, j.root, d)
			r.Epoch++
			requireResult(t, j.Handle(r), "complete", "ok")
			r.Phase = "verify-rollback"
			requireResult(t, j.Handle(r), "complete", "ok")
			if a.starts != 2 || a.creates != 1 {
				t.Fatal("recovery duplicated a writer", a.starts, a.creates)
			}
		})
	}
}
func TestDockerJournalCaptureOnlyRollbackAndHeldClientLock(t *testing.T) {
	d, a, j, _ := dockerJournalFixture(t, false)
	dockerRestorationData(t, a)
	r := a.request
	finishThrough(t, j, r, "stage")
	lock, err := d.activation.backup.agentLock()
	if err != nil {
		t.Fatal(err)
	}
	r.Phase = "backup"
	requireResult(t, j.Handle(r), "unknown", "backup-failed")
	lock.Close()
	_, release, err := acquireServiceOperation(context.Background(), d.runtime.root)
	if err != nil {
		t.Fatal(err)
	}
	r.Epoch++
	r.Operation = "inspect"
	requireResult(t, j.Handle(r), "unknown", "remote-state-unknown")
	release()
	r.Phase, r.Operation = "restore", "apply"
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	if a.starts != 1 || a.creates != 0 {
		t.Fatal("capture-only recovery started target")
	}
}
func TestDockerLifecycleRefusesUnrecordedOrCorruptEffects(t *testing.T) {
	for _, kind := range []string{"missing-intent", "corrupt-intent", "missing-created", "corrupt-created", "unrecorded-exited", "renamed", "duplicate", "foreign-pointer"} {
		t.Run(kind, func(t *testing.T) {
			d, a, j, _ := dockerJournalFixture(t, false)
			r := a.request
			finishThrough(t, j, r, "backup")
			r.Phase = "activate"
			if err := a.activation.run(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing-intent":
				os.Remove(a.activation.intentPath(r))
			case "corrupt-intent":
				writeResourceFixture(t, a.activation.intentPath(r), "{}")
			case "missing-created", "unrecorded-exited":
				os.Remove(a.activation.createdPath(r))
				if kind == "unrecorded-exited" {
					c := a.machine.containers[a.target.ID]
					c.Status = "exited"
					a.machine.containers[c.ID] = c
				}
			case "corrupt-created":
				writeResourceFixture(t, a.activation.createdPath(r), "{}")
			case "renamed":
				c := a.machine.containers[a.target.ID]
				c.Name = "/unrecorded-rename"
				a.machine.containers[c.ID] = c
			case "duplicate":
				c := a.machine.containers[a.target.ID]
				c.ID = strings.Repeat("7", 64)
				c.Name = "/duplicate"
				a.machine.containers[c.ID] = c
			case "foreign-pointer":
				writeResourceFixture(t, filepath.Join(d.runtime.root, "active.json"), "{}")
			}
			creates, starts := a.creates, a.starts
			state, _, err := d.Reconcile(r)
			if state != "unknown" || err == nil {
				t.Fatal("unproven effects replayable", state, err)
			}
			if a.creates != creates || a.starts != starts {
				t.Fatal("reconciliation mutated services")
			}
		})
	}
}
func TestDockerLifecycleCorruptRestoreReceiptIsUnknown(t *testing.T) {
	for _, name := range []string{"intent.json", "export.json"} {
		t.Run(name, func(t *testing.T) {
			d, a, j, _ := dockerJournalFixture(t, false)
			dockerRestorationData(t, a)
			r := a.request
			finishThrough(t, j, r, "activate")
			r.Phase = "restore"
			requireResult(t, j.Handle(r), "complete", "ok")
			writeResourceFixture(t, filepath.Join(a.activation.restoreDirectory(r), name), "{}")
			state, _, err := d.Reconcile(r)
			if state != "unknown" || err == nil {
				t.Fatal("corruption confused with safe replay", state, err)
			}
			requireResult(t, j.Handle(r), "unknown", "remote-state-unknown")
		})
	}
}
func TestDockerLifecycleBackupFailureBeforeCaptureHasNoServiceEffects(t *testing.T) {
	d, a, j, _ := dockerJournalFixture(t, false)
	r := a.request
	finishThrough(t, j, r, "stage")
	// Ownership becomes unknown after preflight, before backup can stop anything.
	host := a.activation.backup.host.(installationHost)
	base := host.command
	host.command = func(ctx context.Context, p string, args ...string) (string, error) {
		if p == "docker" {
			return "", errors.New("daemon-unavailable")
		}
		return base(ctx, p, args...)
	}
	a.activation.backup.host = host
	r.Phase = "backup"
	requireResult(t, j.Handle(r), "unknown", "backup-failed")
	host.command = base
	a.activation.backup.host = host
	r.Epoch++
	r.Phase = "restore"
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	if a.starts != 0 || a.creates != 0 || a.machine.containers[strings.Repeat("1", 64)].Status != "running" {
		t.Fatal("no-effects recovery mutated original")
	}
	// Even the no-effects path cannot certify an unrecorded task container.
	a.machine.containers[a.target.ID] = a.target
	r.Phase = "restore"
	state, _, err := d.Reconcile(r)
	if state != "unknown" || err == nil {
		t.Fatal("unrecorded task ignored", state, err)
	}
}
func TestDockerLifecycleRejectsUnsupportedOriginalAtPreflight(t *testing.T) {
	_, a, j, _ := dockerJournalFixture(t, false)
	c := a.machine.containers[strings.Repeat("1", 64)]
	c.Command = []string{"foreign-program"}
	a.machine.containers[c.ID] = c
	r := a.request
	r.Phase = "preflight"
	requireResult(t, j.Handle(r), "unknown", "preflight-failed")
	if a.starts != 0 || a.creates != 0 || a.machine.containers[c.ID].Status != "running" {
		t.Fatal("failed preflight mutated service")
	}
}
func TestDockerLifecycleRemainsPrivate(t *testing.T) {
	private := newDockerLifecycle()
	production := NewLocalRuntime()
	for _, phase := range []string{"backup", "activate", "verify", "finalize", "restore", "verify-rollback"} {
		if !private.Supports(phase) || production.Supports(phase) {
			t.Fatal("unfinished lifecycle exposed", phase)
		}
	}
}
