package nodeops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This drives the real private phase methods and real SQLite Journal, while
// service-manager/kernel evidence is a controlled fixture. It is not a running
// systemd manager or the production command's handler.
func nativeJournalFixture(t *testing.T, fresh bool) (*nativeLifecycle, *activationMachine, *Journal, *nativeResourceFixture) {
	t.Helper()
	a := nativeActivationFixture(t, fresh)
	if err := os.RemoveAll(filepath.Join(a.activation.runtime.root, "transitions")); err != nil {
		t.Fatal(err)
	}
	a.machine.nativeRunning, a.machine.nativeEnabled = !fresh, !fresh
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
	n := &nativeLifecycle{runtime: a.activation.runtime, activation: a.activation, resources: f.fs, preflight: &testHandler{}}
	j := openTestJournal(t, filepath.Join(n.runtime.root, "journal"), n)
	return n, a, j, f
}

func TestNativeJournalCompletesAndRevalidatesPrivateLifecycle(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing", true: "fresh"}[fresh], func(t *testing.T) {
			n, a, j, _ := nativeJournalFixture(t, fresh)
			db := restorationData(t, a)
			r := a.request
			finishThrough(t, j, r, "finalize")
			if a.starts != 1 {
				t.Fatal("unexpected target restart", a.starts)
			}
			for _, phase := range forward {
				r.Phase = phase
				r.Operation = "inspect"
				requireResult(t, j.Handle(r), "complete", "ok")
			}
			if a.starts != 1 {
				t.Fatal("receipt replay restarted target")
			}
			var nrows int
			if err := db.QueryRow("SELECT count(*) FROM events").Scan(&nrows); err != nil || nrows != 2 {
				t.Fatal("lifecycle replaced live database", err)
			}
			if err := os.WriteFile(filepath.Join(n.activation.backup.directory(r), "finalized.json"), []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			r.Phase = "finalize"
			requireResult(t, j.Handle(r), "unknown", "verification-failed")
		})
	}
}

func TestNativeJournalReconcilesInterruptedActivationWithoutDuplicateStart(t *testing.T) {
	for _, operation := range []string{"daemon-reload", "enable", "start"} {
		t.Run(operation, func(t *testing.T) {
			_, a, j, _ := nativeJournalFixture(t, false)
			r := a.request
			finishThrough(t, j, r, "backup")
			a.crashAfter = operation
			r.Phase = "activate"
			requireResult(t, j.Handle(r), "unknown", "activation-failed")
			a.crashAfter = ""
			r.Epoch++
			r.Operation = "inspect"
			res := j.Handle(r)
			if operation == "start" {
				requireResult(t, res, "complete", "ok")
			} else {
				requireResult(t, res, "absent", "ok")
			}
			r.Operation = "apply"
			requireResult(t, j.Handle(r), "complete", "ok")
			if a.starts != 1 {
				t.Fatal("interrupted activation restarted writer", a.starts)
			}
			r.Phase = "verify"
			requireResult(t, j.Handle(r), "complete", "ok")
		})
	}
}

func TestNativeJournalCanRollbackInterruptedBackupWithoutSnapshot(t *testing.T) {
	n, a, j, _ := nativeJournalFixture(t, false)
	redb := restorationData(t, a)
	r := a.request
	finishThrough(t, j, r, "stage")
	lock, err := n.activation.backup.agentLock()
	if err != nil {
		t.Fatal(err)
	}
	r.Phase = "backup"
	requireResult(t, j.Handle(r), "unknown", "backup-failed")
	lock.Close()
	r.Epoch++
	r.Phase = "restore"
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	if !a.machine.nativeRunning || !a.machine.nativeEnabled {
		t.Fatal("original service not restored")
	}
	var count int
	if err := redb.QueryRow("SELECT count(*) FROM events WHERE accepted IS NULL AND exported IS NOT NULL").Scan(&count); err != nil || count != 1 {
		t.Fatal("pending event lost in journal rollback", err)
	}
	r.Phase = "backup"
	requireResult(t, j.Handle(r), "unknown", "phase-order")
}

func TestNativeJournalResourceFailureAllowsDataPreservingRollback(t *testing.T) {
	_, a, j, f := nativeJournalFixture(t, false)
	redb := restorationData(t, a)
	r := a.request
	finishThrough(t, j, r, "activate")
	writeResourceFixture(t, f.memory, "max\n")
	r.Phase = "verify"
	requireResult(t, j.Handle(r), "unknown", "verification-failed")
	r.Phase = "restore"
	r.Epoch++
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	var count int
	if err := redb.QueryRow("SELECT count(*) FROM events").Scan(&count); err != nil || count != 2 {
		t.Fatal("resource failure rollback changed DB", err)
	}
}

func TestNativeJournalCannotReconcileWhileServiceClientStillOwnsLock(t *testing.T) {
	n, a, j, _ := nativeJournalFixture(t, false)
	r := a.request
	finishThrough(t, j, r, "stage")
	a.fail = "disable"
	r.Phase = "backup"
	requireResult(t, j.Handle(r), "unknown", "backup-failed")
	a.fail = ""
	_, release, err := acquireServiceOperation(context.Background(), n.runtime.root)
	if err != nil {
		t.Fatal(err)
	}
	r.Operation = "inspect"
	r.Epoch++
	requireResult(t, j.Handle(r), "unknown", "remote-state-unknown")
	release()
	requireResult(t, j.Handle(r), "absent", "ok")
}

func TestNativeLifecycleDoesNotAdoptTargetWithoutActivationIntent(t *testing.T) {
	n, a, j, _ := nativeJournalFixture(t, true)
	r := a.request
	finishThrough(t, j, r, "backup")
	r.Phase = "activate"
	if err := a.activation.run(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(a.activation.intentPath(r)); err != nil {
		t.Fatal(err)
	}
	state, _, err := n.Reconcile(r)
	if state != "unknown" || err == nil {
		t.Fatal("unrecorded target adopted", state, err)
	}
}

func TestNativeLifecycleRejectsUnknownOriginalAtPreflight(t *testing.T) {
	n, a, j, _ := nativeJournalFixture(t, false)
	a.program = "/foreign/program"
	r := a.request
	r.Phase = "preflight"
	requireResult(t, j.Handle(r), "unknown", "preflight-failed")
	if !a.machine.nativeRunning || !a.machine.nativeEnabled || a.starts != 0 {
		t.Fatal("failed preflight changed original service")
	}
	if _, err := os.Lstat(filepath.Join(n.activation.backup.directory(r), "capture")); !os.IsNotExist(err) {
		t.Fatal("failed preflight prepared recovery state", err)
	}
}

func TestNativeLifecycleBackupReconciliationRequiresOriginalStopped(t *testing.T) {
	n, a, j, _ := nativeJournalFixture(t, false)
	r := a.request
	finishThrough(t, j, r, "backup")
	a.machine.nativeRunning = true
	r.Phase = "backup"
	state, _, err := n.Reconcile(r)
	if err != nil || state != "absent" {
		t.Fatal("past snapshot was confused with current stopped state", state, err)
	}
	if _, err := n.Apply(r); err != nil {
		t.Fatal("safe backup replay failed", err)
	}
	state, _, err = n.Reconcile(r)
	if err != nil || state != "complete" {
		t.Fatal("stopped original snapshot not reconciled", state, err)
	}
}

func TestNativeLifecycleRemainsPrivateToValidation(t *testing.T) {
	production := NewLocalRuntime()
	for _, phase := range []string{"backup", "activate", "verify", "finalize", "restore", "verify-rollback"} {
		if production.Supports(phase) {
			t.Fatal("unfinished native driver became production default", phase)
		}
	}
	private := newNativeLifecycle()
	if !private.Supports("restore") {
		t.Fatal("private driver missing recovery phase")
	}
}
