package nodeops

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeJournalCanCloseBackupRefusedBeforeCaptureWithoutTouchingHost(t *testing.T) {
	n, a, j, _ := nativeJournalFixture(t, false)
	r := a.request
	finishThrough(t, j, r, "stage")
	// Another operator changes ownership after preflight. The task must not
	// stop that process, recapture it as its own, or remain unrecoverable.
	a.program = "/another/operator/program"
	r.Phase = "backup"
	requireResult(t, j.Handle(r), "unknown", "backup-failed")
	if _, err := os.Lstat(filepath.Join(n.activation.backup.directory(r), "capture")); !os.IsNotExist(err) {
		t.Fatal("unsupported process captured", err)
	}
	calls := len(a.machine.calls)
	r.Phase = "restore"
	r.Epoch++
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	if len(a.machine.calls) != calls || !a.machine.nativeRunning || !a.machine.nativeEnabled || a.starts != 0 {
		t.Fatal("no-effect recovery touched the original/foreign service")
	}
	// A lost local response reconciles the durable no-effect receipt rather
	// than running any host recovery command.
	db, err := j.database()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE phases SET status='running' WHERE job=? AND phase='restore'", r.Job); err != nil {
		t.Fatal(err)
	}
	db.Close()
	r.Phase = "restore"
	r.Operation = "inspect"
	r.Epoch++
	requireResult(t, j.Handle(r), "complete", "ok")
	if len(a.machine.calls) != calls {
		t.Fatal("reconciliation ran a host command")
	}
	r.Operation = "apply"
	r.Phase = "backup"
	if _, err := n.Apply(r); err == nil {
		t.Fatal("direct forward execution after no-effect recovery")
	}
	if _, err := n.activation.backup.run(context.Background(), r); err == nil {
		t.Fatal("backup bypassed recovery receipt")
	}
	r.Phase = "activate"
	if err := n.activation.run(context.Background(), r); err == nil {
		t.Fatal("activation bypassed recovery receipt")
	}
}

func TestMissingCaptureAfterQuiesceCannotBecomeNoEffectRollback(t *testing.T) {
	n, a, j, _ := nativeJournalFixture(t, false)
	r := a.request
	finishThrough(t, j, r, "backup")
	if err := os.RemoveAll(filepath.Join(n.activation.backup.directory(r), "capture")); err != nil {
		t.Fatal(err)
	}
	r.Phase = "backup"
	if state, _, err := n.Reconcile(r); err == nil || state != "unknown" {
		t.Fatal("lost capture recaptured stopped state", state, err)
	}
	r.Phase = "restore"
	if _, err := n.Apply(r); err == nil {
		t.Fatal("missing recovery data treated as no effect")
	}
	if a.machine.nativeRunning || a.starts != 0 {
		t.Fatal("unproven original was started")
	}
}

func TestUncapturedRollbackRequiresBoundIntactAttemptAndReceipt(t *testing.T) {
	for _, damage := range []string{"missing-attempt", "corrupt-attempt", "activation", "quiesce", "corrupt-receipt", "foreign-job"} {
		t.Run(damage, func(t *testing.T) {
			n, a, j, _ := nativeJournalFixture(t, false)
			r := a.request
			finishThrough(t, j, r, "stage")
			a.program = "/foreign/program"
			r.Phase = "backup"
			requireResult(t, j.Handle(r), "unknown", "backup-failed")
			dir := n.activation.backup.directory(r)
			switch damage {
			case "missing-attempt":
				if err := os.Remove(filepath.Join(dir, "backup-attempt.json")); err != nil {
					t.Fatal(err)
				}
			case "corrupt-attempt":
				if err := os.WriteFile(filepath.Join(dir, "backup-attempt.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "activation":
				if err := os.Mkdir(filepath.Join(dir, "activation"), 0700); err != nil {
					t.Fatal(err)
				}
			case "quiesce":
				if err := os.WriteFile(filepath.Join(dir, "quiesce.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-receipt":
				if err := os.Mkdir(filepath.Join(dir, "restoration"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "restoration/no-effects.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-job":
				r.PlanDigest = sha([]byte("another-plan"))
			}
			calls := len(a.machine.calls)
			r.Phase = "restore"
			if _, err := n.Apply(r); err == nil {
				t.Fatal("unproven no-effect restoration accepted")
			}
			if len(a.machine.calls) != calls || !a.machine.nativeRunning {
				t.Fatal("failed no-effect restore touched service")
			}
		})
	}
}
