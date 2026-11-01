package nodeops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallNoEffectsRequiresIntactAttemptAndKeepsOriginalActive(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x := newUninstallFixture(t, mode)
			x.phase(t, "preflight")
			x.phase(t, "stage")
			x.lostBefore = "show"
			if mode == "docker" {
				x.lostBefore = "info"
			}
			r := x.request
			r.Phase = "backup"
			requireResult(t, x.journal.Handle(r), "unknown", "backup-failed")
			x.lostBefore = ""
			x.phase(t, "restore")
			proof := x.phase(t, "verify-rollback")
			if proof.Restoration == nil || !proof.Restoration.NoEffects || proof.Restoration.CaptureSHA256 != "" || proof.Restoration.ActiveSHA256 != r.Uninstall.ActiveSHA256 {
				t.Fatal("no effects evidence wrong", proof)
			}
			raw, _ := json.Marshal(proof.Restoration)
			next := x.request
			q := *next.Uninstall
			q.RestorationJob = next.Job
			q.RestorationPlanDigest = next.PlanDigest
			q.RestorationSHA256 = sha(raw)
			next.Job = "after-no-effects"
			next.PlanDigest = strings.Repeat("5", 64)
			next.Uninstall = &q
			x.request = next
			for _, p := range forward {
				x.phase(t, p)
			}
		})
	}
}
func TestUninstallRefusesMissingCaptureAfterQuiesce(t *testing.T) {
	x := newUninstallFixture(t, "native")
	x.phase(t, "preflight")
	x.phase(t, "stage")
	x.lostAfter = "disable"
	r := x.request
	r.Phase = "backup"
	requireResult(t, x.journal.Handle(r), "unknown", "backup-failed")
	x.lostAfter = ""
	if err := os.RemoveAll(filepath.Join(x.u.backup.directory(r), "capture")); err != nil {
		t.Fatal(err)
	}
	r.Phase = "restore"
	result := x.journal.Handle(r)
	if result.State == "complete" || result.Restoration != nil || x.native.machine.nativeRunning {
		t.Fatal("lost capture became successful rollback", result)
	}
}
func TestUninstallPartialBackupRestoresWithoutReplacingCurrentData(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x := newUninstallFixture(t, mode)
			x.phase(t, "preflight")
			x.phase(t, "stage")
			x.lostAfter = "disable"
			if mode == "docker" {
				x.lostAfter = "stop"
			}
			r := x.request
			r.Phase = "backup"
			requireResult(t, x.journal.Handle(r), "unknown", "backup-failed")
			x.lostAfter = ""
			if _, err := x.database.Exec(`INSERT INTO events(id,payload,created) VALUES('new-after-backup','{}',3)`); err != nil {
				t.Fatal(err)
			}
			x.phase(t, "restore")
			result := x.phase(t, "verify-rollback")
			if result.Restoration == nil || result.Restoration.NoEffects {
				t.Fatal("partial backup lost capture proof")
			}
			var count int
			if err := x.database.QueryRow("SELECT count(*) FROM events WHERE id='new-after-backup'").Scan(&count); err != nil || count != 1 {
				t.Fatal("new queue event lost", err)
			}
		})
	}
}
func TestUninstallReconcilesLostRemoveAndRestoreResponses(t *testing.T) {
	for _, tc := range []struct{ mode, verb string }{{"native", "daemon-reload"}, {"docker", "rm"}} {
		t.Run(tc.mode+"/remove", func(t *testing.T) {
			x := newUninstallFixture(t, tc.mode)
			for _, p := range forward[:3] {
				x.phase(t, p)
			}
			x.lostAfter = tc.verb
			r := x.request
			r.Phase = "activate"
			requireResult(t, x.journal.Handle(r), "unknown", "activation-failed")
			x.lostAfter = ""
			x.request.Epoch++
			x.phase(t, "activate")
			x.phase(t, "verify")
			x.phase(t, "finalize")
		})
	}
	for _, tc := range []struct{ mode, verb string }{{"native", "start"}, {"docker", "compose"}, {"docker", "start"}} {
		t.Run(tc.mode+"/"+tc.verb, func(t *testing.T) {
			x := newUninstallFixture(t, tc.mode)
			for _, p := range forward {
				x.phase(t, p)
			}
			x.lostAfter = tc.verb
			r := x.request
			r.Phase = "restore"
			requireResult(t, x.journal.Handle(r), "unknown", "remote-state-unknown")
			x.lostAfter = ""
			x.request.Epoch++
			x.phase(t, "restore")
			x.phase(t, "verify-rollback")
			before := 0
			if x.native != nil {
				before = x.native.starts
			} else {
				before = x.docker.starts
			}
			x.phase(t, "restore")
			after := 0
			if x.native != nil {
				after = x.native.starts
			} else {
				after = x.docker.starts
			}
			if before != after {
				t.Fatal("replayed restoration restarted a writer")
			}
		})
	}
}
func TestUninstallRefusesTamperedEvidenceWithoutTouchingService(t *testing.T) {
	for _, damage := range []string{"source-capture", "source-active", "source-restoration", "intent", "preservation", "snapshot", "tombstone", "replacement"} {
		t.Run(damage, func(t *testing.T) {
			x := newUninstallFixture(t, "native")
			if strings.HasPrefix(damage, "source-") {
				q := *x.request.Uninstall
				switch damage {
				case "source-capture":
					q.CaptureSHA256 = strings.Repeat("f", 64)
				case "source-active":
					q.ActiveSHA256 = strings.Repeat("f", 64)
				case "source-restoration":
					q.RestorationJob = "missing-restoration"
					q.RestorationPlanDigest = strings.Repeat("f", 64)
					q.RestorationSHA256 = strings.Repeat("f", 64)
				}
				x.request.Uninstall = &q
				r := x.request
				r.Phase = "preflight"
				result := x.journal.Handle(r)
				if result.State == "complete" || !x.native.machine.nativeRunning {
					t.Fatal("unproven source accepted", result)
				}
				return
			}
			for _, p := range forward {
				x.phase(t, p)
			}
			file := ""
			phase := "finalize"
			switch damage {
			case "intent":
				file = filepath.Join(x.u.directory(x.request), "intent.json")
			case "preservation":
				file = filepath.Join(x.u.directory(x.request), "preserved.json")
			case "snapshot":
				file = filepath.Join(x.u.backup.directory(x.request), "snapshot/receipt.json")
			case "tombstone":
				file = filepath.Join(x.u.directory(x.request), "tombstone.json")
			case "replacement":
				x.phase(t, "restore")
				x.phase(t, "verify-rollback")
				file = filepath.Join(x.u.directory(x.request), "restoration-object.json")
				phase = "verify-rollback"
			}
			if err := os.WriteFile(file, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			r := x.request
			r.Phase = phase
			r.Operation = "inspect"
			if result := x.journal.Handle(r); result.State == "complete" || result.Removal != nil || result.Restoration != nil {
				t.Fatal("corrupt evidence accepted", result)
			}
		})
	}
}
func TestUninstallRequiresOriginalRecoveryMaterialsBeforeStop(t *testing.T) {
	x := newUninstallFixture(t, "native")
	if err := os.Remove(filepath.Join(x.u.runtime.releaseDir(x.source.Spec), "webscan")); err != nil {
		t.Fatal(err)
	}
	r := x.request
	r.Phase = "preflight"
	if result := x.journal.Handle(r); result.State == "complete" || !x.native.machine.nativeRunning {
		t.Fatal("missing original program accepted", result)
	}
}
func TestUninstallRetainsPKIAndRejectsReplacedLiveDatabase(t *testing.T) {
	x := newUninstallFixture(t, "native")
	for _, entry := range []struct{ dir, name, text string }{{"pki-trust", "floor.json", "latest-floor"}, {"pki-identity", "active.pem", "latest-identity"}} {
		dir := filepath.Join(x.u.backup.data, entry.dir)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, entry.name), []byte(entry.text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range forward {
		x.phase(t, p)
	}
	x.phase(t, "restore")
	x.phase(t, "verify-rollback")
	for _, entry := range []struct{ path, text string }{{"pki-trust/floor.json", "latest-floor"}, {"pki-identity/active.pem", "latest-identity"}} {
		raw, err := os.ReadFile(filepath.Join(x.u.backup.data, entry.path))
		if err != nil || string(raw) != entry.text {
			t.Fatal("live PKI changed", err)
		}
	}
	// A byte-identical replacement is still an unauthorized database restore.
	db := filepath.Join(x.u.backup.data, "agent.sqlite3")
	raw, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(db, db+".operator-old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(db, raw, 0600); err != nil {
		t.Fatal(err)
	}
	r := x.request
	r.Phase = "verify-rollback"
	r.Operation = "inspect"
	if result := x.journal.Handle(r); result.State == "complete" {
		t.Fatal("replaced live DB accepted", result)
	}
}
func TestUninstallRejectsForeignReplacementContainer(t *testing.T) {
	x := newUninstallFixture(t, "docker")
	for _, p := range forward {
		x.phase(t, p)
	}
	c := x.docker.target
	c.ID = strings.Repeat("6", 64)
	c.Managed = "foreign"
	c.Status = "running"
	x.docker.machine.containers[c.ID] = c
	r := x.request
	r.Phase = "restore"
	result := x.journal.Handle(r)
	if result.State == "complete" {
		t.Fatal("foreign container adopted", result)
	}
	if x.docker.machine.containers[c.ID].Status != "running" {
		t.Fatal("foreign writer modified")
	}
	_ = context.Background()
}

func TestUninstallFinalizationResumesBetweenReceiptAndCurrentPointer(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x := newUninstallFixture(t, mode)
			for _, p := range forward[:5] {
				x.phase(t, p)
			}
			r := x.request
			r.Phase = "finalize"
			if _, err := x.u.operation(r, func(ctx context.Context, q Request) (Outcome, error) { return Outcome{}, x.u.finalizeRemoval(ctx, q) }); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(x.u.runtime.root, "uninstalled.json")); err != nil {
				t.Fatal(err)
			}
			state, _, err := x.u.Reconcile(r)
			if err != nil || state != "absent" {
				t.Fatal("partial marker must be resumable", state, err)
			}
			result := x.phase(t, "finalize")
			if result.Removal == nil {
				t.Fatal("no removal evidence")
			}
		})
	}
}
func TestUninstallRefusesForeignCurrentPointerAfterPartialFinalization(t *testing.T) {
	x := newUninstallFixture(t, "native")
	for _, p := range forward[:5] {
		x.phase(t, p)
	}
	r := x.request
	r.Phase = "finalize"
	if _, err := x.u.operation(r, func(ctx context.Context, q Request) (Outcome, error) { return Outcome{}, x.u.finalizeRemoval(ctx, q) }); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(x.u.runtime.root, "uninstalled.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	state, _, err := x.u.Reconcile(r)
	if err == nil || state != "unknown" {
		t.Fatal("foreign marker accepted", state, err)
	}
}
func TestUninstallMutationRequiresNoUnmanagedAgentWriter(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, phase := range []string{"activate", "restore"} {
			t.Run(mode+"/"+phase, func(t *testing.T) {
				x := newUninstallFixture(t, mode)
				last := 3
				if phase == "restore" {
					last = len(forward)
				}
				for _, p := range forward[:last] {
					x.phase(t, p)
				}
				lock, err := x.u.backup.agentLock()
				if err != nil {
					t.Fatal(err)
				}
				r := x.request
				r.Phase = phase
				result := x.journal.Handle(r)
				if result.State == "complete" {
					lock.Close()
					t.Fatal("unmanaged writer accepted", result)
				}
				if phase == "activate" {
					if _, err := os.Lstat(x.u.host.unitPath); mode == "native" && err != nil {
						lock.Close()
						t.Fatal("unit removed under writer lock", err)
					}
				}
				if phase == "restore" {
					if _, err := os.Lstat(filepath.Join(x.u.runtime.root, "active.json")); !os.IsNotExist(err) {
						lock.Close()
						t.Fatal("active pointer published under writer lock", err)
					}
				}
				lock.Close()
				x.request.Epoch++
				x.phase(t, phase)
			})
		}
	}
}
func TestUninstallRestorationMustConfirmPreviousRemovalPointer(t *testing.T) {
	x := newUninstallFixture(t, "native")
	for _, p := range forward {
		x.phase(t, p)
	}
	x.phase(t, "restore")
	if err := os.WriteFile(filepath.Join(x.u.runtime.root, "uninstalled.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	r := x.request
	r.Phase = "verify-rollback"
	result := x.journal.Handle(r)
	if result.State == "complete" || result.Restoration != nil {
		t.Fatal("unconfirmed predecessor marker accepted", result)
	}
}

func TestUninstallMissingLiveDatabaseCannotBecomeSuccessfulRemoval(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x := newUninstallFixture(t, mode)
			for _, p := range forward[:3] {
				x.phase(t, p)
			}
			if err := os.Remove(filepath.Join(x.u.backup.data, "agent.sqlite3")); err != nil {
				t.Fatal(err)
			}
			r := x.request
			r.Phase = "activate"
			result := x.journal.Handle(r)
			if result.State == "complete" || result.Removal != nil {
				t.Fatal("missing live database accepted", result)
			}
			if _, err := os.Lstat(filepath.Join(x.u.runtime.root, "active.json")); err != nil {
				t.Fatal("original pointer changed", err)
			}
		})
	}
}
