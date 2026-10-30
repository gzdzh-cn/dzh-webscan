package nodeops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recoveryHandoffFixture(t *testing.T) (*groupTargetMachine, Handler, *Journal, Request, Request, Request) {
	t.Helper()
	x, base, j := groupLifecycleFixture(t, "docker", "native")
	convertGroupToCompose(t, x)
	source := x.r
	finishThrough(t, j, source, "finalize")
	head := source
	head.Job, head.PlanDigest = "handoff-head", strings.Repeat("b", 64)
	finishThrough(t, j, head, "finalize")
	head.Epoch++
	for _, phase := range rollback {
		head.Phase = phase
		requireResult(t, j.Handle(head), "complete", "ok")
	}
	capture, err := readPrivate(filepath.Join(x.f.g.backup.directory(source), "capture/intent.json"), 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	active, err := readPrivate(filepath.Join(x.f.g.host.root, "active.json"), MaxRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	r := source
	r.Job, r.PlanDigest, r.Phase, r.Epoch = "handoff-recovery", strings.Repeat("d", 64), "restore", 1
	r.Recovery = &RecoveryReference{SourceJob: source.Job, SourcePlanDigest: source.PlanDigest, CaptureSHA256: sha(capture), HeadJob: head.Job, HeadPlanDigest: head.PlanDigest, ActiveSHA256: sha(active)}
	wrapped := withRecovery(base)
	j = openTestJournal(t, j.root, wrapped)
	return x, wrapped, j, source, head, r
}

func TestRecoveryHandoffRestoresOriginalWithoutRevivingSource(t *testing.T) {
	x, h, j, source, _, r := recoveryHandoffFixture(t)
	if err := h.(*recoveryLifecycle).validateRecoveryAdoption(r, r.Spec.digest()); err != nil {
		t.Fatal("adoption evidence", err)
	}
	before := len(x.f.mutations())
	r.Operation = "inspect"
	requireResult(t, j.Handle(r), "absent", "ok")
	if len(x.f.mutations()) != before {
		t.Fatal("inspection changed services")
	}
	if _, err := os.Lstat(h.(*recoveryLifecycle).path(r)); !os.IsNotExist(err) {
		t.Fatal("inspection wrote recovery intent", err)
	}
	r.Operation = "apply"
	res := j.Handle(r)
	if res.Code != "ok" {
		exists, err := h.(*recoveryLifecycle).prepare(r, false)
		t.Fatalf("recovery apply %+v; intent exists=%v error=%v", res, exists, err)
	}
	requireResult(t, res, "complete", "ok")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	j = openTestJournal(t, j.root, h)
	before = len(x.f.mutations())
	for _, phase := range rollback {
		r.Operation, r.Phase = "inspect", phase
		requireResult(t, j.Handle(r), "complete", "ok")
	}
	if len(x.f.mutations()) != before {
		t.Fatal("completed recovery replay changed services")
	}
	source.Epoch, source.Phase = 99, "restore"
	requireResult(t, j.Handle(source), "unknown", "remote-conflict")
	for _, side := range x.f.wrappers {
		if side.o.Identity.Status != "running" || side.o.Identity.Restart != "unless-stopped" {
			t.Fatal("original sidecar not restored")
		}
	}
	var count int
	if err := x.db.QueryRow("SELECT count(*) FROM events WHERE id='original-id'").Scan(&count); err != nil || count != 1 {
		t.Fatal("current event lost", count, err)
	}
}

func TestRecoveryHandoffRejectsChangedReferencesBeforeAdoption(t *testing.T) {
	for _, damage := range []string{"source", "head", "capture", "active", "plan", "mode", "actual-pointer", "missing-capture", "head-receipt", "parent-link"} {
		t.Run(damage, func(t *testing.T) {
			x, _, j, _, _, r := recoveryHandoffFixture(t)
			switch damage {
			case "source":
				r.Recovery.SourceJob = "other-source"
			case "head":
				r.Recovery.HeadJob = "other-head"
			case "capture":
				r.Recovery.CaptureSHA256 = strings.Repeat("f", 64)
			case "active":
				r.Recovery.ActiveSHA256 = strings.Repeat("f", 64)
			case "plan":
				r.Recovery.SourcePlanDigest = strings.Repeat("f", 64)
			case "mode":
				r.Spec.Mode = "docker"
			case "actual-pointer":
				var active ActiveInstallation
				path := filepath.Join(x.f.g.host.root, "active.json")
				if _, err := decodePrivateJSON(path, &active, MaxRequestBytes); err != nil {
					t.Fatal(err)
				}
				active.Job = "external-installation"
				historyWriteJSON(t, path, active)
			case "missing-capture":
				if err := os.Remove(filepath.Join(x.f.g.host.root, "transitions", r.Recovery.SourceJob, "capture/intent.json")); err != nil {
					t.Fatal(err)
				}
			case "head-receipt":
				if err := os.WriteFile(filepath.Join(x.f.g.host.root, "transitions", r.Recovery.HeadJob, "restoration/export.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				if err := os.Symlink(t.TempDir(), filepath.Join(x.f.g.host.root, "transitions", r.Job)); err != nil {
					t.Fatal(err)
				}
			}
			before := len(x.f.mutations())
			requireResult(t, j.Handle(r), "unknown", "remote-conflict")
			if len(x.f.mutations()) != before {
				t.Fatal("bad reference changed services")
			}
			db, err := j.database()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var count int
			if err := db.QueryRow("SELECT count(*) FROM jobs WHERE id=?", r.Job).Scan(&count); err != nil || count != 0 {
				t.Fatal("bad reference adopted", count, err)
			}
		})
	}
}

func TestRecoveryHandoffBindsReferenceAcrossResume(t *testing.T) {
	x, _, j, _, _, r := recoveryHandoffFixture(t)
	r.Operation = "inspect"
	requireResult(t, j.Handle(r), "absent", "ok")
	r.Operation = "apply"
	r.Recovery.ActiveSHA256 = strings.Repeat("f", 64)
	before := len(x.f.mutations())
	requireResult(t, j.Handle(r), "unknown", "remote-conflict")
	if len(x.f.mutations()) != before {
		t.Fatal("changed reference executed")
	}
}

func TestRecoveryHandoffRequiresSettledJournalAuthority(t *testing.T) {
	for _, damage := range []string{"source-active", "source-unfinished", "source-restoring", "source-running", "head-retired", "head-unfinished", "head-running", "head-spec"} {
		t.Run(damage, func(t *testing.T) {
			x, _, j, source, head, r := recoveryHandoffFixture(t)
			db, err := j.database()
			if err != nil {
				t.Fatal(err)
			}
			var statement string
			var args []any
			switch damage {
			case "source-active":
				statement, args = "UPDATE jobs SET retired=0 WHERE id=?", []any{source.Job}
			case "source-unfinished":
				statement, args = "UPDATE phases SET status='failed' WHERE job=? AND phase='finalize'", []any{source.Job}
			case "source-restoring":
				statement, args = "INSERT INTO phases(job,phase,status) VALUES(?,'restore','failed')", []any{source.Job}
			case "source-running":
				statement, args = "UPDATE phases SET status='running' WHERE job=? AND phase='backup'", []any{source.Job}
			case "head-retired":
				statement, args = "UPDATE jobs SET retired=1 WHERE id=?", []any{head.Job}
			case "head-unfinished":
				statement, args = "UPDATE phases SET status='failed' WHERE job=? AND phase='verify-rollback'", []any{head.Job}
			case "head-running":
				statement, args = "UPDATE phases SET status='running' WHERE job=? AND phase='restore'", []any{head.Job}
			case "head-spec":
				statement, args = "UPDATE jobs SET spec_digest=? WHERE id=?", []any{strings.Repeat("f", 64), head.Job}
			}
			changed, err := db.Exec(statement, args...)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := changed.RowsAffected(); err != nil || n != 1 {
				t.Fatal("fixture did not alter exactly one authority row", n, err)
			}
			db.Close()
			before := len(x.f.mutations())
			requireResult(t, j.Handle(r), "unknown", "remote-conflict")
			if len(x.f.mutations()) != before {
				t.Fatal("unsettled authority changed services")
			}
			db, err = j.database()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var count int
			if err := db.QueryRow("SELECT count(*) FROM jobs WHERE id=?", r.Job).Scan(&count); err != nil || count != 0 {
				t.Fatal("unsettled authority adopted new task", count, err)
			}
		})
	}
}

func TestRecoveryCommandPreservesReferenceAndRestrictsDriver(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			r := boundCommandRequest(t, mode)
			r.Phase = "restore"
			r.Recovery = &RecoveryReference{SourceJob: "original", SourcePlanDigest: strings.Repeat("b", 64), CaptureSHA256: strings.Repeat("c", 64), HeadJob: "successor", HeadPlanDigest: strings.Repeat("d", 64), ActiveSHA256: strings.Repeat("e", 64)}
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeRequest(strings.NewReader(string(raw)))
			if err != nil || decoded.Recovery == nil || *decoded.Recovery != *r.Recovery {
				t.Fatal("recovery envelope lost", err)
			}
			h, err := lifecycleHandler(decoded)
			if err != nil {
				t.Fatal(err)
			}
			wrapped, ok := h.(*recoveryLifecycle)
			if !ok || !wrapped.valid(decoded) || wrapped.Supports("activate") || !wrapped.Supports("restore") {
				t.Fatal("unrestricted or unbound recovery driver")
			}
		})
	}
}

func TestRecoveryHandoffContinuesAfterLostSourceStartResponse(t *testing.T) {
	x, h, j, source, _, r := recoveryHandoffFixture(t)
	x.failAfter = "start " + x.f.wrappers[0].o.Identity.ID
	if result := j.Handle(r); result.Code == "ok" {
		t.Fatal("lost source response reported as success")
	}
	if _, err := readPrivate(h.(*recoveryLifecycle).path(r), MaxRequestBytes); err != nil {
		t.Fatal("authorization not persisted before effects", err)
	}
	j = openTestJournal(t, j.root, h)
	r.Epoch++
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	source.Epoch, source.Phase = 999, "restore"
	requireResult(t, j.Handle(source), "unknown", "remote-conflict")
	if x.f.m.nativeRunning {
		t.Fatal("new writer still running after recovery")
	}
}

func TestRecoveryHandoffCorruptIntentNeverRepairsOrRestarts(t *testing.T) {
	x, h, j, _, _, r := recoveryHandoffFixture(t)
	requireResult(t, j.Handle(r), "complete", "ok")
	path := h.(*recoveryLifecycle).path(r)
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	before := len(x.f.mutations())
	r.Operation = "inspect"
	requireResult(t, j.Handle(r), "unknown", "verification-failed")
	if len(x.f.mutations()) != before {
		t.Fatal("corrupt completed recovery changed services")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "{}" {
		t.Fatal("corrupt authorization repaired", err)
	}
}

func TestRecoveryProtocolRequiresNewIdentityAndRestoreOnly(t *testing.T) {
	_, _, _, _, _, r := recoveryHandoffFixture(t)
	for _, change := range []func(*Request){func(r *Request) { r.Job = r.Recovery.SourceJob }, func(r *Request) { r.Job = r.Recovery.HeadJob }, func(r *Request) { r.Phase = "activate" }, func(r *Request) { r.Recovery.SourceJob = "../source" }} {
		raw, _ := json.Marshal(r)
		var changed Request
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("fixture decode")
		}
		change(&changed)
		if changed.Validate() == nil {
			t.Fatal("invalid recovery accepted")
		}
	}
	if _, err := withRecovery(&testHandler{}).prepare(r, false); err == nil {
		t.Fatal("unbound driver accepted")
	}
}
