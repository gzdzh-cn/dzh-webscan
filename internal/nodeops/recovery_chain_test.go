package nodeops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryHandoffCanContinueThroughRecoveryHead(t *testing.T) {
	x, base, j := groupLifecycleFixture(t, "docker", "native")
	convertGroupToCompose(t, x)
	source := x.r
	finishThrough(t, j, source, "finalize")
	middle := source
	middle.Job, middle.PlanDigest = "chain-middle", strings.Repeat("b", 64)
	finishThrough(t, j, middle, "finalize")
	head := source
	head.Job, head.PlanDigest = "chain-head", strings.Repeat("c", 64)
	finishThrough(t, j, head, "finalize")
	head.Epoch++
	for _, phase := range rollback {
		head.Phase = phase
		requireResult(t, j.Handle(head), "complete", "ok")
	}
	wrapped := withRecovery(base)
	j = openTestJournal(t, j.root, wrapped)
	recovery := func(original, current Request, job, plan string) Request {
		t.Helper()
		capture, err := readPrivate(filepath.Join(x.f.g.backup.directory(original), "capture/intent.json"), 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		active, err := readPrivate(filepath.Join(x.f.g.host.root, "active.json"), MaxRequestBytes)
		if err != nil {
			t.Fatal(err)
		}
		r := original
		r.Job, r.PlanDigest, r.Operation, r.Phase, r.Epoch = job, plan, "apply", "restore", 1
		r.Recovery = &RecoveryReference{SourceJob: original.Job, SourcePlanDigest: original.PlanDigest, CaptureSHA256: sha(capture), HeadJob: current.Job, HeadPlanDigest: current.PlanDigest, ActiveSHA256: sha(active)}
		return r
	}
	first := recovery(middle, head, "chain-middle-recovery", strings.Repeat("d", 64))
	for _, phase := range rollback {
		first.Phase = phase
		requireResult(t, j.Handle(first), "complete", "ok")
	}
	final := recovery(source, first, "chain-original-recovery", strings.Repeat("e", 64))
	for _, phase := range rollback {
		final.Phase = phase
		requireResult(t, j.Handle(final), "complete", "ok")
	}
	j = openTestJournal(t, j.root, wrapped)
	before := len(x.f.mutations())
	for _, phase := range rollback {
		final.Operation, final.Phase = "inspect", phase
		requireResult(t, j.Handle(final), "complete", "ok")
	}
	for _, retired := range []Request{source, middle, head, first} {
		retired.Operation, retired.Phase, retired.Epoch = "apply", "restore", 999
		requireResult(t, j.Handle(retired), "unknown", "remote-conflict")
	}
	if len(x.f.mutations()) != before {
		t.Fatal("retired task or completed replay changed services")
	}
	for _, side := range x.f.wrappers {
		if side.o.Identity.Status != "running" || side.o.Identity.Restart != "unless-stopped" {
			t.Fatal("original sidecar not restored")
		}
	}
	var count int
	if err := x.db.QueryRow("SELECT count(*) FROM events WHERE id='original-id'").Scan(&count); err != nil || count != 1 {
		t.Fatal("current event lost", count, err)
	}
	// A completed outer recovery must continue to authenticate its whole chain.
	path := wrapped.path(first)
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	requireResult(t, j.Handle(final), "unknown", "verification-failed")
	if len(x.f.mutations()) != before {
		t.Fatal("corrupt recovery chain changed services")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "{}" {
		t.Fatal("corrupt recovery chain was repaired", err)
	}

}
