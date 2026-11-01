package nodeops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func (x *uninstallFixture) installJournal(t *testing.T) *Journal {
	t.Helper()
	switch base := x.base.(type) {
	case *nativeLifecycle:
		base.activation.host = x.u.host
		base.activation.backup.host = x.u.host
	case *dockerLifecycle:
		base.activation.host = x.u.host
		base.activation.backup.host = x.u.host
	}
	return openTestJournal(t, x.journal.root, x.base)
}
func (x *uninstallFixture) reinstallRequest(t *testing.T, proof Result) Request {
	t.Helper()
	if proof.Removal == nil {
		t.Fatal("missing removal")
	}
	r := x.source
	r.Job = "reinstall-one"
	r.PlanDigest = strings.Repeat("6", 64)
	r.Reinstall = &ReinstallReference{x.request.Job, x.request.PlanDigest, proof.Removal.TombstoneSHA256}
	r.Phase = "preflight"
	r.Operation = "apply"
	return r
}
func (x *uninstallFixture) installationThrough(t *testing.T, j *Journal, r Request, last string) {
	t.Helper()
	for _, phase := range forward {
		r.Phase = phase
		x.installationPhase(t, j, r)
		if phase == last {
			return
		}
	}
}
func (x *uninstallFixture) installationPhase(t *testing.T, j *Journal, r Request) Result {
	t.Helper()
	if x.docker != nil && (r.Phase == "verify" || r.Phase == "finalize") {
		base := x.base.(*dockerLifecycle)
		group := "/docker/" + x.docker.target.ID
		for _, name := range []string{"cpu.max", "memory.max"} {
			raw, err := os.ReadFile(filepath.Join(base.resources.cgroup, "docker", strings.Repeat("9", 64), name))
			if err != nil {
				t.Fatal(err)
			}
			writeResourceFixture(t, filepath.Join(base.resources.cgroup, group, name), string(raw))
		}
		writeResourceFixture(t, filepath.Join(base.resources.proc, "123/cgroup"), "0::"+group+"\n")
	}
	result := j.Handle(r)
	if result.Code != "ok" || result.State != "complete" {
		var err error
		switch base := x.base.(type) {
		case *nativeLifecycle:
			switch r.Phase {
			case "restore":
				err = base.activation.restore(context.Background(), r)
			case "verify-rollback":
				err = base.verifyRollback(context.Background(), r)
			case "finalize":
				_, err = base.finalReceipt(context.Background(), r)
			}
		case *dockerLifecycle:
			switch r.Phase {
			case "verify":
				p, e := base.activationPlan(context.Background(), r, true)
				err = e
				if err == nil {
					err = base.activation.confirm(context.Background(), r, p)
				}
				if err == nil {
					c, e := base.activation.target(context.Background(), r, p)
					err = e
					if err == nil {
						_, err = base.resources.inspectDocker(context.Background(), base.activation.host, c.ID, p.intent.Target, p.material.Settings.Resources)
					}
				}
			case "restore":
				err = base.activation.restore(context.Background(), r)
			case "verify-rollback":
				err = base.verifyRollback(context.Background(), r)
			case "finalize":
				_, err = base.finalReceipt(context.Background(), r)
			}
		}
		t.Fatalf("phase=%s result=%+v diagnostic=%v", r.Phase, result, err)
	}
	return result
}
func TestUninstallReinstallThenUpgradeAndRollbackRetainsLiveState(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x := newUninstallFixture(t, mode)
			var proof Result
			for _, p := range forward {
				proof = x.phase(t, p)
			}
			if _, err := x.database.Exec(`INSERT INTO events(id,payload,created) VALUES('while-uninstalled','{"event_id":"while-uninstalled","node_id":"node-one"}',4)`); err != nil {
				t.Fatal(err)
			}
			r := x.reinstallRequest(t, proof)
			journal := x.installJournal(t)
			x.installationThrough(t, journal, r, "finalize")
			r.Phase = "finalize"
			res := x.installationPhase(t, journal, r)
			requireResult(t, res, "complete", "ok")
			if res.Installation == nil || res.Installation.ActiveSHA256 == x.request.Uninstall.ActiveSHA256 {
				t.Fatal("reinstall did not create new bound installation", res)
			}
			var active ActiveInstallation
			if _, err := decodePrivateJSON(filepath.Join(x.u.runtime.root, "active.json"), &active, MaxRequestBytes); err != nil || !sameReinstall(active.Reinstall, r.Reinstall) {
				t.Fatal("reinstall pointer lost tombstone", err)
			}
			// A normal upgrade follows the exact reinstalled predecessor. It must not
			// demand the legitimately removed pre-uninstall Docker ID.
			upgrade := r
			upgrade.Job = "upgrade-after-reinstall"
			upgrade.PlanDigest = strings.Repeat("a", 64)
			upgrade.Reinstall = nil
			if x.docker != nil {
				x.nextDockerID = strings.Repeat("6", 64)
				x.docker.target.ID = x.nextDockerID
				x.docker.target.Project = dockerProject(ActiveInstallation{Node: upgrade.Node, Job: upgrade.Job, PlanDigest: upgrade.PlanDigest})
			}
			x.installationThrough(t, journal, upgrade, "activate")
			upgrade.Phase = "restore"
			x.installationPhase(t, journal, upgrade)
			upgrade.Phase = "verify-rollback"
			x.installationPhase(t, journal, upgrade)
			if _, err := x.u.host.inventory(context.Background(), r.Node, mode); err != nil {
				t.Fatal("upgraded/restored history invalid", err)
			}
			var count int
			if err := x.database.QueryRow("SELECT count(*) FROM events WHERE id='while-uninstalled'").Scan(&count); err != nil || count != 1 {
				t.Fatal("reinstall or upgrade replaced queue", err)
			}
			// The actual reinstalled source can be safely removed under its own proof.
			next := x.request
			next.Job = "remove-reinstalled"
			next.PlanDigest = strings.Repeat("b", 64)
			next.Spec = r.Spec
			next.Spec.Action = "uninstall"
			next.Uninstall = &UninstallReference{SourceJob: r.Job, SourcePlanDigest: r.PlanDigest, CaptureSHA256: res.Installation.CaptureSHA256, ActiveSHA256: res.Installation.ActiveSHA256}
			x.request = next
			x.journal = openTestJournal(t, journal.root, x.u)
			for _, p := range forward {
				x.phase(t, p)
			}
		})
	}
}
func TestUninstallFailedReinstallReturnsToUninstalledAndKeepsNewEvents(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x := newUninstallFixture(t, mode)
			var proof Result
			for _, p := range forward {
				proof = x.phase(t, p)
			}
			r := x.reinstallRequest(t, proof)
			journal := x.installJournal(t)
			x.installationThrough(t, journal, r, "activate")
			if _, err := x.database.Exec(`INSERT INTO events(id,payload,created) VALUES('failed-reinstall-new','{"event_id":"failed-reinstall-new","node_id":"node-one"}',5)`); err != nil {
				t.Fatal(err)
			}
			r.Phase = "restore"
			x.installationPhase(t, journal, r)
			r.Phase = "verify-rollback"
			x.installationPhase(t, journal, r)
			if _, err := os.Lstat(filepath.Join(x.u.runtime.root, "active.json")); !os.IsNotExist(err) {
				t.Fatal("failed reinstall revived old installation")
			}
			installed, err := x.u.host.inventory(context.Background(), r.Node, mode)
			if err != nil || installed.Generation != "absent" || !sameReinstall(installed.Removal, r.Reinstall) {
				t.Fatal("failed reinstall lost removal baseline", installed, err)
			}
			var count int
			if err := x.database.QueryRow("SELECT count(*) FROM events WHERE id='failed-reinstall-new'").Scan(&count); err != nil || count != 1 {
				t.Fatal("rollback dropped appended event", err)
			}
		})
	}
}
func TestUninstallRejectsWrongOrMissingReinstallTombstoneBeforeStop(t *testing.T) {
	for _, damage := range []string{"missing", "different", "edited-file"} {
		t.Run(damage, func(t *testing.T) {
			x := newUninstallFixture(t, "native")
			var proof Result
			for _, p := range forward {
				proof = x.phase(t, p)
			}
			r := x.reinstallRequest(t, proof)
			journal := x.installJournal(t)
			switch damage {
			case "missing":
				r.Reinstall = nil
			case "different":
				r.Reinstall.TombstoneSHA256 = strings.Repeat("f", 64)
			case "edited-file":
				if err := os.WriteFile(filepath.Join(x.u.directory(x.request), "tombstone.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Depending on the damage, original discovery can reject preflight already.
			var last Result
			for _, p := range forward[:3] {
				r.Phase = p
				last = journal.Handle(r)
				if last.Code != "ok" {
					break
				}
			}
			if last.State == "complete" {
				t.Fatal("unbound reinstall passed backup", last)
			}
			if x.native.machine.nativeRunning {
				t.Fatal("reinstall rejection started a writer")
			}
		})
	}
}
func TestUninstallRestorationReferenceMustMatchNewObject(t *testing.T) {
	for _, damage := range []string{"omit-reference", "old-active", "other-receipt"} {
		t.Run(damage, func(t *testing.T) {
			x := newUninstallFixture(t, "docker")
			for _, p := range forward {
				x.phase(t, p)
			}
			x.phase(t, "restore")
			proof := x.phase(t, "verify-rollback")
			raw, _ := json.Marshal(proof.Restoration)
			q := *x.request.Uninstall
			q.ActiveSHA256 = proof.Restoration.ActiveSHA256
			q.RestorationJob = x.request.Job
			q.RestorationPlanDigest = x.request.PlanDigest
			q.RestorationSHA256 = sha(raw)
			switch damage {
			case "omit-reference":
				q.RestorationJob = ""
				q.RestorationPlanDigest = ""
				q.RestorationSHA256 = ""
			case "old-active":
				q.ActiveSHA256 = x.request.Uninstall.ActiveSHA256
			case "other-receipt":
				q.RestorationSHA256 = strings.Repeat("f", 64)
			}
			r := x.request
			r.Job = "remove-restored-with-bad-proof"
			r.PlanDigest = strings.Repeat("b", 64)
			r.Uninstall = &q
			r.Phase = "preflight"
			result := x.journal.Handle(r)
			if result.State == "complete" {
				t.Fatal("unproven replacement accepted", result)
			}
			if x.docker.machine.containers[x.docker.target.ID].Status != "running" {
				t.Fatal("bad proof stopped service")
			}
		})
	}
}

func TestUninstallReinstalledAncestorRetainsHistoricalRecovery(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x := newUninstallFixture(t, mode)
			var removed Result
			for _, p := range forward {
				removed = x.phase(t, p)
			}
			r := x.reinstallRequest(t, removed)
			journal := x.installJournal(t)
			x.installationThrough(t, journal, r, "finalize")
			r.Phase = "finalize"
			proof := x.installationPhase(t, journal, r)
			upgrade := r
			upgrade.Job = "upgrade-before-ancestor-recovery"
			upgrade.PlanDigest = strings.Repeat("a", 64)
			upgrade.Reinstall = nil
			if x.docker != nil {
				x.nextDockerID = strings.Repeat("6", 64)
				x.docker.target.ID = x.nextDockerID
				x.docker.runtime.ID = x.nextDockerID
				x.docker.target.Project = dockerProject(ActiveInstallation{Node: upgrade.Node, Job: upgrade.Job, PlanDigest: upgrade.PlanDigest})
			}
			x.installationThrough(t, journal, upgrade, "activate")
			upgrade.Phase = "restore"
			x.installationPhase(t, journal, upgrade)
			upgrade.Phase = "verify-rollback"
			x.installationPhase(t, journal, upgrade)
			recovery := r
			recovery.Job = "recover-reinstalled-ancestor"
			recovery.PlanDigest = strings.Repeat("c", 64)
			recovery.Reinstall = nil
			recovery.Phase = "restore"
			recovery.Recovery = &RecoveryReference{SourceJob: r.Job, SourcePlanDigest: r.PlanDigest, HeadJob: upgrade.Job, HeadPlanDigest: upgrade.PlanDigest, CaptureSHA256: proof.Installation.CaptureSHA256, ActiveSHA256: proof.Installation.ActiveSHA256}
			driver := withRecovery(x.base)
			journal = openTestJournal(t, journal.root, driver)
			if result := journal.Handle(recovery); result.Code != "ok" || result.State != "complete" {
				_, _, err := driver.plan(context.Background(), recovery, true)
				t.Fatal("ancestor recovery failed", result, err)
			}
			recovery.Phase = "verify-rollback"
			requireResult(t, journal.Handle(recovery), "complete", "ok")
			inventory, err := x.u.host.inventory(context.Background(), r.Node, mode)
			if err != nil || inventory.Generation != "absent" || !sameReinstall(inventory.Removal, r.Reinstall) {
				t.Fatal("ancestor recovery lost absent baseline", inventory, err)
			}
		})
	}
}

func TestUninstallReinstalledSourceRejectsMissingHistoricalRemoval(t *testing.T) {
	x := newUninstallFixture(t, "native")
	var removed Result
	for _, p := range forward {
		removed = x.phase(t, p)
	}
	r := x.reinstallRequest(t, removed)
	journal := x.installJournal(t)
	x.installationThrough(t, journal, r, "finalize")
	r.Phase = "finalize"
	proof := x.installationPhase(t, journal, r)
	next := x.request
	next.Job = "uninstall-reinstalled-bad-history"
	next.PlanDigest = strings.Repeat("d", 64)
	next.Spec = r.Spec
	next.Spec.Action = "uninstall"
	next.Uninstall = &UninstallReference{SourceJob: r.Job, SourcePlanDigest: r.PlanDigest, CaptureSHA256: proof.Installation.CaptureSHA256, ActiveSHA256: proof.Installation.ActiveSHA256}
	if err := os.Remove(filepath.Join(x.u.directory(x.request), "tombstone.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := x.u.source(context.Background(), next); err == nil {
		t.Fatal("source accepted missing removal history")
	}
	if !x.native.machine.nativeRunning {
		t.Fatal("source check stopped writer")
	}
}
