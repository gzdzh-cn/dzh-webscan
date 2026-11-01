package nodeops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type uninstallFixture struct {
	base                  Handler
	nextDockerID          string
	u                     *uninstallLifecycle
	journal               *Journal
	source                Request
	request               Request
	database              *sql.DB
	native                *activationMachine
	docker                *dockerActivationMachine
	lostBefore, lostAfter string
}

func newUninstallFixture(t *testing.T, mode string) *uninstallFixture {
	t.Helper()
	x := &uninstallFixture{}
	var base Handler
	var j *Journal
	if mode == "native" {
		n, a, journal, _ := nativeJournalFixture(t, true)
		base = n
		j = journal
		x.native = a
		x.source = a.request
		x.database = restorationData(t, a)
	} else {
		d, a, journal, _ := dockerJournalFixture(t, true)
		base = d
		j = journal
		x.docker = a
		x.source = a.request
		x.database = dockerRestorationData(t, a)
	}
	finishThrough(t, j, x.source, "finalize")
	r := x.source
	r.Phase = "finalize"
	r.Operation = "inspect"
	proof := j.Handle(r)
	requireResult(t, proof, "complete", "ok")
	if proof.Installation == nil {
		t.Fatal("source installation has no proof")
	}
	x.base = base
	x.nextDockerID = strings.Repeat("7", 64)
	x.u = withUninstall(base)
	original := x.u.host.command
	x.u.host.command = func(ctx context.Context, program string, args ...string) (string, error) {
		verb := ""
		if program == "docker" && len(args) > 2 {
			verb = args[2]
		} else if len(args) > 0 {
			verb = args[0]
		}
		if verb == x.lostBefore {
			return "", errors.New("injected-before-operation")
		}
		var out string
		var err error
		if program == "docker" && verb == "ps" && len(args) > 6 && strings.HasPrefix(args[6], "id=") {
			id := strings.TrimPrefix(args[6], "id=")
			if _, ok := x.docker.machine.containers[id]; ok {
				out = id + "\n"
			}
		} else if program == "docker" && verb == "rm" {
			id := args[3]
			c, ok := x.docker.machine.containers[id]
			if !ok || c.Status == "running" {
				return "", errors.New("unsafe rm")
			}
			delete(x.docker.machine.containers, id)
		} else if program == "docker" && verb == "compose" {
			// The original definition is used to create a fresh ID after uninstall.
			if _, ok := x.docker.machine.containers[x.docker.target.ID]; !ok {
				x.docker.target.ID = x.nextDockerID
				x.docker.runtime.ID = x.docker.target.ID
			}
			x.docker.target.Project = args[6]
			out, err = original(ctx, program, args...)
		} else {
			out, err = original(ctx, program, args...)
		}
		if err == nil && verb == x.lostAfter {
			return out, errors.New("injected-response-loss")
		}
		return out, err
	}
	x.u.backup.host = x.u.host
	x.request = x.source
	x.request.Job = "uninstall-one"
	x.request.PlanDigest = strings.Repeat("4", 64)
	x.request.Spec.Action = "uninstall"
	x.request.Phase = "preflight"
	x.request.Operation = "apply"
	x.request.Uninstall = &UninstallReference{SourceJob: x.source.Job, SourcePlanDigest: x.source.PlanDigest, CaptureSHA256: proof.Installation.CaptureSHA256, ActiveSHA256: proof.Installation.ActiveSHA256}
	x.journal = openTestJournal(t, j.root, x.u)
	return x
}
func (x *uninstallFixture) phase(t *testing.T, phase string) Result {
	t.Helper()
	r := x.request
	r.Phase = phase
	r.Operation = "apply"
	res := x.journal.Handle(r)
	if res.Code != "ok" || res.State != "complete" {
		_, err := x.u.operation(r, func(ctx context.Context, q Request) (Outcome, error) {
			switch q.Phase {
			case "preflight", "stage":
				_, _, e := x.u.source(ctx, q)
				if e == nil {
					e = x.u.recoveryMaterials(ctx, q)
				}
				return Outcome{}, e
			case "activate":
				return Outcome{}, x.u.remove(ctx, q)
			case "restore":
				return Outcome{}, x.u.restore(ctx, q)
			case "verify-rollback":
				return Outcome{}, x.u.sealRestoration(ctx, q)
			case "finalize":
				return Outcome{}, x.u.finalizeRemoval(ctx, q)
			}
			return Outcome{}, nil
		})
		t.Fatalf("phase %s: %+v diagnostic=%v", phase, res, err)
	}
	return res
}
func TestUninstallNativeAndDockerRetainDataAndProduceProof(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x := newUninstallFixture(t, mode)
			for _, p := range forward {
				x.phase(t, p)
			}
			res := x.phase(t, "finalize")
			if res.Removal == nil || !res.Removal.Valid() || res.Installation != nil {
				t.Fatal("missing exclusive removal proof", res)
			}
			var count int
			if err := x.database.QueryRow("SELECT count(*) FROM events").Scan(&count); err != nil || count != 2 {
				t.Fatal("data lost", err, count)
			}
			if _, err := os.Lstat(filepath.Join(x.u.runtime.root, "active.json")); !os.IsNotExist(err) {
				t.Fatal("active pointer retained", err)
			}
			installed, err := x.u.host.inventory(context.Background(), x.request.Node, mode)
			if err != nil || installed.Generation != "absent" || installed.Removal == nil || installed.Removal.TombstoneSHA256 != res.Removal.TombstoneSHA256 {
				t.Fatal("uninstalled state not anchored", installed, err)
			}
		})
	}
}
func TestUninstallRestoresFixedServiceAndSupportsAgain(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x := newUninstallFixture(t, mode)
			for _, p := range forward {
				x.phase(t, p)
			}
			x.phase(t, "restore")
			proof := x.phase(t, "verify-rollback")
			if proof.Restoration == nil || !proof.Restoration.Valid() || proof.Restoration.NoEffects || proof.Restoration.ActiveSHA256 == x.request.Uninstall.ActiveSHA256 {
				t.Fatal("missing new restoration proof", proof)
			}
			before := 0
			if mode == "native" {
				before = x.native.starts
			} else {
				before = x.docker.starts
			}
			x.phase(t, "restore")
			x.phase(t, "verify-rollback")
			after := 0
			if mode == "native" {
				after = x.native.starts
			} else {
				after = x.docker.starts
			}
			if before != after {
				t.Fatal("replay restarted writer")
			}
			raw, _ := json.Marshal(proof.Restoration)
			q := *x.request.Uninstall
			q.ActiveSHA256 = proof.Restoration.ActiveSHA256
			q.RestorationJob = x.request.Job
			q.RestorationPlanDigest = x.request.PlanDigest
			q.RestorationSHA256 = sha(raw)
			x.request.Job = "uninstall-again"
			x.request.PlanDigest = strings.Repeat("5", 64)
			x.request.Uninstall = &q
			for _, p := range forward {
				x.phase(t, p)
			}
		})
	}
}
func TestUninstallProtocolKeepsLegacyEncodingAndRejectsMixedReferences(t *testing.T) {
	x := newUninstallFixture(t, "native")
	old := x.source
	if old.identityDigest() != old.Spec.digest() {
		t.Fatal("legacy digest changed")
	}
	if err := x.request.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Request){func(r *Request) { r.Uninstall = nil }, func(r *Request) { r.Spec.Action = "" }, func(r *Request) {
		r.Reinstall = &ReinstallReference{"other", strings.Repeat("2", 64), strings.Repeat("3", 64)}
	}, func(r *Request) { q := *r.Uninstall; q.RestorationJob = "previous"; r.Uninstall = &q }} {
		r := x.request
		mutate(&r)
		if r.Validate() == nil {
			t.Fatal("invalid action accepted")
		}
	}
	e := RestorationEvidence{NoEffects: true, IntentSHA256: strings.Repeat("1", 64), ActiveSHA256: strings.Repeat("2", 64), ObjectSHA256: strings.Repeat("3", 64), PreservedSHA256: strings.Repeat("4", 64)}
	if !e.Valid() {
		t.Fatal("valid no effects rejected")
	}
	e.CaptureSHA256 = strings.Repeat("5", 64)
	if e.Valid() {
		t.Fatal("no effects accepted capture")
	}
}
