package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// CommandLifecycle's Docker driver. The default preparation command still
// uses LocalRuntime, which cannot activate or restore installations.
type dockerLifecycle struct {
	runtime    *LocalRuntime
	activation *dockerActivation
	resources  nativeResources
	preflight  Handler
	stage      Handler
}

func newDockerLifecycle() *dockerLifecycle {
	w := NewLocalRuntime()
	return &dockerLifecycle{runtime: w, activation: newDockerActivation(w), resources: nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}, preflight: LocalPreflight{}, stage: w}
}
func (*dockerLifecycle) Supports(phase string) bool { return phaseIndex(phase) >= 0 }
func (d *dockerLifecycle) valid(r Request) bool {
	return r.Validate() == nil && r.Recovery == nil && r.Uninstall == nil && r.Spec.Mode == "docker" && r.Spec.configurationValid() && d.runtime != nil && d.activation != nil && d.activation.runtime == d.runtime && d.activation.backup != nil && d.preflight != nil && d.stage != nil
}
func dockerPhaseOutcome(phase string) Outcome {
	return Outcome{Checks: []Check{{ID: "docker-" + phase, Status: "passed", Code: "local-phase-verified"}}}
}
func (d *dockerLifecycle) Apply(r Request) (Outcome, error) {
	d = d.forRequest(r)
	if !d.valid(r) || r.Operation != "apply" {
		return Outcome{}, Failure{"executor-unavailable"}
	}
	if r.Phase == "stage" {
		return d.stage.Apply(r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ctx, release, err := acquireServiceOperation(ctx, d.runtime.root)
	if err != nil {
		return Outcome{}, Failure{"remote-state-unknown"}
	}
	defer release()
	switch r.Phase {
	case "preflight":
		out, e := d.preflight.Apply(r)
		if e != nil {
			return out, e
		}
		if err = d.originalDocker(ctx, r); err != nil {
			out.Checks = append(out.Checks, Check{ID: "docker-original", Status: "failed", Code: "original-installation-not-supported"})
			return out, Failure{"preflight-failed"}
		}
		out.Checks = append(out.Checks, Check{ID: "docker-original", Status: "passed", Code: "original-installation-verified"})
		return out, nil
	case "backup":
		if err = d.runtime.verifyConfiguration(ctx, r); err != nil {
			break
		}
		if err = d.activation.backup.beginAttempt(r); err == nil {
			err = d.originalDocker(ctx, r)
		}
		if err == nil {
			_, err = d.activation.backup.run(ctx, r)
		}
	case "activate":
		err = d.activation.run(ctx, r)
	case "verify":
		return d.localVerification(ctx, r)
	case "finalize":
		err = d.finalize(ctx, r)
	case "restore":
		var untouched bool
		untouched, err = d.restoreUncaptured(ctx, r, true)
		if err == nil && !untouched {
			err = d.activation.restore(ctx, r)
		}
	case "verify-rollback":
		err = d.verifyRollback(ctx, r)
	default:
		return Outcome{}, Failure{"executor-unavailable"}
	}
	if err != nil {
		return Outcome{}, Failure{nativePhaseFailure(r.Phase)}
	}
	return dockerPhaseOutcome(r.Phase), nil
}
func (d *dockerLifecycle) originalDocker(ctx context.Context, r Request) error {
	var installed Installation
	if _, err := os.Lstat(filepath.Join(d.activation.backup.directory(r), "capture")); err == nil {
		i, e := d.activation.backup.readIntent(ctx, r)
		if e != nil {
			return e
		}
		installed, e = d.activation.backup.transitionAgent(i)
		if e != nil {
			return e
		}
	} else if os.IsNotExist(err) {
		observation, e := d.activation.host.observeOriginal(ctx, r)
		installed = observation.agent
		if e == nil && observation.grouped && r.Phase == "backup" {
			d.activation.backup.attachGroup(d.activation.host, r)
		}
		if e != nil {
			return e
		}
	} else {
		return err
	}
	if !supportedDockerOriginal(installed) {
		return errors.New("unsupported-original-deployment")
	}
	return nil
}
func (d *dockerLifecycle) activationPlan(ctx context.Context, r Request, required bool) (dockerActivationPlan, error) {
	r.Phase, r.Operation = "activate", "apply"
	p, err := d.activation.plan(ctx, r)
	if err != nil {
		return p, err
	}
	raw, err := readPrivate(d.activation.intentPath(r), MaxRequestBytes)
	if os.IsNotExist(err) && !required {
		if err := d.activation.backup.unchanged(ctx, p.original); err != nil {
			return p, err
		}
		if _, err := os.Lstat(d.activation.createdPath(r)); !os.IsNotExist(err) {
			return p, errors.New("created-receipt-without-activation")
		}
		c, e := d.activation.host.taskContainer(ctx, p.intent.Target)
		if e != nil {
			return p, e
		}
		if c != nil {
			return p, errors.New("unrecorded-task-container")
		}
		for _, s := range p.original.Installed.Services {
			if s.Kind != "docker" {
				continue
			}
			c, e := d.activation.host.ownedContainer(ctx, s)
			if e != nil {
				return p, e
			}
			if c.Name != "/"+s.Name {
				return p, errors.New("unrecorded-container-rename")
			}
		}
		return p, nil
	}
	want, e := json.Marshal(p.intent)
	if err != nil || e != nil || !bytes.Equal(raw, want) {
		return p, errors.New("activation-intent-not-proven")
	}
	return p, nil
}
func (d *dockerLifecycle) localVerification(ctx context.Context, r Request) (Outcome, error) {
	p, err := d.activationPlan(ctx, r, true)
	if err == nil {
		err = d.activation.confirm(ctx, r, p)
	}
	if err != nil {
		return Outcome{}, Failure{"verification-failed"}
	}
	c, err := d.activation.target(ctx, r, p)
	if err != nil || c == nil {
		return Outcome{}, Failure{"verification-failed"}
	}
	proof, err := d.resources.inspectDocker(ctx, d.activation.host, c.ID, p.intent.Target, p.material.Settings.Resources)
	if err == nil {
		err = d.activation.confirm(ctx, r, p)
	}
	if err != nil {
		return Outcome{}, Failure{"verification-failed"}
	}
	return Outcome{Checks: append([]Check{{ID: "docker-service", Status: "passed", Code: "running-service-verified"}}, proof.Kernel.checks()...)}, nil
}

type dockerFinalReceipt struct {
	Format           int               `json:"format"`
	Binding          transitionBinding `json:"binding"`
	ActivationSHA256 string            `json:"activation_sha256"`
	CreatedSHA256    string            `json:"created_sha256"`
}

func (d *dockerLifecycle) finalReceipt(ctx context.Context, r Request) ([]byte, error) {
	if _, err := d.localVerification(ctx, r); err != nil {
		return nil, err
	}
	raw, err := readPrivate(d.activation.intentPath(r), MaxRequestBytes)
	if err != nil {
		return nil, err
	}
	created, err := readPrivate(d.activation.createdPath(r), 4096)
	if err != nil {
		return nil, err
	}
	return json.Marshal(dockerFinalReceipt{1, binding(r), sha(raw), sha(created)})
}
func (d *dockerLifecycle) finalize(ctx context.Context, r Request) error {
	raw, err := d.finalReceipt(ctx, r)
	if err != nil {
		return err
	}
	return replacePrivateFile(filepath.Join(d.activation.backup.directory(r), "finalized.json"), raw, nil)
}
func (d *dockerLifecycle) verifyFinalized(ctx context.Context, r Request) error {
	want, err := d.finalReceipt(ctx, r)
	if err != nil {
		return err
	}
	raw, err := readPrivate(filepath.Join(d.activation.backup.directory(r), "finalized.json"), 4096)
	if err != nil || !bytes.Equal(raw, want) {
		return errors.New("docker-finalization-not-proven")
	}
	return nil
}
func (d *dockerLifecycle) restoreUncaptured(ctx context.Context, r Request, write bool) (bool, error) {
	untouched, _, err := d.activation.backup.uncaptured(r)
	if err != nil {
		return false, err
	}
	if !untouched {
		return d.activation.backup.restoreUncaptured(r, write)
	}
	c, err := d.activation.host.taskContainer(ctx, ActiveInstallation{Node: r.Node, Job: r.Job, PlanDigest: r.PlanDigest})
	if err != nil {
		return false, err
	}
	if c != nil {
		return false, errors.New("unrecorded-task-container")
	}
	return d.activation.backup.restoreUncaptured(r, write)
}

// Missing receipts can be replayed; a present corrupt receipt cannot be treated
// as an absent operation, even if the daemon currently looks quiescent.
func (d *dockerLifecycle) restorationProof(r Request, p dockerRestorePlan, required bool) error {
	raw, err := json.Marshal(p.intent)
	if err != nil {
		return err
	}
	got, err := readPrivate(filepath.Join(d.activation.restoreDirectory(r), "intent.json"), 4096)
	if os.IsNotExist(err) && !required {
		if _, err := os.Lstat(filepath.Join(d.activation.restoreDirectory(r), "export.json")); os.IsNotExist(err) {
			return nil
		}
		return errors.New("restoration-export-without-intent")
	}
	if err != nil || !bytes.Equal(got, raw) {
		return errors.New("restoration-intent-not-proven")
	}
	var receipt nativeRestoreExport
	_, err = decodePrivateJSON(filepath.Join(d.activation.restoreDirectory(r), "export.json"), &receipt, 4096)
	if os.IsNotExist(err) && !required {
		return nil
	}
	if err != nil || receipt.Format != 1 || receipt.Binding != binding(r) || receipt.RestoreSHA256 != sha(raw) || receipt.Count < 0 {
		return errors.New("restoration-export-not-proven")
	}
	return nil
}
func (d *dockerLifecycle) verifyRollback(ctx context.Context, r Request) error {
	r.Phase, r.Operation = "restore", "apply"
	if untouched, err := d.restoreUncaptured(ctx, r, false); err != nil || untouched {
		return err
	}
	if handled, err := d.activation.backup.verifyGroupBeforeTarget(ctx, r); err != nil || handled {
		return err
	}
	p, err := d.activation.restorePlan(ctx, r)
	if err != nil {
		return err
	}
	if err := d.restorationProof(r, p, true); err != nil {
		return err
	}
	expected, _, err := d.activation.backup.recoveryBase(ctx, r)
	if err != nil {
		return err
	}
	if err := privateFile(filepath.Join(d.activation.backup.data, "agent.sqlite3"), !expected); err != nil {
		return err
	}
	return d.activation.confirmRestored(ctx, r, p)
}
func (d *dockerLifecycle) reconcileBackup(ctx context.Context, r Request) (bool, error) {
	if _, err := os.Lstat(filepath.Join(d.activation.backup.directory(r), "capture")); os.IsNotExist(err) {
		untouched, _, e := d.activation.backup.uncaptured(r)
		if e != nil {
			return false, e
		}
		if !untouched {
			return false, errors.New("capture-state-not-proven")
		}
		c, e := d.activation.host.taskContainer(ctx, ActiveInstallation{Node: r.Node, Job: r.Job, PlanDigest: r.PlanDigest})
		if e != nil {
			return false, e
		}
		if c != nil {
			return false, errors.New("unrecorded-task-container")
		}
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := d.originalDocker(ctx, r); err != nil {
		return false, err
	}
	i, err := d.activation.backup.readIntent(ctx, r)
	if err != nil {
		return false, err
	}
	if g, err := d.activation.backup.targetGroup(i); err != nil {
		return false, err
	} else if g != nil {
		if err := g.inspect(ctx, i.Installed, true); err != nil {
			return false, err
		}
	}
	if err := d.activation.backup.unchanged(ctx, i); err != nil {
		return false, err
	}
	// Backup has not authorized any target writer or task object yet.
	// Do not replay quiesce while ignoring a separately created task container.
	c, err := d.activation.host.taskContainer(ctx, ActiveInstallation{Node: r.Node, Job: r.Job, PlanDigest: r.PlanDigest})
	if err != nil {
		return false, err
	}
	if c != nil {
		return false, errors.New("unrecorded-task-container")
	}
	for _, s := range i.Installed.Services {
		if s.Kind == "native" {
			if _, e := d.activation.host.native(ctx, s); e != nil {
				return false, e
			}
			continue
		}
		c, e := d.activation.host.ownedContainer(ctx, s)
		if e != nil {
			return false, e
		}
		if c.Name != "/"+s.Name {
			return false, errors.New("original-container-name-changed")
		}
	}
	if _, err := os.Lstat(filepath.Join(d.activation.backup.directory(r), "snapshot")); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if _, err := d.activation.backup.verify(ctx, r); err != nil {
		return false, err
	}
	return d.activation.backup.host.stopped(ctx, i.Installed)
}
func (d *dockerLifecycle) Reconcile(r Request) (string, Outcome, error) {
	d = d.forRequest(r)
	if !d.valid(r) {
		return "unknown", Outcome{}, Failure{"executor-unavailable"}
	}
	if r.Phase == "preflight" {
		return d.preflight.Reconcile(r)
	}
	if r.Phase == "stage" {
		return d.stage.Reconcile(r)
	}
	// Reconciliation repeats authenticated offline-archive and configuration
	// verification. It needs the same bounded I/O budget as the original phase,
	// including slow hosts; a short RPC timeout must not imply policy drift.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ctx, release, err := acquireServiceOperation(ctx, d.runtime.root)
	if err != nil {
		return "unknown", Outcome{}, Failure{"remote-state-unknown"}
	}
	defer release()
	r.Operation = "apply"
	complete := false
	switch r.Phase {
	case "backup":
		complete, err = d.reconcileBackup(ctx, r)
	case "activate":
		var p dockerActivationPlan
		p, err = d.activationPlan(ctx, r, false)
		if err == nil {
			err = d.activation.originalStopped(ctx, r, p)
		}
		if err == nil {
			_, _, err = allowedEffectiveFile(filepath.Join(d.runtime.root, "active.json"), p.pointer, p.previousPointer)
		}
		if err == nil {
			var c *containerIdentity
			c, err = d.activation.target(ctx, r, p)
			if err == nil && c != nil && c.Status == "running" {
				err = d.activation.confirm(ctx, r, p)
				complete = err == nil
			}
		}
	case "verify":
		out, e := d.localVerification(ctx, r)
		if e == nil {
			return "complete", out, nil
		}
		return "absent", Outcome{}, nil
	case "finalize":
		if _, e := os.Lstat(filepath.Join(d.activation.backup.directory(r), "finalized.json")); os.IsNotExist(e) {
			return "absent", Outcome{}, nil
		} else if e != nil {
			err = e
		} else {
			err = d.verifyFinalized(ctx, r)
			complete = err == nil
		}
	case "restore":
		if untouched, _, e := d.activation.backup.uncaptured(r); e == nil && untouched {
			if e = d.verifyRollback(ctx, r); e == nil {
				return "complete", dockerPhaseOutcome(r.Phase), nil
			}
			if _, e := os.Lstat(filepath.Join(d.activation.restoreDirectory(r), "no-effects.json")); !os.IsNotExist(e) {
				return "unknown", Outcome{}, Failure{"remote-state-unknown"}
			}
			c, e := d.activation.host.taskContainer(ctx, ActiveInstallation{Node: r.Node, Job: r.Job, PlanDigest: r.PlanDigest})
			if e != nil || c != nil {
				return "unknown", Outcome{}, Failure{"remote-state-unknown"}
			}
			return "absent", Outcome{}, nil
		}
		if handled, done, e := d.activation.backup.reconcileGroupBeforeTarget(ctx, r); e != nil {
			return "unknown", Outcome{}, Failure{"remote-state-unknown"}
		} else if handled {
			if done {
				return "complete", dockerPhaseOutcome(r.Phase), nil
			}
			return "absent", Outcome{}, nil
		}
		var p dockerRestorePlan
		p, err = d.activation.restorePlan(ctx, r)
		if err == nil {
			err = d.restorationProof(r, p, false)
		}
		if err == nil {
			if d.verifyRollback(ctx, r) == nil {
				complete = true
			} else {
				_, _, err = d.activation.restorationState(ctx, r, p)
			}
		}
	case "verify-rollback":
		if d.verifyRollback(ctx, r) == nil {
			complete = true
		} else {
			return "absent", Outcome{}, nil
		}
	default:
		err = errors.New("unknown-docker-phase")
	}
	if err != nil {
		return "unknown", Outcome{}, Failure{"remote-state-unknown"}
	}
	if complete {
		return "complete", dockerPhaseOutcome(r.Phase), nil
	}
	return "absent", Outcome{}, nil
}
func (d *dockerLifecycle) VerifyCompleted(r Request, out Outcome) error {
	d = d.forRequest(r)
	if !d.valid(r) {
		return Failure{"executor-unavailable"}
	}
	if r.Phase == "preflight" {
		return nil
	}
	if r.Phase == "stage" {
		if v, ok := d.stage.(CompletedVerifier); ok {
			return v.VerifyCompleted(r, out)
		}
		return Failure{"artifact-invalid"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ctx, release, err := acquireServiceOperation(ctx, d.runtime.root)
	if err != nil {
		return Failure{"remote-state-unknown"}
	}
	defer release()
	r.Operation = "apply"
	switch r.Phase {
	case "backup":
		_, err = d.activation.backup.verify(ctx, r)
	case "activate":
		var p dockerActivationPlan
		p, err = d.activationPlan(ctx, r, true)
		if err == nil {
			err = d.activation.confirm(ctx, r, p)
		}
	case "verify":
		_, err = d.localVerification(ctx, r)
	case "finalize":
		err = d.verifyFinalized(ctx, r)
	case "restore", "verify-rollback":
		err = d.verifyRollback(ctx, r)
	default:
		err = errors.New("unknown-docker-phase")
	}
	if err != nil {
		return Failure{nativePhaseFailure(r.Phase)}
	}
	return nil
}
