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

// nativeLifecycle composes fixed service phases with the durable Journal.
// CommandLifecycle selects this driver; the preparation command retains its
// LocalRuntime boundary. Node-local finalization is not applied_version, and
// unsupported old installations fail before any service is stopped.
type nativeLifecycle struct {
	runtime    *LocalRuntime
	activation *nativeActivation
	resources  nativeResources
	preflight  Handler
}

func newNativeLifecycle() *nativeLifecycle {
	w := NewLocalRuntime()
	return &nativeLifecycle{runtime: w, activation: newNativeActivation(w), resources: nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}, preflight: LocalPreflight{}}
}

func (*nativeLifecycle) Supports(phase string) bool { return phaseIndex(phase) >= 0 }

func (n *nativeLifecycle) valid(r Request) bool {
	return r.Validate() == nil && r.Recovery == nil && r.Uninstall == nil && r.Spec.Mode == "native" && r.Spec.configurationValid() && n.runtime != nil && n.activation != nil && n.activation.backup != nil && n.activation.runtime == n.runtime && n.preflight != nil
}

func (n *nativeLifecycle) Apply(r Request) (Outcome, error) {
	n = n.forRequest(r)
	if !n.valid(r) || r.Operation != "apply" {
		return Outcome{}, Failure{"executor-unavailable"}
	}
	if r.Phase == "preflight" {
		out, err := n.preflight.Apply(r)
		if err != nil {
			return out, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ctx, release, err := acquireServiceOperation(ctx, n.runtime.root)
		if err == nil {
			defer release()
			err = n.originalNative(ctx, r)
		}
		if err != nil {
			out.Checks = append(out.Checks, Check{ID: "native-original", Status: "failed", Code: "original-installation-not-supported"})
			return out, Failure{"preflight-failed"}
		}
		out.Checks = append(out.Checks, Check{ID: "native-original", Status: "passed", Code: "original-installation-verified"})
		return out, nil
	}
	if r.Phase == "stage" {
		return n.runtime.Apply(r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ctx, release, err := acquireServiceOperation(ctx, n.runtime.root)
	if err != nil {
		return Outcome{}, Failure{"remote-state-unknown"}
	}
	defer release()
	switch r.Phase {
	case "backup":
		if err = n.runtime.verifyConfiguration(ctx, r); err != nil {
			break
		}
		// Prove the whole supported original before stopping any service. Known
		// wrappers use the grouped coordinator; unknown/mixed writers still fail.
		if err = n.activation.backup.beginAttempt(r); err == nil {
			err = n.originalNative(ctx, r)
		}
		if err == nil {
			_, err = n.activation.backup.run(ctx, r)
		}
	case "activate":
		err = n.activation.run(ctx, r)
	case "verify":
		return n.localVerification(ctx, r)
	case "finalize":
		err = n.finalize(ctx, r)
	case "restore":
		var untouched bool
		untouched, err = n.activation.backup.restoreUncaptured(r, true)
		if err == nil && !untouched {
			err = n.activation.restore(ctx, r)
		}
	case "verify-rollback":
		err = n.verifyRollback(ctx, r)
	default:
		return Outcome{}, Failure{"executor-unavailable"}
	}
	if err != nil {
		return Outcome{}, Failure{nativePhaseFailure(r.Phase)}
	}
	return nativePhaseOutcome(r.Phase), nil
}

func nativePhaseFailure(phase string) string {
	switch phase {
	case "backup":
		return "backup-failed"
	case "activate":
		return "activation-failed"
	case "verify", "finalize", "verify-rollback":
		return "verification-failed"
	default:
		return "remote-state-unknown"
	}
}
func nativePhaseOutcome(phase string) Outcome {
	return Outcome{Checks: []Check{{ID: "native-" + phase, Status: "passed", Code: "local-phase-verified"}}}
}

func (n *nativeLifecycle) originalNative(ctx context.Context, r Request) error {
	var installed Installation
	if _, err := os.Lstat(filepath.Join(n.activation.backup.directory(r), "capture")); err == nil {
		i, err := n.activation.backup.readIntent(ctx, r)
		if err != nil {
			return err
		}
		installed, err = n.activation.backup.transitionAgent(i)
		if err != nil {
			return err
		}
	} else if os.IsNotExist(err) {
		observation, err := n.activation.host.observeOriginal(ctx, r)
		installed = observation.agent
		if err == nil && observation.grouped && r.Phase == "backup" {
			n.activation.backup.attachGroup(n.activation.host, r)
		}
		if err != nil {
			return err
		}
	} else {
		return err
	}
	if !supportedNativeOriginal(installed) {
		return errors.New("unsupported-original-deployment")
	}
	return nil
}

func (n *nativeLifecycle) localVerification(ctx context.Context, r Request) (Outcome, error) {
	r.Phase = "verify"
	r.Operation = "apply"
	out, err := n.activation.verifyNativeWithResources(ctx, r, n.resources)
	if err != nil {
		return Outcome{}, Failure{"verification-failed"}
	}
	return out, nil
}

type nativeFinalReceipt struct {
	Format           int               `json:"format"`
	Binding          transitionBinding `json:"binding"`
	ActivationSHA256 string            `json:"activation_sha256"`
}

func (n *nativeLifecycle) finalReceipt(ctx context.Context, r Request) ([]byte, error) {
	if _, err := n.localVerification(ctx, r); err != nil {
		return nil, err
	}
	raw, err := readPrivate(n.activation.intentPath(r), MaxRequestBytes)
	if err != nil {
		return nil, err
	}
	return json.Marshal(nativeFinalReceipt{1, binding(r), sha(raw)})
}
func (n *nativeLifecycle) finalize(ctx context.Context, r Request) error {
	raw, err := n.finalReceipt(ctx, r)
	if err != nil {
		return err
	}
	return replacePrivateFile(filepath.Join(n.activation.backup.directory(r), "finalized.json"), raw, nil)
}
func (n *nativeLifecycle) verifyFinalized(ctx context.Context, r Request) error {
	want, err := n.finalReceipt(ctx, r)
	if err != nil {
		return err
	}
	raw, err := readPrivate(filepath.Join(n.activation.backup.directory(r), "finalized.json"), 4096)
	if err != nil || !bytes.Equal(raw, want) {
		return errors.New("native-finalization-not-proven")
	}
	return nil
}
func (n *nativeLifecycle) verifyRollback(ctx context.Context, r Request) error {
	r.Phase = "restore"
	r.Operation = "apply"
	if untouched, err := n.activation.backup.restoreUncaptured(r, false); err != nil || untouched {
		return err
	}
	if handled, err := n.activation.backup.verifyGroupBeforeTarget(ctx, r); err != nil || handled {
		return err
	}
	p, err := n.activation.restorePlan(ctx, r)
	if err != nil {
		return err
	}
	raw, err := readPrivate(filepath.Join(n.activation.restoreDirectory(r), "intent.json"), 4096)
	want, marshalErr := json.Marshal(p.intent)
	if err != nil || marshalErr != nil || !bytes.Equal(raw, want) {
		return errors.New("restoration-intent-not-proven")
	}
	var exported nativeRestoreExport
	if _, err := decodePrivateJSON(filepath.Join(n.activation.restoreDirectory(r), "export.json"), &exported, 4096); err != nil || exported.Format != 1 || exported.Binding != binding(r) || exported.RestoreSHA256 != sha(raw) || exported.Count < 0 {
		return errors.New("restoration-export-not-proven")
	}
	databaseExpected, _, err := n.activation.backup.recoveryBase(ctx, r)
	if err != nil {
		return err
	}
	if err := privateFile(filepath.Join(n.activation.backup.data, "agent.sqlite3"), !databaseExpected); err != nil {
		return err
	}
	return n.activation.confirmRestored(ctx, p)
}

// An absent phase may have known partial effects, but only after its old client
// is proved finished and the saved intent/current ownership prove safe replay.
// It must not be confused with "no files were changed". No service mutation is
// performed during reconciliation.
func (n *nativeLifecycle) Reconcile(r Request) (string, Outcome, error) {
	n = n.forRequest(r)
	if !n.valid(r) {
		return "unknown", Outcome{}, Failure{"executor-unavailable"}
	}
	if r.Phase == "preflight" {
		return n.preflight.Reconcile(r)
	}
	if r.Phase == "stage" {
		return n.runtime.Reconcile(r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx, release, err := acquireServiceOperation(ctx, n.runtime.root)
	if err != nil {
		return "unknown", Outcome{}, Failure{"remote-state-unknown"}
	}
	defer release()
	request := r
	request.Operation = "apply"
	complete := false
	switch r.Phase {
	case "backup":
		err = n.reconcileBackup(ctx, request)
		if err == nil {
			if _, exists := os.Lstat(filepath.Join(n.activation.backup.directory(r), "snapshot")); exists == nil {
				_, err = n.activation.backup.verify(ctx, request)
				if err == nil {
					var original backupIntent
					original, err = n.activation.backup.readIntent(ctx, request)
					if err == nil {
						complete, err = n.activation.backup.host.stopped(ctx, original.Installed)
					}
				}
			} else if !os.IsNotExist(exists) {
				err = exists
			}
		}
	case "activate":
		var p nativeActivationPlan
		p, err = n.activationPlan(ctx, request, false)
		if err == nil {
			_, complete, err = n.activation.state(ctx, p)
			if complete {
				err = n.activation.confirm(ctx, p)
			}
		}
	case "verify":
		// A failed read-only verification has no unfinished mutation.
		out, e := n.localVerification(ctx, request)
		if e == nil {
			return "complete", out, nil
		}
		return "absent", Outcome{}, nil
	case "finalize":
		if _, e := os.Lstat(filepath.Join(n.activation.backup.directory(r), "finalized.json")); os.IsNotExist(e) {
			return "absent", Outcome{}, nil
		} else if e != nil {
			err = e
		} else {
			err = n.verifyFinalized(ctx, request)
			complete = err == nil
		}
	case "restore":
		if untouched, _, e := n.activation.backup.uncaptured(request); e == nil && untouched {
			if n.verifyRollback(ctx, request) == nil {
				return "complete", nativePhaseOutcome(r.Phase), nil
			}
			// Only a missing receipt is safe to publish on replay. A present
			// but unverifiable receipt is corruption, not an absent operation.
			if _, e := os.Lstat(filepath.Join(n.activation.restoreDirectory(r), "no-effects.json")); os.IsNotExist(e) {
				return "absent", Outcome{}, nil
			}
			return "unknown", Outcome{}, Failure{"remote-state-unknown"}
		}
		if handled, done, e := n.activation.backup.reconcileGroupBeforeTarget(ctx, request); e != nil {
			return "unknown", Outcome{}, Failure{"remote-state-unknown"}
		} else if handled {
			if done {
				return "complete", nativePhaseOutcome(r.Phase), nil
			}
			return "absent", Outcome{}, nil
		}
		var p nativeRestorePlan
		p, err = n.activation.restorePlan(ctx, request)
		if err == nil {
			if e := n.verifyRollback(ctx, request); e == nil {
				complete = true
			} else {
				_, _, _, err = n.activation.restoreState(ctx, p)
			}
		}
	case "verify-rollback":
		if e := n.verifyRollback(ctx, request); e == nil {
			complete = true
		} else {
			return "absent", Outcome{}, nil
		}
	default:
		err = errors.New("unknown-native-phase")
	}
	if err != nil {
		return "unknown", Outcome{}, Failure{"remote-state-unknown"}
	}
	if complete {
		return "complete", nativePhaseOutcome(r.Phase), nil
	}
	return "absent", Outcome{}, nil
}

func (n *nativeLifecycle) reconcileBackup(ctx context.Context, r Request) error {
	if _, err := os.Lstat(filepath.Join(n.activation.backup.directory(r), "capture")); os.IsNotExist(err) {
		untouched, _, err := n.activation.backup.uncaptured(r)
		if err != nil {
			return err
		}
		if untouched {
			return nil
		}
		return errors.New("capture-state-not-proven")
	} else if err != nil {
		return err
	}
	if err := n.originalNative(ctx, r); err != nil {
		return err
	}
	i, err := n.activation.backup.readIntent(ctx, r)
	if err != nil {
		return err
	}
	if g, err := n.activation.backup.targetGroup(i); err != nil {
		return err
	} else if g != nil {
		if err := g.inspect(ctx, i.Installed, true); err != nil {
			return err
		}
	}
	if err := n.activation.backup.unchanged(ctx, i); err != nil {
		return err
	}
	for _, s := range i.Installed.Services {
		if s.Kind == "native" {
			if _, err := n.activation.host.native(ctx, s); err != nil {
				return err
			}
		} else {
			c, err := n.activation.host.ownedContainer(ctx, s)
			if err != nil {
				return err
			}
			if c.Name != "/"+s.Name {
				return errors.New("unrecorded-original-rename")
			}
		}
	}
	return nil
}

func (n *nativeLifecycle) VerifyCompleted(r Request, out Outcome) error {
	n = n.forRequest(r)
	if !n.valid(r) {
		return Failure{"executor-unavailable"}
	}
	if r.Phase == "preflight" {
		return nil
	}
	if r.Phase == "stage" {
		return n.runtime.VerifyCompleted(r, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx, release, err := acquireServiceOperation(ctx, n.runtime.root)
	if err != nil {
		return Failure{"remote-state-unknown"}
	}
	defer release()
	r.Operation = "apply"
	switch r.Phase {
	case "backup":
		_, err = n.activation.backup.verify(ctx, r)
	case "activate":
		var p nativeActivationPlan
		p, err = n.activationPlan(ctx, r, true)
		if err == nil {
			err = n.activation.confirm(ctx, p)
		}
	case "verify":
		_, err = n.localVerification(ctx, r)
	case "finalize":
		err = n.verifyFinalized(ctx, r)
	case "restore", "verify-rollback":
		err = n.verifyRollback(ctx, r)
	default:
		err = errors.New("unknown-native-phase")
	}
	if err != nil {
		return Failure{nativePhaseFailure(r.Phase)}
	}
	return nil
}

func (n *nativeLifecycle) activationPlan(ctx context.Context, r Request, required bool) (nativeActivationPlan, error) {
	p, err := n.activation.plan(ctx, r)
	if err != nil {
		return p, err
	}
	raw, err := readPrivate(n.activation.intentPath(r), MaxRequestBytes)
	if os.IsNotExist(err) && !required {
		if err := n.activation.backup.unchanged(ctx, p.original); err != nil {
			return p, err
		}
		if _, err := n.activation.host.nativeOriginalDocker(ctx, p.agent, ""); err != nil {
			return p, err
		}
		// Without an intent, only the captured original files are legitimate;
		// recognizing target hashes would wrongly adopt an unrecorded writer.
		for _, file := range []struct {
			path     string
			expected []byte
		}{{n.activation.host.unitPath, p.previousUnit}, {filepath.Join(n.runtime.root, "active.json"), p.previousPointer}} {
			got, e := readPrivate(file.path, MaxRequestBytes)
			if file.expected == nil && os.IsNotExist(e) {
				continue
			}
			if e != nil || file.expected == nil || !bytes.Equal(got, file.expected) {
				return p, errors.New("unrecorded-activation-effects")
			}
		}
		return p, nil
	}
	want, marshalErr := json.Marshal(p.intent)
	if err != nil || marshalErr != nil || !bytes.Equal(raw, want) {
		return p, errors.New("activation-intent-not-proven")
	}
	return p, nil
}
