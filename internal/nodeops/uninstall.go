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

// Uninstall is a separate fixed lifecycle. It never prepares a newer runtime,
// changes monitoring rules or replaces the live database/identity directory.
type uninstallLifecycle struct {
	runtime *LocalRuntime
	backup  *transitionBackup
	host    installationHost
}

func withUninstall(base Handler) *uninstallLifecycle {
	q := withRecovery(base)
	if q.backup != nil {
		q.host.data = q.backup.data
		q.host.logs = q.backup.logs
	}
	return &uninstallLifecycle{q.runtime, q.backup, q.host}
}
func (*uninstallLifecycle) Supports(phase string) bool { return phaseIndex(phase) >= 0 }
func (u *uninstallLifecycle) valid(r Request) bool {
	return r.Validate() == nil && r.Uninstall != nil && r.Recovery == nil && u.runtime != nil && u.backup != nil && u.runtime.root == u.host.root && u.backup.root == u.runtime.root && u.backup.unit == u.host.unitPath
}
func (u *uninstallLifecycle) directory(r Request) string {
	return filepath.Join(u.backup.directory(r), "uninstall")
}
func (u *uninstallLifecycle) applyRequest(r Request) Request { r.Operation = "apply"; return r }
func uninstallOutcome(phase string) Outcome {
	return Outcome{Checks: []Check{{ID: "uninstall-" + phase, Status: "passed", Code: "local-phase-verified"}}}
}

func (u *uninstallLifecycle) operation(r Request, use func(context.Context, Request) (Outcome, error)) (Outcome, error) {
	if !u.valid(r) {
		return Outcome{}, Failure{"executor-unavailable"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ctx, release, err := acquireServiceOperation(ctx, u.runtime.root)
	if err != nil {
		return Outcome{}, Failure{"remote-state-unknown"}
	}
	defer release()
	return use(ctx, u.applyRequest(r))
}
func (u *uninstallLifecycle) Apply(r Request) (Outcome, error) {
	if r.Operation != "apply" {
		return Outcome{}, Failure{"executor-unavailable"}
	}
	return u.operation(r, func(ctx context.Context, r Request) (Outcome, error) {
		var err error
		switch r.Phase {
		case "preflight":
			_, _, err = u.source(ctx, r)
			if err == nil {
				err = u.recoveryMaterials(ctx, r)
			}
		case "stage":
			_, _, err = u.source(ctx, r)
			if err == nil {
				err = u.recoveryMaterials(ctx, r)
			}
			if err == nil {
				err = u.publishPrepared(r)
			}
		case "backup":
			b := *u.backup
			b.host = uninstallQuiescer{u, r}
			if err = b.beginAttempt(r); err == nil {
				_, err = b.run(ctx, r)
			}
		case "activate":
			err = u.remove(ctx, r)
		case "verify":
			err = u.verifyRemoval(ctx, r, false)
		case "finalize":
			err = u.finalizeRemoval(ctx, r)
		case "restore":
			err = u.restore(ctx, r)
		case "verify-rollback":
			err = u.sealRestoration(ctx, r)
		default:
			return Outcome{}, Failure{"executor-unavailable"}
		}
		if err != nil {
			u.recordDiagnostic(r, err)
			return Outcome{}, Failure{nativePhaseFailure(r.Phase)}
		}
		return uninstallOutcome(r.Phase), nil
	})
}
func (u *uninstallLifecycle) Reconcile(r Request) (string, Outcome, error) {
	state := "absent"
	out, err := u.operation(r, func(ctx context.Context, r Request) (Outcome, error) {
		switch r.Phase {
		case "preflight":
			return Outcome{}, nil
		case "stage":
			path := filepath.Join(u.directory(r), "prepared.json")
			if _, e := os.Lstat(path); os.IsNotExist(e) {
				return Outcome{}, nil
			}
			if e := u.verifyPrepared(ctx, r); e != nil {
				return Outcome{}, e
			}
		case "backup":
			if _, e := os.Lstat(filepath.Join(u.backup.directory(r), "capture")); os.IsNotExist(e) {
				return Outcome{}, nil
			}
			if _, e := u.backup.readIntent(ctx, r); e != nil {
				return Outcome{}, e
			}
			if _, e := os.Lstat(filepath.Join(u.backup.directory(r), "snapshot")); os.IsNotExist(e) {
				return Outcome{}, nil
			}
			if _, e := u.backup.verify(ctx, r); e != nil {
				return Outcome{}, e
			}
		case "activate", "verify", "finalize":
			if _, e := os.Lstat(filepath.Join(u.directory(r), "intent.json")); os.IsNotExist(e) {
				return Outcome{}, nil
			}
			complete, e := u.removalState(ctx, r)
			if e != nil {
				return Outcome{}, e
			}
			if !complete {
				return Outcome{}, nil
			}
			if r.Phase == "finalize" {
				published, e := u.tombstonePublished(ctx, r)
				if e != nil {
					return Outcome{}, e
				}
				if !published {
					return Outcome{}, nil
				}
			}
		case "restore":
			if e := u.verifyRestoration(ctx, r, false); e != nil {
				if e = u.restorationResumable(ctx, r); e != nil {
					return Outcome{}, e
				}
				return Outcome{}, nil
			}
		case "verify-rollback":
			if e := u.verifyRestoration(ctx, r, true); e != nil {
				if _, e := os.Lstat(filepath.Join(u.directory(r), "restoration-final.json")); os.IsNotExist(e) {
					return Outcome{}, nil
				}
				return Outcome{}, e
			}
		default:
			return Outcome{}, errors.New("unsupported-uninstall-phase")
		}
		state = "complete"
		return uninstallOutcome(r.Phase), nil
	})
	if err != nil {
		return "unknown", out, Failure{nativePhaseFailure(r.Phase)}
	}
	return state, out, nil
}
func (u *uninstallLifecycle) VerifyCompleted(r Request, _ Outcome) error {
	_, err := u.operation(r, func(ctx context.Context, r Request) (Outcome, error) {
		var err error
		switch r.Phase {
		case "preflight", "stage":
			err = u.verifyPreparedSource(ctx, r)
		case "backup":
			_, err = u.backup.verify(ctx, r)
		case "activate", "verify":
			err = u.verifyRemoval(ctx, r, false)
		case "finalize":
			err = u.verifyRemoval(ctx, r, true)
		case "restore":
			err = u.verifyRestoration(ctx, r, false)
		case "verify-rollback":
			err = u.verifyRestoration(ctx, r, true)
		}
		return Outcome{}, err
	})
	return err
}
func (u *uninstallLifecycle) publishPrepared(r Request) error {
	dir := u.directory(r)
	if err := ensurePrivateDirectory(dir); err != nil {
		return err
	}
	raw, _ := json.Marshal(struct {
		Format  int
		Binding transitionBinding
	}{1, binding(r)})
	return replacePrivateFile(filepath.Join(dir, "prepared.json"), raw, nil)
}
func (u *uninstallLifecycle) verifyPrepared(ctx context.Context, r Request) error {
	raw, err := readPrivate(filepath.Join(u.directory(r), "prepared.json"), 4096)
	want, _ := json.Marshal(struct {
		Format  int
		Binding transitionBinding
	}{1, binding(r)})
	if err != nil || !bytes.Equal(raw, want) {
		return errors.New("uninstall-stage-not-proven")
	}
	return u.verifyPreparedSource(ctx, r)
}
func (u *uninstallLifecycle) verifyPreparedSource(ctx context.Context, r Request) error {
	if _, _, err := u.source(ctx, r); err != nil {
		return err
	}
	return u.recoveryMaterials(ctx, r)
}

type uninstallQuiescer struct {
	u *uninstallLifecycle
	r Request
}

func (q uninstallQuiescer) inventory(ctx context.Context, node, mode string) (Installation, error) {
	if node != q.r.Node || mode != q.r.Spec.Mode {
		return Installation{}, errors.New("uninstall-target-mismatch")
	}
	if _, _, err := q.u.source(ctx, q.r); err != nil {
		return Installation{}, err
	}
	i, err := q.u.host.inventory(ctx, node, mode)
	if err != nil {
		return i, err
	}
	if i.Generation != "v3" || i.Mode != mode || hasLegacyMembers(i) || len(i.Services) != 1 {
		return i, errors.New("uninstall-original-not-supported")
	}
	raw, err := readPrivate(filepath.Join(q.u.runtime.root, "active.json"), MaxRequestBytes)
	if err != nil || sha(raw) != q.r.Uninstall.ActiveSHA256 {
		return i, errors.New("uninstall-active-changed")
	}
	return i, nil
}
func (q uninstallQuiescer) stop(ctx context.Context, i Installation) error {
	return q.u.host.stop(ctx, i)
}
func (q uninstallQuiescer) stopped(ctx context.Context, i Installation) (bool, error) {
	return q.u.host.stopped(ctx, i)
}
