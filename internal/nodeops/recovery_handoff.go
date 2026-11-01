package nodeops

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type recoveryAdopter interface {
	validateRecoveryAdoption(Request, string) error
	recoverySourceIdentity(Request) (string, error)
}

// This check runs before retiring the current job. Invalid evidence does not
// acquire authority or create a new job, even for inspect requests.
func (s *Journal) authorizeRecovery(tx *sql.Tx, r Request, current string) (bool, error) {
	q := r.Recovery
	guard, ok := s.handler.(recoveryAdopter)
	if !ok || q == nil || current != q.HeadJob {
		return false, nil
	}
	var plan, spec string
	var retired int
	if err := tx.QueryRow("SELECT digest,spec_digest,retired FROM jobs WHERE id=?", q.SourceJob).Scan(&plan, &spec, &retired); err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}
	sourceIdentity, err := guard.recoverySourceIdentity(r)
	if err != nil || plan != q.SourcePlanDigest || spec != sourceIdentity || retired != 1 {
		return false, nil
	}
	var complete, restoring, pending int
	if err := tx.QueryRow("SELECT count(*) FROM phases WHERE job=? AND phase='finalize' AND status='complete'", q.SourceJob).Scan(&complete); err != nil {
		return false, err
	}
	if err := tx.QueryRow("SELECT count(*) FROM phases WHERE job=? AND (phase IN ('restore','verify-rollback') OR status='running')", q.SourceJob).Scan(&restoring); err != nil {
		return false, err
	}
	if complete != 1 || restoring != 0 {
		return false, nil
	}
	if err := tx.QueryRow("SELECT digest,spec_digest,retired FROM jobs WHERE id=?", current).Scan(&plan, &spec, &retired); err != nil {
		return false, err
	}
	if plan != q.HeadPlanDigest || retired != 0 {
		return false, nil
	}
	if err := tx.QueryRow("SELECT count(*) FROM phases WHERE job=? AND phase='verify-rollback' AND status='complete'", current).Scan(&complete); err != nil {
		return false, err
	}
	if err := tx.QueryRow("SELECT count(*) FROM phases WHERE job=? AND status='running'", current).Scan(&pending); err != nil {
		return false, err
	}
	if complete != 1 || pending != 0 {
		return false, nil
	}
	return guard.validateRecoveryAdoption(r, spec) == nil, nil
}

type recoveryIntent struct {
	Format             int               `json:"format"`
	Binding            transitionBinding `json:"binding"`
	Spec               Spec              `json:"spec"`
	Reference          RecoveryReference `json:"reference"`
	HeadEvidenceSHA256 string            `json:"head_evidence_sha256"`
}

// The wrapper owns the new task. Only its bound restore phases are delegated
// to the original immutable capture; the original Journal job stays retired.
type recoveryLifecycle struct {
	base    Handler
	runtime *LocalRuntime
	backup  *transitionBackup
	host    installationHost
}

func withRecovery(base Handler) *recoveryLifecycle {
	q := &recoveryLifecycle{base: base}
	switch h := base.(type) {
	case *nativeLifecycle:
		q.runtime, q.backup, q.host = h.runtime, h.activation.backup, h.activation.host
	case *dockerLifecycle:
		q.runtime, q.backup, q.host = h.runtime, h.activation.backup, h.activation.host
	}
	return q
}

func (*recoveryLifecycle) Supports(phase string) bool {
	return phase == "restore" || phase == "verify-rollback"
}
func (q *recoveryLifecycle) valid(r Request) bool {
	return r.Validate() == nil && r.Recovery != nil && q.runtime != nil && q.backup != nil && q.host.root == q.runtime.root && q.backup.root == q.runtime.root && q.backup.unit == q.host.unitPath
}
func (q *recoveryLifecycle) path(r Request) string {
	return filepath.Join(q.runtime.root, "transitions", r.Job, "recovery", "intent.json")
}

func (q *recoveryLifecycle) intentParents(r Request) error {
	if err := privateDirectoryTree(q.runtime.root); err != nil {
		return err
	}
	for p := filepath.Dir(q.path(r)); ; p = filepath.Dir(p) {
		if _, err := os.Lstat(p); err == nil {
			return privateDirectoryTree(p)
		} else if !os.IsNotExist(err) {
			return err
		}
		if p == q.runtime.root {
			return errors.New("recovery-root-unavailable")
		}
	}
}

// Other-mode drivers are used only to recheck the completed head rollback.
// Keep the same private roots and process/engine implementation as the source.
func (q *recoveryLifecycle) driver(mode string) Handler {
	if n, ok := q.base.(*nativeLifecycle); ok && mode == "native" {
		return n
	}
	if d, ok := q.base.(*dockerLifecycle); ok && mode == "docker" {
		return d
	}
	b := *q.backup
	b.host = q.host
	if mode == "native" {
		a := newNativeActivation(q.runtime)
		a.host, a.backup = q.host, &b
		return &nativeLifecycle{runtime: q.runtime, activation: a, resources: nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}, preflight: LocalPreflight{}}
	}
	a := newDockerActivation(q.runtime)
	a.host, a.backup = q.host, &b
	return &dockerLifecycle{runtime: q.runtime, activation: a, resources: nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}, preflight: LocalPreflight{}, stage: q.runtime}
}

func (q *recoveryLifecycle) verifyRollback(ctx context.Context, r Request) error {
	switch h := q.driver(r.Spec.Mode).(type) {
	case *nativeLifecycle:
		return h.forRequest(r).verifyRollback(ctx, r)
	case *dockerLifecycle:
		return h.forRequest(r).verifyRollback(ctx, r)
	}
	return errors.New("recovery-driver-unavailable")
}

func (q *recoveryLifecycle) sourceEvidence(ctx context.Context, r Request) ([]byte, error) {
	b := *q.backup
	b.host = q.host
	raw, err := readPrivate(filepath.Join(b.directory(r), "activation/intent.json"), MaxRequestBytes)
	if err != nil {
		return nil, err
	}
	var header struct {
		Target ActiveInstallation `json:"target"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return nil, errors.New("recovery-activation-invalid")
	}
	a := header.Target
	if r.Reinstall == nil {
		r.Reinstall = a.Reinstall
	}
	if !sameReinstall(r.Reinstall, a.Reinstall) {
		return nil, errors.New("recovery-reinstall-mismatch")
	}
	i, err := b.readIntent(ctx, r)
	if err != nil {
		return nil, err
	}
	if i.Installed.Generation != "v3" {
		if err := q.host.historicalReinstall(ctx, r, i); err != nil {
			return nil, err
		}
	}
	if a.Format != 1 || a.Node != r.Node || a.Job != r.Job || a.PlanDigest != r.PlanDigest || a.Spec.digest() != r.Spec.digest() || !validDigest(a.RuntimeSHA256) || !validDigest(a.DefinitionSHA256) {
		return nil, errors.New("recovery-activation-invalid")
	}
	if err := q.host.historicalActivation(ctx, installationHistoryLink{r, i, a}); err != nil {
		return nil, err
	}
	return json.Marshal(a)
}

// Reinstall's extra identity is recovered from its immutable activation rather
// than supplied alongside Recovery by a caller. The public recovery reference
// still binds the entire original pointer and capture.
func (q *recoveryLifecycle) boundSourceRequest(ctx context.Context, r Request) (Request, error) {
	source := r.sourceRequest()
	raw, err := q.sourceEvidence(ctx, source)
	if err != nil {
		return source, err
	}
	var a ActiveInstallation
	if json.Unmarshal(raw, &a) != nil {
		return source, errors.New("recovery-source-invalid")
	}
	source.Reinstall = a.Reinstall
	if source.Validate() != nil {
		return source, errors.New("recovery-source-invalid")
	}
	return source, nil
}

func (q *recoveryLifecycle) recoverySourceIdentity(r Request) (string, error) {
	if !q.valid(r) {
		return "", errors.New("invalid-recovery")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	source, err := q.boundSourceRequest(ctx, r)
	return source.identityDigest(), err
}

// Recompute immutable head evidence without requiring its old runtime state.
// A bounded chain also supports a subsequent recovery of another ancestor.
func (q *recoveryLifecycle) headEvidence(ctx context.Context, r Request, seen map[string]bool) (Request, string, string, error) {
	ref := r.Recovery
	if len(seen) >= 128 || seen[ref.HeadJob] {
		return Request{}, "", "", errors.New("recovery-head-cycle")
	}
	seen[ref.HeadJob] = true
	path := filepath.Join(q.runtime.root, "transitions", ref.HeadJob, "recovery/intent.json")
	if _, err := os.Lstat(path); err == nil {
		var i recoveryIntent
		raw, err := decodePrivateJSON(path, &i, MaxRequestBytes)
		h := Request{Protocol: Protocol, Operation: "apply", Job: ref.HeadJob, Node: r.Node, PlanDigest: ref.HeadPlanDigest, Epoch: 1, Phase: "restore", Spec: i.Spec, Recovery: &i.Reference}
		if err != nil || h.Validate() != nil || i.Format != 1 || i.Binding != binding(h) {
			return Request{}, "", "", errors.New("recovery-head-invalid")
		}
		if _, _, err := q.sourceCapture(ctx, h); err != nil {
			return Request{}, "", "", err
		}
		_, proof, _, err := q.headEvidence(ctx, h, seen)
		if err != nil || proof != i.HeadEvidenceSHA256 {
			return Request{}, "", "", errors.New("recovery-head-changed")
		}
		source, err := q.boundSourceRequest(ctx, h)
		return source, sha(raw), h.identityDigest(), err
	} else if !os.IsNotExist(err) {
		return Request{}, "", "", err
	}
	raw, err := readPrivate(filepath.Join(q.runtime.root, "transitions", ref.HeadJob, "activation/intent.json"), MaxRequestBytes)
	if err != nil {
		return Request{}, "", "", err
	}
	var header struct {
		Target ActiveInstallation `json:"target"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return Request{}, "", "", errors.New("recovery-head-invalid")
	}
	h := Request{Protocol: Protocol, Operation: "apply", Job: ref.HeadJob, Node: r.Node, PlanDigest: ref.HeadPlanDigest, Epoch: 1, Phase: "restore", Spec: header.Target.Spec, Reinstall: header.Target.Reinstall}
	if h.Validate() != nil || !h.Spec.configurationValid() {
		return Request{}, "", "", errors.New("recovery-head-invalid")
	}
	if _, err := q.sourceEvidence(ctx, h); err != nil {
		return Request{}, "", "", err
	}
	return h, sha(raw), h.identityDigest(), nil
}

func (q *recoveryLifecycle) sourceCapture(ctx context.Context, r Request) ([]byte, []byte, error) {
	source := r.sourceRequest()
	pointer, err := q.sourceEvidence(ctx, source)
	if err != nil {
		return nil, nil, err
	}
	capture, err := readPrivate(filepath.Join(q.backup.directory(source), "capture/intent.json"), 4<<20)
	if err != nil || sha(capture) != r.Recovery.CaptureSHA256 || sha(pointer) != r.Recovery.ActiveSHA256 {
		return nil, nil, errors.New("recovery-source-changed")
	}
	return pointer, capture, nil
}

func (q *recoveryLifecycle) plan(ctx context.Context, r Request, fresh bool) ([]byte, string, error) {
	if !q.valid(r) {
		return nil, "", errors.New("invalid-recovery")
	}
	pointer, _, err := q.sourceCapture(ctx, r)
	if err != nil {
		return nil, "", err
	}
	head, proof, spec, err := q.headEvidence(ctx, r, map[string]bool{})
	if err != nil {
		return nil, "", err
	}
	want, err := json.Marshal(recoveryIntent{1, binding(r), r.Spec, *r.Recovery, proof})
	if err != nil {
		return nil, "", err
	}
	if fresh {
		active, err := readPrivate(filepath.Join(q.runtime.root, "active.json"), MaxRequestBytes)
		if err != nil || !bytes.Equal(active, pointer) {
			return nil, "", errors.New("recovery-active-changed")
		}
		if _, err := os.Lstat(filepath.Join(q.backup.directory(r.sourceRequest()), "restoration")); !os.IsNotExist(err) {
			return nil, "", errors.New("recovery-source-already-restoring")
		}
		if err := q.verifyRollback(ctx, head); err != nil {
			return nil, "", err
		}
	}
	return want, spec, nil
}

func (q *recoveryLifecycle) validateRecoveryAdoption(r Request, headSpec string) error {
	if !q.valid(r) {
		return errors.New("invalid-recovery")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx, unlock, err := acquireServiceOperation(ctx, q.runtime.root)
	if err != nil {
		return err
	}
	defer unlock()
	if err := q.intentParents(r); err != nil {
		return err
	}
	if _, err := os.Lstat(q.path(r)); !os.IsNotExist(err) {
		return errors.New("recovery-identity-already-used")
	}
	_, actual, err := q.plan(ctx, r, true)
	if err != nil {
		return err
	}
	if actual != headSpec {
		return errors.New("recovery-head-not-proven")
	}
	return nil
}

// Publish authorization before calling a source driver. On resume, compare
// immutable evidence but let that driver prove any partial service transition.
func (q *recoveryLifecycle) prepare(r Request, publish bool) (bool, error) {
	if !q.valid(r) {
		return false, errors.New("invalid-recovery")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx, unlock, err := acquireServiceOperation(ctx, q.runtime.root)
	if err != nil {
		return false, err
	}
	defer unlock()
	if err := q.intentParents(r); err != nil {
		return false, err
	}
	_, err = os.Lstat(q.path(r))
	fresh := os.IsNotExist(err)
	if err != nil && !fresh {
		return false, err
	}
	var raw []byte
	if !fresh {
		raw, err = readPrivate(q.path(r), MaxRequestBytes)
		if err != nil {
			return false, err
		}
	}
	want, _, err := q.plan(ctx, r, fresh)
	if err != nil {
		return false, err
	}
	if !fresh {
		if !bytes.Equal(raw, want) {
			return false, errors.New("recovery-intent-changed")
		}
		return true, nil
	}
	if !publish {
		return false, nil
	}
	if err := ensurePrivateDirectory(filepath.Dir(q.path(r))); err != nil {
		return false, err
	}
	return true, replacePrivateFile(q.path(r), want, nil)
}

func (q *recoveryLifecycle) Apply(r Request) (Outcome, error) {
	if r.Operation != "apply" {
		return Outcome{}, Failure{"executor-unavailable"}
	}
	if _, err := q.prepare(r, true); err != nil {
		return Outcome{}, Failure{"remote-state-unknown"}
	}
	source, err := q.boundSourceRequest(context.Background(), r)
	if err != nil {
		return Outcome{}, Failure{"remote-state-unknown"}
	}
	return q.driver(r.Spec.Mode).Apply(source)
}
func (q *recoveryLifecycle) Reconcile(r Request) (string, Outcome, error) {
	exists, err := q.prepare(r, false)
	if err != nil {
		return "unknown", Outcome{}, Failure{"remote-state-unknown"}
	}
	if !exists {
		return "absent", Outcome{}, nil
	}
	source, err := q.boundSourceRequest(context.Background(), r)
	if err != nil {
		return "unknown", Outcome{}, Failure{"remote-state-unknown"}
	}
	return q.driver(r.Spec.Mode).Reconcile(source)
}
func (q *recoveryLifecycle) VerifyCompleted(r Request, out Outcome) error {
	exists, err := q.prepare(r, false)
	if err != nil || !exists {
		return Failure{"verification-failed"}
	}
	v, ok := q.driver(r.Spec.Mode).(CompletedVerifier)
	if !ok {
		return Failure{"executor-unavailable"}
	}
	source, err := q.boundSourceRequest(context.Background(), r)
	if err != nil {
		return Failure{"verification-failed"}
	}
	return v.VerifyCompleted(source, out)
}
