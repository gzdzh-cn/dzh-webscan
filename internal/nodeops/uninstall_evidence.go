package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
)

type uninstallEvidenceProvider interface {
	removalEvidence(Request) (*RemovalEvidence, error)
	restorationEvidence(Request) (*RestorationEvidence, error)
}

func (u *uninstallLifecycle) removalEvidence(r Request) (*RemovalEvidence, error) {
	var evidence *RemovalEvidence
	_, err := u.operation(r, func(ctx context.Context, r Request) (Outcome, error) {
		if r.Phase != "finalize" {
			return Outcome{}, errors.New("removal-evidence-phase-invalid")
		}
		if err := u.verifyRemoval(ctx, r, true); err != nil {
			return Outcome{}, err
		}
		i, intent, err := u.plan(ctx, r, false)
		if err != nil {
			return Outcome{}, err
		}
		tomb, err := u.readTombstone(ctx, r)
		if err != nil {
			return Outcome{}, err
		}
		evidence = &RemovalEvidence{i.CaptureSHA256, sha(intent), i.PreservedSHA256, sha(tomb)}
		return Outcome{}, nil
	})
	return evidence, err
}
func (u *uninstallLifecycle) restorationEvidence(r Request) (*RestorationEvidence, error) {
	var evidence *RestorationEvidence
	_, err := u.operation(r, func(ctx context.Context, r Request) (Outcome, error) {
		if r.Phase != "verify-rollback" {
			return Outcome{}, errors.New("restoration-evidence-phase-invalid")
		}
		if err := u.verifyRestoration(ctx, r, true); err != nil {
			return Outcome{}, err
		}
		var e RestorationEvidence
		_, err := decodePrivateJSON(filepath.Join(u.directory(r), "restoration-final.json"), &e, 4096)
		if err != nil || !e.Valid() {
			return Outcome{}, errors.New("restoration-evidence-invalid")
		}
		evidence = &e
		return Outcome{}, nil
	})
	return evidence, err
}

func (h installationHost) historicalRestoration(ctx context.Context, a ActiveInstallation) error {
	if a.Restoration == nil {
		return nil
	}
	raw, _ := json.Marshal(a)
	ref := a.Restoration
	if !validActiveRestoration(ref, a.Job) {
		return errors.New("historical-restoration-reference-invalid")
	}
	var e RestorationEvidence
	receipt, err := decodePrivateJSON(filepath.Join(h.root, "transitions", ref.Job, "uninstall/restoration-final.json"), &e, 4096)
	if err != nil || !e.Valid() {
		return errors.New("historical-restoration-not-proven")
	}
	spec := a.Spec
	spec.Action = "uninstall"
	r := Request{Protocol: Protocol, Operation: "apply", Job: "history-verifier", Node: a.Node, PlanDigest: sha([]byte("history-verifier")), Epoch: 1, Phase: "preflight", Spec: spec, Uninstall: &UninstallReference{SourceJob: a.Job, SourcePlanDigest: a.PlanDigest, CaptureSHA256: a.CaptureSHA256, ActiveSHA256: sha(raw), RestorationJob: ref.Job, RestorationPlanDigest: ref.PlanDigest, RestorationSHA256: sha(receipt)}}
	b := newTransitionBackup(h.root)
	b.unit = h.unitPath
	b.host = h
	u := &uninstallLifecycle{runtime: &LocalRuntime{root: h.root}, backup: b, host: h}
	return u.verifyRestorationReference(ctx, r, a, 0)
}
func (h installationHost) restoredService(a ActiveInstallation) (ServiceRecord, error) {
	var empty ServiceRecord
	ref := a.Restoration
	if ref == nil {
		return empty, errors.New("restoration-reference-required")
	}
	if !validActiveRestoration(ref, a.Job) {
		return empty, errors.New("restoration-reference-invalid")
	}
	var p uninstallRestoreIntent
	intent, err := decodePrivateJSON(filepath.Join(h.root, "transitions", ref.Job, "uninstall/restoration-intent.json"), &p, 4<<20)
	if err != nil || sha(intent) != ref.IntentSHA256 {
		return empty, errors.New("restoration-intent-changed")
	}
	r := Request{Protocol: Protocol, Operation: "apply", Job: ref.Job, Node: a.Node, PlanDigest: ref.PlanDigest, Epoch: 1, Phase: "verify-rollback", Spec: p.Spec, Uninstall: &p.Reference}
	if r.Validate() != nil || binding(r) != p.Binding {
		return empty, errors.New("restoration-binding-changed")
	}
	b := newTransitionBackup(h.root)
	b.unit = h.unitPath
	u := &uninstallLifecycle{runtime: &LocalRuntime{root: h.root}, backup: b, host: h}
	o, object, err := u.restoredObject(context.Background(), r, p, intent)
	if err != nil || sha(object) != ref.ObjectSHA256 {
		return empty, errors.New("restoration-object-changed")
	}
	return o.Service, nil
}

func validActiveRestoration(r *ActiveRestorationReference, source string) bool {
	return r != nil && idPattern.MatchString(r.Job) && r.Job != source && validDigest(r.PlanDigest) && validDigest(r.IntentSHA256) && validDigest(r.ObjectSHA256)
}
func (h installationHost) historicalReinstall(ctx context.Context, r Request, i backupIntent) error {
	ref := i.Installed.Removal
	if !sameReinstall(ref, r.Reinstall) {
		return errors.New("historical-reinstall-binding-changed")
	}
	if ref == nil {
		return nil
	}
	raw, err := readPrivate(filepath.Join(h.root, "transitions", ref.SourceJob, "uninstall/tombstone.json"), 4<<20)
	if err != nil || sha(raw) != ref.TombstoneSHA256 {
		return errors.New("historical-removal-tombstone-changed")
	}
	t, source, err := h.readRemovalTombstone(ctx, raw)
	if err != nil || source.Job != ref.SourceJob || source.PlanDigest != ref.SourcePlanDigest || source.Node != r.Node {
		return errors.New("historical-removal-source-mismatch")
	}
	b := newTransitionBackup(h.root)
	b.unit = h.unitPath
	b.host = h
	u := &uninstallLifecycle{runtime: &LocalRuntime{root: h.root}, backup: b, host: h}
	intent, _, err := u.plan(ctx, source, false)
	if err != nil || t.CaptureSHA256 != intent.CaptureSHA256 || t.PreservedSHA256 != intent.PreservedSHA256 {
		return errors.New("historical-removal-not-proven")
	}
	if _, _, err = u.source(ctx, source); err != nil {
		return err
	}
	return nil
}
