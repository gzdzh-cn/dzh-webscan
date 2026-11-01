package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func validReinstall(q *ReinstallReference) bool {
	return q == nil || idPattern.MatchString(q.SourceJob) && validDigest(q.SourcePlanDigest) && validDigest(q.TombstoneSHA256)
}
func sameReinstall(a, b *ReinstallReference) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func (r Request) uninstallSourceRequest() Request {
	q := r
	q.Job = r.Uninstall.SourceJob
	q.PlanDigest = r.Uninstall.SourcePlanDigest
	q.Spec.Action = ""
	q.Uninstall = nil
	q.Operation = "apply"
	q.Phase = "backup"
	return q
}
func (u *uninstallLifecycle) source(ctx context.Context, r Request) (ActiveInstallation, []byte, error) {
	return u.sourceDepth(ctx, r, 0)
}

type uninstallSourceDepthKey struct{}

func (u *uninstallLifecycle) sourceDepth(ctx context.Context, r Request, depth int) (ActiveInstallation, []byte, error) {
	var active ActiveInstallation
	nested, _ := ctx.Value(uninstallSourceDepthKey{}).(int)
	if depth > 64 || nested >= 64 || ctx.Err() != nil || !u.valid(r) {
		return active, nil, errors.New("uninstall-source-invalid")
	}
	ctx = context.WithValue(ctx, uninstallSourceDepthKey{}, nested+1)
	source := r.uninstallSourceRequest()
	// A reinstalled source has an extra immutable tombstone binding. Recover it
	// from the capture/activation protected by the control plane's source hashes.
	var header struct {
		Target ActiveInstallation `json:"target"`
	}
	headerRaw, err := readPrivate(filepath.Join(u.runtime.root, "transitions", source.Job, "activation/intent.json"), MaxRequestBytes)
	if err != nil || json.Unmarshal(headerRaw, &header) != nil {
		return active, nil, errors.New("uninstall-source-activation-invalid")
	}
	source.Reinstall = header.Target.Reinstall
	if source.Validate() != nil {
		return active, nil, errors.New("uninstall-source-invalid")
	}
	capture, err := readPrivate(filepath.Join(u.backup.directory(source), "capture/intent.json"), 4<<20)
	if err != nil || sha(capture) != r.Uninstall.CaptureSHA256 {
		return active, nil, errors.New("uninstall-source-capture-changed")
	}
	q := &recoveryLifecycle{runtime: u.runtime, backup: u.backup, host: u.host}
	pointer, err := q.sourceEvidence(ctx, source)
	if err != nil {
		return active, nil, err
	}
	// After backup the captured pointer is authoritative, even after its live
	// counterpart was removed. A missing/corrupt capture never falls back to it.
	path := filepath.Join(u.runtime.root, "active.json")
	if _, e := os.Lstat(filepath.Join(u.backup.directory(r), "capture")); e == nil {
		if _, e = u.backup.readIntent(ctx, r); e != nil {
			return active, nil, e
		}
		path = filepath.Join(u.backup.directory(r), "capture/active.json")
	} else if !os.IsNotExist(e) {
		return active, nil, e
	}
	var raw []byte
	if _, e := os.Lstat(filepath.Join(u.backup.directory(r), "capture")); os.IsNotExist(e) {
		var restoration uninstallRestoreIntent
		if _, e := decodePrivateJSON(filepath.Join(u.directory(r), "restoration-intent.json"), &restoration, 4<<20); e == nil && restoration.Binding == binding(r) && restoration.NoEffects {
			raw = restoration.OriginalActive
			err = json.Unmarshal(raw, &active)
		}
	}
	if raw == nil {
		raw, err = decodePrivateJSON(path, &active, MaxRequestBytes)
	}
	if err != nil || sha(raw) != r.Uninstall.ActiveSHA256 {
		return active, nil, errors.New("uninstall-active-not-proven")
	}
	canonical, _ := json.Marshal(active)
	if !bytes.Equal(raw, canonical) {
		return active, nil, errors.New("uninstall-active-not-canonical")
	}
	stripped := active
	stripped.Restoration = nil
	plain, _ := json.Marshal(stripped)
	if !bytes.Equal(plain, pointer) {
		return active, nil, errors.New("uninstall-source-pointer-mismatch")
	}
	if r.Uninstall.RestorationJob != "" {
		if err := u.verifyRestorationReference(ctx, r, active, depth+1); err != nil {
			return active, nil, err
		}
	} else if active.Restoration != nil || !bytes.Equal(raw, pointer) {
		return active, nil, errors.New("uninstall-restoration-reference-required")
	}
	return active, raw, nil
}
func (u *uninstallLifecycle) recoveryMaterials(ctx context.Context, r Request) error {
	source := r.uninstallSourceRequest()
	// No certificate time validation or monitor/clamd probing is needed to
	// remove an installed service. Its fixed executable and definition are.
	if err := u.runtime.verifyPrepared(ctx, source.Spec); err != nil {
		return err
	}
	active, _, err := u.source(ctx, r)
	if err != nil {
		return err
	}
	dir := u.runtime.configurationDir(source.Spec)
	runtime, err := readPrivate(filepath.Join(dir, "runtime.json"), 2<<20)
	if err != nil || sha(runtime) != active.RuntimeSHA256 {
		return errors.New("uninstall-runtime-not-preserved")
	}
	definition := "compose.json"
	if source.Spec.Mode == "native" {
		definition = nativeServiceName
	}
	raw, err := readPrivate(filepath.Join(dir, definition), 2<<20)
	if err != nil || sha(raw) != active.DefinitionSHA256 {
		return errors.New("uninstall-definition-not-preserved")
	}
	if source.Spec.Mode == "docker" {
		a := &dockerActivation{runtime: u.runtime, backup: u.backup, host: u.host}
		if _, err = a.imageID(ctx, source.Spec); err != nil {
			return err
		}
	}
	return nil
}
