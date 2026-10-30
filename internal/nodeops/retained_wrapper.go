package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// A fixed, private provenance pointer survives completed tasks. It only
// references the first immutable capture, never an arbitrary path or command.
// Subsequent tasks keep this root of ownership instead of making a chain of
// references whose removal would silently authorize a different old object.
type retainedWrapperAuthority struct {
	Format       int               `json:"format"`
	Name         string            `json:"name"`
	Binding      transitionBinding `json:"binding"`
	Spec         Spec              `json:"spec"`
	IntentSHA256 string            `json:"intent_sha256"`
}

func (w legacyWrapperTransition) authorityPath(name string) (string, error) {
	if name != "webscan-vector-v1.service" && name != "webscan-exporter-v1.service" || !safeServicePath(w.host.root) {
		return "", errors.New("invalid-retained-wrapper")
	}
	return filepath.Join(w.host.root, "retained-wrappers", name+".json"), nil
}

// The synthetic epoch is ONLY for decoding immutable evidence. This helper
// never invokes Journal or replays an operation using the old task's authority.
func (p retainedWrapperAuthority) sourceRequest() Request {
	return Request{Protocol: Protocol, Operation: "apply", Job: p.Binding.Job, Node: p.Binding.Node, PlanDigest: p.Binding.Plan, Epoch: 1, Phase: "backup", Spec: p.Spec}
}

func (w legacyWrapperTransition) authority(node, name string) (legacyWrapperIntent, []byte, error) {
	var empty legacyWrapperIntent
	path, err := w.authorityPath(name)
	if err != nil {
		return empty, nil, err
	}
	for _, dir := range []string{w.host.root, filepath.Dir(path)} {
		if err := privateDirectoryTree(dir); err != nil {
			return empty, nil, errors.New("retained-wrapper-provenance-invalid")
		}
	}
	var p retainedWrapperAuthority
	raw, err := decodePrivateJSON(path, &p, MaxRequestBytes)
	r := p.sourceRequest()
	if err != nil || p.Format != 1 || p.Name != name || p.Binding.Node != node || r.Validate() != nil || !r.Spec.configurationValid() || p.Binding != binding(r) || !validDigest(p.IntentSHA256) {
		return empty, nil, errors.New("retained-wrapper-provenance-invalid")
	}
	// Decode without following any retained reference. The original capture
	// MUST be a v2 template capture, not another retained generation or cycle.
	var i legacyWrapperIntent
	dir, err := w.directory(r, name)
	if err != nil {
		return empty, nil, err
	}
	for p := dir; p != w.host.root; p = filepath.Dir(p) {
		if err := privateDirectoryTree(p); err != nil {
			return empty, nil, errors.New("retained-wrapper-provenance-invalid")
		}
	}
	intentRaw, err := decodePrivateJSON(filepath.Join(dir, "intent.json"), &i, MaxRequestBytes)
	if err != nil || i.RetainedSHA256 != "" || sha(intentRaw) != p.IntentSHA256 {
		return empty, nil, errors.New("retained-wrapper-provenance-invalid")
	}
	i, _, err = w.read(r, name)
	if err != nil || w.mark(r, name, "quiesce.json", i, intentRaw, false) != nil {
		return empty, nil, errors.New("retained-wrapper-provenance-invalid")
	}
	return i, raw, nil
}

func sameWrapperOrigin(a, b legacyWrapperIntent) bool {
	imageA, _ := json.Marshal(a.Image)
	imageB, _ := json.Marshal(b.Image)
	return a.Binding.Node == b.Binding.Node && a.UnitPath == b.UnitPath && a.RuntimePath == b.RuntimePath && a.RuntimeSHA256 == b.RuntimeSHA256 && bytes.Equal(a.Unit, b.Unit) && a.Object.fingerprint() == b.Object.fingerprint() && a.Object.Identity.Name == b.Object.Identity.Name && bytes.Equal(imageA, imageB)
}

func (w legacyWrapperTransition) verifyRetainedIntent(i legacyWrapperIntent) error {
	if !validDigest(i.RetainedSHA256) {
		return errors.New("retained-wrapper-provenance-invalid")
	}
	original, raw, err := w.authority(i.Binding.Node, filepath.Base(i.UnitPath))
	if err != nil || sha(raw) != i.RetainedSHA256 || !sameWrapperOrigin(original, i) {
		return errors.New("retained-wrapper-provenance-invalid")
	}
	return nil
}

func (w legacyWrapperTransition) verifyAuthority(r Request, i legacyWrapperIntent) error {
	if i.RetainedSHA256 != "" {
		return w.verifyRetainedIntent(i)
	}
	original, _, err := w.authority(r.Node, filepath.Base(i.UnitPath))
	a, _ := json.Marshal(original)
	b, _ := json.Marshal(i)
	if err != nil || !bytes.Equal(a, b) {
		return errors.New("retained-wrapper-provenance-invalid")
	}
	return nil
}

// Write-ahead publication: ownership is durable before the effective unit can
// change. An interrupted publication cannot grant a fresh task permission to
// overwrite the pointer or adopt a different reusable name.
func (w legacyWrapperTransition) publishAuthority(r Request, i legacyWrapperIntent) error {
	name := filepath.Base(i.UnitPath)
	saved, raw, err := w.read(r, name)
	want, _ := json.Marshal(i)
	if err != nil || !bytes.Equal(raw, want) || saved.Binding != binding(r) || w.mark(r, name, "quiesce.json", i, raw, false) != nil {
		return errors.New("retained-wrapper-provenance-invalid")
	}
	if i.RetainedSHA256 != "" {
		return w.verifyRetainedIntent(i)
	}
	path, err := w.authorityPath(name)
	if err != nil {
		return err
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	pointer, _ := json.Marshal(retainedWrapperAuthority{1, name, binding(r), r.Spec, sha(raw)})
	if err := replacePrivateFile(path, pointer, nil); err != nil {
		return err
	}
	return w.verifyAuthority(r, i)
}

// Read-only ownership of an effective retained unit. Manager/process/object
// checks are the same as during the original task, using its immutable origin.
func (w legacyWrapperTransition) retainedState(ctx context.Context, node, name string) (legacyWrapperIntent, nativeStatus, error) {
	i, _, err := w.authority(node, name)
	if err != nil {
		return i, nativeStatus{}, err
	}
	if err := expectedWrapperUnit(i, true); err != nil {
		return i, nativeStatus{}, err
	}
	s, o, err := w.state(ctx, Request{Node: node}, i, true)
	if err == nil && ((s.MainPID > 0) != (o.Identity.Status == "running") || s.NeedDaemonReload != "no") {
		err = errors.New("retained-wrapper-state-unknown")
	}
	return i, s, err
}

func (w legacyWrapperTransition) rejectExistingAuthority(name string) error {
	path, err := w.authorityPath(name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return errors.New("retained-wrapper-owner-pending")
	}
	return nil
}
