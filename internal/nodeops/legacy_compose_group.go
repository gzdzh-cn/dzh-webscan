package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
)

// A native switch deliberately retires the legacy Compose definition. Only
// this task's exact capture and published native activation permit its absence;
// a missing file alone never proves that a legacy member was safely parked.
func (q legacyComposeTransition) retiredDefinition(ctx context.Context, r Request, member legacyComposeIntent) error {
	if r.Validate() != nil || r.Spec.Mode != "native" || binding(r) != member.Binding {
		return errors.New("legacy-compose-retirement-not-proven")
	}
	b := newTransitionBackup(q.host.root)
	b.unit = q.host.unitPath
	i, err := b.readIntent(ctx, r)
	if err != nil || i.Installed.Mode != "docker" || i.Installed.Generation != "v2" || filepath.Dir(i.Installed.Runtime) != q.host.configRoot {
		return errors.New("legacy-compose-retirement-not-proven")
	}
	name := member.Object.Identity.Name[1:]
	raw, _ := json.Marshal(member)
	found := false
	for _, m := range i.Installed.Sidecars {
		if m.Name == name && m.IntentSHA256 == sha(raw) {
			found = true
		}
	}
	if !found {
		return errors.New("legacy-compose-retirement-not-proven")
	}
	capture, err := readPrivate(filepath.Join(b.directory(r), "capture/intent.json"), 4<<20)
	if err != nil {
		return err
	}
	var snapshot backupSnapshot
	saved, err := decodePrivateJSON(filepath.Join(b.directory(r), "snapshot/receipt.json"), &snapshot, 16<<20)
	if err != nil || snapshot.Format != 1 || snapshot.Binding != binding(r) || snapshot.IntentSHA256 != sha(capture) {
		return errors.New("legacy-compose-retirement-not-proven")
	}
	var activation nativeActivationIntent
	_, err = decodePrivateJSON(filepath.Join(b.directory(r), "activation/intent.json"), &activation, MaxRequestBytes)
	target := activation.Target
	if err != nil || activation.Format != 1 || activation.Binding != binding(r) || activation.CaptureSHA256 != sha(capture) || activation.SnapshotSHA256 != sha(saved) || target.Format != 1 || target.Node != r.Node || target.Job != r.Job || target.PlanDigest != r.PlanDigest || target.Spec.digest() != r.Spec.digest() || !validDigest(target.RuntimeSHA256) || !validDigest(target.DefinitionSHA256) || target.CaptureSHA256 != "" && target.CaptureSHA256 != activation.CaptureSHA256 || len(activation.Unit) > 64<<10 || sha(activation.Unit) != target.DefinitionSHA256 {
		return errors.New("legacy-compose-retirement-not-proven")
	}
	// As with native recovery, a damaged target configuration or expired leaf
	// must not prevent verification of the immutable retired installation.
	definition, err := readPrivate(filepath.Join(b.directory(r), "capture/config/compose.yml"), 2<<20)
	if err != nil || sha(definition) != member.ComposeSHA256 {
		return errors.New("legacy-compose-retirement-not-proven")
	}
	return q.host.nativeOriginalDockerStopped(ctx, agentOnly(i.Installed), retiredDockerName(r), true)
}

func (b *transitionBackup) composeIntents(r Request, i Installation) (map[string]legacyComposeIntent, error) {
	result := map[string]legacyComposeIntent{}
	if len(i.Sidecars) == 0 {
		return result, nil
	}
	if !i.valid(r.Node) || len(i.Wrappers) != 0 || !singleDockerOriginal(agentOnly(i)) || i.Runtime == "" {
		return nil, errors.New("legacy-compose-group-not-proven")
	}
	h := newInstallationHost(b.root)
	h.configRoot, h.unitPath = filepath.Dir(i.Runtime), b.unit
	q := legacyComposeTransition{h}
	for _, member := range i.Sidecars {
		intent, raw, err := q.read(r, member.Name)
		if err != nil || sha(raw) != member.IntentSHA256 {
			return nil, errors.New("legacy-compose-member-not-proven")
		}
		result[member.Name] = intent
	}
	return result, nil
}
func (h installationHost) observeComposeGroup(ctx context.Context, r Request) (Installation, error) {
	q := legacyComposeTransition{h}
	if err := q.noSupervisor(ctx); err != nil {
		return Installation{}, err
	}
	members := map[string]legacyComposeIntent{}
	for _, name := range legacyComposeNames {
		c, err := h.containerNamed(ctx, name)
		if err != nil {
			return Installation{}, err
		}
		if c == nil {
			continue
		}
		i, err := q.observe(ctx, r, name)
		if err != nil {
			return Installation{}, err
		}
		members[name] = i
	}
	if len(members) == 0 {
		return Installation{}, errors.New("legacy-compose-group-empty")
	}
	i, err := h.inventoryWithLegacyProofs(ctx, r.Node, r.Spec.Mode, nil, members, true)
	if err != nil || i.Generation != "v2" || !singleDockerOriginal(agentOnly(i)) {
		return Installation{}, errors.New("legacy-compose-group-not-proven")
	}
	return i, nil
}
func (g *legacyWrapperGroup) captureCompose(ctx context.Context, r Request) (Installation, error) {
	if _, err := g.host.observeComposeGroup(ctx, r); err != nil {
		return Installation{}, err
	}
	q := legacyComposeTransition{g.host}
	members := map[string]legacyComposeIntent{}
	for _, name := range legacyComposeNames {
		c, err := g.host.containerNamed(ctx, name)
		if err != nil {
			return Installation{}, err
		}
		if c == nil {
			continue
		}
		i, err := q.capture(ctx, r, name)
		if err != nil {
			return Installation{}, err
		}
		members[name] = i
	}
	i, err := g.host.inventoryWithLegacyProofs(ctx, r.Node, r.Spec.Mode, nil, members, false)
	if err != nil || !singleDockerOriginal(agentOnly(i)) {
		return Installation{}, errors.New("legacy-compose-group-not-proven")
	}
	return i, nil
}
func (h installationHost) inspectComposeProofs(ctx context.Context, node string, members map[string]legacyComposeIntent, observed bool) error {
	if len(members) == 0 {
		return nil
	}
	if len(members) > 2 {
		return errors.New("legacy-compose-intent-invalid")
	}
	q := legacyComposeTransition{h}
	for name, i := range members {
		if !composeSidecarName(name) || i.Object.Identity.Name != "/"+name || i.Binding.Node != node || !idPattern.MatchString(i.Binding.Job) || !validDigest(i.Binding.Plan) || !validDigest(i.Binding.Spec) || validateComposeSidecar(i) != nil {
			return errors.New("legacy-compose-intent-invalid")
		}
		if !observed {
			raw, err := readPrivate(filepath.Join(h.root, "transitions", i.Binding.Job, "sidecars", name, "intent.json"), MaxRequestBytes)
			want, _ := json.Marshal(i)
			if err != nil || !bytes.Equal(raw, want) {
				return errors.New("legacy-compose-intent-invalid")
			}
		}
		current, err := q.state(ctx, Request{Node: node}, i)
		c := i.Object.Identity
		if err != nil || current.Identity.Status != c.Status || current.Identity.Restart != c.Restart || current.Identity.MaxRetries != c.MaxRetries {
			return errors.New("legacy-compose-original-state-changed")
		}
	}
	return nil
}
func (g *legacyWrapperGroup) inspectCompose(ctx context.Context, i Installation, forward bool) error {
	members, err := g.backup.composeIntents(g.request, i)
	if err != nil || len(members) == 0 {
		return errors.New("legacy-compose-group-not-proven")
	}
	q := legacyComposeTransition{g.host}
	if err := q.noSupervisor(ctx); err != nil {
		return err
	}
	// No new same-project sidecar may appear outside the complete capture.
	for _, name := range legacyComposeNames {
		c, err := g.host.containerNamed(ctx, name)
		if err != nil {
			return err
		}
		member, ok := members[name]
		if !ok {
			if c != nil {
				return errors.New("unrecorded-legacy-compose-sidecar")
			}
			continue
		}
		if c == nil || c.ID != member.Object.Identity.ID {
			return errors.New("legacy-compose-member-changed")
		}
		if err := q.inspect(ctx, g.request, name, forward); err != nil {
			return err
		}
	}
	return g.inspectAgent(ctx, i)
}
func (g *legacyWrapperGroup) composeQuiescent(ctx context.Context, i Installation) error {
	members, err := g.backup.composeIntents(g.request, i)
	if err != nil || len(members) == 0 {
		return errors.New("legacy-compose-group-not-proven")
	}
	q := legacyComposeTransition{g.host}
	for _, name := range legacyComposeNames {
		c, err := g.host.containerNamed(ctx, name)
		if err != nil {
			return err
		}
		if _, ok := members[name]; !ok {
			if c != nil {
				return errors.New("unrecorded-legacy-compose-sidecar")
			}
			continue
		}
		if err := q.quiescent(ctx, g.request, name); err != nil {
			return err
		}
	}
	return nil
}

// Follow only captured predecessor pointers, never arbitrary jobs or names.
// Later v3 upgrades retain the original parked group through this chain.
func (h installationHost) composeAncestor(ctx context.Context, active *ActiveInstallation) (Request, *backupIntent, error) {
	links, err := h.installationHistory(ctx, active)
	if err != nil {
		return Request{}, nil, err
	}
	for _, link := range links {
		if len(link.captured.Installed.Sidecars) > 0 {
			i := link.captured
			return link.request, &i, nil
		}
	}
	return Request{}, nil, nil
}

// The active pointer's bound immutable capture (or captured predecessors) is
// the only authority to omit parked sidecars from the current writer set.
func (h installationHost) parkedComposeProofs(ctx context.Context, active *ActiveInstallation) (map[string]legacyComposeIntent, error) {
	r, i, err := h.composeAncestor(ctx, active)
	result := map[string]legacyComposeIntent{}
	if err != nil || i == nil {
		return result, err
	}
	qh := h
	qh.configRoot = filepath.Dir(i.Installed.Runtime)
	q := legacyComposeTransition{qh}
	for _, member := range i.Installed.Sidecars {
		original, _, err := q.read(r, member.Name)
		if err != nil {
			return nil, err
		}
		if err := q.quiescent(ctx, r, member.Name); err != nil {
			return nil, err
		}
		result[member.Name] = original
	}
	return result, nil
}
