package nodeops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// An observation is deliberately not an Installation or installationQuiescer.
// Its ephemeral member proofs cannot be submitted to stop/export/activation.
type legacyGroupObservation struct {
	agent   Installation
	grouped bool
}

func (h installationHost) observeOriginal(ctx context.Context, r Request) (legacyGroupObservation, error) {
	if r.Validate() != nil || r.Operation != "apply" {
		return legacyGroupObservation{}, errors.New("invalid-legacy-group-request")
	}
	i, err := h.inventory(ctx, r.Node, r.Spec.Mode)
	if err == nil && (i.Generation == "absent" || len(i.Services) <= 1) {
		return legacyGroupObservation{agent: i}, nil
	}
	w := legacyWrapperTransition{h}
	members := map[string]legacyWrapperIntent{}
	for _, name := range legacyWrapperNames {
		if _, err := os.Lstat(filepath.Join(filepath.Dir(h.unitPath), name)); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return legacyGroupObservation{}, err
		}
		i, err := w.observe(ctx, r, name)
		if err != nil {
			return legacyGroupObservation{}, err
		}
		members[name] = i
	}
	if len(members) == 0 {
		i, composeErr := h.observeComposeGroup(ctx, r)
		if composeErr != nil {
			return legacyGroupObservation{}, composeErr
		}
		return legacyGroupObservation{agent: agentOnly(i), grouped: true}, nil
	}
	i, err = h.inventoryWithWrapperProofs(ctx, r.Node, r.Spec.Mode, members, true)
	if err != nil || i.Generation != "v2" || !singleNativeOriginal(agentOnly(i)) && !singleDockerOriginal(agentOnly(i)) {
		return legacyGroupObservation{}, errors.New("legacy-group-agent-not-proven")
	}
	return legacyGroupObservation{agent: agentOnly(i), grouped: true}, nil
}

func (b *transitionBackup) attachGroup(h installationHost, r Request) {
	r.Operation, r.Phase = "apply", "backup"
	g := &legacyWrapperGroup{host: h, request: r, backup: b}
	b.host = g
}

// Each request owns its driver copy. Selection never mutates a shared handler
// or publishes files, and later phases select from the exact durable capture.
func (n *nativeLifecycle) forRequest(r Request) *nativeLifecycle {
	if n == nil || n.activation == nil || n.activation.backup == nil || r.Validate() != nil || !r.Spec.configurationValid() {
		return n
	}
	copy := *n
	a := *n.activation
	b := *a.backup
	copy.activation = &a
	a.backup = &b
	lookup := r
	lookup.Operation = "apply"
	if i, err := b.readIntent(context.Background(), lookup); err == nil && hasLegacyMembers(i.Installed) {
		b.attachGroup(a.host, r)
	}
	return &copy
}

func (d *dockerLifecycle) forRequest(r Request) *dockerLifecycle {
	if d == nil || d.activation == nil || d.activation.backup == nil || r.Validate() != nil || !r.Spec.configurationValid() {
		return d
	}
	copy := *d
	a := *d.activation
	b := *a.backup
	copy.activation = &a
	a.backup = &b
	lookup := r
	lookup.Operation = "apply"
	if i, err := b.readIntent(context.Background(), lookup); err == nil && hasLegacyMembers(i.Installed) {
		b.attachGroup(a.host, r)
	}
	return &copy
}
