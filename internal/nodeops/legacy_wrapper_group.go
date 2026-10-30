package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Grouped backup is deliberately private until the target activation and
// post-activation recovery drivers can verify the entire retained group.
// It composes the actual SQLite/JSONL backup, not a second snapshot writer.
// The outer Journal must fence requests before calling this coordinator.
type legacyWrapperGroup struct {
	host    installationHost
	request Request
	backup  *transitionBackup
}

func newLegacyWrapperGroup(h installationHost, r Request, data, logs string) *legacyWrapperGroup {
	g := &legacyWrapperGroup{host: h, request: r}
	g.backup = &transitionBackup{root: h.root, data: data, logs: logs, unit: h.unitPath, host: g}
	return g
}

func agentOnly(i Installation) Installation {
	i.Wrappers = nil
	i.Sidecars = nil
	return i
}

func (b *transitionBackup) wrapperIntents(r Request, i Installation) (map[string]legacyWrapperIntent, error) {
	result := map[string]legacyWrapperIntent{}
	if len(i.Wrappers) == 0 {
		return result, nil
	}
	if !i.valid(r.Node) || !singleNativeOriginal(agentOnly(i)) && !singleDockerOriginal(agentOnly(i)) || i.Runtime == "" {
		return nil, errors.New("legacy-group-agent-not-proven")
	}
	h := newInstallationHost(b.root)
	h.configRoot, h.unitPath = filepath.Dir(i.Runtime), b.unit
	w := legacyWrapperTransition{h}
	for _, member := range i.Wrappers {
		intent, raw, err := w.read(r, member.Name)
		if err != nil || sha(raw) != member.IntentSHA256 {
			return nil, errors.New("legacy-group-member-not-proven")
		}
		result[member.Name] = intent
	}
	return result, nil
}

func (b *transitionBackup) verifyWrapperMembers(r Request, i Installation) error {
	if _, err := b.composeIntents(r, i); err != nil {
		return err
	}
	_, err := b.wrapperIntents(r, i)
	return err
}

// inventory only publishes private member captures. Both wrappers and the
// Agent are proved before transitionBackup may publish its quiesce marker.
func (g *legacyWrapperGroup) inventory(ctx context.Context, node, mode string) (Installation, error) {
	r := g.request
	if r.Validate() != nil || r.Operation != "apply" || r.Phase != "backup" || r.Node != node || r.Spec.Mode != mode {
		return Installation{}, errors.New("invalid-legacy-group-request")
	}
	w := legacyWrapperTransition{g.host}
	members := map[string]legacyWrapperIntent{}
	for _, name := range legacyWrapperNames {
		if _, err := os.Lstat(filepath.Join(filepath.Dir(g.host.unitPath), name)); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return Installation{}, err
		}
		i, err := w.capture(ctx, r, name)
		if err != nil {
			return Installation{}, err
		}
		members[name] = i
	}
	if len(members) == 0 {
		return g.captureCompose(ctx, r)
	}
	i, err := g.host.inventoryWithWrappers(ctx, node, mode, members)
	if err != nil || i.Generation != "v2" || !singleNativeOriginal(agentOnly(i)) && !singleDockerOriginal(agentOnly(i)) {
		return Installation{}, errors.New("legacy-group-agent-not-proven")
	}
	return i, nil
}

// Probe the complete set before the first mutating command, also on replay.
// Original stopped members may not acquire an unrecorded writer. A quiesce
// receipt authorizes only the exact retained-ID unit, never arbitrary changes.
func (g *legacyWrapperGroup) inspect(ctx context.Context, i Installation, forward bool) error {
	if len(i.Sidecars) > 0 {
		return g.inspectCompose(ctx, i, forward)
	}
	members, err := g.backup.wrapperIntents(g.request, i)
	if err != nil || len(members) == 0 {
		return errors.New("legacy-group-member-not-proven")
	}
	// A later, unrecorded supervisor could recreate a writer even though every
	// captured object is valid. Prove absence as well as presence under the lock.
	for _, name := range append([]string{"webscan-agent-v1.service"}, legacyWrapperNames...) {
		if _, captured := members[name]; captured {
			continue
		}
		if _, err := os.Lstat(filepath.Join(filepath.Dir(g.host.unitPath), name)); !os.IsNotExist(err) {
			return errors.New("unrecorded-legacy-wrapper")
		}
	}
	w := legacyWrapperTransition{g.host}
	for _, name := range legacyWrapperNames {
		intent, exists := members[name]
		if !exists {
			continue
		}
		_, raw, err := w.read(g.request, name)
		if err != nil {
			return err
		}
		dir, _ := w.directory(g.request, name)
		if forward {
			for _, marker := range []string{"restore.json", "restored.json"} {
				if _, err := os.Lstat(filepath.Join(dir, marker)); !os.IsNotExist(err) {
					return errors.New("rollback-already-started")
				}
			}
		} else {
			for _, marker := range []string{"restore.json", "restored.json"} {
				if _, err := os.Lstat(filepath.Join(dir, marker)); !os.IsNotExist(err) {
					if err := w.mark(g.request, name, marker, intent, raw, false); err != nil {
						return err
					}
					if marker == "restored.json" {
						if err := w.restored(ctx, g.request, name); err != nil {
							return err
						}
					}
				}
			}
		}
		safe := false
		if _, err := os.Lstat(filepath.Join(dir, "quiesce.json")); !os.IsNotExist(err) {
			if err := w.mark(g.request, name, "quiesce.json", intent, raw, false); err != nil {
				return err
			}
			safe = true
		}
		s, o, err := w.state(ctx, g.request, intent, safe)
		if err != nil || !intent.Running && (s.MainPID > 0 || o.Identity.Status == "running") {
			return errors.New("legacy-group-member-changed")
		}
		if !safe && ((s.MainPID > 0) != intent.Running || (s.UnitFileState == "enabled") != intent.Enabled || (o.Identity.Status == "running") != intent.Running) {
			return errors.New("legacy-group-original-state-changed")
		}
	}
	return g.inspectAgent(ctx, i)
}

func (g *legacyWrapperGroup) inspectAgent(ctx context.Context, i Installation) error {
	i = agentOnly(i)
	if !singleNativeOriginal(i) && !singleDockerOriginal(i) {
		return errors.New("legacy-group-agent-not-proven")
	}
	s := i.Services[0]
	if s.Kind == "native" {
		current, err := g.host.native(ctx, s)
		if err != nil || !s.Running && current.MainPID > 0 {
			return errors.New("legacy-group-agent-changed")
		}
		if c, err := g.host.containerNamed(ctx, agentContainerName); err != nil || c != nil {
			return errors.New("unrecorded-original-agent-container")
		}
	} else {
		if _, err := os.Lstat(g.host.unitPath); !os.IsNotExist(err) {
			return errors.New("unrecorded-original-agent-unit")
		}
		c, err := g.host.ownedContainer(ctx, s)
		if err != nil || c.Name != "/"+s.Name || !s.Running && c.Status == "running" || c.Restart != "no" && (c.Restart != s.Restart || c.MaxRetries != s.MaxRetries) {
			return errors.New("legacy-group-agent-changed")
		}
	}
	return nil
}

func (g *legacyWrapperGroup) stop(ctx context.Context, i Installation) error {
	if g.backup.rollbackStarted(g.request) {
		return errors.New("rollback-already-started")
	}
	if err := g.inspect(ctx, i, true); err != nil {
		return err
	}
	w := legacyWrapperTransition{g.host}
	for _, name := range legacyWrapperNames {
		for _, member := range i.Wrappers {
			if member.Name == name {
				if err := w.quiesce(ctx, g.request, name); err != nil {
					return err
				}
			}
		}
	}
	q := legacyComposeTransition{g.host}
	for _, member := range i.Sidecars {
		if err := q.quiesce(ctx, g.request, member.Name); err != nil {
			return err
		}
	}
	if err := g.host.stop(ctx, agentOnly(i)); err != nil {
		return err
	}
	stopped, err := g.stopped(ctx, i)
	if err != nil || !stopped {
		return errors.New("legacy-group-not-quiescent")
	}
	return nil
}

func (g *legacyWrapperGroup) stopped(ctx context.Context, i Installation) (bool, error) {
	if err := g.backup.verifyWrapperMembers(g.request, i); err != nil || !hasLegacyMembers(i) {
		return false, errors.New("legacy-group-member-not-proven")
	}
	w := legacyWrapperTransition{g.host}
	for _, member := range i.Wrappers {
		if err := w.quiescent(ctx, g.request, member.Name); err != nil {
			return false, err
		}
	}
	q := legacyComposeTransition{g.host}
	for _, member := range i.Sidecars {
		if err := q.quiescent(ctx, g.request, member.Name); err != nil {
			return false, err
		}
	}
	return g.host.stopped(ctx, agentOnly(i))
}

type legacyGroupRestoreReceipt struct {
	Format        int               `json:"format"`
	Binding       transitionBinding `json:"binding"`
	CaptureSHA256 string            `json:"capture_sha256"`
	Kind          string            `json:"kind"`
}

// This recovery path is intentionally limited to the backup boundary. It
// cannot stop/replace a new target or accept any activation/checkpoint. The
// live DB and JSONL remain untouched, including events written after capture.
func (g *legacyWrapperGroup) restoreBeforeActivation(ctx context.Context, r Request) error {
	if r.Validate() != nil || r.Operation != "apply" || r.Phase != "restore" || binding(r) != binding(g.request) {
		return errors.New("invalid-legacy-group-request")
	}
	ctx, release, err := acquireServiceOperation(ctx, g.host.root)
	if err != nil {
		return err
	}
	defer release()
	i, err := g.backup.readIntent(ctx, r)
	if err != nil || !hasLegacyMembers(i.Installed) {
		return errors.New("legacy-group-member-not-proven")
	}
	for _, path := range []string{"activation", "finalized.json"} {
		if _, err := os.Lstat(filepath.Join(g.backup.directory(r), path)); !os.IsNotExist(err) {
			return errors.New("legacy-group-target-recovery-required")
		}
	}
	// A v2 group had no active pointer at capture. A newly appearing pointer
	// is evidence of an unknown target, even without this task's activation dir.
	if _, err := os.Lstat(filepath.Join(g.host.root, "active.json")); !os.IsNotExist(err) {
		return errors.New("legacy-group-target-recovery-required")
	}
	if err := g.backup.unchanged(ctx, i); err != nil {
		return err
	}
	if err := g.backup.groupDatabasePresent(i); err != nil {
		return err
	}
	raw, err := readPrivate(filepath.Join(g.backup.directory(r), "capture", "intent.json"), 4<<20)
	if err != nil {
		return err
	}
	want, _ := json.Marshal(legacyGroupRestoreReceipt{1, binding(r), sha(raw), "legacy-wrapper-group-before-activation"})
	dir := filepath.Join(g.backup.directory(r), "restoration")
	if err := ensurePrivateDirectory(dir); err != nil {
		return err
	}
	done := filepath.Join(dir, "group-completed.json")
	if got, err := readPrivate(done, 4096); err == nil {
		if !bytes.Equal(got, want) {
			return errors.New("legacy-group-restore-receipt-invalid")
		}
		intent, err := readPrivate(filepath.Join(dir, "intent.json"), 4096)
		if err != nil || !bytes.Equal(intent, want) {
			return errors.New("legacy-group-restore-receipt-invalid")
		}
		return g.restored(ctx, r, i.Installed)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := g.inspect(ctx, i.Installed, false); err != nil {
		return err
	}
	// Establish the ordinary rollback gate before changing any service state.
	if err := replacePrivateFile(filepath.Join(dir, "intent.json"), want, nil); err != nil {
		return err
	}
	w := legacyWrapperTransition{g.host}
	for _, member := range i.Installed.Wrappers {
		if err := w.restore(ctx, r, member.Name); err != nil {
			return err
		}
	}
	q := legacyComposeTransition{g.host}
	for _, member := range i.Installed.Sidecars {
		if err := q.restore(ctx, r, member.Name); err != nil {
			return err
		}
	}
	if err := g.agentRestored(ctx, i.Installed); err != nil {
		if err := g.host.restoreServices(ctx, agentOnly(i.Installed)); err != nil {
			return err
		}
	}
	if err := g.restored(ctx, r, i.Installed); err != nil {
		return err
	}
	return replacePrivateFile(done, want, nil)
}

func (g *legacyWrapperGroup) restored(ctx context.Context, r Request, i Installation) error {
	if err := g.inspect(ctx, i, false); err != nil {
		return err
	}
	w := legacyWrapperTransition{g.host}
	for _, member := range i.Wrappers {
		if err := w.restored(ctx, r, member.Name); err != nil {
			return err
		}
	}
	q := legacyComposeTransition{g.host}
	for _, member := range i.Sidecars {
		if err := q.restored(ctx, r, member.Name); err != nil {
			return err
		}
	}
	return g.agentRestored(ctx, i)
}

func (g *legacyWrapperGroup) agentRestored(ctx context.Context, i Installation) error {
	if err := g.inspectAgent(ctx, i); err != nil {
		return err
	}
	s := i.Services[0]
	if s.Kind == "native" {
		current, err := g.host.native(ctx, s)
		if err != nil || (current.MainPID > 0) != s.Running || (current.UnitFileState == "enabled") != s.Enabled {
			return errors.New("legacy-group-agent-not-restored")
		}
	} else {
		c, err := g.host.ownedContainer(ctx, s)
		if err != nil || (c.Status == "running") != s.Running || c.Restart != s.Restart || c.MaxRetries != s.MaxRetries {
			return errors.New("legacy-group-agent-not-restored")
		}
	}
	return nil
}
