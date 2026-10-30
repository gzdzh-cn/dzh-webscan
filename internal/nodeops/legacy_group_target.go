package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// A grouped capture is usable by a target driver only when the same private
// coordinator is attached. The durable capture and its digests retain every
// member; only explicitly Agent-only host operations use the returned view.
func (b *transitionBackup) targetGroup(i backupIntent) (*legacyWrapperGroup, error) {
	if !hasLegacyMembers(i.Installed) {
		return nil, nil
	}
	g, ok := b.host.(*legacyWrapperGroup)
	if !ok || g.backup != b || g.host.root != b.root || g.host.unitPath != b.unit || binding(g.request) != i.Binding || !i.Installed.valid(g.request.Node) {
		return nil, errors.New("legacy-group-target-coordinator-required")
	}
	if err := b.verifyWrapperMembers(g.request, i.Installed); err != nil {
		return nil, err
	}
	return g, nil
}

func (b *transitionBackup) transitionAgent(i backupIntent) (Installation, error) {
	if _, err := b.targetGroup(i); err != nil {
		return Installation{}, err
	}
	return agentOnly(i.Installed), nil
}

func (b *transitionBackup) groupDatabasePresent(i backupIntent) error {
	if i.DatabasePresent == nil {
		return errors.New("original-database-presence-unknown")
	}
	for _, name := range []string{"agent.sqlite3", "agent.sqlite3-wal", "agent.sqlite3-shm"} {
		if err := privateFile(filepath.Join(b.data, name), name != "agent.sqlite3" || !*i.DatabasePresent); err != nil {
			return err
		}
	}
	return nil
}

func (b *transitionBackup) restoreGroupBeforeTarget(ctx context.Context, r Request) (bool, error) {
	i, err := b.readIntent(ctx, r)
	if err != nil {
		return false, err
	}
	g, err := b.targetGroup(i)
	if err != nil || g == nil {
		return false, err
	}
	if _, err := os.Lstat(filepath.Join(b.directory(r), "activation")); os.IsNotExist(err) {
		return true, g.restoreBeforeActivation(ctx, r)
	} else if err != nil {
		return false, err
	}
	if _, err := os.Lstat(filepath.Join(b.directory(r), "activation/intent.json")); err != nil {
		return false, errors.New("legacy-group-activation-intent-missing")
	}
	return false, nil
}

func (b *transitionBackup) verifyGroupBeforeTarget(ctx context.Context, r Request) (bool, error) {
	handled, complete, err := b.reconcileGroupBeforeTarget(ctx, r)
	if err == nil && handled && !complete {
		err = errors.New("legacy-group-restore-not-completed")
	}
	return handled, err
}

func (b *transitionBackup) reconcileGroupBeforeTarget(ctx context.Context, r Request) (bool, bool, error) {
	i, err := b.readIntent(ctx, r)
	if err != nil {
		return false, false, err
	}
	g, err := b.targetGroup(i)
	if err != nil || g == nil {
		return false, false, err
	}
	if _, err := os.Lstat(filepath.Join(b.directory(r), "activation")); err == nil {
		return false, false, nil
	} else if !os.IsNotExist(err) {
		return false, false, err
	}
	for _, path := range []string{filepath.Join(b.directory(r), "finalized.json"), filepath.Join(b.root, "active.json")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return true, false, errors.New("legacy-group-target-recovery-required")
		}
	}
	if err := b.unchanged(ctx, i); err != nil {
		return true, false, err
	}
	if err := b.groupDatabasePresent(i); err != nil {
		return true, false, err
	}
	if err := g.inspect(ctx, i.Installed, false); err != nil {
		return true, false, err
	}
	raw, err := readPrivate(filepath.Join(b.directory(r), "capture/intent.json"), 4<<20)
	if err != nil {
		return true, false, err
	}
	want, _ := json.Marshal(legacyGroupRestoreReceipt{1, binding(r), sha(raw), "legacy-wrapper-group-before-activation"})
	for _, name := range []string{"intent.json", "group-completed.json"} {
		got, err := readPrivate(filepath.Join(b.directory(r), "restoration", name), 4096)
		if os.IsNotExist(err) {
			if name == "intent.json" {
				if _, err := os.Lstat(filepath.Join(b.directory(r), "restoration/group-completed.json")); !os.IsNotExist(err) {
					return true, false, errors.New("legacy-group-restore-receipt-invalid")
				}
			}
			return true, false, nil
		}
		if err != nil || !bytes.Equal(got, want) {
			return true, false, errors.New("legacy-group-restore-receipt-invalid")
		}
	}
	return true, true, g.restored(ctx, r, i.Installed)
}

func (b *transitionBackup) targetWrappersQuiescent(ctx context.Context, i backupIntent) error {
	g, err := b.targetGroup(i)
	if err != nil || g == nil {
		return err
	}
	return g.wrappersQuiescent(ctx, i.Installed)
}

func (b *transitionBackup) targetGroupRestored(ctx context.Context, i backupIntent) error {
	g, err := b.targetGroup(i)
	if err != nil || g == nil {
		return err
	}
	r := g.request
	r.Phase = "restore"
	started, err := g.resumeStarted(r, i)
	if err != nil || !started {
		return errors.New("legacy-group-resume-not-proven")
	}
	return g.restored(ctx, r, i.Installed)
}

func (g *legacyWrapperGroup) wrappersQuiescent(ctx context.Context, i Installation) error {
	if len(i.Sidecars) > 0 {
		return g.composeQuiescent(ctx, i)
	}
	members, err := g.backup.wrapperIntents(g.request, i)
	if err != nil || len(members) == 0 {
		return errors.New("legacy-group-member-not-proven")
	}
	for _, name := range append([]string{"webscan-agent-v1.service"}, legacyWrapperNames...) {
		if _, captured := members[name]; captured {
			continue
		}
		if _, err := os.Lstat(filepath.Join(filepath.Dir(g.host.unitPath), name)); !os.IsNotExist(err) {
			return errors.New("unrecorded-legacy-wrapper")
		}
	}
	w := legacyWrapperTransition{g.host}
	for _, m := range i.Wrappers {
		if err := w.quiescent(ctx, g.request, m.Name); err != nil {
			return err
		}
	}
	return nil
}

// Target identity is proved by the restore driver before calling the exporter.
// The original grouped host remains responsible for backup; export additionally
// proves all captured sidecars stopped while checking the target-only writer.
func (b *transitionBackup) rollbackStopped(ctx context.Context, r Request, current Installation) (bool, error) {
	if g, ok := b.host.(*legacyWrapperGroup); ok {
		i, err := b.readIntent(ctx, r)
		if err != nil {
			return false, err
		}
		if err := b.targetWrappersQuiescent(ctx, i); err != nil {
			return false, err
		}
		if hasLegacyMembers(current) {
			return g.stopped(ctx, current)
		}
		return g.host.stopped(ctx, current)
	}
	return b.host.stopped(ctx, current)
}

func (g *legacyWrapperGroup) resumeReceipt(r Request, i backupIntent) ([]byte, error) {
	if binding(r) != i.Binding || binding(r) != binding(g.request) || r.Phase != "restore" || r.Operation != "apply" {
		return nil, errors.New("invalid-legacy-group-request")
	}
	raw, err := readPrivate(filepath.Join(g.backup.directory(r), "capture/intent.json"), 4<<20)
	if err != nil {
		return nil, err
	}
	return json.Marshal(legacyGroupRestoreReceipt{1, binding(r), sha(raw), "legacy-wrapper-group-target-resume"})
}

func (g *legacyWrapperGroup) resumeStarted(r Request, i backupIntent) (bool, error) {
	want, err := g.resumeReceipt(r, i)
	if err != nil {
		return false, err
	}
	got, err := readPrivate(filepath.Join(g.backup.directory(r), "restoration/group-resume.json"), 4096)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !bytes.Equal(got, want) {
		return false, errors.New("legacy-group-resume-receipt-invalid")
	}
	return true, nil
}

// Caller proves the target retired, the original config/pointer restored and
// the live pending-event export durable before entering this boundary. Publish
// it before the first wrapper can read JSONL. A lost response then resumes the
// group without stopping it or exporting a database whose delivery has resumed.
func (g *legacyWrapperGroup) resumeOriginal(ctx context.Context, r Request, i backupIntent) error {
	want, err := g.resumeReceipt(r, i)
	if err != nil {
		return err
	}
	if err := g.backup.groupDatabasePresent(i); err != nil {
		return err
	}
	intent, err := readPrivate(filepath.Join(g.backup.directory(r), "restoration/intent.json"), 4096)
	if err != nil {
		return err
	}
	var exported nativeRestoreExport
	if _, err := decodePrivateJSON(filepath.Join(g.backup.directory(r), "restoration/export.json"), &exported, 4096); err != nil || exported.Format != 1 || exported.Binding != binding(r) || exported.RestoreSHA256 != sha(intent) || exported.Count < 0 {
		return errors.New("restoration-export-not-proven")
	}
	started, err := g.resumeStarted(r, i)
	if err != nil {
		return err
	}
	if !started {
		if err := g.wrappersQuiescent(ctx, i.Installed); err != nil {
			return err
		}
		stopped, err := g.host.stopped(ctx, agentOnly(i.Installed))
		if err != nil || !stopped {
			return errors.New("legacy-group-agent-not-quiescent")
		}
	}
	if err := g.inspect(ctx, i.Installed, false); err != nil {
		return err
	}
	if err := replacePrivateFile(filepath.Join(g.backup.directory(r), "restoration/group-resume.json"), want, nil); err != nil {
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
	return g.restored(ctx, r, i.Installed)
}

func originalEffectiveFile(path string, expected []byte) error {
	raw, err := readPrivate(path, 2<<20)
	if expected == nil && os.IsNotExist(err) {
		return nil
	}
	if err != nil || expected == nil || !bytes.Equal(raw, expected) {
		return errors.New("original-effective-file-not-restored")
	}
	return nil
}

func (b *transitionBackup) originalConfigurationRestored(ctx context.Context, i backupIntent) error {
	for _, f := range i.Files {
		if len(f.Path) > 7 && f.Path[:7] == "config/" {
			if err := verifyBackupFile(ctx, filepath.Join(filepath.Dir(i.Installed.Runtime), f.Path[7:]), f); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *nativeActivation) resumeGroup(ctx context.Context, r Request, p nativeRestorePlan) error {
	g, err := a.backup.targetGroup(p.original)
	if err != nil || g == nil {
		return errors.New("legacy-group-target-coordinator-required")
	}
	if err := originalEffectiveFile(a.host.unitPath, p.originalUnit); err != nil {
		return err
	}
	if err := originalEffectiveFile(filepath.Join(a.runtime.root, "active.json"), p.originalPointer); err != nil {
		return err
	}
	if err := a.backup.originalConfigurationRestored(ctx, p.original); err != nil {
		return err
	}
	s, target, oldPointer, err := a.restoreState(ctx, p)
	if err != nil || target || !oldPointer || s.NeedDaemonReload != "no" {
		return errors.New("legacy-group-target-not-retired")
	}
	if err := g.resumeOriginal(ctx, r, p.original); err != nil {
		return err
	}
	return a.confirmRestored(ctx, p)
}

func (a *dockerActivation) resumeGroup(ctx context.Context, r Request, p dockerRestorePlan) error {
	g, err := a.backup.targetGroup(p.original)
	if err != nil || g == nil {
		return errors.New("legacy-group-target-coordinator-required")
	}
	if err := originalEffectiveFile(filepath.Join(a.runtime.root, "active.json"), p.originalPointer); err != nil {
		return err
	}
	if err := a.backup.originalConfigurationRestored(ctx, p.original); err != nil {
		return err
	}
	old, target, err := a.restorationState(ctx, r, p)
	if err != nil || target != nil && (target.Name != "/"+p.failedName || target.Status == "running" || target.Restart != "no") || old != nil && old.Name != "/"+agentContainerName {
		return errors.New("legacy-group-target-not-retired")
	}
	if singleNativeOriginal(p.agent) {
		_, present, err := a.restorationNative(ctx, r, p, target)
		if err != nil || !present {
			return errors.New("original-unit-not-restored")
		}
	}
	if err := g.resumeOriginal(ctx, r, p.original); err != nil {
		return err
	}
	return a.confirmRestored(ctx, r, p)
}
