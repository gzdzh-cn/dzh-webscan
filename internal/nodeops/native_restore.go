package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type nativeRestoreIntent struct {
	Format           int               `json:"format"`
	Binding          transitionBinding `json:"binding"`
	CaptureSHA256    string            `json:"capture_sha256"`
	SnapshotSHA256   string            `json:"snapshot_sha256"`
	ActivationSHA256 string            `json:"activation_sha256,omitempty"`
}
type nativeRestoreExport struct {
	Format        int               `json:"format"`
	Binding       transitionBinding `json:"binding"`
	RestoreSHA256 string            `json:"restore_sha256"`
	Count         int64             `json:"count"`
}
type nativeRestorePlan struct {
	agent                                                    Installation
	intent                                                   nativeRestoreIntent
	original                                                 backupIntent
	originalUnit, originalPointer, targetUnit, targetPointer []byte
	target                                                   *ServiceRecord
	retiredDocker                                            string
}

func (a *nativeActivation) restorePlan(ctx context.Context, r Request) (nativeRestorePlan, error) {
	var p nativeRestorePlan
	if r.Validate() != nil || r.Operation != "apply" || r.Phase != "restore" || r.Spec.Mode != "native" || a.runtime == nil || a.backup == nil || a.runtime.root != a.backup.root || a.host.root != a.runtime.root || a.host.unitPath != a.backup.unit {
		return p, errors.New("invalid-native-restore")
	}
	original, err := a.backup.readIntent(ctx, r)
	if err != nil {
		return p, err
	}
	p.agent, err = a.backup.transitionAgent(original)
	if err != nil {
		return p, err
	}
	if !supportedNativeOriginal(p.agent) {
		return p, errors.New("original-native-transition-not-supported")
	}
	_, snapshotDigest, err := a.backup.recoveryBase(ctx, r)
	if err != nil {
		return p, err
	}
	capture := filepath.Join(a.backup.directory(r), "capture")
	captureRaw, err := readPrivate(filepath.Join(capture, "intent.json"), 4<<20)
	if err != nil {
		return p, err
	}
	p.original = original
	p.intent = nativeRestoreIntent{Format: 1, Binding: binding(r), CaptureSHA256: sha(captureRaw), SnapshotSHA256: snapshotDigest}
	for _, file := range original.Files {
		if file.Path == "native.service" {
			p.originalUnit, err = readPrivate(filepath.Join(capture, file.Path), 64<<10)
		}
		if file.Path == "active.json" {
			p.originalPointer, err = readPrivate(filepath.Join(capture, file.Path), MaxRequestBytes)
		}
		if err != nil {
			return p, err
		}
	}
	activationPath := a.intentPath(r)
	if _, err := os.Lstat(activationPath); os.IsNotExist(err) {
		return p, nil
	} else if err != nil {
		return p, err
	}
	var activation nativeActivationIntent
	raw, err := decodePrivateJSON(activationPath, &activation, MaxRequestBytes)
	target := activation.Target
	if err != nil || activation.Format != 1 || activation.Binding != binding(r) || activation.CaptureSHA256 != p.intent.CaptureSHA256 || activation.SnapshotSHA256 != p.intent.SnapshotSHA256 || target.Format != 1 || target.Node != r.Node || target.Job != r.Job || target.PlanDigest != r.PlanDigest || target.Spec.digest() != r.Spec.digest() || !validDigest(target.RuntimeSHA256) || !validDigest(target.DefinitionSHA256) || target.CaptureSHA256 != "" && target.CaptureSHA256 != activation.CaptureSHA256 || len(activation.Unit) > 64<<10 || sha(activation.Unit) != target.DefinitionSHA256 {
		return p, errors.New("activation-intent-mismatch")
	}
	p.intent.ActivationSHA256 = sha(raw)
	if original.Installed.Mode == "docker" {
		p.retiredDocker = retiredDockerName(r)
	}
	// An activation intent binds the unit hash. Restoration must not require an
	// intact new binary, unexpired new certificate or valid new runtime: damage
	// there may be precisely why the operator requested rollback.
	p.targetUnit = activation.Unit
	p.targetPointer, err = json.Marshal(target)
	if err != nil {
		return p, err
	}
	p.target = &ServiceRecord{Kind: "native", Name: nativeServiceName, ID: nativeServiceName, Proof: target.DefinitionSHA256, Program: filepath.Join(a.runtime.releaseDir(r.Spec), "webscan"), Configuration: filepath.Join(a.runtime.configurationDir(r.Spec), "runtime.json"), Running: true, Enabled: true}
	return p, nil
}
func (a *nativeActivation) restoreDirectory(r Request) string {
	return filepath.Join(a.backup.directory(r), "restoration")
}
func (a *nativeActivation) restoreIntent(r Request, p nativeRestorePlan) ([]byte, error) {
	dir := a.restoreDirectory(r)
	if err := ensurePrivateDirectory(dir); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(p.intent)
	if err != nil {
		return nil, err
	}
	if err := replacePrivateFile(filepath.Join(dir, "intent.json"), raw, nil); err != nil {
		return nil, err
	}
	return raw, nil
}
func (a *nativeActivation) restoreState(ctx context.Context, p nativeRestorePlan) (nativeStatus, bool, bool, error) {
	var empty nativeStatus
	unit, err := readPrivate(a.host.unitPath, 64<<10)
	unitAbsent := os.IsNotExist(err)
	if err != nil && !unitAbsent {
		return empty, false, false, err
	}
	oldUnit := p.originalUnit != nil && !unitAbsent && bytes.Equal(unit, p.originalUnit)
	newUnit := p.targetUnit != nil && !unitAbsent && bytes.Equal(unit, p.targetUnit)
	if !oldUnit && !newUnit && !(unitAbsent && p.originalUnit == nil) {
		return empty, false, false, errors.New("effective-unit-changed")
	}
	pointer, err := readPrivate(filepath.Join(a.runtime.root, "active.json"), MaxRequestBytes)
	pointerAbsent := os.IsNotExist(err)
	if err != nil && !pointerAbsent {
		return empty, false, false, err
	}
	oldPointer := pointerAbsent && p.originalPointer == nil || !pointerAbsent && p.originalPointer != nil && bytes.Equal(pointer, p.originalPointer)
	newPointer := !pointerAbsent && p.targetPointer != nil && bytes.Equal(pointer, p.targetPointer)
	if !oldPointer && !newPointer {
		return empty, false, false, errors.New("effective-pointer-changed")
	}
	raw, commandErr := a.host.command(ctx, "systemctl", "show", nativeServiceName, "--property=LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,Job,MainPID")
	status, err := decodeNativeStatus(raw, true, p.originalUnit == nil)
	if err != nil || commandErr != nil && status.LoadState != "not-found" {
		return empty, false, false, errors.New("native-service-state-unknown")
	}
	if status.LoadState == "loaded" && (status.FragmentPath != a.host.unitPath || status.UnitFileState != "enabled" && status.UnitFileState != "disabled") {
		return empty, false, false, errors.New("native-service-ownership-not-proven")
	}
	oldDocker, err := a.host.nativeOriginalDocker(ctx, p.agent, p.retiredDocker)
	if err != nil {
		return empty, false, false, err
	}
	if oldDocker != nil {
		original := p.agent.Services[0]
		// Policy/start responses may be lost after the original pointer and unit
		// were restored. A Docker writer is allowed only at that exact boundary.
		boundary := oldPointer && unitAbsent && status.MainPID == 0 && oldDocker.Name == "/"+original.Name
		if (oldDocker.Status == "running" || oldDocker.Restart != "no") && !boundary || oldDocker.Status == "running" && !original.Running || oldDocker.Restart != "no" && (oldDocker.Restart != original.Restart || oldDocker.MaxRetries != original.MaxRetries) {
			return empty, false, false, errors.New("unexpected-original-docker-writer")
		}
	}
	if status.MainPID > 0 {
		// An identical old/new unit (same release+config) is only unambiguous after
		// considering the active pointer, not a preference for one hash branch.
		if oldUnit && oldPointer {
			if len(p.agent.Services) != 1 {
				return empty, false, false, errors.New("original-service-proof-unavailable")
			}
			s := p.agent.Services[0]
			if err := a.host.proveNativeProcess(status, s.Program, s.Configuration); err != nil {
				return empty, false, false, err
			}
		} else if newUnit && newPointer && p.target != nil {
			if err := a.host.proveNativeProcess(status, p.target.Program, p.target.Configuration); err != nil {
				return empty, false, false, err
			}
		} else {
			return empty, false, false, errors.New("unexpected-node-writer-active")
		}
	}
	return status, newUnit && !oldUnit, oldPointer, nil
}
func (a *nativeActivation) restore(ctx context.Context, r Request) error {
	if a.runtime == nil || a.backup == nil || r.Validate() != nil || r.Operation != "apply" || r.Phase != "restore" || r.Spec.Mode != "native" {
		return errors.New("invalid-native-restore")
	}
	ctx, release, err := acquireServiceOperation(ctx, a.runtime.root)
	if err != nil {
		return err
	}
	defer release()
	if handled, err := a.backup.restoreGroupBeforeTarget(ctx, r); err != nil || handled {
		return err
	}
	p, err := a.restorePlan(ctx, r)
	if err != nil {
		return err
	}
	raw, err := a.restoreIntent(r, p)
	if err != nil {
		return err
	}
	exportPath := filepath.Join(a.restoreDirectory(r), "export.json")
	var exported nativeRestoreExport
	receiptPresent := false
	if _, err := os.Lstat(exportPath); err == nil {
		if _, err := decodePrivateJSON(exportPath, &exported, 4096); err != nil || exported.Format != 1 || exported.Binding != binding(r) || exported.RestoreSHA256 != sha(raw) || exported.Count < 0 {
			return errors.New("restore-export-receipt-mismatch")
		}
		receiptPresent = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if g, err := a.backup.targetGroup(p.original); err != nil {
		return err
	} else if g != nil {
		started, err := g.resumeStarted(r, p.original)
		if err != nil {
			return err
		}
		if started {
			if !receiptPresent {
				return errors.New("restoration-export-not-proven")
			}
			return a.resumeGroup(ctx, r, p)
		}
		if err := g.wrappersQuiescent(ctx, p.original.Installed); err != nil {
			return err
		}
	}
	status, isTarget, oldPointer, err := a.restoreState(ctx, p)
	if err != nil {
		return err
	}
	// Once the original service was started, do not stop it again just because
	// the SSH response/phase receipt was lost. Data processing may have resumed.
	if receiptPresent && !isTarget && oldPointer && status.MainPID > 0 {
		return a.confirmRestored(ctx, p)
	}
	if receiptPresent && p.agent.Mode == "docker" && a.confirmRestored(ctx, p) == nil {
		return nil
	}
	current := p.agent
	if isTarget {
		if p.target == nil {
			return errors.New("target-service-proof-unavailable")
		}
		current = Installation{Node: r.Node, Generation: "v3", Mode: "native", Runtime: p.target.Configuration, Services: []ServiceRecord{*p.target}}
	}
	if len(current.Services) > 0 {
		if _, err := a.host.command(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := a.host.stop(ctx, current); err != nil {
			return err
		}
	} else if status.MainPID != 0 || status.UnitFileState == "enabled" {
		return errors.New("unexpected-node-writer-active")
	}
	// An export receipt is not evidence that its JSONL still exists. Before
	// restarting a stopped original, reread current pending events and verify/
	// recreate their content-addressed logs. A corrupt existing file fails closed.
	// Once the original is already running, the early branch above avoids this
	// rewrite because delivery/retention may legitimately have resumed.
	count, err := a.backup.exportRollbackPending(ctx, r, current)
	if err != nil {
		return err
	}
	if !receiptPresent {
		exported = nativeRestoreExport{Format: 1, Binding: binding(r), RestoreSHA256: sha(raw), Count: count}
		bytes, err := json.Marshal(exported)
		if err != nil {
			return err
		}
		if err := replacePrivateFile(exportPath, bytes, nil); err != nil {
			return err
		}
	}
	// Files can be changed only with no writer, even when the export receipt was
	// already durable. This also rejects a foreign process acquiring agent.lock.
	lock, err := a.backup.agentLock()
	if err != nil {
		return err
	}
	locked := true
	defer func() {
		if locked {
			lock.Close()
		}
	}()
	status, _, _, err = a.restoreState(ctx, p)
	if err != nil {
		return err
	}
	if status.MainPID != 0 {
		return errors.New("unexpected-node-writer-active")
	}
	if err := a.host.nativeOriginalDockerStopped(ctx, p.agent, p.retiredDocker, false); err != nil {
		return err
	}
	if err := a.backup.restoreOriginalConfiguration(ctx, r, p.original); err != nil {
		return err
	}
	if p.originalUnit == nil {
		if err := removeExpectedPrivate(a.host.unitPath, p.targetUnit); err != nil {
			return err
		}
	} else if err := replacePrivateFile(a.host.unitPath, p.originalUnit, p.targetUnit); err != nil {
		return err
	}
	if err := a.host.restoreDockerNameForNative(ctx, p.agent, p.retiredDocker); err != nil {
		return err
	}
	pointerPath := filepath.Join(a.runtime.root, "active.json")
	if p.originalPointer == nil {
		if err := removeExpectedPrivate(pointerPath, p.targetPointer); err != nil {
			return err
		}
	} else if err := replacePrivateFile(pointerPath, p.originalPointer, p.targetPointer); err != nil {
		return err
	}
	if _, err := a.host.command(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	lock.Close()
	locked = false
	if g, err := a.backup.targetGroup(p.original); err != nil {
		return err
	} else if g != nil {
		return a.resumeGroup(ctx, r, p)
	}
	if err := a.host.restoreServices(ctx, p.agent); err != nil {
		return err
	}
	return a.confirmRestored(ctx, p)
}
func removeExpectedPrivate(path string, expected []byte) error {
	raw, err := readPrivate(path, 2<<20)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if expected == nil || !bytes.Equal(raw, expected) {
		return errors.New("effective-file-changed")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func (b *transitionBackup) restoreOriginalConfiguration(ctx context.Context, r Request, original backupIntent) error {
	for _, f := range original.Files {
		if len(f.Path) < 7 || f.Path[:7] != "config/" {
			continue
		}
		destination := filepath.Join(filepath.Dir(original.Installed.Runtime), f.Path[7:])
		if _, err := os.Lstat(destination); err == nil {
			if err := verifyBackupFile(ctx, destination, f); err != nil {
				return errors.New("original-configuration-changed")
			}
		} else if os.IsNotExist(err) {
			if err := ensurePrivateDirectory(filepath.Dir(destination)); err != nil {
				return err
			}
			source := filepath.Join(b.directory(r), "capture", f.Path)
			if err := restoreCapturedFile(ctx, source, destination, f); err != nil {
				return errors.New("original-configuration-restore-failed")
			}
		} else {
			return err
		}
	}
	return nil
}

// Only publish a complete verified configuration. A killed copy may leave a
// private staging directory, never a partial file at the active pathname.
// Replays must also refuse a path created by another writer in the meantime.
func restoreCapturedFile(ctx context.Context, source, destination string, expected backupFile) error {
	stage, err := os.MkdirTemp(filepath.Dir(destination), ".config-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	temporary := filepath.Join(stage, "file")
	got, err := copyBackupFile(ctx, source, temporary, expected.Path, expected.Bytes)
	if err != nil || got != expected {
		return errors.New("captured-configuration-copy-failed")
	}
	if err := syncDirectory(stage); err != nil {
		return err
	}
	if err := renameNoReplace(temporary, destination); err != nil {
		return err
	}
	if err := syncDirectory(stage); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}
func (a *nativeActivation) confirmRestored(ctx context.Context, p nativeRestorePlan) error {
	if err := a.backup.targetGroupRestored(ctx, p.original); err != nil {
		return err
	}
	for _, file := range p.original.Files {
		if len(file.Path) > 7 && file.Path[:7] == "config/" {
			path := filepath.Join(filepath.Dir(p.agent.Runtime), file.Path[7:])
			if err := verifyBackupFile(ctx, path, file); err != nil {
				return errors.New("original-configuration-changed")
			}
		}
	}
	status, isTarget, oldPointer, err := a.restoreState(ctx, p)
	if err != nil {
		return err
	}
	if isTarget || !oldPointer {
		return errors.New("native-restore-not-confirmed")
	}
	if p.agent.Mode == "docker" {
		if status.MainPID != 0 || status.UnitFileState == "enabled" || status.NeedDaemonReload != "no" {
			return errors.New("native-target-not-disabled")
		}
		return a.host.nativeOriginalDockerRestored(ctx, p.agent, p.retiredDocker)
	}
	if len(p.agent.Services) == 0 {
		if status.MainPID != 0 || status.UnitFileState == "enabled" {
			return errors.New("native-restore-not-confirmed")
		}
		return nil
	}
	service := p.agent.Services[0]
	if err := a.host.proveRunningNativeProcess(status, service.Program, service.Configuration); err != nil {
		return err
	}
	if (status.MainPID > 0) != service.Running || (status.UnitFileState == "enabled") != service.Enabled || status.NeedDaemonReload != "no" {
		return errors.New("native-restore-not-confirmed")
	}
	return nil
}
