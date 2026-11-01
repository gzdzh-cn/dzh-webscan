package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"webscan/internal/nodeconfig"
)

// nativeActivation is an internal phase implementation. It is intentionally not
// exposed by LocalRuntime until restore, verification and finalization compose
// into a fully recoverable lifecycle.
type nativeActivation struct {
	runtime *LocalRuntime
	backup  *transitionBackup
	host    installationHost
}
type nativeActivationIntent struct {
	Format         int                `json:"format"`
	Binding        transitionBinding  `json:"binding"`
	CaptureSHA256  string             `json:"capture_sha256"`
	SnapshotSHA256 string             `json:"snapshot_sha256"`
	Target         ActiveInstallation `json:"target"`
	Unit           []byte             `json:"unit"`
}
type nativeActivationPlan struct {
	agent                                        Installation
	intent                                       nativeActivationIntent
	original                                     backupIntent
	retiredDocker                                string
	material                                     nodeconfig.Material
	unit, pointer, previousUnit, previousPointer []byte
	target                                       ServiceRecord
}

func newNativeActivation(w *LocalRuntime) *nativeActivation {
	host := newInstallationHost(w.root)
	backup := newTransitionBackup(w.root)
	return &nativeActivation{runtime: w, backup: backup, host: host}
}
func (a *nativeActivation) plan(ctx context.Context, r Request) (nativeActivationPlan, error) {
	var p nativeActivationPlan
	if r.Validate() != nil || r.Operation != "apply" || r.Phase != "activate" || r.Spec.Mode != "native" || a.runtime == nil || a.backup == nil || a.runtime.root != a.backup.root || a.host.root != a.runtime.root || a.host.unitPath != a.backup.unit {
		return p, errors.New("invalid-native-activation")
	}
	if err := a.runtime.verifyPrepared(ctx, r.Spec); err != nil {
		return p, err
	}
	if err := a.runtime.verifyConfiguration(ctx, r); err != nil {
		return p, err
	}
	m, err := a.runtime.configurationMaterial(ctx, r)
	if err != nil {
		return p, err
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
	if _, err := a.backup.verify(ctx, r); err != nil {
		return p, err
	}
	capture := filepath.Join(a.backup.directory(r), "capture")
	captureRaw, err := readPrivate(filepath.Join(capture, "intent.json"), 4<<20)
	if err != nil {
		return p, err
	}
	snapshotRaw, err := readPrivate(filepath.Join(a.backup.directory(r), "snapshot", "receipt.json"), 16<<20)
	if err != nil {
		return p, err
	}
	files, err := a.runtime.configurationFiles(m, r.Spec)
	if err != nil {
		return p, err
	}
	p.unit = files[nativeServiceName]
	target := ActiveInstallation{Reinstall: r.Reinstall, Format: 1, Node: r.Node, Spec: r.Spec, RuntimeSHA256: sha(files["runtime.json"]), DefinitionSHA256: sha(p.unit), Job: r.Job, PlanDigest: r.PlanDigest, CaptureSHA256: sha(captureRaw)}
	target = retainPriorPointerEncoding(a.intentPath(r), target)
	p.pointer, err = json.Marshal(target)
	if err != nil {
		return p, err
	}
	for _, file := range original.Files {
		if file.Path == "native.service" {
			p.previousUnit, err = readPrivate(filepath.Join(capture, file.Path), 64<<10)
		}
		if file.Path == "active.json" {
			p.previousPointer, err = readPrivate(filepath.Join(capture, file.Path), MaxRequestBytes)
		}
		if err != nil {
			return p, err
		}
	}
	p.target = ServiceRecord{Kind: "native", Name: nativeServiceName, ID: nativeServiceName, Proof: target.DefinitionSHA256, Running: true, Enabled: true, Program: filepath.Join(a.runtime.releaseDir(r.Spec), "webscan"), Configuration: filepath.Join(a.runtime.configurationDir(r.Spec), "runtime.json")}
	p.material = m
	p.original = original
	if original.Installed.Mode == "docker" {
		p.retiredDocker = retiredDockerName(r)
	}
	p.intent = nativeActivationIntent{Format: 1, Binding: binding(r), CaptureSHA256: sha(captureRaw), SnapshotSHA256: sha(snapshotRaw), Target: target, Unit: p.unit}
	if err := a.originalConfiguration(ctx, r, p); err != nil {
		return p, err
	}
	return p, nil
}

func (a *nativeActivation) originalConfiguration(ctx context.Context, r Request, p nativeActivationPlan) error {
	want, err := json.Marshal(p.intent)
	if err != nil {
		return err
	}
	intent, intentErr := readPrivate(a.intentPath(r), MaxRequestBytes)
	retirementAllowed := intentErr == nil && bytes.Equal(intent, want)
	for _, f := range p.original.Files {
		if !strings.HasPrefix(f.Path, "config/") {
			continue
		}
		path := filepath.Join(filepath.Dir(p.agent.Runtime), strings.TrimPrefix(f.Path, "config/"))
		if retirementAllowed && p.agent.Mode == "docker" && p.agent.Generation == "v2" && f.Path == "config/compose.yml" {
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				continue
			}
		}
		if err := verifyBackupFile(ctx, path, f); err != nil {
			return errors.New("original-configuration-changed")
		}
	}
	return nil
}
func (a *nativeActivation) intentPath(r Request) string {
	return filepath.Join(a.backup.directory(r), "activation", "intent.json")
}
func (a *nativeActivation) publishIntent(r Request, p nativeActivationPlan) error {
	dir := filepath.Dir(a.intentPath(r))
	if err := ensurePrivateDirectory(dir); err != nil {
		return err
	}
	raw, err := json.Marshal(p.intent)
	if err != nil {
		return err
	}
	return replacePrivateFile(a.intentPath(r), raw, nil)
}

// replacePrivateFile performs a checked atomic transition between explicitly
// permitted contents under service-operation.lock. It never chmods an existing
// file, follows a link, or overwrites an unrecognized configuration.
func replacePrivateFile(path string, want []byte, previous []byte) error {
	if err := directoryAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	raw, err := readPrivate(path, 2<<20)
	absent := os.IsNotExist(err)
	if err != nil && !absent {
		return err
	}
	if !absent && bytes.Equal(raw, want) {
		return syncDirectory(filepath.Dir(path))
	}
	if absent && previous != nil || !absent && (previous == nil || !bytes.Equal(raw, previous)) {
		return errors.New("effective-file-changed")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".native-switch-")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	_, err = file.Write(want)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if absent {
		err = renameNoReplace(temp, path)
	} else {
		current, readErr := readPrivate(path, 2<<20)
		if readErr != nil || !bytes.Equal(current, previous) {
			return errors.New("effective-file-changed")
		}
		err = os.Rename(temp, path)
	}
	if err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func allowedEffectiveFile(path string, target, previous []byte) (bool, bool, error) {
	raw, err := readPrivate(path, 2<<20)
	if os.IsNotExist(err) && previous == nil {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if bytes.Equal(raw, target) {
		return true, true, nil
	}
	if previous != nil && bytes.Equal(raw, previous) {
		return true, false, nil
	}
	return false, false, errors.New("effective-file-changed")
}
func (a *nativeActivation) state(ctx context.Context, p nativeActivationPlan) (nativeStatus, bool, error) {
	var empty nativeStatus
	if err := a.backup.targetWrappersQuiescent(ctx, p.original); err != nil {
		return empty, false, err
	}
	_, isTarget, err := allowedEffectiveFile(a.host.unitPath, p.unit, p.previousUnit)
	if err != nil {
		return empty, false, err
	}
	_, pointerTarget, err := allowedEffectiveFile(filepath.Join(a.runtime.root, "active.json"), p.pointer, p.previousPointer)
	if err != nil {
		return empty, false, err
	}
	raw, commandErr := a.host.command(ctx, "systemctl", "show", nativeServiceName, "--property=LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,Job,MainPID")
	status, err := decodeNativeStatus(raw, true, p.previousUnit == nil)
	if err != nil || commandErr != nil && status.LoadState != "not-found" {
		return empty, false, errors.New("native-service-state-unknown")
	}
	if status.LoadState == "loaded" && (status.FragmentPath != a.host.unitPath || status.UnitFileState != "enabled" && status.UnitFileState != "disabled") {
		return empty, false, errors.New("native-service-ownership-not-proven")
	}
	if err := a.host.nativeOriginalDockerStopped(ctx, p.agent, p.retiredDocker, status.MainPID > 0); err != nil {
		return empty, false, err
	}
	if status.MainPID > 0 {
		if err := a.backup.retireLegacyComposeForNative(ctx, p.original, a.host, false); err != nil {
			return empty, false, err
		}
	}
	if status.MainPID > 0 {
		if !isTarget || !pointerTarget || status.NeedDaemonReload != "no" {
			return empty, false, errors.New("unexpected-node-writer-active")
		}
		if err := a.host.proveRunningNativeProcess(status, p.target.Program, p.target.Configuration); err != nil {
			return empty, false, err
		}
		return status, true, nil
	}
	if !isTarget && status.UnitFileState == "enabled" {
		return empty, false, errors.New("original-service-not-disabled")
	}
	return status, false, nil
}
func (a *nativeActivation) run(ctx context.Context, r Request) error {
	if a.runtime == nil || a.backup == nil || r.Validate() != nil || r.Operation != "apply" || r.Phase != "activate" || r.Spec.Mode != "native" {
		return errors.New("invalid-native-activation")
	}
	ctx, release, err := acquireServiceOperation(ctx, a.runtime.root)
	if err != nil {
		return err
	}
	defer release()
	if a.backup.rollbackStarted(r) {
		return errors.New("rollback-already-started")
	}
	p, err := a.plan(ctx, r)
	if err != nil {
		return err
	}
	if err := a.publishIntent(r, p); err != nil {
		return err
	}
	status, running, err := a.state(ctx, p)
	if err != nil {
		return err
	}
	if running {
		if err := a.backup.verifyLegacyReconciliation(p.original, p.intent.SnapshotSHA256); err != nil {
			return err
		}
		if status.UnitFileState != "enabled" {
			if _, err := a.host.command(ctx, "systemctl", "enable", nativeServiceName); err != nil {
				return err
			}
		}
		return a.confirm(ctx, p)
	}
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
	if _, running, err := a.state(ctx, p); err != nil || running {
		if err != nil {
			return err
		}
		return errors.New("unexpected-node-writer-active")
	}
	if err := a.backup.reconcileLegacyLogsLocked(ctx, r); err != nil {
		return err
	}
	if err := a.host.retireDockerForNative(ctx, p.agent, p.retiredDocker); err != nil {
		return err
	}
	if err := a.backup.retireLegacyComposeForNative(ctx, p.original, a.host, true); err != nil {
		return err
	}
	for _, root := range r.Spec.MonitorDirectories {
		stat, err := os.Stat(root)
		if err != nil || !stat.IsDir() {
			return errors.New("monitor-directory-not-accessible")
		}
	}
	// Never mkdir a missing business directory as an installation side effect.
	probe := p.material.Settings.ProbeDirectory
	if err := directoryAncestors(filepath.Dir(probe)); err != nil {
		return err
	}
	if _, err := os.Lstat(probe); os.IsNotExist(err) {
		if err := os.Mkdir(probe, 0700); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := privateDirectoryTree(probe); err != nil {
		return err
	}
	if err := ensurePrivateDirectory(a.backup.logs); err != nil {
		return err
	}
	if err := replacePrivateFile(a.host.unitPath, p.unit, p.previousUnit); err != nil {
		return err
	}
	if err := replacePrivateFile(filepath.Join(a.runtime.root, "active.json"), p.pointer, p.previousPointer); err != nil {
		return err
	}
	if _, err := a.host.command(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	status, err = a.host.native(ctx, p.target)
	if err != nil {
		return err
	}
	if status.MainPID != 0 {
		return errors.New("unexpected-node-writer-active")
	}
	// Agent.New must acquire the same lifetime flock. Only the exact generated
	// service may be started after releasing it; no other writer is enabled.
	if err := a.backup.targetWrappersQuiescent(ctx, p.original); err != nil {
		return err
	}
	lock.Close()
	locked = false
	if _, err := a.host.command(ctx, "systemctl", "enable", nativeServiceName); err != nil {
		return err
	}
	if _, err := a.host.command(ctx, "systemctl", "start", nativeServiceName); err != nil {
		return err
	}
	return a.confirm(ctx, p)
}
func (a *nativeActivation) confirm(ctx context.Context, p nativeActivationPlan) error {
	if err := a.backup.verifyLegacyReconciliation(p.original, p.intent.SnapshotSHA256); err != nil {
		return err
	}
	_, running, err := a.state(ctx, p)
	if err != nil {
		return err
	}
	status, err := a.host.native(ctx, p.target)
	if err != nil {
		return err
	}
	if !running || status.UnitFileState != "enabled" {
		return errors.New("native-activation-not-confirmed")
	}
	return nil
}
