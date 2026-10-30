package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type dockerRestorePlan struct {
	agent                          Installation
	intent                         nativeRestoreIntent // common capture/snapshot/activation binding
	original                       backupIntent
	activation                     *dockerActivationIntent
	originalPointer, targetPointer []byte
	retiredName, failedName        string
}

func (a *dockerActivation) restoreDirectory(r Request) string {
	return filepath.Join(a.backup.directory(r), "restoration")
}

// Does not require intact target binaries, valid new certificates or live target
// configuration. A created receipt plus retained Docker ID proves what to stop.
func (a *dockerActivation) restorePlan(ctx context.Context, r Request) (dockerRestorePlan, error) {
	var p dockerRestorePlan
	if !a.valid(r, "restore") {
		return p, errors.New("invalid-docker-restore")
	}
	i, err := a.backup.readIntent(ctx, r)
	if err != nil {
		return p, err
	}
	p.agent, err = a.backup.transitionAgent(i)
	if err != nil {
		return p, err
	}
	if !supportedDockerOriginal(p.agent) {
		return p, errors.New("original-docker-transition-not-supported")
	}
	_, snapshot, err := a.backup.recoveryBase(ctx, r)
	if err != nil {
		return p, err
	}
	capture, err := readPrivate(filepath.Join(a.backup.directory(r), "capture/intent.json"), 4<<20)
	if err != nil {
		return p, err
	}
	p.original = i
	p.intent = nativeRestoreIntent{Format: 1, Binding: binding(r), CaptureSHA256: sha(capture), SnapshotSHA256: snapshot}
	p.failedName = "webscan-failed-" + sha([]byte(r.Node + "\x00" + r.Job + "\x00" + r.PlanDigest))[:24]
	for _, f := range i.Files {
		if f.Path == "active.json" {
			p.originalPointer, err = readPrivate(filepath.Join(a.backup.directory(r), "capture", f.Path), MaxRequestBytes)
			if err != nil {
				return p, err
			}
		}
	}
	if _, err := os.Lstat(a.intentPath(r)); os.IsNotExist(err) {
		return p, nil
	} else if err != nil {
		return p, err
	}
	var activation dockerActivationIntent
	raw, err := decodePrivateJSON(a.intentPath(r), &activation, MaxRequestBytes)
	t := activation.Target
	retired := "webscan-retired-" + sha([]byte(r.Node + "\x00" + r.Job + "\x00" + r.PlanDigest))[:24]
	if err != nil || activation.Format != 1 || activation.Binding != binding(r) || activation.CaptureSHA256 != p.intent.CaptureSHA256 || activation.SnapshotSHA256 != snapshot || t.Format != 1 || t.Node != r.Node || t.Job != r.Job || t.PlanDigest != r.PlanDigest || t.Spec.digest() != r.Spec.digest() || !validDigest(t.RuntimeSHA256) || !validDigest(t.DefinitionSHA256) || t.CaptureSHA256 != "" && t.CaptureSHA256 != activation.CaptureSHA256 || activation.RetiredName != retired || !strings.HasPrefix(activation.ImageID, "sha256:") || !validDigest(strings.TrimPrefix(activation.ImageID, "sha256:")) {
		return p, errors.New("activation-intent-mismatch")
	}
	p.intent.ActivationSHA256 = sha(raw)
	p.activation, p.retiredName = &activation, retired
	p.targetPointer, err = json.Marshal(t)
	return p, err
}

func (a *dockerActivation) restoredTarget(ctx context.Context, r Request, p dockerRestorePlan) (*containerIdentity, error) {
	task, err := a.host.taskContainer(ctx, ActiveInstallation{Node: r.Node, Job: r.Job, PlanDigest: r.PlanDigest})
	if err != nil {
		return nil, err
	}
	if task != nil && p.activation == nil {
		return nil, errors.New("unrecorded-task-container")
	}
	var receipt dockerCreatedReceipt
	if _, err := os.Lstat(a.createdPath(r)); os.IsNotExist(err) {
		c, err := a.host.containerNamed(ctx, agentContainerName)
		if err != nil {
			return nil, err
		}
		if c == nil {
			if task != nil {
				return nil, errors.New("task-container-name-changed")
			}
			return nil, nil
		}
		if len(p.agent.Services) > 0 && c.ID == p.agent.Services[0].ID {
			if task != nil {
				return nil, errors.New("task-container-name-changed")
			}
			return nil, nil
		}
		if task == nil || task.ID != c.ID {
			return nil, errors.New("task-container-identity-mismatch")
		}
		// A lost create response can precede its ID receipt. Adopt only a still
		// unstarted object proven against the intact staged definition and task.
		if p.activation == nil || c.Status != "created" || c.ImageID != p.activation.ImageID {
			return nil, errors.New("unrecorded-target-container")
		}
		if err := a.host.verifyV3Container(*c, p.activation.Target); err != nil {
			return nil, err
		}
		return c, nil
	} else if err != nil {
		return nil, err
	}
	if p.activation == nil {
		return nil, errors.New("created-receipt-without-activation")
	}
	if _, err := decodePrivateJSON(a.createdPath(r), &receipt, 4096); err != nil {
		return nil, err
	}
	if receipt.Format != 1 || receipt.Binding != binding(r) || receipt.ActivationSHA256 != p.intent.ActivationSHA256 || !validDigest(receipt.ID) || !validDigest(receipt.Proof) {
		return nil, errors.New("created-container-receipt-mismatch")
	}
	if task == nil || task.ID != receipt.ID {
		return nil, errors.New("recorded-target-container-missing")
	}
	c, err := a.host.container(ctx, receipt.ID)
	if err != nil {
		return nil, err
	}
	if c.fingerprint() != receipt.Proof || (c.Name != "/"+agentContainerName && c.Name != "/"+p.failedName) || (c.Restart != "no" && c.Restart != "unless-stopped") || c.MaxRetries != 0 || (c.Status != "running" && c.Status != "created" && c.Status != "exited") {
		return nil, errors.New("created-container-changed")
	}
	return &c, nil
}

func (a *dockerActivation) restorationState(ctx context.Context, r Request, p dockerRestorePlan) (*containerIdentity, *containerIdentity, error) {
	if _, _, err := allowedEffectiveFile(filepath.Join(a.runtime.root, "active.json"), p.targetPointer, p.originalPointer); err != nil {
		return nil, nil, err
	}
	var old *containerIdentity
	if singleDockerOriginal(p.agent) && len(p.agent.Services) > 0 {
		s := p.agent.Services[0]
		c, err := a.host.ownedContainer(ctx, s)
		if err != nil {
			return nil, nil, err
		}
		if c.Name != "/"+s.Name && (p.retiredName == "" || c.Name != "/"+p.retiredName) {
			return nil, nil, errors.New("original-container-name-changed")
		}
		old = &c
	}
	target, err := a.restoredTarget(ctx, r, p)
	if err != nil {
		return nil, nil, err
	}
	if old != nil && target != nil && target.Status == "running" && (old.Status == "running" || old.Restart != "no") {
		return nil, nil, errors.New("unexpected-original-writer")
	}
	// Prove all names before a stop or rename. A collision is never solved by
	// deleting the other object or asking Compose to replace it.
	for _, pair := range []struct{ name string }{
		{agentContainerName}, {p.retiredName}, {p.failedName},
	} {
		if pair.name == "" {
			continue
		}
		c, err := a.host.containerNamed(ctx, pair.name)
		if err != nil {
			return nil, nil, err
		}
		if c == nil {
			continue
		}
		valid := old != nil && c.ID == old.ID && (pair.name == agentContainerName || pair.name == p.retiredName) || target != nil && c.ID == target.ID && (pair.name == agentContainerName || pair.name == p.failedName)
		if !valid {
			return nil, nil, errors.New("restoration-container-name-in-use")
		}
	}
	if _, _, err := a.restorationNative(ctx, r, p, target); err != nil {
		return nil, nil, err
	}
	return old, target, nil
}

func (a *dockerActivation) restore(ctx context.Context, r Request) error {
	if !a.valid(r, "restore") {
		return errors.New("invalid-docker-restore")
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
	if err := ensurePrivateDirectory(a.restoreDirectory(r)); err != nil {
		return err
	}
	raw, err := json.Marshal(p.intent)
	if err != nil {
		return err
	}
	if err := replacePrivateFile(filepath.Join(a.restoreDirectory(r), "intent.json"), raw, nil); err != nil {
		return err
	}
	exportPath := filepath.Join(a.restoreDirectory(r), "export.json")
	var receipt nativeRestoreExport
	receiptPresent := false
	if _, err := os.Lstat(exportPath); err == nil {
		if _, err := decodePrivateJSON(exportPath, &receipt, 4096); err != nil || receipt.Format != 1 || receipt.Binding != binding(r) || receipt.RestoreSHA256 != sha(raw) || receipt.Count < 0 {
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
	old, target, err := a.restorationState(ctx, r, p)
	if err != nil {
		return err
	}
	if receiptPresent && (singleNativeOriginal(p.agent) && a.confirmRestored(ctx, r, p) == nil || old != nil && old.Status == "running" && old.Name == "/"+agentContainerName) {
		// The original already resumed. Do not stop it or rewrite exports just
		// because a prior successful SSH response was lost.
		return a.confirmRestored(ctx, r, p)
	}
	current := p.agent
	if singleNativeOriginal(p.agent) {
		_, present, err := a.restorationNative(ctx, r, p, target)
		if err != nil {
			return err
		}
		if present {
			if _, err := a.host.command(ctx, "systemctl", "daemon-reload"); err != nil {
				return err
			}
			if err := a.host.stop(ctx, p.agent); err != nil {
				return err
			}
		}
		// Missing retired units are not stoppable services. Both writers are proven
		// independently before exporting the live database with an absent inventory.
		current = Installation{Node: r.Node, Generation: "absent", Services: []ServiceRecord{}}
	}
	if target != nil {
		if err := a.recordCreated(r, dockerActivationPlan{intent: *p.activation}, *target); err != nil {
			return err
		}
		if old != nil && old.Status == "running" {
			return errors.New("unexpected-original-writer")
		}
		current = Installation{Node: r.Node, Generation: "v3", Mode: "docker", Runtime: filepath.Join(a.runtime.configurationDir(r.Spec), "runtime.json"), Services: []ServiceRecord{{Kind: "docker", Name: agentContainerName, ID: target.ID, Proof: target.fingerprint(), Running: true, Enabled: target.Restart != "no", Restart: target.Restart}}}
	}
	if err := a.host.stop(ctx, current); err != nil {
		return err
	}
	if old != nil {
		c, err := a.host.ownedContainer(ctx, p.agent.Services[0])
		if err != nil {
			return err
		}
		if c.Status == "running" || c.Restart != "no" {
			return errors.New("original-container-not-quiescent")
		}
	}
	if singleNativeOriginal(p.agent) {
		status, _, err := a.restorationNative(ctx, r, p, target)
		if err != nil {
			return err
		}
		if status.MainPID != 0 || status.UnitFileState == "enabled" {
			return errors.New("original-native-not-quiescent")
		}
	}
	count, err := a.backup.exportRollbackPending(ctx, r, current)
	if err != nil {
		return err
	}
	if !receiptPresent {
		payload, err := json.Marshal(nativeRestoreExport{1, binding(r), sha(raw), count})
		if err != nil {
			return err
		}
		if err := replacePrivateFile(exportPath, payload, nil); err != nil {
			return err
		}
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
	old, target, err = a.restorationState(ctx, r, p)
	if err != nil {
		return err
	}
	for _, c := range []*containerIdentity{old, target} {
		if c != nil && (c.Status == "running" || c.Restart != "no") {
			return errors.New("node-writers-not-stopped")
		}
	}
	if singleNativeOriginal(p.agent) {
		status, _, err := a.restorationNative(ctx, r, p, target)
		if err != nil {
			return err
		}
		if status.MainPID != 0 || status.UnitFileState == "enabled" {
			return errors.New("node-writers-not-stopped")
		}
	}
	// Only captured original config files are restored. The shared copier
	// never reads or replaces the current Agent database.
	if err := a.backup.restoreOriginalConfiguration(ctx, r, p.original); err != nil {
		return err
	}
	if target != nil && target.Name == "/"+agentContainerName {
		if _, err := a.host.docker(ctx, "rename", target.ID, p.failedName); err != nil {
			return err
		}
	}
	if old != nil && old.Name != "/"+agentContainerName {
		if _, err := a.host.docker(ctx, "rename", old.ID, agentContainerName); err != nil {
			return err
		}
	}
	pointer := filepath.Join(a.runtime.root, "active.json")
	if p.originalPointer == nil {
		if err := removeExpectedPrivate(pointer, p.targetPointer); err != nil {
			return err
		}
	} else if err := replacePrivateFile(pointer, p.originalPointer, p.targetPointer); err != nil {
		return err
	}
	if singleNativeOriginal(p.agent) {
		if err := a.restoreNativeUnit(ctx, r, p); err != nil {
			return err
		}
		if _, err := a.host.command(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
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
	return a.confirmRestored(ctx, r, p)
}

func (a *dockerActivation) confirmRestored(ctx context.Context, r Request, p dockerRestorePlan) error {
	if err := a.backup.targetGroupRestored(ctx, p.original); err != nil {
		return err
	}
	for _, f := range p.original.Files {
		if strings.HasPrefix(f.Path, "config/") {
			if err := verifyBackupFile(ctx, filepath.Join(filepath.Dir(p.agent.Runtime), strings.TrimPrefix(f.Path, "config/")), f); err != nil {
				return errors.New("original-configuration-changed")
			}
		}
	}
	raw, err := readPrivate(filepath.Join(a.runtime.root, "active.json"), MaxRequestBytes)
	if p.originalPointer == nil {
		if !os.IsNotExist(err) {
			return errors.New("original-pointer-not-restored")
		}
	} else if err != nil || !bytes.Equal(raw, p.originalPointer) {
		return errors.New("original-pointer-not-restored")
	}
	old, target, err := a.restorationState(ctx, r, p)
	if err != nil {
		return err
	}
	if target != nil && (target.Name != "/"+p.failedName || target.Status == "running" || target.Restart != "no") {
		return errors.New("target-container-not-retired")
	}
	if singleNativeOriginal(p.agent) {
		status, present, err := a.restorationNative(ctx, r, p, target)
		if err != nil {
			return err
		}
		s := p.agent.Services[0]
		if !present || status.LoadState != "loaded" || status.NeedDaemonReload != "no" || (status.MainPID > 0) != s.Running || (status.UnitFileState == "enabled") != s.Enabled {
			return errors.New("original-native-not-restored")
		}
		if err := a.host.proveRunningNativeProcess(status, s.Program, s.Configuration); err != nil {
			return err
		}
	}
	if old != nil {
		s := p.agent.Services[0]
		if old.Name != "/"+s.Name || (old.Status == "running") != s.Running || old.Restart != s.Restart || old.MaxRetries != s.MaxRetries {
			return errors.New("original-container-not-restored")
		}
	}
	return nil
}
