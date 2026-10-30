package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func singleNativeOriginal(i Installation) bool {
	return !hasLegacyMembers(i) && i.Mode == "native" && len(i.Services) == 1 && i.Services[0].Kind == "native" && i.Services[0].Name == nativeServiceName
}
func supportedDockerOriginal(i Installation) bool {
	return singleDockerOriginal(i) || singleNativeOriginal(i)
}

// The captured unit, not a reusable service name, authorizes retirement. A
// missing live unit is valid only after this task's activation intent is proven.
func (a *dockerActivation) originalNative(ctx context.Context, r Request, i backupIntent, authorized bool) (nativeStatus, bool, error) {
	var empty nativeStatus
	agent, err := a.backup.transitionAgent(i)
	if err != nil || !singleNativeOriginal(agent) {
		return empty, false, errors.New("original-native-not-supported")
	}
	var captured *backupFile
	for _, f := range i.Files {
		if f.Path == "native.service" {
			copy := f
			captured = &copy
		}
	}
	if captured == nil || captured.SHA256 != i.Installed.Services[0].Proof {
		return empty, false, errors.New("original-unit-not-captured")
	}
	source := filepath.Join(a.backup.directory(r), "capture/native.service")
	if err := verifyBackupFile(ctx, source, *captured); err != nil {
		return empty, false, err
	}
	unit, err := readPrivate(a.host.unitPath, 64<<10)
	present := !os.IsNotExist(err)
	if err != nil && present {
		return empty, false, err
	}
	if !present && !authorized {
		return empty, false, errors.New("unrecorded-unit-retirement")
	}
	if present && sha(unit) != captured.SHA256 {
		return empty, false, errors.New("original-unit-changed")
	}
	if present {
		if err := verifyBackupFile(ctx, a.host.unitPath, *captured); err != nil {
			return empty, false, err
		}
	}
	raw, commandErr := a.host.command(ctx, "systemctl", "show", nativeServiceName, "--property=LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,Job,MainPID")
	status, err := decodeNativeStatus(raw, true, true)
	if err != nil || commandErr != nil && status.LoadState != "not-found" {
		return empty, false, errors.New("native-service-state-unknown")
	}
	if status.LoadState == "loaded" && (status.FragmentPath != a.host.unitPath || status.UnitFileState != "enabled" && status.UnitFileState != "disabled") {
		return empty, false, errors.New("native-service-ownership-not-proven")
	}
	if !present && (status.MainPID != 0 || status.UnitFileState == "enabled") || present && status.LoadState != "loaded" && !authorized {
		return empty, false, errors.New("native-unit-manager-mismatch")
	}
	s := i.Installed.Services[0]
	if err := a.host.proveNativeProcess(status, s.Program, s.Configuration); err != nil {
		return empty, false, err
	}
	return status, present, nil
}
func (a *dockerActivation) nativeRetirementAuthorized(r Request, p dockerActivationPlan) (bool, error) {
	if _, err := os.Lstat(a.intentPath(r)); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	raw, err := readPrivate(a.intentPath(r), MaxRequestBytes)
	if err != nil {
		return false, err
	}
	want, err := json.Marshal(p.intent)
	if err != nil || !bytes.Equal(raw, want) {
		return false, errors.New("activation-intent-not-proven")
	}
	return true, nil
}
func (a *dockerActivation) nativeOriginalStopped(ctx context.Context, r Request, p dockerActivationPlan, retired bool) error {
	if !singleNativeOriginal(p.agent) {
		return nil
	}
	authorized, err := a.nativeRetirementAuthorized(r, p)
	if err != nil {
		return err
	}
	status, present, err := a.originalNative(ctx, r, p.original, authorized)
	if err != nil {
		return err
	}
	if status.MainPID != 0 || status.UnitFileState == "enabled" {
		return errors.New("original-native-not-quiescent")
	}
	if retired && (present || status.LoadState != "not-found" || status.NeedDaemonReload != "no") {
		return errors.New("original-native-not-retired")
	}
	return nil
}
func (a *dockerActivation) retireNative(ctx context.Context, r Request, p dockerActivationPlan) error {
	if !singleNativeOriginal(p.agent) {
		return nil
	}
	if err := a.nativeOriginalStopped(ctx, r, p, false); err != nil {
		return err
	}
	raw, err := readPrivate(filepath.Join(a.backup.directory(r), "capture/native.service"), 64<<10)
	if err != nil {
		return err
	}
	if err := removeExpectedPrivate(a.host.unitPath, raw); err != nil {
		return err
	}
	if _, err := a.host.command(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	return a.nativeOriginalStopped(ctx, r, p, true)
}

func (a *dockerActivation) restoreNativeUnit(ctx context.Context, r Request, p dockerRestorePlan) error {
	if !singleNativeOriginal(p.agent) {
		return nil
	}
	for _, f := range p.original.Files {
		if f.Path != "native.service" {
			continue
		}
		if _, err := os.Lstat(a.host.unitPath); os.IsNotExist(err) {
			return restoreCapturedFile(ctx, filepath.Join(a.backup.directory(r), "capture", f.Path), a.host.unitPath, f)
		} else if err != nil {
			return err
		}
		return verifyBackupFile(ctx, a.host.unitPath, f)
	}
	return errors.New("original-unit-not-captured")
}

// A resumed original is legitimate only after both the original pointer and
// unit have been restored and the target cannot restart. This covers a lost
// systemctl start/enable reply without accepting simultaneous writers.
func (a *dockerActivation) restorationNative(ctx context.Context, r Request, p dockerRestorePlan, target *containerIdentity) (nativeStatus, bool, error) {
	var empty nativeStatus
	if !singleNativeOriginal(p.agent) {
		return empty, false, nil
	}
	status, present, err := a.originalNative(ctx, r, p.original, p.activation != nil)
	if err != nil {
		return empty, false, err
	}
	pointer, err := readPrivate(filepath.Join(a.runtime.root, "active.json"), MaxRequestBytes)
	oldPointer := os.IsNotExist(err) && p.originalPointer == nil || err == nil && p.originalPointer != nil && bytes.Equal(pointer, p.originalPointer)
	if err != nil && !os.IsNotExist(err) {
		return empty, false, err
	}
	boundary := oldPointer && present && (target == nil || target.Name == "/"+p.failedName && target.Status != "running" && target.Restart == "no")
	original := p.agent.Services[0]
	if (status.MainPID > 0 || status.UnitFileState == "enabled") && !boundary || status.MainPID > 0 && !original.Running || status.UnitFileState == "enabled" && !original.Enabled {
		return empty, false, errors.New("unexpected-original-native-writer")
	}
	return status, present, nil
}
