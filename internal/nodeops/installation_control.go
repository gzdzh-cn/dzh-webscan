package nodeops

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

func (h installationHost) native(ctx context.Context, s ServiceRecord) (nativeStatus, error) {
	var empty nativeStatus
	unit, err := readPrivate(h.unitPath, 64<<10)
	if err != nil || sha(unit) != s.Proof {
		return empty, errors.New("native-unit-changed")
	}
	raw, err := h.command(ctx, "systemctl", "show", nativeServiceName, "--property=LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,Job,MainPID")
	if err != nil {
		return empty, err
	}
	status, err := parseNativeStatus(raw)
	if err != nil || status.FragmentPath != h.unitPath {
		return empty, errors.New("native-service-ownership-not-proven")
	}
	if err := h.proveNativeProcess(status, s.Program, s.Configuration); err != nil {
		return empty, err
	}
	if status.UnitFileState != "enabled" && status.UnitFileState != "disabled" {
		return empty, errors.New("native-service-enable-state-unknown")
	}
	return status, nil
}

func (h installationHost) proveNativeProcess(status nativeStatus, program, configuration string) error {
	return h.nativeProcess(status, program, configuration, true)
}

// An unlinked executable is sufficient ownership evidence to stop a damaged
// writer during recovery. It is never evidence of a healthy installed target.
func (h installationHost) proveRunningNativeProcess(status nativeStatus, program, configuration string) error {
	return h.nativeProcess(status, program, configuration, false)
}

func (h installationHost) nativeProcess(status nativeStatus, program, configuration string, allowDeleted bool) error {
	if status.MainPID == 0 {
		return nil
	}
	if h.processExecutable == nil || h.processArguments == nil {
		return errors.New("native-process-proof-unavailable")
	}
	executable, err := h.processExecutable(status.MainPID)
	if err != nil || executable != program && !(allowDeleted && executable == program+" (deleted)") {
		return errors.New("native-running-program-mismatch")
	}
	arguments, err := h.processArguments(status.MainPID)
	if err != nil || !equalStrings(arguments, []string{program, "agent", "--config", configuration}) {
		return errors.New("native-running-configuration-mismatch")
	}
	return nil
}

func (h installationHost) ownedContainer(ctx context.Context, s ServiceRecord) (containerIdentity, error) {
	c, err := h.container(ctx, s.ID)
	if err != nil || c.fingerprint() != s.Proof || !validRestart(c.Restart) || c.MaxRetries < 0 || (c.Status != "running" && c.Status != "exited" && c.Status != "created") {
		return c, errors.New("owned-container-changed")
	}
	return c, nil
}

// stop changes only previously proven services. Docker operations use the
// immutable ID captured before intent publication, never a reusable name. No
// command here removes data, containers, images, Docker or unrelated services.
func (h installationHost) stop(ctx context.Context, i Installation) error {
	if !i.valid(i.Node) || hasLegacyMembers(i) {
		return errors.New("invalid-installation")
	}
	// Prove the complete set first. A conflict in a later sidecar must not cause
	// the earlier Agent to be stopped as a side effect of discovering it.
	for _, s := range i.Services {
		if s.Kind == "native" {
			if _, err := h.native(ctx, s); err != nil {
				return err
			}
		} else {
			if _, err := h.ownedContainer(ctx, s); err != nil {
				return err
			}
		}
	}
	for _, s := range i.Services {
		if s.Kind == "native" {
			if _, err := h.native(ctx, s); err != nil {
				return err
			}
			if _, err := h.command(ctx, "systemctl", "disable", "--now", nativeServiceName); err != nil {
				return err
			}
		} else {
			c, err := h.ownedContainer(ctx, s)
			if err != nil {
				return err
			}
			if _, err := h.docker(ctx, "update", "--restart=no", s.ID); err != nil {
				return err
			}
			if c.Status == "running" {
				if _, err := h.docker(ctx, "stop", "--time", "60", s.ID); err != nil {
					return err
				}
			}
		}
	}
	stopped, err := h.stopped(ctx, i)
	if err != nil {
		return err
	}
	if !stopped {
		return errors.New("node-writers-not-stopped")
	}
	return nil
}

func (h installationHost) stopped(ctx context.Context, i Installation) (bool, error) {
	if !i.valid(i.Node) || hasLegacyMembers(i) {
		return false, errors.New("invalid-installation")
	}
	for _, s := range i.Services {
		if s.Kind == "native" {
			status, err := h.native(ctx, s)
			if err != nil {
				return false, err
			}
			if status.MainPID != 0 || status.UnitFileState != "disabled" {
				return false, nil
			}
		} else {
			c, err := h.ownedContainer(ctx, s)
			if err != nil {
				return false, err
			}
			if c.Status == "running" || c.Restart != "no" {
				return false, nil
			}
		}
	}
	return true, nil
}

// restoreServices is used only after the rollback driver has stopped the new
// runtime and restored the captured unit/config identity. It does not restore a
// database snapshot. Initially disabled/stopped services retain that state.
func (h installationHost) restoreServices(ctx context.Context, i Installation) error {
	if !i.valid(i.Node) || hasLegacyMembers(i) {
		return errors.New("invalid-installation")
	}
	for _, s := range i.Services {
		if s.Kind == "native" {
			status, err := h.native(ctx, s)
			if err != nil {
				return err
			}
			if !s.Running && status.MainPID > 0 {
				return errors.New("unexpected-node-writer-active")
			}
		} else {
			c, err := h.ownedContainer(ctx, s)
			if err != nil {
				return err
			}
			if strings.TrimPrefix(c.Name, "/") != s.Name || !s.Running && c.Status == "running" {
				return errors.New("owned-container-state-not-restored")
			}
		}
	}
	for _, s := range i.Services {
		if s.Kind == "native" {
			verb := "disable"
			if s.Enabled {
				verb = "enable"
			}
			if _, err := h.command(ctx, "systemctl", verb, nativeServiceName); err != nil {
				return err
			}
			if s.Running {
				if _, err := h.command(ctx, "systemctl", "start", nativeServiceName); err != nil {
					return err
				}
			}
		} else {
			c, err := h.ownedContainer(ctx, s)
			if err != nil {
				return err
			}
			if strings.TrimPrefix(c.Name, "/") != s.Name {
				return errors.New("owned-container-name-not-restored")
			}
			policy := s.Restart
			if policy == "on-failure" && s.MaxRetries > 0 {
				policy += ":" + strconv.Itoa(s.MaxRetries)
			}
			if _, err := h.docker(ctx, "update", "--restart="+policy, s.ID); err != nil {
				return err
			}
			if s.Running && c.Status != "running" {
				if _, err := h.docker(ctx, "start", s.ID); err != nil {
					return err
				}
			}
		}
	}
	for _, s := range i.Services {
		if s.Kind == "native" {
			status, err := h.native(ctx, s)
			if err != nil {
				return err
			}
			if (status.MainPID > 0) != s.Running || (status.UnitFileState == "enabled") != s.Enabled {
				return errors.New("native-restore-not-confirmed")
			}
		} else {
			c, err := h.ownedContainer(ctx, s)
			if err != nil {
				return err
			}
			if (c.Status == "running") != s.Running || c.Restart != s.Restart || c.MaxRetries != s.MaxRetries {
				return errors.New("container-restore-not-confirmed")
			}
		}
	}
	return nil
}
