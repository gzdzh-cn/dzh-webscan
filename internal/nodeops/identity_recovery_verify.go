package nodeops

import (
	"context"
	"path/filepath"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

// Startup is not resource acceptance. This fixed, read-only operation proves
// the owned live process against its immutable saved policy and host kernel.
// The caller holds journal -> service -> trust -> identity locks; it must not
// reacquire those locks, use a seed, or change service/resource configuration.
func (w *LocalRuntime) verifyRecoveredService(ctx context.Context, in IdentityRecoveryInput, host installationHost, fs nativeResources) error {
	return w.verifyIdentityMaintenanceService(ctx, in.Intent.Node, in.CRL, host, fs)
}

func (w *LocalRuntime) verifyIdentityMaintenanceService(ctx context.Context, node string, crl []byte, host installationHost, fs nativeResources) error {
	roots, err := w.installedRootState(time.Now())
	if err != nil {
		return errIdentityRecovery
	}
	var state *nodepki.RootSetSnapshot
	if roots.Format != 0 {
		state = &roots
	}
	return w.verifyIdentityMaintenanceServiceWithRoots(ctx, node, crl, state, host, fs)
}

func (w *LocalRuntime) verifyIdentityMaintenanceServiceWithRoots(ctx context.Context, node string, crl []byte, roots *nodepki.RootSetSnapshot, host installationHost, fs nativeResources) error {
	held, locked := ctx.Value(serviceOperationKey{}).(serviceOperation)
	if host.root != w.root || !locked || held.root != w.root || held.file == nil {
		return errIdentityRecovery
	}
	before, err := host.inventory(ctx, node, "native")
	if err != nil || before.Generation != "v3" || len(before.Services) != 1 || hasLegacyMembers(before) || !before.Services[0].Running || !before.Services[0].Enabled {
		return errIdentityRecovery
	}
	var active ActiveInstallation
	if _, err := decodePrivateJSON(filepath.Join(w.root, "active.json"), &active, MaxRequestBytes); err != nil || active.Node != node || active.Spec.Mode != before.Mode || w.verifyPrepared(ctx, active.Spec) != nil {
		return errIdentityRecovery
	}
	raw, err := readPrivate(filepath.Join(w.root, "configs", active.Spec.RuntimeSHA256, "node.json"), nodeconfig.MaxBytes)
	if err != nil {
		return errIdentityRecovery
	}
	defer clear(raw)
	var m nodeconfig.Material
	if roots == nil {
		m, err = nodeconfig.DecodeManagedRuntime(raw, time.Now(), crl)
	} else {
		m, err = nodeconfig.DecodeManagedRootRuntime(raw, time.Now(), *roots)
	}
	defer clear(m.Key)
	if err != nil || m.Node != active.Node || m.SourceSHA256 != active.Spec.ConfigSourceSHA256 || m.Version != active.Spec.ConfigVersion {
		return errIdentityRecovery
	}
	s := before.Services[0]
	if before.Mode == "native" {
		status, err := host.native(ctx, s)
		if err != nil {
			return errIdentityRecovery
		}
		proof, err := fs.inspect(ctx, host, status, s, m.Settings.Resources)
		if err != nil {
			return errIdentityRecovery
		}
		last, err := host.native(ctx, s)
		if err != nil || last.MainPID != proof.PID {
			return errIdentityRecovery
		}
	} else if before.Mode == "docker" {
		if _, err := fs.inspectDocker(ctx, host, s.ID, active, m.Settings.Resources); err != nil {
			return errIdentityRecovery
		}
	} else {
		return errIdentityRecovery
	}
	after, err := host.inventory(ctx, node, before.Mode)
	if err != nil || after.Generation != before.Generation || after.Mode != before.Mode || after.Runtime != before.Runtime || len(after.Services) != 1 || hasLegacyMembers(after) || after.Services[0] != s {
		return errIdentityRecovery
	}
	return ctx.Err()
}
