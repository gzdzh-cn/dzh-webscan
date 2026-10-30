package nodeops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

func retiredDockerName(r Request) string {
	return "webscan-retired-" + sha([]byte(r.Node + "\x00" + r.Job + "\x00" + r.PlanDigest))[:24]
}

// Used only by native-target transitions. The prior Docker object survives the
// switch; a name is never sufficient proof and collisions are never removed.
func (h installationHost) nativeOriginalDocker(ctx context.Context, i Installation, retired string) (*containerIdentity, error) {
	if i.Mode != "docker" {
		return nil, nil
	}
	if !singleDockerOriginal(i) {
		return nil, errors.New("unsupported-original-docker")
	}
	s := i.Services[0]
	c, err := h.ownedContainer(ctx, s)
	if err != nil {
		return nil, err
	}
	if c.Name != "/"+s.Name && (retired == "" || c.Name != "/"+retired) {
		return nil, errors.New("original-container-name-changed")
	}
	for _, name := range []string{s.Name, retired} {
		if name == "" {
			continue
		}
		named, err := h.containerNamed(ctx, name)
		if err != nil {
			return nil, err
		}
		if named != nil && named.ID != c.ID {
			return nil, errors.New("original-container-name-in-use")
		}
	}
	return &c, nil
}
func (h installationHost) nativeOriginalDockerStopped(ctx context.Context, i Installation, retired string, requireRetired bool) error {
	c, err := h.nativeOriginalDocker(ctx, i, retired)
	if err != nil || c == nil {
		return err
	}
	if c.Status == "running" || c.Restart != "no" || requireRetired && c.Name != "/"+retired {
		return errors.New("original-container-not-quiescent")
	}
	return nil
}
func (h installationHost) retireDockerForNative(ctx context.Context, i Installation, retired string) error {
	if err := h.nativeOriginalDockerStopped(ctx, i, retired, false); err != nil {
		return err
	}
	c, err := h.nativeOriginalDocker(ctx, i, retired)
	if err != nil || c == nil {
		return err
	}
	if c.Name == "/"+i.Services[0].Name {
		if _, err := h.docker(ctx, "rename", c.ID, retired); err != nil {
			return err
		}
	}
	return h.nativeOriginalDockerStopped(ctx, i, retired, true)
}
func (h installationHost) restoreDockerNameForNative(ctx context.Context, i Installation, retired string) error {
	if err := h.nativeOriginalDockerStopped(ctx, i, retired, false); err != nil {
		return err
	}
	c, err := h.nativeOriginalDocker(ctx, i, retired)
	if err != nil || c == nil {
		return err
	}
	if c.Name != "/"+i.Services[0].Name {
		if _, err := h.docker(ctx, "rename", c.ID, i.Services[0].Name); err != nil {
			return err
		}
	}
	c, err = h.nativeOriginalDocker(ctx, i, retired)
	if err != nil {
		return err
	}
	if c.Name != "/"+i.Services[0].Name {
		return errors.New("original-container-name-not-restored")
	}
	return nil
}
func (h installationHost) nativeOriginalDockerRestored(ctx context.Context, i Installation, retired string) error {
	c, err := h.nativeOriginalDocker(ctx, i, retired)
	if err != nil || c == nil {
		return err
	}
	s := i.Services[0]
	if c.Name != "/"+s.Name || (c.Status == "running") != s.Running || c.Restart != s.Restart || c.MaxRetries != s.MaxRetries {
		return errors.New("original-container-not-restored")
	}
	return nil
}
func supportedNativeOriginal(i Installation) bool {
	if hasLegacyMembers(i) {
		return false
	}
	if i.Mode == "docker" {
		return singleDockerOriginal(i)
	}
	if i.Generation == "absent" {
		return len(i.Services) == 0
	}
	if i.Mode != "native" {
		return false
	}
	for _, s := range i.Services {
		if s.Kind != "native" {
			return false
		}
	}
	return true
}

// The old generated Compose file is preserved in capture, then removed from
// its active legacy path. Otherwise future native inventory would keep
// requiring a Docker engine merely because of a disabled legacy definition.
// No immutable v3 configuration, main YAML or unrelated file is removed.
func (b *transitionBackup) retireLegacyComposeForNative(ctx context.Context, i backupIntent, h installationHost, write bool) error {
	if i.Installed.Mode != "docker" || i.Installed.Generation != "v2" {
		return nil
	}
	if filepath.Dir(i.Installed.Runtime) != h.configRoot {
		return errors.New("legacy-configuration-root-changed")
	}
	var captured *backupFile
	for _, f := range i.Files {
		if f.Path == "config/compose.yml" {
			copy := f
			captured = &copy
		}
	}
	if captured == nil {
		return errors.New("legacy-compose-not-captured")
	}
	if !idPattern.MatchString(i.Binding.Job) {
		return errors.New("invalid-capture-job")
	}
	source := filepath.Join(b.root, "transitions", i.Binding.Job, "capture", captured.Path)
	if err := verifyBackupFile(ctx, source, *captured); err != nil {
		return err
	}
	destination := filepath.Join(h.configRoot, "compose.yml")
	if !write {
		if _, err := os.Lstat(destination); !os.IsNotExist(err) {
			return errors.New("legacy-compose-not-retired")
		}
		return nil
	}
	raw, err := readPrivate(source, 2<<20)
	if err != nil {
		return err
	}
	return removeExpectedPrivate(destination, raw)
}
