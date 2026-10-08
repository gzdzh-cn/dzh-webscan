package deploy

import (
	"context"
	"errors"
	"os"
	"regexp"
	"sort"
	"strings"
	"webscan/internal/common"

	"gopkg.in/yaml.v3"
)

const imageLockLabel = "io.webscan.locked-image"

// Retained third-party components also need readable names on an upgrade.
// Changing their display name must keep their current immutable image.
func updateVendorImageAliases(c *Config, services, images common.Map, refresh bool) []string {
	var changed []string
	for name, value := range services {
		role := name
		if name == "host-exporter" {
			role = "exporter"
		}
		if _, known := VendorImages[role]; !known {
			continue
		}
		s := common.M(value)
		image := lockedServiceImage(s)
		if refresh && common.S(images[role]) != "" {
			image = common.S(images[role])
		}
		next := imageService(c, role, image)
		if common.S(s["image"]) == common.S(next["image"]) && lockedServiceImage(s) == lockedServiceImage(next) {
			continue
		}
		s["image"] = next["image"]
		labels := common.M(s["labels"])
		if lock := common.S(common.M(next["labels"])[imageLockLabel]); lock != "" {
			labels[imageLockLabel] = lock
			s["pull_policy"] = "never"
		} else {
			delete(labels, imageLockLabel)
			delete(s, "pull_policy")
		}
		s["labels"] = labels
		changed = append(changed, name)
	}
	sort.Strings(changed)
	return changed
}

func lockedServiceImage(service common.Map) string {
	if locked := common.S(common.M(service["labels"])[imageLockLabel]); locked != "" {
		return locked
	}
	return common.S(service["image"])
}

// Keep digest locks in metadata while showing readable tags in docker ps.
func imageService(c *Config, role, image string) common.Map {
	s := service(image)
	if !strings.Contains(image, "@sha256:") && !strings.HasPrefix(image, "sha256:") {
		return s
	}
	alias := "docker.io/" + VendorImages[role]
	if role == "central" || role == "agent" {
		alias = strings.Split(c.Image(role), "@")[0]
		if strings.LastIndex(alias, ":") <= strings.LastIndex(alias, "/") {
			alias += ":latest"
		}
	}
	s["image"] = alias
	s["labels"] = common.Map{imageLockLabel: image}
	s["pull_policy"] = "never"
	return s
}

// Retag the saved immutable image before every start, including a rollback.
// Never pull a mutable latest here: it may point to a different release now.
func EnsureComposeImages(ctx context.Context, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var compose common.Map
	if err = yaml.Unmarshal(b, &compose); err != nil {
		return err
	}
	return pinComposeImages(ctx, compose, func(ctx context.Context, args ...string) ([]byte, error) {
		return RunCommand(ctx, nil, append([]string{"docker"}, args...)...)
	})
}

func pinComposeImages(ctx context.Context, compose common.Map, run func(context.Context, ...string) ([]byte, error)) error {
	for _, value := range common.M(compose["services"]) {
		s := common.M(value)
		locked := common.S(common.M(s["labels"])[imageLockLabel])
		if locked == "" {
			continue // Legacy digest references and fresh standalone Compose packages.
		}
		alias := common.S(s["image"])
		if !regexp.MustCompile(`^(?:[a-z0-9][a-z0-9._:/-]*@)?sha256:[a-f0-9]{64}$`).MatchString(locked) || strings.Contains(alias, "@") || strings.LastIndex(alias, ":") <= strings.LastIndex(alias, "/") {
			return errors.New("runtime_image_alias_lock_invalid")
		}
		b, err := run(ctx, "image", "inspect", "--format", "{{.Id}}", locked)
		if err != nil {
			return errors.New("runtime_locked_image_unavailable")
		}
		id := strings.TrimSpace(string(b))
		if !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(id) {
			return errors.New("runtime_locked_image_identity_invalid")
		}
		if _, err = run(ctx, "image", "tag", id, alias); err != nil {
			return errors.New("runtime_image_alias_tag_failed")
		}
		b, err = run(ctx, "image", "inspect", "--format", "{{.Id}}", alias)
		if err != nil || strings.TrimSpace(string(b)) != id {
			return errors.New("runtime_image_alias_identity_mismatch")
		}
	}
	return nil
}
