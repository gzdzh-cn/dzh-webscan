package nodeops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"webscan/internal/common"
)

// Docker's classic store launches config IDs; the containerd store launches
// manifest IDs. A local receipt selects between them only after the complete
// signed archive has proved that the manifest references the expected config.
// It is not a replacement for the archive or a trusted registry digest.
func dockerLaunchReference(root string, s Spec) (string, error) {
	if s.imageArchiveValid() {
		if _, version := agentImageName(s.AgentImage); version != "" {
			// Offline stores need not retain RepoDigests. The alias is checked
			// against the signed image ID before creating or starting a container.
			return strings.SplitN(s.AgentImage, "@", 2)[0], nil
		}
	}
	return dockerLaunchIdentity(root, s)
}

func dockerLaunchIdentity(root string, s Spec) (string, error) {
	if !s.imageArchiveValid() {
		return s.AgentImage, nil
	}
	file := filepath.Join(root, "images", s.ImageArchiveSHA256, "launch-image")
	if _, err := os.Lstat(file); os.IsNotExist(err) {
		return "sha256:" + s.ImageConfigSHA256, nil
	}
	raw, err := readPrivate(file, 128)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	f, manifest, err := verifiedImageArchiveManifest(context.Background(), root, s)
	if err != nil {
		return "", err
	}
	f.Close()
	if manifest == "" || id != manifest {
		return "", errors.New("image-launch-proof-invalid")
	}
	return id, nil
}

func recordDockerLaunchReference(root string, s Spec, id, manifest string) error {
	if id == "sha256:"+s.ImageConfigSHA256 {
		return nil
	}
	if manifest == "" || id != manifest {
		return errors.New("image-launch-proof-invalid")
	}
	file := filepath.Join(root, "images", s.ImageArchiveSHA256, "launch-image")
	if _, err := os.Lstat(file); err == nil {
		raw, err := readPrivate(file, 128)
		if err != nil {
			return err
		}
		if string(raw) != id+"\n" {
			return errors.New("image-launch-proof-changed")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return common.Atomic(file, []byte(id+"\n"), 0600)
}
