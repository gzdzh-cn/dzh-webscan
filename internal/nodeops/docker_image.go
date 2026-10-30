package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const imageIdentityFormat = `{"id":{{json .Id}},"repo_digests":{{json .RepoDigests}},"os":{{json .Os}},"arch":{{json .Architecture}}}`

func prepareDockerImage(ctx context.Context, root string, s Spec) error {
	if !ValidAgentImage(s.AgentImage) {
		return errors.New("image-requires-immutable-reference")
	}
	if err := inspectDockerImageSource(ctx, root, s); err == nil {
		return prepareDockerLaunchAlias(ctx, root, s)
	}
	// When a verified fallback is available, leave most of the stage deadline
	// for archive verification and import instead of spending it on a registry
	// connection that may not be reachable from the node.
	pullContext := ctx
	stop := func() {}
	if s.imageArchiveValid() {
		pullContext, stop = context.WithTimeout(ctx, time.Minute)
	}
	_, pullError := dockerImageCommand(pullContext, "pull", "--platform", "linux/amd64", s.AgentImage)
	stop()
	if pullError == nil {
		if err := inspectDockerImageSource(ctx, root, s); err == nil {
			return prepareDockerLaunchAlias(ctx, root, s)
		}
	}
	if !s.imageArchiveValid() {
		return errors.New("immutable-image-pull-failed")
	}
	f, err := verifiedImageArchive(ctx, root, s)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := dockerImageCommandInput(ctx, io.LimitReader(f, int64(s.ImageArchiveBytes)+1), "load"); err != nil {
		return errors.New("verified-image-load-failed")
	}
	if err := inspectLoadedImage(ctx, root, s); err != nil {
		return err
	}
	return prepareDockerLaunchAlias(ctx, root, s)
}

func inspectDockerImage(ctx context.Context, root string, s Spec) error {
	if err := inspectDockerImageSource(ctx, root, s); err != nil {
		return err
	}
	if !hasDockerLaunchAlias(s) {
		return nil
	}
	ref, err := dockerLaunchReference(root, s)
	if err != nil {
		return err
	}
	raw, err := dockerImageCommand(ctx, "image", "inspect", ref, "--format", imageIdentityFormat)
	if err != nil {
		return errors.New("versioned-image-alias-missing")
	}
	return verifyDockerLaunchAlias(root, s, raw)
}

func inspectDockerImageSource(ctx context.Context, root string, s Spec) error {
	if !ValidAgentImage(s.AgentImage) {
		return errors.New("image-requires-immutable-reference")
	}
	raw, err := dockerImageCommand(ctx, "image", "inspect", s.AgentImage, "--format", imageIdentityFormat)
	if err == nil && verifyDockerImageForSpec(raw, s) == nil {
		return nil
	}
	if !s.imageArchiveValid() {
		return errors.New("image-inspection-failed")
	}
	// A signed archive binds its config ID to the intended registry digest.
	// Recheck that proof before trusting an image lacking RepoDigests.
	f, err := verifiedImageArchive(ctx, root, s)
	if err != nil {
		return err
	}
	f.Close()
	return inspectLoadedImage(ctx, root, s)
}

func hasDockerLaunchAlias(s Spec) bool {
	_, version := agentImageName(s.AgentImage)
	return s.imageArchiveValid() && version != ""
}

func verifyDockerLaunchAlias(root string, s Spec, raw string) error {
	id, err := dockerLaunchIdentity(root, s)
	if err != nil {
		return err
	}
	var image struct{ ID, OS, Arch string }
	if len(raw) > 8192 || json.Unmarshal([]byte(raw), &image) != nil || image.ID != id || image.OS != "linux" || image.Arch != "amd64" {
		return errors.New("versioned-image-alias-mismatch")
	}
	return nil
}

func prepareDockerLaunchAlias(ctx context.Context, root string, s Spec) error {
	if !hasDockerLaunchAlias(s) {
		return nil
	}
	ref, err := dockerLaunchReference(root, s)
	if err != nil {
		return err
	}
	raw, err := dockerImageCommand(ctx, "image", "inspect", ref, "--format", imageIdentityFormat)
	if err == nil {
		// A version tag already bound to other bytes must never be overwritten.
		return verifyDockerLaunchAlias(root, s, raw)
	}
	id, err := dockerLaunchIdentity(root, s)
	if err != nil {
		return err
	}
	if _, err = dockerImageCommand(ctx, "tag", id, ref); err != nil {
		return errors.New("versioned-image-alias-create-failed")
	}
	raw, err = dockerImageCommand(ctx, "image", "inspect", ref, "--format", imageIdentityFormat)
	if err != nil {
		return errors.New("versioned-image-alias-missing")
	}
	return verifyDockerLaunchAlias(root, s, raw)
}

func verifyDockerImageForSpec(raw string, s Spec) error {
	if err := verifyDockerImageIdentity(raw, s.AgentImage); err != nil {
		return err
	}
	if s.imageArchiveValid() {
		var image struct {
			ID string `json:"id"`
		}
		if json.Unmarshal([]byte(raw), &image) != nil || image.ID != "sha256:"+s.ImageConfigSHA256 {
			return errors.New("image-config-identity-mismatch")
		}
	}
	return nil
}

func inspectLoadedImage(ctx context.Context, root string, s Spec) error {
	f, manifest, err := verifiedImageArchiveManifest(ctx, root, s)
	if err != nil {
		return err
	}
	f.Close()
	candidates := []string{"sha256:" + s.ImageConfigSHA256}
	if manifest != "" {
		candidates = append(candidates, manifest)
	}
	for _, ref := range candidates {
		raw, err := dockerImageCommand(ctx, "image", "inspect", ref, "--format", imageIdentityFormat)
		if err != nil {
			continue
		}
		var image struct {
			ID   string `json:"id"`
			OS   string `json:"os"`
			Arch string `json:"arch"`
		}
		if len(raw) > 8192 || json.Unmarshal([]byte(raw), &image) != nil || image.ID != ref || image.OS != "linux" || image.Arch != "amd64" {
			continue
		}
		return recordDockerLaunchReference(root, s, image.ID, manifest)
	}
	return errors.New("loaded-image-identity-not-verified")
}

func verifyDockerImageIdentity(raw, expected string) error {
	var image struct {
		ID          string   `json:"id"`
		RepoDigests []string `json:"repo_digests"`
		OS          string   `json:"os"`
		Arch        string   `json:"arch"`
	}
	if !ValidAgentImage(expected) || len(raw) > 8192 || json.Unmarshal([]byte(raw), &image) != nil || image.OS != "linux" || image.Arch != "amd64" || !strings.HasPrefix(image.ID, "sha256:") || !validDigest(strings.TrimPrefix(image.ID, "sha256:")) {
		return errors.New("image-identity-not-verified")
	}
	want := expected[strings.LastIndex(expected, "@")+1:]
	for _, ref := range image.RepoDigests {
		if ValidAgentImage(ref) && ref[strings.LastIndex(ref, "@")+1:] == want {
			return nil
		}
	}
	// A tag or config ID alone is not proof of a registry manifest digest.
	// Loaded images require the separately verified signed archive provenance.
	return errors.New("image-identity-not-verified")
}

func dockerImageCommand(ctx context.Context, args ...string) (string, error) {
	return dockerImageCommandInput(ctx, nil, args...)
}

func dockerImageCommandInput(ctx context.Context, input io.Reader, args ...string) (string, error) {
	probe, stop := context.WithTimeout(ctx, 3*time.Minute)
	defer stop()
	// Use the node's local engine and anonymous registry access. A process's
	// inherited DOCKER_HOST or saved registry login cannot change the target.
	config, err := os.MkdirTemp("", "webscan-registry-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(config)
	fixed := []string{"--host", "unix:///var/run/docker.sock", "--config", config}
	cmd := exec.CommandContext(probe, "docker", append(fixed, args...)...)
	cmd.Stdin = input
	b := &boundedOutput{}
	cmd.Stdout, cmd.Stderr = b, io.Discard
	err = cmd.Run()
	return string(b.raw), err
}
