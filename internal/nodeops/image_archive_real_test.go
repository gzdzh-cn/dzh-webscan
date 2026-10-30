package nodeops

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This optional integration check exports an existing image without loading,
// tagging, pulling or starting it. It exercises real Docker-save metadata.
func TestRealDockerSavedImageIdentity(t *testing.T) {
	image := os.Getenv("WEBSCAN_V3_IMAGE_IDENTITY_TEST")
	if image == "" {
		t.Skip("set WEBSCAN_V3_IMAGE_IDENTITY_TEST to a local immutable agent digest")
	}
	if !ValidAgentImage(image) {
		t.Fatal("test image must be an immutable agent reference")
	}
	out, err := exec.Command("docker", "image", "inspect", image, "--format", imageIdentityFormat).Output()
	if err != nil {
		t.Fatal(err)
	}
	var actual struct{ ID, OS, Arch string }
	if json.Unmarshal(out, &actual) != nil || actual.OS != "linux" || actual.Arch != "amd64" {
		t.Fatal("test image is not linux/amd64")
	}
	root := testRoot(t)
	archive := filepath.Join(root, "save.tar")
	if out, err := exec.Command("docker", "image", "save", "--output", archive, image).CombinedOutput(); err != nil {
		t.Fatalf("image save: %v: %s", err, out)
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := fileDigest(context.Background(), f, stat.Size())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(f)
	var config string
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if h.Name == "manifest.json" {
			var manifests []savedImage
			if json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&manifests) != nil || len(manifests) != 1 {
				t.Fatal("invalid saved manifest")
			}
			config = strings.TrimPrefix(manifests[0].Config, "blobs/sha256/")
			config = strings.TrimSuffix(config, ".json")
			break
		}
	}
	f.Close()
	if !validDigest(config) {
		t.Fatal("invalid saved config identity")
	}
	spec := Spec{Mode: "docker", AgentImage: image, ImageArchiveSHA256: digest, ImageArchiveBytes: uint64(stat.Size()), ImageConfigSHA256: config}
	dir := filepath.Join(root, "images", digest)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(archive, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(archive, filepath.Join(dir, "docker-image.tar")); err != nil {
		t.Fatal(err)
	}
	verified, manifest, err := verifiedImageArchiveManifest(context.Background(), root, spec)
	if err != nil {
		t.Fatal(err)
	}
	verified.Close()
	if actual.ID != "sha256:"+config && (manifest == "" || actual.ID != manifest) {
		t.Fatalf("engine identity %q differs from verified config and manifest", actual.ID)
	}
	configInspect, configErr := exec.Command("docker", "image", "inspect", "sha256:"+config, "--format", imageIdentityFormat).Output()
	if configErr == nil {
		var inspected struct{ ID, OS, Arch string }
		if json.Unmarshal(configInspect, &inspected) != nil || inspected.ID != actual.ID || inspected.OS != actual.OS || inspected.Arch != actual.Arch {
			t.Fatal("config reference resolves to a different image")
		}
	}
	t.Logf("engine ID matches config=%t manifest=%t; config reference resolves=%t", actual.ID == "sha256:"+config, actual.ID == manifest, configErr == nil)
}
