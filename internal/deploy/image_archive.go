package deploy

import (
	"archive/tar"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"webscan/internal/common"
)

func archiveMember(path, name string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	t := tar.NewReader(f)
	for {
		h, err := t.Next()
		if err != nil {
			return nil, err
		}
		if h.Name != name {
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size > limit {
			return nil, errors.New("image_archive_metadata_invalid")
		}
		return io.ReadAll(io.LimitReader(t, limit))
	}
}

// Bind the optional OCI import identity to the same config as manifest.json.
// Legacy Docker archives have no OCI index and continue using the config ID.
func archiveImageIdentities(path string) ([]string, error) {
	config, err := archiveConfig(path)
	if err != nil {
		return nil, err
	}
	ids := []string{config}
	b, err := archiveMember(path, "index.json", 1048576)
	if errors.Is(err, io.EOF) {
		return ids, nil
	}
	if err != nil {
		return nil, err
	}
	var index struct {
		Manifests []struct {
			MediaType string
			Digest    string
			Size      int64
		}
	}
	if json.Unmarshal(b, &index) != nil || len(index.Manifests) != 1 {
		return nil, errors.New("image_archive_requires_one_platform_manifest")
	}
	descriptor := index.Manifests[0]
	hexDigest := strings.TrimPrefix(descriptor.Digest, "sha256:")
	_, digestErr := hex.DecodeString(hexDigest)
	if len(hexDigest) != 64 || !strings.HasPrefix(descriptor.Digest, "sha256:") || digestErr != nil || !common.Contains([]string{"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}, descriptor.MediaType) {
		return nil, errors.New("image_archive_manifest_identity_invalid")
	}
	b, err = archiveMember(path, "blobs/sha256/"+hexDigest, 1048576)
	if err != nil {
		return nil, err
	}
	var manifest struct{ Config struct{ Digest string } }
	if int64(len(b)) != descriptor.Size || "sha256:"+common.Hash(b) != descriptor.Digest || json.Unmarshal(b, &manifest) != nil || manifest.Config.Digest != config {
		return nil, errors.New("image_archive_manifest_config_mismatch")
	}
	return append(ids, descriptor.Digest), nil
}
