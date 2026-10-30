package nodeops

import (
	"encoding/json"
	"errors"
	"strings"
)

// Docker-save can wrap a platform manifest in an OCI index containing build
// attestations. The archive's signed SHA256 authenticates every byte; this
// additionally proves that its launchable manifest uses the signed config and
// the already checked layer list. Neither a tag nor an attestation is a proof.
type savedOCIDescriptor struct {
	Digest      string            `json:"digest"`
	Media       string            `json:"mediaType"`
	Annotations map[string]string `json:"annotations"`
	Platform    *struct {
		OS   string `json:"os"`
		Arch string `json:"architecture"`
	} `json:"platform"`
}
type savedOCIIndex struct {
	Schema    int                  `json:"schemaVersion"`
	Manifests []savedOCIDescriptor `json:"manifests"`
}

var errSavedOCIIndex = errors.New("image-archive-oci-index-invalid")

func verifySavedOCIIndex(metadata map[string][]byte, raw []byte, s Spec, saved savedImage) (string, error) {
	var top savedOCIIndex
	if json.Unmarshal(raw, &top) != nil || top.Schema != 2 || len(top.Manifests) != 1 {
		return "", errSavedOCIIndex
	}
	var visit func(savedOCIDescriptor, int) (int, error)
	visit = func(d savedOCIDescriptor, depth int) (int, error) {
		if depth > 4 || !strings.HasPrefix(d.Digest, "sha256:") || !validDigest(strings.TrimPrefix(d.Digest, "sha256:")) {
			return 0, errSavedOCIIndex
		}
		blob := metadata["blobs/sha256/"+strings.TrimPrefix(d.Digest, "sha256:")]
		if len(blob) == 0 || sha(blob) != strings.TrimPrefix(d.Digest, "sha256:") {
			return 0, errSavedOCIIndex
		}
		if full := d.Annotations["io.containerd.image.name"]; full != "" && !sameImageRepository(full, s.AgentImage) {
			return 0, errSavedOCIIndex
		}
		if ref := d.Annotations["org.opencontainers.image.ref.name"]; ref != "" {
			full := d.Annotations["io.containerd.image.name"]
			if full == "" || !strings.HasSuffix(full, ":"+ref) || strings.ContainsAny(ref, "/@\x00\r\n ") {
				return 0, errSavedOCIIndex
			}
		}
		if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			// Only an explicitly marked non-runnable descriptor can be skipped.
			if d.Media != "application/vnd.oci.image.manifest.v1+json" || d.Platform == nil || d.Platform.OS != "unknown" || d.Platform.Arch != "unknown" {
				return 0, errSavedOCIIndex
			}
			return 0, nil
		}
		if d.Platform != nil && (d.Platform.OS != "linux" || d.Platform.Arch != "amd64") {
			return 0, errSavedOCIIndex
		}
		switch d.Media {
		case "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json":
			var index savedOCIIndex
			if json.Unmarshal(blob, &index) != nil || index.Schema != 2 || len(index.Manifests) < 1 || len(index.Manifests) > 32 {
				return 0, errSavedOCIIndex
			}
			count := 0
			for _, child := range index.Manifests {
				n, e := visit(child, depth+1)
				if e != nil {
					return 0, e
				}
				count += n
			}
			if count != 1 {
				return 0, errSavedOCIIndex
			}
			return count, nil
		case "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json":
			var manifest struct {
				Schema int `json:"schemaVersion"`
				Config struct {
					Digest string `json:"digest"`
				} `json:"config"`
				Layers []struct {
					Digest string `json:"digest"`
				} `json:"layers"`
			}
			if json.Unmarshal(blob, &manifest) != nil || manifest.Schema != 2 || manifest.Config.Digest != "sha256:"+s.ImageConfigSHA256 || len(manifest.Layers) != len(saved.Layers) {
				return 0, errSavedOCIIndex
			}
			for i, layer := range manifest.Layers {
				if !strings.HasPrefix(layer.Digest, "sha256:") || !validDigest(strings.TrimPrefix(layer.Digest, "sha256:")) || saved.Layers[i] != "blobs/sha256/"+strings.TrimPrefix(layer.Digest, "sha256:") {
					return 0, errSavedOCIIndex
				}
			}
			return 1, nil
		default:
			return 0, errSavedOCIIndex
		}
	}
	if n, e := visit(top.Manifests[0], 0); e != nil || n != 1 {
		return "", errSavedOCIIndex
	}
	return top.Manifests[0].Digest, nil
}
