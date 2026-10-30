package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"webscan/internal/nodeops"
)

// ReleaseManifest is detached-signed JSON. The public key must come from the
// administrator's independent trust configuration, never from this document,
// a deployment request, or the SSH host being provisioned. This code does not
// download artifacts, trust a registry tag, or generate a production signing key.
type ReleaseManifest struct {
	Format            int              `json:"format"`
	Release           string           `json:"release"`
	Platform          string           `json:"platform"`
	Protocol          int              `json:"node_protocol"`
	Helper            ReleaseArtifact  `json:"helper"`
	Native            ReleaseArtifact  `json:"native_bundle"`
	Image             string           `json:"agent_image"`
	ImageArchive      *ReleaseArtifact `json:"image_archive,omitempty"`
	ImageConfigSHA256 string           `json:"image_config_sha256,omitempty"`
}

type ReleaseArtifact struct {
	SHA256 string `json:"sha256"`
	Bytes  uint64 `json:"bytes"`
}

// TrustedRelease cannot be constructed with exported manifest fields. Only a
// verified signature and validated contract can produce a usable release.
// The immutable value can be shared across concurrent execution workers.
type TrustedRelease struct {
	manifest ReleaseManifest
	digest   string
}

func releaseDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func VerifyReleaseManifest(raw, signature []byte, key ed25519.PublicKey) (*TrustedRelease, error) {
	invalid := errors.New("发布清单签名、格式或程序校验值不正确")
	if len(raw) == 0 || len(raw) > 64<<10 || len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, raw, signature) {
		return nil, invalid
	}
	var m ReleaseManifest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return nil, invalid
	}
	// One canonical representation prevents duplicate keys and parser-dependent
	// interpretations of the signed manifest. A trailing newline is permitted.
	canonical, err := json.Marshal(m)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(raw)) || m.Format != 1 || !releaseVersion.MatchString(m.Release) || len(m.Release) > 128 || m.Platform != "linux/amd64" || m.Protocol != 1 {
		return nil, invalid
	}
	if !releaseDigest(m.Helper.SHA256) || m.Helper.Bytes < 1 || m.Helper.Bytes > 256<<20 || !releaseDigest(m.Native.SHA256) || m.Native.Bytes < 1 || m.Native.Bytes > 4<<30 || !nodeops.AgentImageMatchesRelease(m.Image, m.Release) {
		return nil, invalid
	}
	if m.ImageArchive != nil {
		if !releaseDigest(m.ImageArchive.SHA256) || m.ImageArchive.Bytes < 1 || m.ImageArchive.Bytes > 4<<30 || !releaseDigest(m.ImageConfigSHA256) {
			return nil, invalid
		}
	} else if m.ImageConfigSHA256 != "" {
		return nil, invalid
	}
	return &TrustedRelease{manifest: m, digest: digest(raw)}, nil
}

func (r *TrustedRelease) SHA256() string {
	if r == nil {
		return ""
	}
	return r.digest
}

func (r *TrustedRelease) matches(j DeploymentJob) bool {
	if r == nil || r.digest == "" || j.Plan.Request.ManifestSHA256 != r.digest || j.Plan.Request.Release != r.manifest.Release {
		return false
	}
	target := r.manifest.Native.SHA256
	if j.Plan.Node.Mode == "docker" {
		target = r.manifest.Image[len(r.manifest.Image)-64:]
	}
	return j.Plan.Request.SHA256 == target
}
