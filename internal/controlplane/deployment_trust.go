package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
)

// This configuration supplies trust, not permission to activate an installer.
// Public deployment writes remain gated until all runtime phases are wired.
type DeploymentTrustConfig struct {
	VaultKeyFile     string   `yaml:"vault_key_file" json:"vault_key_file"`
	PreviousKeyFiles []string `yaml:"previous_vault_key_files,omitempty" json:"previous_vault_key_files,omitempty"`
	PublicKeyFile    string   `yaml:"release_public_key_file" json:"release_public_key_file"`
	ManifestFile     string   `yaml:"release_manifest_file" json:"release_manifest_file"`
	SignatureFile    string   `yaml:"release_signature_file" json:"release_signature_file"`
	HelperFile       string   `yaml:"helper_file" json:"helper_file"`
	NativeBundleFile string   `yaml:"native_bundle_file" json:"native_bundle_file"`
	ImageArchiveFile string   `yaml:"image_archive_file,omitempty" json:"image_archive_file,omitempty"`
}

func (c DeploymentTrustConfig) configured() bool {
	return c.VaultKeyFile != "" || len(c.PreviousKeyFiles) != 0 || c.PublicKeyFile != "" || c.ManifestFile != "" || c.SignatureFile != "" || c.HelperFile != "" || c.NativeBundleFile != "" || c.ImageArchiveFile != ""
}

func (c DeploymentTrustConfig) validate() error {
	if !c.configured() {
		return nil
	}
	invalid := errors.New("deployment_trust 必须完整配置独立凭据密钥、信任公钥、清单、签名、工具及 native 包的绝对规范路径；旧密钥最多 8 个")
	if len(c.PreviousKeyFiles) > 8 {
		return invalid
	}
	paths := []string{c.VaultKeyFile, c.PublicKeyFile, c.ManifestFile, c.SignatureFile}
	if c.HelperFile != "" || c.NativeBundleFile != "" {
		paths = append(paths, c.HelperFile, c.NativeBundleFile)
	}
	paths = append(paths, c.PreviousKeyFiles...)
	if c.ImageArchiveFile != "" {
		paths = append(paths, c.ImageArchiveFile)
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, "\x00\r\n") || seen[path] {
			return invalid
		}
		seen[path] = true
	}
	return nil
}

type deploymentTrust struct {
	vault   *Vault
	release *TrustedRelease
	config  DeploymentTrustConfig
}

func loadDeploymentTrust(ctx context.Context, c DeploymentTrustConfig) (*deploymentTrust, error) {
	t, err := loadDeploymentMetadata(ctx, c)
	if err != nil {
		return nil, err
	}
	r := t.release
	if c.HelperFile == "" || c.NativeBundleFile == "" {
		return nil, DeploymentFailure{"artifact-invalid"}
	}
	for _, entry := range []struct {
		path  string
		want  ReleaseArtifact
		limit uint64
	}{{c.HelperFile, r.manifest.Helper, 256 << 20}, {c.NativeBundleFile, r.manifest.Native, 4 << 30}} {
		got, err := hashTrustArtifact(ctx, entry.path, entry.limit)
		if err != nil || got != entry.want {
			return nil, DeploymentFailure{"artifact-invalid"}
		}
	}
	if c.ImageArchiveFile != "" {
		if r.manifest.ImageArchive == nil {
			return nil, DeploymentFailure{"artifact-invalid"}
		}
		got, err := hashTrustArtifact(ctx, c.ImageArchiveFile, 4<<30)
		if err != nil || got != *r.manifest.ImageArchive {
			return nil, DeploymentFailure{"artifact-invalid"}
		}
	}
	return t, nil
}

// API processes verify the signed release and the shared Vault, without
// requiring executables, image archives or a CA private key in the container.
func loadDeploymentMetadata(ctx context.Context, c DeploymentTrustConfig) (*deploymentTrust, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if !c.configured() {
		return nil, errors.New("尚未配置 deployment_trust；不会自动生成或信任发布公钥")
	}
	r, _, err := LoadTrustedRelease(c.ManifestFile, c.SignatureFile, c.PublicKeyFile)
	if err != nil {
		return nil, err
	}
	vault, err := OpenVault(c.VaultKeyFile, c.PreviousKeyFiles...)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &deploymentTrust{vault: vault, release: r, config: c}, nil
}

func checkDeploymentTrust(ctx context.Context, c DeploymentTrustConfig, out io.Writer) error {
	t, err := loadDeploymentTrust(ctx, c)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{"status": "verified", "release": t.release.manifest.Release, "manifest_sha256": t.release.SHA256(), "vault_key_id": t.vault.active, "previous_vault_keys": len(t.vault.keys) - 1, "artifacts_verified": true, "image_archive_verified": c.ImageArchiveFile != "", "executor_enabled": false})
}
