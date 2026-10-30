package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strings"

	"webscan/internal/nodeops"
)

type ReleaseOptions struct {
	Action, Output, KeyFile, PublicKeyFile, Manifest, Signature                string
	Release, Helper, NativeBundle, AgentImage, ImageArchive, ImageConfigSHA256 string
}

var errReleaseOptions = errors.New("发布工具参数不正确；操作为 init-key、sign 或 verify，密钥及程序包仅通过文件读取")
var errSigningKey = errors.New("发布密钥格式错误；要求独立保存的 Ed25519 PKCS8 私钥或 PKIX 公钥 PEM 文件")

// ReleaseCommand is offline and independent of PostgreSQL, SSH, registries and
// the running control plane. Signing binds bytes, not their functional safety:
// bundle, ELF, scanner and image identity checks still run on the destination.
func ReleaseCommand(ctx context.Context, o ReleaseOptions, out io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	remaining := o
	remaining.Action = ""
	switch o.Action {
	case "init-key":
		remaining.Output = ""
		if remaining != (ReleaseOptions{}) || o.Output == "" {
			return errReleaseOptions
		}
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return errSigningKey
		}
		defer clear(key)
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return errSigningKey
		}
		defer clear(der)
		private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		defer clear(private)
		publicDER, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return errSigningKey
		}
		public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
		if err = publishTrustFiles(ctx, o.Output, map[string][]byte{"signing.key": private, "signing.pub": public}); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"status": "initialized", "algorithm": "Ed25519", "public_key_sha256": digest(publicDER)})
	case "sign":
		remaining.Output, remaining.KeyFile, remaining.Release, remaining.Helper, remaining.NativeBundle, remaining.AgentImage, remaining.ImageArchive, remaining.ImageConfigSHA256 = "", "", "", "", "", "", "", ""
		if remaining != (ReleaseOptions{}) || o.Output == "" || o.KeyFile == "" || o.Helper == "" || o.NativeBundle == "" || (o.ImageArchive == "") != (o.ImageConfigSHA256 == "") {
			return errReleaseOptions
		}
		// Reject invalid contracts before hashing potentially large archives.
		m := ReleaseManifest{Format: 1, Release: o.Release, Platform: "linux/amd64", Protocol: 1, Image: o.AgentImage}
		if !releaseVersion.MatchString(o.Release) || len(o.Release) > 128 || !nodeops.ValidAgentImage(o.AgentImage) || o.ImageConfigSHA256 != "" && !releaseDigest(o.ImageConfigSHA256) {
			return errReleaseOptions
		}
		key, err := loadSigningKey(o.KeyFile)
		if err != nil {
			return err
		}
		defer clear(key)
		if m.Helper, err = hashTrustArtifact(ctx, o.Helper, 256<<20); err != nil {
			return err
		}
		if m.Native, err = hashTrustArtifact(ctx, o.NativeBundle, 4<<30); err != nil {
			return err
		}
		if o.ImageArchive != "" {
			a, err := hashTrustArtifact(ctx, o.ImageArchive, 4<<30)
			if err != nil {
				return err
			}
			m.ImageArchive, m.ImageConfigSHA256 = &a, o.ImageConfigSHA256
		}
		raw, err := json.Marshal(m)
		if err != nil {
			return errReleaseOptions
		}
		signature := ed25519.Sign(key, raw)
		trusted, err := VerifyReleaseManifest(raw, signature, key.Public().(ed25519.PublicKey))
		if err != nil {
			return err
		}
		if err = publishTrustFiles(ctx, o.Output, map[string][]byte{"release.json": raw, "release.sig": signature}); err != nil {
			return err
		}
		return writeReleaseResult(out, trusted, key.Public().(ed25519.PublicKey), true, o.ImageArchive != "")
	case "verify":
		remaining.PublicKeyFile, remaining.Manifest, remaining.Signature, remaining.Helper, remaining.NativeBundle, remaining.ImageArchive = "", "", "", "", "", ""
		if remaining != (ReleaseOptions{}) || o.PublicKeyFile == "" || o.Manifest == "" || o.Signature == "" || (o.Helper == "") != (o.NativeBundle == "") || o.ImageArchive != "" && o.Helper == "" {
			return errReleaseOptions
		}
		r, pub, err := LoadTrustedRelease(o.Manifest, o.Signature, o.PublicKeyFile)
		if err != nil {
			return err
		}
		if o.Helper != "" {
			for _, artifact := range []struct {
				path     string
				expected ReleaseArtifact
				limit    uint64
			}{{o.Helper, r.manifest.Helper, 256 << 20}, {o.NativeBundle, r.manifest.Native, 4 << 30}} {
				got, err := hashTrustArtifact(ctx, artifact.path, artifact.limit)
				if err != nil || got != artifact.expected {
					return DeploymentFailure{"artifact-invalid"}
				}
			}
		}
		if o.ImageArchive != "" {
			if r.manifest.ImageArchive == nil {
				return DeploymentFailure{"artifact-invalid"}
			}
			got, err := hashTrustArtifact(ctx, o.ImageArchive, 4<<30)
			if err != nil || got != *r.manifest.ImageArchive {
				return DeploymentFailure{"artifact-invalid"}
			}
		}
		return writeReleaseResult(out, r, pub, o.Helper != "", o.ImageArchive != "")
	default:
		return errReleaseOptions
	}
}

func loadSigningKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readTrustData(path, true, 4096)
	if err != nil {
		return nil, errSigningKey
	}
	defer clear(raw)
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errSigningKey
	}
	defer clear(block.Bytes)
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := value.(ed25519.PrivateKey)
	if err != nil || !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errSigningKey
	}
	return key, nil
}

func LoadTrustedRelease(manifest, signature, publicKeyFile string) (*TrustedRelease, ed25519.PublicKey, error) {
	public, err := readTrustData(publicKeyFile, false, 4096)
	if err != nil {
		return nil, nil, errSigningKey
	}
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, nil, errSigningKey
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	pub, ok := value.(ed25519.PublicKey)
	if err != nil || !ok || len(pub) != ed25519.PublicKeySize {
		return nil, nil, errSigningKey
	}
	raw, err := readTrustData(manifest, false, 64<<10)
	if err != nil {
		return nil, nil, err
	}
	sig, err := readTrustData(signature, false, ed25519.SignatureSize)
	if err != nil {
		return nil, nil, err
	}
	r, err := VerifyReleaseManifest(raw, sig, pub)
	return r, pub, err
}

func writeReleaseResult(out io.Writer, r *TrustedRelease, pub ed25519.PublicKey, artifacts, archive bool) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return errSigningKey
	}
	return json.NewEncoder(out).Encode(map[string]any{"status": "verified", "release": r.manifest.Release, "manifest_sha256": r.SHA256(), "public_key_sha256": digest(der), "artifacts_verified": artifacts, "image_archive_verified": archive})
}

func hashTrustArtifact(ctx context.Context, path string, limit uint64) (ReleaseArtifact, error) {
	f, err := openTrustFile(path, true, int64(limit))
	if err != nil {
		return ReleaseArtifact{}, DeploymentFailure{"artifact-invalid"}
	}
	defer f.Close()
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	var size uint64
	for {
		if err := ctx.Err(); err != nil {
			return ReleaseArtifact{}, err
		}
		n, err := f.Read(buffer)
		size += uint64(n)
		if size > limit {
			return ReleaseArtifact{}, DeploymentFailure{"artifact-invalid"}
		}
		h.Write(buffer[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return ReleaseArtifact{}, DeploymentFailure{"artifact-invalid"}
		}
	}
	if size == 0 {
		return ReleaseArtifact{}, DeploymentFailure{"artifact-invalid"}
	}
	return ReleaseArtifact{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: size}, nil
}

type VaultOptions struct{ Action, Output, KeyFile string }

// Initializing never reads or changes PostgreSQL. Key replacement is explicit:
// create a new directory, keep old keys/backups, then rewrap via the vault API.
func VaultCommand(ctx context.Context, o VaultOptions, out io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch o.Action {
	case "init-key":
		if o.Output == "" || o.KeyFile != "" {
			return errors.New("凭据密钥初始化仅接受 --output 新私有目录")
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return ErrCredentialUnavailable
		}
		defer clear(key)
		sum := sha256.Sum256(key)
		encoded := []byte(hex.EncodeToString(key) + "\n")
		defer clear(encoded)
		if err := publishTrustFiles(ctx, o.Output, map[string][]byte{"vault.key": encoded}); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"status": "initialized", "algorithm": "AES-256-GCM", "key_id": hex.EncodeToString(sum[:16])})
	case "check":
		if o.KeyFile == "" || o.Output != "" {
			return errors.New("凭据密钥检查仅接受 --key-file")
		}
		raw, err := readTrustData(o.KeyFile, true, 128)
		if err != nil {
			return ErrCredentialUnavailable
		}
		defer clear(raw)
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(key) != 32 {
			return ErrCredentialUnavailable
		}
		defer clear(key)
		sum := sha256.Sum256(key)
		return json.NewEncoder(out).Encode(map[string]string{"status": "verified", "algorithm": "AES-256-GCM", "key_id": hex.EncodeToString(sum[:16])})
	default:
		return errors.New("凭据密钥操作须为 init-key 或 check")
	}
}
