package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

type trustToolFixture struct {
	root, signing, vault, helper, native, image, signed string
	sign                                                ReleaseOptions
}

// Formal artifact acceptance uses the same fixtures with the exact published
// release. Ordinary tests retain their isolated, non-release default.
func deploymentFixtureRelease(t *testing.T) string {
	t.Helper()
	version := os.Getenv("WEBSCAN_V3_TEST_RELEASE")
	if version == "" {
		return "v3.0.0-local-test"
	}
	if !releaseVersion.MatchString(version) || len(version) > 128 {
		t.Fatal("invalid explicit acceptance release")
	}
	return version
}

func newTrustToolFixture(t *testing.T) trustToolFixture {
	t.Helper()
	f := trustToolFixture{root: privateTestDir(t)}
	f.signing, f.vault, f.signed = filepath.Join(f.root, "signing"), filepath.Join(f.root, "vault"), filepath.Join(f.root, "release")
	f.helper, f.native, f.image = filepath.Join(f.root, "helper"), filepath.Join(f.root, "native.tar.gz"), filepath.Join(f.root, "image.tar")
	for _, path := range []string{f.helper, f.native, f.image} {
		if err := os.WriteFile(path, []byte("isolated-artifact-"+filepath.Base(path)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := ReleaseCommand(context.Background(), ReleaseOptions{Action: "init-key", Output: f.signing}, &out); err != nil {
		t.Fatal(err)
	}
	if err := VaultCommand(context.Background(), VaultOptions{Action: "init-key", Output: f.vault}, &out); err != nil {
		t.Fatal(err)
	}
	f.sign = ReleaseOptions{Action: "sign", Output: f.signed, KeyFile: filepath.Join(f.signing, "signing.key"), Release: deploymentFixtureRelease(t), Helper: f.helper, NativeBundle: f.native, AgentImage: "docker.io/gzdzh/webscan-agent@sha256:" + strings.Repeat("a", 64), ImageArchive: f.image, ImageConfigSHA256: strings.Repeat("b", 64)}
	if err := ReleaseCommand(context.Background(), f.sign, &out); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f trustToolFixture) verify() ReleaseOptions {
	return ReleaseOptions{Action: "verify", PublicKeyFile: filepath.Join(f.signing, "signing.pub"), Manifest: filepath.Join(f.signed, "release.json"), Signature: filepath.Join(f.signed, "release.sig"), Helper: f.helper, NativeBundle: f.native, ImageArchive: f.image}
}

func (f trustToolFixture) config() DeploymentTrustConfig {
	return DeploymentTrustConfig{VaultKeyFile: filepath.Join(f.vault, "vault.key"), PublicKeyFile: filepath.Join(f.signing, "signing.pub"), ManifestFile: filepath.Join(f.signed, "release.json"), SignatureFile: filepath.Join(f.signed, "release.sig"), HelperFile: f.helper, NativeBundleFile: f.native, ImageArchiveFile: f.image}
}

func TestOfflineReleaseExplicitAcceptanceVersion(t *testing.T) {
	t.Setenv("WEBSCAN_V3_TEST_RELEASE", "v3.0.0")
	f := newTrustToolFixture(t)
	var out bytes.Buffer
	if err := ReleaseCommand(context.Background(), f.verify(), &out); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result["release"] != "v3.0.0" || result["artifacts_verified"] != true {
		t.Fatal("explicit acceptance release not retained", out.String(), err)
	}
}

func TestOfflineReleaseRoundTripIndependentTrustAndNoSecretOutput(t *testing.T) {
	f := newTrustToolFixture(t)
	ctx := context.Background()
	var out bytes.Buffer
	if err := ReleaseCommand(ctx, f.verify(), &out); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result["artifacts_verified"] != true || result["image_archive_verified"] != true {
		t.Fatal("incorrect result", out.String(), err)
	}
	keyRaw, _ := os.ReadFile(f.sign.KeyFile)
	block, _ := pem.Decode(keyRaw)
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := value.(ed25519.PrivateKey)
	manifest, _ := os.ReadFile(f.verify().Manifest)
	signature, _ := os.ReadFile(f.verify().Signature)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), manifest, signature) {
		t.Fatal("not a standard detached Ed25519 signature")
	}
	for _, path := range []string{f.signing, f.vault, f.signed} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != 0700 {
			t.Fatal("unsafe directory", err)
		}
		entries, _ := os.ReadDir(path)
		for _, e := range entries {
			st, err := os.Stat(filepath.Join(path, e.Name()))
			if err != nil || st.Mode().Perm() != 0600 {
				t.Fatal("unsafe file", err)
			}
		}
	}
	// Public trust may be installed read-only and need not be secret.
	for _, path := range []string{f.verify().PublicKeyFile, f.verify().Manifest, f.verify().Signature} {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := ReleaseCommand(ctx, f.verify(), &out); err != nil {
		t.Fatal(err)
	}
	metadata := f.verify()
	metadata.Helper, metadata.NativeBundle, metadata.ImageArchive = "", "", ""
	out.Reset()
	if err := ReleaseCommand(ctx, metadata, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"artifacts_verified":false`) {
		t.Fatal("metadata verification falsely verified artifacts")
	}
	// Signing twice is deterministic and never rotates the key implicitly.
	second := f.sign
	second.Output = filepath.Join(f.root, "second")
	if err := ReleaseCommand(ctx, second, &out); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(second.Output, "release.sig"))
	if !bytes.Equal(got, signature) {
		t.Fatal("signature changed for identical bytes")
	}
	if strings.Contains(out.String(), "PRIVATE KEY") || strings.Contains(out.String(), hex.EncodeToString(key.Seed())) {
		t.Fatal("secret in output")
	}
}

func TestOfflineReleaseRejectsWrongKeyTamperingAndUnsafeArtifacts(t *testing.T) {
	f := newTrustToolFixture(t)
	ctx := context.Background()
	var out bytes.Buffer
	other := filepath.Join(f.root, "other")
	if err := ReleaseCommand(ctx, ReleaseOptions{Action: "init-key", Output: other}, &out); err != nil {
		t.Fatal(err)
	}
	wrong := f.verify()
	wrong.PublicKeyFile = filepath.Join(other, "signing.pub")
	if err := ReleaseCommand(ctx, wrong, &out); err == nil {
		t.Fatal("untrusted signer accepted")
	}
	for _, path := range []string{f.verify().Manifest, f.verify().Signature, f.helper, f.native, f.image} {
		raw, _ := os.ReadFile(path)
		tampered := append([]byte{}, raw...)
		tampered[len(tampered)-1] ^= 1
		if err := os.WriteFile(path, tampered, 0600); err != nil {
			t.Fatal(err)
		}
		if err := ReleaseCommand(ctx, f.verify(), &out); err == nil {
			t.Fatal("tampering accepted", filepath.Base(path))
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"symlink", "hardlink", "fifo", "public", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(f.root, kind)
			switch kind {
			case "symlink":
				if err := os.Symlink(f.helper, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.helper, path); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(path)
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				h, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				err = h.Truncate((256 << 20) + 1)
				h.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			op := f.sign
			op.Output = filepath.Join(f.root, "bad-"+kind)
			op.Helper = path
			if err := ReleaseCommand(ctx, op, &out); err == nil {
				t.Fatal("unsafe artifact signed")
			}
			if _, err := os.Lstat(op.Output); !os.IsNotExist(err) {
				t.Fatal("failed sign published output")
			}
		})
	}
	if err := os.Chmod(f.sign.KeyFile, 0644); err != nil {
		t.Fatal(err)
	}
	privateTest := f.sign
	privateTest.Output = filepath.Join(f.root, "bad-key")
	if err := ReleaseCommand(ctx, privateTest, &out); err == nil {
		t.Fatal("public signing private key accepted")
	}
}

func TestTrustPublicationConcurrentNoOverwriteCancellationAndPathSafety(t *testing.T) {
	root := privateTestDir(t)
	ctx := context.Background()
	target := filepath.Join(root, "keys")
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if VaultCommand(ctx, VaultOptions{Action: "init-key", Output: target}, &bytes.Buffer{}) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("concurrent key creation", successes.Load())
	}
	keyPath := filepath.Join(target, "vault.key")
	before, _ := os.ReadFile(keyPath)
	if err := VaultCommand(ctx, VaultOptions{Action: "init-key", Output: target}, &bytes.Buffer{}); err == nil {
		t.Fatal("existing key overwritten")
	}
	after, _ := os.ReadFile(keyPath)
	if !bytes.Equal(before, after) {
		t.Fatal("existing key changed")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", filepath.Join(root, "unused") + "/../escaped", filepath.Join(link, "escape")} {
		if err := VaultCommand(ctx, VaultOptions{Action: "init-key", Output: path}, &bytes.Buffer{}); err == nil {
			t.Fatal("unsafe output path accepted", path)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := VaultCommand(cancelled, VaultOptions{Action: "init-key", Output: filepath.Join(root, "cancelled")}, &bytes.Buffer{}); err == nil {
		t.Fatal("cancelled operation published")
	}
	if err := ReleaseCommand(cancelled, ReleaseOptions{Action: "init-key", Output: filepath.Join(root, "cancelled-sign")}, &bytes.Buffer{}); err == nil {
		t.Fatal("cancelled signing init published")
	}
	// An existing symlink target must never be replaced or followed.
	symlinkTarget := filepath.Join(root, "existing-link")
	if err := os.Symlink(target, symlinkTarget); err != nil {
		t.Fatal(err)
	}
	if err := VaultCommand(ctx, VaultOptions{Action: "init-key", Output: symlinkTarget}, &bytes.Buffer{}); err == nil {
		t.Fatal("existing symlink overwritten")
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".trust-") {
			t.Fatal("unpublished stage leaked")
		}
	}
}

func TestVaultToolsKeyIdentityAndInvalidInputs(t *testing.T) {
	f := newTrustToolFixture(t)
	ctx := context.Background()
	var out bytes.Buffer
	keyPath := filepath.Join(f.vault, "vault.key")
	if err := VaultCommand(ctx, VaultOptions{Action: "check", KeyFile: keyPath}, &out); err != nil {
		t.Fatal(err)
	}
	v, err := OpenVault(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), v.active) {
		t.Fatal("key identity differs from vault")
	}
	copyPath := filepath.Join(f.root, "copied-vault.key")
	copied, _ := os.ReadFile(keyPath)
	if err := os.WriteFile(copyPath, copied, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVault(keyPath, copyPath); err == nil {
		t.Fatal("same key configured twice")
	}
	raw, _ := os.ReadFile(keyPath)
	if strings.Contains(out.String(), strings.TrimSpace(string(raw))) {
		t.Fatal("key leaked")
	}
	for _, o := range []VaultOptions{{Action: "init-key", Output: filepath.Join(f.root, "invalid"), KeyFile: keyPath}, {Action: "check", KeyFile: keyPath, Output: f.root}, {Action: "check"}, {Action: "unknown"}} {
		if err := VaultCommand(ctx, o, &out); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	link := filepath.Join(f.root, "vault-link")
	if err := os.Symlink(f.vault, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVault(filepath.Join(link, "vault.key")); err == nil {
		t.Fatal("vault key ancestor symlink accepted")
	}
	hard := filepath.Join(f.root, "vault-hardlink")
	if err := os.Link(keyPath, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVault(keyPath); err == nil {
		t.Fatal("multiply linked key accepted")
	}
	if err := os.Remove(hard); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("z", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VaultCommand(ctx, VaultOptions{Action: "check", KeyFile: keyPath}, &out); err == nil {
		t.Fatal("malformed key accepted")
	}
}

func TestTrustPublicationLowDiskLeavesNoPartialKey(t *testing.T) {
	root := os.Getenv("WEBSCAN_V3_TRUST_LOW_DISK_DIRECTORY")
	if root == "" {
		t.Skip("requires explicit isolated small tmpfs")
	}
	dir, err := trustDirectory(root, true)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(dir.Fd()), &fs) != nil || uint64(fs.Bavail)*uint64(fs.Bsize) > 2<<20 {
		t.Fatal("test requires at most 2 MiB free")
	}
	target := filepath.Join(root, "incomplete-key")
	if err := publishTrustFiles(context.Background(), target, map[string][]byte{"vault.key": bytes.Repeat([]byte("x"), 3<<20)}); err == nil {
		t.Fatal("full filesystem reported success")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("partial output published")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed stage was not cleaned", err)
	}
}

func TestReleaseOptionsFailClosed(t *testing.T) {
	f := newTrustToolFixture(t)
	for _, change := range []func(*ReleaseOptions){
		func(o *ReleaseOptions) { o.AgentImage = "agent:latest" }, func(o *ReleaseOptions) { o.Release = "latest" }, func(o *ReleaseOptions) { o.ImageConfigSHA256 = "" }, func(o *ReleaseOptions) { o.ImageArchive = "" }, func(o *ReleaseOptions) { o.Manifest = f.verify().Manifest }, func(o *ReleaseOptions) { o.Signature = f.verify().Signature }, func(o *ReleaseOptions) { o.PublicKeyFile = f.verify().PublicKeyFile },
	} {
		o := f.sign
		o.Output = filepath.Join(f.root, "bad-options-"+token())
		change(&o)
		if err := ReleaseCommand(context.Background(), o, &bytes.Buffer{}); err == nil {
			t.Fatal("invalid signing options accepted")
		}
	}
	for _, change := range []func(*ReleaseOptions){func(o *ReleaseOptions) { o.KeyFile = f.sign.KeyFile }, func(o *ReleaseOptions) { o.NativeBundle = "" }, func(o *ReleaseOptions) { o.Output = f.root }, func(o *ReleaseOptions) { o.Release = "v3.0.1" }} {
		o := f.verify()
		change(&o)
		if err := ReleaseCommand(context.Background(), o, &bytes.Buffer{}); err == nil {
			t.Fatal("invalid verification options accepted")
		}
	}
}

func TestDeploymentTrustConfigurationBindsIndependentFilesWithoutDatabase(t *testing.T) {
	f := newTrustToolFixture(t)
	ctx := context.Background()
	var out bytes.Buffer
	c := f.config()
	if err := checkDeploymentTrust(ctx, c, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"executor_enabled":false`) {
		t.Fatal("trust check enabled deployment")
	}
	if err := (DeploymentTrustConfig{}).validate(); err != nil {
		t.Fatal("optional config should preserve old installations")
	}
	if err := checkDeploymentTrust(ctx, DeploymentTrustConfig{}, &out); err == nil {
		t.Fatal("unconfigured trust accepted")
	}
	for _, change := range []func(*DeploymentTrustConfig){func(c *DeploymentTrustConfig) { c.VaultKeyFile = "" }, func(c *DeploymentTrustConfig) { c.PublicKeyFile = "relative" }, func(c *DeploymentTrustConfig) { c.SignatureFile = c.ManifestFile }, func(c *DeploymentTrustConfig) { c.HelperFile = f.root + "/sub/../helper" }, func(c *DeploymentTrustConfig) { c.PreviousKeyFiles = []string{c.VaultKeyFile} }, func(c *DeploymentTrustConfig) { c.PreviousKeyFiles = make([]string, 9) }} {
		bad := c
		change(&bad)
		if err := bad.validate(); err == nil {
			t.Fatal("invalid trust config accepted")
		}
	}
	second := filepath.Join(f.root, "second-vault")
	if err := VaultCommand(ctx, VaultOptions{Action: "init-key", Output: second}, &out); err != nil {
		t.Fatal(err)
	}
	c.PreviousKeyFiles = []string{filepath.Join(second, "vault.key")}
	if err := checkDeploymentTrust(ctx, c, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"previous_vault_keys":1`) {
		t.Fatal("old key not loaded")
	}
	// Parse full YAML then check trust with an absent DSN file: this action
	// deliberately never opens PostgreSQL or contacts any remote service.
	configPath := filepath.Join(f.root, "control.yaml")
	if err := Initialize(Options{Config: configPath, NonInteractive: true, PublicURL: "https://monitor.example.test"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	base, _ := os.ReadFile(configPath)
	extra := "\ndeployment_trust:\n  vault_key_file: " + c.VaultKeyFile + "\n  release_public_key_file: " + c.PublicKeyFile + "\n  release_manifest_file: " + c.ManifestFile + "\n  release_signature_file: " + c.SignatureFile + "\n  helper_file: " + c.HelperFile + "\n  native_bundle_file: " + c.NativeBundleFile + "\n"
	if err := os.WriteFile(configPath, append(base, extra...), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Command(ctx, Options{Config: configPath, Action: "check-deployment-trust"}, strings.NewReader(""), &out); err != nil {
		t.Fatal("trust check unexpectedly requires database", err)
	}
	if err := os.WriteFile(f.helper, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkDeploymentTrust(ctx, c, &out); err == nil {
		t.Fatal("changed helper accepted")
	}
}
