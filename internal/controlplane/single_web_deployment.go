package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var singleWebDeploymentFiles = []string{"vault.key", "release.pub", "release.json", "release.sig", "rules.yar", "executor.yaml", "executor.service"}

func prepareSingleWebDeployment(ctx context.Context, s singleInstallSpec, files map[string][]byte) error {
	source := *s.ReleaseTrust
	release, _, err := LoadTrustedRelease(source.ManifestFile, source.SignatureFile, source.PublicKeyFile)
	if err != nil {
		return err
	}
	if digest(files["webscan"]) != release.manifest.Helper.SHA256 || uint64(len(files["webscan"])) != release.manifest.Helper.Bytes {
		return errSingleInstall
	}
	for _, entry := range []struct {
		path     string
		artifact ReleaseArtifact
	}{{source.HelperFile, release.manifest.Helper}, {source.NativeBundleFile, release.manifest.Native}} {
		got, err := hashTrustArtifact(ctx, entry.path, 4<<30)
		if err != nil || got != entry.artifact {
			return errSingleInstall
		}
	}
	if source.ImageArchiveFile != "" {
		if release.manifest.ImageArchive == nil {
			return errSingleInstall
		}
		got, err := hashTrustArtifact(ctx, source.ImageArchiveFile, 4<<30)
		if err != nil || got != *release.manifest.ImageArchive {
			return errSingleInstall
		}
	}
	for name, path := range map[string]string{"release.pub": source.PublicKeyFile, "release.json": source.ManifestFile, "release.sig": source.SignatureFile, "rules.yar": s.RulesFile} {
		raw, err := readTrustData(path, false, 512<<10)
		if err != nil {
			return err
		}
		files[name] = raw
	}
	// The new directory is published no-replace. A resume never calls this
	// generator and validates the original immutable Vault bytes instead.
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return err
	}
	defer clear(secret[:])
	files["vault.key"] = []byte(hex.EncodeToString(secret[:]))
	c := s.configuration()
	c.Executor = ExecutorConfig{Enabled: true, Mode: "embedded", ConfigurationDirectory: filepath.Join(s.Root, "state", "node-configurations"), RulesFile: filepath.Join(s.Root, "rules.yar")}
	c.NodePKI = NodePKIConfig{Enabled: true, AuthorityDirectory: filepath.Join(s.Root, "authority")}
	c.DeploymentTrust.HelperFile = source.HelperFile
	c.DeploymentTrust.NativeBundleFile = source.NativeBundleFile
	c.DeploymentTrust.ImageArchiveFile = source.ImageArchiveFile
	if c.Validate() != nil {
		return errSingleInstall
	}
	files["executor.yaml"], err = yaml.Marshal(c)
	if err != nil {
		return err
	}
	files["executor.service"] = []byte("[Unit]\nDescription=Webscan host deployment executor\nRequires=docker.service\nAfter=docker.service network-online.target " + singleProject(s.Root) + ".service\nWants=network-online.target\n\n[Service]\nType=simple\nUMask=0077\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=yes\nExecStart=" + strconv.Quote(filepath.Join(s.Root, "webscan")) + " control-v3 --config " + strconv.Quote(filepath.Join(s.Root, "executor.yaml")) + " --action run --role executor\n\n[Install]\nWantedBy=multi-user.target\n")
	return nil
}
func (i singleInstaller) verifySingleWebDeployment(ctx context.Context, s singleInstallSpec) error {
	expected, err := readTrustData(filepath.Join(s.Root, "executor.service"), true, 64<<10)
	if err != nil {
		return err
	}
	actual, err := readTrustData(filepath.Join(i.unitDirectory, singleProject(s.Root)+"-executor.service"), true, 64<<10)
	if err != nil || digest(expected) != digest(actual) {
		return errSingleInstall
	}
	for _, state := range []string{"is-enabled", "is-active"} {
		if _, err = i.run(ctx, "systemctl", state, "--quiet", singleProject(s.Root)+"-executor.service"); err != nil {
			return errSingleInstall
		}
	}
	return nil
}

// Verify the actual executable from the pinned image before starting it. New
// installs never hide an old image behind a bind-mounted pilot executable.
func (i singleInstaller) verifyCentralExecutable(ctx context.Context, s singleInstallSpec) error {
	raw, err := i.imageInspect(ctx, "{{json .Config.Cmd}}", s.RuntimeImage)
	var cmd []string
	if err != nil || json.Unmarshal(raw, &cmd) != nil || len(cmd) == 0 || cmd[0] != "control-v3" {
		return errSingleInstall
	}
	dir, err := os.MkdirTemp(s.Root, ".verify-image-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	raw, err = i.run(ctx, i.docker, "create", "--network", "none", "--read-only", "--entrypoint", "/usr/local/bin/webscan", s.RuntimeImage, "--version")
	id := strings.TrimSpace(string(raw))
	if err != nil || !releaseDigest(id) {
		return errSingleInstall
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = i.run(cleanup, i.docker, "rm", id)
	}()
	path := filepath.Join(dir, "webscan")
	if _, err = i.run(ctx, i.docker, "cp", id+":/usr/local/bin/webscan", path); err != nil {
		return errSingleInstall
	}
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	got, err := hashTrustArtifact(ctx, path, 256<<20)
	if err != nil {
		return err
	}
	want, err := hashTrustArtifact(ctx, filepath.Join(s.Root, "webscan"), 256<<20)
	if err != nil || got != want {
		return errSingleInstall
	}
	return nil
}
