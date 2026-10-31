package controlplane

// A maintenance overlay authenticates a new helper independently of the
// immutable installation. The old helper, installation journal and key seeds
// remain valid for recovery; a timer is never allowed to migrate the database.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"webscan/internal/deploy"
)

var errSinglePKIUpgrade = errors.New("证书维护升级资料校验失败；请核对原安装、独立信任公钥、发布签名及维护程序版本，原安装和密钥未修改")

type singlePKIUpgradeSpec struct {
	Format        int    `json:"format"`
	Installation  string `json:"installation_file"`
	PublicKeyFile string `json:"release_public_key_file"`
	ManifestFile  string `json:"release_manifest_file"`
	SignatureFile string `json:"release_signature_file"`
	HelperFile    string `json:"helper_file"`
}

type singlePKIUpgradeManifest struct {
	Format          int               `json:"format"`
	Directory       string            `json:"directory"`
	Installation    string            `json:"installation_file"`
	InstallationSHA string            `json:"installation_sha256"`
	PublicKeyFile   string            `json:"release_public_key_file"`
	PublicKeySHA    string            `json:"release_public_key_sha256"`
	ReleaseSHA      string            `json:"release_manifest_sha256"`
	Schema          int               `json:"schema_version"`
	Files           map[string]string `json:"files"`
}

func singlePKIUpgradePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsAny(path, "%\r\n\x00")
}

func singlePKIUpgradeInstallation(path string) (singleInstallManifest, []byte, singleInstallJournal, error) {
	var m singleInstallManifest
	raw, err := readTrustData(path, true, 64<<10)
	if err != nil || singleDecode(raw, &m) != nil || m.Spec.validate() != nil || m.Spec.Format < 2 || path != filepath.Join(m.Spec.Root, "install.json") {
		return m, nil, singleInstallJournal{}, errSinglePKIUpgrade
	}
	// Verify the ORIGINAL helper against the original manifest, not against the
	// executing upgraded binary. All other immutable files are still checked.
	j, err := readSingleInstallation(m.Spec, m.Files["webscan"])
	if err != nil {
		return m, nil, j, errSinglePKIUpgrade
	}
	return m, raw, j, nil
}

func singlePKIUpgradeFiles(ctx context.Context, s singlePKIUpgradeSpec, output string) (map[string][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.Format != 1 || !singlePKIUpgradePath(output) {
		return nil, errSinglePKIUpgrade
	}
	seen := map[string]bool{}
	for _, path := range []string{s.Installation, s.PublicKeyFile, s.ManifestFile, s.SignatureFile, s.HelperFile} {
		if !singlePKIUpgradePath(path) || seen[path] || path == output || strings.HasPrefix(path, output+"/") {
			return nil, errSinglePKIUpgrade
		}
		seen[path] = true
	}
	m, install, _, err := singlePKIUpgradeInstallation(s.Installation)
	if err != nil || output == m.Spec.Root || strings.HasPrefix(output, m.Spec.Root+"/") {
		return nil, errSinglePKIUpgrade
	}
	r, _, err := LoadTrustedRelease(s.ManifestFile, s.SignatureFile, s.PublicKeyFile)
	if err != nil {
		return nil, errSinglePKIUpgrade
	}
	files := map[string][]byte{}
	for name, path := range map[string]string{"release.pub": s.PublicKeyFile, "release.json": s.ManifestFile, "release.sig": s.SignatureFile, "webscan": s.HelperFile} {
		limit := int64(512 << 10)
		if name == "webscan" {
			limit = 256 << 20
		}
		files[name], err = readTrustData(path, name == "webscan", limit)
		if err != nil {
			return nil, errSinglePKIUpgrade
		}
	}
	// Verify the exact copied bytes, including the trust anchor, to reject a
	// replacement between signature verification and overlay publication.
	if digest(files["release.json"]) != r.SHA256() || digest(files["webscan"]) != r.manifest.Helper.SHA256 || uint64(len(files["webscan"])) != r.manifest.Helper.Bytes {
		return nil, errSinglePKIUpgrade
	}
	anchor, err := readTrustData(s.PublicKeyFile, false, 64<<10)
	if err != nil || !bytes.Equal(anchor, files["release.pub"]) || verifySinglePKIUpgradeSignature(files, anchor) != nil {
		return nil, errSinglePKIUpgrade
	}
	service, timer := singlePKIUnits(m.Spec)
	oldCommand := "ExecStart=" + strconv.Quote(filepath.Join(m.Spec.Root, "webscan")) + " control-v3 --action maintain-single-pki --source " + strconv.Quote(s.Installation)
	newCommand := "ExecStart=" + strconv.Quote(filepath.Join(output, "webscan")) + " control-v3 --action maintain-single-pki-upgrade --source " + strconv.Quote(filepath.Join(output, "maintenance.json"))
	if bytes.Count(service, []byte(oldCommand)) != 1 {
		return nil, errSinglePKIUpgrade
	}
	files["pki-maintenance.service"] = bytes.Replace(service, []byte(oldCommand), []byte(newCommand), 1)
	files["pki-maintenance.timer"] = timer
	manifest := singlePKIUpgradeManifest{Format: 1, Directory: output, Installation: s.Installation, InstallationSHA: digest(install), PublicKeyFile: s.PublicKeyFile, PublicKeySHA: digest(anchor), ReleaseSHA: r.SHA256(), Schema: SchemaVersion, Files: map[string]string{}}
	for name, raw := range files {
		manifest.Files[name] = digest(raw)
	}
	files["maintenance.json"], _ = json.Marshal(manifest)
	return files, nil
}

func verifySinglePKIUpgradeSignature(files map[string][]byte, anchor []byte) error {
	// The on-disk independent public key remains the trust root. A public key
	// copied into an overlay alone cannot authorize its own helper.
	r, _, err := verifyTrustedReleaseData(files["release.json"], files["release.sig"], anchor)
	if err != nil || r.manifest.Helper.SHA256 != digest(files["webscan"]) || r.manifest.Helper.Bytes != uint64(len(files["webscan"])) {
		return errSinglePKIUpgrade
	}
	return nil
}

func readSinglePKIUpgrade(ctx context.Context, source, executable, executingRelease string) (singleInstallSpec, string, error) {
	var m singlePKIUpgradeManifest
	raw, err := readTrustData(source, true, 64<<10)
	if err != nil || singleDecode(raw, &m) != nil || m.Format != 1 || m.Schema != SchemaVersion || !singlePKIUpgradePath(m.Directory) || source != filepath.Join(m.Directory, "maintenance.json") {
		return singleInstallSpec{}, "", errSinglePKIUpgrade
	}
	dir, err := trustDirectory(m.Directory, true)
	if err != nil {
		return singleInstallSpec{}, "", errSinglePKIUpgrade
	}
	dir.Close()
	installed, install, j, err := singlePKIUpgradeInstallation(m.Installation)
	if err != nil || j.Step < 2 || digest(install) != m.InstallationSHA || singlePKIBound(installed.Spec) != nil {
		return singleInstallSpec{}, "", errSinglePKIUpgrade
	}
	anchor, err := readTrustData(m.PublicKeyFile, false, 64<<10)
	if err != nil || digest(anchor) != m.PublicKeySHA {
		return singleInstallSpec{}, "", errSinglePKIUpgrade
	}
	names := []string{"release.pub", "release.json", "release.sig", "webscan", "pki-maintenance.service", "pki-maintenance.timer"}
	if len(m.Files) != len(names) {
		return singleInstallSpec{}, "", errSinglePKIUpgrade
	}
	files := map[string][]byte{}
	for _, name := range names {
		if ctx.Err() != nil {
			return singleInstallSpec{}, "", ctx.Err()
		}
		limit := int64(512 << 10)
		if name == "webscan" {
			limit = 256 << 20
		}
		files[name], err = readTrustData(filepath.Join(m.Directory, name), true, limit)
		if err != nil || digest(files[name]) != m.Files[name] {
			return singleInstallSpec{}, "", errSinglePKIUpgrade
		}
	}
	if !bytes.Equal(anchor, files["release.pub"]) || digest(files["release.json"]) != m.ReleaseSHA || verifySinglePKIUpgradeSignature(files, anchor) != nil {
		return singleInstallSpec{}, "", errSinglePKIUpgrade
	}
	if executable != "" {
		binary, err := readTrustData(executable, true, 256<<20)
		if err != nil || digest(binary) != m.Files["webscan"] || executable != filepath.Join(m.Directory, "webscan") {
			return singleInstallSpec{}, "", errSinglePKIUpgrade
		}
		release, _, err := verifyTrustedReleaseData(files["release.json"], files["release.sig"], anchor)
		if err != nil || !releaseVersion.MatchString(executingRelease) || release.manifest.Release != executingRelease {
			return singleInstallSpec{}, "", errSinglePKIUpgrade
		}
	}
	return installed.Spec, m.ReleaseSHA, nil
}

func singlePKIUpgradeCommand(ctx context.Context, o Options, out io.Writer) error {
	if o.Action == "preview-single-pki-upgrade" || o.Action == "prepare-single-pki-upgrade" {
		var s singlePKIUpgradeSpec
		raw, err := readTrustData(o.Source, true, 64<<10)
		if err != nil || singleDecode(raw, &s) != nil {
			return errSinglePKIUpgrade
		}
		files, err := singlePKIUpgradeFiles(ctx, s, o.Output)
		if err != nil {
			return err
		}
		state := "preview"
		if o.Action == "prepare-single-pki-upgrade" {
			if err := publishTrustFiles(ctx, o.Output, files); err != nil {
				return err
			}
			if err := os.Chmod(filepath.Join(o.Output, "webscan"), 0700); err != nil {
				return errSinglePKIUpgrade
			}
			state = "prepared"
		}
		return json.NewEncoder(out).Encode(map[string]any{"state": state, "directory": o.Output, "schema_version": SchemaVersion, "immutable_installation_unchanged": true, "activation_required": true})
	}
	executable := ""
	if o.Action == "maintain-single-pki-upgrade" {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 || o.Topology != "" || o.PasswordFile != "" {
			return errSinglePKIUpgrade
		}
		var err error
		executable, err = os.Executable()
		if err != nil {
			return errSinglePKIUpgrade
		}
	}
	s, release, err := readSinglePKIUpgrade(ctx, o.Source, executable, deploy.Release)
	if err != nil {
		return err
	}
	if o.Action == "check-single-pki-upgrade" {
		return json.NewEncoder(out).Encode(map[string]any{"state": "verified", "schema_version": SchemaVersion, "release_manifest_sha256": release, "database_checked": false, "activation_required": true})
	}
	_, _, j, err := singlePKIUpgradeInstallation(filepath.Join(s.Root, "install.json"))
	if err != nil {
		return errSinglePKIUpgrade
	}
	receipt, err := maintainSinglePKIHostCycle(ctx, s, time.Now().UTC(), j.Step >= 3)
	if encode := json.NewEncoder(out).Encode(receipt); encode != nil {
		return encode
	}
	return err
}
