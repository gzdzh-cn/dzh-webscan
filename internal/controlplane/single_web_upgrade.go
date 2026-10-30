package controlplane

// Upgrade packages are overlays: they never rewrite an immutable installation
// manifest or generate a new Vault/CA. Applying the package is a separate,
// explicit maintenance operation documented in V3-SINGLE-INSTALL.md.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type singleWebUpgradeSpec struct {
	Format         int                   `json:"format"`
	APIConfig      string                `json:"api_config"`
	ExecutorConfig string                `json:"executor_config"`
	ComposeFile    string                `json:"compose_file"`
	Project        string                `json:"project"`
	RuntimeImage   string                `json:"runtime_image"`
	RulesFile      string                `json:"rules_file"`
	Trust          DeploymentTrustConfig `json:"deployment_trust"`
}

var errSingleWebUpgrade = errors.New("升级资料不匹配、密钥不可用或挂载边界不安全；原安装资料及密钥未修改")

func singleWebUpgradeCommand(ctx context.Context, o Options, out io.Writer) error {
	var spec singleWebUpgradeSpec
	raw, err := readTrustData(o.Source, true, 64<<10)
	if err != nil || singleDecode(raw, &spec) != nil {
		return errSingleWebUpgrade
	}
	files, err := singleWebUpgradeFiles(ctx, spec, o.Output)
	if err != nil {
		return err
	}
	if o.Action == "prepare-single-web-upgrade" {
		if err = publishTrustFiles(ctx, o.Output, files); err != nil {
			return err
		}
	}
	return json.NewEncoder(out).Encode(map[string]any{"state": map[bool]string{true: "prepared", false: "preview"}[o.Action == "prepare-single-web-upgrade"], "directory": o.Output, "project": spec.Project, "runtime_image": spec.RuntimeImage, "preserves_existing_vault": true, "immutable_installation_unchanged": true, "services_changed": []string{"central", "host-executor"}, "runtime_changed": false, "migration_backup_required": true})
}
func singleWebUpgradeFiles(ctx context.Context, s singleWebUpgradeSpec, output string) (map[string][]byte, error) {
	if s.Format != 1 || !identifier.MatchString(s.Project) || !strings.HasPrefix(s.RuntimeImage, "docker.io/gzdzh/webscan-central:") || !filepath.IsAbs(output) || filepath.Clean(output) != output || output == "/" || strings.ContainsAny(output, "%\r\n\x00") {
		return nil, errSingleWebUpgrade
	}
	for _, path := range []string{s.APIConfig, s.ExecutorConfig, s.ComposeFile, s.RulesFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errSingleWebUpgrade
		}
	}
	// Parse and hash the same immutable bytes. Re-reading at the end could
	// approve a source change that was never used to generate this overlay.
	originals := map[string][]byte{}
	for _, path := range []string{s.APIConfig, s.ExecutorConfig, s.ComposeFile} {
		raw, err := readTrustData(path, true, 512<<10)
		if err != nil {
			return nil, errSingleWebUpgrade
		}
		originals[path] = raw
	}
	decodeConfig := func(raw []byte) (Config, error) {
		var c Config
		d := yaml.NewDecoder(bytes.NewReader(raw))
		d.KnownFields(true)
		if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
			return c, errSingleWebUpgrade
		}
		return c, c.Validate()
	}
	api, err := decodeConfig(originals[s.APIConfig])
	if err != nil {
		return nil, errSingleWebUpgrade
	}
	host, err := decodeConfig(originals[s.ExecutorConfig])
	if err != nil {
		return nil, errSingleWebUpgrade
	}
	if api.Central.Topology != "single" || host.Central.Topology != "single" || api.Database.DSNFile != host.Database.DSNFile || !host.NodePKI.Enabled {
		return nil, errSingleWebUpgrade
	}
	// The existing key and its rotation history are authoritative. A request
	// cannot supply a replacement key to make inaccessible ciphertext disappear.
	if s.Trust.VaultKeyFile != "" && s.Trust.VaultKeyFile != host.DeploymentTrust.VaultKeyFile || len(s.Trust.PreviousKeyFiles) > 0 {
		return nil, errSingleWebUpgrade
	}
	s.Trust.VaultKeyFile = host.DeploymentTrust.VaultKeyFile
	s.Trust.PreviousKeyFiles = host.DeploymentTrust.PreviousKeyFiles
	t, err := loadDeploymentTrust(ctx, s.Trust)
	if err != nil {
		return nil, errSingleWebUpgrade
	}
	if !strings.HasPrefix(s.RuntimeImage, "docker.io/gzdzh/webscan-central:"+t.release.manifest.Release+"@sha256:") || !releaseDigest(s.RuntimeImage[strings.LastIndex(s.RuntimeImage, ":")+1:]) {
		return nil, errSingleWebUpgrade
	}
	rules, err := readTrustData(s.RulesFile, false, 512<<10)
	if err != nil || len(rules) == 0 {
		return nil, errSingleWebUpgrade
	}
	files := map[string][]byte{}
	for name, path := range map[string]string{"release.pub": s.Trust.PublicKeyFile, "release.json": s.Trust.ManifestFile, "release.sig": s.Trust.SignatureFile} {
		files[name], err = readTrustData(path, false, 512<<10)
		if err != nil {
			return nil, err
		}
	}
	// Authenticate the copied metadata too, so a source replacement during
	// package preparation cannot publish a different trust record.
	if digest(files["release.json"]) != t.release.SHA256() {
		return nil, errSingleWebUpgrade
	}
	s.Trust.PublicKeyFile = filepath.Join(output, "release.pub")
	s.Trust.ManifestFile = filepath.Join(output, "release.json")
	s.Trust.SignatureFile = filepath.Join(output, "release.sig")
	host.DeploymentTrust = s.Trust
	host.Executor.Enabled, host.Executor.Mode, host.Executor.RulesFile = true, "embedded", filepath.Join(output, "rules.yar")
	api.DeploymentTrust = s.Trust
	api.DeploymentTrust.HelperFile, api.DeploymentTrust.NativeBundleFile, api.DeploymentTrust.ImageArchiveFile = "", "", ""
	api.Executor = ExecutorConfig{Enabled: true, Mode: "external"}
	api.NodePKI = NodePKIConfig{}
	if api.Validate() != nil || host.Validate() != nil {
		return nil, errSingleWebUpgrade
	}
	files["rules.yar"] = rules
	files["config.yaml"], _ = yaml.Marshal(api)
	files["executor.yaml"], _ = yaml.Marshal(host)
	raw := originals[s.ComposeFile]
	var compose map[string]any
	if yaml.Unmarshal(raw, &compose) != nil {
		return nil, errSingleWebUpgrade
	}
	services, ok := compose["services"].(map[string]any)
	if !ok {
		return nil, errSingleWebUpgrade
	}
	central, ok := services["central"].(map[string]any)
	if !ok || central["network_mode"] != "host" {
		return nil, errSingleWebUpgrade
	}
	volumes, ok := central["volumes"].([]any)
	if !ok {
		return nil, errSingleWebUpgrade
	}
	kept := []any{}
	// Preserve only known writable data directories; replace all old trust,
	// identity and program mounts with an explicit read-only allowlist.
	for _, item := range volumes {
		v, ok := item.(map[string]any)
		if !ok {
			return nil, errSingleWebUpgrade
		}
		source, _ := v["source"].(string)
		target, _ := v["target"].(string)
		if v["type"] != "bind" || !filepath.IsAbs(source) || source != target {
			if target == "/usr/local/bin/webscan" {
				continue
			}
			return nil, errSingleWebUpgrade
		}
		if target == filepath.Dir(api.Metrics.SpoolDir) && target != "/" || target == api.Central.ExportDirectory || target == api.Metrics.SpoolDir || target == api.Collector.RevocationStateDirectory {
			if source == host.NodePKI.AuthorityDirectory || strings.HasPrefix(host.NodePKI.AuthorityDirectory, source+"/") {
				return nil, errSingleWebUpgrade
			}
			kept = append(kept, item)
		}
	}
	if len(kept) == 0 {
		return nil, errSingleWebUpgrade
	}
	mount := func(source, target string) {
		kept = append(kept, map[string]any{"type": "bind", "source": source, "target": target, "read_only": true, "bind": map[string]any{"create_host_path": false}})
	}
	mount(filepath.Join(output, "config.yaml"), filepath.Join(output, "config.yaml"))
	paths := []string{api.Database.DSNFile, api.DeploymentTrust.VaultKeyFile, api.DeploymentTrust.PublicKeyFile, api.DeploymentTrust.ManifestFile, api.DeploymentTrust.SignatureFile}
	paths = append(paths, api.DeploymentTrust.PreviousKeyFiles...)
	if api.Collector.IdentityFile != "" {
		paths = append(paths, filepath.Dir(api.Collector.IdentityFile))
	} else {
		paths = append(paths, api.Collector.CertFile, api.Collector.KeyFile, api.Collector.CAFile)
	}
	if api.Central.CertFile != "" {
		paths = append(paths, api.Central.CertFile, api.Central.KeyFile)
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" || p == "/" || p == host.NodePKI.AuthorityDirectory || strings.HasPrefix(p, host.NodePKI.AuthorityDirectory+"/") {
			return nil, errSingleWebUpgrade
		}
		if !seen[p] {
			mount(p, p)
			seen[p] = true
		}
	}
	central["volumes"], central["image"] = kept, s.RuntimeImage
	central["entrypoint"] = []string{"/usr/local/bin/webscan"}
	central["command"] = []string{"control-v3", "--config", filepath.Join(output, "config.yaml"), "--action", "run", "--role", "all"}
	files["compose.yaml"], err = yaml.Marshal(compose)
	if err != nil {
		return nil, err
	}
	files["executor.service"] = []byte("[Unit]\nDescription=Webscan host deployment executor\nAfter=network-online.target docker.service\nRequires=docker.service\n\n[Service]\nUMask=0077\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=yes\nExecStart=" + strconv.Quote(s.Trust.HelperFile) + " control-v3 --config " + strconv.Quote(filepath.Join(output, "executor.yaml")) + " --action run --role executor\n\n[Install]\nWantedBy=multi-user.target\n")
	manifest := map[string]any{"format": 1, "project": s.Project, "image": s.RuntimeImage, "source_files": map[string]string{s.APIConfig: "", s.ExecutorConfig: "", s.ComposeFile: ""}, "vault_key_id": t.vault.active, "files": map[string]string{}}
	for _, p := range []string{s.APIConfig, s.ExecutorConfig, s.ComposeFile} {
		b, e := readTrustData(p, true, 512<<10)
		if e != nil || !bytes.Equal(b, originals[p]) {
			return nil, errSingleWebUpgrade
		}
		manifest["source_files"].(map[string]string)[p] = digest(originals[p])
	}
	for name, b := range files {
		manifest["files"].(map[string]string)[name] = digest(b)
	}
	files["upgrade.json"], _ = json.Marshal(manifest)
	return files, nil
}
