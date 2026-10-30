package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSingleWebUpgradePreservesVaultAndOriginalInstallation(t *testing.T) {
	s := singleSpecFixture(t)
	s.Format = 2
	if err := prepareSingleInstallation(context.Background(), s, []byte("original-program"), "isolated-admin-password-123", "/usr/bin/docker"); err != nil {
		t.Fatal(err)
	}
	f := newTrustToolFixture(t)
	host := s.configuration()
	host.DeploymentTrust = f.config()
	host.NodePKI = NodePKIConfig{Enabled: true, AuthorityDirectory: filepath.Join(s.Root, "authority")}
	host.Executor = ExecutorConfig{Enabled: true, ConfigurationDirectory: filepath.Join(s.Root, "state", "node-configurations")}
	if err := host.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, _ := yaml.Marshal(host)
	executor := filepath.Join(s.Root, "old-executor.yaml")
	os.WriteFile(executor, raw, 0600)
	rules := filepath.Join(s.Root, "rules.yar")
	os.WriteFile(rules, []byte("rule isolated { condition: false }"), 0600)
	before := map[string][]byte{}
	for _, p := range []string{host.DeploymentTrust.VaultKeyFile, filepath.Join(s.Root, "install.json"), filepath.Join(s.Root, "config.yaml"), filepath.Join(s.Root, "compose.yaml"), executor} {
		before[p], _ = os.ReadFile(p)
	}
	upgrade := singleWebUpgradeSpec{Format: 1, APIConfig: filepath.Join(s.Root, "config.yaml"), ExecutorConfig: executor, ComposeFile: filepath.Join(s.Root, "compose.yaml"), Project: singleProject(s.Root), RuntimeImage: "docker.io/gzdzh/webscan-central:v3.0.0-local-test@sha256:" + strings.Repeat("a", 64), RulesFile: rules, Trust: f.config()}
	output := filepath.Join(filepath.Dir(s.Root), "new-version")
	files, err := singleWebUpgradeFiles(context.Background(), upgrade, output)
	if err != nil {
		t.Fatal(err)
	}
	for p, b := range before {
		after, _ := os.ReadFile(p)
		if !bytes.Equal(b, after) {
			t.Fatal("rewrote original", p)
		}
	}
	if _, ok := files["vault.key"]; ok {
		t.Fatal("generated/copied Vault")
	}
	var api Config
	if yaml.Unmarshal(files["config.yaml"], &api) != nil || api.DeploymentTrust.VaultKeyFile != host.DeploymentTrust.VaultKeyFile || api.Executor.Mode != "external" || api.NodePKI.Enabled {
		t.Fatal("wrong privilege/key")
	}
	var compose struct {
		Services map[string]struct {
			Volumes []struct {
				Source, Target string
				ReadOnly       bool `yaml:"read_only"`
			}
		}
	}
	if yaml.Unmarshal(files["compose.yaml"], &compose) != nil {
		t.Fatal("invalid compose")
	}
	found := false
	for _, v := range compose.Services["central"].Volumes {
		if v.Target == "/usr/local/bin/webscan" || strings.Contains(v.Source, "authority") || strings.Contains(v.Source, "docker.sock") {
			t.Fatal("unsafe mount", v)
		}
		if v.Source == host.DeploymentTrust.VaultKeyFile {
			found = v.ReadOnly
		}
	}
	if !found {
		t.Fatal("missing existing read-only Vault")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("preview wrote package")
	}
	source := filepath.Join(filepath.Dir(s.Root), "upgrade-request.json")
	raw, _ = json.Marshal(upgrade)
	os.WriteFile(source, raw, 0600)
	var out bytes.Buffer
	if err = singleWebUpgradeCommand(context.Background(), Options{Action: "prepare-single-web-upgrade", Source: source, Output: output}, &out); err != nil {
		t.Fatal(err)
	}
	if err = singleWebUpgradeCommand(context.Background(), Options{Action: "prepare-single-web-upgrade", Source: source, Output: output}, &out); err == nil {
		t.Fatal("overwrote published upgrade")
	}
	upgrade.Trust.VaultKeyFile = filepath.Join(output, "replacement.key")
	if _, err = singleWebUpgradeFiles(context.Background(), upgrade, output); err == nil {
		t.Fatal("allowed key replacement")
	}
}
