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

func TestSingleInstallFormat3SharesVaultAndSeparatesHostPrivileges(t *testing.T) {
	s := singleSpecFixture(t)
	source := newTrustToolFixture(t)
	trust := source.config()
	s.Format = 3
	s.ReleaseTrust = &trust
	s.RulesFile = filepath.Join(source.root, "rules.yar")
	if err := os.WriteFile(s.RulesFile, []byte("rule local_test { condition: false }"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(source.helper)
	if err != nil {
		t.Fatal(err)
	}
	if err = prepareSingleInstallation(context.Background(), s, binary, "isolated-password-123", "/usr/bin/docker"); err != nil {
		t.Fatal(err)
	}
	original, err := readTrustData(filepath.Join(s.Root, "vault.key"), true, 128)
	if err != nil {
		t.Fatal(err)
	}
	var api, host Config
	for name, c := range map[string]*Config{"config.yaml": &api, "executor.yaml": &host} {
		raw, err := os.ReadFile(filepath.Join(s.Root, name))
		if err != nil || yaml.Unmarshal(raw, c) != nil || c.Validate() != nil {
			t.Fatal("invalid config", name, err)
		}
	}
	if api.Executor.Mode != "external" || api.Executor.embedded() || api.NodePKI.Enabled || api.DeploymentTrust.HelperFile != "" {
		t.Fatal("API privileged")
	}
	if !host.Executor.embedded() || !host.NodePKI.Enabled || host.DeploymentTrust.VaultKeyFile != api.DeploymentTrust.VaultKeyFile {
		t.Fatal("host/shared key missing")
	}
	var compose struct {
		Services map[string]struct {
			Volumes []struct {
				Source, Target string
				ReadOnly       bool `yaml:"read_only"`
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(s.Root, "compose.yaml"))
	if err != nil || yaml.Unmarshal(raw, &compose) != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, v := range compose.Services["central"].Volumes {
		for _, forbidden := range []string{"ca.key", "authority", "docker.sock", "/usr/local/bin/webscan", "executor.yaml"} {
			if strings.Contains(v.Target, forbidden) || strings.Contains(v.Source, forbidden) {
				t.Fatal("host privilege mounted", forbidden)
			}
		}
		name := filepath.Base(v.Target)
		found[name] = true
		if name != "state" && !v.ReadOnly {
			t.Fatal("writable API trust", name)
		}
	}
	for _, name := range []string{"vault.key", "release.pub", "release.json", "release.sig", "collector-pki"} {
		if !found[name] {
			t.Fatal("missing read-only mount", name)
		}
	}
	j, err := readSingleInstallation(s, digest(binary))
	if err != nil || j.Step != 0 {
		t.Fatal("immutable format3 invalid", err)
	}
	// A fresh retry cannot regenerate the key in an already published package.
	if err = prepareSingleInstallation(context.Background(), s, binary, "isolated-password-123", "/usr/bin/docker"); err == nil {
		t.Fatal("replaced existing installation")
	}
	after, _ := os.ReadFile(filepath.Join(s.Root, "vault.key"))
	if !bytes.Equal(original, after) {
		t.Fatal("regenerated Vault")
	}
	if err = os.WriteFile(filepath.Join(s.Root, "vault.key"), []byte(strings.Repeat("ab", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readSingleInstallation(s, digest(binary)); err == nil {
		t.Fatal("replaced key accepted during resume")
	}
}
func TestSingleInstallFormat3RejectsMismatchedExecutableAndMissingTrust(t *testing.T) {
	s := singleSpecFixture(t)
	s.Format = 3
	if s.validate() == nil {
		t.Fatal("missing trust accepted")
	}
	source := newTrustToolFixture(t)
	trust := source.config()
	s.ReleaseTrust = &trust
	s.RulesFile = source.native
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	if err := prepareSingleInstallation(context.Background(), s, []byte("different-binary"), "isolated-password-123", "/usr/bin/docker"); err == nil {
		t.Fatal("different embedded binary accepted")
	}
	if _, err := os.Lstat(s.Root); !os.IsNotExist(err) {
		t.Fatal("published mismatched installation")
	}
	// The source request uses explicit snake_case trust keys.
	raw, _ := json.Marshal(s)
	if !bytes.Contains(raw, []byte(`"release_public_key_file"`)) {
		t.Fatal("missing documented JSON contract")
	}
}
