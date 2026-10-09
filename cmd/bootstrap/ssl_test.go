package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"webscan/internal/assets"
	"webscan/internal/common"
	configuration "webscan/internal/config"
	"webscan/internal/deploy"
)

func TestSSLMenuAndStrictArguments(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  []string
	}{
		{"5\n1\n", []string{"--set-ssl", "on"}},
		{"5\nbad\n2\n", []string{"--set-ssl", "off"}},
		{"5\n0\n1\n", []string{"--install"}},
	} {
		var out bytes.Buffer
		got, err := selectActionWithNodes(nil, strings.NewReader(tc.input), &out, nil)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatal(got, err)
		}
	}
	for _, args := range [][]string{{"--set-ssl", "invalid"}, {"--set-ssl", "off", "--upgrade"}, {"--set-ssl", "off", "--central-only"}, {"--set-ssl", "off", "--node", "x"}} {
		if validateActions(args) == nil {
			t.Fatal("unsafe combination accepted", args)
		}
	}
	if err := validateActions([]string{"--set-ssl", "off", "--non-interactive"}); err != nil {
		t.Fatal(err)
	}
}

func TestSSLChoiceAtomicYAMLPreservationAndPendingRun(t *testing.T) {
	previous := deploy.StateRoot
	deploy.StateRoot = t.TempDir()
	t.Cleanup(func() { deploy.StateRoot = previous })
	b, _ := assets.Files.ReadFile("schema.yaml")
	var raw common.Map
	yaml.Unmarshal(b, &raw)
	common.M(raw["feishu"])["enabled"] = false
	raw["registry"] = common.Map{"prefix": "docker.io/gzdzh", "auth_required": false, "username": "", "password": ""}
	raw["images"] = common.Map{"central": "webscan-central:latest", "agent": "webscan-agent:latest"}
	path := filepath.Join(t.TempDir(), "webscan.yaml")
	input := append([]byte("# retained comment\n"), deploy.YAML(raw)...)
	os.WriteFile(path, input, 0600)
	for _, enabled := range []bool{false, true} {
		var output bytes.Buffer
		if err := saveSSLChoice(path, enabled, &output); err != nil {
			t.Fatal(err)
		}
		c, err := configuration.Load(path)
		if err != nil || c.SSLEnabled() != enabled {
			t.Fatal(err)
		}
		b, _ = os.ReadFile(path)
		if !bytes.Contains(b, []byte("# retained comment")) {
			t.Fatal("comment lost")
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("permissions")
		}
		if !strings.Contains(output.String(), "接下来按本次所选操作自动部署") || strings.Contains(output.String(), "请执行 bash") {
			t.Fatal("missing automatic deployment instruction")
		}
	}
	before, _ := os.ReadFile(path)
	common.AtomicJSON(filepath.Join(deploy.StateRoot, "state.json"), common.Map{"run_id": "go-test", "step": "central"})
	if saveSSLChoice(path, false, new(bytes.Buffer)) == nil {
		t.Fatal("changed unfinished deployment configuration")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed operation changed YAML")
	}
}
