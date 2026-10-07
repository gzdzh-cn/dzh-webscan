package config

import (
	"errors"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/assets"
	"webscan/internal/common"
)

func example(t *testing.T) common.Map {
	t.Helper()
	b, _ := assets.Files.ReadFile("configuration-example.yaml")
	var m common.Map
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	f := common.M(m["feishu"])
	f["webhook_url"] = "https://open.feishu.cn/open-apis/bot/v2/hook/never-echo-token"
	f["signing_secret"] = "never-echo-secret"
	return m
}

func loadMap(t *testing.T, m common.Map) (*Config, error) {
	t.Helper()
	b, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err = os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestMissingFeishuReportsBothFieldsAndPreservesCode(t *testing.T) {
	m := example(t)
	f := common.M(m["feishu"])
	f["webhook_url"], f["signing_secret"] = "", ""
	_, err := loadMap(t, m)
	if err == nil || err.Error() != "feishu_requires_https_webhook" {
		t.Fatal(err)
	}
	message, ok := Explain(err)
	for _, want := range []string{"feishu.webhook_url", "feishu.signing_secret", "自定义机器人", "加签", "0600"} {
		if !ok || !strings.Contains(message, want) {
			t.Fatalf("missing %s: %s", want, message)
		}
	}
	if _, err = loadMap(t, example(t)); err != nil {
		t.Fatal(err)
	}
}

func TestFieldsValuesAndSecretFreeDiagnostics(t *testing.T) {
	tests := []struct {
		name, field, hint string
		mutate            func(common.Map)
	}{
		{"node host", "nodes[1].host", "IP", func(m common.Map) { common.M(common.A(m["nodes"])[1])["host"] = "never-echo-host" }},
		{"key", "nodes[0].ssh.private_key_path", "绝对路径", func(m common.Map) {
			common.M(common.M(common.A(m["nodes"])[0])["ssh"])["private_key_path"] = "never-echo-path"
		}},
		{"extension", "nodes[1].monitor.extensions[0]", "前导点", func(m common.Map) {
			common.M(common.A(m["nodes"])[1])["monitor"] = common.Map{"extensions": []any{"never-echo-extension"}}
		}},
		{"type", "nodes[0].enabled", "true 或 false", func(m common.Map) { common.M(common.A(m["nodes"])[0])["enabled"] = "never-echo-boolean" }},
		{"unknown", "nodes[0].typo", "无法识别", func(m common.Map) { common.M(common.A(m["nodes"])[0])["typo"] = "never-echo-value" }},
		{"empty rule item", "node_defaults.monitor.critical_paths[0]", "字符串", func(m common.Map) { common.M(common.M(m["node_defaults"])["monitor"])["critical_paths"] = []any{nil} }},
		{"time", "backup.time", "HH:MM", func(m common.Map) { common.M(m["backup"])["time"] = "never-echo-time" }},
		{"timezone", "backup.timezone", "时区", func(m common.Map) { common.M(m["backup"])["timezone"] = "never-echo-zone" }},
		{"metrics port", "nodes[0].metrics.port", "65535", func(m common.Map) { common.M(common.A(m["nodes"])[0])["metrics"] = common.Map{"port": 65536} }},
		{"threshold", "health.alerts.disk_warning_percent", "低于", func(m common.Map) { common.M(common.M(m["health"])["alerts"])["disk_warning_percent"] = 95 }},
		{"capacity", "node_defaults.transport.vector_buffer_mib", "至少", func(m common.Map) { common.M(common.M(m["node_defaults"])["transport"])["vector_buffer_mib"] = 0 }},
		{"resource", "nodes[0].resources", "128", func(m common.Map) {
			common.M(common.A(m["nodes"])[0])["resources"] = common.Map{"agent_memory_mib": 10}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := example(t)
			tt.mutate(m)
			_, err := loadMap(t, m)
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			message, ok := Explain(err)
			if !ok || !strings.Contains(message, tt.field) || !strings.Contains(message, tt.hint) || strings.Contains(message, "never-echo") {
				t.Fatal(message)
			}
		})
	}
}

func TestSyntaxAndMultipleDocumentsDoNotEchoSecrets(t *testing.T) {
	for _, b := range []string{"", "password: [never-echo-secret\n", "registry: {}\n---\npassword: never-echo-secret\n", "password: one\npassword: never-echo-secret\n"} {
		p := filepath.Join(t.TempDir(), "config.yaml")
		os.WriteFile(p, []byte(b), 0600)
		_, err := Load(p)
		if err == nil {
			t.Fatal("invalid YAML accepted")
		}
		message, ok := Explain(err)
		if !ok || strings.Contains(message, "never-echo") {
			t.Fatal(message)
		}
	}
}

func TestEveryConfigurationCodeHasGuidanceAndHelpIsCurrent(t *testing.T) {
	for _, path := range []string{"config.go", "mirrors.go", "../common/policy.go"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// Only stable errors; dynamic shape errors are covered by prefix handling.
		for _, line := range strings.Split(string(b), "\n") {
			_, rest, ok := strings.Cut(line, `errors.New("`)
			if !ok {
				continue
			}
			code, _, _ := strings.Cut(rest, `"`)
			if _, ok := Explain(errors.New(code)); !ok {
				t.Errorf("no guidance: %s", code)
			}
		}
	}
	b, err := os.ReadFile("../../webscan.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(Help(), string(b)) {
		t.Fatal("embedded parameter help is out of date")
	}
}
