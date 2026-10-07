package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/assets"
)

func TestHelpNeedsNoConfigurationAndInvalidArgumentsArePrivate(t *testing.T) {
	var out bytes.Buffer
	if err := execute([]string{"--config", "/missing.yaml", "--config-help"}, &out); err != nil || !strings.Contains(out.String(), "signing_secret") {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--check=never-echo-secret"}, {"--config"}, {"--config", "--check"}, {"--unknown=never-echo-secret"}, {"--check", "never-echo-secret"}} {
		err := execute(args, &out)
		if err == nil || strings.Contains(explainComposeError(err), "never-echo") || !strings.Contains(explainComposeError(err), "--config") {
			t.Fatal(err)
		}
	}
}

func TestCheckIsOfflineAndCreatesNoPackage(t *testing.T) {
	b, _ := assets.Files.ReadFile("configuration-example.yaml")
	s := strings.Replace(string(b), "webhook_url: ''", "webhook_url: 'https://open.feishu.cn/open-apis/bot/v2/hook/fixture'", 1)
	s = strings.Replace(s, "signing_secret: ''", "signing_secret: 'never-echo-secret'", 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	output := filepath.Join(dir, "package")
	os.WriteFile(path, []byte(s), 0600)
	var out bytes.Buffer
	if err := execute([]string{"--config", path, "--output", output, "--launcher", "/missing.yaml", "--check"}, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("check created output")
	}
	if !strings.Contains(out.String(), "检查通过") || strings.Contains(out.String(), "never-echo") {
		t.Fatal(out.String())
	}
}
