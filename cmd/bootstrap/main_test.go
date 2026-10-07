package main

import (
	"context"
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"webscan/internal/assets"
	"webscan/internal/common"
)

func TestOfflineDryRunDoesNotExposeSecretsOrRequireDocker(t *testing.T) {
	raw, _ := assets.Files.ReadFile("schema.yaml")
	var cfg common.Map
	yaml.Unmarshal(raw, &cfg)
	reg := common.M(cfg["registry"])
	reg["auth_required"] = true
	reg["username"] = "publisher"
	reg["password"] = "must-not-appear"
	common.M(cfg["feishu"])["enabled"] = false
	for _, value := range common.A(cfg["nodes"]) {
		common.M(common.M(value)["ssh"])["host_key_sha256"] = "SHA256:fixture"
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	b, _ := yaml.Marshal(cfg)
	os.WriteFile(path, b, 0600)
	previousArgs, previousOut := os.Args, os.Stdout
	defer func() { os.Args, os.Stdout = previousArgs, previousOut }()
	out, e := os.CreateTemp(t.TempDir(), "dry-run")
	if e != nil {
		t.Fatal(e)
	}
	os.Stdout = out
	os.Args = []string{"bootstrap", "--config", path, "--dry-run"}
	if e = run(); e != nil {
		t.Fatal(e)
	}
	out.Close()
	body, _ := os.ReadFile(out.Name())
	if strings.Contains(string(body), "must-not-appear") || strings.Contains(string(body), "publisher") {
		t.Fatal("registry secret in dry run")
	}
	if !strings.Contains(string(body), `"offline":true`) {
		t.Fatal("not offline")
	}
	os.Args = append(os.Args, "--check")
	if e = run(); e == nil {
		t.Fatal("incompatible dry-run action accepted")
	}
}

// The complete packaged shell must uninstall offline without pulling an image
// or creating even an extraction container. All filesystem writes are confined
// to this disposable Linux container; Docker operations inside it are mocked.
func TestPackagedUninstallRunsOfflineWithoutCreatingContainer(t *testing.T) {
	version := os.Getenv("WEBSCAN_IMAGE_VERSION")
	if version == "" {
		t.Skip("requires locally built release package")
	}
	scriptPath, err := filepath.Abs(filepath.Join("..", "..", "dist", version, "deploy-webscan.sh"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := assets.Files.ReadFile("schema.yaml")
	var cfg common.Map
	yaml.Unmarshal(raw, &cfg)
	common.M(cfg["registry"])["auth_required"] = true
	common.M(cfg["registry"])["username"] = "offline-fixture"
	common.M(cfg["registry"])["password"] = "offline-password-must-not-appear"
	common.M(cfg["feishu"])["enabled"] = false
	center := common.M(cfg["central"])
	center["install_dir"], center["data_dir"], center["backup_dir"] = "/tmp/test/install", "/tmp/test/data", "/tmp/test/backups"
	for _, v := range common.A(cfg["nodes"]) {
		common.M(common.M(v)["ssh"])["host_key_sha256"] = "SHA256:fixture"
	}
	b, _ := yaml.Marshal(cfg)
	configPath := filepath.Join(t.TempDir(), "fixture.yaml")
	os.WriteFile(configPath, b, 0600)
	setup := `set -e
mkdir -p /tmp/test/bin /tmp/test/package /tmp/test/data /tmp/test/install/webscan-v1
cp /input/deploy-webscan.sh /tmp/test/package/deploy-webscan.sh
cp /input/fixture.yaml /tmp/test/package/webscan.yaml
chmod 600 /tmp/test/package/webscan.yaml
printf readme > /tmp/test/package/README.md
printf preserved-history > /tmp/test/data/events-v1.sqlite3
printf running-config > /tmp/test/install/webscan-v1/runtime.json
cat > /tmp/test/bin/docker <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >> /tmp/test/docker-calls
case "$1" in info|ps) exit 0;; network) exit 1;; *) exit 53;; esac
MOCK
cat > /tmp/test/bin/systemctl <<'MOCK'
#!/bin/sh
[ "$1" != is-active ]
MOCK
chmod +x /tmp/test/bin/*
export PATH=/tmp/test/bin:$PATH
if bash /tmp/test/package/deploy-webscan.sh --uninstall --centrl-only > /tmp/test/invalid.log 2>&1; then exit 55; fi
grep '无法识别' /tmp/test/invalid.log >/dev/null
test -e /tmp/test/install/webscan-v1
test ! -e /tmp/test/docker-calls
if bash /tmp/test/package/deploy-webscan.sh --uninstall --node > /tmp/test/missing.log 2>&1; then exit 56; fi
grep '必须填写' /tmp/test/missing.log >/dev/null
test -e /tmp/test/install/webscan-v1
test ! -e /tmp/test/docker-calls
bash /tmp/test/package/deploy-webscan.sh --uninstall --central-only --non-interactive
test ! -e /tmp/test/install/webscan-v1
test "$(cat /tmp/test/data/events-v1.sqlite3)" = preserved-history
test -f /tmp/test/package/deploy-webscan.sh
test -f /tmp/test/package/webscan.yaml
test -f /tmp/test/package/README.md
if grep -Eq '(^| )(create|pull|login|cp)( |$)' /tmp/test/docker-calls; then exit 54; fi
printf '\nOFFLINE_UNINSTALL_WITHOUT_CONTAINER_OK\n'
`
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none", "-i", "-v", scriptPath+":/input/deploy-webscan.sh:ro", "-v", configPath+":/input/fixture.yaml:ro", "--entrypoint", "/bin/bash", "webscan-central:"+version, "-se")
	cmd.Stdin = strings.NewReader(setup)
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "offline-password-must-not-appear") {
		t.Fatal("credential exposed")
	}
	if err != nil {
		t.Fatalf("packaged offline uninstall: %v %s", err, out)
	}
	if !strings.Contains(string(out), "OFFLINE_UNINSTALL_WITHOUT_CONTAINER_OK") || !strings.Contains(string(out), "无需镜像仓库，也不创建引导容器") {
		t.Fatal("embedded uninstall did not run", string(out))
	}
	t.Log("packaged private-registry YAML uninstalled with network disabled; no login, pull or create; history and three-file package preserved")
}
