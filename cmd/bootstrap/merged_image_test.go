package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/assets"
	"webscan/internal/common"
)

// Run the complete shell and the actual extracted binary in an isolated Linux
// container. Mock only Docker access: this proves the bootstrap selects central,
// forwards deploy arguments and cleans extraction/auth resources in both modes.
func TestPackagedBootstrapExtractsCentralToolWithTwoImages(t *testing.T) {
	version := os.Getenv("WEBSCAN_IMAGE_VERSION")
	if version == "" {
		t.Skip("requires locally built release package")
	}
	script, _ := filepath.Abs(filepath.Join("..", "..", "dist", version, "deploy-webscan.sh"))
	for _, private := range []bool{false, true} {
		t.Run(map[bool]string{false: "public", true: "private"}[private], func(t *testing.T) {
			raw, _ := assets.Files.ReadFile("schema.yaml")
			var cfg common.Map
			yaml.Unmarshal(raw, &cfg)
			reg := common.M(cfg["registry"])
			reg["auth_required"], reg["username"], reg["password"] = private, "test-publisher", "test-only-registry-password"
			common.M(cfg["images"])["central"] = "webscan-central:" + version
			common.M(cfg["images"])["agent"] = "webscan-agent:" + version
			common.M(cfg["feishu"])["enabled"] = false
			// The packaged bootstrap and extracted deploy tool must both accept
			// new nodes without manually supplied SSH host fingerprints.
			delete(common.M(common.M(cfg["node_defaults"])["ssh"]), "host_key_sha256")
			for _, v := range common.A(cfg["nodes"]) {
				delete(common.M(common.M(v)["ssh"]), "host_key_sha256")
			}
			b, _ := yaml.Marshal(cfg)
			path := filepath.Join(t.TempDir(), "fixture.yaml")
			os.WriteFile(path, b, 0600)
			setup := `set -eu
mkdir -p /tmp/merged/bin /tmp/merged/package /root/.docker
cp /input/deploy-webscan.sh /tmp/merged/package/deploy-webscan.sh
cp /input/fixture.yaml /tmp/merged/package/webscan.yaml
chmod 600 /tmp/merged/package/webscan.yaml
printf '{"auths":{"registry.cn-heyuan.aliyuncs.com":{"auth":"existing-state-must-not-be-used"}}}' > /root/.docker/config.json
cat > /tmp/merged/bin/docker <<'MOCK'
#!/bin/sh
set -eu
task_config=''
while [ "$1" = --host ] || [ "$1" = --config ]; do
 if [ "$1" = --config ]; then task_config="$2"; fi
 shift 2
done
printf '%s\n' "$*" >> /tmp/merged/commands
case "$1" in
 info|compose|ps) exit 0;;
 context) printf 'unix:///test-only.sock\n'; exit;;
 login)
  test "$TEST_PRIVATE" = true
  read -r task_password
  test "$task_password" = test-only-registry-password
  printf logged-in > "$task_config/auth-marker"
  ;;
 pull)
  test "$4" = "registry.cn-heyuan.aliyuncs.com/gzdzh/webscan-central:$TEST_VERSION"
  test "$task_config" != /root/.docker
  if [ "$TEST_PRIVATE" = true ]; then test -f "$task_config/auth-marker"; else test ! -f "$task_config/auth-marker"; fi
  printf '%s' "$task_config" > /tmp/merged/auth-path
  ;;
 create)
  test "$8" = "registry.cn-heyuan.aliyuncs.com/gzdzh/webscan-central:$TEST_VERSION"
  test "$9" = version
  touch /tmp/merged/extraction-container
  ;;
 cp)
  cp /usr/local/bin/webscan "$3.real"
  cat > "$3" <<'TOOL'
#!/bin/sh
set -eu
if [ "$1" = version ]; then
 if [ -n "${TEST_TOOL_VERSION:-}" ]; then printf '%s\n' "$TEST_TOOL_VERSION"; else exec "$0.real" version; fi
fi
test ! -f /tmp/merged/extraction-container
test ! -d "$(cat /tmp/merged/auth-path)"
printf '%s\n' "$@" > /tmp/merged/forwarded-args
exec "$0.real" deploy --config /tmp/merged/package/webscan.yaml --dry-run --central-only
TOOL
  ;;
 rm) rm -f /tmp/merged/extraction-container;;
 *) exit 88;;
esac
MOCK
chmod 700 /tmp/merged/bin/docker
export PATH=/tmp/merged/bin:$PATH
bash /tmp/merged/package/deploy-webscan.sh --upgrade --central-only --non-interactive > /tmp/merged/run.log
printf 'deploy\n--upgrade\n--central-only\n--non-interactive\n' > /tmp/merged/expected-args
diff /tmp/merged/expected-args /tmp/merged/forwarded-args
test ! -f /tmp/merged/extraction-container
test ! -d "$(cat /tmp/merged/auth-path)"
if grep -q webscan-deployer /tmp/merged/commands; then exit 89; fi
if grep -q test-only-registry-password /tmp/merged/run.log; then exit 90; fi
if TEST_TOOL_VERSION=wrong-version bash /tmp/merged/package/deploy-webscan.sh --check --central-only > /tmp/merged/mismatch.log 2>&1; then exit 91; fi
grep bootstrap_tool_release_mismatch /tmp/merged/mismatch.log >/dev/null
test ! -f /tmp/merged/extraction-container
test ! -d "$(cat /tmp/merged/auth-path)"
printf 'MERGED_CENTRAL_BOOTSTRAP_AUTH_FORWARDING_CLEANUP_AND_VERSION_OK\n'
`
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			mode := "false"
			if private {
				mode = "true"
			}
			cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none", "-i", "-e", "TEST_PRIVATE="+mode, "-e", "TEST_VERSION="+version, "-v", script+":/input/deploy-webscan.sh:ro", "-v", path+":/input/fixture.yaml:ro", "--entrypoint", "/bin/bash", "webscan-central:"+version, "-se")
			cmd.Stdin = strings.NewReader(setup)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("merged bootstrap failed: %v %s", err, out)
			}
			if !strings.Contains(string(out), "MERGED_CENTRAL_BOOTSTRAP_AUTH_FORWARDING_CLEANUP_AND_VERSION_OK") {
				t.Fatal(string(out))
			}
			t.Log("Two-image package extracts actual central binary; credentials isolated; temporary container removed before deploy; wrong version rejected")
		})
	}
}
