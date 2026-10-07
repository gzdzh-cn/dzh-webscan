package deploy

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"webscan/internal/common"
	"webscan/internal/progress"
)

// Exercise Deploy itself, including initialization, registry and SSH operations.
// Stop at the first backup so no production service or website is needed.
func TestDeployEntryPreparesToolsBeforeNodeBackup(t *testing.T) {
	for _, mode := range []string{"addition", "addition-current-release", "upgrade", "fresh"} {
		t.Run(mode, func(t *testing.T) {
			d := additionFixture(t)
			switch mode {
			case "addition", "addition-current-release":
				d.O = Options{AddNode: true, Node: "new-node"}
				// v2.0.11 could leave a rollout on a completed old run.
				d.State["rollout"] = common.Map{"prepared": common.Map{}, "main_started": false}
				if mode == "addition-current-release" {
					d.State["go_release"] = Release
					d.State["config_hash"] = common.Hash(common.JSON(Redact(d.C.Raw)))
					d.State["active"] = []string{"node-202", "new-node"}
				}
			case "upgrade":
				d.O = Options{Upgrade: true}
			case "fresh":
				d.O = Options{}
				d.State = common.Map{"nodes": common.Map{}, "active": []string{}}
			}
			before, err := os.ReadFile(filepath.Join(d.C.CentralRoot(), "runtime.json"))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("WEBSCAN_ENTRY_COMMANDS", filepath.Join(dir, "commands"))
			script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$WEBSCAN_ENTRY_COMMANDS"
if [ "$1" = context ]; then printf 'unix:///test-only.sock\n'; exit; fi
while [ "$1" = --host ] || [ "$1" = --config ]; do shift 2; done
case "$1" in
 pull) exit 0;;
 image) printf '[{"Id":"sha256:fixture"}]\n'; exit 0;;
 *) exit 90;;
esac
`
			if err = os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var commands []string
			r := testRemoteCommand(t, func(cmd string) (string, bool) {
				mu.Lock()
				defer mu.Unlock()
				commands = append(commands, cmd)
				switch {
				case strings.Contains(cmd, "--action backup-node"):
					return "", true // Controlled failure after all prerequisites.
				case strings.Contains(cmd, "docker create --name 'webscan-extract-"):
					return Release, false
				case strings.HasPrefix(cmd, "docker image inspect"):
					return `[{"Id":"sha256:fixture"}]`, false
				case strings.Contains(cmd, " pull --platform"):
					return "", false
				default:
					return "", true
				}
			})
			for _, n := range d.C.Selected(d.O.Node) {
				d.Remotes[common.S(n["id"])] = r
			}
			t.Cleanup(d.Close)
			var log bytes.Buffer
			ctx := progress.With(context.Background(), progress.New(&log, d.C.Raw, "部署"))
			err = d.Deploy(ctx)
			if err == nil || !strings.Contains(err.Error(), "remote_command_failed") {
				t.Fatalf("unexpected failure: %v\n%s", err, log.String())
			}
			if d.RunID == "" || d.Journal == nil || d.RunID != common.S(d.State["run_id"]) {
				t.Fatal("backup ran before initialization")
			}
			if d.addingNode() != strings.HasPrefix(mode, "addition") {
				t.Fatal("incorrect flow selected", mode)
			}
			if strings.HasPrefix(mode, "addition") && len(common.M(d.State["rollout"])) > 0 {
				t.Fatal("addition entered rollout")
			}
			for _, n := range d.C.Selected(d.O.Node) {
				if common.S(common.M(common.M(d.State["nodes"])[common.S(n["id"])])["go_image"]) == "" {
					t.Fatal("node image not prepared")
				}
			}
			mu.Lock()
			joined := strings.Join(commands, "\n")
			mu.Unlock()
			extract := strings.LastIndex(joined, "docker create --name 'webscan-extract-")
			backup := strings.Index(joined, "--action backup-node")
			if extract < 0 || backup < extract || !strings.Contains(joined, "/runs/"+d.RunID) {
				t.Fatal("backup before extraction or without run ID", joined)
			}
			text := log.String()
			labels := []string{"准备部署状态、凭据和回退记录", "准备主服务器和节点 HTTPS 证书", "下载节点镜像并准备部署工具", "保存节点配置、数据库和服务状态"}
			last := -1
			for _, label := range labels {
				at := strings.Index(text, label)
				if at <= last {
					t.Fatal("incorrect entry order", text)
				}
				last = at
			}
			after, _ := os.ReadFile(filepath.Join(d.C.CentralRoot(), "runtime.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("backup failure changed main runtime")
			}
			dockerCommands, _ := os.ReadFile(filepath.Join(dir, "commands"))
			if strings.Contains(string(dockerCommands), "compose") {
				t.Fatal("backup failure touched main services", string(dockerCommands))
			}
		})
	}
}

func TestDeployEntryRejectsUnfinishedRunBeforeAnyNodeOperation(t *testing.T) {
	d := additionFixture(t)
	d.State["run_id"], d.State["step"] = "go-unfinished", "preparing"
	d.State["rollout"] = common.Map{"prepared": common.Map{}}
	err := d.Deploy(context.Background())
	if err == nil || err.Error() != "unfinished_deployment_requires_resume_or_rollback" {
		t.Fatal(err)
	}
	if d.RunID != "" || len(d.Remotes) != 0 {
		t.Fatal("unfinished run performed node operations")
	}
}

func TestRolloutRejectsUninitializedOrAdditionFlow(t *testing.T) {
	d := additionFixture(t)
	if err := d.deployRollout(context.Background()); err == nil || err.Error() != "rollout_requires_initialized_deployment" {
		t.Fatal(err)
	}
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	if d.canStageRollout() {
		t.Fatal("addition selected combined rollout")
	}
	if err := d.deployRollout(context.Background()); err == nil {
		t.Fatal("initialized addition accepted as rollout")
	}
}
