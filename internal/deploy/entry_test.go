package deploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"
)

// A missing or invalid package must be detected before any node writer stops.
func TestPrepareUnifiedToolsBeforeNodeBackup(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			d := additionFixture(t)
			n := d.C.Selected("new-node")[0]
			n["deployment"] = common.Map{"mode": mode}
			if e := d.initialize(); e != nil {
				t.Fatal(e)
			}
			dir := t.TempDir()
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			script := `#!/bin/sh
set -eu
if [ "$1" = context ]; then printf 'unix:///test-only.sock\n'; exit; fi
while [ "$1" = --host ] || [ "$1" = --config ]; do shift 2; done
case "$1" in
 create|rm) exit 0;;
 cp) printf 'verified-test-bundle' > "$3";exit 0;;
 image) printf '[{"Id":"sha256:fixture"}]\n';exit 0;;
 *) exit 90;;
esac
`
			os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700)
			var commands []string
			r := testRemoteCommand(t, func(cmd string) (string, bool) {
				commands = append(commands, cmd)
				if strings.Contains(cmd, "--action backup-node") {
					return "", true
				}
				if strings.Contains(cmd, "sha256sum") && strings.Contains(cmd, "package.tar.gz") {
					return Release, false
				}
				if strings.Contains(cmd, "image inspect") {
					return `[{"Id":"sha256:fixture"}]`, false
				}
				if strings.Contains(cmd, " pull --platform") {
					return "", false
				}
				if strings.Contains(cmd, "yara-check-") {
					return "", false
				}
				return "", true
			})
			d.Remotes["new-node"] = r
			docker, e := NewDocker(context.Background(), d.C, false)
			if e != nil {
				t.Fatal(e)
			}
			d.Docker = docker
			t.Cleanup(d.Close)
			d.Images["agent"] = "fixture/agent:v35"
			if e = d.PrepareNode(context.Background(), n); e != nil {
				t.Fatal(e)
			}
			if e = d.nodeBackup(context.Background(), n); e == nil {
				t.Fatal("expected controlled backup failure")
			}
			joined := strings.Join(commands, "\n")
			if strings.Index(joined, "package.tar.gz") > strings.Index(joined, "--action backup-node") || strings.Contains(joined, "docker stop") {
				t.Fatal(joined)
			}
			if !strings.Contains(joined, "yara-check-") || strings.Index(joined, "yara-check-") > strings.Index(joined, "--action backup-node") {
				t.Fatal("scan rules were not checked before backup", joined)
			}
			if mode == "native" && strings.Contains(joined, "docker ") {
				t.Fatal("native node used Docker", joined)
			}
			if common.S(common.M(common.M(d.State["nodes"])["new-node"])["native_sha256"]) == "" {
				t.Fatal("missing verified package checkpoint")
			}
		})
	}
}
