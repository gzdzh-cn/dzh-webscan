package main

import (
	"github.com/gogf/gf/v2/os/gcmd"
	"testing"
)

func TestGoFrameOrphanFlagPresence(t *testing.T) {
	names := []string{"dry-run", "check", "upgrade", "add-node", "resume", "rollback", "uninstall", "central-only", "grafana-only", "sync-grafana-credentials", "reload-rules", "non-interactive"}
	for _, name := range names {
		p, e := gcmd.ParseArgs([]string{"--" + name}, map[string]bool{name: false})
		if e != nil {
			t.Fatal(e)
		}
		if !present(p, name) {
			t.Fatalf("orphan flag --%s was ignored", name)
		}
		p, e = gcmd.ParseArgs([]string{}, map[string]bool{name: false})
		if e != nil {
			t.Fatal(e)
		}
		if present(p, name) {
			t.Fatalf("absent --%s was enabled", name)
		}
	}
}
