package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"webscan/internal/common"
	"webscan/internal/deploy"
)

func TestInstallAfterConfirmedRollbackUsesLatestWithoutChangingProtocol(t *testing.T) {
	path := sslFlowFixture(t)
	c, err := deploy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	state := common.Map{
		"run_id": "go-failed", "step": "central-go-ready", "target_release": "v2.0.26",
		"target_tool_image":  "docker.io/gzdzh/webscan-central@sha256:" + strings.Repeat("a", 64),
		"target_config_hash": common.Hash(common.JSON(deploy.Redact(c.Raw))), "active": []string{},
		"last_failure": common.Map{"stage": "rollout", "rollback_confirmed": true},
		"rollout":      common.Map{"accepted": common.Map{}, "prepared": common.Map{}, "previous_active": []string{}},
		"nodes":        common.Map{"node-202": common.Map{"go_run_id": "go-failed", "phase": "go-rolled-back"}},
	}
	common.AtomicJSON(filepath.Join(deploy.StateRoot, "state.json"), state)
	args := []string{"--install", "--config", path}
	latest := "docker.io/gzdzh/webscan-central:latest"
	if got := bootstrapImageForOperation(latest, args); got != latest {
		t.Fatal("confirmed rollback still pinned broken tool", got)
	}
	before, _ := os.ReadFile(path)
	var out bytes.Buffer
	got, err := installationSSL(args, bufio.NewScanner(strings.NewReader("")), &out)
	after, _ := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(args, got) || !bytes.Equal(before, after) || !strings.Contains(out.String(), "已确认回退") {
		t.Fatal("retry changed config or prompted for protocol", err, out.String())
	}
	for _, flag := range []string{"--resume", "--rollback"} {
		if got := bootstrapImageForOperation(latest, []string{flag, "--config", path}); got != state["target_tool_image"] {
			t.Fatal("explicit recovery lost original image", flag, got)
		}
	}
	state["target_config_hash"] = "changed"
	common.AtomicJSON(filepath.Join(deploy.StateRoot, "state.json"), state)
	if got := bootstrapImageForOperation(latest, args); got != state["target_tool_image"] {
		t.Fatal("changed YAML silently retried", got)
	}
}
