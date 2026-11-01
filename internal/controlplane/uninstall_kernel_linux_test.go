//go:build linux

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"testing"

	"webscan/internal/nodeops"
	"webscan/internal/persist"
)

func webKernelUninstallDiagnostic(t *testing.T, j DeploymentJob) {
	t.Helper()
	if j.Kind != "uninstall" || !identifier.MatchString(j.ID) {
		return
	}
	raw, err := os.ReadFile(filepath.Join(nodeops.DeploymentRoot, "transitions", j.ID, "uninstall", "diagnostic.json"))
	var d struct {
		Phase string `json:"phase"`
		Code  string `json:"code"`
	}
	if err == nil && len(raw) <= 4096 && json.Unmarshal(raw, &d) == nil && regexp.MustCompile(`^[a-z][a-z0-9-]{0,99}$`).MatchString(d.Phase) && regexp.MustCompile(`^[a-z][a-z0-9-]{0,99}$`).MatchString(d.Code) {
		t.Logf("fixed uninstall diagnostic phase=%s code=%s", d.Phase, d.Code)
	}
}

func webKernelUninstall(t *testing.T, ctx context.Context, f webDeploymentFixture, mode, site string, lose *atomic.Bool, losses *atomic.Int32, call func(string, string, any, string) (int, []byte), queue func(string, string) string, jobStatus func(string, string) DeploymentJob, recover func(DeploymentJob, string, string), wait func(func() bool, string), unchanged func()) {
	t.Helper()
	const database = "/var/lib/webscan-v1/agent.sqlite3"
	before, err := os.Stat(database)
	if err != nil {
		t.Fatal("actual Agent database", err)
	}
	pendingPath := site + "/pending-uninstall.php"
	// A lost backup response leaves the authenticated removal task paused and
	// collection fenced, while the old Agent still watches files.
	lose.Store(true)
	id := queue("uninstall", "kernel-uninstall-loss")
	failed := jobStatus(id, "failed")
	if !failed.CanRecover() || failed.Step != 2 || losses.Load() != 1 {
		t.Fatal("removal backup loss not fenced", failed.Phase(), failed.ErrorCode)
	}
	pending := func() bool { return webKernelPendingEvent(pendingPath) }
	wait(pending, "real unacknowledged event before removal")
	recover(failed, "resume", "kernel-uninstall-resume")
	removed := jobStatus(id, "succeeded")
	after, err := os.Stat(database)
	if err != nil || !os.SameFile(before, after) || !pending() {
		t.Fatal("removal lost live SQLite or pending event", err)
	}
	preserved := webKernelPendingEventIDs(t, pendingPath)
	if mode == "docker" {
		if exec.CommandContext(ctx, "docker", "inspect", "webscan-agent-go").Run() == nil {
			t.Fatal("project container still installed")
		}
	} else if _, err := os.Lstat("/etc/systemd/system/webscan-agent-native.service"); !os.IsNotExist(err) {
		t.Fatal("native service definition not removed", err)
	}
	status, raw := call("GET", "/api/v3/servers/node-a", nil, "")
	if status != 200 || !bytes.Contains(raw, []byte(`"lifecycle":"uninstalled"`)) {
		t.Fatalf("unconfirmed removal UI: %d %s", status, raw)
	}
	status, raw = call("GET", "/api/v3/deployments/"+id, nil, "")
	if status != 200 || !bytes.Contains(raw, []byte(`"can_rollback":true`)) {
		t.Fatalf("successful removal not recoverable: %d %s", status, raw)
	}
	unchanged()
	recover(removed, "rollback", "kernel-uninstall-success-restore")
	jobStatus(id, "rolled_back")
	wait(func() bool {
		var n int
		// Creating a PHP file may also produce a separate scan event at the
		// same path. Deduplication concerns event IDs, not one row per path.
		return f.s.DB.QueryRowContext(ctx, `SELECT count(*) FROM v3_events WHERE node='node-a' AND id=ANY($1::text[])`, preserved).Scan(&n) == nil && n == len(preserved)
	}, "restored Agent drains preserved event exactly once")
	wait(func() bool { return !pending() }, "central commit acknowledged to restored Agent")
	unchanged()
	// Repeat actual stop/start under the same immutable installation. A single
	// successful Type=simple restoration does not cover its exec transition.
	for cycle := 1; cycle <= 2; cycle++ {
		repeated := queue("uninstall", fmt.Sprintf("kernel-uninstall-cycle-%d", cycle))
		completed := jobStatus(repeated, "succeeded")
		recover(completed, "rollback", fmt.Sprintf("kernel-restore-cycle-%d", cycle))
		jobStatus(repeated, "rolled_back")
		unchanged()
	}
	// A second removal must use the replacement object's signed restoration
	// identity. A new installation then consumes the exact tombstone reference.
	second := queue("uninstall", "kernel-uninstall-again")
	jobStatus(second, "succeeded")
	reinstalled := queue("install", "kernel-reinstall-preserved")
	done := jobStatus(reinstalled, "succeeded")
	if done.Plan.Reinstall == nil || done.Plan.Reinstall.SourceJob != second {
		t.Fatal("new install did not bind preserved removal")
	}
	after, err = os.Stat(database)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("reinstallation replaced live data", err)
	}
	if err := os.WriteFile(site+"/after-reinstall.php", []byte("<?php echo 'after reinstall';"), 0600); err != nil {
		t.Fatal(err)
	}
	wait(func() bool {
		var n int
		return f.s.DB.QueryRowContext(ctx, `SELECT count(*) FROM v3_events WHERE node='node-a' AND payload->>'path'=$1`, site+"/after-reinstall.php").Scan(&n) == nil && n > 0
	}, "reinstalled signed Agent and mTLS event")
	status, raw = call("GET", "/api/v3/servers/node-a", nil, "")
	var detail struct {
		Node Node `json:"node"`
	}
	if status != 200 || json.Unmarshal(raw, &detail) != nil || !bytes.Contains(raw, []byte(`"lifecycle":"installed"`)) {
		t.Fatalf("reinstallation state not confirmed: %d %s", status, raw)
	}
	if tableCount(t, f.s, "v3_notifications") != 0 {
		t.Fatal("unexpected business notification")
	}
	unchanged()
	t.Log("real HTTPS API, PostgreSQL, fixed SSH, native/systemd or Docker29 removal, lost-response resume, preserved unacknowledged SQLite event, successful-removal rollback and tombstone-bound reinstall passed; center container/process/session/CSRF unchanged; metric sink simulated")
}

func webKernelPendingEventIDs(t *testing.T, path string) []string {
	t.Helper()
	db, err := persist.OpenReadOnly("/var/lib/webscan-v1/agent.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id FROM events WHERE accepted IS NULL AND json_extract(payload,'$.path')=? ORDER BY id`, path)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil || len(ids) == 0 {
		t.Fatal("missing preserved event IDs", rows.Err())
	}
	t.Logf("preserved %d actual unacknowledged event IDs", len(ids))
	return ids
}

func webKernelPendingEvent(path string) bool {
	db, err := persist.OpenReadOnly("/var/lib/webscan-v1/agent.sqlite3")
	if err != nil {
		return false
	}
	defer db.Close()
	var count int
	return db.QueryRow(`SELECT count(*) FROM events WHERE accepted IS NULL AND json_extract(payload,'$.path')=?`, path).Scan(&count) == nil && count > 0
}
