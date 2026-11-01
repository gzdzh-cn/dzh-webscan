//go:build linux

package controlplane

import (
	"context"
	"encoding/json"
	"os"
	"sync/atomic"
	"testing"
)

// Called only by the networkless kernel guest: these public API requests reach
// a real center container, SSH helper and native/systemd or Docker 29 service.
func webKernelMonitoringApplication(t *testing.T, ctx context.Context, f webDeploymentFixture, site string, version *int64, lose *atomic.Bool, losses *atomic.Int32, call func(string, string, any, string) (int, []byte), wait func(func() bool, string), unchanged func()) {
	t.Helper()
	root := "/v3-tests/new-monitor-root"
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	status, raw := call("GET", "/api/v3/monitoring/rules", nil, "")
	var rules monitoringRulesView
	if status != 200 || json.Unmarshal(raw, &rules) != nil {
		t.Fatalf("real public rules read: %d %s", status, raw)
	}
	rules.Rules.Roots = []string{site, root}
	rules.Rules.ExcludePaths, rules.Rules.CriticalPaths = []string{}, []string{}
	for index := 0; index < 2; index++ {
		if index == 1 {
			rules.Rules.ReconciliationIntervalHours++
		}
		edit := monitoringRulesRequest{Expected: rules.Version, Rules: rules.Rules}
		status, raw = call("POST", "/api/v3/monitoring/rules/preview", edit, "")
		var preview struct {
			Token string `json:"token"`
		}
		if status != 200 || json.Unmarshal(raw, &preview) != nil || preview.Token == "" {
			t.Fatalf("real rules save preview: %d %s", status, raw)
		}
		edit.Preview = preview.Token
		key := "kernel-monitoring-success"
		if index == 1 {
			key = "kernel-monitoring-rollback"
		}
		status, raw = call("PUT", "/api/v3/monitoring/rules", edit, key+"-save")
		if status != 200 || json.Unmarshal(raw, &rules) != nil {
			t.Fatalf("real rules save: %d %s", status, raw)
		}
		status, raw = call("POST", "/api/v3/monitoring/applications/preview", monitoringApplicationRequest{Expected: rules.Version, Nodes: []monitoringApplicationTarget{{ID: "node-a", Expected: *version}}}, key+"-preview")
		var application struct {
			ID    string `json:"id"`
			Token string `json:"token"`
		}
		if status != 200 || json.Unmarshal(raw, &application) != nil || application.ID == "" || application.Token == "" {
			t.Fatalf("real rules application preview: %d %s", status, raw)
		}
		if index == 1 {
			lose.Store(true)
		}
		status, raw = call("POST", "/api/v3/monitoring/applications", map[string]string{"preview": application.ID, "token": application.Token}, key+"-confirm")
		if status != 202 {
			t.Fatalf("real rules application confirm: %d %s", status, raw)
		}
		var current monitoringApplication
		await := func(want string) {
			t.Helper()
			wait(func() bool {
				status, raw = call("GET", "/api/v3/monitoring/applications/"+application.ID, nil, "")
				if status != 200 || json.Unmarshal(raw, &current) != nil {
					t.Fatalf("real monitoring progress: %d %s", status, raw)
				}
				if current.Status == "paused" && want == "succeeded" {
					t.Fatalf("real monitoring application paused: %s", raw)
				}
				return current.Status == want
			}, "actual rules application "+want)
		}
		if index == 0 {
			await("succeeded")
			if len(current.Nodes) != 1 || current.Nodes[0].State != "succeeded" || current.Nodes[0].Job == "" {
				t.Fatal("rules application lacks actual child evidence")
			}
			if err := os.WriteFile(root+"/batch-acceptance.php", []byte("<?php echo 'new monitored root';"), 0600); err != nil {
				t.Fatal(err)
			}
			wait(func() bool {
				var count int
				return f.s.DB.QueryRowContext(ctx, `SELECT count(*) FROM v3_events WHERE node='node-a' AND payload->>'path'=$1`, root+"/batch-acceptance.php").Scan(&count) == nil && count > 0
			}, "actual new root bind mount and mTLS event")
		} else {
			await("paused")
			if !current.CanRollback || len(current.Nodes) != 1 || current.Nodes[0].Job == "" {
				t.Fatal("lost backup response must provide real rollback")
			}
			status, raw = call("POST", "/api/v3/monitoring/applications/"+application.ID+"/rollback", map[string]string{"expected_version": current.Expected}, key+"-recover")
			if status != 202 {
				t.Fatalf("actual batch rollback: %d %s", status, raw)
			}
			await("rolled_back")
			if !losses.CompareAndSwap(1, 0) {
				t.Fatal("actual response-loss fixture did not execute exactly once")
			}
		}
		n, err := scanNode(f.s.DB.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE id='node-a'"))
		if err != nil || n.Version <= *version {
			t.Fatal("saved node version not advanced", err)
		}
		*version = n.Version
		unchanged()
	}
	t.Log("public inherited rules: actual signed deployment, added-root event, interrupted rollback and unchanged center/login passed")
}
