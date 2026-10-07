//go:build linux

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/assets"
	"webscan/internal/common"
)

func TestStartupInventoryReplacesRetainedStatusAndHonorsCancellation(t *testing.T) {
	for _, cancelInventory := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "cancelled"}[cancelInventory], func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "site")
			os.MkdirAll(root, 0700)
			// A real throttled read keeps startup in progress; no fake inventory.
			os.WriteFile(filepath.Join(root, "fixture.php"), []byte("<?php /* startup */"+strings.Repeat(" ", 2*1024*1024)), 0600)
			raw, _ := assets.Files.ReadFile("schema.yaml")
			var schema common.Map
			yaml.Unmarshal(raw, &schema)
			n := common.M(schema["node_defaults"])
			monitor := common.Clone(common.M(n["monitor"]))
			monitor["roots"], monitor["critical_paths"], monitor["exclude_paths"] = []string{root}, []string{}, []string{}
			common.M(monitor["reconciliation"])["max_read_mib_per_second"] = 1
			c := common.Map{"node_id": "startup-test", "monitor": monitor, "scan": n["scan"], "transport": n["transport"], "data_dir": filepath.Join(base, "data"), "log_dir": filepath.Join(base, "logs"), "probe_directory": filepath.Join(base, "probe"), "metrics_file": filepath.Join(base, "textfile", "agent.prom"), "yara_rules": filepath.Join(base, "rules.yar"), "retention_days": 7, "probe_seconds": 30, "public_url": "https://127.0.0.1:1", "vector_metrics_url": "http://127.0.0.1:1/metrics", "central_ca_file": "", "token": "test-only"}
			yara, _ := assets.Files.ReadFile("php-webshell.yar")
			os.WriteFile(common.S(c["yara_rules"]), yara, 0600)
			path := filepath.Join(base, "runtime.json")
			common.AtomicJSON(path, c)
			a, err := New(c, path)
			if err != nil {
				t.Fatal(err)
			}
			a.counter("baseline_completed", 1, true)
			a.counter("collector_ready", 1, true)
			common.AtomicJSON(filepath.Join(a.Data, "rules-status.json"), common.Map{"state": "applied", "instance_id": "previous-process", "coverage_ok": 1, "collector_ready": true})
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			stopped := make(chan struct{})
			go func() { result <- a.Run(ctx); close(stopped) }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-stopped:
				case <-time.After(10 * time.Second):
					t.Error("startup did not stop")
				}
				a.Close()
			})
			await(t, func() bool { return a.inventoryRunning.Load() && a.inventoryChecked.Load() > 0 })
			status, err := common.ReadJSON(filepath.Join(a.Data, "rules-status.json"))
			if err != nil || common.S(status["state"]) != "initializing" || common.S(status["instance_id"]) != a.Instance || common.B(status["collector_ready"]) {
				t.Fatal("old readiness survived startup", status, err)
			}
			if cancelInventory {
				cancel()
				if err := <-result; !errors.Is(err, context.Canceled) {
					t.Fatal("cancelled inventory reported success", err)
				}
				status, _ = common.ReadJSON(filepath.Join(a.Data, "rules-status.json"))
				if common.S(status["state"]) == "applied" || a.ready.Load() {
					t.Fatal("cancellation published ready", status)
				}
				var ready int
				a.DB.QueryRow("SELECT value FROM counters WHERE key='collector_ready'").Scan(&ready)
				if ready != 0 {
					t.Fatal("cancelled startup changed ready counter", ready)
				}
			} else {
				await(t, func() bool {
					s, e := common.ReadJSON(filepath.Join(a.Data, "rules-status.json"))
					return e == nil && common.S(s["state"]) == "applied" && common.B(s["collector_ready"])
				})
				b, err := os.ReadFile(common.S(c["metrics_file"]))
				if err != nil || !strings.Contains(string(b), "webscan_collector_ready 1\n") || !strings.Contains(string(b), "webscan_inventory_files_checked ") {
					t.Fatal("readiness metrics not published with applied status", string(b), err)
				}
			}
		})
	}
}
