package deploy

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"webscan/internal/common"
	"webscan/internal/progress"
)

func TestNodeReadyRejectsRetainedStatusAndPriorBaseline(t *testing.T) {
	started := time.Now().Add(-2 * time.Second)
	status := common.Map{"implementation": "goframe", "state": "applied", "instance_id": "current", "coverage_ok": 1, "collector_ready": true, "time": common.Now()}
	metrics := map[string]float64{"webscan_collector_ready": 1, "webscan_baseline_completed": 1, "webscan_coverage_ok": 1, "webscan_agent_heartbeat_seconds": common.Now()}
	if !currentNodeReady(status, metrics, started) {
		t.Fatal("current ready node rejected")
	}
	status["coverage_ok"] = 0
	if !currentNodeReady(status, metrics, started) {
		t.Fatal("legacy initial coverage result blocked a recovered live process")
	}
	metrics["webscan_coverage_ok"] = 0
	if currentNodeReady(status, metrics, started) {
		t.Fatal("incomplete live directory coverage accepted")
	}
	metrics["webscan_coverage_ok"], status["coverage_ok"] = 1, 1
	old := common.Clone(status)
	old["time"] = float64(started.Add(-time.Second).Unix())
	if currentNodeReady(old, metrics, started) {
		t.Fatal("previous process status accepted")
	}
	status["collector_ready"] = false
	if currentNodeReady(status, metrics, started) {
		t.Fatal("current initializing process accepted")
	}
	status["collector_ready"] = true
	metrics["webscan_collector_ready"] = 0
	if currentNodeReady(status, metrics, started) {
		t.Fatal("retained baseline passed before startup inventory")
	}
	metrics["webscan_collector_ready"] = 1
	metrics["webscan_agent_heartbeat_seconds"] = float64(started.Add(-time.Second).Unix())
	if currentNodeReady(status, metrics, started) {
		t.Fatal("old heartbeat accepted")
	}
}

func TestNodeReadyWaitsThroughStaleStatusAndCurrentInventory(t *testing.T) {
	d := additionFixture(t)
	n := d.C.Selected(d.O.Node)[0]
	started := time.Now().Add(-2 * time.Second)
	var mu sync.Mutex
	polls := 0
	r := testRemoteCommand(t, func(cmd string) (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasPrefix(cmd, "docker inspect"):
			polls++
			return "true false " + started.Format(time.RFC3339Nano), false
		case strings.Contains(cmd, "rules-status.json"):
			stamp := common.Now()
			if polls == 1 {
				stamp = float64(started.Add(-time.Second).Unix())
			}
			return string(common.JSON(common.Map{"implementation": "goframe", "state": "applied", "instance_id": "fixture", "coverage_ok": 1, "time": stamp})), false
		case strings.Contains(cmd, "agent.prom"):
			ready := 0
			if polls >= 4 {
				ready = 1
			}
			return fmt.Sprintf("webscan_collector_ready %d\nwebscan_baseline_completed 1\nwebscan_coverage_ok 1\nwebscan_agent_heartbeat_seconds %g\nwebscan_watches 29818\nwebscan_inventory_files_checked %d\n", ready, common.Now(), polls*1000), false
		default:
			return "", true
		}
	})
	d.Remotes[common.S(n["id"])] = r
	var out bytes.Buffer
	ctx := progress.With(context.Background(), progress.New(&out, d.C.Raw, "部署"))
	if err := d.waitNodeReady(ctx, n, time.Second, 10*time.Millisecond); err != nil {
		t.Fatal(err, out.String())
	}
	mu.Lock()
	got := polls
	mu.Unlock()
	if got < 4 {
		t.Fatal("startup check skipped current inventory", got)
	}
	if !strings.Contains(out.String(), "已核对 1000 个文件") || !strings.Contains(out.String(), "本次启动文件清单已完成") {
		t.Fatal("progress missing", out.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.waitNodeReady(ctx, n, time.Second, time.Millisecond); err != context.Canceled {
		t.Fatal("cancellation swallowed", err)
	}
}

func TestConfirmedAdditionRollbackCanStartFixedReleaseWithoutOverwritingOldJournal(t *testing.T) {
	d := additionFixture(t)
	d.O = Options{AddNode: true, Node: "new-node"}
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	oldRun, oldJournal := d.RunID, d.Journal.Dir
	if err := d.rollbackAddition(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.State["step"] = "addition-rolled-back"
	d.State["last_failure"] = common.Map{"stage": "node-addition", "rollback_confirmed": true}
	if !d.canRetryAddition() {
		t.Fatal("confirmed rollback cannot retry")
	}
	d.O.Node = "node-202"
	if d.canRetryAddition() {
		t.Fatal("different node bypassed recovery")
	}
	d.O.Node = "new-node"
	common.M(d.State["last_failure"])["rollback_confirmed"] = false
	if d.canRetryAddition() {
		t.Fatal("unconfirmed rollback bypassed recovery")
	}
	common.M(d.State["last_failure"])["rollback_confirmed"] = true
	common.M(d.State["node_addition"])["registration_started"] = true
	if d.canRetryAddition() {
		t.Fatal("incomplete registration bypassed recovery")
	}
	delete(common.M(d.State["node_addition"]), "registration_started")
	d.State["target_release"] = "old-release"
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	if !d.addingNode() || d.RunID == oldRun || d.Journal.Dir == oldJournal || common.S(d.State["target_release"]) != Release {
		t.Fatal("retry reused old run or selected wrong flow")
	}
}

func TestConfirmedRollbackWithCompletedSingleUninstallCanRetry(t *testing.T) {
	d := additionFixture(t)
	d.O = Options{AddNode: true, Node: "new-node"}
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	if err := d.rollbackAddition(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.State["step"] = "addition-rolled-back"
	d.State["last_failure"] = common.Map{"stage": "node-addition", "rollback_confirmed": true}
	common.M(d.State["nodes"])[d.O.Node] = common.Map{"go_run_id": d.RunID, "phase": "uninstalled"}
	u := common.Map{"node": d.O.Node, "complete": true, "node_removed": true, "central_present": true, "central_updated": true}
	d.State["single_uninstall"] = u
	if !d.canRetryAddition() {
		t.Fatal("completed uninstall after confirmed rollback cannot retry")
	}
	for _, key := range []string{"complete", "node_removed", "central_updated"} {
		u[key] = false
		if d.canRetryAddition() {
			t.Fatal("unfinished uninstall bypassed recovery", key)
		}
		u[key] = true
	}
	u["node"] = "node-202"
	if d.canRetryAddition() {
		t.Fatal("different node uninstall bypassed recovery")
	}
	u["node"] = d.O.Node
	d.State["active"] = append(common.SS(d.State["active"]), d.O.Node)
	if d.canRetryAddition() {
		t.Fatal("still registered node bypassed recovery")
	}
	d.State["active"] = common.SS(common.M(d.State["node_addition"])["previous_active"])
	u["central_present"], u["central_updated"] = false, false
	if !d.canRetryAddition() {
		t.Fatal("completed uninstall without central unnecessarily rejected")
	}
	oldRun := d.RunID
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	if d.RunID == oldRun || !d.addingNode() {
		t.Fatal("retry failed to create a new addition run")
	}
}
