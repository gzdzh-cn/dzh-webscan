package deploy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webscan/internal/common"
	"webscan/internal/progress"
)

func TestCombinedRolloutPreparesAllNodesBeforeMainAndResumesWithoutSecondMainUpdate(t *testing.T) {
	d := additionFixture(t)
	d.O.Node = ""
	d.O.Upgrade = true
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	d.State["rollout"] = common.Map{"prepared": common.Map{}, "accepted": common.Map{}}
	var out bytes.Buffer
	ctx := progress.With(context.Background(), progress.New(&out, d.C.Raw, "部署"))
	calls := []string{}
	prepare := func(ctx context.Context, n common.Map) error {
		calls = append(calls, "prepare:"+common.S(n["id"]))
		return nil
	}
	main := func(ctx context.Context) error { calls = append(calls, "main"); return nil }
	interrupted := errors.New("interrupted-after-main")
	accept := func(ctx context.Context, n common.Map) error {
		calls = append(calls, "accept:"+common.S(n["id"]))
		return interrupted
	}
	if err := d.runRolloutSteps(ctx, prepare, main, accept); !errors.Is(err, interrupted) {
		t.Fatal(err)
	}
	if strings.Join(calls, ",") != "prepare:node-202,prepare:new-node,main,accept:node-202" {
		t.Fatal("unsafe ordering", calls)
	}
	state, err := common.ReadJSON(stateFile())
	if err != nil {
		t.Fatal(err)
	}
	d.State = state
	accept = func(ctx context.Context, n common.Map) error {
		calls = append(calls, "accept-success:"+common.S(n["id"]))
		return nil
	}
	if err = d.runRolloutSteps(ctx, prepare, main, accept); err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.Join(calls, ","), "main") != 1 || strings.Count(strings.Join(calls, ","), "prepare:") != 2 {
		t.Fatal("resume reinstalled or restarted main", calls)
	}
	if common.S(d.State["step"]) != "notifying" {
		t.Fatal(d.State["step"])
	}
	if !strings.Contains(out.String(), "[主服务器") || !strings.Contains(out.String(), "合并主服务器升级") {
		t.Fatal("wrong server log", out.String())
	}
}

func TestRolloutCrashConfirmationRequiresFilesAndBothServiceIdentities(t *testing.T) {
	d := additionFixture(t)
	dir := fakeAdditionDocker(t)
	root := d.C.CentralRoot()
	b, _ := os.ReadFile(filepath.Join(root, "runtime.json"))
	d.State["rollout"] = common.Map{"receiver_before": "receiver-old started true", "prometheus_before": "prometheus-old started true", "prom_changed": true, "main_config_hashes": common.Map{"runtime.json": common.Hash(b)}}
	if d.rolloutMainApplied(context.Background()) {
		t.Fatal("unchanged services treated as completed upgrade")
	}
	os.WriteFile(filepath.Join(dir, "receiver"), []byte("receiver-new started true\n"), 0600)
	if d.rolloutMainApplied(context.Background()) {
		t.Fatal("receiver-only update treated as complete")
	}
	os.WriteFile(filepath.Join(dir, "prometheus"), []byte("prometheus-new started true\n"), 0600)
	if !d.rolloutMainApplied(context.Background()) {
		t.Fatal("completed operation would recreate services on resume")
	}
	d.State["central_image_services"] = []string{"grafana"}
	common.M(d.State["rollout"])["grafana_before"] = "grafana-old started true"
	os.WriteFile(filepath.Join(dir, "grafana"), []byte("grafana-old started true\n"), 0600)
	if d.rolloutMainApplied(context.Background()) {
		t.Fatal("unfinished vendor name migration treated as completed upgrade")
	}
	os.WriteFile(filepath.Join(dir, "grafana"), []byte("grafana-new started true\n"), 0600)
	if !d.rolloutMainApplied(context.Background()) {
		t.Fatal("completed vendor name migration would repeat on resume")
	}
	os.WriteFile(filepath.Join(root, "runtime.json"), []byte("changed configuration"), 0600)
	if d.rolloutMainApplied(context.Background()) {
		t.Fatal("modified files accepted as original upgrade")
	}
}

func TestCombinedRolloutPreparationFailureCannotChangeMainOrStartTransport(t *testing.T) {
	d := additionFixture(t)
	d.O.Node = ""
	d.State["rollout"] = common.Map{"prepared": common.Map{}, "accepted": common.Map{}}
	blocked := errors.New("baseline-failure")
	mainCalled, transportCalled := false, false
	err := d.runRolloutSteps(context.Background(), func(context.Context, common.Map) error { return blocked }, func(context.Context) error { mainCalled = true; return nil }, func(context.Context, common.Map) error { transportCalled = true; return nil })
	if !errors.Is(err, blocked) || mainCalled || transportCalled {
		t.Fatal("baseline failure modified main or enabled transmission", err)
	}
}
