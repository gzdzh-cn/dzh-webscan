package deploy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"webscan/internal/common"
)

func additionFixture(t *testing.T) *Deploy {
	t.Helper()
	oldRoot := StateRoot
	StateRoot = t.TempDir()
	t.Cleanup(func() { StateRoot = oldRoot })
	c := fixture(t)
	common.M(c.Raw["central"])["install_dir"] = t.TempDir()
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ready":true}`)) }))
	t.Cleanup(ready.Close)
	u, _ := url.Parse(ready.URL)
	port, _ := strconv.Atoi(u.Port())
	common.M(common.M(c.Raw["central"])["event_service"])["port"] = port
	// Retain one old node, then add a genuinely new selected node.
	old := c.Nodes[0]
	added := common.Clone(old)
	added["id"], added["name"], added["host"] = "new-node", "新增节点", "192.0.2.99"
	c.Nodes = []common.Map{old, added}
	c.Raw["nodes"] = []any{old, added}
	common.M(c.Raw["deployment"])["node_order"] = []string{common.S(old["id"]), "new-node"}
	previous := common.Clone(c.Raw)
	previous["nodes"] = []any{old}
	common.M(previous["deployment"])["node_order"] = []string{common.S(old["id"])}
	secrets := common.Map{"alert_token": "test-alert", "nodes": common.Map{common.S(old["id"]): common.Map{"token": "test-old"}, "new-node": common.Map{"token": "test-new"}}}
	active := []string{common.S(old["id"])}
	images := common.Map{"central": "test/central@sha256:immutable", "agent": "test/agent@sha256:immutable", "prometheus": "test/prometheus@sha256:immutable"}
	d := &Deploy{C: c, O: Options{Node: "new-node", Upgrade: true}, Secrets: secrets, Images: images, HTTP: ready.Client(), Remotes: map[string]*Remote{}, State: common.Map{"nodes": common.Map{}, "active": active, "step": "complete", "central_installed": true, "go_release": "old-version", "configuration": Redact(previous), "config_hash": "previous-hash", "image_lock": images}}
	root := c.CentralRoot()
	os.MkdirAll(filepath.Join(root, "pki"), 0700)
	os.WriteFile(filepath.Join(root, "pki", "ca.key"), []byte("fixture"), 0600)
	os.WriteFile(filepath.Join(root, "compose.yml"), YAML(ComposeCentral(c, images)), 0600)
	priorC := &Config{Raw: previous, Nodes: []common.Map{old}}
	common.AtomicJSON(filepath.Join(root, "runtime.json"), CentralRuntime(priorC, secrets, active))
	os.WriteFile(filepath.Join(root, "prometheus.yml"), YAML(Prometheus(priorC, active)), 0600)
	return d
}

func TestAdditionEligibilityAndMainUpgradeFallback(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Deploy)
	}{
		{"fresh", func(d *Deploy) { d.State["central_installed"] = false }},
		{"main-image-upgrade", func(d *Deploy) { common.M(d.C.Raw["images"])["central"] = "webscan-central:v-next" }},
		{"main-port-change", func(d *Deploy) { common.M(common.M(d.C.Raw["central"])["grafana"])["host_port"] = 3301 }},
		{"secret-change", func(d *Deploy) { common.M(d.C.Raw["feishu"])["signing_secret"] = "new-secret" }},
		{"existing-node-change", func(d *Deploy) { d.C.Nodes[0]["name"] = "edited-existing" }},
		{"active-node", func(d *Deploy) { d.State["active"] = []string{"new-node"} }},
		{"all-nodes", func(d *Deploy) { d.O.Node = "" }},
		{"vendor-upgrade", func(d *Deploy) { common.M(d.C.Raw["deployment"])["upgrade_existing_components"] = true }},
		{"missing-main-compose", func(d *Deploy) { os.Remove(filepath.Join(d.C.CentralRoot(), "compose.yml")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := additionFixture(t)
			// A newer agent release needn't upgrade the receiver.
			common.M(d.C.Raw["images"])["agent"] = "webscan-agent:v-next"
			if !d.canAddNode() {
				t.Fatal("compatible new node did not select incremental flow")
			}
			tc.change(d)
			if d.canAddNode() {
				t.Fatal("unsafe incremental flow accepted")
			}
		})
	}
}

func TestAdditionCheckpointsStopBeforeRegistrationAndResume(t *testing.T) {
	d := additionFixture(t)
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	if !d.addingNode() {
		t.Fatal("flow was not persisted")
	}
	calls := []string{}
	interrupted := errors.New("interrupted")
	steps := []additionStep{
		{key: "local_ready", run: func(context.Context) error { calls = append(calls, "local"); return nil }},
		{key: "registered", run: func(context.Context) error { calls = append(calls, "register"); return interrupted }},
		{key: "transport_ready", run: func(context.Context) error { calls = append(calls, "transport"); return nil }},
	}
	if !errors.Is(d.additionSteps(context.Background(), steps), interrupted) {
		t.Fatal("missing failure")
	}
	if strings.Join(calls, ",") != "local,register" {
		t.Fatal(calls)
	}
	state, err := common.ReadJSON(stateFile())
	if err != nil {
		t.Fatal(err)
	}
	d.State = state
	d.O.Resume = true
	if err = d.initialize(); err != nil {
		t.Fatal(err)
	}
	steps[1].run = func(context.Context) error { calls = append(calls, "register-success"); return nil }
	if err = d.additionSteps(context.Background(), steps); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, ",") != "local,register,register-success,transport" {
		t.Fatal("repeated installation or early transport", calls)
	}
	if err = d.additionSteps(context.Background(), steps); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 4 {
		t.Fatal("completed stages repeated", calls)
	}
}

func fakeAdditionDocker(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("WEBSCAN_TEST_DOCKER_DIR", dir)
	// Model identities across recreation, including a crash after Docker finished
	// but before the deployer saved its checkpoint. No real server is contacted.
	script := `#!/bin/sh
set -eu
task_dir="$WEBSCAN_TEST_DOCKER_DIR"
printf '%s\n' "$*" >> "$task_dir/commands"
if [ "$1" = inspect ]; then cat "$task_dir/$4"; exit; fi
shift 3
if [ "$1" = ps ]; then printf '%s\n' "$3"; exit; fi
if [ "$1" = up ]; then
 for service in "$@"; do
  case "$service" in receiver|prometheus)
   printf '%s\n' "$service-new started true" > "$task_dir/$service";;
  esac
 done
 exit
fi
exit 1
`
	os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700)
	for _, s := range []string{"receiver", "prometheus"} {
		os.WriteFile(filepath.Join(dir, s), []byte(s+"-old started true\n"), 0600)
	}
	return dir
}

func TestAdditionRegistrationSingleRecreationResumeAndRollback(t *testing.T) {
	d := additionFixture(t)
	beforeRuntime, _ := os.ReadFile(filepath.Join(d.C.CentralRoot(), "runtime.json"))
	beforeProm, _ := os.ReadFile(filepath.Join(d.C.CentralRoot(), "prometheus.yml"))
	beforeCompose, _ := os.ReadFile(filepath.Join(d.C.CentralRoot(), "compose.yml"))
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	dir := fakeAdditionDocker(t)
	if err := d.registerAddition(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime, err := common.ReadJSON(filepath.Join(d.C.CentralRoot(), "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	if common.S(common.M(common.M(runtime["nodes"])["new-node"])["token"]) != "test-new" || !common.Contains(common.SS(runtime["active_nodes"]), "new-node") {
		t.Fatal("node was not registered")
	}
	// Simulate death immediately after successful Docker recreation.
	s := common.M(d.State["node_addition"])
	delete(s, "receiver_restarted")
	delete(s, "prometheus_restarted")
	d.save()
	state, err := common.ReadJSON(stateFile())
	if err != nil {
		t.Fatal(err)
	}
	d.State = state
	if err = d.registerAddition(context.Background()); err != nil {
		t.Fatal(err)
	}
	commands, _ := os.ReadFile(filepath.Join(dir, "commands"))
	if strings.Count(string(commands), "--force-recreate receiver\n") != 1 || strings.Count(string(commands), "--force-recreate prometheus\n") != 1 {
		t.Fatalf("main restarted more than once: %s", commands)
	}
	for _, line := range strings.Split(string(commands), "\n") {
		if strings.Contains(line, " up ") && !strings.Contains(line, "--no-deps") {
			t.Fatal("dependencies may be restarted")
		}
	}
	queue := filepath.Join(StateRoot, "pending-events")
	os.WriteFile(queue, []byte("keep-event"), 0600)
	// Explicit node-scoped rollback must also undo its main registration.
	if err = d.Rollback(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(d.C.CentralRoot(), "runtime.json"))
	if string(after) != string(beforeRuntime) {
		t.Fatal("runtime not restored")
	}
	after, _ = os.ReadFile(filepath.Join(d.C.CentralRoot(), "prometheus.yml"))
	if string(after) != string(beforeProm) {
		t.Fatal("scrapes not restored")
	}
	after, _ = os.ReadFile(filepath.Join(d.C.CentralRoot(), "compose.yml"))
	if string(after) != string(beforeCompose) {
		t.Fatal("compose changed")
	}
	after, _ = os.ReadFile(queue)
	if string(after) != "keep-event" {
		t.Fatal("events lost")
	}
	if common.Contains(common.SS(d.State["active"]), "new-node") {
		t.Fatal("rolled back node still active")
	}
	if d.State["step"] != "rolled-back" {
		t.Fatal("rollback not marked")
	}
	if !d.canAddNode() {
		t.Fatal("a restored main cannot retry incremental addition")
	}
}

func TestAdditionPreparationFailureDoesNotRestartMain(t *testing.T) {
	d := additionFixture(t)
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	dir := fakeAdditionDocker(t)
	failure := errors.New("node preparation failed")
	if err := d.additionSteps(context.Background(), []additionStep{
		{key: "local_ready", run: func(context.Context) error { return failure }},
		{key: "registered", run: d.registerAddition},
	}); !errors.Is(err, failure) {
		t.Fatal("node failure was not propagated")
	}
	if err := d.rollbackAddition(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "commands")); len(b) != 0 {
		t.Fatal("untouched main was restarted")
	}
}

func TestStagedNodeRequiresBaselineAndCollectorButAllowsHeldVector(t *testing.T) {
	metrics := map[string]float64{"webscan_collector_ready": 1, "webscan_baseline_completed": 1, "webscan_coverage_ok": 1, "webscan_agent_heartbeat_seconds": common.Now(), "webscan_vector_metrics_up": 0}
	if !stagedNodeHealthy(metrics) {
		t.Fatal("held Vector prevented local readiness")
	}
	for _, key := range []string{"webscan_collector_ready", "webscan_baseline_completed", "webscan_coverage_ok", "webscan_agent_heartbeat_seconds"} {
		prior := metrics[key]
		metrics[key] = 0
		if stagedNodeHealthy(metrics) {
			t.Fatal("unready collector accepted", key)
		}
		metrics[key] = prior
	}
}
