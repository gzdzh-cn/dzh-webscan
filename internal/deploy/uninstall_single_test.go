package deploy

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"
)

type uninstallTransport struct{}

func (uninstallTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
}

type singleReadyTransport struct{ original http.RoundTripper }

func (t singleReadyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/-/ready" {
		return uninstallTransport{}.RoundTrip(r)
	}
	return t.original.RoundTrip(r)
}

func fakeSingleDocker(t *testing.T) string {
	dir := fakeAdditionDocker(t)
	path := filepath.Join(dir, "docker")
	b, _ := os.ReadFile(path)
	s := string(b)
	s = strings.Replace(s, "if [ \"$1\" = inspect ];", "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then exit 0; fi\nif [ \"$1\" = inspect ];", 1)
	s = strings.Replace(s, "shift 3", "shift 3\nif [ \"$1\" = config ]; then exit 0; fi", 1)
	s = strings.Replace(s, "if [ \"$1\" = up ]; then", "if [ \"$1\" = up ]; then\n if [ -f \"$task_dir/fail-up\" ]; then exit 17; fi", 1)
	os.WriteFile(path, []byte(s), 0700)
	return dir
}

func TestSingleUninstallPreservesRunningSettingsAndRetriesOnlyMain(t *testing.T) {
	d := additionFixture(t)
	root := d.C.CentralRoot()
	// The selected node currently exists, alongside an unrelated scrape job.
	runtime, _ := common.ReadJSON(filepath.Join(root, "runtime.json"))
	common.M(runtime["nodes"])["new-node"] = common.Map{"name": "new", "token": "existing-token"}
	runtime["active_nodes"] = append(common.SS(runtime["active_nodes"]), "new-node")
	runtime["feishu"] = common.Map{"enabled": true, "webhook_url": "preserve-running-webhook"}
	common.AtomicJSON(filepath.Join(root, "runtime.json"), runtime)
	prom := common.Map{"global": common.Map{"scrape_interval": "special-interval"}, "scrape_configs": []any{common.Map{"job_name": "custom-job"}, common.Map{"job_name": "webscan-node-new-node"}}}
	os.WriteFile(filepath.Join(root, "prometheus.yml"), YAML(prom), 0600)
	d.State["active"] = common.SS(runtime["active_nodes"])
	dir := fakeSingleDocker(t)
	os.WriteFile(filepath.Join(dir, "fail-up"), nil, 0600)
	d.Remotes["new-node"] = testRemoteResult(t, "node removed", false)
	d.HTTP.Transport = singleReadyTransport{original: http.DefaultTransport}
	if err := d.Uninstall(context.Background()); err == nil || !strings.Contains(err.Error(), "single_uninstall_main_cleanup_pending") {
		t.Fatal("partial failure was not reported", err)
	}
	pending := common.M(d.State["single_uninstall"])
	if !common.B(pending["node_removed"]) || common.B(pending["complete"]) {
		t.Fatal("lost partial progress", pending)
	}
	beforeID := common.S(pending["id"])
	// A retry must succeed even when contacting the node would now fail.
	d.Remotes["new-node"] = testRemoteResult(t, "should not run", true)
	os.Remove(filepath.Join(dir, "fail-up"))
	if err := d.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if common.S(common.M(d.State["single_uninstall"])["id"]) != beforeID {
		t.Fatal("original backup replaced")
	}
	got, _ := common.ReadJSON(filepath.Join(root, "runtime.json"))
	if common.S(common.M(got["feishu"])["webhook_url"]) != "preserve-running-webhook" {
		t.Fatal("running secrets replaced from YAML")
	}
	if _, ok := common.M(got["nodes"])["new-node"]; ok {
		t.Fatal("token registration not removed")
	}
	if common.Contains(common.SS(got["active_nodes"]), "new-node") {
		t.Fatal("health registration not removed")
	}
	p, _ := os.ReadFile(filepath.Join(root, "prometheus.yml"))
	if !strings.Contains(string(p), "custom-job") || !strings.Contains(string(p), "special-interval") || strings.Contains(string(p), "webscan-node-new-node") {
		t.Fatal("unrelated scrape config changed")
	}
	commands, _ := os.ReadFile(filepath.Join(dir, "commands"))
	for _, line := range strings.Split(string(commands), "\n") {
		if strings.Contains(line, " up ") && !strings.Contains(line, "--no-deps --pull never") {
			t.Fatal("recreate could pull or touch dependencies", line)
		}
	}
	size := len(commands)
	if err := d.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	commands, _ = os.ReadFile(filepath.Join(dir, "commands"))
	if len(commands) != size {
		t.Fatal("completed uninstall repeated Docker operations")
	}
}

func TestSingleUninstallRejectsMissingMainImageBeforeNodeDeletion(t *testing.T) {
	d := additionFixture(t)
	dir := fakeSingleDocker(t)
	p := filepath.Join(dir, "docker")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), "[ \"$2\" = inspect ]; then exit 0", "[ \"$2\" = inspect ]; then exit 18", 1)), 0700)
	d.Remotes["new-node"] = testRemoteResult(t, "should not uninstall", true)
	if err := d.Uninstall(context.Background()); err == nil || err.Error() != "uninstall_main_image_not_available_locally" {
		t.Fatal(err)
	}
	if len(common.M(d.State["single_uninstall"])) > 0 {
		t.Fatal("destructive work started")
	}
}

func TestPendingSingleUninstallCannotBeBypassedWithInstall(t *testing.T) {
	d := additionFixture(t)
	common.AtomicJSON(stateFile(), common.Map{"nodes": common.Map{}, "single_uninstall": common.Map{"node": "new-node", "complete": false}})
	if err := Run(context.Background(), Options{Config: d.C.Path, Install: true}); err == nil || err.Error() != "single_uninstall_pending_use_original_node" {
		t.Fatal(err)
	}
}
