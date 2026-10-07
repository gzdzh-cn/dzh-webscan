package deploy

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"webscan/internal/common"
	"webscan/internal/progress"
)

func TestNodeOnlyPreservesPendingGlobalConfigurationAndCurrentImage(t *testing.T) {
	d := additionFixture(t)
	d.State["go_release"] = "v2.0.10"
	d.O = Options{AddNode: true, Node: "new-node"}
	common.M(common.M(d.State["configuration"])["images"])["deployer"] = "webscan-deployer:v2.0.12"
	before := common.Clone(d.C.Raw)
	common.M(d.C.Raw["images"])["central"] = "webscan-central:v99"
	common.M(common.M(d.C.Raw["central"])["grafana"])["host_port"] = 3301
	common.M(d.C.Raw["central"])["install_dir"] = t.TempDir()
	common.M(d.C.Raw["feishu"])["webhook_url"] = "https://pending.invalid/secret"
	common.M(d.C.Raw["deployment"])["upgrade_existing_components"] = true
	if err := d.useInstalledMain(); err != nil {
		t.Fatal(err)
	}
	if !d.canAddNode() {
		t.Fatal("node-only unexpectedly requires global upgrade")
	}
	if len(common.M(d.C.Raw["images"])) != 2 {
		t.Fatal("legacy snapshot kept obsolete deployer image")
	}
	if common.S(common.M(d.C.Raw["images"])["central"]) != common.S(common.M(before["images"])["central"]) || common.I(common.M(common.M(d.C.Raw["central"])["grafana"])["host_port"]) == 3301 || common.S(common.M(d.C.Raw["feishu"])["webhook_url"]) == "https://pending.invalid/secret" {
		t.Fatal("pending global settings applied")
	}
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	if !common.B(d.State["target_add_node"]) || !d.addingNode() {
		t.Fatal("operation scope not persisted")
	}
	var out bytes.Buffer
	d.showScope(progress.With(context.Background(), progress.New(&out, d.C.Raw, "部署")))
	if !strings.Contains(out.String(), "忽略 YAML") || !strings.Contains(out.String(), "各最多重建一次") {
		t.Fatal(out.String())
	}
	// Resume the same node-only operation even though the pending YAML is newer.
	d.O.Resume = true
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	d.O.AddNode = false
	if err := d.initialize(); err == nil || err.Error() != "resume_scope_must_match_original_run" {
		t.Fatal("resume changed operation scope", err)
	}
}

func TestNodeOnlyUpdatesActiveNodeWithoutDuplicateRegistrationAndPreservesScrapeJobs(t *testing.T) {
	d := additionFixture(t)
	d.State["go_release"] = "v2.0.10"
	d.State["active"] = append(common.SS(d.State["active"]), "new-node")
	d.O = Options{AddNode: true, Node: "new-node"}
	root := d.C.CentralRoot()
	runtime, _ := common.ReadJSON(filepath.Join(root, "runtime.json"))
	runtime["active_nodes"] = common.SS(d.State["active"])
	common.AtomicJSON(filepath.Join(root, "runtime.json"), runtime)
	b, _ := os.ReadFile(filepath.Join(root, "prometheus.yml"))
	var prom common.Map
	yaml.Unmarshal(b, &prom)
	prom["scrape_configs"] = append(common.A(prom["scrape_configs"]), common.Map{"job_name": "custom-business", "static_configs": []any{common.Map{"targets": []string{"custom:1234"}}}})
	os.WriteFile(filepath.Join(root, "prometheus.yml"), YAML(prom), 0600)
	if err := d.useInstalledMain(); err != nil {
		t.Fatal(err)
	}
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	dir := fakeAdditionDocker(t)
	if err := d.registerAddition(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(root, "prometheus.yml"))
	yaml.Unmarshal(b, &prom)
	custom, count := false, 0
	for _, v := range common.A(prom["scrape_configs"]) {
		switch common.S(common.M(v)["job_name"]) {
		case "custom-business":
			custom = true
		case "webscan-node-new-node":
			count++
		}
	}
	if !custom || count != 1 || len(common.SS(d.State["active"])) != 2 {
		t.Fatal("registration altered unrelated jobs or duplicated active nodes", prom, d.State["active"])
	}
	commands, _ := os.ReadFile(filepath.Join(dir, "commands"))
	if strings.Count(string(commands), "--force-recreate receiver") != 1 || strings.Count(string(commands), "--force-recreate prometheus") != 1 || !strings.Contains(string(commands), "--pull never") {
		t.Fatal(string(commands))
	}
}
