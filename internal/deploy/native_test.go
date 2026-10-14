package deploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"
)

func TestLegacyStopUsesProjectOwnershipForGeneratedNames(t *testing.T) {
	old := common.Map{"name": "webscan-v1", "services": common.Map{"loki": common.Map{"image": "fixture/loki"}}}
	q, e := legacyOwnedContainerQuery(old, "loki")
	if e != nil || !strings.Contains(strings.Join(q, " "), "label=com.docker.compose.project=webscan-v1") || !strings.Contains(strings.Join(q, " "), "label=com.docker.compose.service=loki") {
		t.Fatal(q, e)
	}
	if q, e = legacyOwnedContainerQuery(old, "grafana"); e != nil || q != nil {
		t.Fatal("external service selected", q, e)
	}
	delete(old, "name")
	if _, e = legacyOwnedContainerQuery(old, "loki"); e == nil {
		t.Fatal("missing project must stop cutover")
	}
}

func TestNativeStackRuntimeMemoryAndTLS(t *testing.T) {
	c := fixture(t)
	common.M(common.M(c.Raw["central"])["monitoring"])["mode"] = "native"
	images := common.Map{"central": "fixture/central:latest", "exporter": "fixture/exporter:v1"}
	services := common.M(ComposeCentral(c, images)["services"])
	if len(services) != 1 || services["receiver"] == nil || services["host-exporter"] != nil {
		t.Fatal(services)
	}
	runtime := CentralRuntime(c, common.Map{"nodes": common.Map{}}, []string{common.S(c.Nodes[0]["id"])})
	m := common.M(runtime["monitoring"])
	if len(common.A(m["nodes"])) != 3 || common.S(m["client_cert"]) != "/backup-config/pki/client.crt" {
		t.Fatal(m)
	}
	common.M(c.Raw["ssl"])["enabled"] = false
	runtime = CentralRuntime(c, common.Map{"nodes": common.Map{}}, nil)
	if common.M(runtime["monitoring"])["client_cert"] != nil {
		t.Fatal("retained TLS settings")
	}
	budget := freshInstallMemory(c)
	if budget.Grafana != 0 || budget.Loki != 0 || budget.Components != 544 {
		t.Fatal(budget)
	}
}
func TestNativeAdditionRegistersOnlyNodePreservesPendingSettings(t *testing.T) {
	d := additionFixture(t)
	common.M(common.M(d.C.Raw["central"])["monitoring"])["mode"] = "native"
	common.M(common.M(common.M(d.State["configuration"])["central"])["monitoring"])["mode"] = "native"
	root := d.C.CentralRoot()
	os.WriteFile(filepath.Join(root, "compose.yml"), YAML(ComposeCentral(d.C, d.Images)), 0600)
	prior := &Config{Raw: common.M(d.State["configuration"]), Nodes: []common.Map{d.C.Nodes[0]}}
	runtime := CentralRuntime(prior, d.Secrets, common.SS(d.State["active"]))
	common.M(runtime["website_monitor"])["interval_seconds"] = 77
	common.AtomicJSON(filepath.Join(root, "runtime.json"), runtime)
	// Explicit add-node uses installed runtime even if a global YAML change is pending.
	d.O.AddNode = true
	common.M(common.M(d.C.Raw["central"])["website_monitor"])["interval_seconds"] = 123
	if !d.canAddNode() {
		t.Fatal("native node addition rejected")
	}
	// The registration renders only the selected endpoint, preserving actual settings.
	desired := monitoringRuntime(d.C, []string{d.O.Node})
	var added common.Map
	for _, v := range common.A(desired["nodes"]) {
		if common.S(common.M(v)["id"]) == d.O.Node {
			added = common.M(v)
		}
	}
	if added == nil || !strings.Contains(common.S(added["url"]), common.S(d.C.Selected(d.O.Node)[0]["host"])) {
		t.Fatal(added)
	}
	if len(d.registrationServices()) != 1 {
		t.Fatal(d.registrationServices())
	}
}
func TestNativeRejectsDirectMigrationWithoutReceipt(t *testing.T) {
	c := fixture(t)
	common.M(common.M(c.Raw["central"])["monitoring"])["mode"] = "native"
	common.M(c.Raw["central"])["install_dir"] = t.TempDir()
	root := c.CentralRoot()
	common.AtomicJSON(filepath.Join(root, "runtime.json"), common.Map{"monitoring": common.Map{"mode": "legacy"}})
	old := StateRoot
	StateRoot = t.TempDir()
	defer func() { StateRoot = old }()
	d := &Deploy{C: c, State: common.Map{}}
	if e := d.nativeCentral(context.Background()); e == nil || !strings.Contains(e.Error(), "历史尚未迁移") {
		t.Fatal(e)
	}
}

func TestNativeComposeHasNoLegacyFilesOrPrivilegedMounts(t *testing.T) {
	c := fixture(t)
	common.M(c.Raw["registry"])["prefix"] = "docker.io/gzdzh"
	common.M(common.M(c.Raw["central"])["monitoring"])["mode"] = "native"
	dir := filepath.Join(t.TempDir(), "package")
	if e := PrepareCompose(c, dir, []byte("include: []\n")); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"central/config/prometheus.yml", "central/config/alertmanager.yml", "central/config/loki.yml", "central/grafana-credentials.json", "central/data/grafana"} {
		if _, e := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(e) {
			t.Fatal("legacy file in native package", name, e)
		}
	}
	runtime, e := common.ReadJSON(filepath.Join(dir, "central/config/runtime.json"))
	if e != nil {
		t.Fatal(e)
	}
	if common.S(runtime["management_socket"]) != "" {
		t.Fatal("implicitly enabled host management")
	}
	raw, e := os.ReadFile(filepath.Join(dir, "central/services.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), "docker.sock") || strings.Contains(string(raw), "/run/webscan-management") {
		t.Fatal("privileged mount in standalone package")
	}
}
