package deploy

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"

	"gopkg.in/yaml.v3"
)

func TestMergedVectorTimeoutHasNumericYAMLType(t *testing.T) {
	c := fixture(t)
	config := VectorConfig(c, c.Nodes[0], common.Map{"nodes": common.Map{}})
	request := common.M(common.M(common.M(config["sinks"])["central"])["request"])
	if _, ok := request["timeout_secs"].(json.Number); !ok {
		t.Fatal("regression fixture must reproduce merged json.Number", request)
	}
	var parsed common.Map
	if err := yaml.Unmarshal(YAML(config), &parsed); err != nil {
		t.Fatal(err)
	}
	value := common.M(common.M(common.M(common.M(parsed["sinks"])["central"])["request"]))["timeout_secs"]
	if _, ok := value.(int); !ok || common.I(value) != 10 {
		t.Fatal("Vector timeout is not YAML integer", value)
	}
	var roundTrip common.Map
	if err := yaml.Unmarshal(YAML(common.Clone(common.Map{"integer": 10, "fraction": 1.25, "literal_string": "10", "nested": []any{common.Map{"port": 18081}}})), &roundTrip); err != nil {
		t.Fatal(err)
	}
	if _, ok := roundTrip["integer"].(int); !ok || roundTrip["fraction"] != 1.25 || roundTrip["literal_string"] != "10" {
		t.Fatal("numeric normalization changed other scalar types", roundTrip)
	}
}

func TestGeneratedVectorConfigValidatesInOfficialImage(t *testing.T) {
	image := os.Getenv("WEBSCAN_VECTOR_IMAGE")
	if image == "" {
		t.Skip("set WEBSCAN_VECTOR_IMAGE to run fixed-image configuration validation")
	}
	c := fixture(t)
	path := filepath.Join(t.TempDir(), "vector.yaml")
	if err := os.WriteFile(path, YAML(VectorConfig(c, c.Nodes[0], common.Map{"nodes": common.Map{"node-202": common.Map{"token": "isolated-token"}}})), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none", "--read-only", "-v", path+":/config/vector.yaml:ro", image, "validate", "--no-environment", "/config/vector.yaml").CombinedOutput()
	if err != nil {
		t.Fatal("generated Vector configuration rejected", string(output))
	}
	if !strings.Contains(string(output), "Validated") {
		t.Fatal("Vector did not confirm validation", string(output))
	}
}

func TestSidecarConfigErrorStopsBeforeFileAcceptance(t *testing.T) {
	c := fixture(t)
	n := c.Selected("node-202")[0]
	d := &Deploy{C: c, Remotes: map[string]*Remote{"node-202": testRemoteResult(t, "false 78\nfalse 143\n", false)}}
	if err := d.WaitNodeSidecars(context.Background(), n); err == nil || err.Error() != "node_vector_config_invalid" {
		t.Fatal("configuration failure not detected immediately", err)
	}
}
