package config

import (
	"testing"
	"webscan/internal/common"
)

func TestAppliedFingerprintsPreserveOtherScopes(t *testing.T) {
	raw := common.Map{"central": common.Map{"name": "main"}, "node_defaults": common.Map{"monitor": common.Map{"roots": []any{"/www"}}}, "nodes": []any{common.Map{"id": "a", "ssh": common.Map{"password": "one"}}, common.Map{"id": "b"}}}
	state := common.Map{}
	RecordApplied(state, raw, "", false)
	before := common.Clone(common.M(state["applied_fingerprints"]))
	common.M(common.M(raw["node_defaults"])["monitor"])["roots"] = []any{"/new"}
	RecordApplied(state, raw, "a", false)
	after := common.M(state["applied_fingerprints"])
	if before["a"] == after["a"] || before["b"] != after["b"] || before["central"] != after["central"] {
		t.Fatal("node-only polluted application scopes")
	}
	common.M(raw["central"])["name"] = "changed"
	RecordApplied(state, raw, "", true)
	if before["b"] != common.M(state["applied_fingerprints"])["b"] || before["central"] == common.M(state["applied_fingerprints"])["central"] {
		t.Fatal("central-only polluted node scope")
	}
	// Reordering node definitions has no effect on per-node signatures.
	original := ApplicationFingerprints(raw, "test-key")
	nodes := common.A(raw["nodes"])
	raw["nodes"] = []any{nodes[1], nodes[0]}
	if string(common.JSON(original)) != string(common.JSON(ApplicationFingerprints(raw, "test-key"))) {
		t.Fatal("order changed signatures")
	}
}
