package deploy

import (
	"testing"
	"webscan/internal/common"
)

func TestRulesComparisonUsesEffectiveNodesAndIgnoresImagePublication(t *testing.T) {
	c := fixture(t)
	current := common.M(Redact(c.Raw))
	previous := common.Clone(current)
	for _, value := range common.A(previous["nodes"]) {
		node := common.M(value)
		expanded := common.Merge(common.M(previous["node_defaults"]), node)
		for key, val := range expanded {
			node[key] = val
		}
	}
	common.M(previous["images"])["central"] = "old/central@sha256:locked"
	common.M(common.M(previous["node_defaults"])["ssh"])["host_key_sha256"] = ""
	for _, value := range common.A(current["nodes"]) {
		delete(common.M(common.M(value)["ssh"]), "host_key_sha256")
	}
	common.M(common.M(current["node_defaults"])["monitor"])["exclude_paths"] = []string{"**/cache/**"}
	if string(common.JSON(withoutRules(previous))) != string(common.JSON(withoutRules(current))) {
		t.Fatal("equivalent inherited/expanded configuration or new image blocked filters")
	}
	if common.S(common.M(previous["images"])["central"]) != "old/central@sha256:locked" {
		t.Fatal("comparison mutated deployment state")
	}
	for _, test := range []struct {
		name   string
		change func(common.Map)
	}{
		{"root", func(raw common.Map) {
			common.M(common.M(raw["node_defaults"])["monitor"])["roots"] = []string{"/another"}
		}},
		{"memory", func(raw common.Map) { common.M(common.M(raw["node_defaults"])["resources"])["agent_memory_mib"] = 512 }},
		{"host", func(raw common.Map) { common.M(common.A(raw["nodes"])[0])["host"] = "198.51.100.99" }},
		{"metrics port", func(raw common.Map) { common.M(common.M(raw["node_defaults"])["metrics"])["port"] = 19123 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			modified := common.Clone(current)
			test.change(modified)
			if string(common.JSON(withoutRules(previous))) == string(common.JSON(withoutRules(modified))) {
				t.Fatal("non-rule change escaped validation")
			}
		})
	}
}

func TestRulesCommitPreservesUnappliedSettingsAndReplacesInheritedFilters(t *testing.T) {
	c := fixture(t)
	previous := common.M(Redact(c.Raw))
	current := common.Clone(previous)
	common.M(current["images"])["central"] = "new/central:vnext"
	defaults := common.M(common.M(current["node_defaults"])["monitor"])
	defaults["exclude_paths"] = []string{"**/cache/**"}
	first := common.M(common.A(previous["nodes"])[0])
	first["monitor"] = common.Merge(common.M(common.M(previous["node_defaults"])["monitor"]), common.Map{"exclude_paths": []string{"**/old/**"}})
	currentFirst := common.M(common.A(current["nodes"])[0])
	delete(common.M(currentFirst["monitor"]), "exclude_paths")
	second := common.M(common.A(current["nodes"])[1])
	second["monitor"] = common.Map{"extensions": []string{".php", ".js"}}
	applied := configurationWithRules(previous, current)
	if common.S(common.M(applied["images"])["central"]) != common.S(common.M(previous["images"])["central"]) {
		t.Fatal("unapplied image committed")
	}
	for index, value := range common.A(applied["nodes"]) {
		got := common.Merge(common.M(applied["node_defaults"]), common.M(value))
		want := common.Merge(common.M(current["node_defaults"]), common.M(common.A(current["nodes"])[index]))
		for _, key := range common.RuleFields {
			if string(common.JSON(common.M(got["monitor"])[key])) != string(common.JSON(common.M(want["monitor"])[key])) {
				t.Fatalf("node %d filter %s did not preserve inheritance", index, key)
			}
		}
	}
	if common.SS(common.M(first["monitor"])["exclude_paths"])[0] != "**/old/**" {
		t.Fatal("commit mutated previous state")
	}
}
