package deploy

import (
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"
	"webscan/internal/progress"
)

func TestDeploymentFixturesRespectHiddenExclusionsAndNodeRoots(t *testing.T) {
	n := fixture(t).Nodes[0]
	m := common.M(n["monitor"])
	m["roots"], m["critical_paths"], m["exclude_paths"] = []string{"/sites"}, []string{}, []string{}
	id := "0123456789abcdef0123456789abcdef"
	root, err := deploymentFixtureRoot(n, id)
	if err != nil || root != "/sites/.webscan-deploy-test-"+id {
		t.Fatal(root, err)
	}
	m["exclude_paths"] = []string{"/sites/**/.*"}
	before := common.JSON(m)
	p, _ := common.NewPolicy(m)
	if p.Tracked(filepath.Join(root, "fixture.php"), "") {
		t.Fatal("fixture must reproduce production exclusion")
	}
	root, err = deploymentFixtureRoot(n, id)
	if err != nil || root != "/sites/webscan-deploy-test-"+id || !p.Watches(root, "") || !p.Tracked(filepath.Join(root, "fixture.php"), "") {
		t.Fatal(root, err)
	}
	if string(common.JSON(m)) != string(before) {
		t.Fatal("user monitor changed")
	}
	m["roots"] = []string{"/sites", "/other-sites"}
	m["exclude_paths"] = []string{"/sites/**/fixture.php", "/other-sites/**/.*"}
	root, err = deploymentFixtureRoot(n, id)
	if err != nil || root != "/other-sites/webscan-deploy-test-"+id {
		t.Fatal("second monitor root not selected", root, err)
	}
}

func TestDeploymentFixturesFailImmediatelyWhenNotMonitored(t *testing.T) {
	n := fixture(t).Nodes[0]
	m := common.M(n["monitor"])
	m["roots"], m["critical_paths"] = []string{"/sites"}, []string{}
	for _, tc := range []struct{ extensions, excludes []string }{
		{[]string{".php"}, []string{"/sites/**/fixture.php"}},
		{[]string{".js"}, []string{}},
	} {
		m["extensions"], m["exclude_paths"] = tc.extensions, tc.excludes
		root, err := deploymentFixtureRoot(n, common.ID())
		if root != "" || err == nil || !strings.Contains(progress.Explain(err), "monitor.roots") {
			t.Fatal("unmonitorable PHP test not rejected", root, err)
		}
	}
}

func TestVisibleFixtureCapabilityPreservesOlderCentralCompatibility(t *testing.T) {
	hidden := "/sites/.webscan-deploy-test-0123456789abcdef0123456789abcdef/fixture.php"
	visible := strings.Replace(hidden, "/.webscan", "/webscan", 1)
	if validateFixtureCapability(common.Map{}, hidden) != nil || validateFixtureCapability(common.Map{"deployment_visible_tests": true}, visible) != nil {
		t.Fatal("supported fixture refused")
	}
	if err := validateFixtureCapability(common.Map{"deployment_acceptance": true}, visible); err == nil || err.Error() != "acceptance_visible_test_requires_central_upgrade" {
		t.Fatal("old central silently allowed incompatible registration", err)
	}
}
