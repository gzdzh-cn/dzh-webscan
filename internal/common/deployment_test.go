package common

import "testing"

func TestDeploymentPHPTestRecognizesOnlyReservedFixtureNames(t *testing.T) {
	for _, path := range []string{
		"/sites/.webscan-deploy-test-0123456789abcdef0123456789abcdef/fixture.php",
		"/sites/webscan-deploy-test-0123456789abcdef0123456789abcdef/fixture.php",
	} {
		if !DeploymentPHPTest(path) {
			t.Fatal("reserved fixture not recognized", path)
		}
	}
	for _, path := range []string{"/sites/config.php", "/sites/webscan-deploy-test/fixture.php", "/sites/webscan-deploy-test-0123456789abcdef0123456789abcdef/other.php", "/sites/business-webscan-deploy-test-0123456789abcdef0123456789abcdef/fixture.php"} {
		if DeploymentPHPTest(path) {
			t.Fatal("ordinary path recognized as deployment fixture", path)
		}
	}
}
