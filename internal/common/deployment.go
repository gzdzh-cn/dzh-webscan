package common

import "regexp"

// Reserved, isolated fixtures used only by the deployment acceptance workflow.
var deploymentPHP = regexp.MustCompile(`/\.webscan-deploy-test-[a-f0-9]{32}/fixture\.php$`)

func DeploymentPHPTest(path string) bool { return deploymentPHP.MatchString(path) }
