package deploy

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"webscan/internal/common"
	"webscan/internal/progress"
)

// Keep legacy paths when allowed, but never bypass the user's monitor rules.
// Both acceptance and the final PHP modification test use this selection.
func deploymentFixtureRoot(n common.Map, id string) (string, error) {
	p, err := common.NewPolicy(common.M(n["monitor"]))
	if err != nil {
		return "", err
	}
	for _, base := range p.Roots {
		for _, prefix := range []string{".webscan-deploy-test-", "webscan-deploy-test-"} {
			root := filepath.Join(base, prefix+id)
			if p.Watches(root, "") && p.Tracked(filepath.Join(root, "fixture.php"), "") {
				return root, nil
			}
		}
	}
	return "", &progress.Failure{Code: "acceptance_php_path_not_monitored", Message: "该节点的监控规则无法覆盖独立 PHP 测试文件。请检查此节点 monitor.roots、extensions（须包含 .php）和 exclude_paths；脚本不会绕过忽略规则，尚未创建测试文件"}
}

func visibleFixture(path string) bool {
	return strings.HasPrefix(filepath.Base(filepath.Dir(path)), "webscan-deploy-test-")
}

func validateFixtureCapability(ready common.Map, path string) error {
	if visibleFixture(path) && !common.B(ready["deployment_visible_tests"]) {
		return &progress.Failure{Code: "acceptance_visible_test_requires_central_upgrade", Message: "忽略隐藏目录的规则需要使用普通目录验收，但现有主服务器尚不支持这种测试目录。请先执行 bash deploy-webscan.sh --upgrade --central-only 升级主服务器，再新增或更新子服务器；忽略规则无需删除"}
	}
	return nil
}

func (d *Deploy) requireFixtureCapability(ctx context.Context, path string) error {
	if !visibleFixture(path) {
		return nil
	}
	_, ready, err := common.Request(ctx, d.HTTP, "GET", fmt.Sprintf("http://127.0.0.1:%d/ready", common.I(common.M(common.M(d.C.Raw["central"])["event_service"])["port"])), nil, nil)
	if err != nil {
		return err
	}
	return validateFixtureCapability(common.M(ready), path)
}

func (d *Deploy) checkAcceptancePaths(ctx context.Context, n common.Map) error {
	root, err := deploymentFixtureRoot(n, common.ID())
	if err != nil {
		return err
	}
	if d.O.AddNode {
		return d.requireFixtureCapability(ctx, filepath.Join(root, "fixture.php"))
	}
	return nil
}
