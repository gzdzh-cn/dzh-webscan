package deploy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"webscan/internal/common"
)

type checkExecutor func(context.Context, string) ([]byte, error)

func (f checkExecutor) Run(ctx context.Context, cmd string) ([]byte, error) { return f(ctx, cmd) }
func TestPrerequisitesAreReadOnlyAndReportFailures(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		n := common.Map{"deployment": common.Map{"mode": mode}, "monitor": common.Map{"roots": []string{"/www/site with space"}}, "scan": common.Map{"clamav": common.Map{"enabled": true}}}
		commands := []string{}
		report := CheckNodePrerequisites(context.Background(), checkExecutor(func(_ context.Context, cmd string) ([]byte, error) {
			commands = append(commands, cmd)
			if strings.Contains(cmd, "test -S") {
				return nil, errors.New("missing socket")
			}
			if strings.Contains(cmd, "docker info") {
				return []byte("install-on-deploy"), nil
			}
			return nil, nil
		}), n, nil)
		if report.OK {
			t.Fatal("unavailable scanner accepted")
		}
		all := strings.Join(commands, "\n")
		for _, mutation := range []string{"docker restart", "apt-get", "systemctl restart", "mkdir", "rm -"} {
			if strings.Contains(all, mutation) {
				t.Fatal("check mutated host", mutation)
			}
		}
		if mode == "native" && strings.Contains(all, "docker") {
			t.Fatal("native required Docker")
		}
		if !strings.Contains(all, Q("/www/site with space")) {
			t.Fatal("root was not safely quoted")
		}
		if mode == "docker" {
			warning := false
			for _, i := range report.Items {
				warning = warning || i.Status == "warning"
			}
			if !warning {
				t.Fatal("missing Docker not distinguished")
			}
		}
	}
}
func TestPrerequisiteFailuresCannotLookLikeSuccess(t *testing.T) {
	report := CheckNodePrerequisites(context.Background(), checkExecutor(func(context.Context, string) ([]byte, error) { return nil, errors.New("sensitive stderr") }), common.Map{"deployment": common.Map{"mode": "native"}}, nil)
	if report.OK || len(report.Items) < 3 {
		t.Fatal(report)
	}
	for _, item := range report.Items {
		if item.Status != "failed" || item.Suggestion == "" || strings.Contains(item.Message, "sensitive") {
			t.Fatal(item)
		}
	}
}
func TestRequirementsReflectConfiguredPortsWithoutCredentials(t *testing.T) {
	c := fixture(t)
	n := c.Nodes[0]
	common.M(n["ssh"])["port"] = 2222
	common.M(n["metrics"])["port"] = 19101
	v := DeploymentRequirements(c)
	items := common.A(v["nodes"])
	if common.I(common.M(items[0])["ssh_port"]) != 2222 || common.I(common.M(items[0])["metrics_port"]) != 19101 {
		t.Fatal(v)
	}
	if strings.Contains(string(common.JSON(v)), "password") {
		t.Fatal("requirements leaked credentials")
	}
}
