package deploy

import (
	"context"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"
)

func TestResolveNodeModePreservesExisting(t *testing.T) {
	n := common.Map{"id": "old", "deployment": common.Map{"mode": "native"}}
	for _, tc := range []struct {
		state    common.Map
		explicit bool
		want     string
	}{{common.Map{}, false, "docker"}, {common.Map{"active": []string{"old"}}, false, "docker"}, {common.Map{"nodes": common.Map{"old": common.Map{"phase": "complete"}}}, false, "docker"}, {common.Map{"nodes": common.Map{"old": common.Map{"deployment_mode": "native"}}}, false, "native"}, {common.Map{"active": []string{"old"}}, true, "native"}} {
		n["_deployment_explicit"] = tc.explicit
		if got := ResolveNodeMode(n, tc.state); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
}
func TestNativeUnitHasLimitsAndNoDockerDependency(t *testing.T) {
	n := fixture(t).Nodes[0]
	unit := NativeNodeUnit(n, "/opt/webscan-go/releases/v35")
	for _, want := range []string{"MemoryMax=256M", "CPUQuota=100%", "GOMEMLIMIT=64MiB", "LimitNOFILE=65536", "ProtectSystem=strict"} {
		if !strings.Contains(unit, want) {
			t.Fatal(want, unit)
		}
	}
	if strings.Contains(unit, "docker") {
		t.Fatal(unit)
	}
}
func TestSingleContainerAndNativeStandalonePackages(t *testing.T) {
	c := fixture(t)
	common.M(c.Raw["registry"])["prefix"] = "docker.io/gzdzh"
	for i, n := range c.Nodes {
		mode := "native"
		if i == 0 {
			mode = "docker"
		}
		n["deployment"] = common.Map{"mode": mode}
	}
	dir := filepath.Join(t.TempDir(), "packages")
	if e := PrepareCompose(c, dir, []byte("include: [services.yaml]")); e != nil {
		t.Fatal(e)
	}
	for _, n := range c.Nodes {
		id := common.S(n["id"])
		if nodeMode(n) == "native" {
			for _, name := range []string{"install-native.sh", "webscan-agent-native.service", "config/runtime.json"} {
				if _, e := os.Stat(filepath.Join(dir, id, name)); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := os.Stat(filepath.Join(dir, id, "services.yaml")); !os.IsNotExist(e) {
				t.Fatal("native emitted Docker stack")
			}
		} else {
			b, e := os.ReadFile(filepath.Join(dir, id, "services.yaml"))
			if e != nil {
				t.Fatal(e)
			}
			var cfg common.Map
			if e = yaml.Unmarshal(b, &cfg); e != nil {
				t.Fatal(e)
			}
			if len(common.M(cfg["services"])) != 1 {
				t.Fatal("sidecars retained")
			}
		}
	}
}

func TestNativeLimitsRejectUnenforcedOrChangedLimits(t *testing.T) {
	r := common.Map{"agent_memory_mib": 256, "cpus": 1.0}
	for _, tc := range []struct {
		output string
		valid  bool
	}{
		{"MemoryMax=268435456\nCPUQuotaPerSecUSec=1s\nLimitNOFILE=65536\n", true},
		{"MemoryMax=infinity\nCPUQuotaPerSecUSec=1s\nLimitNOFILE=65536\n", false},
		{"MemoryMax=268435456\nCPUQuotaPerSecUSec=infinity\nLimitNOFILE=65536\n", false},
		{"MemoryMax=268435456\nCPUQuotaPerSecUSec=500ms\nLimitNOFILE=65536\n", false},
		{"MemoryMax=268435456\nCPUQuotaPerSecUSec=1s\nLimitNOFILE=1024\n", false},
	} {
		if got := VerifyNativeLimits(tc.output, r); (got == nil) != tc.valid {
			t.Fatal(tc, got)
		}
	}
}
func TestNativeEnvironmentWithoutDockerAndInsufficientDisk(t *testing.T) {
	for _, diskOK := range []bool{true, false} {
		d := additionFixture(t)
		n := d.C.Selected("new-node")[0]
		n["deployment"] = common.Map{"mode": "native"}
		var commands []string
		r := testRemoteCommand(t, func(cmd string) (string, bool) {
			commands = append(commands, cmd)
			if strings.Contains(cmd, "free=$(df") {
				return "", !diskOK
			}
			if strings.Contains(cmd, "systemctl --version") {
				return "systemd 252\nmemory cpu io\n", false
			}
			return "", false
		})
		err := d.checkNodeEnvironment(context.Background(), r, n)
		if (err == nil) != diskOK {
			t.Fatal(err, diskOK)
		}
		if strings.Contains(strings.Join(commands, "\n"), "docker") {
			t.Fatal(commands)
		}
	}
}

func TestInterruptedBackupRestoresOnlyCompletedCurrentBackup(t *testing.T) {
	for _, complete := range []bool{false, true} {
		d := additionFixture(t)
		n := d.C.Selected("new-node")[0]
		d.RunID = "go-current"
		common.M(d.State["nodes"])["new-node"] = common.Map{"go_run_id": "go-previous", "backup_pending": "go-current", "previous_deployment_mode": "docker"}
		var commands []string
		d.Remotes["new-node"] = testRemoteCommand(t, func(cmd string) (string, bool) {
			commands = append(commands, cmd)
			if strings.HasPrefix(cmd, "test -f") {
				return "", !complete
			}
			return "", false
		})
		if err := d.RollbackNode(context.Background(), n, false); err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(commands, "\n")
		if strings.Contains(joined, "go-previous") {
			t.Fatal("restored an unrelated earlier task", joined)
		}
		if strings.Contains(joined, "--action restore-node") != complete {
			t.Fatal(complete, joined)
		}
	}
}
