package deploy

import (
	"testing"
	"webscan/internal/common"
)

func TestDockerCPUQuotaCapabilities(t *testing.T) {
	for _, test := range []struct {
		name, data         string
		supported, invalid bool
	}{
		{"supported", `{"CPUCfsQuota":true,"CPUCfsPeriod":true}`, true, false},
		{"unsupported", `{"CPUCfsQuota":false,"CPUCfsPeriod":false}`, false, false},
		{"actual Docker field names", `{"CpuCfsQuota":false,"CpuCfsPeriod":false,"MemoryLimit":true}`, false, false},
		{"no quota", `{"CPUCfsQuota":false,"CPUCfsPeriod":true}`, false, false},
		{"no period", `{"CPUCfsQuota":true,"CPUCfsPeriod":false}`, false, false},
		{"missing", `{}`, false, true},
		{"partial", `{"CPUCfsQuota":true}`, false, true},
		{"null", `{"CPUCfsQuota":null,"CPUCfsPeriod":true}`, false, true},
		{"wrong type", `{"CPUCfsQuota":"false","CPUCfsPeriod":true}`, false, true},
		{"bad json", `daemon unavailable`, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := dockerCPUQuotaSupported([]byte(test.data))
			if got != test.supported || (err != nil) != test.invalid {
				t.Fatalf("supported=%v error=%v", got, err)
			}
		})
	}
}

func TestAgentResourceLimitsWithUnsupportedCPUQuota(t *testing.T) {
	c := fixture(t)
	node := c.Nodes[0]
	resources := common.M(node["resources"])
	for _, supported := range []bool{true, false} {
		compose := compatibleAgentCompose(c, node, "test/agent:v1", supported)
		agent := common.M(common.M(compose["services"])["agent"])
		_, limited := agent["cpus"]
		if limited != supported {
			t.Fatalf("quota capability %v: cpus=%v", supported, agent["cpus"])
		}
		if agent["mem_limit"] != "256m" || common.S(common.M(agent["environment"])["GOMEMLIMIT"]) != "64MiB" || common.S(common.M(agent["environment"])["GOMAXPROCS"]) != "2" {
			t.Fatal("CPU compatibility changed memory or Go concurrency limits", agent)
		}
		if common.F(resources["cpus"]) != 1 {
			t.Fatal("configured CPU limit was mutated")
		}
	}
}
