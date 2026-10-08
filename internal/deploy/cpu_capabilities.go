package deploy

import (
	"encoding/json"
	"errors"
	"webscan/internal/common"
)

// Query the Docker daemon rather than the deployer's host cgroup filesystem.
// Missing or malformed capability data must not silently disable a limit.
func dockerCPUQuotaSupported(data []byte) (bool, error) {
	var info struct {
		Quota  *bool `json:"CPUCfsQuota"`
		Period *bool `json:"CPUCfsPeriod"`
	}
	if err := json.Unmarshal(data, &info); err != nil || info.Quota == nil || info.Period == nil {
		return false, errors.New("node_docker_cpu_capability_check_failed")
	}
	return *info.Quota && *info.Period, nil
}

func compatibleAgentCompose(c *Config, node common.Map, image string, cpuQuotaSupported bool) common.Map {
	compose := ComposeAgent(c, node, image)
	if !cpuQuotaSupported {
		delete(common.M(common.M(compose["services"])["agent"]), "cpus")
	}
	return compose
}
