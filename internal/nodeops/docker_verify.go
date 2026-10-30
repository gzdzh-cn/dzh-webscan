package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"webscan/internal/nodeconfig"
)

// Private, read-only evidence for the Docker lifecycle under construction. This
// proves what the local engine loaded, not kernel enforcement or collector
// readiness. It does not enable the production installation executor.
const dockerRuntimeFormat = `{"ID":{{json .Id}},"State":{{json .State}},"RestartCount":{{json .RestartCount}},"User":{{json .Config.User}},"Environment":{{json .Config.Env}},"Host":{{json .HostConfig}}}`

type dockerRuntimeState struct {
	ID    string
	State struct {
		Status                                       string
		Running, Paused, Restarting, OOMKilled, Dead bool
		Pid                                          int
		StartedAt                                    string
	}
	RestartCount int
	User         string
	Environment  []string
	Host         struct {
		NetworkMode, PidMode                  string
		ReadonlyRootfs, Privileged            bool
		Memory, NanoCpus, CpuQuota, CpuPeriod int64
		CpusetCpus                            string
		CapAdd, CapDrop, SecurityOpt          []string
		Ulimits                               []struct {
			Name       string
			Soft, Hard int64
		}
		RestartPolicy struct {
			Name              string
			MaximumRetryCount int
		}
	}
}

type dockerRuntimeEvidence struct {
	ID                                     string
	PID                                    int
	StartedAt                              time.Time
	MemoryBytes, NanoCPUs, FileDescriptors int64
}

func (h installationHost) dockerRuntime(ctx context.Context, id string) (dockerRuntimeState, error) {
	var state dockerRuntimeState
	if !validDigest(id) || ctx.Err() != nil {
		return state, errors.New("invalid-container-inspection")
	}
	raw, err := h.docker(ctx, "container", "inspect", id, "--format", dockerRuntimeFormat)
	if err != nil || len(raw) > 128<<10 || json.Unmarshal([]byte(raw), &state) != nil || state.ID != id {
		return state, errors.New("container-runtime-unavailable")
	}
	return state, nil
}

func dockerCapabilities(values []string, expected string) bool {
	return len(values) == 1 && strings.TrimPrefix(values[0], "CAP_") == expected
}

func (s dockerRuntimeState) verify(resources nodeconfig.Resources) (dockerRuntimeEvidence, error) {
	var proof dockerRuntimeEvidence
	// Reuse the same configuration bounds as the service generator.
	settings := nodeconfig.DefaultSettings()
	settings.Resources = resources
	if settings.Validate() != nil || !validDigest(s.ID) {
		return proof, errors.New("invalid-docker-resource-requirements")
	}
	started, err := time.Parse(time.RFC3339Nano, s.State.StartedAt)
	if err != nil || started.IsZero() || s.State.Pid < 1 || s.RestartCount < 0 || s.State.Status != "running" || !s.State.Running || s.State.Paused || s.State.Restarting || s.State.OOMKilled || s.State.Dead {
		return proof, errors.New("container-not-running-stably")
	}
	if err := s.verifyPolicy(resources, "unless-stopped"); err != nil {
		return proof, err
	}
	return dockerRuntimeEvidence{s.ID, s.State.Pid, started, int64(resources.MemoryMiB) << 20, int64(math.Round(resources.CPUs * 1e9)), int64(resources.FileDescriptors)}, nil
}

// Created/stopped containers need the same policy proof before their first
// start; policy validation never fabricates running-process evidence.
func (s dockerRuntimeState) verifyPolicy(resources nodeconfig.Resources, restart string) error {
	settings := nodeconfig.DefaultSettings()
	settings.Resources = resources
	if settings.Validate() != nil || !validDigest(s.ID) || (restart != "no" && restart != "unless-stopped") {
		return errors.New("invalid-docker-resource-requirements")
	}
	h := s.Host
	if s.User != "0:0" || h.NetworkMode != "host" || h.PidMode != "" || !h.ReadonlyRootfs || h.Privileged || !dockerCapabilities(h.CapDrop, "ALL") || !dockerCapabilities(h.CapAdd, "DAC_READ_SEARCH") || len(h.SecurityOpt) != 1 || (h.SecurityOpt[0] != "no-new-privileges:true" && h.SecurityOpt[0] != "no-new-privileges") || h.RestartPolicy.Name != restart || h.RestartPolicy.MaximumRetryCount != 0 {
		return errors.New("container-isolation-policy-not-effective")
	}
	memory, nano := int64(resources.MemoryMiB)<<20, int64(math.Round(resources.CPUs*1e9))
	if h.Memory != memory || h.NanoCpus != nano || h.CpuQuota != 0 || h.CpuPeriod != 0 || h.CpusetCpus != "" {
		return errors.New("container-resource-limits-not-effective")
	}
	fd := int64(resources.FileDescriptors)
	count := 0
	for _, limit := range h.Ulimits {
		if limit.Name == "nofile" {
			count++
			if limit.Soft != fd || limit.Hard != fd {
				return errors.New("container-descriptor-limit-not-effective")
			}
		}
	}
	if count != 1 {
		return errors.New("container-descriptor-limit-not-proven")
	}
	wanted := map[string]string{"GOMEMLIMIT": strconv.Itoa(resources.GoMemoryMiB) + "MiB", "GOMAXPROCS": strconv.Itoa(resources.GoMaxProcs)}
	for _, value := range s.Environment {
		key, value, _ := strings.Cut(value, "=")
		if key != "GOMEMLIMIT" && key != "GOMAXPROCS" {
			continue
		}
		if expected, ok := wanted[key]; !ok || value != expected {
			return errors.New("container-go-runtime-limits-not-effective")
		}
		delete(wanted, key)
	}
	if len(wanted) != 0 {
		return errors.New("container-go-runtime-limits-not-effective")
	}
	return nil
}

func (h installationHost) verifyRunningDocker(ctx context.Context, id string, active ActiveInstallation, resources nodeconfig.Resources) (dockerRuntimeEvidence, error) {
	var empty dockerRuntimeEvidence
	if active.Spec.Mode != "docker" || active.Spec.Validate() != nil || !active.Spec.configurationValid() {
		return empty, errors.New("invalid-docker-verification")
	}
	before, err := h.container(ctx, id)
	if err != nil {
		return empty, err
	}
	if before.Name != "/"+agentContainerName || before.Status != "running" || before.Restart != "unless-stopped" || before.MaxRetries != 0 {
		return empty, errors.New("target-container-not-active")
	}
	if err := h.verifyV3Container(before, active); err != nil {
		return empty, err
	}
	if err := h.dockerResourceDefinition(active, resources); err != nil {
		return empty, err
	}
	state, err := h.dockerRuntime(ctx, id)
	if err != nil {
		return empty, err
	}
	proof, err := state.verify(resources)
	if err != nil {
		return empty, err
	}
	// A successful inspect is not enough if the daemon restarted or replaced the
	// process while the other evidence was being read. Never query by name here.
	after, err := h.container(ctx, id)
	if err != nil {
		return empty, err
	}
	if before.fingerprint() != after.fingerprint() || before.Name != after.Name || before.Status != after.Status || before.Restart != after.Restart || before.MaxRetries != after.MaxRetries {
		return empty, errors.New("container-changed-during-verification")
	}
	last, err := h.dockerRuntime(ctx, id)
	if err != nil || !reflect.DeepEqual(state, last) {
		return empty, errors.New("container-changed-during-verification")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return proof, nil
}

// Bind the requested resource values to the already hashed service definition.
// A caller cannot weaken both its expected values and the live engine settings
// and thereby certify a configuration that the staged material never allowed.
func (h installationHost) dockerResourceDefinition(active ActiveInstallation, resources nodeconfig.Resources) error {
	raw, err := readPrivate(filepath.Join(h.root, "configurations", active.Spec.RuntimeSHA256, "compose.json"), 2<<20)
	if err != nil || sha(raw) != active.DefinitionSHA256 {
		return errors.New("v3-compose-changed")
	}
	var doc struct {
		Services map[string]struct {
			Memory      int64                                 `json:"mem_limit"`
			CPUs        float64                               `json:"cpus"`
			Environment map[string]string                     `json:"environment"`
			Ulimits     map[string]struct{ Soft, Hard int64 } `json:"ulimits"`
		} `json:"services"`
	}
	if json.Unmarshal(raw, &doc) != nil || len(doc.Services) != 1 {
		return errors.New("v3-compose-changed")
	}
	s, ok := doc.Services["agent"]
	fd, okFD := s.Ulimits["nofile"]
	if !ok || !okFD || s.Memory != int64(resources.MemoryMiB)<<20 || s.CPUs != resources.CPUs || fd.Soft != int64(resources.FileDescriptors) || fd.Hard != int64(resources.FileDescriptors) || s.Environment["GOMEMLIMIT"] != strconv.Itoa(resources.GoMemoryMiB)+"MiB" || s.Environment["GOMAXPROCS"] != strconv.Itoa(resources.GoMaxProcs) {
		return errors.New("docker-resource-requirements-not-bound")
	}
	return nil
}

type dockerLocalEvidence struct {
	Runtime dockerRuntimeEvidence
	Kernel  nativeResourceEvidence
}

// Only the node-local helper can read the host PID/cgroup. Running this reader
// in an unrelated container's PID namespace is not evidence about the Agent.
func (fs nativeResources) inspectDocker(ctx context.Context, host installationHost, id string, active ActiveInstallation, resources nodeconfig.Resources) (dockerLocalEvidence, error) {
	var out dockerLocalEvidence
	running, err := host.verifyRunningDocker(ctx, id, active, resources)
	if err != nil {
		return out, err
	}
	program := filepath.Join(host.root, "releases", active.Spec.BundleSHA256, "webscan")
	configuration := filepath.Join(host.root, "configurations", active.Spec.RuntimeSHA256, "runtime.json")
	prove := func() error {
		return host.proveRunningNativeProcess(nativeStatus{MainPID: running.PID}, program, configuration)
	}
	if err := prove(); err != nil {
		return out, err
	}
	dir := filepath.Join(fs.proc, strconv.Itoa(running.PID))
	stat, err := readKernelFile(filepath.Join(dir, "stat"))
	if err != nil {
		return out, err
	}
	started, err := processStart(stat, running.PID)
	if err != nil {
		return out, err
	}
	membership, err := readKernelFile(filepath.Join(dir, "cgroup"))
	if err != nil {
		return out, err
	}
	groups, err := cgroupMembership(membership)
	if err != nil {
		return out, err
	}
	group := groups[""]
	if v1, ok := groups["cpu"]; ok {
		group = v1
	}
	// Both cgroupfs and systemd Docker drivers bind the complete container ID.
	// A namespace root, short ID or shared parent cannot certify containment.
	if !safeServicePath(group) || (filepath.Base(group) != id && filepath.Base(group) != "docker-"+id+".scope") {
		return out, errors.New("docker-process-cgroup-not-owned")
	}
	kernel, err := fs.inspectKernel(ctx, running.PID, group, started, resources, prove)
	if err != nil {
		return out, err
	}
	last, err := host.verifyRunningDocker(ctx, id, active, resources)
	if err != nil || !reflect.DeepEqual(running, last) {
		return out, errors.New("container-changed-during-kernel-verification")
	}
	out.Runtime, out.Kernel = running, kernel
	return out, nil
}
