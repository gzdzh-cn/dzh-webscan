package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"webscan/internal/nodeconfig"
)

func dockerStateFixture(t *testing.T, r nodeconfig.Resources) dockerRuntimeState {
	t.Helper()
	raw := `{"ID":"` + strings.Repeat("1", 64) + `","State":{"Status":"running","Running":true,"Pid":123,"StartedAt":"2026-10-18T00:00:00.123456789Z"},"User":"0:0","Environment":[],"Host":{"NetworkMode":"host","ReadonlyRootfs":true,"CapDrop":["ALL"],"CapAdd":["CAP_DAC_READ_SEARCH"],"SecurityOpt":["no-new-privileges:true"],"RestartPolicy":{"Name":"unless-stopped"}}}`
	var s dockerRuntimeState
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatal(err)
	}
	s.Host.Memory = int64(r.MemoryMiB) << 20
	s.Host.NanoCpus = int64(r.CPUs * 1e9)
	s.Host.Ulimits = append(s.Host.Ulimits, struct {
		Name       string
		Soft, Hard int64
	}{"nofile", int64(r.FileDescriptors), int64(r.FileDescriptors)})
	s.Environment = []string{"GOMEMLIMIT=" + strconv.Itoa(r.GoMemoryMiB) + "MiB", "GOMAXPROCS=" + strconv.Itoa(r.GoMaxProcs), "UNRELATED=not-returned"}
	return s
}

func TestDockerRuntimeRejectsUnprovedLoadedState(t *testing.T) {
	r := nodeconfig.DefaultSettings().Resources
	r.CPUs = 1.25
	mutations := map[string]func(*dockerRuntimeState){
		"memory":               func(s *dockerRuntimeState) { s.Host.Memory = 0 },
		"cpu":                  func(s *dockerRuntimeState) { s.Host.NanoCpus = 0 },
		"alternate-cpu-quota":  func(s *dockerRuntimeState) { s.Host.CpuQuota = 125000 },
		"alternate-cpu-period": func(s *dockerRuntimeState) { s.Host.CpuPeriod = 100000 },
		"cpuset":               func(s *dockerRuntimeState) { s.Host.CpusetCpus = "0" },
		"missing-fd":           func(s *dockerRuntimeState) { s.Host.Ulimits = nil },
		"duplicate-fd":         func(s *dockerRuntimeState) { s.Host.Ulimits = append(s.Host.Ulimits, s.Host.Ulimits[0]) },
		"soft-fd":              func(s *dockerRuntimeState) { s.Host.Ulimits[0].Soft-- },
		"hard-fd":              func(s *dockerRuntimeState) { s.Host.Ulimits[0].Hard-- },
		"missing-go-env":       func(s *dockerRuntimeState) { s.Environment = s.Environment[1:] },
		"wrong-go-env":         func(s *dockerRuntimeState) { s.Environment[0] = "GOMEMLIMIT=1GiB" },
		"duplicate-go-env":     func(s *dockerRuntimeState) { s.Environment = append(s.Environment, s.Environment[0]) },
		"user":                 func(s *dockerRuntimeState) { s.User = "root" },
		"network":              func(s *dockerRuntimeState) { s.Host.NetworkMode = "bridge" },
		"pid-namespace":        func(s *dockerRuntimeState) { s.Host.PidMode = "host" },
		"writable-root":        func(s *dockerRuntimeState) { s.Host.ReadonlyRootfs = false },
		"privileged":           func(s *dockerRuntimeState) { s.Host.Privileged = true },
		"capabilities":         func(s *dockerRuntimeState) { s.Host.CapAdd = append(s.Host.CapAdd, "SYS_ADMIN") },
		"capabilities-drop":    func(s *dockerRuntimeState) { s.Host.CapDrop = nil },
		"security":             func(s *dockerRuntimeState) { s.Host.SecurityOpt = nil },
		"restart-policy":       func(s *dockerRuntimeState) { s.Host.RestartPolicy.Name = "always" },
		"retry-count":          func(s *dockerRuntimeState) { s.Host.RestartPolicy.MaximumRetryCount = 3 },
		"not-running":          func(s *dockerRuntimeState) { s.State.Running = false },
		"stopped":              func(s *dockerRuntimeState) { s.State.Status = "exited" },
		"paused":               func(s *dockerRuntimeState) { s.State.Paused = true },
		"restarting":           func(s *dockerRuntimeState) { s.State.Restarting = true },
		"oom":                  func(s *dockerRuntimeState) { s.State.OOMKilled = true },
		"dead":                 func(s *dockerRuntimeState) { s.State.Dead = true },
		"no-process":           func(s *dockerRuntimeState) { s.State.Pid = 0 },
		"no-start":             func(s *dockerRuntimeState) { s.State.StartedAt = "0001-01-01T00:00:00Z" },
		"invalid-id":           func(s *dockerRuntimeState) { s.ID = "mutable-name" },
	}
	s := dockerStateFixture(t, r)
	proof, err := s.verify(r)
	if err != nil || proof.PID != 123 || proof.NanoCPUs != 1250000000 || proof.MemoryBytes != 256<<20 || proof.FileDescriptors != 65536 {
		t.Fatal(proof, err)
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := dockerStateFixture(t, r)
			mutate(&s)
			if _, err := s.verify(r); err == nil {
				t.Fatal("unproved runtime accepted")
			}
		})
	}
}

func dockerVerificationFixture(t *testing.T) (installationHost, ActiveInstallation, nodeconfig.Resources, *containerIdentity, *dockerRuntimeState) {
	t.Helper()
	w, r, m := serviceFixture(t, "docker")
	_, definition, err := w.serviceDefinition(m, r.Spec)
	if err != nil {
		t.Fatal(err)
	}
	dir := w.configurationDir(r.Spec)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.json"), definition, 0600); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Volumes []serviceMount `json:"volumes"`
		} `json:"services"`
	}
	if err := json.Unmarshal(definition, &doc); err != nil {
		t.Fatal(err)
	}
	c := &containerIdentity{ID: strings.Repeat("1", 64), Name: "/" + agentContainerName, Image: r.Spec.AgentImage, ImageID: "sha256:" + strings.Repeat("2", 64), Project: "webscan-v3-agent", Service: "agent", Managed: "v3", Node: r.Node, Configuration: r.Spec.RuntimeSHA256, Entrypoint: []string{filepath.Join(w.releaseDir(r.Spec), "webscan")}, Command: []string{"agent", "--config", filepath.Join(dir, "runtime.json")}, Status: "running", Restart: "unless-stopped"}
	for _, v := range doc.Services["agent"].Volumes {
		c.Mounts = append(c.Mounts, struct {
			Type                string
			Source, Destination string
			RW                  bool
		}{"bind", strings.ReplaceAll(v.Source, "$$", "$"), strings.ReplaceAll(v.Target, "$$", "$"), !v.ReadOnly})
	}
	s := dockerStateFixture(t, m.Settings.Resources)
	h := installationHost{root: w.root, command: func(_ context.Context, program string, args ...string) (string, error) {
		if program != "docker" || len(args) != 7 || args[0] != "--host" || args[1] != "unix:///var/run/docker.sock" || args[2] != "container" || args[3] != "inspect" || args[4] != c.ID || args[5] != "--format" {
			return "", errors.New("unexpected or mutating command")
		}
		var value any
		switch args[6] {
		case inventoryContainerFormat:
			value = c
		case dockerRuntimeFormat:
			value = s
		default:
			return "", errors.New("unexpected inspection")
		}
		raw, err := json.Marshal(value)
		return string(raw), err
	}}
	return h, ActiveInstallation{Node: r.Node, Spec: r.Spec, DefinitionSHA256: sha(definition)}, m.Settings.Resources, c, &s
}

func TestDockerVerificationBindsImmutableContainerAndStableProcess(t *testing.T) {
	for _, kind := range []string{"valid", "changed-pid", "changed-start", "changed-restarts", "changed-memory", "changed-mount", "changed-name", "engine-error", "invalid-json", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			h, a, r, c, s := dockerVerificationFixture(t)
			original := h.command
			calls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.command = func(ctx context.Context, p string, args ...string) (string, error) {
				calls++
				if calls == 3 {
					switch kind {
					case "changed-pid":
						s.State.Pid++
					case "changed-start":
						s.State.StartedAt = "2026-10-18T00:00:01Z"
					case "changed-restarts":
						s.RestartCount++
					case "changed-memory":
						s.Host.Memory++
					case "changed-mount":
						c.Mounts[0].RW = true
					case "changed-name":
						c.Name = "/replaced"
					case "engine-error":
						return "", errors.New("unavailable")
					case "invalid-json":
						return "not-json", nil
					case "cancelled":
						cancel()
					}
				}
				return original(ctx, p, args...)
			}
			proof, err := h.verifyRunningDocker(ctx, c.ID, a, r)
			if kind == "valid" {
				if err != nil || proof.ID != c.ID || proof.PID != 123 || calls != 4 {
					t.Fatal(proof, err, calls)
				}
			} else if err == nil {
				t.Fatal("changed process or inspection failure accepted")
			}
		})
	}
}

func TestDockerVerificationCannotWeakenExpectedResources(t *testing.T) {
	h, a, r, c, s := dockerVerificationFixture(t)
	r.MemoryMiB = 256
	r.GoMemoryMiB = 64
	*s = dockerStateFixture(t, r)
	if _, err := h.verifyRunningDocker(context.Background(), c.ID, a, r); err == nil {
		t.Fatal("runtime and expected values bypassed staged configuration")
	}
}

func TestDockerLoadedRuntimeOnDisposableContainer(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_DOCKER_RUNTIME") != "1" {
		t.Skip("requires explicitly opted-in disposable local container")
	}
	image := os.Getenv("WEBSCAN_V3_AGENT_TEST_IMAGE")
	if image == "" {
		image = "gzdzh/webscan-agent:v2.0.46"
	}
	name := "webscan-v3-runtime-" + sha([]byte(t.TempDir()))[:16]
	r := nodeconfig.DefaultSettings().Resources
	r.CPUs = 1.25
	// No Agent, business data, host bind mount, socket, exposed port or listener.
	// Host networking is necessary only to check the intended engine setting.
	args := []string{"run", "-d", "--name", name, "--platform", "linux/amd64", "--pull", "never", "--network", "host", "--user", "0:0", "--read-only", "--cap-drop", "ALL", "--cap-add", "DAC_READ_SEARCH", "--security-opt", "no-new-privileges:true", "--restart", "unless-stopped", "--memory", "256m", "--cpus", "1.25", "--ulimit", "nofile=65536:65536", "-e", "GOMEMLIMIT=" + strconv.Itoa(r.GoMemoryMiB) + "MiB", "-e", "GOMAXPROCS=" + strconv.Itoa(r.GoMaxProcs), "--entrypoint", "/bin/sleep", image, "90"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t.Cleanup(func() {
		out, err := exec.Command("docker", "rm", "-fv", name).CombinedOutput()
		if err != nil {
			t.Errorf("cleanup: %v %s", err, out)
		}
	})
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("isolated runtime start: %v %s", err, out)
	}
	id := strings.TrimSpace(string(out))
	if !validDigest(id) {
		t.Fatal("unexpected container ID")
	}
	// Use the desktop engine selected for tests, not the node-only fixed socket.
	raw, err := exec.CommandContext(ctx, "docker", "inspect", id, "--format", dockerRuntimeFormat).Output()
	if err != nil {
		t.Fatal(err)
	}
	var state dockerRuntimeState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	proof, err := state.verify(r)
	if err != nil || proof.ID != id || proof.PID < 1 {
		t.Fatal(proof, err)
	}
	// Docker update really changes the loaded requirement; the verifier must
	// reject it even though the process and image still look healthy.
	if out, err := exec.CommandContext(ctx, "docker", "update", "--memory", "384m", id).CombinedOutput(); err != nil {
		t.Fatalf("isolated limit update: %v %s", err, out)
	}
	raw, err = exec.CommandContext(ctx, "docker", "inspect", id, "--format", dockerRuntimeFormat).Output()
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &state) != nil {
		t.Fatal("invalid runtime response")
	}
	if _, err := state.verify(r); err == nil {
		t.Fatal("real engine resource drift accepted")
	}
}
