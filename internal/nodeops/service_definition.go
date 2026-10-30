package nodeops

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"webscan/internal/common"
	"webscan/internal/nodeconfig"
)

const nativeServiceName = "webscan-agent-native.service"
const agentContainerName = "webscan-agent-go"
const agentDataDirectory = "/var/lib/webscan-v1"
const agentLogDirectory = "/var/log/webscan-v1"

// serviceDefinition is generated from verified material, never a submitted
// shell command. Stage only stores it; activation must separately prove old
// service ownership, quiesce writers, back up and verify effective limits.
func (w *LocalRuntime) serviceDefinition(m nodeconfig.Material, s Spec) (string, []byte, error) {
	if m.Settings.Validate() != nil || m.Mode != s.Mode || !s.configurationValid() {
		return "", nil, errors.New("invalid-service-configuration")
	}
	directory, release := w.configurationDir(s), w.releaseDir(s)
	if !safeServicePath(directory) || !safeServicePath(release) {
		return "", nil, errors.New("invalid-service-path")
	}
	if s.Mode == "native" {
		return nativeServiceName, nativeDefinition(m, directory, release), nil
	}
	raw, err := dockerDefinition(m, s, directory, release)
	if err != nil || !s.imageArchiveValid() {
		return "compose.json", raw, err
	}
	ref, err := dockerLaunchReference(w.root, s)
	if err != nil {
		return "", nil, err
	}
	var definition map[string]any
	if err = json.Unmarshal(raw, &definition); err != nil {
		return "", nil, err
	}
	definition["services"].(map[string]any)["agent"].(map[string]any)["image"] = ref
	raw, err = json.Marshal(definition)
	return "compose.json", raw, err
}

func safeServicePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

// ExecStart has both specifier and environment expansion; filesystem directive
// arguments have only specifier expansion. Shell escaping cannot substitute for
// either, and no shell is used to start the Agent.
func unitPath(path string, exec bool) string {
	path = strings.ReplaceAll(path, "%", "%%")
	if exec {
		path = strings.ReplaceAll(path, "$", "$$")
	}
	return strconv.Quote(path)
}

func nativeDefinition(m nodeconfig.Material, directory, release string) []byte {
	r := m.Settings.Resources
	writable := []string{unitPath(agentDataDirectory, false), unitPath(agentLogDirectory, false), unitPath(m.Settings.ProbeDirectory, false)}
	if m.Settings.Scan.ClamAV.Enabled {
		writable = append(writable, unitPath("/run/clamav", false))
	}
	return []byte(fmt.Sprintf(`[Unit]
Description=Webscan v3 unified Agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
Group=root
UMask=0077
ExecStart=%s agent --config %s
Restart=on-failure
RestartSec=5
TimeoutStopSec=60
KillMode=control-group
MemoryAccounting=yes
CPUAccounting=yes
MemoryMax=%dM
CPUQuota=%s%%
LimitNOFILE=%d
Environment=GOMEMLIMIT=%dMiB
Environment=GOMAXPROCS=%d
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`, unitPath(filepath.Join(release, "webscan"), true), unitPath(filepath.Join(directory, "runtime.json"), true), r.MemoryMiB, strconv.FormatFloat(r.CPUs*100, 'f', -1, 64), r.FileDescriptors, r.GoMemoryMiB, r.GoMaxProcs, strings.Join(writable, " ")))
}

type bindOptions struct {
	CreateHostPath bool   `json:"create_host_path"`
	Propagation    string `json:"propagation,omitempty"`
}
type serviceMount struct {
	Type     string      `json:"type"`
	Source   string      `json:"source"`
	Target   string      `json:"target"`
	ReadOnly bool        `json:"read_only"`
	Bind     bindOptions `json:"bind"`
}

func dockerDefinition(m nodeconfig.Material, s Spec, directory, release string) ([]byte, error) {
	if !ValidAgentImage(s.AgentImage) {
		return nil, errors.New("service-image-not-pinned")
	}
	image := s.AgentImage
	if s.imageArchiveValid() {
		// Docker load may not retain RepoDigests. Stage verifies the signed
		// archive/config proof; launch this exact local ID with pulling disabled.
		image = "sha256:" + s.ImageConfigSHA256
	}
	var mounts []serviceMount
	add := func(source, target string, readOnly, recursive bool) {
		bind := bindOptions{CreateHostPath: false}
		if recursive {
			bind.Propagation = "rslave"
		}
		// Compose interpolation runs even for JSON and long bind syntax.
		mounts = append(mounts, serviceMount{"bind", composeLiteral(source), composeLiteral(target), readOnly, bind})
	}
	add("/proc", "/host/proc", true, false)
	add("/sys", "/host/sys", true, false)
	add("/", "/rootfs", true, true)
	add(directory, directory, true, false)
	add(release, release, true, false)
	add(agentDataDirectory, agentDataDirectory, false, false)
	add(agentLogDirectory, agentLogDirectory, false, false)
	protected := []string{"/proc", "/sys", "/dev", "/host", "/rootfs", "/tmp", directory, release, agentDataDirectory, agentLogDirectory}
	if m.Settings.Scan.ClamAV.Enabled {
		protected = append(protected, "/run/clamav")
	}
	monitorMounts, err := dockerMonitorMounts(m.Settings.Monitor, protected)
	if err != nil {
		return nil, err
	}
	for _, root := range monitorMounts {
		add(root, root, true, true)
	}
	// A read-write child mount only permits the controlled probe, never the
	// complete website directory. It must already exist before activation.
	for _, root := range protected {
		if common.Inside(m.Settings.ProbeDirectory, root) || common.Inside(root, m.Settings.ProbeDirectory) {
			return nil, errors.New("probe-mount-conflicts-with-service")
		}
	}
	add(m.Settings.ProbeDirectory, m.Settings.ProbeDirectory, false, false)
	if m.Settings.Scan.ClamAV.Enabled {
		add("/run/clamav", "/run/clamav", false, false)
	}
	r := m.Settings.Resources
	service := map[string]any{
		"image": image, "platform": "linux/amd64", "pull_policy": "never", "container_name": agentContainerName,
		"entrypoint": []string{composeLiteral(filepath.Join(release, "webscan"))}, "command": []string{"agent", "--config", composeLiteral(filepath.Join(directory, "runtime.json"))},
		"user": "0:0", "network_mode": "host", "restart": "unless-stopped", "stop_grace_period": "60s",
		"read_only": true, "cap_drop": []string{"ALL"}, "cap_add": []string{"DAC_READ_SEARCH"}, "security_opt": []string{"no-new-privileges:true"},
		"mem_limit": int64(r.MemoryMiB) << 20, "cpus": r.CPUs,
		"ulimits":     map[string]any{"nofile": map[string]int{"soft": r.FileDescriptors, "hard": r.FileDescriptors}},
		"environment": map[string]string{"GOMEMLIMIT": strconv.Itoa(r.GoMemoryMiB) + "MiB", "GOMAXPROCS": strconv.Itoa(r.GoMaxProcs)},
		"tmpfs":       []string{"/tmp:rw,noexec,nosuid,size=16777216,mode=1777"}, "volumes": mounts,
		"logging": map[string]any{"driver": "json-file", "options": map[string]string{"max-size": "10m", "max-file": "3"}},
		"labels":  map[string]string{"io.webscan.managed": "v3", "io.webscan.node": m.Node, "io.webscan.configuration": s.RuntimeSHA256, "io.webscan.source": m.SourceSHA256, "io.webscan.release": m.Release},
	}
	return json.Marshal(map[string]any{"name": "webscan-v3-agent", "services": map[string]any{"agent": service}})
}

func composeLiteral(s string) string { return strings.ReplaceAll(s, "$", "$$") }

func dockerMonitorMounts(m nodeconfig.Monitor, protected []string) ([]string, error) {
	paths := append([]string{}, m.Roots...)
	for _, critical := range m.CriticalPaths {
		paths = append(paths, filepath.Dir(critical))
	}
	if len(paths) > 128 {
		return nil, errors.New("too-many-monitor-mounts")
	}
	sort.Slice(paths, func(i, j int) bool {
		if len(paths[i]) != len(paths[j]) {
			return len(paths[i]) < len(paths[j])
		}
		return paths[i] < paths[j]
	})
	var mounts []string
	for _, path := range paths {
		if !safeServicePath(path) || path == "/" {
			return nil, errors.New("monitor-mount-conflicts-with-service")
		}
		for _, reserved := range protected {
			if common.Inside(path, reserved) || common.Inside(reserved, path) {
				return nil, errors.New("monitor-mount-conflicts-with-service")
			}
		}
		covered := false
		for _, existing := range mounts {
			covered = covered || common.Inside(path, existing)
		}
		if !covered {
			mounts = append(mounts, path)
		}
	}
	return mounts, nil
}
