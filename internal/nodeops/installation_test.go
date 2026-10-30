package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type installationMachine struct {
	host                         installationHost
	containers                   map[string]containerIdentity
	calls                        []string
	nativeRunning, nativeEnabled bool
	nativeUnit                   []byte
	inspectError                 string
}

func installationFixture(t *testing.T, mode string) *installationMachine {
	t.Helper()
	root := testRoot(t)
	cfg := filepath.Join(root, "etc")
	if err := os.Mkdir(cfg, 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"node_id": "node-one", "deployment_mode": mode, "data_dir": agentDataDirectory, "log_dir": agentLogDirectory, "probe_directory": "/srv/site/.webscan-probe"})
	if err := os.WriteFile(filepath.Join(cfg, "runtime.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	m := &installationMachine{containers: map[string]containerIdentity{}, nativeRunning: true, nativeEnabled: true}
	m.host = installationHost{root: root, configRoot: cfg, unitPath: filepath.Join(root, nativeServiceName), processExecutable: func(int) (string, error) { return "/opt/webscan-go/releases/v2.0.46/webscan", nil }}
	m.host.processArguments = func(int) ([]string, error) {
		return []string{"/opt/webscan-go/releases/v2.0.46/webscan", "agent", "--config", filepath.Join(m.host.configRoot, "runtime.json")}, nil
	}
	m.host.command = m.command
	return m
}
func (m *installationMachine) status() string {
	active, sub, pid, enabled := "inactive", "dead", 0, "disabled"
	if m.nativeRunning {
		active, sub, pid = "active", "running", 123
	}
	if m.nativeEnabled {
		enabled = "enabled"
	}
	return fmt.Sprintf("LoadState=loaded\nActiveState=%s\nSubState=%s\nFragmentPath=%s\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=%s\nJob=0\nMainPID=%d\n", active, sub, m.host.unitPath, enabled, pid)
}
func (m *installationMachine) command(_ context.Context, program string, args ...string) (string, error) {
	m.calls = append(m.calls, program+" "+strings.Join(args, " "))
	if program == "systemctl" {
		switch args[0] {
		case "show":
			return m.status(), nil
		case "disable":
			m.nativeEnabled = false
			if len(args) > 1 && args[1] == "--now" {
				m.nativeRunning = false
			}
			return "", nil
		case "enable":
			m.nativeEnabled = true
			return "", nil
		case "start":
			m.nativeRunning = true
			return "", nil
		}
	}
	if program != "docker" || len(args) < 3 || args[0] != "--host" || args[1] != "unix:///var/run/docker.sock" {
		return "", errors.New("unexpected command")
	}
	args = args[2:]
	switch args[0] {
	case "info":
		return "27.0.0", nil
	case "ps":
		for _, c := range m.containers {
			if args[4] == "name=^/"+strings.TrimPrefix(c.Name, "/")+"$" {
				return c.ID + "\n", nil
			}
		}
		return "", nil
	case "container":
		if args[2] == m.inspectError {
			return "", errors.New("daemon unavailable")
		}
		c, ok := m.containers[args[2]]
		if !ok {
			return "", errors.New("no such container")
		}
		raw, _ := json.Marshal(c)
		return string(raw), nil
	case "update":
		id := args[2]
		c, ok := m.containers[id]
		if !ok {
			return "", errors.New("no such ID")
		}
		policy := strings.TrimPrefix(args[1], "--restart=")
		c.Restart = policy
		c.MaxRetries = 0
		if policy == "on-failure:3" {
			c.Restart = "on-failure"
			c.MaxRetries = 3
		}
		m.containers[id] = c
		return "", nil
	case "stop", "start":
		id := args[len(args)-1]
		c, ok := m.containers[id]
		if !ok {
			return "", errors.New("no such ID")
		}
		c.Status = "exited"
		if args[0] == "start" {
			c.Status = "running"
		}
		m.containers[id] = c
		return "", nil
	}
	return "", errors.New("unexpected operation")
}
func (m *installationMachine) addDocker(t *testing.T) containerIdentity {
	t.Helper()
	compose := "name: webscan-node\nservices:\n  agent:\n    image: gzdzh/webscan-agent:v2.0.46\n    container_name: webscan-agent-go\n  vector:\n    image: timberio/vector:0.45.0-alpine\n    container_name: webscan-vector-v1\n"
	if err := os.WriteFile(filepath.Join(m.host.configRoot, "compose.yml"), []byte(compose), 0600); err != nil {
		t.Fatal(err)
	}
	c := containerIdentity{ID: strings.Repeat("1", 64), Name: "/" + agentContainerName, Image: "gzdzh/webscan-agent:v2.0.46", ImageID: "sha256:" + strings.Repeat("2", 64), Project: "webscan-node", Service: "agent", Entrypoint: []string{"/usr/local/bin/webscan"}, Command: []string{"agent", "--config", filepath.Join(m.host.configRoot, "runtime.json")}, Status: "running", Restart: "unless-stopped"}
	for _, p := range []string{m.host.configRoot, agentDataDirectory, agentLogDirectory} {
		c.Mounts = append(c.Mounts, struct {
			Type                string
			Source, Destination string
			RW                  bool
		}{"bind", p, p, p != m.host.configRoot})
	}
	m.containers[c.ID] = c
	return c
}
func (m *installationMachine) addNative(t *testing.T) {
	t.Helper()
	m.nativeUnit = []byte("[Unit]\nDescription=Webscan unified agent\nWants=network-online.target\nAfter=network-online.target\n[Service]\nType=simple\nUser=root\nUMask=0077\nExecStart=/opt/webscan-go/releases/v2.0.46/webscan agent --config /etc/webscan-v1/runtime.json\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=60\nMemoryMax=256M\nCPUQuota=50%\nEnvironment=GOMEMLIMIT=192MiB\nEnvironment=GOMAXPROCS=1\nLimitNOFILE=65536\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=/var/lib/webscan-v1 /var/log/webscan-v1 \"/srv/site/.webscan-probe\" -/run/clamav\n[Install]\nWantedBy=multi-user.target\n")
	if err := os.WriteFile(m.host.unitPath, m.nativeUnit, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestInstallationNativeOwnershipAndRestore(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, running := range []bool{false, true} {
			t.Run(fmt.Sprint(enabled, running), func(t *testing.T) {
				m := installationFixture(t, "native")
				m.addNative(t)
				m.nativeEnabled, m.nativeRunning = enabled, running
				i, err := m.host.inventory(context.Background(), "node-one", "native")
				if err != nil {
					t.Fatal(err)
				}
				if err = m.host.stop(context.Background(), i); err != nil {
					t.Fatal(err)
				}
				if m.nativeRunning || m.nativeEnabled {
					t.Fatal("old writer not disabled")
				}
				if err = m.host.restoreServices(context.Background(), i); err != nil {
					t.Fatal(err)
				}
				if m.nativeEnabled != enabled || m.nativeRunning != running {
					t.Fatal("original state not restored")
				}
				for _, c := range m.calls {
					if strings.HasPrefix(c, "docker ") {
						t.Fatal("native called Docker", c)
					}
				}
			})
		}
	}
}
func TestInstallationRejectsUnprovenNativeBeforeMutation(t *testing.T) {
	for _, kind := range []string{"hook", "dropin", "reload", "executable", "arguments", "symlink-parent", "wrong-node", "duplicate-property", "missing-property"} {
		t.Run(kind, func(t *testing.T) {
			m := installationFixture(t, "native")
			m.addNative(t)
			base := m.host.command
			switch kind {
			case "hook":
				os.WriteFile(m.host.unitPath, append(m.nativeUnit, []byte("ExecStop=/bin/false\n")...), 0600)
			case "executable":
				m.host.processExecutable = func(int) (string, error) { return "/usr/bin/foreign", nil }
			case "arguments":
				m.host.processArguments = func(int) ([]string, error) {
					return []string{"/opt/webscan-go/releases/v2.0.46/webscan", "agent", "--config", "/etc/unrelated.json"}, nil
				}
			case "wrong-node":
				raw, _ := os.ReadFile(filepath.Join(m.host.configRoot, "runtime.json"))
				os.WriteFile(filepath.Join(m.host.configRoot, "runtime.json"), []byte(strings.ReplaceAll(string(raw), "node-one", "another")), 0600)
			case "symlink-parent":
				link := filepath.Join(m.host.root, "alias")
				if err := os.Symlink(m.host.configRoot, link); err != nil {
					t.Fatal(err)
				}
				m.host.configRoot = link
			default:
				m.host.command = func(ctx context.Context, p string, a ...string) (string, error) {
					raw, err := base(ctx, p, a...)
					if p == "systemctl" && a[0] == "show" {
						switch kind {
						case "dropin":
							raw = strings.Replace(raw, "DropInPaths=", "DropInPaths=/etc/override.conf", 1)
						case "reload":
							raw = strings.Replace(raw, "NeedDaemonReload=no", "NeedDaemonReload=yes", 1)
						case "duplicate-property":
							raw += "DropInPaths=\n"
						case "missing-property":
							raw = strings.Replace(raw, "DropInPaths=\n", "", 1)
						}
					}
					return raw, err
				}
			}
			if _, err := m.host.inventory(context.Background(), "node-one", "native"); err == nil {
				t.Fatal("unproven service accepted")
			}
			for _, c := range m.calls {
				if strings.Contains(c, "disable") || strings.Contains(c, " stop ") {
					t.Fatal("mutation before proof")
				}
			}
		})
	}
}
func TestInstallationDockerStopAndRestoreByImmutableID(t *testing.T) {
	m := installationFixture(t, "docker")
	c := m.addDocker(t)
	c.Restart = "on-failure"
	c.MaxRetries = 3
	m.containers[c.ID] = c
	i, err := m.host.inventory(context.Background(), "node-one", "native")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.host.stop(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	if m.containers[c.ID].Status != "exited" || m.containers[c.ID].Restart != "no" {
		t.Fatal("writer still active")
	}
	if err = m.host.restoreServices(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.containers[c.ID], c) {
		t.Fatal("restart policy or original state lost")
	}
	for _, call := range m.calls {
		if strings.Contains(call, " stop ") || strings.Contains(call, " update ") || strings.Contains(call, " start ") {
			if !strings.HasSuffix(call, c.ID) {
				t.Fatal("mutable name used", call)
			}
		}
	}
}
func TestInstallationDockerRejectsForeignIdentity(t *testing.T) {
	for _, kind := range []string{"project", "image", "command", "mount", "daemon", "replaced-id"} {
		t.Run(kind, func(t *testing.T) {
			m := installationFixture(t, "docker")
			c := m.addDocker(t)
			switch kind {
			case "project":
				c.Project = "foreign"
			case "image":
				c.Image = "foreign:latest"
			case "command":
				c.Command = []string{"sleep", "100"}
			case "mount":
				c.Mounts[1].Source = "/foreign"
			case "daemon":
				m.inspectError = c.ID
			case "replaced-id":
				c.ID = strings.Repeat("f", 64)
			}
			m.containers[strings.Repeat("1", 64)] = c
			if _, err := m.host.inventory(context.Background(), "node-one", "docker"); err == nil {
				t.Fatal("foreign service accepted")
			}
		})
	}
}
func TestInstallationProvesAllServicesBeforeStoppingAny(t *testing.T) {
	m := installationFixture(t, "docker")
	c := m.addDocker(t)
	i, err := m.host.inventory(context.Background(), "node-one", "docker")
	if err != nil {
		t.Fatal(err)
	}
	side := ServiceRecord{Kind: "docker", Name: "webscan-vector-v1", ID: strings.Repeat("3", 64), Proof: strings.Repeat("4", 64), Enabled: true, Restart: "always"}
	i.Services = append(i.Services, side)
	m.calls = nil
	if err := m.host.stop(context.Background(), i); err == nil {
		t.Fatal("missing sidecar accepted")
	}
	if !reflect.DeepEqual(c, m.containers[c.ID]) {
		t.Fatal("agent stopped before sidecar checked")
	}
	for _, call := range m.calls {
		if strings.Contains(call, " update ") || strings.Contains(call, " stop ") {
			t.Fatal("partial mutation", call)
		}
	}
}
func TestFreshNativeInventoryNeverUsesDocker(t *testing.T) {
	m := installationFixture(t, "native")
	if err := os.Remove(filepath.Join(m.host.configRoot, "runtime.json")); err != nil {
		t.Fatal(err)
	}
	i, err := m.host.inventory(context.Background(), "node-one", "native")
	if err != nil || i.Generation != "absent" || len(m.calls) != 0 {
		t.Fatal(i, err, m.calls)
	}
}

func TestV3ContainerRequiresExactGeneratedMountSet(t *testing.T) {
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
	c := containerIdentity{ID: strings.Repeat("1", 64), Name: "/" + agentContainerName, Managed: "v3", Node: r.Node, Configuration: r.Spec.RuntimeSHA256, Project: "webscan-v3-agent", Service: "agent", Image: r.Spec.AgentImage, ImageID: "sha256:" + strings.Repeat("2", 64), Entrypoint: []string{filepath.Join(w.releaseDir(r.Spec), "webscan")}, Command: []string{"agent", "--config", filepath.Join(dir, "runtime.json")}, Status: "running", Restart: "unless-stopped"}
	for _, v := range doc.Services["agent"].Volumes {
		c.Mounts = append(c.Mounts, struct {
			Type                string
			Source, Destination string
			RW                  bool
		}{"bind", strings.ReplaceAll(v.Source, "$$", "$"), strings.ReplaceAll(v.Target, "$$", "$"), !v.ReadOnly})
	}
	active := ActiveInstallation{Node: r.Node, Spec: r.Spec, DefinitionSHA256: sha(definition)}
	h := installationHost{root: w.root}
	if err := h.verifyV3Container(c, active); err != nil {
		t.Fatal("generated literal paths rejected", err)
	}
	for _, kind := range []string{"extra", "missing", "duplicate", "writable-monitor", "volume-substitution", "wrong-probe"} {
		t.Run(kind, func(t *testing.T) {
			changed := c
			changed.Mounts = append(changed.Mounts[:0:0], c.Mounts...)
			switch kind {
			case "extra":
				changed.Mounts = append(changed.Mounts, struct {
					Type                string
					Source, Destination string
					RW                  bool
				}{"bind", "/etc", "/unauthorized", true})
			case "missing":
				changed.Mounts = changed.Mounts[1:]
			case "duplicate":
				changed.Mounts[1] = changed.Mounts[0]
			case "writable-monitor":
				for index, mount := range changed.Mounts {
					if mount.Destination == r.Spec.MonitorDirectories[0] {
						changed.Mounts[index].RW = true
					}
				}
			case "volume-substitution":
				changed.Mounts[0].Type = "volume"
			case "wrong-probe":
				for index, mount := range changed.Mounts {
					if mount.Destination == m.Settings.ProbeDirectory {
						changed.Mounts[index].Source = "/foreign"
					}
				}
			}
			if err := h.verifyV3Container(changed, active); err == nil {
				t.Fatal("unverified mounts accepted")
			}
		})
	}
}

func TestRestoreServicesRequiresActualStartedState(t *testing.T) {
	m := installationFixture(t, "native")
	m.addNative(t)
	i, err := m.host.inventory(context.Background(), "node-one", "native")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.host.stop(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	original := m.host.command
	m.host.command = func(ctx context.Context, program string, args ...string) (string, error) {
		if program == "systemctl" && args[0] == "start" {
			return "", nil
		}
		return original(ctx, program, args...)
	}
	if err := m.host.restoreServices(context.Background(), i); err == nil || err.Error() != "native-restore-not-confirmed" {
		t.Fatal("successful command mistaken for healthy restore", err)
	}
}

func TestInstallationRejectsActiveLegacyWrapperBeforeStoppingContainer(t *testing.T) {
	m := installationFixture(t, "docker")
	agent := m.addDocker(t)
	path := filepath.Join(m.host.root, "webscan-vector-v1.service")
	unit := legacySidecarUnit{Role: "vector", SourceImage: "timberio/vector:0.45.0-alpine", TLS: true}
	if err := os.WriteFile(path, unit.definition(), 0644); err != nil {
		t.Fatal(err)
	}
	command := m.host.command
	m.host.command = func(ctx context.Context, p string, a ...string) (string, error) {
		if p == "systemctl" && a[1] == "webscan-vector-v1.service" {
			return strings.Replace(m.status(), m.host.unitPath, path, 1), nil
		}
		return command(ctx, p, a...)
	}
	if _, err := m.host.inventory(context.Background(), "node-one", "docker"); err == nil || err.Error() != "legacy-wrapper-transition-not-supported" {
		t.Fatal("wrapper could race stopped container", err)
	}
	if !reflect.DeepEqual(agent, m.containers[agent.ID]) {
		t.Fatal("container changed")
	}
}
func TestInstallationDoesNotTakeOverActiveLegacySidecarWithoutRecovery(t *testing.T) {
	m := installationFixture(t, "docker")
	m.addDocker(t)
	side := containerIdentity{ID: strings.Repeat("3", 64), Name: "/webscan-vector-v1", Image: "timberio/vector:0.45.0-alpine", ImageID: "sha256:" + strings.Repeat("4", 64), Project: "webscan-node", Service: "vector", Status: "running", Restart: "always"}
	m.containers[side.ID] = side
	if _, err := m.host.inventory(context.Background(), "node-one", "docker"); err == nil || err.Error() != "legacy-sidecar-transition-not-supported" {
		t.Fatal("unsupported sidecar silently accepted", err)
	}
	for _, call := range m.calls {
		if strings.Contains(call, " update ") || strings.Contains(call, " stop ") {
			t.Fatal("sidecar changed before recovery supported")
		}
	}
}

func TestDockerToNativeCannotIgnoreMissingComposeOwnership(t *testing.T) {
	m := installationFixture(t, "docker")
	m.addDocker(t)
	if err := os.Remove(filepath.Join(m.host.configRoot, "compose.yml")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.host.inventory(context.Background(), "node-one", "native"); err == nil || err.Error() != "container-not-in-owned-compose" {
		t.Fatal("existing Docker installation ignored during native transition", err)
	}
	for _, call := range m.calls {
		if strings.Contains(call, " update ") || strings.Contains(call, " stop ") {
			t.Fatal("unproven container changed")
		}
	}
}

func TestContainerFingerprintIgnoresOnlyMountOrdering(t *testing.T) {
	m := installationFixture(t, "docker")
	m.addDocker(t)
	original := m.containers[strings.Repeat("1", 64)]
	before, _ := json.Marshal(original)
	reordered := original
	reordered.Mounts = append(reordered.Mounts[:0:0], reordered.Mounts...)
	for i, j := 0, len(reordered.Mounts)-1; i < j; i, j = i+1, j-1 {
		reordered.Mounts[i], reordered.Mounts[j] = reordered.Mounts[j], reordered.Mounts[i]
	}
	if reordered.fingerprint() != original.fingerprint() {
		t.Fatal("same mount set had a different proof")
	}
	after, _ := json.Marshal(original)
	if string(before) != string(after) {
		t.Fatal("fingerprinting modified caller evidence")
	}
	for _, kind := range []string{"source", "target", "writable", "type", "duplicate", "missing"} {
		t.Run(kind, func(t *testing.T) {
			changed := original
			changed.Mounts = append(changed.Mounts[:0:0], changed.Mounts...)
			switch kind {
			case "source":
				changed.Mounts[0].Source = "/other"
			case "target":
				changed.Mounts[0].Destination = "/other"
			case "writable":
				changed.Mounts[0].RW = !changed.Mounts[0].RW
			case "type":
				changed.Mounts[0].Type = "volume"
			case "duplicate":
				changed.Mounts = append(changed.Mounts, changed.Mounts[0])
			case "missing":
				changed.Mounts = changed.Mounts[1:]
			}
			if changed.fingerprint() == original.fingerprint() {
				t.Fatal("changed mount set retained proof")
			}
		})
	}
}
