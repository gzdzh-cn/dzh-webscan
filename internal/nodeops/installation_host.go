package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/common"
)

const legacyConfigurationRoot = "/etc/webscan-v1"
const nativeUnitPath = "/etc/systemd/system/webscan-agent-native.service"

// ActiveInstallation is a private, node-local pointer published only by the
// eventual activation/finalization driver. Hashes prove its generated files;
// neither private keys nor legacy push tokens belong in this pointer.
type ActiveInstallation struct {
	Format           int                         `json:"format"`
	Node             string                      `json:"node"`
	Spec             Spec                        `json:"spec"`
	RuntimeSHA256    string                      `json:"runtime_sha256"`
	DefinitionSHA256 string                      `json:"definition_sha256"`
	Job              string                      `json:"job,omitempty"`
	PlanDigest       string                      `json:"plan_digest,omitempty"`
	CaptureSHA256    string                      `json:"capture_sha256,omitempty"`
	Restoration      *ActiveRestorationReference `json:"restoration,omitempty"`
	Reinstall        *ReinstallReference         `json:"reinstall,omitempty"`
}

type ActiveRestorationReference struct {
	Job          string `json:"job"`
	PlanDigest   string `json:"plan_digest"`
	IntentSHA256 string `json:"intent_sha256"`
	ObjectSHA256 string `json:"object_sha256"`
}

type installationHost struct {
	root, configRoot, unitPath string
	data, logs                 string
	command                    func(context.Context, string, ...string) (string, error)
	processExecutable          func(int) (string, error)
	processArguments           func(int) ([]string, error)
}

func newInstallationHost(root string) installationHost {
	return installationHost{root: root, configRoot: legacyConfigurationRoot, unitPath: nativeUnitPath, command: inventoryCommand, processExecutable: func(pid int) (string, error) { return os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")) }, processArguments: func(pid int) ([]string, error) {
		raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
		if err != nil || len(raw) > 16384 || len(raw) == 0 || raw[len(raw)-1] != 0 {
			return nil, errors.New("native-arguments-unavailable")
		}
		return strings.Split(string(raw[:len(raw)-1]), "\x00"), nil
	}}
}

func inventoryCommand(ctx context.Context, program string, args ...string) (string, error) {
	mutation := serviceMutation(program, args)
	timeout := 10 * time.Second
	if mutation {
		timeout = 75 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return executeServiceCommand(ctx, program, args, mutation)
}

func executeServiceCommand(ctx context.Context, program string, args []string, mutation bool) (string, error) {
	var cmd *exec.Cmd
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if mutation {
		held, ok := ctx.Value(serviceOperationKey{}).(serviceOperation)
		if !ok || held.file == nil {
			return "", errors.New("service-operation-lock-required")
		}
		if _, err := held.file.Stat(); err != nil {
			return "", errors.New("service-operation-lock-lost")
		}
		// Do not kill a mutating client on a caller timeout: the daemon operation
		// may still be running. Its inherited flock keeps the next operation out.
		cmd = exec.Command(program, args...)
		cmd.ExtraFiles = []*os.File{held.file}
	} else {
		cmd = exec.CommandContext(ctx, program, args...)
	}
	cmd.WaitDelay = 2 * time.Second
	var b boundedInventory
	cmd.Stdout = &b
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return "", errors.New("service-command-start-failed")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-ctx.Done():
		return "", errors.New("service-command-state-unknown")
	case err := <-done:
		if b.overflow {
			return "", errors.New("service-inspection-unavailable")
		}
		if err != nil {
			return string(b.raw), errors.New("service-inspection-unavailable")
		}
		return string(b.raw), nil
	}
}

type boundedInventory struct {
	raw      []byte
	overflow bool
}

func (b *boundedInventory) Write(p []byte) (int, error) {
	n := len(p)
	left := (128 << 10) - len(b.raw)
	if n > left {
		b.overflow = true
	}
	b.raw = append(b.raw, p[:min(n, left)]...)
	return n, nil
}

func (h installationHost) inventory(ctx context.Context, node, targetMode string) (Installation, error) {
	return h.inventoryWithWrappers(ctx, node, targetMode, nil)
}

// Only the grouped backup coordinator supplies wrappers, after durably
// capturing their exact unit, object and image. This is not a public bypass.
func (h installationHost) inventoryWithWrappers(ctx context.Context, node, targetMode string, wrappers map[string]legacyWrapperIntent) (Installation, error) {
	return h.inventoryWithWrapperProofs(ctx, node, targetMode, wrappers, false)
}

func (h installationHost) inventoryWithWrapperProofs(ctx context.Context, node, targetMode string, wrappers map[string]legacyWrapperIntent, observed bool) (Installation, error) {
	return h.inventoryWithLegacyProofs(ctx, node, targetMode, wrappers, nil, observed)
}

func (h installationHost) inventoryWithLegacyProofs(ctx context.Context, node, targetMode string, wrappers map[string]legacyWrapperIntent, sidecars map[string]legacyComposeIntent, observed bool) (Installation, error) {
	i := Installation{Node: node, Generation: "absent", Services: []ServiceRecord{}}
	if !idPattern.MatchString(node) || (targetMode != "native" && targetMode != "docker") || h.command == nil {
		return i, errors.New("invalid-inventory-request")
	}
	if err := privateDirectoryTree(h.root); err != nil {
		return i, err
	}
	if _, err := os.Lstat(h.configRoot); err == nil {
		if err := privateDirectoryTree(h.configRoot); err != nil {
			return i, err
		}
	} else if !os.IsNotExist(err) {
		return i, err
	}
	var active *ActiveInstallation
	var runtime common.Map
	activePath := filepath.Join(h.root, "active.json")
	if _, err := os.Lstat(activePath); err == nil {
		raw, e := readPrivate(activePath, MaxRequestBytes)
		if e != nil {
			return i, e
		}
		var a ActiveInstallation
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&a) != nil || decoder.Decode(new(any)) != io.EOF || a.Format != 1 || a.Node != node || a.Spec.Validate() != nil || !a.Spec.configurationValid() || !validDigest(a.RuntimeSHA256) || !validDigest(a.DefinitionSHA256) || (a.Job != "" || a.PlanDigest != "") && (!idPattern.MatchString(a.Job) || !validDigest(a.PlanDigest)) {
			return i, errors.New("active-installation-not-proven")
		}
		canonical, _ := json.Marshal(a)
		if !bytes.Equal(raw, canonical) || a.CaptureSHA256 != "" && (!validDigest(a.CaptureSHA256) || a.Job == "" || a.PlanDigest == "") {
			return i, errors.New("active-installation-not-proven")
		}
		active = &a
		i.Generation = "v3"
		i.Mode = a.Spec.Mode
		i.Runtime = filepath.Join(h.root, "configurations", a.Spec.RuntimeSHA256, "runtime.json")
		if err := privateDirectoryTree(filepath.Dir(i.Runtime)); err != nil {
			return i, err
		}
		raw, e = readPrivate(i.Runtime, 2<<20)
		if e != nil || sha(raw) != a.RuntimeSHA256 {
			return i, errors.New("active-runtime-changed")
		}
		value, e := common.Decode(raw)
		runtime = common.M(value)
		if e != nil {
			return i, errors.New("active-runtime-invalid")
		}
	} else if !os.IsNotExist(err) {
		return i, err
	} else {
		if removed, err := h.uninstalledInventory(ctx, node); err != nil || removed != nil {
			if removed != nil {
				return *removed, err
			}
			return i, err
		}
		i.Runtime = filepath.Join(h.configRoot, "runtime.json")
		if _, err := os.Lstat(i.Runtime); err == nil {
			raw, e := readPrivate(i.Runtime, 2<<20)
			if e != nil {
				return i, e
			}
			value, e := common.Decode(raw)
			runtime = common.M(value)
			if e != nil {
				return i, e
			}
			i.Generation = "v2"
			i.Mode = common.S(runtime["deployment_mode"])
			if i.Mode == "" {
				i.Mode = "docker"
			}
		} else if !os.IsNotExist(err) {
			return i, err
		} else {
			i.Runtime = ""
		}
	}
	if len(sidecars) > 0 && (len(wrappers) > 0 || i.Generation != "v2" || i.Mode != "docker") {
		return i, errors.New("legacy-compose-group-not-proven")
	}
	if err := h.inspectComposeProofs(ctx, node, sidecars, observed); err != nil {
		return i, err
	}
	for _, name := range legacyComposeNames {
		if intent, ok := sidecars[name]; ok {
			raw, _ := json.Marshal(intent)
			i.Sidecars = append(i.Sidecars, legacyComposeMember{name, sha(raw)})
		}
	}
	if runtime != nil && (common.S(runtime["node_id"]) != node || common.S(runtime["data_dir"]) != agentDataDirectory || common.S(runtime["log_dir"]) != agentLogDirectory || (i.Mode != "native" && i.Mode != "docker")) {
		return i, errors.New("installed-node-identity-mismatch")
	}
	// Old systemd wrappers can recreate a stopped Docker container under a new
	// ID. Until their recovery is supported, never stop only the
	// container and mistake that for a quiescent installation. Inactive, disabled
	// remnants with exact known templates are left untouched; unknown units or
	// states fail closed. Their public 0644 units are not credential files.
	parked, err := h.inspectLegacyWrapperProofs(ctx, node, wrappers, observed)
	if err != nil {
		return i, err
	}
	for _, name := range legacyWrapperNames {
		if intent, ok := wrappers[name]; ok {
			raw, _ := json.Marshal(intent)
			i.Wrappers = append(i.Wrappers, legacyWrapperMember{name, sha(raw)})
		}
	}
	if _, err := os.Lstat(h.unitPath); err == nil {
		if err := directoryAncestors(filepath.Dir(h.unitPath)); err != nil {
			return i, err
		}
		if runtime == nil {
			return i, errors.New("native-unit-without-node-configuration")
		}
		unit, e := readPrivate(h.unitPath, 64<<10)
		if e != nil {
			return i, e
		}
		program := ""
		if active != nil && i.Mode == "native" {
			if sha(unit) != active.DefinitionSHA256 {
				return i, errors.New("native-unit-changed")
			}
			prepared := filepath.Join(h.root, "configurations", active.Spec.RuntimeSHA256, nativeServiceName)
			want, e := readPrivate(prepared, 64<<10)
			if e != nil || !bytes.Equal(want, unit) {
				return i, errors.New("native-unit-changed")
			}
			program = filepath.Join(h.root, "releases", active.Spec.BundleSHA256, "webscan")
		} else {
			program, e = legacyNativeProgram(unit, runtime)
			if e != nil {
				return i, e
			}
		}
		raw, e := h.command(ctx, "systemctl", "show", nativeServiceName, "--property=LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,Job,MainPID")
		if e != nil {
			return i, e
		}
		status, e := parseNativeStatus(raw)
		if e != nil || status.FragmentPath != h.unitPath {
			return i, errors.New("native-service-ownership-not-proven")
		}
		if err := h.proveNativeProcess(status, program, i.Runtime); err != nil {
			return i, err
		}
		if status.UnitFileState != "enabled" && status.UnitFileState != "disabled" {
			return i, errors.New("native-service-enable-state-unknown")
		}
		i.Services = append(i.Services, ServiceRecord{Kind: "native", Name: nativeServiceName, ID: nativeServiceName, Proof: sha(unit), Running: status.MainPID > 0, Enabled: status.UnitFileState == "enabled", Program: program, Configuration: i.Runtime})
	} else if !os.IsNotExist(err) {
		return i, err
	}
	if err := h.retainedAgentHistory(ctx, active); err != nil {
		return i, err
	}
	parkedSidecars, err := h.parkedComposeProofs(ctx, active)
	if err != nil {
		return i, err
	}
	composePath := filepath.Join(h.configRoot, "compose.yml")
	_, composeErr := os.Lstat(composePath)
	// A fresh native node never calls Docker. Existing Docker deployments and
	// Docker targets must prove their engine state, never reinstall on failure.
	if targetMode == "docker" || composeErr == nil || i.Mode == "docker" || len(wrappers) > 0 || len(parkedSidecars) > 0 {
		project := ""
		configured := map[string]struct{ Service, Image string }{}
		if composeErr == nil {
			raw, e := readPrivate(composePath, 2<<20)
			if e != nil {
				return i, e
			}
			var c struct {
				Name     string
				Services map[string]struct {
					Image         string
					ContainerName string `yaml:"container_name"`
				}
			}
			if yaml.Unmarshal(raw, &c) != nil || c.Name == "" || !strings.HasPrefix(c.Name, "webscan") {
				return i, errors.New("compose-ownership-not-proven")
			}
			project = c.Name
			for name, s := range c.Services {
				if knownContainer(s.ContainerName) {
					if _, exists := configured[s.ContainerName]; exists {
						return i, errors.New("duplicate-owned-container")
					}
					configured[s.ContainerName] = struct{ Service, Image string }{name, s.Image}
				}
			}
		} else if !os.IsNotExist(composeErr) {
			return i, composeErr
		}
		if _, e := h.docker(ctx, "info", "--format", "{{.ServerVersion}}"); e != nil {
			return i, e
		}
		for _, name := range []string{agentContainerName, "webscan-vector-v1", "webscan-exporter-v1"} {
			raw, e := h.docker(ctx, "ps", "-a", "--no-trunc", "--filter", "name=^/"+name+"$", "--format", "{{.ID}}")
			if e != nil {
				return i, e
			}
			id := strings.TrimSpace(raw)
			if id == "" {
				continue
			}
			if !validDigest(id) {
				return i, errors.New("container-lookup-not-unique")
			}
			c, e := h.container(ctx, id)
			if e != nil {
				return i, e
			}
			if strings.TrimPrefix(c.Name, "/") != name {
				return i, errors.New("container-name-raced")
			}
			if runtime == nil {
				return i, errors.New("container-without-node-configuration")
			}
			wrapper, wrapped := wrappers[name+".service"]
			parkedMember := false
			if !wrapped {
				wrapper, parkedMember = parked[name+".service"]
				wrapped = parkedMember
			}
			if wrapped {
				if c.ID != wrapper.Object.Identity.ID || c.fingerprint() != wrapper.Object.Identity.fingerprint() || c.Restart != "no" || c.MaxRetries != 0 || parkedMember && c.Status == "running" {
					return i, errors.New("legacy-wrapper-container-changed")
				}
				continue
			}
			if sidecar, proven := sidecars[name]; proven {
				if c.ID != sidecar.Object.Identity.ID || c.fingerprint() != sidecar.Object.Identity.fingerprint() {
					return i, errors.New("legacy-compose-member-changed")
				}
				continue
			}
			if parked, proven := parkedSidecars[name]; proven {
				if c.ID != parked.Object.Identity.ID || c.fingerprint() != parked.Object.Identity.fingerprint() || c.Status == "running" || c.Restart != "no" || c.MaxRetries != 0 {
					return i, errors.New("parked-compose-member-changed")
				}
				continue
			}
			if active != nil && name == agentContainerName && active.Spec.Mode == "docker" {
				if e := h.verifyV3Container(c, *active); e != nil {
					return i, e
				}
			} else {
				expected, ok := configured[name]
				if !ok {
					return i, errors.New("container-not-in-owned-compose")
				}
				if e := verifyLegacyContainer(c, expected.Service, project, expected.Image, h.configRoot); e != nil {
					return i, e
				}
				if name != agentContainerName && (c.Status == "running" || c.Restart != "no") {
					return i, errors.New("legacy-sidecar-transition-not-supported")
				}
			}
			i.Services = append(i.Services, ServiceRecord{Kind: "docker", Name: name, ID: c.ID, Proof: c.fingerprint(), Running: c.Status == "running", Enabled: c.Restart != "no", Restart: c.Restart, MaxRetries: c.MaxRetries})
		}
	} else if !os.IsNotExist(composeErr) {
		return i, composeErr
	}
	if !i.valid(node) {
		return i, errors.New("installation-not-proven")
	}
	if len(wrappers) > 0 {
		if _, err := h.inspectLegacyWrapperProofs(ctx, node, wrappers, observed); err != nil {
			return i, err
		}
	}
	for name := range parked {
		_, status, err := (legacyWrapperTransition{h}).retainedState(ctx, node, name)
		if err != nil || status.MainPID != 0 || status.UnitFileState != "disabled" {
			return i, errors.New("retained-wrapper-state-changed")
		}
	}
	if err := h.inspectComposeProofs(ctx, node, sidecars, observed); err != nil {
		return i, err
	}
	if len(parkedSidecars) > 0 {
		if _, err := h.parkedComposeProofs(ctx, active); err != nil {
			return i, err
		}
	}
	if err := h.retainedAgentHistory(ctx, active); err != nil {
		return i, err
	}
	return i, nil
}

func (h installationHost) docker(ctx context.Context, args ...string) (string, error) {
	return h.command(ctx, "docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
}

const inventoryContainerFormat = `{"ID":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Config.Image}},"ImageID":{{json .Image}},"Project":{{json (index .Config.Labels "com.docker.compose.project")}},"Service":{{json (index .Config.Labels "com.docker.compose.service")}},"Managed":{{json (index .Config.Labels "io.webscan.managed")}},"Node":{{json (index .Config.Labels "io.webscan.node")}},"Configuration":{{json (index .Config.Labels "io.webscan.configuration")}},"Entrypoint":{{json .Config.Entrypoint}},"Command":{{json .Config.Cmd}},"Mounts":{{json .Mounts}},"Status":{{json .State.Status}},"Restart":{{json .HostConfig.RestartPolicy.Name}},"MaxRetries":{{json .HostConfig.RestartPolicy.MaximumRetryCount}}}`

func (h installationHost) container(ctx context.Context, id string) (containerIdentity, error) {
	var c containerIdentity
	if !validDigest(id) {
		return c, errors.New("invalid-container-id")
	}
	raw, err := h.docker(ctx, "container", "inspect", id, "--format", inventoryContainerFormat)
	if err != nil || json.Unmarshal([]byte(raw), &c) != nil || c.ID != id {
		return c, errors.New("container-inspection-failed")
	}
	return c, nil
}

func (h installationHost) verifyV3Container(c containerIdentity, a ActiveInstallation) error {
	if a.Restoration != nil {
		s, err := h.restoredService(a)
		if err != nil || s.Kind != "docker" || s.ID != c.ID || s.Proof != c.fingerprint() {
			return errors.New("restored-container-not-proven")
		}
	}
	if c.Managed != "v3" || c.Node != a.Node || c.Configuration != a.Spec.RuntimeSHA256 || c.Project != dockerProject(a) || c.Service != "agent" || !validDigest(c.ID) || !validRestart(c.Restart) || (c.Status != "running" && c.Status != "exited" && c.Status != "created") {
		return errors.New("v3-container-ownership-not-proven")
	}
	dir := filepath.Join(h.root, "configurations", a.Spec.RuntimeSHA256)
	release := filepath.Join(h.root, "releases", a.Spec.BundleSHA256)
	definition, err := readPrivate(filepath.Join(dir, "compose.json"), 2<<20)
	if err != nil || sha(definition) != a.DefinitionSHA256 {
		return errors.New("v3-compose-changed")
	}
	if !equalStrings(c.Entrypoint, []string{filepath.Join(release, "webscan")}) || !equalStrings(c.Command, []string{"agent", "--config", filepath.Join(dir, "runtime.json")}) {
		return errors.New("v3-container-command-changed")
	}
	image := a.Spec.AgentImage
	if a.Spec.imageArchiveValid() {
		image, err = dockerLaunchReference(h.root, a.Spec)
		if err != nil {
			return err
		}
	}
	identity := image
	if a.Spec.imageArchiveValid() {
		identity, err = dockerLaunchIdentity(h.root, a.Spec)
		if err != nil {
			return err
		}
	}
	if c.Image != image || !strings.HasPrefix(c.ImageID, "sha256:") || !validDigest(strings.TrimPrefix(c.ImageID, "sha256:")) || a.Spec.imageArchiveValid() && c.ImageID != identity {
		return errors.New("v3-container-image-changed")
	}
	var compose struct {
		Services map[string]struct {
			Volumes []serviceMount `json:"volumes"`
		} `json:"services"`
	}
	if json.Unmarshal(definition, &compose) != nil || len(compose.Services) != 1 {
		return errors.New("v3-compose-changed")
	}
	service, ok := compose.Services["agent"]
	if !ok || len(service.Volumes) != len(c.Mounts) {
		return errors.New("v3-container-mount-changed")
	}
	need := map[string]serviceMount{}
	for _, mount := range service.Volumes {
		mount.Source = strings.ReplaceAll(mount.Source, "$$", "$")
		mount.Target = strings.ReplaceAll(mount.Target, "$$", "$")
		if _, duplicate := need[mount.Target]; duplicate || mount.Type != "bind" {
			return errors.New("v3-compose-changed")
		}
		need[mount.Target] = mount
	}
	for _, m := range c.Mounts {
		want, ok := need[m.Destination]
		if !ok || m.Type != "bind" || m.Source != want.Source || m.RW == want.ReadOnly {
			return errors.New("v3-container-mount-changed")
		}
		delete(need, m.Destination)
	}
	if len(need) != 0 {
		return errors.New("v3-container-mount-changed")
	}
	return nil
}

// A task-specific project prevents Compose create from reconciling/deleting a
// retained old Agent. Older private fixtures/pointers without a task keep the
// original name. The full node/job/plan binding is already in the active pointer.
func dockerProject(a ActiveInstallation) string {
	if a.Job == "" {
		return "webscan-v3-agent"
	}
	return "webscan-v3-" + sha([]byte(a.Node + "\x00" + a.Job + "\x00" + a.PlanDigest))[:24]
}
