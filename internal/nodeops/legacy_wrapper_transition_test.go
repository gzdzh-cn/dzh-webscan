package nodeops

import (
	"bytes"
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

type wrapperMachine struct {
	w                legacyWrapperTransition
	r                Request
	unit, name       string
	loaded           []byte
	o                legacyWrapperObject
	image            legacyWrapperImage
	u                legacySidecarUnit
	running, enabled bool
	args             []string
	calls            []string
	lose             string
	lost             bool
	unknownProcess   bool
	dropin           bool
	reloadLie        bool
}

func wrapperFixture(t *testing.T, role string, tls, running, enabled bool) *wrapperMachine {
	t.Helper()
	m := installationFixture(t, "docker")
	_, r, _ := serviceFixture(t, "native")
	r.Phase = "backup"
	name := "webscan-" + role + "-v1.service"
	raw := legacyWrapperFixture(t, role, tls)
	u, err := parseLegacySidecarUnit(name, raw)
	if err != nil {
		t.Fatal(err)
	}
	f := &wrapperMachine{r: r, name: name, u: u, loaded: raw, running: running, enabled: enabled}
	f.w.host = m.host
	f.unit = filepath.Join(filepath.Dir(m.host.unitPath), name)
	if err := os.WriteFile(f.unit, raw, 0644); err != nil {
		t.Fatal(err)
	}
	f.image = legacyWrapperImage{"sha256:" + strings.Repeat("d", 64), "linux", "amd64", "root", []string{"/usr/bin/" + role}, []string{"--default-image-config"}}
	f.o = legacyWrapperObject{Identity: containerIdentity{ID: strings.Repeat("1", 64), Name: "/webscan-" + role + "-v1", Image: u.alias(), ImageID: f.image.ID, Entrypoint: f.image.Entrypoint, Command: f.image.Cmd, Status: "exited", Restart: "no"}, Network: "host", User: f.image.User, ReadOnly: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}, LogType: "json-file", LogOptions: map[string]string{"max-size": "10m", "max-file": "3"}}
	if running {
		f.o.Identity.Status = "running"
	}
	args := u.runArguments()
	for j, arg := range args {
		if role == "exporter" && arg == u.alias() {
			f.o.Identity.Command = args[j+1:]
		}
		if arg != "-v" {
			continue
		}
		parts := strings.Split(args[j+1], ":")
		prop := "rprivate"
		if len(parts) == 3 && parts[2] == "ro,rslave" {
			prop = "rslave"
		}
		f.o.Identity.Mounts = append(f.o.Identity.Mounts, struct {
			Type                string
			Source, Destination string
			RW                  bool
		}{"bind", parts[0], parts[1], len(parts) == 2})
		f.o.Propagation = append(f.o.Propagation, legacyBindPropagation{parts[1], prop})
	}
	if role == "exporter" {
		f.o.PIDMode, f.o.User = "host", "0:0"
	}
	f.args = append([]string{"/usr/bin/docker"}, u.runArguments()...)
	f.w.host.processExecutable = func(int) (string, error) {
		if f.unknownProcess {
			return "/usr/bin/unrelated", nil
		}
		return "/usr/bin/docker", nil
	}
	f.w.host.processArguments = func(int) ([]string, error) { return append([]string(nil), f.args...), nil }
	f.w.host.command = f.command
	return f
}

func (m *wrapperMachine) command(ctx context.Context, p string, args ...string) (string, error) {
	call := p + " " + strings.Join(args, " ")
	m.calls = append(m.calls, call)
	if serviceMutation(p, args) {
		held, ok := ctx.Value(serviceOperationKey{}).(serviceOperation)
		if !ok || held.root != m.w.host.root || held.file == nil {
			return "", errors.New("mutation without node service lock")
		}
	}
	var out string
	mutation := ""
	if p == "systemctl" && len(args) > 0 {
		switch args[0] {
		case "show":
			enabled, active, sub, pid, reload, dropin := "disabled", "inactive", "dead", 0, "no", ""
			if m.enabled {
				enabled = "enabled"
			}
			if m.running {
				active, sub, pid = "active", "running", 12345
			}
			unit, _ := os.ReadFile(m.unit)
			if !bytes.Equal(unit, m.loaded) && !m.reloadLie {
				reload = "yes"
			}
			if m.dropin {
				dropin = "/etc/foreign.conf"
			}
			return fmt.Sprintf("LoadState=loaded\nActiveState=%s\nSubState=%s\nFragmentPath=%s\nDropInPaths=%s\nNeedDaemonReload=%s\nUnitFileState=%s\nJob=0\nMainPID=%d\n", active, sub, m.unit, dropin, reload, enabled, pid), nil
		case "daemon-reload":
			m.loaded, _ = os.ReadFile(m.unit)
			mutation = "reload"
		case "disable":
			m.enabled = false
			mutation = "disable"
			if len(args) == 3 && args[1] == "--now" {
				if !bytes.Equal(m.loaded, retainedWrapperUnit(m.u, m.o.Identity.ID)) {
					return "", errors.New("refusing original name-based stop")
				}
				m.running, m.o.Identity.Status = false, "exited"
			}
		case "enable":
			m.enabled, mutation = true, "enable"
		case "start":
			if !bytes.Equal(m.loaded, retainedWrapperUnit(m.u, m.o.Identity.ID)) {
				return "", errors.New("original ExecStartPre would remove retained object")
			}
			m.running, m.o.Identity.Status, mutation = true, "running", "start"
			m.args = []string{"/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "start", "--attach", m.o.Identity.ID}
		default:
			return "", errors.New("unexpected systemctl operation")
		}
	} else if p == "docker" && len(args) > 2 && args[0] == "--host" && args[1] == "unix:///var/run/docker.sock" {
		a := args[2:]
		switch a[0] {
		case "ps":
			if len(a) != 7 || a[4] != "name=^"+m.o.Identity.Name+"$" {
				return "", errors.New("wrong exact-name discovery")
			}
			return m.o.Identity.ID, nil
		case "container":
			if a[2] != m.o.Identity.ID || a[4] != legacyWrapperObjectFormat {
				return "", errors.New("inspection without exact ID")
			}
			b, _ := json.Marshal(m.o)
			return string(b), nil
		case "image":
			if a[2] != m.u.SourceImage && a[2] != m.image.ID {
				return "", errors.New("source image not checked")
			}
			b, _ := json.Marshal(m.image)
			return string(b), nil
		case "stop":
			if a[len(a)-1] != m.o.Identity.ID {
				return "", errors.New("stop without exact ID")
			}
			m.o.Identity.Status, mutation = "exited", "docker-stop"
		default:
			return "", errors.New("forbidden Docker mutation")
		}
	} else {
		return "", errors.New("unexpected wrapper command")
	}
	if mutation != "" && m.lose == mutation && !m.lost {
		m.lost = true
		return "", errors.New("simulated lost response")
	}
	return out, nil
}

func (m *wrapperMachine) mutations() []string {
	var calls []string
	for _, call := range m.calls {
		if strings.HasPrefix(call, "systemctl show ") || strings.Contains(call, " inspect ") || strings.Contains(call, " ps ") {
			continue
		}
		calls = append(calls, call)
	}
	return calls
}

func TestLegacyWrapperTransitionRetainsObjectAndSupervision(t *testing.T) {
	for _, role := range []string{"vector", "exporter"} {
		for _, tls := range []bool{false, true} {
			for _, running := range []bool{false, true} {
				for _, enabled := range []bool{false, true} {
					t.Run(fmt.Sprint(role, tls, running, enabled), func(t *testing.T) {
						m := wrapperFixture(t, role, tls, running, enabled)
						original := m.o
						originalUnit, _ := os.ReadFile(m.unit)
						if _, err := m.w.capture(context.Background(), m.r, m.name); err != nil {
							t.Fatal("capture", err)
						}
						if len(m.mutations()) != 0 {
							t.Fatal("capture changed services", m.mutations())
						}
						if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
							t.Fatal("quiesce", err)
						}
						if m.running || m.enabled || m.o.Identity.Status == "running" || m.o.Identity.ID != original.Identity.ID || m.o.fingerprint() != original.fingerprint() {
							t.Fatal("old object not quiesced and retained")
						}
						m.r.Phase = "restore"
						if err := m.w.restore(context.Background(), m.r, m.name); err != nil {
							t.Fatal("restore", err)
						}
						if m.running != running || m.enabled != enabled || (m.o.Identity.Status == "running") != running || m.o.Identity.ID != original.Identity.ID || m.o.fingerprint() != original.fingerprint() {
							t.Fatal("original object/state not restored")
						}
						i, _, err := m.w.read(m.r, m.name)
						if err != nil || !bytes.Equal(i.Unit, originalUnit) {
							t.Fatal("original unit not retained privately", err)
						}
						got, _ := os.ReadFile(m.unit)
						if !bytes.Equal(got, retainedWrapperUnit(m.u, original.Identity.ID)) || strings.Contains(string(got), "ExecStartPre") || strings.Contains(string(got), " rm ") {
							t.Fatal("unsafe original wrapper restored")
						}
						before := len(m.mutations())
						if err := m.w.restore(context.Background(), m.r, m.name); err != nil || len(m.mutations()) != before {
							t.Fatal("completed restore mutated service", err)
						}
						m.r.Phase = "backup"
						if err := m.w.quiesce(context.Background(), m.r, m.name); err == nil || len(m.mutations()) != before {
							t.Fatal("forward operation after rollback", err)
						}
					})
				}
			}
		}
	}
}

func TestLegacyWrapperTransitionResumesLostResponses(t *testing.T) {
	for _, loss := range []string{"reload", "disable", "enable", "start"} {
		t.Run(loss, func(t *testing.T) {
			m := wrapperFixture(t, "vector", true, true, true)
			if loss == "reload" || loss == "disable" {
				m.lose = loss
				if err := m.w.quiesce(context.Background(), m.r, m.name); err == nil || !m.lost {
					t.Fatal("fault did not occur", err)
				}
			}
			if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
				t.Fatal("resume quiesce", err)
			}
			m.r.Phase = "restore"
			if loss == "enable" || loss == "start" {
				m.lose = loss
				if err := m.w.restore(context.Background(), m.r, m.name); err == nil || !m.lost {
					t.Fatal("fault did not occur", err)
				}
			}
			before := append([]string(nil), m.mutations()...)
			if err := m.w.restore(context.Background(), m.r, m.name); err != nil {
				t.Fatal("resume restore", err)
			}
			if !m.running || !m.enabled || m.o.Identity.ID != strings.Repeat("1", 64) {
				t.Fatal("lost original state or ID")
			}
			if loss == "start" {
				for _, call := range m.mutations()[len(before):] {
					if strings.HasPrefix(call, "systemctl start ") || strings.HasPrefix(call, "systemctl disable ") {
						t.Fatal("restarted an already restored original", call)
					}
				}
			}
		})
	}
}

func TestLegacyWrapperTransitionRejectsUnprovenOriginals(t *testing.T) {
	for _, kind := range []string{"command", "entrypoint", "image", "source-retag", "project", "extra-mount", "writable-mount", "mount-propagation", "duplicate-mount", "restart", "network", "privileged", "read-only", "capability", "security-opt", "logging", "user", "pid-mode", "process", "process-arguments", "dropin", "runtime", "unit-hook"} {
		t.Run(kind, func(t *testing.T) {
			m := wrapperFixture(t, "exporter", true, true, true)
			switch kind {
			case "command":
				m.o.Identity.Command = []string{"unrelated"}
			case "entrypoint":
				m.o.Identity.Entrypoint = []string{"/bin/false"}
			case "image":
				m.o.Identity.Image = "foreign:latest"
			case "source-retag":
				m.image.ID = "sha256:" + strings.Repeat("e", 64)
			case "project":
				m.o.Identity.Project = "foreign"
			case "extra-mount":
				m.o.Identity.Mounts = append(m.o.Identity.Mounts, m.o.Identity.Mounts[0])
			case "writable-mount":
				m.o.Identity.Mounts[0].RW = true
			case "mount-propagation":
				m.o.Propagation[0].Propagation = "rshared"
			case "duplicate-mount":
				m.o.Identity.Mounts[0] = m.o.Identity.Mounts[1]
			case "restart":
				m.o.Identity.Restart = "always"
			case "network":
				m.o.Network = "bridge"
			case "privileged":
				m.o.Privileged = true
			case "read-only":
				m.o.ReadOnly = false
			case "capability":
				m.o.CapAdd = []string{"SYS_ADMIN"}
			case "security-opt":
				m.o.SecurityOpt = nil
			case "logging":
				m.o.LogOptions["max-file"] = "20"
			case "user":
				m.o.User = "1000:1000"
			case "pid-mode":
				m.o.PIDMode = ""
			case "process":
				m.unknownProcess = true
			case "process-arguments":
				m.args = []string{"/usr/bin/docker", "run", "unrelated"}
			case "dropin":
				m.dropin = true
			case "runtime":
				os.WriteFile(filepath.Join(m.w.host.configRoot, "runtime.json"), []byte(`{"node_id":"another"}`), 0600)
			case "unit-hook":
				os.WriteFile(m.unit, append(m.loaded, []byte("ExecStopPost=/bin/false\n")...), 0644)
			}
			before, _ := os.ReadFile(m.unit)
			if err := m.w.quiesce(context.Background(), m.r, m.name); err == nil {
				t.Fatal("unknown original accepted")
			}
			after, _ := os.ReadFile(m.unit)
			if len(m.mutations()) != 0 || !bytes.Equal(before, after) {
				t.Fatal("unproven original changed", m.mutations())
			}
		})
	}
}

func TestLegacyWrapperTransitionCheckpointGuards(t *testing.T) {
	for _, kind := range []string{"plan", "node", "spec", "intent", "quiesce", "missing-quiesce", "symlink-quiesce", "unit", "container", "name", "runtime", "lock"} {
		t.Run(kind, func(t *testing.T) {
			m := wrapperFixture(t, "vector", true, true, true)
			if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
				t.Fatal(err)
			}
			dir, _ := m.w.directory(m.r, m.name)
			m.r.Phase = "restore"
			switch kind {
			case "plan":
				m.r.PlanDigest = strings.Repeat("e", 64)
			case "node":
				m.r.Node = "another"
			case "spec":
				m.r.Spec.MetricsPort++
			case "intent":
				os.WriteFile(filepath.Join(dir, "intent.json"), []byte(`{}`), 0600)
			case "quiesce":
				os.WriteFile(filepath.Join(dir, "quiesce.json"), []byte(`{}`), 0600)
			case "missing-quiesce":
				os.Remove(filepath.Join(dir, "quiesce.json"))
			case "symlink-quiesce":
				os.Remove(filepath.Join(dir, "quiesce.json"))
				os.Symlink(filepath.Join(dir, "intent.json"), filepath.Join(dir, "quiesce.json"))
			case "unit":
				os.WriteFile(m.unit, []byte("foreign unit"), 0600)
			case "container":
				m.o.Identity.ImageID = "sha256:" + strings.Repeat("e", 64)
			case "name":
				m.o.Identity.Name = "/foreign"
			case "runtime":
				os.WriteFile(filepath.Join(m.w.host.configRoot, "runtime.json"), []byte(`{}`), 0600)
			case "lock":
				_, unlock, err := acquireServiceOperation(context.Background(), m.w.host.root)
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
			}
			before := len(m.mutations())
			if err := m.w.restore(context.Background(), m.r, m.name); err == nil {
				t.Fatal("damaged or conflicting evidence accepted")
			}
			if len(m.mutations()) != before {
				t.Fatal("mutation before proof", m.mutations()[before:])
			}
		})
	}
}

func TestLegacyWrapperTransitionCaptureOnlyRestoreAndCompletedConflict(t *testing.T) {
	for _, untouched := range []bool{false, true} {
		t.Run(fmt.Sprint(untouched), func(t *testing.T) {
			m := wrapperFixture(t, "vector", false, true, true)
			if untouched {
				if _, err := m.w.capture(context.Background(), m.r, m.name); err != nil {
					t.Fatal(err)
				}
			} else if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
				t.Fatal(err)
			}
			m.r.Phase = "restore"
			if err := m.w.restore(context.Background(), m.r, m.name); err != nil {
				t.Fatal(err)
			}
			before := len(m.mutations())
			m.running, m.o.Identity.Status = false, "exited"
			if err := m.w.restore(context.Background(), m.r, m.name); err == nil || len(m.mutations()) != before {
				t.Fatal("completed task repaired external state", err)
			}
		})
	}
}

func TestLegacyWrapperTransitionUnloadedUnitCannotUseOldStop(t *testing.T) {
	m := wrapperFixture(t, "vector", false, true, true)
	i, err := m.w.capture(context.Background(), m.r, m.name)
	if err != nil {
		t.Fatal(err)
	}
	_, raw, _ := m.w.read(m.r, m.name)
	if err := m.w.mark(m.r, m.name, "quiesce.json", i, raw, true); err != nil {
		t.Fatal(err)
	}
	if err := installRetainedWrapper(i); err != nil {
		t.Fatal(err)
	}
	m.reloadLie = true // Simulate unchanged timestamp or a stale reload flag.
	if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
		t.Fatal(err)
	}
	mutations := m.mutations()
	if len(mutations) < 2 || mutations[0] != "systemctl daemon-reload" || mutations[1] != "systemctl disable --now "+m.name {
		t.Fatal("did not explicitly load immutable-ID stop before disabling", mutations)
	}
}

func TestLegacyWrapperObjectProofIgnoresOnlyOrderAndRuntime(t *testing.T) {
	m := wrapperFixture(t, "exporter", true, true, true)
	before := m.o
	canonical, _ := json.Marshal(before)
	var copy legacyWrapperObject
	json.Unmarshal(canonical, &copy)
	for left, right := 0, len(copy.Identity.Mounts)-1; left < right; left, right = left+1, right-1 {
		copy.Identity.Mounts[left], copy.Identity.Mounts[right] = copy.Identity.Mounts[right], copy.Identity.Mounts[left]
		copy.Propagation[left], copy.Propagation[right] = copy.Propagation[right], copy.Propagation[left]
	}
	copy.Identity.Status = "exited"
	if copy.fingerprint() != before.fingerprint() || !reflect.DeepEqual(before, m.o) {
		t.Fatal("unstable or mutating object proof")
	}
	copy.Network = "bridge"
	if copy.fingerprint() == before.fingerprint() {
		t.Fatal("changed ownership setting ignored")
	}
}

func TestLegacyWrapperTransitionVerifiesExpectedUnitWithoutRepairs(t *testing.T) {
	m := wrapperFixture(t, "exporter", false, false, false)
	if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
		t.Fatal(err)
	}
	if err := m.w.quiescent(context.Background(), m.r, m.name); err != nil {
		t.Fatal(err)
	}
	m.r.Phase = "restore"
	if err := m.w.restore(context.Background(), m.r, m.name); err != nil {
		t.Fatal(err)
	}
	if err := m.w.restored(context.Background(), m.r, m.name); err != nil {
		t.Fatal(err)
	}
	i, _, _ := m.w.read(m.r, m.name)
	if err := os.WriteFile(m.unit, i.Unit, 0600); err != nil {
		t.Fatal(err)
	}
	m.loaded = i.Unit
	before := len(m.mutations())
	if err := m.w.restored(context.Background(), m.r, m.name); err == nil {
		t.Fatal("original destructive wrapper accepted as completed retained wrapper")
	}
	if err := m.w.restore(context.Background(), m.r, m.name); err == nil {
		t.Fatal("completed restore repaired replaced unit")
	}
	if err := m.w.quiescent(context.Background(), m.r, m.name); err == nil {
		t.Fatal("quiescence verified destructive unit")
	}
	if len(m.mutations()) != before {
		t.Fatal("verification mutated services")
	}
}

func TestLegacyWrapperTransitionDockerAutomaticHostPIDLabel(t *testing.T) {
	m := wrapperFixture(t, "exporter", false, true, true)
	m.o.SecurityOpt = []string{"no-new-privileges", "label=disable"}
	if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
		t.Fatal(err)
	}
	m.o.SecurityOpt[0], m.o.SecurityOpt[1] = m.o.SecurityOpt[1], m.o.SecurityOpt[0]
	if err := m.w.quiescent(context.Background(), m.r, m.name); err != nil {
		t.Fatal("option ordering changed ownership proof", err)
	}
	m.r.Phase = "restore"
	if err := m.w.restore(context.Background(), m.r, m.name); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyWrapperTransitionDoesNotAcceptArbitrarySecurityOptions(t *testing.T) {
	for _, kind := range []string{"missing-nnp", "duplicate-nnp", "duplicate-label", "seccomp", "different-label", "vector-label"} {
		t.Run(kind, func(t *testing.T) {
			role, options := "exporter", []string{"no-new-privileges", "label=disable"}
			switch kind {
			case "missing-nnp":
				options = []string{"label=disable"}
			case "duplicate-nnp":
				options = []string{"no-new-privileges", "no-new-privileges=true"}
			case "duplicate-label":
				options = append(options, "label=disable")
			case "seccomp":
				options = append(options, "seccomp=unconfined")
			case "different-label":
				options[1] = "label=type:unconfined_t"
			case "vector-label":
				role = "vector"
			}
			m := wrapperFixture(t, role, false, true, true)
			m.o.SecurityOpt = options
			if err := m.w.quiesce(context.Background(), m.r, m.name); err == nil || len(m.mutations()) != 0 {
				t.Fatal("unrelated security override accepted", err)
			}
		})
	}
}

func TestLegacyWrapperTransitionStopsOrphanOnlyByCapturedID(t *testing.T) {
	m := wrapperFixture(t, "vector", false, true, false)
	if _, err := m.w.capture(context.Background(), m.r, m.name); err != nil {
		t.Fatal(err)
	}
	m.running = false // Original Docker client disappeared; its object survives.
	m.lose = "docker-stop"
	if err := m.w.quiesce(context.Background(), m.r, m.name); err == nil || !m.lost {
		t.Fatal("lost-response fixture not exercised", err)
	}
	if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
		t.Fatal(err)
	}
	stops := 0
	for _, call := range m.mutations() {
		if strings.HasPrefix(call, "docker ") {
			if call != "docker --host unix:///var/run/docker.sock stop --time 60 "+m.o.Identity.ID {
				t.Fatal("changed unbound Docker object", call)
			}
			stops++
		}
	}
	if stops != 1 {
		t.Fatal("repeated stop after lost success", stops)
	}
	m.r.Phase = "restore"
	if err := m.w.restore(context.Background(), m.r, m.name); err != nil || !m.running || m.enabled {
		t.Fatal("original manual running state not restored", err)
	}
}
