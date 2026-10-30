package nodeops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"webscan/internal/common"
)

// Installation is PRIVATE deployment evidence. Runtime/config files may hold
// legacy push credentials and must never be returned as an API/task outcome.
// A service name alone is not proof that it is safe to stop that service.
type Installation struct {
	Node       string          `json:"node"`
	Generation string          `json:"generation"` // absent, v2, v3
	Mode       string          `json:"mode,omitempty"`
	Runtime    string          `json:"runtime,omitempty"`
	Services   []ServiceRecord `json:"services"`
	// Private references to same-task immutable sidecar captures. Ordinary
	// single-Agent lifecycle drivers cannot adopt or operate such a group.
	Wrappers []legacyWrapperMember `json:"wrappers,omitempty"`
	Sidecars []legacyComposeMember `json:"sidecars,omitempty"`
}

type legacyWrapperMember struct {
	Name         string `json:"name"`
	IntentSHA256 string `json:"intent_sha256"`
}

type ServiceRecord struct {
	Kind          string `json:"kind"` // native, docker
	Name          string `json:"name"`
	ID            string `json:"id"` // Docker's immutable ID, not its reusable name
	Proof         string `json:"proof"`
	Running       bool   `json:"running"`
	Enabled       bool   `json:"enabled"`
	Restart       string `json:"restart,omitempty"`
	MaxRetries    int    `json:"max_retries,omitempty"`
	Program       string `json:"program,omitempty"`
	Configuration string `json:"configuration,omitempty"`
}

func (i Installation) valid(node string) bool {
	if i.Node != node || !idPattern.MatchString(node) || len(i.Services) > 4 || len(i.Wrappers) > 2 || len(i.Sidecars) > 2 || len(i.Wrappers) > 0 && len(i.Sidecars) > 0 {
		return false
	}
	if i.Generation == "absent" {
		return i.Mode == "" && i.Runtime == "" && len(i.Services) == 0 && !hasLegacyMembers(i)
	}
	if i.Generation != "v2" && i.Generation != "v3" || (i.Mode != "native" && i.Mode != "docker") || !safeServicePath(i.Runtime) {
		return false
	}
	seen := map[string]bool{}
	for _, w := range i.Wrappers {
		if i.Generation != "v2" || w.Name != "webscan-vector-v1.service" && w.Name != "webscan-exporter-v1.service" || seen[w.Name] || !validDigest(w.IntentSHA256) {
			return false
		}
		seen[w.Name] = true
	}
	for _, m := range i.Sidecars {
		if i.Generation != "v2" || i.Mode != "docker" || !composeSidecarName(m.Name) || seen[m.Name] || !validDigest(m.IntentSHA256) {
			return false
		}
		seen[m.Name] = true
	}
	identities := map[string]bool{}
	for _, s := range i.Services {
		if !validDigest(s.Proof) || seen[s.Kind+":"+s.Name] || identities[s.Kind+":"+s.ID] || s.MaxRetries < 0 {
			return false
		}
		seen[s.Kind+":"+s.Name] = true
		identities[s.Kind+":"+s.ID] = true
		if s.Kind == "native" {
			if s.Name != nativeServiceName || s.ID != nativeServiceName || s.Restart != "" || s.MaxRetries != 0 || !safeServicePath(s.Program) || !safeServicePath(s.Configuration) {
				return false
			}
		} else if s.Kind == "docker" {
			if seen[s.Name] || !validDigest(s.ID) || !knownContainer(s.Name) || !validRestart(s.Restart) || s.Program != "" || s.Configuration != "" || s.Enabled != (s.Restart != "no") || (s.Restart != "on-failure" && s.MaxRetries != 0) {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func knownContainer(name string) bool {
	return name == agentContainerName || name == "webscan-vector-v1" || name == "webscan-exporter-v1"
}
func validRestart(s string) bool {
	return s == "no" || s == "always" || s == "unless-stopped" || s == "on-failure"
}

type nativeStatus struct {
	LoadState, ActiveState, SubState, FragmentPath, DropInPaths, NeedDaemonReload, UnitFileState, Job string
	MainPID                                                                                           int
}

func parseNativeStatus(raw string) (nativeStatus, error) {
	return decodeNativeStatus(raw, false, false)
}

func decodeNativeStatus(raw string, allowReload, allowAbsent bool) (nativeStatus, error) {
	var s nativeStatus
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if _, duplicate := fields[k]; !ok || duplicate {
			return s, errors.New("invalid-native-status")
		}
		fields[k] = v
	}
	for _, key := range []string{"LoadState", "ActiveState", "SubState", "FragmentPath", "DropInPaths", "NeedDaemonReload", "UnitFileState", "Job", "MainPID"} {
		if _, present := fields[key]; !present {
			return s, errors.New("invalid-native-status")
		}
	}
	if len(fields) != 9 {
		return s, errors.New("invalid-native-status")
	}
	s.LoadState, s.ActiveState, s.SubState = fields["LoadState"], fields["ActiveState"], fields["SubState"]
	s.FragmentPath, s.DropInPaths, s.NeedDaemonReload, s.UnitFileState, s.Job = fields["FragmentPath"], fields["DropInPaths"], fields["NeedDaemonReload"], fields["UnitFileState"], fields["Job"]
	var err error
	s.MainPID, err = strconv.Atoi(fields["MainPID"])
	// systemctl 252 renders the unset Job property as an empty value. Keep the
	// existing 0 representation compatible. Both mean no queued job; it must still
	// be present, and any nonzero ID or malformed value remains unsafe.
	if err != nil || s.MainPID < 0 || s.DropInPaths != "" || s.Job != "" && s.Job != "0" || s.NeedDaemonReload != "no" && !(allowReload && s.NeedDaemonReload == "yes") {
		return s, errors.New("native-service-identity-unknown")
	}
	if allowAbsent && s.LoadState == "not-found" && s.ActiveState == "inactive" && s.SubState == "dead" && s.MainPID == 0 && s.FragmentPath == "" && s.UnitFileState == "" {
		return s, nil
	}
	if s.LoadState != "loaded" {
		return s, errors.New("native-service-identity-unknown")
	}
	if (s.ActiveState == "active" && s.SubState == "running" && s.MainPID > 0) || ((s.ActiveState == "inactive" || s.ActiveState == "failed") && s.MainPID == 0) {
		return s, nil
	}
	return s, errors.New("native-service-transition-pending")
}

type containerIdentity struct {
	ID, Name, Image, ImageID, Project, Service, Managed, Node, Configuration string
	Entrypoint, Command                                                      []string
	Mounts                                                                   []struct {
		Type                string
		Source, Destination string
		RW                  bool
	}
	Status, Restart string
	MaxRetries      int
}

func (c containerIdentity) fingerprint() string {
	// Deliberately omit mutable running/restart/name state. Stop and rename may
	// change those after intent is durable, but must not change the object ID,
	// image, command, project/node identity, or host mounts.
	c.Name, c.Status, c.Restart, c.MaxRetries = "", "", "", 0
	// Docker assembles Mounts from a map: independent inspect calls can return
	// the same mounts in different orders. Canonicalize a copy, preserving every
	// mount and access bit without modifying the caller's inspection evidence.
	c.Mounts = append(c.Mounts[:0:0], c.Mounts...)
	sort.Slice(c.Mounts, func(i, j int) bool {
		a, b := c.Mounts[i], c.Mounts[j]
		for _, pair := range [][2]string{{a.Destination, b.Destination}, {a.Source, b.Source}, {a.Type, b.Type}} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
		return !a.RW && b.RW
	})
	raw, _ := json.Marshal(c)
	return sha(raw)
}

func verifyLegacyContainer(c containerIdentity, service, project, image string, runtimeRoot string) error {
	if !knownContainer(strings.TrimPrefix(c.Name, "/")) || !validDigest(c.ID) || !strings.HasPrefix(c.ImageID, "sha256:") || !validDigest(strings.TrimPrefix(c.ImageID, "sha256:")) || project == "" || c.Project != project || c.Service != service || c.Image != image || !validRestart(c.Restart) || c.MaxRetries < 0 {
		return errors.New("container-ownership-not-proven")
	}
	if c.Status != "running" && c.Status != "exited" && c.Status != "created" {
		return errors.New("container-transition-pending")
	}
	if strings.TrimPrefix(c.Name, "/") == agentContainerName {
		if !equalStrings(c.Command, []string{"agent", "--config", filepath.Join(runtimeRoot, "runtime.json")}) || !equalStrings(c.Entrypoint, []string{"/usr/local/bin/webscan"}) {
			return errors.New("agent-command-not-owned")
		}
		needed := map[string]bool{runtimeRoot: false, agentDataDirectory: false, agentLogDirectory: false}
		for _, mount := range c.Mounts {
			if _, ok := needed[mount.Destination]; ok {
				if needed[mount.Destination] || mount.Source != mount.Destination || (mount.Destination == runtimeRoot && mount.RW) || (mount.Destination != runtimeRoot && !mount.RW) {
					return errors.New("agent-data-mount-not-owned")
				}
				needed[mount.Destination] = true
			}
		}
		for _, found := range needed {
			if !found {
				return errors.New("agent-data-mount-not-owned")
			}
		}
	}
	return nil
}

func equalStrings(a, b []string) bool {
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(aa, bb)
}

var legacyExec = regexp.MustCompile(`^ExecStart=(/opt/webscan-go/releases/v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?/webscan) agent --config /etc/webscan-v1/runtime.json$`)
var positiveInteger = regexp.MustCompile(`^[1-9][0-9]*$`)

func legacyNativeProgram(unit []byte, runtime common.Map) (string, error) {
	// Accept the existing generated v2 template exactly, not a loose search for
	// "webscan" in an otherwise arbitrary unit containing ExecStop hooks.
	values := map[string]string{}
	for _, line := range strings.Split(string(unit), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			if k == "Environment" {
				k += ":" + strings.SplitN(v, "=", 2)[0]
			}
			if _, duplicate := values[k]; duplicate {
				return "", errors.New("native-unit-not-owned")
			}
			values[k] = v
		}
	}
	match := legacyExec.FindStringSubmatch("ExecStart=" + values["ExecStart"])
	if len(match) != 2 {
		return "", errors.New("native-program-not-owned")
	}
	mem := strings.TrimSuffix(values["MemoryMax"], "M")
	goMem := strings.TrimSuffix(strings.TrimPrefix(values["Environment:GOMEMLIMIT"], "GOMEMLIMIT="), "MiB")
	goProcs := strings.TrimPrefix(values["Environment:GOMAXPROCS"], "GOMAXPROCS=")
	quota := strings.TrimSuffix(values["CPUQuota"], "%")
	n, err := strconv.ParseFloat(quota, 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 || n > 1600 || !positiveInteger.MatchString(mem) || !positiveInteger.MatchString(goMem) || !positiveInteger.MatchString(goProcs) {
		return "", errors.New("native-unit-not-owned")
	}
	probe := common.S(runtime["probe_directory"])
	if !safeServicePath(probe) {
		return "", errors.New("native-probe-not-owned")
	}
	want := fmt.Sprintf("[Unit]\nDescription=Webscan unified agent\nWants=network-online.target\nAfter=network-online.target\n[Service]\nType=simple\nUser=root\nUMask=0077\nExecStart=%s agent --config /etc/webscan-v1/runtime.json\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=60\nMemoryMax=%sM\nCPUQuota=%s%%\nEnvironment=GOMEMLIMIT=%sMiB\nEnvironment=GOMAXPROCS=%s\nLimitNOFILE=65536\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=/var/lib/webscan-v1 /var/log/webscan-v1 %s -/run/clamav\n[Install]\nWantedBy=multi-user.target\n", match[1], mem, quota, goMem, goProcs, strconv.Quote(strings.ReplaceAll(probe, "%", "%%")))
	if !bytes.Equal(unit, []byte(want)) {
		return "", errors.New("native-unit-not-owned")
	}
	return match[1], nil
}
