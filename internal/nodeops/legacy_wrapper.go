package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// PRIVATE evidence for the exact v2 InstallNodeSidecars templates. Parsing a
// wrapper is not permission to start it: its ExecStartPre removes/recreates the
// container, which is incompatible with the current exact-ID rollback driver.
type legacySidecarUnit struct {
	Role        string
	SourceImage string
	TLS         bool
	MetricsPort int
}

func (u legacySidecarUnit) alias() string {
	if u.Role == "vector" {
		return "docker.io/timberio/vector:0.45.0-alpine"
	}
	return "docker.io/prom/node-exporter:v1.9.1"
}

// These tokens never pass through a shell. Also reject systemd's environment
// and specifier syntax; a syntactically familiar unit must not hide expansion.
var legacyImageToken = regexp.MustCompile(`^[a-z0-9][a-zA-Z0-9./:@_-]{0,511}$`)

func (u legacySidecarUnit) valid() bool {
	return (u.Role == "vector" && u.MetricsPort == 0 || u.Role == "exporter" && u.MetricsPort >= 1 && u.MetricsPort <= 65535) &&
		legacyImageToken.MatchString(u.SourceImage) && !strings.Contains(u.SourceImage, "..") && !strings.Contains(u.SourceImage, "//")
}

func (u legacySidecarUnit) runArguments() []string {
	args := []string{"run", "--pull", "never", "--name", "webscan-" + u.Role + "-v1", "--network", "host", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--log-opt", "max-size=10m", "--log-opt", "max-file=3"}
	if u.Role == "vector" {
		args = append(args, "-v", "/etc/webscan-v1/vector.yml:/etc/vector/vector.yaml:ro")
		if u.TLS {
			args = append(args, "-v", "/etc/webscan-v1/pki/ca.crt:/etc/webscan-v1/pki/ca.crt:ro")
		}
		args = append(args, "-v", "/var/log/webscan-v1:/var/log/webscan-v1:ro", "-v", "/var/lib/webscan-vector-v1:/var/lib/vector", u.alias())
	} else {
		args = append(args, "--user", "0:0", "--pid", "host", "-v", "/proc:/host/proc:ro", "-v", "/sys:/host/sys:ro", "-v", "/:/rootfs:ro,rslave", "-v", "/var/lib/webscan-v1/textfile:/textfile:ro", "-v", "/etc/webscan-v1/exporter.yml:/etc/webscan-v1/exporter.yml:ro")
		if u.TLS {
			args = append(args, "-v", "/etc/webscan-v1/pki:/etc/webscan-v1/pki:ro")
		}
		args = append(args, u.alias(), "--web.listen-address=:"+strconv.Itoa(u.MetricsPort), "--web.config.file=/etc/webscan-v1/exporter.yml", "--path.procfs=/host/proc", "--path.sysfs=/host/sys", "--path.rootfs=/rootfs", "--collector.textfile.directory=/textfile")
	}
	return args
}

func (u legacySidecarUnit) definition() []byte {
	return []byte(fmt.Sprintf("[Unit]\nDescription=Webscan %s\nRequires=docker.service\nPartOf=docker.service\nAfter=docker.service network-online.target\n[Service]\nExecStartPre=/usr/bin/docker image tag %s %s\nExecStartPre=-/usr/bin/docker rm -f webscan-%s-v1\nExecStart=/usr/bin/docker %s\nExecStop=/usr/bin/docker stop -t 20 webscan-%s-v1\nRestart=always\nRestartSec=5\nTimeoutStopSec=35\n[Install]\nWantedBy=multi-user.target docker.service\n", u.Role, u.SourceImage, u.alias(), u.Role, strings.Join(u.runArguments(), " "), u.Role))
}

func parseLegacySidecarUnit(name string, raw []byte) (legacySidecarUnit, error) {
	var u legacySidecarUnit
	switch name {
	case "webscan-vector-v1.service":
		u.Role = "vector"
	case "webscan-exporter-v1.service":
		u.Role = "exporter"
	default:
		return u, errors.New("legacy-wrapper-not-owned")
	}
	if len(raw) == 0 || len(raw) > 64<<10 {
		return u, errors.New("legacy-wrapper-not-owned")
	}
	// Extract only the variable source and port, then compare EVERY byte against
	// the generated template. Duplicate sections/keys, hooks, CRLF, whitespace,
	// extra mounts, newlines and systemd expansions are never normalized away.
	for _, line := range strings.Split(string(raw), "\n") {
		if source, ok := strings.CutPrefix(line, "ExecStartPre=/usr/bin/docker image tag "); ok {
			u.SourceImage, _, _ = strings.Cut(source, " ")
		}
		if _, value, ok := strings.Cut(line, " --web.listen-address=:"); ok {
			port, _, _ := strings.Cut(value, " ")
			u.MetricsPort, _ = strconv.Atoi(port)
		}
	}
	for _, tls := range []bool{false, true} {
		u.TLS = tls
		if u.valid() && bytes.Equal(raw, u.definition()) {
			return u, nil
		}
	}
	return u, errors.New("legacy-wrapper-not-owned")
}

// Legacy units were generated mode 0644. They contain no private material;
// this reader is deliberately separate from readPrivate, whose credential and
// backup permission requirements must remain unchanged. Only fixed legacy
// unit names are accepted. Production lifecycle commands separately require root.
func readLegacyWrapperUnit(path string) ([]byte, error) {
	name := filepath.Base(path)
	if name != "webscan-agent-v1.service" && name != "webscan-vector-v1.service" && name != "webscan-exporter-v1.service" {
		return nil, errors.New("legacy-wrapper-not-owned")
	}
	if err := directoryAncestors(filepath.Dir(path)); err != nil {
		return nil, errors.New("unsafe-legacy-wrapper")
	}
	var parent unix.Stat_t
	if unix.Lstat(filepath.Dir(path), &parent) != nil || parent.Uid != uint32(os.Geteuid()) || parent.Mode&0022 != 0 {
		return nil, errors.New("unsafe-legacy-wrapper")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("unsafe-legacy-wrapper")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var opened, named unix.Stat_t
	if unix.Fstat(fd, &opened) != nil || unix.Lstat(path, &named) != nil || opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Uid != uint32(os.Geteuid()) || opened.Nlink != 1 || opened.Dev != named.Dev || opened.Ino != named.Ino || opened.Mode&07777 != 0600 && opened.Mode&07777 != 0644 || opened.Size <= 0 || opened.Size > 64<<10 {
		return nil, errors.New("unsafe-legacy-wrapper")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	var after unix.Stat_t
	if err != nil || int64(len(raw)) != opened.Size || unix.Fstat(fd, &after) != nil || unix.Lstat(path, &named) != nil {
		return nil, errors.New("legacy-wrapper-changed")
	}
	// Reading may update atime. All other identity, ownership, permissions,
	// size, modification and change-time evidence must remain the same.
	opened.Atim, named.Atim = after.Atim, after.Atim
	if after != opened || named != opened {
		return nil, errors.New("legacy-wrapper-changed")
	}
	return raw, nil
}

func (h installationHost) checkLegacyWrappers(ctx context.Context) error {
	return h.checkLegacyWrappersWithEvidence(ctx, "", nil)
}

var legacyWrapperNames = []string{"webscan-vector-v1.service", "webscan-exporter-v1.service"}

func (h installationHost) checkLegacyWrappersWithEvidence(ctx context.Context, node string, wrappers map[string]legacyWrapperIntent) error {
	_, err := h.inspectLegacyWrappers(ctx, node, wrappers)
	return err
}

func (h installationHost) inspectLegacyWrappers(ctx context.Context, node string, wrappers map[string]legacyWrapperIntent) (map[string]legacyWrapperIntent, error) {
	return h.inspectLegacyWrapperProofs(ctx, node, wrappers, false)
}

// observed is used only by read-only preflight. It never grants stop authority.
func (h installationHost) inspectLegacyWrapperProofs(ctx context.Context, node string, wrappers map[string]legacyWrapperIntent, observed bool) (map[string]legacyWrapperIntent, error) {
	parked := map[string]legacyWrapperIntent{}
	if len(wrappers) > 2 {
		return nil, errors.New("legacy-wrapper-intent-invalid")
	}
	for name, i := range wrappers {
		if name != "webscan-vector-v1.service" && name != "webscan-exporter-v1.service" || i.Binding.Node != node || !idPattern.MatchString(i.Binding.Job) || !validDigest(i.Binding.Plan) || !validDigest(i.Binding.Spec) {
			return nil, errors.New("legacy-wrapper-intent-invalid")
		}
		// Mutation inventory requires the canonical immutable capture. The separate
		// read-only observer verifies the same current proofs without publication.
		var saved legacyWrapperIntent
		raw, err := decodePrivateJSON(filepath.Join(h.root, "transitions", i.Binding.Job, "wrappers", name, "intent.json"), &saved, MaxRequestBytes)
		want, _ := json.Marshal(i)
		if observed {
			raw, err = want, nil
		}
		u, parseErr := parseLegacySidecarUnit(name, i.Unit)
		if err != nil || !bytes.Equal(raw, want) || parseErr != nil || i.Format != 1 || i.UnitPath != filepath.Join(filepath.Dir(h.unitPath), name) || i.RuntimePath != filepath.Join(h.configRoot, "runtime.json") || !validDigest(i.RuntimeSHA256) || validateLegacyWrapperObject(u, i.Object, i.Image) != nil || i.Running != (i.Object.Identity.Status == "running") {
			return nil, errors.New("legacy-wrapper-intent-invalid")
		}
		w := legacyWrapperTransition{h}
		s, o, err := w.state(ctx, Request{Node: node}, i, false)
		if err != nil || (s.MainPID > 0) != i.Running || (s.UnitFileState == "enabled") != i.Enabled || (o.Identity.Status == "running") != i.Running {
			return nil, errors.New("legacy-wrapper-original-state-changed")
		}
	}
	for _, name := range []string{"webscan-agent-v1.service", "webscan-vector-v1.service", "webscan-exporter-v1.service"} {
		if _, proven := wrappers[name]; proven {
			continue
		}
		path := filepath.Join(filepath.Dir(h.unitPath), name)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			if name != "webscan-agent-v1.service" {
				authority, _ := (legacyWrapperTransition{h}).authorityPath(name)
				if _, err := os.Lstat(authority); !os.IsNotExist(err) {
					return nil, errors.New("retained-wrapper-unit-missing")
				}
			}
			continue
		} else if err != nil {
			return nil, errors.New("unsafe-legacy-wrapper")
		}
		unit, err := readLegacyWrapperUnit(path)
		if err != nil {
			return nil, err
		}
		if _, err := parseLegacySidecarUnit(name, unit); err != nil {
			w := legacyWrapperTransition{h}
			i, status, err := w.retainedState(ctx, node, name)
			if err != nil {
				return nil, err
			}
			if status.MainPID != 0 || status.UnitFileState != "disabled" {
				return nil, errors.New("legacy-wrapper-transition-not-supported")
			}
			parked[name] = i
			continue
		}
		if err := (legacyWrapperTransition{h}).rejectExistingAuthority(name); err != nil {
			return nil, err
		}
		raw, err := h.command(ctx, "systemctl", "show", name, "--property=LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,Job,MainPID")
		if err != nil {
			return nil, errors.New("legacy-wrapper-state-unavailable")
		}
		status, err := parseNativeStatus(raw)
		if err != nil || status.FragmentPath != path || status.MainPID != 0 || status.UnitFileState != "disabled" {
			return nil, errors.New("legacy-wrapper-transition-not-supported")
		}
		// Refuse changed unit contents while manager state was inspected.
		current, err := readLegacyWrapperUnit(path)
		if err != nil || !bytes.Equal(unit, current) {
			return nil, errors.New("legacy-wrapper-changed")
		}
	}
	return parked, nil
}
