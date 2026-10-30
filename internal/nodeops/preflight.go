package nodeops

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// LocalPreflight has no install actions. It does not listen on a port, install
// packages, stop services, contact a registry or alter firewall configuration.
// A complete deployment must additionally verify connections from the collector
// network and verify its artifact/rules bundle before any service switch.
type LocalPreflight struct{}

func (LocalPreflight) Supports(phase string) bool { return phase == "preflight" }
func (LocalPreflight) Reconcile(r Request) (string, Outcome, error) {
	// Rechecking an interrupted read-only probe cannot duplicate installation.
	return "absent", Outcome{}, nil
}
func (LocalPreflight) Apply(r Request) (Outcome, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out := localChecks(ctx, r.Spec)
	for _, c := range out.Checks {
		if c.Status == "failed" || c.Status == "unknown" {
			return out, Failure{"preflight-failed"}
		}
	}
	return out, nil
}
func localChecks(ctx context.Context, spec Spec) Outcome {
	out := Outcome{}
	add := func(id, status, code string) {
		out.Checks = append(out.Checks, Check{ID: id, Status: status, Code: code})
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		add("platform", "failed", "requires-linux-amd64")
	} else {
		add("platform", "passed", "linux-amd64")
	}
	if os.Geteuid() != 0 {
		add("root", "failed", "requires-root")
	} else {
		add("root", "passed", "root")
	}
	for i, path := range spec.MonitorDirectories {
		id := "monitor-directory-" + strconv.Itoa(i+1)
		st, err := os.Stat(path)
		if err != nil || !st.IsDir() {
			add(id, "failed", "directory-missing-or-inaccessible")
			continue
		}
		if err = unix.Access(path, unix.R_OK|unix.X_OK); err != nil {
			add(id, "failed", "directory-not-readable")
		} else {
			add(id, "passed", "directory-accessible")
		}
	}
	required := uint64(512<<20) + (spec.ArtifactBytes+spec.ImageArchiveBytes)*2
	if st, err := os.Lstat("/var/lib/webscan-v1/agent.sqlite3"); err == nil {
		if !st.Mode().IsRegular() || st.Size() < 0 {
			add("database-file", "failed", "agent-database-not-regular")
		} else {
			if uint64(st.Size()) > (^uint64(0)-required)/2 {
				required = ^uint64(0)
			} else {
				required += uint64(st.Size()) * 2
			}
		}
	} else if !os.IsNotExist(err) {
		add("database-file", "failed", "agent-database-inaccessible")
	}
	path := "/var/lib/webscan-v1"
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if path == "/" {
			break
		}
		path = filepath.Dir(path)
	}
	free, inodes, err := filesystemFree(path)
	if err != nil {
		add("disk", "unknown", "disk-stat-unavailable")
	} else {
		status, code := "passed", "disk-space-available"
		if free < required {
			status, code = "failed", "insufficient-disk-space"
		}
		out.Checks = append(out.Checks, Check{"disk", status, code, free, required})
		status, code = "passed", "inodes-available"
		if inodes < 4096 {
			status, code = "failed", "insufficient-inodes"
		}
		out.Checks = append(out.Checks, Check{"inodes", status, code, inodes, 4096})
	}
	if spec.Mode == "native" {
		raw, err := readonlyCommand(ctx, "systemctl", "--version")
		fields := strings.Fields(raw)
		version := 0
		if len(fields) > 1 {
			version, _ = strconv.Atoi(fields[1])
		}
		if err != nil || version < 231 {
			add("systemd", "failed", "requires-systemd-231")
		} else {
			if _, err = os.Stat("/run/systemd/system"); err != nil {
				add("systemd", "failed", "systemd-not-running")
			} else if raw, err = readonlyCommand(ctx, "systemctl", "show", "--property=Version", "--value"); err != nil || strings.TrimSpace(raw) == "" {
				add("systemd", "failed", "systemd-manager-unavailable")
			} else {
				add("systemd", "passed", "systemd-available")
			}
		}
		cpu, memory := resourceControllers()
		if !cpu {
			add("cpu-control", "failed", "cpu-controller-unavailable")
		} else {
			add("cpu-control", "passed", "cpu-controller-available")
		}
		if !memory {
			add("memory-control", "failed", "memory-controller-unavailable")
		} else {
			add("memory-control", "passed", "memory-controller-available")
		}
	} else {
		if _, err := exec.LookPath("docker"); err != nil {
			add("docker", "failed", "docker-not-installed")
		} else if _, err = readonlyCommand(ctx, "docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
			add("docker", "failed", "docker-service-unavailable")
		} else {
			add("docker", "passed", "docker-available")
		}
		if _, err := readonlyCommand(ctx, "docker", "compose", "version", "--short"); err != nil {
			add("compose", "failed", "compose-unavailable")
		} else {
			add("compose", "passed", "compose-available")
		}
	}
	if spec.ClamAV {
		if _, err := exec.LookPath("clamdscan"); err != nil && !spec.bundleValid() {
			add("clamav", "failed", "clamav-client-unavailable")
		} else {
			conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", "/run/clamav/clamd.ctl")
			if err != nil {
				add("clamav", "failed", "clamd-unavailable")
			} else {
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, err = conn.Write([]byte("zPING\x00"))
				var b [64]byte
				n, e := conn.Read(b[:])
				conn.Close()
				if err != nil || e != nil || !strings.HasPrefix(string(b[:n]), "PONG") {
					add("clamav", "failed", "clamd-ping-failed")
				} else {
					add("clamav", "passed", "clamd-available")
				}
			}
		}
	}
	// /proc inspection cannot establish cloud ingress or ownership of a listener.
	// Report occupation without terminating it or claiming its identity is known.
	occupied, known := metricsListener(spec.MetricsPort)
	if !known {
		add("metrics-port", "unknown", "listener-table-unavailable")
	} else if occupied {
		add("metrics-port", "warning", "port-in-use-needs-network-verification")
	} else {
		add("metrics-port", "passed", "port-not-listening")
	}
	return out
}
func readonlyCommand(ctx context.Context, name string, args ...string) (string, error) {
	probe, stop := context.WithTimeout(ctx, 8*time.Second)
	defer stop()
	cmd := exec.CommandContext(probe, name, args...)
	// Output goes through a bounded sink and is interpreted locally, never copied
	// into task logs or API responses.
	b := &boundedOutput{}
	cmd.Stdout = b
	cmd.Stderr = nil
	err := cmd.Run()
	return string(b.raw), err
}

type boundedOutput struct{ raw []byte }

func (b *boundedOutput) Write(raw []byte) (int, error) {
	n := len(raw)
	free := 8192 - len(b.raw)
	if free > 0 {
		b.raw = append(b.raw, raw[:min(free, len(raw))]...)
	}
	return n, nil
}
func filesystemFree(path string) (uint64, uint64, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return 0, 0, err
	}
	if fs.Bsize <= 0 {
		return 0, 0, fmt.Errorf("invalid-block-size")
	}
	blocks, size := uint64(fs.Bavail), uint64(fs.Bsize)
	if blocks > ^uint64(0)/size {
		return 0, 0, fmt.Errorf("disk-size-overflow")
	}
	return blocks * size, uint64(fs.Ffree), nil
}
func resourceControllers() (cpu, memory bool) {
	if raw, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		for _, c := range strings.Fields(string(raw)) {
			if c == "cpu" {
				cpu = true
			}
			if c == "memory" {
				memory = true
			}
		}
		return
	}
	for _, p := range []string{"/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us"} {
		if _, err := os.Stat(p); err == nil {
			cpu = true
		}
	}
	_, err := os.Stat("/sys/fs/cgroup/memory/memory.limit_in_bytes")
	memory = err == nil
	return
}
func metricsListener(port int) (occupied, known bool) {
	return listenerTables(port, []string{"/proc/net/tcp", "/proc/net/tcp6"})
}

func listenerTables(port int, paths []string) (occupied, known bool) {
	known = true
	read := false
	for i, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			// Linux may omit tcp6 when IPv6 support is disabled. An unreadable
			// table, including a missing IPv4 table, is not proof of a free port.
			if i == 0 || !os.IsNotExist(err) {
				known = false
			}
			continue
		}
		read = true
		if !strings.Contains(string(raw), "local_address") {
			known = false
			continue
		}
		for _, line := range strings.Split(string(raw), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				continue
			}
			p, err := strconv.ParseInt(parts[1], 16, 32)
			if err == nil && int(p) == port {
				occupied = true
			}
		}
	}
	return occupied, known && read
}
