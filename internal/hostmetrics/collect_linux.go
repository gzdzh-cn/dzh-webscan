//go:build linux

// Package hostmetrics collects the fixed set of Linux metrics used by Webscan.
package hostmetrics

import (
	"bufio"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Paths struct{ Proc, Sys, Root string }

func (p Paths) defaults() Paths {
	if p.Proc == "" {
		p.Proc = "/proc"
	}
	if p.Sys == "" {
		p.Sys = "/sys"
	}
	if p.Root == "" {
		p.Root = "/"
	}
	return p
}
func Collect(p Paths) string {
	p = p.defaults()
	var out strings.Builder
	emit := func(name string, v float64, labels ...string) {
		fmt.Fprintf(&out, "%s", name)
		if len(labels) > 0 {
			out.WriteByte('{')
			for i := 0; i < len(labels); i += 2 {
				if i > 0 {
					out.WriteByte(',')
				}
				fmt.Fprintf(&out, "%s=%q", labels[i], labels[i+1])
			}
			out.WriteByte('}')
		}
		fmt.Fprintf(&out, " %g\n", v)
	}
	read := func(name string) (string, error) {
		f, e := os.Open(filepath.Join(p.Proc, name))
		if e != nil {
			return "", e
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, (4<<20)+1))
		if len(b) > 4<<20 {
			return "", fmt.Errorf("proc file exceeds limit")
		}
		return string(b), e
	}
	check := func(name string, e error) {
		v := 0.
		if e != nil {
			v = 1
		}
		emit("webscan_host_collector_error", v, "collector", name)
	}
	raw, e := read("stat")
	check("cpu", e)
	if e == nil {
		for _, line := range strings.Split(raw, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			if f[0] == "btime" {
				v, _ := strconv.ParseFloat(f[1], 64)
				emit("node_boot_time_seconds", v)
			}
			if strings.HasPrefix(f[0], "cpu") && f[0] != "cpu" {
				if _, err := strconv.Atoi(strings.TrimPrefix(f[0], "cpu")); err != nil {
					continue
				}
				for i, mode := range []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice"} {
					if i+1 < len(f) {
						v, err := strconv.ParseFloat(f[i+1], 64)
						if err == nil {
							// Linux includes guest time in user/nice; exporter counters
							// expose those states separately, so subtract it here.
							if i < 2 && len(f) > i+9 {
								guest, err := strconv.ParseFloat(f[i+9], 64)
								if err == nil {
									v = max(0, v-guest)
								}
							}
							emit("node_cpu_seconds_total", v/100, "cpu", strings.TrimPrefix(f[0], "cpu"), "mode", mode)
						}
					}
				}
			}
		}
	}
	raw, e = read("meminfo")
	check("memory", e)
	if e == nil {
		for _, line := range strings.Split(raw, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			name := strings.TrimSuffix(f[0], ":")
			if name == "MemTotal" || name == "MemAvailable" || name == "SwapTotal" || name == "SwapFree" {
				v, err := strconv.ParseFloat(f[1], 64)
				if err == nil {
					emit("node_memory_"+name+"_bytes", v*1024)
				}
			}
		}
	}
	raw, e = read("loadavg")
	check("load", e)
	if e == nil {
		f := strings.Fields(raw)
		for i, name := range []string{"node_load1", "node_load5", "node_load15"} {
			if i < len(f) {
				v, err := strconv.ParseFloat(f[i], 64)
				if err == nil {
					emit(name, v)
				}
			}
		}
	}
	raw, e = read("diskstats")
	check("disk", e)
	if e == nil {
		for _, line := range strings.Split(raw, "\n") {
			f := strings.Fields(line)
			if len(f) < 14 {
				continue
			}
			dev := f[2]
			_, partition := os.Stat(filepath.Join(p.Sys, "class/block", dev, "partition"))
			if partition == nil || strings.HasPrefix(dev, "loop") || strings.HasPrefix(dev, "ram") {
				continue
			}
			for _, x := range []struct {
				name  string
				index int
				scale float64
			}{{"reads_completed", 3, 1}, {"read_bytes", 5, 512}, {"writes_completed", 7, 1}, {"written_bytes", 9, 512}} {
				v, err := strconv.ParseFloat(f[x.index], 64)
				if err == nil {
					emit("node_disk_"+x.name+"_total", v*x.scale, "device", dev)
				}
			}
		}
	}
	// /proc/net follows the caller's network namespace. PID 1 is the host's
	// namespace when /proc is bind-mounted, including a bridge-networked center.
	raw, e = read("1/net/dev")
	check("network", e)
	if e == nil {
		for _, line := range strings.Split(raw, "\n") {
			name, values, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			f := strings.Fields(values)
			if len(f) < 16 {
				continue
			}
			for _, x := range []struct {
				name  string
				index int
			}{{"receive_bytes", 0}, {"receive_errs", 2}, {"receive_drop", 3}, {"transmit_bytes", 8}, {"transmit_errs", 10}, {"transmit_drop", 11}} {
				v, err := strconv.ParseFloat(f[x.index], 64)
				if err == nil {
					emit("node_network_"+x.name+"_total", v, "device", strings.TrimSpace(name))
				}
			}
		}
	}
	raw, e = read("1/mountinfo")
	check("filesystem", e)
	if e == nil {
		seen := map[string]bool{}
		scan := bufio.NewScanner(strings.NewReader(raw))
		for scan.Scan() {
			left, right, ok := strings.Cut(scan.Text(), " - ")
			if !ok {
				continue
			}
			f, r := strings.Fields(left), strings.Fields(right)
			if len(f) < 5 || len(r) < 2 {
				continue
			}
			mount := unescape(f[4])
			fs := r[0]
			if seen[mount] || excluded(fs, mount) {
				continue
			}
			seen[mount] = true
			if len(seen) > 128 {
				check("filesystem_limit", fmt.Errorf("too many mounts"))
				break
			}
			var st unix.Statfs_t
			err := unix.Statfs(filepath.Join(p.Root, mount), &st)
			if err != nil {
				emit("webscan_host_collector_error", 1, "collector", "filesystem:"+mount)
				continue
			}
			for _, x := range []struct {
				name  string
				value float64
			}{{"size_bytes", float64(st.Blocks) * float64(st.Bsize)}, {"avail_bytes", float64(st.Bavail) * float64(st.Bsize)}, {"files", float64(st.Files)}, {"files_free", float64(st.Ffree)}} {
				emit("node_filesystem_"+x.name, x.value, "device", unescape(r[1]), "mountpoint", mount, "fstype", fs)
			}
		}
	}
	var u unix.Utsname
	e = unix.Uname(&u)
	check("uname", e)
	if e == nil {
		emit("node_uname_info", 1, "sysname", cstring(u.Sysname[:]), "release", cstring(u.Release[:]), "version", cstring(u.Version[:]), "machine", cstring(u.Machine[:]), "nodename", hostName(p.Root, u.Nodename[:]))
	}
	var tx unix.Timex
	_, e = unix.Adjtimex(&tx)
	check("time", e)
	if e == nil {
		v := 1.
		if tx.Status&unix.STA_UNSYNC != 0 {
			v = 0
		}
		emit("node_timex_sync_status", v)
		scale := 1e-6
		if tx.Status&unix.STA_NANO != 0 {
			scale = 1e-9
		}
		emit("node_timex_offset_seconds", float64(tx.Offset)*scale)
	}
	return out.String()
}
func cstring(b []byte) string { return strings.TrimRight(string(b), "\x00") }
func hostName(root string, fallback []byte) string {
	if b, e := os.ReadFile(filepath.Join(root, "etc/hostname")); e == nil && len(b) < 256 {
		return strings.TrimSpace(string(b))
	}
	return cstring(fallback)
}
func unescape(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}
func excluded(fs, m string) bool {
	switch fs {
	case "proc", "sysfs", "tmpfs", "devtmpfs", "devpts", "overlay", "squashfs", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs", "pstore", "mqueue", "hugetlbfs", "configfs", "fusectl", "autofs", "nfs", "nfs4", "cifs", "smb3":
		return true
	}
	return strings.HasPrefix(fs, "fuse") || strings.HasPrefix(m, "/var/lib/docker/") || strings.HasPrefix(m, "/var/lib/containerd/") || strings.HasPrefix(m, "/proc/") || strings.HasPrefix(m, "/sys/")
}
