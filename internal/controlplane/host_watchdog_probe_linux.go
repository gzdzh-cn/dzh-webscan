//go:build linux

package controlplane

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type linuxHostWatchdogProbe struct {
	spec   HostWatchdogSpec
	pg     *sql.DB
	client *http.Client
}

func newHostWatchdogProbe(spec HostWatchdogSpec, pg *sql.DB) hostWatchdogProbe {
	return &linuxHostWatchdogProbe{spec, pg, &http.Client{Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (p *linuxHostWatchdogProbe) Check(ctx context.Context) ([]HostWatchdogCheck, HostWatchdogEnvironment) {
	out := make([]HostWatchdogCheck, 0, 4)
	for _, item := range []struct{ component, url string }{{"api", strings.TrimRight(p.spec.APIURL, "/") + "/healthz"}, {"metrics", strings.TrimRight(p.spec.MetricsURL, "/") + "/health"}} {
		started := time.Now()
		check := HostWatchdogCheck{Component: item.component, State: "abnormal", Reason: "health_endpoint_unavailable", ObservedAt: started.UTC()}
		req, err := http.NewRequestWithContext(ctx, "GET", item.url, nil)
		if err == nil {
			res, e := p.client.Do(req)
			if e == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
				res.Body.Close()
				if res.StatusCode == 200 {
					check.State, check.Reason = "normal", "health_endpoint_responded"
				}
			}
		}
		check.LatencyMilliseconds = time.Since(started).Milliseconds()
		out = append(out, check)
	}
	started := time.Now()
	check := HostWatchdogCheck{Component: "postgres", State: "abnormal", Reason: "database_unavailable", ObservedAt: started.UTC()}
	op, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	if p.pg != nil && p.pg.PingContext(op) == nil {
		check.State, check.Reason = "normal", "database_responded"
	}
	cancel()
	check.LatencyMilliseconds = time.Since(started).Milliseconds()
	out = append(out, check)
	env := hostLinuxEnvironment(p.spec)
	disk := HostWatchdogCheck{Component: "storage", State: "unknown", Reason: "storage_evidence_unavailable", ObservedAt: time.Now().UTC()}
	if len(env.Storage) == 3 {
		disk.State, disk.Reason = "normal", "storage_capacity_available"
	}
	for _, s := range env.Storage {
		if s.AvailableBytes < 256<<20 || s.Inodes > 0 && s.AvailableInodes < 128 {
			disk.State, disk.Reason = "abnormal", "storage_capacity_low"
		}
	}
	return append(out, disk), env
}
func hostLinuxEnvironment(spec HostWatchdogSpec) HostWatchdogEnvironment {
	env := HostWatchdogEnvironment{OS: "linux", Architecture: runtime.GOARCH, Storage: []HostWatchdogStorage{}}
	var uname unix.Utsname
	if unix.Uname(&uname) == nil {
		b := make([]byte, 0, len(uname.Release))
		for _, c := range uname.Release {
			if c == 0 {
				break
			}
			b = append(b, byte(c))
		}
		env.Kernel = string(b)
	}
	if raw, e := os.ReadFile("/proc/sys/kernel/random/boot_id"); e == nil {
		v := strings.TrimSpace(string(raw))
		if len(v) == 36 {
			env.BootID = v
		}
	}
	if raw, e := os.ReadFile("/proc/uptime"); e == nil {
		fields := strings.Fields(string(raw))
		if len(fields) > 0 {
			if v, e := strconv.ParseFloat(fields[0], 64); e == nil && v >= 0 {
				env.UptimeSeconds = &v
			}
		}
	}
	if raw, e := os.ReadFile("/proc/meminfo"); e == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) == 3 && f[0] == "MemTotal:" && f[2] == "kB" {
				if v, e := strconv.ParseUint(f[1], 10, 64); e == nil && v < 1<<54 {
					v *= 1024
					env.MemoryBytes = &v
				}
			}
		}
	}
	for _, item := range []struct{ component, path string }{{"watchdog_state", spec.StateDirectory}, {"postgres", filepath.Join(filepath.Dir(spec.InstallationFile), "postgres-data")}, {"metrics", filepath.Join(filepath.Dir(spec.InstallationFile), "metrics-data")}} {
		var st unix.Statfs_t
		if info, e := os.Lstat(item.path); e == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && unix.Statfs(item.path, &st) == nil && st.Bsize > 0 {
			env.Storage = append(env.Storage, HostWatchdogStorage{Component: item.component, TotalBytes: st.Blocks * uint64(st.Bsize), AvailableBytes: st.Bavail * uint64(st.Bsize), Inodes: st.Files, AvailableInodes: st.Ffree})
		}
	}
	return env
}
