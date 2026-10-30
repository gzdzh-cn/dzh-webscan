package nodeops

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/nodeconfig"
)

// nativeResources inspects the manager's loaded values AND the live process's
// kernel limits. A unit file or successful systemctl command alone is not proof
// of enforcement. Paths are internal, never supplied by an HTTP/SSH request.
type nativeResources struct{ proc, cgroup string }

type nativeResourceEvidence struct {
	PID                                          int
	MemoryBytes, CPUQuotaMicros, CPUPeriodMicros uint64
	FileDescriptors                              uint64
	CgroupVersion                                int
}

func readKernelFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("resource-evidence-unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("resource-evidence-unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 128<<10+1))
	if err != nil || len(raw) > 128<<10 {
		return nil, errors.New("resource-evidence-unavailable")
	}
	return raw, nil
}

func positiveResourceInteger(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != s {
		return 0, errors.New("invalid-resource-limit")
	}
	return n, nil
}

func resourceProperties(raw string) (map[string]string, error) {
	want := map[string]bool{"MainPID": true, "ControlGroup": true, "MemoryAccounting": true, "CPUAccounting": true, "MemoryMax": true, "CPUQuotaPerSecUSec": true, "LimitNOFILE": true, "LimitNOFILESoft": true}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !want[key] {
			return nil, errors.New("invalid-resource-properties")
		}
		if _, found := values[key]; found {
			return nil, errors.New("invalid-resource-properties")
		}
		values[key] = value
	}
	if len(values) != len(want) {
		return nil, errors.New("invalid-resource-properties")
	}
	return values, nil
}

func processStart(raw []byte, pid int) (string, error) {
	// comm may itself contain ')' and spaces. Field 22 follows the final ') '.
	text := string(raw)
	i := strings.LastIndex(text, ") ")
	if !strings.HasPrefix(text, strconv.Itoa(pid)+" (") || i < 0 {
		return "", errors.New("process-identity-unavailable")
	}
	fields := strings.Fields(text[i+2:])
	if len(fields) < 20 {
		return "", errors.New("process-identity-unavailable")
	}
	if _, err := positiveResourceInteger(fields[19]); err != nil {
		return "", err
	}
	return fields[19], nil
}

func descriptorLimits(raw []byte, expected uint64) error {
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "Max open files") {
			continue
		}
		fields := strings.Fields(line)
		if found || len(fields) != 6 || fields[5] != "files" {
			return errors.New("descriptor-limit-not-proven")
		}
		soft, e1 := positiveResourceInteger(fields[3])
		hard, e2 := positiveResourceInteger(fields[4])
		if e1 != nil || e2 != nil || soft != expected || hard != expected {
			return errors.New("descriptor-limit-not-effective")
		}
		found = true
	}
	if !found {
		return errors.New("descriptor-limit-not-proven")
	}
	return nil
}

func cgroupMembership(raw []byte) (map[string]string, error) {
	groups := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || !safeServicePath(fields[2]) || strings.ContainsAny(fields[2], "\t") {
			return nil, errors.New("invalid-cgroup-membership")
		}
		id, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil || (fields[1] == "") != (id == 0) {
			return nil, errors.New("invalid-cgroup-membership")
		}
		controllers := strings.Split(fields[1], ",")
		for _, name := range controllers {
			if _, duplicate := groups[name]; duplicate {
				return nil, errors.New("invalid-cgroup-membership")
			}
			groups[name] = fields[2]
		}
	}
	return groups, nil
}

func mountPath(raw string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			b.WriteByte(raw[i])
			continue
		}
		if i+3 >= len(raw) {
			return "", errors.New("invalid-cgroup-mount")
		}
		escape := raw[i : i+4]
		switch escape {
		case `\040`:
			b.WriteByte(' ')
		case `\134`:
			b.WriteByte('\\')
		default:
			return "", errors.New("invalid-cgroup-mount")
		}
		i += 3
	}
	p := b.String()
	if !safeServicePath(p) {
		return "", errors.New("invalid-cgroup-mount")
	}
	return p, nil
}

// Resolve against actual mountinfo, including non-root and combined v1 mounts;
// guessing /sys/fs/cgroup/cpu can inspect the wrong hierarchy.
func cgroupDirectory(raw []byte, root, group, controller string, version int) (string, error) {
	var found string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		before, after, ok := strings.Cut(line, " - ")
		left, right := strings.Fields(before), strings.Fields(after)
		if !ok || len(left) < 6 || len(right) != 3 {
			return "", errors.New("invalid-cgroup-mounts")
		}
		if version == 2 && right[0] != "cgroup2" || version == 1 && right[0] != "cgroup" {
			continue
		}
		if version == 1 {
			present := false
			for _, option := range strings.Split(right[2], ",") {
				present = present || option == controller
			}
			if !present {
				continue
			}
		}
		mountRoot, e1 := mountPath(left[3])
		mount, e2 := mountPath(left[4])
		if e1 != nil || e2 != nil || mount != root && !strings.HasPrefix(mount, root+"/") {
			return "", errors.New("unsafe-cgroup-mount")
		}
		if mountRoot != "/" && group != mountRoot && !strings.HasPrefix(group, mountRoot+"/") {
			continue
		}
		suffix := strings.TrimPrefix(group, mountRoot)
		directory := filepath.Join(mount, suffix)
		if found != "" {
			return "", errors.New("ambiguous-cgroup-mount")
		}
		found = directory
	}
	if found == "" {
		return "", errors.New("cgroup-mount-unavailable")
	}
	return found, nil
}

func (fs nativeResources) inspect(ctx context.Context, host installationHost, status nativeStatus, target ServiceRecord, resources nodeconfig.Resources) (nativeResourceEvidence, error) {
	var result nativeResourceEvidence
	if resources.MemoryMiB < 128 || resources.MemoryMiB > 8192 || resources.FileDescriptors < 1024 || resources.FileDescriptors > 1048576 || resources.CPUs < 0.1 || resources.CPUs > 16 || math.IsNaN(resources.CPUs) || math.IsInf(resources.CPUs, 0) || !safeServicePath(fs.proc) || !safeServicePath(fs.cgroup) || status.MainPID < 1 || status.UnitFileState != "enabled" || status.NeedDaemonReload != "no" {
		return result, errors.New("invalid-resource-inspection")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := host.proveRunningNativeProcess(status, target.Program, target.Configuration); err != nil {
		return result, err
	}
	dir := filepath.Join(fs.proc, strconv.Itoa(status.MainPID))
	stat, err := readKernelFile(filepath.Join(dir, "stat"))
	if err != nil {
		return result, err
	}
	started, err := processStart(stat, status.MainPID)
	if err != nil {
		return result, err
	}
	raw, err := host.command(ctx, "systemctl", "show", nativeServiceName, "--property=MainPID,ControlGroup,MemoryAccounting,CPUAccounting,MemoryMax,CPUQuotaPerSecUSec,LimitNOFILE,LimitNOFILESoft")
	if err != nil {
		return result, err
	}
	properties, err := resourceProperties(raw)
	if err != nil {
		return result, err
	}
	group := properties["ControlGroup"]
	quota, quotaErr := time.ParseDuration(strings.Join(strings.Fields(properties["CPUQuotaPerSecUSec"]), ""))
	fd := uint64(resources.FileDescriptors)
	memory := uint64(resources.MemoryMiB) << 20
	if properties["MainPID"] != strconv.Itoa(status.MainPID) || !safeServicePath(group) || filepath.Base(group) != nativeServiceName || properties["MemoryAccounting"] != "yes" || properties["CPUAccounting"] != "yes" || properties["MemoryMax"] != strconv.FormatUint(memory, 10) || properties["LimitNOFILE"] != strconv.FormatUint(fd, 10) || properties["LimitNOFILESoft"] != strconv.FormatUint(fd, 10) || quotaErr != nil || quota != time.Duration(math.Round(resources.CPUs*float64(time.Second))) {
		return result, errors.New("loaded-resource-limits-not-effective")
	}
	return fs.inspectKernel(ctx, status.MainPID, group, started, resources, func() error {
		return host.proveRunningNativeProcess(status, target.Program, target.Configuration)
	})
}

// Native and Docker use the same host kernel evidence. The caller must first
// bind the expected cgroup and process to its manager's immutable identity.
func (fs nativeResources) inspectKernel(ctx context.Context, pid int, group, started string, resources nodeconfig.Resources, prove func() error) (nativeResourceEvidence, error) {
	var result nativeResourceEvidence
	settings := nodeconfig.DefaultSettings()
	settings.Resources = resources
	if settings.Validate() != nil || !safeServicePath(fs.proc) || !safeServicePath(fs.cgroup) || !safeServicePath(group) || pid < 1 || started == "" || prove == nil || ctx.Err() != nil {
		return result, errors.New("invalid-kernel-resource-inspection")
	}
	if err := prove(); err != nil {
		return result, err
	}
	dir := filepath.Join(fs.proc, strconv.Itoa(pid))
	fd, memory := uint64(resources.FileDescriptors), uint64(resources.MemoryMiB)<<20
	limits, err := readKernelFile(filepath.Join(dir, "limits"))
	if err != nil {
		return result, err
	}
	if err := descriptorLimits(limits, fd); err != nil {
		return result, err
	}
	membership, err := readKernelFile(filepath.Join(dir, "cgroup"))
	if err != nil {
		return result, err
	}
	groups, err := cgroupMembership(membership)
	if err != nil {
		return result, err
	}
	mounts, err := readKernelFile(filepath.Join(fs.proc, "self", "mountinfo"))
	if err != nil {
		return result, err
	}
	version := 1
	_, unified := groups[""]
	if _, cpuV1 := groups["cpu"]; cpuV1 {
		// Hybrid systems may also mount an empty unified hierarchy. Assigned
		// controllers remain in their v1 mounts and must be inspected there.
		unified = false
	}
	if unified {
		version = 2
	}
	for _, controller := range []string{"cpu", "memory"} {
		key := controller
		if unified {
			key = ""
		}
		if groups[key] != group {
			return result, errors.New("process-cgroup-not-owned")
		}
		directory, err := cgroupDirectory(mounts, fs.cgroup, group, controller, version)
		if err != nil {
			return result, err
		}
		if controller == "memory" {
			file := "memory.limit_in_bytes"
			if unified {
				file = "memory.max"
			}
			raw, err := readKernelFile(filepath.Join(directory, file))
			if err != nil || strings.TrimSpace(string(raw)) != strconv.FormatUint(memory, 10) {
				return result, errors.New("memory-cgroup-limit-not-effective")
			}
		} else {
			var quota, period uint64
			var e1, e2 error
			if unified {
				raw, err := readKernelFile(filepath.Join(directory, "cpu.max"))
				fields := strings.Fields(string(raw))
				if err != nil || len(fields) != 2 {
					return result, errors.New("cpu-cgroup-limit-not-proven")
				}
				quota, e1 = positiveResourceInteger(fields[0])
				period, e2 = positiveResourceInteger(fields[1])
			} else {
				q, err := readKernelFile(filepath.Join(directory, "cpu.cfs_quota_us"))
				p, err2 := readKernelFile(filepath.Join(directory, "cpu.cfs_period_us"))
				if err != nil || err2 != nil {
					return result, errors.New("cpu-cgroup-limit-not-proven")
				}
				quota, e1 = positiveResourceInteger(strings.TrimSpace(string(q)))
				period, e2 = positiveResourceInteger(strings.TrimSpace(string(p)))
			}
			if e1 != nil || e2 != nil || period < 1000 || period > 1000000 || quota != uint64(math.Ceil(resources.CPUs*float64(period))) {
				return result, errors.New("cpu-cgroup-limit-not-effective")
			}
			result.CPUQuotaMicros, result.CPUPeriodMicros = quota, period
		}
	}
	// Re-read identity and membership to reject PID reuse/movement during proof.
	stat, err := readKernelFile(filepath.Join(dir, "stat"))
	if err != nil {
		return result, err
	}
	finishedStart, err := processStart(stat, pid)
	if err != nil || started != finishedStart {
		return result, errors.New("process-changed-during-verification")
	}
	lastMembership, err := readKernelFile(filepath.Join(dir, "cgroup"))
	if err != nil || string(lastMembership) != string(membership) {
		return result, errors.New("process-cgroup-changed")
	}
	if err := prove(); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	result.PID, result.MemoryBytes, result.FileDescriptors, result.CgroupVersion = pid, memory, fd, version
	return result, nil
}

func (r nativeResourceEvidence) checks() []Check {
	return []Check{
		{ID: "native-memory", Status: "passed", Code: "kernel-limit-verified", Actual: r.MemoryBytes, Required: r.MemoryBytes},
		{ID: "native-cpu", Status: "passed", Code: "kernel-limit-verified", Actual: r.CPUQuotaMicros, Required: r.CPUQuotaMicros},
		{ID: "native-descriptors", Status: "passed", Code: "kernel-limit-verified", Actual: r.FileDescriptors, Required: r.FileDescriptors},
	}
}
