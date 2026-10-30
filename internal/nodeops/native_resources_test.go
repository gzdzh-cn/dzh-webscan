package nodeops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"webscan/internal/nodeconfig"
)

type nativeResourceFixture struct {
	fs                             nativeResources
	host                           installationHost
	status                         nativeStatus
	target                         ServiceRecord
	resources                      nodeconfig.Resources
	properties, group, cpu, memory string
}

func resourceFixture(t *testing.T, version int) *nativeResourceFixture {
	t.Helper()
	root := testRoot(t)
	f := &nativeResourceFixture{fs: nativeResources{proc: filepath.Join(root, "proc"), cgroup: filepath.Join(root, "cgroup")}, resources: nodeconfig.DefaultSettings().Resources,
		status: nativeStatus{MainPID: 123, UnitFileState: "enabled", NeedDaemonReload: "no"},
		target: ServiceRecord{Program: "/trusted/webscan", Configuration: "/trusted/runtime.json"}, group: "/system.slice/" + nativeServiceName}
	f.resources.CPUs = 1.25
	f.properties = fmt.Sprintf("MainPID=123\nControlGroup=%s\nMemoryAccounting=yes\nCPUAccounting=yes\nMemoryMax=268435456\nCPUQuotaPerSecUSec=1s 250ms\nLimitNOFILE=65536\nLimitNOFILESoft=65536\n", f.group)
	f.host = installationHost{processExecutable: func(int) (string, error) { return f.target.Program, nil }, processArguments: func(int) ([]string, error) {
		return []string{f.target.Program, "agent", "--config", f.target.Configuration}, nil
	}, command: func(context.Context, string, ...string) (string, error) { return f.properties, nil }}
	writeResourceFixture(t, filepath.Join(f.fs.proc, "123", "stat"), processStat(123, "agent (worker)", 98765))
	writeResourceFixture(t, filepath.Join(f.fs.proc, "123", "limits"), "Limit                     Soft Limit           Hard Limit           Units\nMax open files            65536                65536                files\n")
	if version == 2 {
		writeResourceFixture(t, filepath.Join(f.fs.proc, "123", "cgroup"), "0::"+f.group+"\n")
		writeResourceFixture(t, filepath.Join(f.fs.proc, "self", "mountinfo"), "30 20 0:28 / "+f.fs.cgroup+" rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n")
		f.cpu, f.memory = filepath.Join(f.fs.cgroup, f.group, "cpu.max"), filepath.Join(f.fs.cgroup, f.group, "memory.max")
		writeResourceFixture(t, f.cpu, "125000 100000\n")
	} else {
		writeResourceFixture(t, filepath.Join(f.fs.proc, "123", "cgroup"), "2:cpu,cpuacct:"+f.group+"\n3:memory:"+f.group+"\n1:name=systemd:"+f.group+"\n0::/\n")
		writeResourceFixture(t, filepath.Join(f.fs.proc, "self", "mountinfo"), "30 20 0:28 / "+f.fs.cgroup+"/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct\n31 20 0:29 / "+f.fs.cgroup+"/memory rw - cgroup cgroup rw,memory\n32 20 0:30 / "+f.fs.cgroup+"/unified rw - cgroup2 cgroup rw\n")
		f.cpu, f.memory = filepath.Join(f.fs.cgroup, "cpu,cpuacct", f.group, "cpu.cfs_quota_us"), filepath.Join(f.fs.cgroup, "memory", f.group, "memory.limit_in_bytes")
		writeResourceFixture(t, f.cpu, "125000\n")
		writeResourceFixture(t, filepath.Join(filepath.Dir(f.cpu), "cpu.cfs_period_us"), "100000\n")
	}
	writeResourceFixture(t, f.memory, "268435456\n")
	return f
}

func writeResourceFixture(t *testing.T, path, raw string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
}

func processStat(pid int, name string, started uint64) string {
	fields := []string{"S"}
	for len(fields) < 19 {
		fields = append(fields, "0")
	}
	return strconv.Itoa(pid) + " (" + name + ") " + strings.Join(append(fields, strconv.FormatUint(started, 10)), " ") + "\n"
}

func TestNativeResourceInspectionChecksLoadedAndKernelLimits(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			f := resourceFixture(t, version)
			proof, err := f.fs.inspect(context.Background(), f.host, f.status, f.target, f.resources)
			if err != nil || proof.PID != 123 || proof.CgroupVersion != version || proof.MemoryBytes != 268435456 || proof.CPUQuotaMicros != 125000 || proof.CPUPeriodMicros != 100000 || proof.FileDescriptors != 65536 {
				t.Fatal("actual limits not verified", proof, err)
			}
			if len(proof.checks()) != 3 {
				t.Fatal("missing resource checks")
			}
		})
	}
}

func TestNativeResourceInspectionRejectsUnprovedLimits(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, kind := range []string{"missing-property", "duplicate-property", "manager-memory", "manager-cpu", "manager-nofile", "accounting", "manager-pid", "foreign-group", "memory-unlimited", "memory-wrong", "cpu-unlimited", "cpu-wrong", "cpu-period", "descriptors", "membership", "mount", "stat", "file-link", "overflow", "changed-process", "cancelled"} {
			t.Run(fmt.Sprintf("v%d/%s", version, kind), func(t *testing.T) {
				f := resourceFixture(t, version)
				ctx := context.Background()
				switch kind {
				case "missing-property":
					f.properties = strings.ReplaceAll(f.properties, "MemoryAccounting=yes\n", "")
				case "duplicate-property":
					f.properties += "MemoryMax=268435456\n"
				case "manager-memory":
					f.properties = strings.ReplaceAll(f.properties, "MemoryMax=268435456", "MemoryMax=infinity")
				case "manager-cpu":
					f.properties = strings.ReplaceAll(f.properties, "1s 250ms", "infinity")
				case "manager-nofile":
					f.properties = strings.ReplaceAll(f.properties, "LimitNOFILESoft=65536", "LimitNOFILESoft=1024")
				case "accounting":
					f.properties = strings.ReplaceAll(f.properties, "CPUAccounting=yes", "CPUAccounting=no")
				case "manager-pid":
					f.properties = strings.ReplaceAll(f.properties, "MainPID=123", "MainPID=124")
				case "foreign-group":
					f.properties = strings.ReplaceAll(f.properties, f.group, "/system.slice/foreign.service")
				case "memory-unlimited":
					writeResourceFixture(t, f.memory, "max\n")
				case "memory-wrong":
					writeResourceFixture(t, f.memory, "536870912\n")
				case "cpu-unlimited":
					if version == 2 {
						writeResourceFixture(t, f.cpu, "max 100000\n")
					} else {
						writeResourceFixture(t, f.cpu, "-1\n")
					}
				case "cpu-wrong":
					if version == 2 {
						writeResourceFixture(t, f.cpu, "250000 100000\n")
					} else {
						writeResourceFixture(t, f.cpu, "250000\n")
					}
				case "cpu-period":
					if version == 2 {
						writeResourceFixture(t, f.cpu, "125000 0\n")
					} else {
						writeResourceFixture(t, filepath.Join(filepath.Dir(f.cpu), "cpu.cfs_period_us"), "0\n")
					}
				case "descriptors":
					writeResourceFixture(t, filepath.Join(f.fs.proc, "123/limits"), "Max open files   65535   65536   files\n")
				case "membership":
					writeResourceFixture(t, filepath.Join(f.fs.proc, "123/cgroup"), "0::/foreign\n")
				case "mount":
					writeResourceFixture(t, filepath.Join(f.fs.proc, "self/mountinfo"), "invalid\n")
				case "stat":
					writeResourceFixture(t, filepath.Join(f.fs.proc, "123/stat"), processStat(124, "agent", 1))
				case "file-link":
					os.Remove(f.memory)
					if err := os.Symlink(f.cpu, f.memory); err != nil {
						t.Fatal(err)
					}
				case "overflow":
					writeResourceFixture(t, f.cpu, strings.Repeat("1", 128<<10+1))
				case "changed-process":
					f.host.command = func(context.Context, string, ...string) (string, error) {
						writeResourceFixture(t, filepath.Join(f.fs.proc, "123/stat"), processStat(123, "agent", 98766))
						return f.properties, nil
					}
				case "cancelled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				if _, err := f.fs.inspect(ctx, f.host, f.status, f.target, f.resources); err == nil {
					t.Fatal("unproved resource policy passed")
				}
			})
		}
	}
}

func TestCgroupMountResolutionUsesHierarchyAndEscapes(t *testing.T) {
	for _, tc := range []struct {
		mount, group, controller, want string
		version                        int
		valid                          bool
	}{
		{"30 20 0:28 /tenant /sys/fs/cgroup rw - cgroup2 cgroup rw", "/tenant/system.slice/agent", "", "/sys/fs/cgroup/system.slice/agent", 2, true},
		{`30 20 0:28 /tenant\040one /sys/fs/cgroup/cpu\040control rw - cgroup cgroup rw,cpu,cpuacct`, "/tenant one/system.slice/agent", "cpu", "/sys/fs/cgroup/cpu control/system.slice/agent", 1, true},
		{"30 20 0:28 /another /sys/fs/cgroup rw - cgroup2 cgroup rw", "/tenant/agent", "", "", 2, false},
		{"30 20 0:28 / /outside rw - cgroup2 cgroup rw", "/tenant/agent", "", "", 2, false},
		{"30 20 0:28 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n31 20 0:29 / /sys/fs/cgroup/other rw - cgroup2 cgroup rw", "/tenant/agent", "", "", 2, false},
	} {
		got, err := cgroupDirectory([]byte(tc.mount), "/sys/fs/cgroup", tc.group, tc.controller, tc.version)
		if (err == nil) != tc.valid || got != tc.want {
			t.Fatal("wrong resolved cgroup", got, err, tc)
		}
	}
}
