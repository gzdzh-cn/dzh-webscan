//go:build linux

package nodeops

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"webscan/internal/nodeconfig"
)

// A disposable container supplies actual kernel limits. This proves the reader
// against Linux cgroups/rlimits, not systemd's installation or cgroup placement.
func TestKernelCgroupResourceLimitReader(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_KERNEL_LIMITS") != "1" {
		t.Skip("requires disposable container with explicit CPU/memory/descriptor limits")
	}
	proc := filepath.Join("/proc", strconv.Itoa(os.Getpid()))
	stat, err := readKernelFile(filepath.Join(proc, "stat"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := processStart(stat, os.Getpid()); err != nil {
		t.Fatal(err)
	}
	limits, err := readKernelFile(filepath.Join(proc, "limits"))
	if err != nil {
		t.Fatal(err)
	}
	if err := descriptorLimits(limits, 65536); err != nil {
		t.Fatal(err)
	}
	membership, err := readKernelFile(filepath.Join(proc, "cgroup"))
	if err != nil {
		t.Fatal(err)
	}
	groups, err := cgroupMembership(membership)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := readKernelFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	group, ok := groups[""]
	if !ok {
		t.Fatal("isolated cgroup v2 fixture required")
	}
	dir, err := cgroupDirectory(mounts, "/sys/fs/cgroup", group, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	memory, err := readKernelFile(filepath.Join(dir, "memory.max"))
	if err != nil || strings.TrimSpace(string(memory)) != "268435456" {
		t.Fatal("kernel memory limit mismatch", err)
	}
	cpu, err := readKernelFile(filepath.Join(dir, "cpu.max"))
	if err != nil || strings.TrimSpace(string(cpu)) != "125000 100000" {
		t.Fatal("kernel CPU limit mismatch", err)
	}
	started, err := processStart(stat, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	r := nodeconfig.DefaultSettings().Resources
	r.CPUs = 1.25
	// Exercise the shared reader against this disposable test process. This
	// does not certify Agent ownership, Docker host PID visibility or systemd.
	proof, err := (nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}).inspectKernel(context.Background(), os.Getpid(), group, started, r, func() error { return nil })
	if err != nil || proof.CgroupVersion != 2 || proof.MemoryBytes != 268435456 || proof.CPUQuotaMicros != 125000 || proof.FileDescriptors != 65536 {
		t.Fatal(proof, err)
	}
}
