package nodeops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDockerKernelProofBindsProcessAndBothControllers(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, driver := range []string{"systemd", "cgroupfs"} {
			for _, kind := range []string{"valid", "foreign-group", "cpu-unlimited", "memory-wrong", "descriptors", "deleted-program", "wrong-arguments", "pid-reuse", "process-moved"} {
				t.Run(fmt.Sprintf("v%d/%s/%s", version, driver, kind), func(t *testing.T) {
					f := resourceFixture(t, version)
					h, a, r, c, s := dockerVerificationFixture(t)
					*s = dockerStateFixture(t, r)
					group := "/docker/" + c.ID
					if driver == "systemd" {
						group = "/system.slice/docker-" + c.ID + ".scope"
					}
					for _, root := range []string{f.fs.cgroup} {
						parents := []string{root}
						if version == 1 {
							parents = []string{filepath.Join(root, "cpu,cpuacct"), filepath.Join(root, "memory")}
						}
						for _, parent := range parents {
							if err := os.MkdirAll(filepath.Dir(filepath.Join(parent, group)), 0700); err != nil {
								t.Fatal(err)
							}
							if err := os.Rename(filepath.Join(parent, f.group), filepath.Join(parent, group)); err != nil {
								t.Fatal(err)
							}
						}
					}
					f.cpu = strings.Replace(f.cpu, f.group, group, 1)
					f.memory = strings.Replace(f.memory, f.group, group, 1)
					membershipFile := filepath.Join(f.fs.proc, "123/cgroup")
					raw, err := os.ReadFile(membershipFile)
					if err != nil {
						t.Fatal(err)
					}
					writeResourceFixture(t, membershipFile, strings.ReplaceAll(string(raw), f.group, group))
					writeResourceFixture(t, f.memory, strconv.FormatInt(int64(r.MemoryMiB)<<20, 10)+"\n")
					limits := fmt.Sprintf("Max open files   %d   %d   files\n", r.FileDescriptors, r.FileDescriptors)
					writeResourceFixture(t, filepath.Join(f.fs.proc, "123/limits"), limits)
					h.processExecutable = func(int) (string, error) { return c.Entrypoint[0], nil }
					h.processArguments = func(int) ([]string, error) { return append(append([]string{}, c.Entrypoint...), c.Command...), nil }
					switch kind {
					case "foreign-group":
						writeResourceFixture(t, membershipFile, "0::/shared/parent\n")
					case "cpu-unlimited":
						writeResourceFixture(t, f.cpu, "max 100000\n")
					case "memory-wrong":
						writeResourceFixture(t, f.memory, "1\n")
					case "descriptors":
						writeResourceFixture(t, filepath.Join(f.fs.proc, "123/limits"), "Max open files   1024   1024   files\n")
					case "deleted-program":
						h.processExecutable = func(int) (string, error) { return c.Entrypoint[0] + " (deleted)", nil }
					case "wrong-arguments":
						h.processArguments = func(int) ([]string, error) { return []string{"sleep", "90"}, nil }
					case "pid-reuse", "process-moved":
						calls := 0
						original := h.processExecutable
						h.processExecutable = func(pid int) (string, error) {
							calls++
							if calls == 2 {
								if kind == "pid-reuse" {
									writeResourceFixture(t, filepath.Join(f.fs.proc, "123/stat"), processStat(123, "new-process", 99888))
								} else {
									writeResourceFixture(t, membershipFile, "0::/different\n")
								}
							}
							return original(pid)
						}
					}
					proof, err := f.fs.inspectDocker(context.Background(), h, c.ID, a, r)
					if kind == "valid" {
						if err != nil || proof.Kernel.PID != s.State.Pid || proof.Kernel.CgroupVersion != version || proof.Kernel.MemoryBytes != uint64(r.MemoryMiB)<<20 || proof.Kernel.CPUQuotaMicros != 125000 {
							t.Fatal(proof, err)
						}
					} else if err == nil {
						t.Fatal("unproved kernel limits or ownership accepted")
					}
				})
			}
		}
	}
}
