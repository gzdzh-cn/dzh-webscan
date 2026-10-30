package nodeops

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real private installation/PKI files, explicitly simulated managers and
// kernel files. Full-kernel tests remain a separate release requirement.
func TestIdentityRecoveryVerifyRequiresActualSavedResourcePolicy(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, version := range []int{1, 2} {
			for _, scenario := range []string{"valid", "not-running", "memory-unlimited", "cpu-unlimited", "descriptors", "missing-evidence", "deleted-program", "wrong-command", "manager-limits", "not-activated"} {
				t.Run(fmt.Sprintf("%s/v%d/%s", mode, version, scenario), func(t *testing.T) {
					f := signedHelperRecovery(t, mode, scenario != "not-activated")
					m := recoveryServiceMachine(t, f)
					kernel := resourceFixture(t, version)
					kernel.properties = strings.ReplaceAll(kernel.properties, "1s 250ms", "1s")
					quota := "100000\n"
					if version == 2 {
						quota = "100000 100000\n"
					}
					writeResourceFixture(t, kernel.cpu, quota)
					base := m.host.command
					state := dockerStateFixture(t, kernel.resources)
					state.Host.NanoCpus = 1000000000
					m.nativeRunning = true
					if mode == "docker" {
						for id, c := range m.containers {
							c.Status = "running"
							m.containers[id] = c
						}
						group := "/system.slice/docker-" + state.ID + ".scope"
						parents := []string{kernel.fs.cgroup}
						if version == 1 {
							parents = []string{filepath.Join(kernel.fs.cgroup, "cpu,cpuacct"), filepath.Join(kernel.fs.cgroup, "memory")}
						}
						for _, root := range parents {
							if err := os.Rename(filepath.Join(root, kernel.group), filepath.Join(root, group)); err != nil {
								t.Fatal(err)
							}
						}
						kernel.cpu = strings.ReplaceAll(kernel.cpu, kernel.group, group)
						kernel.memory = strings.ReplaceAll(kernel.memory, kernel.group, group)
						membership := filepath.Join(kernel.fs.proc, "123/cgroup")
						raw, err := os.ReadFile(membership)
						if err != nil {
							t.Fatal(err)
						}
						writeResourceFixture(t, membership, strings.ReplaceAll(string(raw), kernel.group, group))
					}
					m.host.command = func(ctx context.Context, p string, args ...string) (string, error) {
						if p == "systemctl" && strings.Contains(strings.Join(args, " "), "MemoryAccounting") {
							m.calls = append(m.calls, p+" "+strings.Join(args, " "))
							return kernel.properties, nil
						}
						if p == "docker" && len(args) == 7 && args[6] == dockerRuntimeFormat {
							m.calls = append(m.calls, p+" "+strings.Join(args, " "))
							raw, _ := json.Marshal(state)
							return string(raw), nil
						}
						return base(ctx, p, args...)
					}
					switch scenario {
					case "not-running":
						m.nativeRunning = false
						for id, c := range m.containers {
							c.Status = "exited"
							m.containers[id] = c
						}
					case "memory-unlimited":
						writeResourceFixture(t, kernel.memory, "max\n")
					case "cpu-unlimited":
						writeResourceFixture(t, kernel.cpu, "max 100000\n")
					case "descriptors":
						writeResourceFixture(t, filepath.Join(kernel.fs.proc, "123/limits"), "Max open files 1024 1024 files\n")
					case "missing-evidence":
						os.Remove(kernel.memory)
					case "deleted-program":
						original := m.host.processExecutable
						m.host.processExecutable = func(pid int) (string, error) { p, err := original(pid); return p + " (deleted)", err }
					case "wrong-command":
						m.host.processArguments = func(int) ([]string, error) { return []string{"sleep", "100"}, nil }
					case "manager-limits":
						kernel.properties = strings.ReplaceAll(kernel.properties, "MemoryMax=268435456", "MemoryMax=infinity")
						state.Host.Memory = 0
					}
					f.in.Operation = "verify"
					out, err := f.w.identityRecoveryWithResources(context.Background(), f.in, m.host, kernel.fs)
					if scenario == "valid" {
						if err != nil || !out.ResourcesVerified || out.CertificateSHA256 == "" || out.Operation != "verify" {
							t.Fatal("saved kernel resources not proven", err)
						}
					} else if err == nil || out.ResourcesVerified {
						t.Fatal("unproven resource policy accepted", err)
					}
					for _, call := range m.calls {
						for _, action := range []string{" start ", " stop ", " restart ", " update ", " enable ", " disable "} {
							if strings.Contains(" "+call+" ", action) {
								t.Fatal("resource acceptance mutated service", call)
							}
						}
					}
				})
			}
		}
	}
}
