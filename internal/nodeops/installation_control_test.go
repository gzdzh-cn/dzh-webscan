package nodeops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRestoreServicesWaitsForNativeExecAfterOwnStart(t *testing.T) {
	for _, transition := range []string{"executable", "arguments"} {
		t.Run(transition, func(t *testing.T) {
			m := installationFixture(t, "native")
			m.addNative(t)
			installed, err := m.host.inventory(context.Background(), "node-one", "native")
			if err != nil {
				t.Fatal(err)
			}
			if err = m.host.stop(context.Background(), installed); err != nil {
				t.Fatal(err)
			}
			original := m.host.command
			starts, reads := 0, 0
			m.host.command = func(ctx context.Context, p string, a ...string) (string, error) {
				if p == "systemctl" && a[0] == "start" {
					starts++
				}
				return original(ctx, p, a...)
			}
			if transition == "executable" {
				m.host.processExecutable = func(int) (string, error) {
					reads++
					if reads <= 2 {
						return "/usr/lib/systemd/systemd", nil
					}
					return installed.Services[0].Program, nil
				}
			} else {
				m.host.processArguments = func(int) ([]string, error) {
					reads++
					if reads <= 2 {
						return []string{"/usr/lib/systemd/systemd", "--deserialize", "99"}, nil
					}
					s := installed.Services[0]
					return []string{s.Program, "agent", "--config", s.Configuration}, nil
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err = m.host.restoreServices(ctx, installed); err != nil {
				t.Fatal("own Type=simple exec transition was mistaken for failed restoration", err)
			}
			if starts != 1 || reads < 3 {
				t.Fatal("must confirm exact process without repeating start", starts, reads)
			}
		})
	}
}

func TestRestoreServicesRejectsPersistentForeignProcessAfterOwnStart(t *testing.T) {
	m := installationFixture(t, "native")
	m.addNative(t)
	installed, err := m.host.inventory(context.Background(), "node-one", "native")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.host.stop(context.Background(), installed); err != nil {
		t.Fatal(err)
	}
	original := m.host.command
	starts := 0
	m.host.command = func(ctx context.Context, p string, a ...string) (string, error) {
		if p == "systemctl" && a[0] == "start" {
			starts++
		}
		return original(ctx, p, a...)
	}
	m.host.processExecutable = func(int) (string, error) { return filepath.Join(m.host.root, "foreign-program"), nil }
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err = m.host.restoreServices(ctx, installed)
	if err == nil || !strings.Contains(err.Error(), "native-running-program-mismatch") || starts != 1 {
		t.Fatal("foreign process accepted or start repeated", err, starts)
	}
}

func TestRestoreServicesDoesNotGrantExecGraceToAlreadyRunningWriter(t *testing.T) {
	m := installationFixture(t, "native")
	m.addNative(t)
	installed, err := m.host.inventory(context.Background(), "node-one", "native")
	if err != nil {
		t.Fatal(err)
	}
	original := m.host.command
	starts, reads := 0, 0
	m.host.command = func(ctx context.Context, p string, a ...string) (string, error) {
		if p == "systemctl" && a[0] == "start" {
			starts++
		}
		return original(ctx, p, a...)
	}
	m.host.processExecutable = func(int) (string, error) {
		if starts > 0 {
			reads++
			return "/foreign/program", nil
		}
		return installed.Services[0].Program, nil
	}
	if err = m.host.restoreServices(context.Background(), installed); err == nil || err.Error() != "native-running-program-mismatch" || starts != 1 || reads != 1 {
		t.Fatal("pre-existing writer received exec grace", err, starts, reads)
	}
}

func TestRestoreServicesExecGraceStillChecksUnitAndEnableState(t *testing.T) {
	for _, changed := range []string{"unit", "enable"} {
		t.Run(changed, func(t *testing.T) {
			m := installationFixture(t, "native")
			m.addNative(t)
			installed, err := m.host.inventory(context.Background(), "node-one", "native")
			if err != nil {
				t.Fatal(err)
			}
			if err = m.host.stop(context.Background(), installed); err != nil {
				t.Fatal(err)
			}
			original := m.host.command
			starts, reads := 0, 0
			m.host.command = func(ctx context.Context, p string, a ...string) (string, error) {
				if p == "systemctl" && a[0] == "start" {
					starts++
				}
				return original(ctx, p, a...)
			}
			m.host.processExecutable = func(int) (string, error) {
				reads++
				if reads == 1 {
					if changed == "unit" {
						if err := os.WriteFile(m.host.unitPath, []byte("foreign-unit"), 0600); err != nil {
							t.Fatal(err)
						}
					} else {
						m.nativeEnabled = false
					}
					return "/usr/lib/systemd/systemd", nil
				}
				return installed.Services[0].Program, nil
			}
			want := "native-unit-changed"
			if changed == "enable" {
				want = "native-restore-not-confirmed"
			}
			if err = m.host.restoreServices(context.Background(), installed); err == nil || err.Error() != want || starts != 1 {
				t.Fatal("changed ownership or state accepted", err, starts)
			}
		})
	}
}
