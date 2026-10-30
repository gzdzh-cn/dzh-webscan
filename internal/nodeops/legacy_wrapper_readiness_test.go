package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// systemd Type=simple starts the attached Docker client before Docker has
// necessarily started the captured container. Keep both identities strict.
func TestLegacyWrapperRestoreWaitsForCapturedContainer(t *testing.T) {
	for _, role := range []string{"vector", "exporter"} {
		t.Run(role, func(t *testing.T) {
			m := wrapperFixture(t, role, false, true, true)
			ctx := context.Background()
			if err := m.w.quiesce(ctx, m.r, m.name); err != nil {
				t.Fatal(err)
			}
			command := m.w.host.command
			started, lagged, observed := false, 0, 0
			m.w.host.command = func(ctx context.Context, program string, args ...string) (string, error) {
				out, err := command(ctx, program, args...)
				if err == nil && program == "systemctl" && len(args) > 1 && args[0] == "start" && args[1] == m.name {
					started = true
				}
				if err == nil && started && program == "docker" && len(args) > 4 && args[2] == "container" && args[3] == "inspect" && args[len(args)-1] == legacyWrapperObjectFormat {
					observed++
					if lagged < 2 {
						var o legacyWrapperObject
						if err := json.Unmarshal([]byte(out), &o); err != nil {
							t.Fatal(err)
						}
						o.Identity.Status = "exited"
						body, _ := json.Marshal(o)
						lagged++
						return string(body), nil
					}
				}
				return out, err
			}
			m.r.Phase = "restore"
			if err := m.w.restore(ctx, m.r, m.name); err != nil {
				t.Fatal("did not wait for the exact captured container", err)
			}
			if lagged != 2 || observed < 3 {
				t.Fatal("test did not observe delayed Docker startup", lagged, observed)
			}
			starts := 0
			for _, call := range m.calls {
				if strings.HasPrefix(call, "systemctl start "+m.name) {
					starts++
				}
			}
			if starts != 1 {
				t.Fatal("readiness wait repeated a start", starts)
			}
			if err := m.w.restored(ctx, m.r, m.name); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLegacyWrapperRestoreWaitRejectsDriftAndCancellation(t *testing.T) {
	for _, failure := range []string{"object-changed", "unit-changed", "cancelled"} {
		t.Run(failure, func(t *testing.T) {
			m := wrapperFixture(t, "vector", false, true, true)
			if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			command := m.w.host.command
			observed := 0
			started := false
			m.w.host.command = func(ctx context.Context, program string, args ...string) (string, error) {
				out, err := command(ctx, program, args...)
				if err == nil && program == "systemctl" && len(args) > 1 && args[0] == "start" && args[1] == m.name {
					started = true
					if failure == "unit-changed" {
						if err := os.WriteFile(m.unit, []byte("foreign unit\n"), 0644); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err == nil && started && program == "docker" && len(args) > 4 && args[2] == "container" && args[3] == "inspect" && args[len(args)-1] == legacyWrapperObjectFormat {
					observed++
					var o legacyWrapperObject
					if err := json.Unmarshal([]byte(out), &o); err != nil {
						t.Fatal(err)
					}
					if failure == "object-changed" {
						o.Identity.ImageID = "sha256:" + strings.Repeat("7", 64)
					} else if failure == "cancelled" {
						o.Identity.Status = "exited"
						cancel()
					}
					body, _ := json.Marshal(o)
					return string(body), nil
				}
				return out, err
			}
			m.r.Phase = "restore"
			err := m.w.restore(ctx, m.r, m.name)
			if err == nil || failure == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("unsafe or cancelled restoration accepted", err)
			}
			if observed > 1 {
				t.Fatal("retried after ownership change or cancellation", observed)
			}
			dir, err := m.w.directory(m.r, m.name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(dir, "restored.json")); !os.IsNotExist(err) {
				t.Fatal("false restoration completion receipt", err)
			}
		})
	}
}
