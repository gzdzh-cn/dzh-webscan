//go:build linux

package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real vendor images, Docker inspection and retained-ID start/stop, but NO
// real systemd manager. The service evidence is an explicit substitute and
// cannot certify active-wrapper adoption, installation or three-container
// migration. No Agent, notification worker or external network is started.
func TestLegacyWrapperObjectsOnDisposableNestedEngine(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_WRAPPER_DIND") != "1" {
		t.Skip("requires opted-in disposable nested Docker engine")
	}
	marker, err := os.ReadFile("/v3-tests/isolated-engine")
	if os.Geteuid() != 0 || err != nil || string(marker) != "webscan-v3-disposable-dind\n" {
		t.Fatal("missing disposable-engine marker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	run := func(t *testing.T, operation context.Context, args ...string) string {
		t.Helper()
		raw, err := inventoryCommand(operation, "docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
		if err != nil {
			t.Fatal("isolated engine operation", args[:1], err)
		}
		return strings.TrimSpace(raw)
	}
	if run(t, ctx, "ps", "-aq") != "" {
		t.Fatal("refusing existing containers")
	}
	for _, path := range []string{legacyConfigurationRoot, agentDataDirectory, agentLogDirectory, "/var/lib/webscan-vector-v1"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refusing existing node paths", path, err)
		}
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(path) })
	}
	for _, role := range []string{"vector", "exporter"} {
		t.Run(role, func(t *testing.T) {
			m := wrapperFixture(t, role, false, false, false)
			// The source is a verified immutable image config imported only into
			// this engine. Tags are local aliases, never registry writes.
			raw := run(t, ctx, "image", "inspect", m.u.alias(), "--format", legacyWrapperImageFormat)
			if json.Unmarshal([]byte(raw), &m.image) != nil || m.image.OS != "linux" || m.image.Arch != "amd64" {
				t.Fatal("requires matching real Linux amd64 vendor image")
			}
			m.u.SourceImage = m.image.ID
			m.loaded = m.u.definition()
			if err := os.WriteFile(m.unit, m.loaded, 0644); err != nil {
				t.Fatal(err)
			}
			m.args = append([]string{"/usr/bin/docker"}, m.u.runArguments()...)
			// Vector consumes only an empty test file source into a blackhole.
			// No real center endpoint, push token or notification is configured.
			if err := os.WriteFile(filepath.Join(legacyConfigurationRoot, "vector.yml"), []byte("data_dir: /var/lib/vector\nsources:\n  test_files:\n    type: file\n    include: [\"/var/log/webscan-v1/events-*.jsonl\"]\nsinks:\n  discard:\n    type: blackhole\n    inputs: [test_files]\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(legacyConfigurationRoot, "exporter.yml"), []byte("{}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(agentDataDirectory, "textfile"), 0700); err != nil {
				t.Fatal(err)
			}
			args := m.u.runArguments()
			args[0] = "create"
			id := run(t, ctx, args...)
			t.Cleanup(func() {
				// Fixture teardown only: never a production lifecycle operation.
				cleanupContext, release, err := acquireServiceOperation(context.Background(), m.w.host.root)
				if err == nil {
					_, err = inventoryCommand(cleanupContext, "docker", "--host", "unix:///var/run/docker.sock", "rm", "-f", id)
					release()
				}
				if err != nil {
					t.Error("remove exact disposable object", err)
				}
			})
			m.o.Identity.ID = id
			fake := m.w.host.command
			m.w.host.command = func(ctx context.Context, p string, a ...string) (string, error) {
				if p == "docker" {
					return inventoryCommand(ctx, p, a...)
				}
				return fake(ctx, p, a...)
			}
			captured, err := m.w.capture(ctx, m.r, m.name)
			if err != nil {
				object, _ := m.w.object(ctx, id)
				proof, _ := json.Marshal(struct {
					Object legacyWrapperObject
					Image  legacyWrapperImage
				}{object, m.image})
				t.Log("isolated vendor fixture ownership evidence:", string(proof))
				t.Fatal("real ownership and mount inspection", err)
			}
			if captured.Object.Identity.ID != id {
				t.Fatal("did not capture actual immutable ID")
			}
			if err := m.w.quiesce(ctx, m.r, m.name); err != nil {
				t.Fatal("idle-object quiesce", err)
			}
			m.r.Phase = "restore"
			if err := m.w.restore(ctx, m.r, m.name); err != nil {
				t.Fatal("idle-object recovery", err)
			}
			pointer, err := m.w.authorityPath(m.name)
			if err != nil {
				t.Fatal(err)
			}
			provenance, err := readPrivate(pointer, MaxRequestBytes)
			if err != nil {
				t.Fatal(err)
			}
			next := nextWrapperRequest(m.r)
			fresh, err := m.w.capture(ctx, next, m.name)
			if err != nil || fresh.RetainedSHA256 != sha(provenance) || fresh.Object.Identity.ID != id {
				t.Fatal("fresh task cannot prove real retained object", err)
			}
			if err := m.w.quiesce(ctx, next, m.name); err != nil {
				t.Fatal("fresh task quiesce", err)
			}
			next.Phase = "restore"
			if err := m.w.restore(ctx, next, m.name); err != nil {
				t.Fatal("fresh task recovery", err)
			}
			currentProvenance, err := readPrivate(pointer, MaxRequestBytes)
			if err != nil || !bytes.Equal(currentProvenance, provenance) {
				t.Fatal("fresh task rewrote root provenance", err)
			}
			unit, err := os.ReadFile(m.unit)
			if err != nil || !bytes.Equal(unit, retainedWrapperUnit(m.u, id)) {
				t.Fatal("retained-ID unit not installed", err)
			}
			// Execute the generated fixed start/stop arguments against the real
			// daemon. systemd itself remains outside this test's evidence scope.
			start := exec.Command("docker", "--host", "unix:///var/run/docker.sock", "start", "--attach", id)
			var output boundedInventory
			start.Stdout, start.Stderr = &output, &output
			if err := start.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			finished := make(chan struct{})
			go func() {
				done <- start.Wait()
				close(finished)
			}()
			t.Cleanup(func() {
				select {
				case <-finished:
				default:
					start.Process.Kill()
					<-finished
				}
			})
			deadline := time.Now().Add(15 * time.Second)
			for {
				o, err := m.w.object(ctx, id)
				if err == nil && o.Identity.Status == "running" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("vendor process did not run")
				}
				time.Sleep(50 * time.Millisecond)
			}
			time.Sleep(200 * time.Millisecond)
			if run(t, ctx, "container", "inspect", id, "--format", "{{.State.Running}}") != "true" {
				t.Fatal("vendor process exited")
			}
			operation, unlock, err := acquireServiceOperation(ctx, m.w.host.root)
			if err != nil {
				t.Fatal(err)
			}
			run(t, operation, "stop", "--time", "20", id)
			unlock()
			select {
			case err := <-done:
				if err != nil {
					// This fixed node-exporter image exits with the normal SIGTERM
					// status 143 on docker stop, which start --attach propagates.
					var state struct {
						ExitCode  int
						OOMKilled bool
						Error     string
					}
					stateRaw := run(t, ctx, "container", "inspect", id, "--format", "{{json .State}}")
					exit, ok := err.(*exec.ExitError)
					if role != "exporter" || !ok || exit.ExitCode() != 143 || json.Unmarshal([]byte(stateRaw), &state) != nil || state.ExitCode != 143 || state.OOMKilled || state.Error != "" {
						t.Fatal("attached client failed", err, string(output.raw))
					}
					t.Log("exporter propagated confirmed normal SIGTERM exit 143; no OOM or engine error")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("attached Docker client did not finish")
			}
			after, err := m.w.object(ctx, id)
			if err != nil || after.Identity.ID != id || after.fingerprint() != captured.Object.fingerprint() || after.Identity.Status != "exited" {
				t.Fatal("actual stop/start changed immutable object or settings", err)
			}
			t.Log("real vendor object retained across generated ID-based start/stop; manager and idle service state are substitutes")
		})
	}
}
