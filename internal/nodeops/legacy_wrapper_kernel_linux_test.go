//go:build linux

package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Real vendor processes under a real systemd manager and its own Docker
// daemon. This proves active wrapper adoption/recovery, not a whole v2 Agent
// migration: the only runtime.json here is the private ownership identity.
func TestKernelActiveLegacyWrappersRetainOriginalContainers(t *testing.T) {
	requireDockerKernelGuest(t)
	marker, err := os.ReadFile("/v3-tests/isolated-engine")
	if os.Geteuid() != 0 || os.Getenv("WEBSCAN_V3_TEST_DIND") != "1" || err != nil || string(marker) != "webscan-v3-disposable-dind\n" {
		t.Fatal("refusing unmarked daemon")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	listing, err := inventoryCommand(ctx, "docker", "--host", "unix:///var/run/docker.sock", "ps", "-aq")
	if err != nil || strings.TrimSpace(listing) != "" {
		t.Fatal("refusing nonempty daemon", err)
	}
	for _, path := range append([]string{legacyConfigurationRoot, agentDataDirectory, agentLogDirectory, "/var/lib/webscan-vector-v1", nativeUnitPath},
		filepath.Join(filepath.Dir(nativeUnitPath), legacyWrapperNames[0]), filepath.Join(filepath.Dir(nativeUnitPath), legacyWrapperNames[1])) {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refusing existing node state", path, err)
		}
	}
	raw, err := os.ReadFile("/v3-tests/agent-native.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	w, request := stageFixture(t, raw)
	request.Spec.Mode, request.Phase = "native", "backup"
	attachConfiguration(t, w, &request, nil)
	host := newInstallationHost(w.root)
	for _, path := range []string{legacyConfigurationRoot, agentLogDirectory, agentDataDirectory, "/var/lib/webscan-vector-v1", filepath.Join(agentDataDirectory, "textfile")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// No Agent or push target is configured. Vector handles an empty private
	// file source and a blackhole sink; exporter reads this disposable guest.
	files := map[string][]byte{
		"runtime.json": []byte(`{"node_id":"` + request.Node + `","data_dir":"` + agentDataDirectory + `","log_dir":"` + agentLogDirectory + `"}`),
		"vector.yml":   []byte("data_dir: /var/lib/vector\nsources:\n  test_files:\n    type: file\n    include: [\"/var/log/webscan-v1/events-*.jsonl\"]\nsinks:\n  discard:\n    type: blackhole\n    inputs: [test_files]\n"),
		"exporter.yml": []byte("{}\n"),
	}
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(legacyConfigurationRoot, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var sources map[string]string
	proof, err := os.ReadFile("/v3-tests/sidecar-proof.json")
	if err != nil || json.Unmarshal(proof, &sources) != nil || len(sources) != 2 {
		t.Fatal("missing vendor image proof", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 90*time.Second)
		defer stop()
		cleanup, unlock, err := acquireServiceOperation(cleanup, w.root)
		if err != nil {
			t.Error("cleanup lock", err)
			return
		}
		defer unlock()
		for _, name := range legacyWrapperNames {
			if _, err := os.Lstat(filepath.Join(filepath.Dir(nativeUnitPath), name)); os.IsNotExist(err) {
				continue
			}
			if _, err := inventoryCommand(cleanup, "systemctl", "disable", "--now", name); err != nil {
				t.Error("cleanup exact test unit", name, err)
			}
		}
	})
	for _, role := range []string{"vector", "exporter"} {
		t.Run(role, func(t *testing.T) {
			if !strings.HasPrefix(sources[role], "sha256:") || !validDigest(strings.TrimPrefix(sources[role], "sha256:")) {
				t.Fatal("invalid vendor source ID")
			}
			unit := legacySidecarUnit{Role: role, SourceImage: sources[role]}
			if role == "exporter" {
				unit.MetricsPort = 19100
			}
			name := "webscan-" + role + "-v1.service"
			if err := os.WriteFile(filepath.Join(filepath.Dir(nativeUnitPath), name), unit.definition(), 0644); err != nil {
				t.Fatal(err)
			}
			operation, unlock, err := acquireServiceOperation(ctx, w.root)
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", name}} {
				if _, err := inventoryCommand(operation, "systemctl", args...); err != nil {
					t.Fatal("start actual vendor unit", err)
				}
			}
			wrapper := legacyWrapperTransition{host}
			var captured legacyWrapperIntent
			var observeErr error
			deadline := time.Now().Add(60 * time.Second)
			for time.Now().Before(deadline) {
				captured, observeErr = wrapper.observe(operation, request, name)
				if observeErr == nil && captured.Running && captured.Enabled {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if observeErr != nil || !captured.Running || !captured.Enabled {
				// Disposable test-only diagnostics contain no operational secrets.
				status, _ := inventoryCommand(ctx, "systemctl", "status", name, "--no-pager")
				t.Log(status)
				t.Fatal("actual active wrapper not proven", observeErr)
			}
			originalID := captured.Object.Identity.ID
			for attempt := 0; attempt < 2; attempt++ {
				r := request
				if attempt > 0 {
					r.Job, r.PlanDigest = "job-wrapper-next-"+role, strings.Repeat("e", 64)
				}
				captured, err := wrapper.capture(operation, r, name)
				if err != nil || captured.Object.Identity.ID != originalID || !captured.Running || !captured.Enabled || attempt > 0 && captured.RetainedSHA256 == "" {
					t.Fatal("active original/provenance not captured", err)
				}
				if err := wrapper.quiesce(operation, r, name); err != nil {
					t.Fatal("actual systemd quiesce", err)
				}
				if err := wrapper.quiescent(operation, r, name); err != nil {
					t.Fatal("actual quiescence not proven", err)
				}
				r.Phase = "restore"
				if err := wrapper.restore(operation, r, name); err != nil {
					for sample := 0; sample < 3; sample++ {
						status, _ := inventoryCommand(ctx, "systemctl", "show", name, "--property=LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,Job,MainPID")
						object, objectErr := wrapper.object(ctx, originalID)
						t.Logf("restore failure sample=%d systemd=%q object_status=%s object_error=%v", sample, status, object.Identity.Status, objectErr)
						time.Sleep(500 * time.Millisecond)
					}
					t.Fatal("actual retained-ID restoration", err)
				}
				if err := wrapper.restored(operation, r, name); err != nil {
					t.Fatal("actual restoration not proven", err)
				}
				current, err := wrapper.object(ctx, originalID)
				if err != nil || current.Identity.Status != "running" || current.fingerprint() != captured.Object.fingerprint() {
					t.Fatal("original vendor process/object changed", err)
				}
				loaded, err := os.ReadFile(filepath.Join(filepath.Dir(nativeUnitPath), name))
				if err != nil || !bytes.Equal(loaded, retainedWrapperUnit(unit, originalID)) {
					t.Fatal("retained-ID unit not installed", err)
				}
				// Replaying completed restoration cannot replace the attached
				// client or restart the vendor process.
				before, err := wrapper.status(ctx, captured, true)
				if err != nil || before.MainPID < 1 {
					t.Fatal(err)
				}
				if err := wrapper.restore(operation, r, name); err != nil {
					t.Fatal(err)
				}
				after, err := wrapper.status(ctx, captured, true)
				if err != nil || after.MainPID != before.MainPID {
					t.Fatal("restoration replay restarted attached client", err)
				}
				t.Logf("actual %s active capture/quiesce/restore %s: original container and systemd PID %d retained", role, strconv.Itoa(attempt+1), after.MainPID)
			}
		})
	}
}
