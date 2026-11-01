//go:build linux

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
)

func migrationFreezeKernelGuard(t *testing.T) {
	t.Helper()
	if os.Getenv("WEBSCAN_V3_MIGRATION_FREEZE_KERNEL") != "1" {
		t.Skip("requires explicitly enabled dedicated networkless migration guest")
	}
	marker, e := os.ReadFile("/v3-tests/kernel-guest")
	pid, pe := os.Readlink("/proc/1/exe")
	interfaces, ne := os.ReadDir("/sys/class/net")
	if os.Geteuid() != 0 || e != nil || string(marker) != "webscan-v3-networkless-kernel-guest\n" || pe != nil || pid != "/usr/lib/systemd/systemd" || ne != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("refusing non-isolated migration kernel environment")
	}
}

// Both writers execute the actual legacy central command from the newly built
// binary. Only loopback and network-none test containers exist in this guest.
func TestMigrationSessionKernelFreezeActualSystemdAndDockerWriters(t *testing.T) {
	migrationFreezeKernelGuard(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	binary, e := os.ReadFile("/v3-tests/webscan")
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"systemd", "docker"} {
		t.Run(mode, func(t *testing.T) {
			s := migrationSessionTestStore(t)
			id, sourceID := digest([]byte(t.Name())), digest([]byte("kernel-source-"+t.Name()))
			if _, e := s.BeginMigrationSession(ctx, id, 0, []string{"central"}); e != nil {
				t.Fatal(e)
			}
			root := privateTestDir(t)
			dataDir := filepath.Join(root, "legacy-data")
			if e := os.Mkdir(dataDir, 0700); e != nil {
				t.Fatal(e)
			}
			configuredDir := dataDir
			port := hostWatchdogKernelPort(t)
			if mode == "docker" {
				configuredDir = "/var/lib/webscan-legacy"
				port = "127.0.0.1:18080"
			}
			bind, portText, _ := strings.Cut(port, ":")
			portNumber, err := strconv.Atoi(portText)
			if err != nil || portNumber < 1 {
				t.Fatal("invalid isolated port")
			}
			config := common.Map{"data_dir": configuredDir, "bind": bind, "port": portNumber, "nodes": common.Map{}, "active_nodes": []string{}, "retention": common.Map{"sqlite_events_days": 90, "delivery_records_days": 90}, "feishu": common.Map{"enabled": false}, "email": common.Map{"enabled": false}}
			configRaw, _ := json.Marshal(config)
			configFile := filepath.Join(root, "legacy-runtime.json")
			localWrite(t, configFile, configRaw)
			w := MigrationFreezeWriter{Kind: mode, Role: "central", ConfigFile: configFile, ConfigSHA256: digest(configRaw)}
			stop := func() {}
			if mode == "systemd" {
				w.ID = "webscan-migration-freeze-" + token()[:10] + ".service"
				w.Executable, w.ExecutableSHA256 = "/v3-tests/webscan", digest(binary)
				w.DefinitionFile = filepath.Join("/etc/systemd/system", w.ID)
				definition := []byte("[Unit]\nDescription=Isolated legacy Webscan migration writer\n[Service]\nType=simple\nExecStart=/v3-tests/webscan central --config " + configFile + "\n[Install]\nWantedBy=multi-user.target\n")
				w.DefinitionSHA256 = digest(definition)
				localWrite(t, w.DefinitionFile, definition)
				t.Cleanup(func() {
					exec.Command("systemctl", "disable", "--now", w.ID).Run()
					os.Remove(w.DefinitionFile)
					exec.Command("systemctl", "daemon-reload").Run()
				})
				hostWatchdogKernelCommand(t, ctx, "systemctl", "daemon-reload")
				hostWatchdogKernelCommand(t, ctx, "systemctl", "enable", "--now", w.ID)
				client := &http.Client{Timeout: time.Second}
				hostWatchdogKernelWait(t, ctx, 20*time.Second, func() bool {
					r, e := client.Get("http://" + port + "/ready")
					if e != nil {
						return false
					}
					r.Body.Close()
					return r.StatusCode == 200
				}, "actual legacy systemd central ready")
				stop = func() { hostWatchdogKernelCommand(t, ctx, "systemctl", "disable", "--now", w.ID) }
			} else {
				pg := os.Getenv("WEBSCAN_V3_WATCHDOG_PG_CONTAINER")
				if pg == "" || !identifier.MatchString(pg) {
					t.Fatal("owned test PostgreSQL container required")
				}
				label := hostWatchdogKernelCommand(t, ctx, "docker", "inspect", "--format", "{{index .Config.Labels \"io.webscan.test\"}}", pg)
				if strings.TrimSpace(string(label)) != "watchdog-kernel" {
					t.Fatal("unowned test image source")
				}
				image := strings.TrimSpace(string(hostWatchdogKernelCommand(t, ctx, "docker", "inspect", "--format", "{{.Image}}", pg)))
				if !strings.HasPrefix(image, "sha256:") || !releaseDigest(strings.TrimPrefix(image, "sha256:")) {
					t.Fatal("invalid test image identity")
				}
				w.ComposeProject, w.ContainerConfigFile = "webscan_migration_freeze_"+token()[:10], "/etc/webscan/runtime.json"
				w.ID = strings.TrimSpace(string(hostWatchdogKernelCommand(t, ctx, "docker", "create", "--network", "none", "--restart", "no", "--user", "0", "--label", "io.webscan.test=migration-freeze", "--label", "com.docker.compose.project="+w.ComposeProject, "--label", "com.docker.compose.service=receiver", "--mount", "type=bind,source=/v3-tests/webscan,target=/usr/local/bin/webscan,readonly", "--mount", "type=bind,source="+configFile+",target="+w.ContainerConfigFile+",readonly", "--mount", "type=bind,source="+dataDir+",target="+configuredDir, "--entrypoint", "/usr/local/bin/webscan", image, "central", "--config", w.ContainerConfigFile)))
				if !validArchiveSource(w.ID) {
					t.Fatal("invalid isolated writer container")
				}
				t.Cleanup(func() { exec.Command("docker", "rm", "-f", w.ID).Run() })
				hostWatchdogKernelCommand(t, ctx, "docker", "start", w.ID)
				hostWatchdogKernelWait(t, ctx, 20*time.Second, func() bool {
					raw, e := exec.CommandContext(ctx, "docker", "logs", w.ID).CombinedOutput()
					return e == nil && strings.Contains(string(raw), "central_ready=goframe")
				}, "actual legacy Docker central ready")
				stop = func() { hostWatchdogKernelCommand(t, ctx, "docker", "stop", "--time", "10", w.ID) }
			}
			source := MigrationFreezeSource{Role: "central", SourceID: sourceID, SQLite: filepath.Join(dataDir, "events-v1.sqlite3"), Writers: []MigrationFreezeWriter{w}}
			if _, e := observeMigrationFrozenSource(ctx, source); !errors.Is(e, ErrMigrationSession) {
				t.Fatal("live legacy writer accepted", e)
			}
			stop()
			if proof, e := observeMigrationFrozenSource(ctx, source); e != nil || !releaseDigest(proof) {
				t.Fatal("stopped writer was not verified", e)
			}
			manifest := MigrationFreezeManifest{Format: 1, Session: id, Sources: []MigrationFreezeSource{source}}
			raw, _ := json.Marshal(manifest)
			manifestFile := filepath.Join(root, "freeze.json")
			localWrite(t, manifestFile, raw)
			frozen, e := s.FreezeMigrationSession(ctx, id, 1, manifestFile, filepath.Join(root, "snapshots"))
			if e != nil || frozen.Phase != "frozen" || len(frozen.Revisions) != 1 || !releaseDigest(frozen.FreezeDigest) {
				t.Fatal("real writer final snapshot not frozen", e)
			}
		})
	}
}
