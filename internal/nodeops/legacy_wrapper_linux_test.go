//go:build linux

package nodeops

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The real unit parser is exercised without connecting to a service manager.
// The sandbox contains only inert dependency definitions and a Docker stub;
// no container operation, systemctl invocation or network is permitted here.
func TestLegacyWrapperTemplatesPassSystemdAnalyze(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_SYSTEMD_ANALYZE") != "1" || os.Geteuid() != 0 {
		t.Skip("requires opted-in disposable Linux systemd parser")
	}
	root := testRoot(t)
	units := filepath.Join(root, "etc/systemd/system")
	for _, path := range []string{units, filepath.Join(root, "usr/bin")} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"sysinit.target", "basic.target", "shutdown.target", "network-online.target", "multi-user.target"} {
		if err := os.WriteFile(filepath.Join(units, name), []byte("[Unit]\nDescription=Isolated parser dependency\nDefaultDependencies=no\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(units, "docker.service"), []byte("[Unit]\nDescription=Inert Docker parser fixture\nDefaultDependencies=no\n[Service]\nExecStart=/usr/bin/docker\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/bin/docker"), []byte("#!/bin/sh\nexit 91\n"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"vector", "exporter"} {
		for _, variant := range []string{"http", "https", "retained"} {
			transport := "http"
			if variant == "https" {
				transport = "https"
			}
			t.Run(role+"/"+variant, func(t *testing.T) {
				name := "webscan-" + role + "-v1.service"
				raw := legacyWrapperFixture(t, role, transport == "https")
				u, err := parseLegacySidecarUnit(name, raw)
				if err != nil {
					t.Fatal(err)
				}
				if variant == "retained" {
					raw = retainedWrapperUnit(u, "1111111111111111111111111111111111111111111111111111111111111111")
				}
				if err := os.WriteFile(filepath.Join(units, name), raw, 0644); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "systemd-analyze", "verify", "--man=no", "--root="+root, name)
				cmd.Env = append(os.Environ(), "SYSTEMD_LOG_LEVEL=warning", "SYSTEMD_COLORS=0", "SYSTEMD_UNIT_PATH=/etc/systemd/system")
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("real systemd parser rejected legacy producer fixture: %v: %s", err, output)
				}
			})
		}
	}
}
