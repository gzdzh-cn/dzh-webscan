//go:build linux

package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
)

func TestStartupProbeWaitsForInventoryAndThenProducesEvents(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "first-start"
		if restart {
			name = "restart"
		}
		t.Run(name, func(t *testing.T) {
			a, parent := newTestAgent(t)
			a.C["scanner_tools"] = common.Map{"yara": scannerFixture(t, "exit 0")}
			scan := common.Clone(common.M(a.C["scan"]))
			for _, engine := range []string{"yara", "clamav"} {
				common.M(scan[engine])["enabled"] = false
			}
			a.C["scan"] = scan
			if restart {
				if err := a.counter("baseline_completed", 1, true); err != nil {
					t.Fatal(err)
				}
			}
			// Block the actual inventory while the actual Run workers start.
			// Probe writes must wait even if inventory is slow on restart.
			a.inventoryMu.Lock()
			locked := true
			ctx, cancel := context.WithCancel(parent)
			result := make(chan error, 1)
			go func() { result <- a.Run(ctx) }()
			defer func() {
				cancel()
				if locked {
					a.inventoryMu.Unlock()
				}
				select {
				case <-result:
				case <-time.After(5 * time.Second):
					t.Error("Agent did not stop")
				}
			}()
			await(t, func() bool {
				select {
				case err := <-result:
					result <- err
					t.Fatal("Agent exited while starting", err)
				default:
				}
				var heartbeat float64
				return a.DB.QueryRow("SELECT value FROM counters WHERE key='agent_heartbeat_seconds'").Scan(&heartbeat) == nil && heartbeat > 0
			})
			path := filepath.Join(a.Probe, "heartbeat.php")
			timer := time.NewTimer(250 * time.Millisecond)
			defer timer.Stop()
			select {
			case err := <-result:
				result <- err
				t.Fatal("Agent exited before inventory", err)
			case <-timer.C:
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) || a.ready.Load() {
				t.Fatal("probe wrote before initial inventory completed", err)
			}
			a.inventoryMu.Unlock()
			locked = false
			await(t, func() bool {
				return a.ready.Load() && len(operations(a, path)) > 0
			})
		})
	}
}

func TestFileChangedAfterSnapshotCannotCommitStaleHash(t *testing.T) {
	for _, mutation := range []string{"rewrite", "replace", "symlink"} {
		t.Run(mutation, func(t *testing.T) {
			a, ctx := newTestAgent(t)
			path := filepath.Join(root(a), "changing.php")
			original := []byte("<?php /* original */\n")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := a.Process(ctx, path, "create", "", true, false); err != nil {
				t.Fatal(err)
			}
			fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if _, err := unix.InotifyAddWatch(fd, path, unix.IN_CLOSE_NOWRITE); err != nil {
				t.Fatal(err)
			}
			a.writeMu.Lock()
			locked := true
			defer func() {
				if locked {
					a.writeMu.Unlock()
				}
			}()
			result := make(chan error, 1)
			a.worker.Add(1)
			go func() {
				defer a.worker.Done()
				result <- a.Process(ctx, path, "modify", "", false, false)
			}()
			// Actual close-after-read notification proves the snapshot finished;
			// the write mutex keeps its transaction from starting meanwhile.
			await(t, func() bool {
				var events [4096]byte
				n, err := unix.Read(fd, events[:])
				return err == nil && n >= unix.SizeofInotifyEvent
			})
			changed := []byte("<?php /* replacement contents */\n")
			switch mutation {
			case "rewrite":
				err = os.WriteFile(path, changed, 0600)
			case "replace":
				next := path + ".new"
				if err = os.WriteFile(next, changed, 0600); err == nil {
					err = os.Rename(next, path)
				}
			case "symlink":
				next := path + ".target"
				if err = os.WriteFile(next, changed, 0600); err == nil {
					err = os.Remove(path)
				}
				if err == nil {
					err = os.Symlink(next, path)
				}
			}
			a.writeMu.Unlock()
			locked = false
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err == nil || err.Error() != "content_changed_before_commit" {
					t.Fatal("changed file was not rejected", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("file processing did not finish")
			}
			var hash string
			if err := a.DB.QueryRow("SELECT hash FROM manifest WHERE path=?", path).Scan(&hash); err != nil || hash != common.Hash(original) {
				t.Fatal("stale transaction changed baseline", hash, err)
			}
			if len(operations(a, path)) != 0 {
				t.Fatal("stale hash produced a file event")
			}
		})
	}
}
