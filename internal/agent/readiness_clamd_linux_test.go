//go:build linux

package agent

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
)

// This opt-in fixture runs its own foreground daemon with one harmless local
// signature. It never uses the host's clamd socket or downloads virus databases.
func TestScannerReadinessWithPrivateClamd(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_CLAMD") != "1" {
		t.Skip("requires disposable Linux scanner-daemon image")
	}
	client, err := exec.LookPath("clamdscan")
	if err != nil {
		t.Fatal(err)
	}
	daemon, err := exec.LookPath("clamd")
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	database := filepath.Join(base, "signatures")
	if err := os.Mkdir(database, 0700); err != nil {
		t.Fatal(err)
	}
	marker := "Webscan scanner readiness"
	if err := os.WriteFile(filepath.Join(database, "safe-test.ndb"), []byte("Webscan.SafeTest:0:*:"+hex.EncodeToString([]byte(marker))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(base, "clamd.sock")
	conf := filepath.Join(base, "clamd.conf")
	raw := fmt.Sprintf("Foreground yes\nUser root\nLocalSocket %s\nDatabaseDirectory %s\nMaxThreads 2\nMaxQueue 4\nSelfCheck 0\nConcurrentDatabaseReload no\n", socket, database)
	if err := os.WriteFile(conf, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, daemon, "--config-file="+conf)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stop := func() {
		if !stopped {
			cancel()
			<-done
			stopped = true
		}
	}
	defer stop()
	for {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
		if err == nil {
			conn.SetDeadline(time.Now().Add(time.Second))
			_, err = io.WriteString(conn, "nPING\n")
			if err == nil {
				var response [16]byte
				n, readErr := conn.Read(response[:])
				err = readErr
				if readErr == nil && strings.TrimSpace(string(response[:n])) == "PONG" {
					conn.Close()
					break
				}
			}
			conn.Close()
		}
		select {
		case err := <-done:
			stopped = true
			t.Fatal("private clamd exited before ready", err)
		case <-ctx.Done():
			t.Fatal("private clamd did not become ready", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	a, agentCtx := testAgent(t)
	enableTestScanner(a, "yara", scannerFixture(t, "exit 0"))
	enableTestScanner(a, "clamav", client)
	a.C["clamav_config"] = conf
	// Prove the real daemon used the test signature, not merely a successful
	// version/ping command or an unreachable default socket.
	input := []byte("<?php /* " + marker + " */\n")
	path := filepath.Join(a.Data, "private-clamd-input.php")
	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := a.scanEngine(agentCtx, scanTask{Path: path, Hash: common.Hash(input)}, "clamav", common.M(common.M(a.C["scan"])["clamav"]), nil)
	os.Remove(path)
	if err != nil || common.S(result["status"]) != "matched" {
		t.Fatal("private signature was not actually scanned", result, err)
	}
	var before, after int
	if err := a.DB.QueryRow("SELECT count(*) FROM events").Scan(&before); err != nil {
		t.Fatal(err)
	}
	a.checkScannerReadiness(agentCtx)
	if scannerMetric(t, a, "webscan_clamav_ready") != 1 {
		t.Fatal("actual clamd did not certify private snapshot")
	}
	assertNoScannerScratch(t, a)
	stop()
	a.checkScannerReadiness(agentCtx)
	if scannerMetric(t, a, "webscan_clamav_ready") != 0 || scannerMetric(t, a, "webscan_yara_ready") != 1 {
		t.Fatal("dead clamd reused old success or masked YARA")
	}
	assertNoScannerScratch(t, a)
	if err := a.DB.QueryRow("SELECT count(*) FROM events").Scan(&after); err != nil || before != after {
		t.Fatal("scanner selftest created business events", before, after, err)
	}
	t.Log("real private clamd matched a harmless test signature; shutdown invalidated readiness without business events")
}
