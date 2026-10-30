//go:build linux

package nodeops

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This is a real systemctl client connected to a deliberately non-responsive
// private test bus. It proves descriptor/operation-lock retention, not service
// startup, cgroup limits or a real systemd manager lifecycle.
func TestSystemctlMutationRetainsOperationLock(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_SYSTEMD_ANALYZE") != "1" || os.Geteuid() != 0 {
		t.Skip("requires opted-in disposable Linux systemd validator")
	}
	for _, path := range []string{"/run/systemd/system", "/run/systemd/private"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refusing existing systemd runtime", path, err)
		}
	}
	if err := os.MkdirAll("/run/systemd/system", 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove("/run/systemd/system") })
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: "/run/systemd/private", Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.SetDeadline(time.Now().Add(4 * time.Second))
	root := testRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx, release, err := acquireServiceOperation(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	done := make(chan error, 1)
	go func() { _, err := inventoryCommand(ctx, "systemctl", "start", nativeServiceName); done <- err }()
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal("real systemctl did not contact isolated private bus", err)
	}
	defer connection.Close()
	var pid int
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		peer, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			peerErr = e
			return
		}
		pid = int(peer.Pid)
	}); err != nil || peerErr != nil || pid < 1 {
		t.Fatal("systemctl peer unavailable", err, peerErr)
	}
	t.Cleanup(func() {
		if path, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", "3")); err == nil && path == filepath.Join(root, "service-operation.lock") {
			if process, err := os.FindProcess(pid); err == nil {
				process.Kill()
			}
		}
	})
	path, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", "3"))
	if err != nil || path != filepath.Join(root, "service-operation.lock") {
		t.Fatal("systemctl discarded inherited operation lock", path, err)
	}
	if err := <-done; err == nil {
		t.Fatal("non-responsive bus reported mutation success")
	}
	release()
	if _, unlock, err := acquireServiceOperation(context.Background(), root); err == nil {
		unlock()
		t.Fatal("timed-out systemctl did not retain lock")
	}
	connection.Close()
	deadline := time.Now().Add(4 * time.Second)
	for {
		if _, unlock, err := acquireServiceOperation(context.Background(), root); err == nil {
			unlock()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("systemctl failed to release lock after bus disconnect")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
