//go:build linux

package controlplane

import (
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
)

func hostWatchdogListener(spec HostWatchdogSpec) (net.Listener, func(), error) {
	parent := filepath.Dir(spec.Socket)
	if os.MkdirAll(parent, 0700) != nil {
		return nil, nil, errHostWatchdog
	}
	d, err := trustDirectory(parent, true)
	if err != nil {
		return nil, nil, errHostWatchdog
	}
	d.Close()
	fd, err := unix.Open(filepath.Join(parent, ".watchdog.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, nil, errHostWatchdog
	}
	lock := os.NewFile(uintptr(fd), "watchdog-lock")
	st, e := lock.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !snapshotOwned(st) {
		lock.Close()
		return nil, nil, errHostWatchdog
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		lock.Close()
		return nil, nil, errHostWatchdog
	}
	if st, e := os.Lstat(spec.Socket); e == nil {
		if st.Mode()&os.ModeSocket == 0 || !snapshotOwned(st) || st.Mode().Perm()&0077 != 0 {
			lock.Close()
			return nil, nil, errHostWatchdog
		}
		if os.Remove(spec.Socket) != nil {
			lock.Close()
			return nil, nil, errHostWatchdog
		}
	} else if !os.IsNotExist(e) {
		lock.Close()
		return nil, nil, errHostWatchdog
	}
	listener, err := net.Listen("unix", spec.Socket)
	if err != nil {
		lock.Close()
		return nil, nil, err
	}
	if os.Chmod(spec.Socket, 0600) != nil {
		listener.Close()
		lock.Close()
		return nil, nil, errHostWatchdog
	}
	cleanup := func() { listener.Close(); os.Remove(spec.Socket); lock.Close() }
	return &hostPeerListener{Listener: listener}, cleanup, nil
}

type hostPeerListener struct{ net.Listener }

func (l *hostPeerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		u, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			continue
		}
		raw, err := u.SyscallConn()
		if err != nil {
			c.Close()
			continue
		}
		var cred *unix.Ucred
		var peerErr error
		err = raw.Control(func(fd uintptr) { cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
		if err == nil && peerErr == nil && cred != nil && cred.Uid == uint32(os.Geteuid()) {
			return c, nil
		}
		c.Close()
	}
}
func hostWatchdogPlatform() error {
	if os.Geteuid() != 0 {
		return errHostWatchdog
	}
	return nil
}
