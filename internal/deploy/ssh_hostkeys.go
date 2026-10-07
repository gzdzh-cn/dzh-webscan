package deploy

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sys/unix"
	"webscan/internal/common"
)

func ownedPrivate(st os.FileInfo) bool {
	owner, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(owner.Uid) == os.Geteuid() && st.Mode().Perm() == 0600 && st.Mode().IsRegular()
}

// Empty/missing stores permit first use; malformed or unsafe stores never do.
func readHostKeys(path string) ([]byte, ssh.HostKeyCallback, error) {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, func(string, net.Addr, ssh.PublicKey) error { return &knownhosts.KeyError{} }, nil
	}
	if err != nil {
		return nil, nil, errors.New("ssh_known_hosts_read_failed")
	}
	if !ownedPrivate(st) {
		return nil, nil, errors.New("ssh_known_hosts_insecure_permissions")
	}
	if st.Size() > 4*1048576 {
		return nil, nil, errors.New("ssh_known_hosts_invalid")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, errors.New("ssh_known_hosts_read_failed")
	}
	callback, err := knownhosts.New(path)
	if err != nil {
		return nil, nil, errors.New("ssh_known_hosts_invalid")
	}
	return data, callback, nil
}

// Commit only after SSH authentication succeeds. Recheck while holding a lock,
// so simultaneous first connections cannot overwrite each other's host pins.
func recordHostKey(ctx context.Context, path, address string, remote net.Addr, key ssh.PublicKey) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return false, errors.New("ssh_known_hosts_write_failed")
	}
	st, err := os.Lstat(parent)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("ssh_known_hosts_insecure_permissions")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		return false, errors.New("ssh_known_hosts_insecure_permissions")
	}
	if st.Mode().Perm() != 0700 {
		if err := os.Chmod(parent, 0700); err != nil {
			return false, errors.New("ssh_known_hosts_insecure_permissions")
		}
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return false, errors.New("ssh_known_hosts_write_failed")
	}
	defer lock.Close()
	st, err = lock.Stat()
	if err != nil || !ownedPrivate(st) {
		return false, errors.New("ssh_known_hosts_insecure_permissions")
	}
	for {
		err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return false, errors.New("ssh_known_hosts_write_failed")
		}
		if !common.Sleep(ctx, 20*time.Millisecond) {
			return false, ctx.Err()
		}
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	data, callback, err := readHostKeys(path)
	if err != nil {
		return false, err
	}
	err = callback(address, remote, key)
	if err == nil {
		return false, nil
	}
	var unknown *knownhosts.KeyError
	if !errors.As(err, &unknown) || len(unknown.Want) != 0 {
		return false, errors.New("ssh_host_fingerprint_mismatch")
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, []byte(knownhosts.Line([]string{address}, key)+"\n")...)
	if err := common.Atomic(path, data, 0600); err != nil {
		return false, errors.New("ssh_known_hosts_write_failed")
	}
	return true, nil
}
