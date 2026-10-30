package controlplane

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var errTrustStorage = errors.New("信任资料路径不安全、目标已存在或无法持久化；请使用当前账号的私有目录及绝对规范路径")

// Walk from a pinned root descriptor. No component may be a symlink or a
// directory writable by another account (except a root-owned sticky ancestor).
// Keys and signed releases are never created through browser-supplied paths.
func trustDirectory(path string, private bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errTrustStorage
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errTrustStorage
	}
	d := os.NewFile(uintptr(fd), "/")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		parts = nil
	}
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			next, e := unix.Openat(int(d.Fd()), parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			d.Close()
			if e != nil {
				return nil, errTrustStorage
			}
			d = os.NewFile(uintptr(next), parts[i])
		}
		st, e := d.Stat()
		if e != nil {
			d.Close()
			return nil, errTrustStorage
		}
		o, ok := st.Sys().(*syscall.Stat_t)
		final := i == len(parts)-1
		if !ok || !st.IsDir() || o.Uid != 0 && o.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0022 != 0 && !(o.Uid == 0 && st.Mode()&os.ModeSticky != 0 && !final) || final && private && (o.Uid != uint32(os.Geteuid()) || st.Mode().Perm() != 0700) {
			d.Close()
			return nil, errTrustStorage
		}
	}
	return d, nil
}

func openTrustFile(path string, private bool, limit int64) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errTrustStorage
	}
	d, err := trustDirectory(filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	fd, err := unix.Openat(int(d.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errTrustStorage
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, errTrustStorage
	}
	o, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || o.Nlink != 1 || o.Uid != 0 && o.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0022 != 0 || private && (o.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0077 != 0) || st.Size() < 1 || st.Size() > limit {
		f.Close()
		return nil, errTrustStorage
	}
	return f, nil
}

func readTrustData(path string, private bool, limit int64) ([]byte, error) {
	f, err := openTrustFile(path, private, limit)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, errTrustStorage
	}
	return raw, nil
}

// Publish the entire new directory in one no-replace rename. A failed or
// concurrent invocation cannot overwrite a key or leave a usable half-release.
func publishTrustFiles(ctx context.Context, path string, files map[string][]byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || path == "/" {
		return errTrustStorage
	}
	d, err := trustDirectory(filepath.Dir(path), true)
	if err != nil {
		return err
	}
	defer d.Close()
	tmp := ".trust-" + token()
	if err := unix.Mkdirat(int(d.Fd()), tmp, 0700); err != nil {
		return errTrustStorage
	}
	fd, err := unix.Openat(int(d.Fd()), tmp, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Unlinkat(int(d.Fd()), tmp, unix.AT_REMOVEDIR)
		return errTrustStorage
	}
	stage := os.NewFile(uintptr(fd), tmp)
	defer stage.Close()
	defer func() {
		for name := range files {
			if filepath.Base(name) == name && name != "." && name != ".." {
				unix.Unlinkat(int(stage.Fd()), name, 0)
			}
		}
		unix.Unlinkat(int(d.Fd()), tmp, unix.AT_REMOVEDIR)
	}()
	for name, raw := range files {
		if filepath.Base(name) != name || name == "." || name == ".." || name == "" || ctx.Err() != nil {
			return errTrustStorage
		}
		fd, err := unix.Openat(int(stage.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			return errTrustStorage
		}
		f := os.NewFile(uintptr(fd), name)
		_, err = f.Write(raw)
		if err == nil {
			err = f.Sync()
		}
		closed := f.Close()
		if err != nil || closed != nil {
			return errTrustStorage
		}
	}
	if stage.Sync() != nil || ctx.Err() != nil {
		return errTrustStorage
	}
	if err := publishTrustDirectory(int(d.Fd()), tmp, filepath.Base(path)); err != nil {
		return errTrustStorage
	}
	// The stage descriptor now refers to the published directory. Never delete
	// its files in deferred cleanup, even if syncing the parent fails.
	files = nil
	if d.Sync() != nil {
		return errTrustStorage
	}
	return nil
}
