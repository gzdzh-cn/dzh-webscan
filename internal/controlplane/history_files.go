package controlplane

import (
	"context"
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const historyPartLimit = 8 << 20

type historyPart struct {
	ID             string
	Ordinal, Bytes int64
	SHA256         string
}

func (s *Store) historyDirectory() (*os.File, error) {
	if s.ExportDirectory == "" {
		return nil, ErrHistoryExport
	}
	d, err := privateDirectory(s.ExportDirectory)
	if err != nil {
		return nil, ErrHistoryExport
	}
	return d, nil
}

func writeHistoryPart(ctx context.Context, d *os.File, id string, raw []byte) error {
	if !validArchiveSource(id) || len(raw) > historyPartLimit {
		return ErrHistoryExport
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(d.Fd()), &fs) != nil || uint64(fs.Bavail)*uint64(fs.Bsize) < uint64(len(raw))+(64<<20) {
		return ErrHistoryExport
	}
	tmp, name := id+".partial", id+".jsonl"
	fd, err := unix.Openat(int(d.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrHistoryExport
	}
	f := os.NewFile(uintptr(fd), tmp)
	defer f.Close()
	defer unix.Unlinkat(int(d.Fd()), tmp, 0)
	for offset := 0; offset < len(raw); {
		if err = ctx.Err(); err != nil {
			return err
		}
		n, e := f.Write(raw[offset:min(offset+(64<<10), len(raw))])
		if e != nil || n == 0 {
			return ErrHistoryExport
		}
		offset += n
	}
	if err = f.Sync(); err != nil {
		return ErrHistoryExport
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = unix.Renameat(int(d.Fd()), tmp, int(d.Fd()), name); err != nil {
		return ErrHistoryExport
	}
	if d.Sync() != nil {
		return ErrHistoryExport
	}
	return nil
}

func readHistoryPart(ctx context.Context, d *os.File, p historyPart) ([]byte, error) {
	if !validArchiveSource(p.ID) || p.Bytes < 0 || p.Bytes > historyPartLimit || !validArchiveSource(p.SHA256) {
		return nil, ErrHistoryExport
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	fd, err := unix.Openat(int(d.Fd()), p.ID+".jsonl", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrHistoryExport
	}
	f := os.NewFile(uintptr(fd), p.ID)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, ErrHistoryExport
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() != p.Bytes {
		return nil, ErrHistoryExport
	}
	raw, err := io.ReadAll(io.LimitReader(f, historyPartLimit+1))
	if err != nil || int64(len(raw)) != p.Bytes || digest(raw) != p.SHA256 {
		return nil, ErrHistoryExport
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return raw, nil
}

func removeHistoryPart(d *os.File, id string) error {
	if !validArchiveSource(id) {
		return ErrHistoryExport
	}
	for _, suffix := range []string{".jsonl", ".partial"} {
		if err := unix.Unlinkat(int(d.Fd()), id+suffix, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return ErrHistoryExport
		}
	}
	return d.Sync()
}
