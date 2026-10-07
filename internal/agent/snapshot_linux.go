//go:build linux

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
	"hash"
	"io"
	"os"
)

func openSnapshotSource(path string) (*os.File, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("scan_non_regular_file")
	}
	return f, nil
}

type hashReader struct {
	source io.Reader
	hash   hash.Hash
}

func newHashReader(r io.Reader) *hashReader { return &hashReader{r, sha256.New()} }
func (r *hashReader) Read(p []byte) (int, error) {
	n, e := r.source.Read(p)
	r.hash.Write(p[:n])
	return n, e
}
func (r *hashReader) Sum() string { return hex.EncodeToString(r.hash.Sum(nil)) }
