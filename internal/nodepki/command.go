package nodepki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Options struct {
	Action, Authority, Output, Role, ID, Names, Certificate string
	LifetimeHours                                           int
	CAFile, IdentityFile, Source, ExpectedSHA256            string
}

var errStorage = errors.New("证书目录或文件不安全、已存在或无法持久化")

// Command is an explicit offline administrator tool. It does not register a
// node, distribute keys, restart a listener or install a production trust root.
func Command(ctx context.Context, o Options, out io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	if o.Action == "publish-identity" || o.Action == "renew-identity" {
		return identityCommand(ctx, o, out, now)
	}
	if o.CAFile != "" || o.IdentityFile != "" || o.Source != "" || o.ExpectedSHA256 != "" {
		return ErrIdentity
	}
	if o.Action == "init" {
		if o.Authority == "" || o.Output != "" || o.Role != "" || o.ID != "" || o.Names != "" || o.Certificate != "" || o.LifetimeHours != 0 {
			return ErrIdentity
		}
		authority, err := NewAuthority(now, 5*365*24*time.Hour)
		if err != nil {
			return err
		}
		bundle, err := authority.Export()
		if err != nil {
			return err
		}
		crl, err := authority.Revoke(nil, nil, now, 24*time.Hour)
		if err != nil {
			return err
		}
		if err := newPrivateDirectory(o.Authority, map[string][]byte{"ca.crt": bundle.CA, "ca.key": bundle.Key, "ca.crl": crl, "crls/1.pem": crl}); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"status": "initialized", "authority": o.Authority})
	}
	if o.Action != "issue" && o.Action != "revoke" && o.Action != "renew-crl" {
		return errors.New("证书操作须为 init、issue、revoke、renew-crl、publish-identity 或 renew-identity")
	}
	if err := secureDirectory(o.Authority); err != nil {
		return err
	}
	lock, err := authorityLock(ctx, o.Authority)
	if err != nil {
		return err
	}
	defer func() { unix.Flock(int(lock.Fd()), unix.LOCK_UN); lock.Close() }()
	ca, err := readTrustFile(filepath.Join(o.Authority, "ca.crt"), 64<<10)
	if err != nil {
		return errStorage
	}
	keyPath := filepath.Join(o.Authority, "ca.key")
	key, err := readIdentityFile(keyPath, 64<<10, true)
	if err != nil {
		return errStorage
	}
	authority, err := ParseAuthority(ca, key, now)
	if err != nil {
		return err
	}
	crl, number, err := latestCRL(o.Authority, authority)
	if err != nil {
		return err
	}
	switch o.Action {
	case "issue":
		if o.Output == "" || o.Certificate != "" {
			return ErrIdentity
		}
		hours := o.LifetimeHours
		if hours == 0 {
			hours = 30 * 24
		}
		if hours < 1 || hours > 90*24 {
			return ErrIdentity
		}
		var names []string
		if o.Names != "" {
			names = strings.Split(o.Names, ",")
		}
		// A fresh leaf must not be distributed with expired revocation evidence.
		if _, err := NewTrust(ca, crl, now); err != nil {
			return err
		}
		bundle, err := authority.Issue(o.Role, o.ID, names, now, time.Duration(hours)*time.Hour)
		if err != nil {
			return err
		}
		if err := newPrivateDirectory(o.Output, map[string][]byte{"ca.crt": ca, "ca.crl": crl, "identity.crt": bundle.Certificate, "identity.key": bundle.Key}); err != nil {
			return err
		}
		cert, _ := parseCertificate(bundle.Certificate)
		return json.NewEncoder(out).Encode(map[string]string{"status": "issued", "role": o.Role, "id": o.ID, "serial": cert.SerialNumber.Text(16), "output": o.Output})
	default:
		if o.Output != "" || o.Role != "" || o.ID != "" || o.Names != "" || o.LifetimeHours != 0 {
			return ErrIdentity
		}
		var certificates [][]byte
		if o.Action == "revoke" {
			raw, err := readTrustFile(o.Certificate, 64<<10)
			if err != nil {
				return ErrIdentity
			}
			certificates = [][]byte{raw}
		} else if o.Certificate != "" {
			return ErrIdentity
		}
		next, err := authority.Revoke(crl, certificates, now, 24*time.Hour)
		if err != nil {
			return err
		}
		// Immutable history is durable first. If publishing is interrupted, the
		// next invocation selects this newer snapshot and repairs the active copy.
		name := filepath.Join(o.Authority, "crls", strconv.FormatInt(number+1, 10)+".pem")
		if err := writeExclusive(name, next); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(name)); err != nil {
			return err
		}
		if err := replaceCRL(o.Authority, next); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"status": "crl-updated", "revision": number + 1})
	}
}

func secureDirectory(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errStorage
	}
	for current := dir; ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errStorage
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) {
			return errStorage
		}
		// Root-owned sticky temporary parents are allowed; the final directory is
		// private and owned by the running administrator. No symlink is traversed.
		if st.Mode().Perm()&0022 != 0 && !(st.Mode()&os.ModeSticky != 0 && owner.Uid == 0) {
			return errStorage
		}
		if current == dir && (st.Mode().Perm() != 0700 || owner.Uid != uint32(os.Geteuid())) {
			return errStorage
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}
func newPrivateDirectory(dir string, files map[string][]byte) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errStorage
	}
	// Require a private existing parent; output locations come only from CLI.
	if err := secureDirectory(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return errStorage
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(dir)
		}
	}()
	for name, raw := range files {
		if strings.Contains(name, "/") {
			if filepath.Dir(name) != "crls" {
				return errStorage
			}
			if err := os.MkdirAll(filepath.Join(dir, "crls"), 0700); err != nil {
				return errStorage
			}
		}
		if err := writeExclusive(filepath.Join(dir, name), raw); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "crls")); err == nil {
		if err := syncDir(filepath.Join(dir, "crls")); err != nil {
			return err
		}
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(dir)); err != nil {
		return err
	}
	complete = true
	return nil
}
func writeExclusive(path string, raw []byte) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return errStorage
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return errStorage
	}
	if err := f.Sync(); err != nil {
		return errStorage
	}
	return nil
}
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return errStorage
	}
	defer f.Close()
	if f.Sync() != nil {
		return errStorage
	}
	return nil
}
func authorityLock(ctx context.Context, root string) (*os.File, error) {
	path := filepath.Join(root, ".lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errStorage
	}
	f := os.NewFile(uintptr(fd), path)
	valid := false
	defer func() {
		if !valid {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, errStorage
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return nil, errStorage
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			valid = true
			return f, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			return nil, errStorage
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
func latestCRL(root string, a *Authority) ([]byte, int64, error) {
	dir := filepath.Join(root, "crls")
	if err := secureDirectory(dir); err != nil {
		return nil, 0, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > 10000 {
		return nil, 0, errStorage
	}
	var latest []byte
	var number int64
	for _, e := range entries {
		name := e.Name()
		n, err := strconv.ParseInt(strings.TrimSuffix(name, ".pem"), 10, 64)
		if err != nil || n < 1 || n >= 1<<62 || name != fmt.Sprintf("%d.pem", n) || e.IsDir() {
			return nil, 0, errStorage
		}
		if n > number {
			raw, err := readTrustFile(filepath.Join(dir, name), MaxCRLBytes)
			if err != nil {
				return nil, 0, err
			}
			list, err := parseCRL(raw, a.certificate)
			if err != nil || !list.Number.IsInt64() || list.Number.Int64() != n {
				return nil, 0, ErrRevocation
			}
			latest, number = raw, n
		}
	}
	if number == 0 {
		return nil, 0, ErrRevocation
	}
	active, err := readTrustFile(filepath.Join(root, "ca.crl"), MaxCRLBytes)
	if err != nil {
		return nil, 0, err
	}
	list, err := parseCRL(active, a.certificate)
	if err != nil || !list.Number.IsInt64() || list.Number.Int64() > number {
		return nil, 0, ErrRevocation
	}
	if string(active) != string(latest) {
		if list.Number.Int64() == number {
			return nil, 0, ErrRevocation
		}
		if err := replaceCRL(root, latest); err != nil {
			return nil, 0, err
		}
	}
	return latest, number, nil
}
func replaceCRL(root string, raw []byte) error {
	f, err := os.CreateTemp(root, ".crl-")
	if err != nil {
		return errStorage
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return errStorage
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return errStorage
	}
	if err := f.Close(); err != nil {
		return errStorage
	}
	if err := os.Rename(name, filepath.Join(root, "ca.crl")); err != nil {
		return errStorage
	}
	return syncDir(root)
}
