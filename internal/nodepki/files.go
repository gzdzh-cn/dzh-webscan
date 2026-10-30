package nodepki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// FileTrust accepts a fixed administrator-installed root and complete signed
// CRL snapshots. The CA key is never needed by an online Agent or collector.
// Snapshots must be replaced atomically. This cache checks at most once/second;
// read errors fail closed, including on already-established HTTP/2 connections.
// NewPersistentFileTrust additionally retains its revision/revocation floor
// across restarts. Issuance, distribution and CA rollover remain separate.
type FileTrust struct {
	trust          *Trust
	crlFile        string
	mu             sync.Mutex
	lastCheck      time.Time
	lastErr        error
	stateDirectory string
	ca             []byte
	snapshot       []byte
	snapshotSHA    string
}

func NewFileTrust(caFile, crlFile string, now time.Time) (*FileTrust, error) {
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return nil, ErrIdentity
	}
	crl, err := readTrustFile(crlFile, MaxCRLBytes)
	if err != nil {
		return nil, ErrRevocation
	}
	trust, err := NewTrust(ca, crl, now)
	if err != nil {
		return nil, err
	}
	p := &FileTrust{trust: trust, crlFile: crlFile, lastCheck: now, ca: ca}
	p.setSnapshot(crl)
	return p, nil
}
func (p *FileTrust) setSnapshot(raw []byte) {
	sum := sha256.Sum256(raw)
	p.snapshot, p.snapshotSHA = append([]byte{}, raw...), hex.EncodeToString(sum[:])
}

// refreshLocked shares disk reads, signature checks and snapshot bytes among
// every node worker of a collector; it does not read once per target node.
func (p *FileTrust) refreshLocked(now time.Time) {
	if now.Before(p.lastCheck) || now.Sub(p.lastCheck) >= time.Second {
		raw, err := readTrustFile(p.crlFile, MaxCRLBytes)
		if err == nil {
			err = p.trust.UpdateCRL(raw, now)
		}
		if err == nil && p.stateDirectory != "" {
			var accepted *Trust
			accepted, err = persistentTrust(p.stateDirectory, p.ca, raw, now)
			if err == nil {
				p.trust = accepted
			}
		}
		p.lastCheck, p.lastErr = now, err
		if err == nil {
			p.setSnapshot(raw)
		}
	}
}

func (p *FileTrust) Verify(cert *x509.Certificate, role, id string, now time.Time) error {
	p.mu.Lock()
	p.refreshLocked(now)
	err := p.lastErr
	trust := p.trust
	p.mu.Unlock()
	if err != nil {
		return ErrRevocation
	}
	return trust.Verify(cert, role, id, now)
}

// Snapshot returns public signed CRL bytes only if their digest changed since
// known. Expired/failed trust never supplies an apparent current snapshot.
func (p *FileTrust) Snapshot(now time.Time, known string) ([]byte, string, error) {
	if p == nil {
		return nil, "", ErrRevocation
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refreshLocked(now)
	if p.lastErr != nil || !p.trust.validAt(now) || p.snapshotSHA == "" {
		return nil, "", ErrRevocation
	}
	if known == p.snapshotSHA {
		return nil, p.snapshotSHA, nil
	}
	return append([]byte{}, p.snapshot...), p.snapshotSHA, nil
}
func readTrustFile(path string, limit int64) ([]byte, error) {
	return readIdentityFile(path, limit, false)
}

func readIdentityFile(path string, limit int64, private bool) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrIdentity
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, ErrIdentity
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() < 1 || st.Size() > limit {
		return nil, ErrIdentity
	}
	if private && st.Mode().Perm()&0077 != 0 {
		return nil, ErrIdentity
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrIdentity
	}
	return raw, nil
}
