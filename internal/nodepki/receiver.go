package nodepki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"
)

// ReceiverTrust uses its durable complete CRL as both the live source and the
// monotonic floor. The immutable installation CRL is used only on first setup.
// An expired authentic floor may start the listener, but authorizes no ordinary
// RPC until an allowed, currently valid collector supplies a valid newer CRL.
// It never changes the pinned CA, leaf identity or any other configuration.
type ReceiverTrust struct {
	*FileTrust
	updates chan struct{}
}

type CRLReceipt struct {
	SHA256     string
	Number     string
	NextUpdate time.Time
}

func NewReceiverTrust(caFile, seedFile, directory string, now time.Time) (*ReceiverTrust, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrRevocation
	}
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return nil, ErrIdentity
	}
	if _, err := os.Lstat(directory); err == nil {
		roots, receipt, err := readRootSet(directory, ca, now, true)
		if err != nil {
			return nil, err
		}
		if roots != nil {
			return &ReceiverTrust{&FileTrust{rootSet: roots, rootReceipt: receipt, crlFile: filepath.Join(directory, "ca.crl"), stateDirectory: directory, ca: ca, lastCheck: now}, make(chan struct{}, 1)}, nil
		}
	}
	root, err := parseCertificate(ca)
	if err != nil || !validAuthority(root, now) {
		return nil, ErrIdentity
	}
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		seed, err := readTrustFile(seedFile, MaxCRLBytes)
		if err != nil || initializeTrustState(directory, ca, seed, now) != nil {
			return nil, ErrRevocation
		}
	}
	if secureDirectory(directory) != nil {
		return nil, ErrRevocation
	}
	pinned, err := readIdentityFile(filepath.Join(directory, "ca.crt"), 64<<10, true)
	if err != nil {
		return nil, ErrIdentity
	}
	pinnedRoot, err := parseCertificate(pinned)
	if err != nil || !bytes.Equal(root.Raw, pinnedRoot.Raw) {
		return nil, ErrIdentity
	}
	file := filepath.Join(directory, "ca.crl")
	crl, err := readIdentityFile(file, MaxCRLBytes, true)
	if err != nil {
		return nil, ErrRevocation
	}
	list, err := parseCRL(crl, root)
	if err != nil || list.ThisUpdate.After(now) {
		return nil, ErrRevocation
	}
	trust, err := NewTrust(ca, crl, list.ThisUpdate)
	if err != nil {
		return nil, err
	}
	p := &FileTrust{trust: trust, crlFile: file, stateDirectory: directory, ca: ca, lastCheck: now}
	p.setSnapshot(crl)
	return &ReceiverTrust{p, make(chan struct{}, 1)}, nil
}

// Publish authenticates the caller under the proposed current signed snapshot
// AND preserves all revocations in the installed floor. This narrow path can
// recover from CRL expiry without granting ordinary RPCs a stale-policy bypass.
// The caller must additionally enforce its configured collector allowlist.
func (p *ReceiverTrust) Publish(ctx context.Context, cert *x509.Certificate, raw []byte, now time.Time) (CRLReceipt, error) {
	if p == nil || p.FileTrust == nil || ctx.Err() != nil {
		return CRLReceipt{}, ErrRevocation
	}
	if roots, _, err := ReadRootSet(p.stateDirectory, p.ca, now); err != nil || roots != nil {
		return CRLReceipt{}, ErrRootRotation
	}
	// A caller without a deadline cannot hold the trust lock indefinitely.
	// Serialize expensive validation too, without queueing unbounded work.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case p.updates <- struct{}{}:
		defer func() { <-p.updates }()
	case <-ctx.Done():
		return CRLReceipt{}, ctx.Err()
	}
	id, err := PeerID(cert, Collector)
	if err != nil {
		return CRLReceipt{}, ErrIdentity
	}
	current, err := NewTrust(p.ca, raw, now)
	if err != nil || current.Verify(cert, Collector, id, now) != nil {
		return CRLReceipt{}, ErrRevocation
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if secureDirectory(p.stateDirectory) != nil {
		return CRLReceipt{}, ErrRevocation
	}
	lock, err := authorityLock(ctx, p.stateDirectory)
	if err != nil {
		return CRLReceipt{}, err
	}
	defer lock.Close()
	if roots, _, err := ReadRootSet(p.stateDirectory, p.ca, now); err != nil || roots != nil {
		return CRLReceipt{}, ErrRootRotation
	}
	pinned, err := readIdentityFile(filepath.Join(p.stateDirectory, "ca.crt"), 64<<10, true)
	if err != nil || !bytes.Equal(pinned, p.ca) {
		return CRLReceipt{}, ErrIdentity
	}
	floor, err := readIdentityFile(p.crlFile, MaxCRLBytes, true)
	if err != nil || ValidateCRLAdvance(p.ca, floor, raw, now) != nil {
		return CRLReceipt{}, ErrRevocation
	}
	// Check the process floor as well as the persisted floor, before writing.
	// On a storage failure the process stays closed until a successful retry.
	if err := ctx.Err(); err != nil {
		return CRLReceipt{}, err
	}
	if err := p.trust.UpdateCRL(raw, now); err != nil {
		return CRLReceipt{}, err
	}
	if !bytes.Equal(floor, raw) {
		if err := replaceCRL(p.stateDirectory, raw); err != nil {
			p.lastErr = ErrRevocation
			return CRLReceipt{}, err
		}
	}
	p.lastCheck, p.lastErr = now, nil
	p.setSnapshot(raw)
	root, _ := parseCertificate(p.ca)
	list, _ := parseCRL(raw, root) // authenticated above
	sum := sha256.Sum256(raw)
	return CRLReceipt{hex.EncodeToString(sum[:]), list.Number.Text(10), list.NextUpdate}, nil
}
