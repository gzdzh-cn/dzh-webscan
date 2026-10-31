package nodepki

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"time"
)

// NewPersistentFileTrust stores the accepted signed CRL outside immutable
// release/config directories. Restart or config rollback must not lower this
// floor. Losing/corrupting an initialized floor fails closed; callers must back
// it up with the node/collector state. CA rollover needs an explicit migration.
func NewPersistentFileTrust(caFile, crlFile, stateDirectory string, now time.Time) (*FileTrust, error) {
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return nil, ErrIdentity
	}
	crl, err := readTrustFile(crlFile, MaxCRLBytes)
	if err != nil {
		return nil, ErrRevocation
	}
	if _, err := os.Lstat(stateDirectory); err == nil {
		roots, receipt, err := ReadRootSet(stateDirectory, ca, now)
		if err != nil {
			return nil, err
		}
		if roots != nil {
			return &FileTrust{rootSet: roots, rootReceipt: receipt, crlFile: crlFile, lastCheck: now, stateDirectory: stateDirectory, ca: ca}, nil
		}
	}
	if err := initializeTrustState(stateDirectory, ca, crl, now); err != nil {
		return nil, err
	}
	trust, err := persistentTrust(stateDirectory, ca, crl, now)
	if err != nil {
		return nil, err
	}
	p := &FileTrust{trust: trust, crlFile: crlFile, lastCheck: now, stateDirectory: stateDirectory, ca: ca}
	p.setSnapshot(crl)
	return p, nil
}

func initializeTrustState(directory string, ca, crl []byte, now time.Time) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return ErrRevocation
	}
	if _, err := NewTrust(ca, crl, now); err != nil {
		return err
	}
	parent := filepath.Dir(directory)
	if err := secureDirectory(parent); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	lock, err := authorityLock(ctx, parent)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		return secureDirectory(directory)
	}
	// Only a fully fsynced directory becomes visible. An interrupted temporary
	// directory is never treated as an accepted floor or a reason to reset one.
	stage, err := os.MkdirTemp(parent, ".trust-state-")
	if err != nil {
		return errStorage
	}
	defer os.RemoveAll(stage)
	for name, raw := range map[string][]byte{"ca.crt": ca, "ca.crl": crl} {
		if err := writeExclusive(filepath.Join(stage, name), raw); err != nil {
			return err
		}
	}
	if err := syncDir(stage); err != nil {
		return err
	}
	if err := os.Rename(stage, directory); err != nil {
		return errStorage
	}
	return syncDir(parent)
}

func persistentTrust(directory string, ca, current []byte, now time.Time) (*Trust, error) {
	if err := secureDirectory(directory); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	lock, err := authorityLock(ctx, directory)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	pinned, err := readIdentityFile(filepath.Join(directory, "ca.crt"), 64<<10, true)
	if err != nil {
		return nil, ErrIdentity
	}
	root, err := parseCertificate(ca)
	if err != nil {
		return nil, ErrIdentity
	}
	previousRoot, err := parseCertificate(pinned)
	if err != nil || !bytes.Equal(root.Raw, previousRoot.Raw) {
		return nil, ErrIdentity
	}
	floor, err := readIdentityFile(filepath.Join(directory, "ca.crl"), MaxCRLBytes, true)
	if err != nil {
		return nil, ErrRevocation
	}
	list, err := parseCRL(floor, root)
	if err != nil || list.ThisUpdate.After(now) {
		return nil, ErrRevocation
	}
	// An expired authentic floor still protects all earlier revocations. It is
	// historical evidence only; the new live snapshot must be valid *now*.
	trust, err := NewTrust(ca, floor, list.ThisUpdate)
	if err != nil || trust.UpdateCRL(current, now) != nil {
		return nil, ErrRevocation
	}
	if !bytes.Equal(floor, current) {
		if err := replaceCRL(directory, current); err != nil {
			return nil, err
		}
	}
	return trust, nil
}
