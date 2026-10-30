package nodepki

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"time"
)

// SeedNodeIdentity imports a node's immutable installation identity exactly
// once. The complete private directory is published atomically; subsequent
// starts never read the seed key or replace the active identity. In particular,
// rolling back configuration must not roll back a renewed node certificate.
// An existing incomplete directory fails closed. Like the durable CRL floor,
// complete state-directory deletion or disk rollback requires external recovery.
func SeedNodeIdentity(ctx context.Context, caFile, seed, directory, id string, now time.Time) (IdentityRecord, error) {
	var empty IdentityRecord
	if _, err := Identity(Node, id); err != nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !filepath.IsAbs(seed) || filepath.Clean(seed) != seed || seed == directory || secureDirectory(filepath.Dir(directory)) != nil {
		return empty, ErrIdentity
	}
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return empty, ErrIdentity
	}
	root, err := parseCertificate(ca)
	if err != nil || !validAuthority(root, now) {
		return empty, ErrIdentity
	}
	lock, err := authorityLock(ctx, filepath.Dir(directory))
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		if secureDirectory(seed) != nil {
			return empty, ErrIdentity
		}
		cert, err := readTrustFile(filepath.Join(seed, "identity.crt"), 64<<10)
		if err != nil {
			return empty, ErrIdentity
		}
		key, err := readIdentityFile(filepath.Join(seed, "identity.key"), 64<<10, true)
		if err != nil {
			return empty, ErrIdentity
		}
		defer clear(key)
		raw := append(append([]byte{}, cert...), key...)
		defer clear(raw)
		if _, _, err := identityPair(raw, ca, Node, id, now, false); err != nil {
			return empty, err
		}
		stage, err := os.MkdirTemp(filepath.Dir(directory), ".node-identity-*")
		if err != nil {
			return empty, errStorage
		}
		defer os.RemoveAll(stage)
		for name, content := range map[string][]byte{"ca.crt": ca, "active.pem": raw} {
			if err := writeExclusive(filepath.Join(stage, name), content); err != nil {
				return empty, err
			}
		}
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if syncDir(stage) != nil || identityRenameNoReplace(stage, directory) != nil || syncDir(filepath.Dir(directory)) != nil {
			return empty, errStorage
		}
	} else if err != nil {
		return empty, errStorage
	}
	if secureDirectory(directory) != nil {
		return empty, errStorage
	}
	pinned, err := readIdentityFile(filepath.Join(directory, "ca.crt"), 64<<10, true)
	if err != nil {
		return empty, ErrIdentity
	}
	prior, err := parseCertificate(pinned)
	if err != nil || !bytes.Equal(root.Raw, prior.Raw) {
		return empty, ErrIdentity
	}
	b, record, err := ReadIdentity(caFile, filepath.Join(directory, "active.pem"), Node, id, now)
	clear(b.Key)
	return record, err
}

// WithIdentitySnapshot serializes a private backup with PublishIdentity. The
// callback must not publish an identity or acquire the same lock recursively.
// Holding the regular activation lock keeps active.pem and its private history
// in one snapshot even when an administrator concurrently rotates a leaf.
func WithIdentitySnapshot(ctx context.Context, directory string, capture func() error) error {
	if capture == nil || secureDirectory(directory) != nil {
		return ErrIdentity
	}
	lock, err := authorityLock(ctx, directory)
	if err != nil {
		return err
	}
	defer lock.Close()
	return capture()
}
