package nodepki

import (
	"context"
	"path/filepath"
	"time"
)

// WithRootIdentitySnapshot holds trust -> identity through a read-only runtime
// inspection. It cannot sign, publish, initialize state or control a service.
func WithRootIdentitySnapshot(ctx context.Context, caFile, identityFile, floor, role, id, expected string, now time.Time, use func(context.Context, IdentityRecord) error) error {
	if use == nil || !recoverySHA(expected) || floor == filepath.Dir(identityFile) || secureDirectory(floor) != nil {
		return ErrRootRotation
	}
	lock, err := authorityLock(ctx, floor)
	if err != nil {
		return err
	}
	defer lock.Close()
	return WithIdentitySnapshot(ctx, filepath.Dir(identityFile), func() error {
		anchor, err := readTrustFile(caFile, 64<<10)
		if err != nil {
			return ErrRootRotation
		}
		roots, _, err := ReadRootSet(floor, anchor, now)
		if err != nil || roots == nil {
			return ErrRootRotation
		}
		b, record, err := ReadIdentityWithRootState(caFile, identityFile, floor, role, id, now)
		defer clear(b.Key)
		if err != nil || record.CertificateSHA256 != expected {
			return ErrRootRotation
		}
		leaf, err := parseCertificate(b.Certificate)
		if err != nil || roots.Verify(leaf, role, id, now) != nil || ctx.Err() != nil {
			return ErrRootRotation
		}
		if err := use(ctx, record); err != nil {
			return err
		}
		return ctx.Err()
	})
}
