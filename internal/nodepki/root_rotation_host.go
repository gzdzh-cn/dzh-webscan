package nodepki

// These host-only helpers never expose either CA private key. Authorization
// and delivery are separate from ordinary leaf issuance and CRL maintenance.
import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"time"
)

// EnsureSuccessorAuthority creates only the fixed private child, after a host
// administrator task has been committed. Existing material is never replaced.
// An existing directory does not itself authorize using its key.
func EnsureSuccessorAuthority(ctx context.Context, authority string, now time.Time) error {
	if !filepath.IsAbs(authority) || filepath.Clean(authority) != authority || secureDirectory(authority) != nil {
		return ErrRootRotation
	}
	dir := SuccessorAuthorityDirectory(authority)
	if _, err := os.Lstat(dir); err == nil {
		lock, err := authorityLock(ctx, dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		a, err := loadMaintenanceAuthority(dir, now)
		if a != nil {
			clear(a.key)
		}
		return err
	} else if !os.IsNotExist(err) {
		return ErrRootRotation
	}
	a, err := NewAuthority(now, 5*365*24*time.Hour)
	if err != nil {
		return err
	}
	defer clear(a.key)
	b, err := a.Export()
	if err != nil {
		return err
	}
	defer clear(b.Key)
	crl, err := a.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		return err
	}
	// Concurrent first creators race safely: SeedAuthority never overwrites the
	// winner. The losing explicit task must retry and inspect the saved child.
	return SeedAuthority(ctx, dir, b, crl, now)
}

func withRootAuthorities(ctx context.Context, authority string, anchor []byte, now time.Time, run func(*Authority, *Authority, []byte, []byte) error) error {
	if run == nil || !filepath.IsAbs(authority) || filepath.Clean(authority) != authority {
		return ErrRootRotation
	}
	var issuers []*Authority
	var crls [][]byte
	for _, directory := range []string{authority, SuccessorAuthorityDirectory(authority)} {
		if secureDirectory(directory) != nil {
			return ErrRootRotation
		}
		lock, err := authorityLock(ctx, directory)
		if err != nil {
			return err
		}
		defer lock.Close()
		a, err := loadMaintenanceAuthority(directory, now)
		if err != nil {
			return err
		}
		defer clear(a.key)
		crl, _, err := latestCRL(directory, a)
		if err != nil {
			return err
		}
		issuers, crls = append(issuers, a), append(crls, crl)
	}
	if !bytes.Equal(certificatePEM(issuers[0].certificate), anchor) {
		return ErrRootRotation
	}
	return run(issuers[0], issuers[1], crls[0], crls[1])
}

// accept must commit the immutable task authorization before it is delivered.
// Do not call this with database row locks held: the backup lock order is
// authority -> database. No local TLS trust changes inside this function.
func AuthorizeStoredRootSet(ctx context.Context, authority string, anchor []byte, rotation, members string, previous *RootSetSnapshot, confirmations string, now time.Time, accept func(RootSetSnapshot) error) error {
	if accept == nil {
		return ErrRootRotation
	}
	return withRootAuthorities(ctx, authority, anchor, now, func(old, next *Authority, oldCRL, newCRL []byte) error {
		var prior *RootAuthorization
		if previous != nil {
			if previous.Final != nil || previous.Dual.Rotation != rotation || previous.Dual.MembersSHA256 != members || !bytes.Equal(previous.Dual.NewCA, certificatePEM(next.certificate)) || ValidateCRLAdvance(anchor, previous.OldCRL, oldCRL, now) != nil || ValidateCRLAdvance(previous.Dual.NewCA, previous.NewCRL, newCRL, now) != nil {
				return ErrRootRotation
			}
			prior = &previous.Dual
		}
		a, err := old.AuthorizeRootRotation(next, rotation, members, prior, confirmations, now)
		if err != nil {
			return err
		}
		snapshot := RootSetSnapshot{Format: 1, Dual: a, OldCRL: oldCRL, NewCRL: newCRL}
		if previous != nil {
			snapshot.Dual, snapshot.Final = previous.Dual, &a
		}
		if _, err := NewRootSet(anchor, snapshot, now); err != nil {
			return err
		}
		return accept(snapshot)
	})
}

func AuthorizeStoredRootDelivery(ctx context.Context, authority string, anchor []byte, snapshot RootSetSnapshot, role, id, configuration, certificate string, now time.Time) (RootDelivery, error) {
	var out RootDelivery
	err := withRootAuthorities(ctx, authority, anchor, now, func(old, next *Authority, _, _ []byte) error {
		var err error
		out, err = old.AuthorizeRootDelivery(next, snapshot, role, id, configuration, certificate, now)
		return err
	})
	return out, err
}
