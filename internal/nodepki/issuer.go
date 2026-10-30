package nodepki

import (
	"context"
	"path/filepath"
	"time"
)

// IssueRegistered holds the existing authority lock while the caller durably
// accepts the leaf. The CA key never leaves this package or enters a bundle.
// The caller must commit its registry transaction before exposing the leaf.
// A rejected callback does not publish a leaf or change revocation history.
func IssueRegistered(ctx context.Context, directory, role, id string, names []string, now time.Time, lifetime time.Duration, accept func(Bundle, []byte) error) error {
	if accept == nil || ctx.Err() != nil {
		return ErrIdentity
	}
	if err := secureDirectory(directory); err != nil {
		return err
	}
	lock, err := authorityLock(ctx, directory)
	if err != nil {
		return err
	}
	defer lock.Close()
	ca, err := readTrustFile(filepath.Join(directory, "ca.crt"), 64<<10)
	if err != nil {
		return errStorage
	}
	key, err := readIdentityFile(filepath.Join(directory, "ca.key"), 64<<10, true)
	if err != nil {
		return errStorage
	}
	defer clear(key)
	authority, err := ParseAuthority(ca, key, now)
	if err != nil {
		return err
	}
	defer clear(authority.key)
	crl, _, err := latestCRL(directory, authority)
	if err != nil {
		return err
	}
	if _, err := NewTrust(ca, crl, now); err != nil {
		return err
	}
	bundle, err := authority.Issue(role, id, names, now, lifetime)
	if err != nil {
		return err
	}
	defer clear(bundle.Key)
	if err := ctx.Err(); err != nil {
		return err
	}
	return accept(bundle, crl)
}

// ValidateCRLAdvance also accepts an expired authentic *previous* floor. The
// new signed snapshot must be current and cannot lower its number or remove
// revocations. This lets a shared registry protect independent HA issuers.
func ValidateCRLAdvance(ca, previous, next []byte, now time.Time) error {
	root, err := parseCertificate(ca)
	if err != nil || !validAuthority(root, now) {
		return ErrIdentity
	}
	if len(previous) == 0 {
		_, err := NewTrust(ca, next, now)
		return err
	}
	floor, err := parseCRL(previous, root)
	if err != nil || floor.ThisUpdate.After(now) {
		return ErrRevocation
	}
	trust, err := NewTrust(ca, previous, floor.ThisUpdate)
	if err != nil {
		return err
	}
	return trust.UpdateCRL(next, now)
}
