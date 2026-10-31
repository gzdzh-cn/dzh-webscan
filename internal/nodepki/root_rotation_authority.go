package nodepki

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"time"
)

// The successor is stored inside the original private authority so complete
// backups retain both signing histories. No request can choose another path.
// SeedAuthority takes the parent (original authority) lock when creating it.
func SuccessorAuthorityDirectory(authority string) string {
	return filepath.Join(authority, "successor")
}

// ReadRootState verifies the durable authorization/history, allowing expired
// authentic CRLs for maintenance only. Ordinary admission still uses live
// ReadRootSet/FileTrust checks. Absence is distinct from damaged rotation state.
func ReadRootState(caFile, directory string, now time.Time) (RootSetSnapshot, error) {
	anchor, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return RootSetSnapshot{}, ErrRootRotation
	}
	s, raw, err := readRootSetSnapshot(directory, anchor)
	if err != nil || len(raw) == 0 {
		return s, err
	}
	if _, err := newRootSet(anchor, s, now, true); err != nil {
		return RootSetSnapshot{}, err
	}
	return s, nil
}

// IdentityAuthority selects an already approved issuer for an existing leaf.
// It never selects a successor by the mere presence of a directory or key.
// Finalization permanently disallows the old issuer. The returned directory
// still has to be verified by the signing primitive before it can issue a leaf.
func IdentityAuthority(authority, caFile, directory, issuer string, now time.Time) (string, error) {
	if !filepath.IsAbs(authority) || filepath.Clean(authority) != authority || secureDirectory(authority) != nil || !recoverySHA(issuer) {
		return "", ErrRootRotation
	}
	anchor, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return "", ErrRootRotation
	}
	anchorSHA, err := RootFingerprint(anchor)
	if err != nil {
		return "", err
	}
	original, err := readTrustFile(filepath.Join(authority, "ca.crt"), 64<<10)
	if err != nil || !bytes.Equal(original, anchor) {
		return "", ErrRootRotation
	}
	s, err := ReadRootState(caFile, directory, now)
	if err != nil {
		return "", err
	}
	path, expected := authority, anchor
	if issuer != anchorSHA {
		if s.Format != 1 {
			return "", ErrRootRotation
		}
		approved, err := RootFingerprint(s.Dual.NewCA)
		if err != nil || approved != issuer {
			return "", ErrRootRotation
		}
		path, expected = SuccessorAuthorityDirectory(authority), s.Dual.NewCA
	} else if s.Final != nil {
		return "", ErrRootRotation
	}
	actual, err := readTrustFile(filepath.Join(path, "ca.crt"), 64<<10)
	if err != nil || !bytes.Equal(actual, expected) || secureDirectory(path) != nil {
		return "", ErrRootRotation
	}
	return path, nil
}

// RefreshAuthorizedRootSet renews per-issuer CRLs for an EXISTING explicit
// authorization. It cannot start/finalize a rotation or change its membership.
// A wrong/missing successor fails without changing the accepted trust snapshot.
// After finalization the retired CA key is no longer required for maintenance.
func RefreshAuthorizedRootSet(ctx context.Context, authority, caFile, directory string, now time.Time) (RootSetSnapshot, error) {
	s, err := ReadRootState(caFile, directory, now)
	if err != nil || s.Format == 0 {
		return s, err
	}
	anchor, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return RootSetSnapshot{}, ErrRootRotation
	}
	newSHA, err := RootFingerprint(s.Dual.NewCA)
	if err != nil {
		return RootSetSnapshot{}, err
	}
	nextDirectory, err := IdentityAuthority(authority, caFile, directory, newSHA, now)
	if err != nil {
		return RootSetSnapshot{}, err
	}
	if s.Final == nil {
		oldSHA, _ := RootFingerprint(anchor)
		oldDirectory, err := IdentityAuthority(authority, caFile, directory, oldSHA, now)
		if err != nil {
			return RootSetSnapshot{}, err
		}
		_, s.OldCRL, _, err = RefreshCRL(ctx, oldDirectory, now, 12*time.Hour, 24*time.Hour)
		if err != nil {
			return RootSetSnapshot{}, err
		}
	}
	_, s.NewCRL, _, err = RefreshCRL(ctx, nextDirectory, now, 12*time.Hour, 24*time.Hour)
	if err != nil {
		return RootSetSnapshot{}, err
	}
	raw, _ := json.Marshal(s)
	if _, err := PublishRootSet(ctx, directory, anchor, raw, now); err != nil {
		return RootSetSnapshot{}, err
	}
	return s, nil
}
