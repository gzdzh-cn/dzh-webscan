package nodepki

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// SeedAuthority imports only an explicit, already generated private CA. A
// complete directory is published atomically; an existing authority is checked
// and never replaced. An expired signed CRL remains a floor, not live trust.
func SeedAuthority(ctx context.Context, dir string, b Bundle, initial []byte, now time.Time) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || secureDirectory(filepath.Dir(dir)) != nil || len(b.Certificate) > 0 {
		return ErrIdentity
	}
	a, err := ParseAuthority(b.CA, b.Key, now)
	if err != nil {
		return err
	}
	defer clear(a.key)
	list, err := parseCRL(initial, a.certificate)
	if err != nil || list.ThisUpdate.After(now) {
		return ErrRevocation
	}
	if _, err := NewTrust(b.CA, initial, list.ThisUpdate); err != nil {
		return err
	}
	lock, err := authorityLock(ctx, filepath.Dir(dir))
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		if secureDirectory(dir) != nil {
			return errStorage
		}
		inner, err := authorityLock(ctx, dir)
		if err != nil {
			return err
		}
		defer inner.Close()
		current, err := loadMaintenanceAuthority(dir, now)
		if err != nil {
			return err
		}
		defer clear(current.key)
		if !bytes.Equal(current.certificate.Raw, a.certificate.Raw) {
			return ErrIdentity
		}
		crl, _, err := latestCRL(dir, current)
		if err != nil {
			return err
		}
		latest, err := parseCRL(crl, a.certificate)
		if err != nil || latest.ThisUpdate.After(now) {
			return ErrRevocation
		}
		return ValidateCRLAdvance(b.CA, initial, crl, latest.ThisUpdate)
	}
	stage, err := os.MkdirTemp(filepath.Dir(dir), ".authority-seed-*")
	if err != nil {
		return errStorage
	}
	defer os.RemoveAll(stage)
	if err := os.Mkdir(filepath.Join(stage, "crls"), 0700); err != nil {
		return errStorage
	}
	for name, raw := range map[string][]byte{"ca.crt": b.CA, "ca.key": b.Key, "ca.crl": initial, "crls/" + list.Number.Text(10) + ".pem": initial} {
		if err := writeExclusive(filepath.Join(stage, name), raw); err != nil {
			return err
		}
	}
	if syncDir(filepath.Join(stage, "crls")) != nil || syncDir(stage) != nil || ctx.Err() != nil {
		return errStorage
	}
	if identityRenameNoReplace(stage, dir) != nil {
		return errStorage
	}
	return syncDir(filepath.Dir(dir))
}

func loadMaintenanceAuthority(dir string, now time.Time) (*Authority, error) {
	ca, err := readTrustFile(filepath.Join(dir, "ca.crt"), 64<<10)
	if err != nil {
		return nil, errStorage
	}
	key, err := readIdentityFile(filepath.Join(dir, "ca.key"), 64<<10, true)
	if err != nil {
		return nil, errStorage
	}
	defer clear(key)
	return ParseAuthority(ca, key, now)
}

// RefreshCRL preserves the full monotonic history, including an expired
// authentic floor. It does not distribute trust or remove revoked serials.
func RefreshCRL(ctx context.Context, dir string, now time.Time, before, lifetime time.Duration) ([]byte, []byte, bool, error) {
	if before < time.Hour || lifetime < 2*time.Hour || lifetime > 7*24*time.Hour || before >= lifetime || secureDirectory(dir) != nil {
		return nil, nil, false, ErrRevocation
	}
	lock, err := authorityLock(ctx, dir)
	if err != nil {
		return nil, nil, false, err
	}
	defer lock.Close()
	a, err := loadMaintenanceAuthority(dir, now)
	if err != nil {
		return nil, nil, false, err
	}
	defer clear(a.key)
	crl, number, err := latestCRL(dir, a)
	if err != nil {
		return nil, nil, false, err
	}
	list, err := parseCRL(crl, a.certificate)
	if err != nil || list.ThisUpdate.After(now) {
		return nil, nil, false, ErrRevocation
	}
	if _, err := NewTrust(certificatePEM(a.certificate), crl, list.ThisUpdate); err != nil {
		return nil, nil, false, err
	}
	ca := certificatePEM(a.certificate)
	if list.NextUpdate.Sub(now) > before {
		return ca, crl, false, nil
	}
	next, err := a.Revoke(crl, nil, now, lifetime)
	if err != nil {
		return nil, nil, false, err
	}
	// Stage outside crls: a killed process cannot leave a partial numbered
	// snapshot or an extra hard link that makes subsequent history unreadable.
	f, err := os.CreateTemp(dir, ".crl-history-*")
	if err != nil {
		return nil, nil, false, errStorage
	}
	name := f.Name()
	defer os.Remove(name)
	_, err = f.Write(next)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil || closed != nil || ctx.Err() != nil {
		return nil, nil, false, errStorage
	}
	if identityRenameNoReplace(name, filepath.Join(dir, "crls", strconv.FormatInt(number+1, 10)+".pem")) != nil || syncDir(filepath.Join(dir, "crls")) != nil {
		return nil, nil, false, errStorage
	}
	if err := replaceCRL(dir, next); err != nil {
		return nil, nil, false, err
	}
	return ca, next, true, nil
}

// MaintainIdentity renews only the installed identity, with its signed SANs.
// The caller schedules this and distributes CRLs separately. Revoked leaves
// cannot be renewed, including when their original certificate has expired.
func MaintainIdentity(ctx context.Context, authority, caFile, file, role, id string, now time.Time, before, lifetime time.Duration) (IdentityRecord, error) {
	return MaintainIdentityWithRootState(ctx, authority, caFile, file, "", role, id, now, before, lifetime)
}

// Maintenance renews under the installed leaf's authorized issuer. It cannot
// roll a leaf to another CA; that requires the explicit administrator rollout.
func MaintainIdentityWithRootState(ctx context.Context, authority, caFile, file, directory, role, id string, now time.Time, before, lifetime time.Duration) (IdentityRecord, error) {
	if before < time.Hour || lifetime < 2*time.Hour || lifetime > 90*24*time.Hour || before >= lifetime || lifetime%time.Hour != 0 {
		return IdentityRecord{}, ErrIdentity
	}
	b, record, err := readIdentityWithRootState(caFile, file, directory, role, id, now, true)
	if err != nil {
		return IdentityRecord{}, err
	}
	defer clear(b.Key)
	if directory != "" {
		issuer, err := RootFingerprint(b.CA)
		if err != nil {
			return IdentityRecord{}, err
		}
		authority, err = IdentityAuthority(authority, caFile, directory, issuer, now)
		if err != nil {
			return IdentityRecord{}, err
		}
	}
	ca, crl, _, err := RefreshCRL(ctx, authority, now, 12*time.Hour, 24*time.Hour)
	if err != nil {
		return IdentityRecord{}, err
	}
	root, e1 := parseCertificate(ca)
	other, e2 := parseCertificate(b.CA)
	if e1 != nil || e2 != nil || !bytes.Equal(root.Raw, other.Raw) {
		return IdentityRecord{}, ErrIdentity
	}
	if record.ExpiresAt.Sub(now) > before {
		trust, err := NewTrust(ca, crl, now)
		if err != nil {
			return IdentityRecord{}, err
		}
		leaf, err := parseCertificate(b.Certificate)
		if err != nil {
			return IdentityRecord{}, err
		}
		if err := trust.Verify(leaf, role, id, now); err != nil {
			return IdentityRecord{}, err
		}
		return record, nil
	}
	leaf, err := parseCertificate(b.Certificate)
	if err != nil {
		return IdentityRecord{}, err
	}
	names := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	var out IdentityRecord
	err = IssueRegistered(ctx, authority, role, id, names, now, lifetime, func(next Bundle, currentCRL []byte) error {
		if !bytes.Equal(next.CA, b.CA) {
			return ErrIdentity
		}
		list, err := parseCRL(currentCRL, root)
		if err != nil {
			return err
		}
		for _, entry := range list.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				return ErrRevocation
			}
		}
		out, err = PublishIdentityWithRootState(ctx, caFile, file, directory, role, id, record.CertificateSHA256, next, now)
		return err
	})
	if err != nil {
		return IdentityRecord{}, err
	}
	return out, nil
}
