package nodepki

import (
	"bytes"
	"context"
	"path/filepath"
	"time"
)

// NameChangeVerificationTimeout is the existing helper operation budget. A
// live host inspection hashes the installed bundle and queries real managers
// and kernel limits; it is not a five-second certificate publication. The
// caller's earlier deadline and the authorization expiry always take priority.
const NameChangeVerificationTimeout = 30 * time.Second

// PublishNodeNameChangeTrust advances only an EXISTING trust floor, after the
// pinned SSH operation has produced the exact authorized local-key request.
// Missing state, another CA and loss of any previous revocation are errors.
// It is not an online authentication exception or a way to initialize a node.
func PublishNodeNameChangeTrust(ctx context.Context, caFile, directory string, raw []byte, r NodeNameChangeRequest, expected NodeNameChangeIntent, now time.Time) (CRLReceipt, error) {
	return publishNodeNameMaintenanceTrust(ctx, caFile, directory, expected.AuthoritySHA256, raw, expected.ExpiresAt, now, func(ca []byte) error {
		return ValidateNodeNameChangeRequest(ca, raw, r, expected, now)
	})
}

func publishNodeNameMaintenanceTrust(ctx context.Context, caFile, directory, issuer string, raw []byte, expires time.Time, now time.Time, validate func([]byte) error) (CRLReceipt, error) {
	var empty CRLReceipt
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || secureDirectory(directory) != nil {
		return empty, ErrRevocation
	}
	if receipt, rotated, err := publishRootMaintenanceCRL(ctx, caFile, directory, issuer, raw, now, validate); err != nil || rotated {
		return receipt, err
	}
	ca, err := readTrustFile(caFile, 64<<10)
	if err != nil || validate(ca) != nil {
		return empty, ErrIdentity
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	ctx, finish := context.WithTimeout(ctx, 5*time.Second)
	defer finish()
	lock, err := authorityLock(ctx, directory)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	pinned, err := readIdentityFile(filepath.Join(directory, "ca.crt"), 64<<10, true)
	if err != nil {
		return empty, ErrIdentity
	}
	root, e1 := parseCertificate(ca)
	prior, e2 := parseCertificate(pinned)
	if e1 != nil || e2 != nil || !bytes.Equal(root.Raw, prior.Raw) {
		return empty, ErrIdentity
	}
	floor, err := readIdentityFile(filepath.Join(directory, "ca.crl"), MaxCRLBytes, true)
	if err != nil || ValidateCRLAdvance(ca, floor, raw, now) != nil {
		return empty, ErrRevocation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if !bytes.Equal(floor, raw) {
		if err := replaceCRL(directory, raw); err != nil {
			return empty, err
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	list, _ := parseCRL(raw, root)
	return CRLReceipt{publicSHA(raw), list.Number.Text(10), list.NextUpdate}, nil
}

// WithNameChangedNodeIdentity holds trust -> identity locks through a fixed,
// read-only host verification. The exact committed public receipt must already
// be active and match the locally retained CSR. It never activates, initializes
// or starts a service, and cannot be used to switch runtime configuration.
func WithNameChangedNodeIdentity(ctx context.Context, caFile, identityFile, trustDirectory string, r NodeNameChangeRequest, expected NodeNameChangeIntent, certificate []byte, now time.Time, use func(context.Context, IdentityRecord) error) error {
	if use == nil || !validNameChangeIntent(expected, now) || !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile || filepath.Dir(identityFile) == trustDirectory || secureDirectory(filepath.Dir(identityFile)) != nil {
		return ErrIdentity
	}
	ctx, cancel := context.WithDeadline(ctx, expected.ExpiresAt)
	defer cancel()
	ctx, finish := context.WithTimeout(ctx, NameChangeVerificationTimeout)
	defer finish()
	return nameChangeTrust(ctx, caFile, trustDirectory, expected.AuthoritySHA256, now, func(ca, crl []byte) error {
		if err := ValidateNodeNameChangeCertificate(ca, crl, r, expected, certificate, now); err != nil {
			return err
		}
		return WithIdentitySnapshot(ctx, filepath.Dir(identityFile), func() error {
			original, err := nameChangeOriginal(r)
			if err != nil {
				return err
			}
			saved, key, err := readNameChangePendingAt(nameChangePending(identityFile, original.Intent), ca, crl, original.Intent, now, r.Kind != nameChangeKind)
			defer clear(key)
			if err != nil || saved.SHA256() != original.SHA256() {
				return ErrIdentity
			}
			active, record, err := ReadIdentityWithRootState(caFile, identityFile, trustDirectory, Node, expected.Node, now)
			defer clear(active.Key)
			if err != nil {
				return ErrIdentity
			}
			leaf, err := parseCertificate(certificate)
			if err != nil || record.CertificateSHA256 != publicSHA(leaf.Raw) {
				return ErrIdentity
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := use(ctx, record); err != nil {
				return err
			}
			return ctx.Err()
		})
	})
}
