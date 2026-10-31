package nodepki

import (
	"context"
	"path/filepath"
	"time"
)

// PublishNodeNamePruningTrust advances an existing floor for the exact
// administrator-authorized subset request. It cannot initialize missing trust.
func PublishNodeNamePruningTrust(ctx context.Context, caFile, directory string, raw []byte, r NodeNamePruningRequest, expected NodeNamePruningIntent, now time.Time) (CRLReceipt, error) {
	return publishNodeNameMaintenanceTrust(ctx, caFile, directory, expected.AuthoritySHA256, raw, expected.ExpiresAt, now, func(ca []byte) error {
		return ValidateNodeNamePruningRequest(ca, raw, r, expected, now)
	})
}

// WithPrunedNodeIdentity verifies the active certificate, retained local key
// request and current trust while holding trust -> identity locks. Only a
// read-only runtime inspection belongs in use; it must not restart the Agent.
func WithPrunedNodeIdentity(ctx context.Context, caFile, identityFile, trustDirectory string, r NodeNamePruningRequest, expected NodeNamePruningIntent, certificate []byte, now time.Time, use func(context.Context, IdentityRecord) error) error {
	if use == nil || !validNamePruningIntent(expected, now) || !filepath.IsAbs(identityFile) || filepath.Clean(identityFile) != identityFile || filepath.Dir(identityFile) == trustDirectory || secureDirectory(filepath.Dir(identityFile)) != nil {
		return ErrIdentity
	}
	ctx, cancel := context.WithDeadline(ctx, expected.ExpiresAt)
	defer cancel()
	ctx, finish := context.WithTimeout(ctx, NameChangeVerificationTimeout)
	defer finish()
	return nameChangeTrust(ctx, caFile, trustDirectory, expected.AuthoritySHA256, now, func(ca, crl []byte) error {
		if err := ValidateNodeNamePruningCertificate(ca, crl, r, expected, certificate, now); err != nil {
			return err
		}
		return WithIdentitySnapshot(ctx, filepath.Dir(identityFile), func() error {
			original, err := namePruningOriginal(r)
			if err != nil {
				return err
			}
			saved, key, err := readNamePruningPendingAt(namePruningPending(identityFile, original.Intent), ca, crl, original.Intent, now, r.Kind != namePruningKind)
			defer clear(key)
			if err != nil || saved.SHA256() != original.SHA256() {
				return ErrIdentity
			}
			active, record, err := ReadIdentityWithRootState(caFile, identityFile, trustDirectory, Node, expected.Node, now)
			defer clear(active.Key)
			leaf, parseErr := parseCertificate(certificate)
			if err != nil || parseErr != nil || record.CertificateSHA256 != publicSHA(leaf.Raw) {
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
