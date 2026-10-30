package nodepki

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"path/filepath"
	"time"
)

// The offline activation path has no network or service-control side effects.
// Renewal preserves the signed identity and SANs; it cannot restore a revoked
// identity or replace the installed trust root.
func identityCommand(ctx context.Context, o Options, out io.Writer, now time.Time) error {
	if o.Output != "" || o.Certificate != "" || o.Names != "" || o.CAFile == "" || o.IdentityFile == "" {
		return ErrIdentity
	}
	if _, err := Identity(o.Role, o.ID); err != nil {
		return err
	}
	var record IdentityRecord
	var err error
	switch o.Action {
	case "publish-identity":
		if o.Authority != "" || o.Source == "" || o.LifetimeHours != 0 || secureDirectory(o.Source) != nil {
			return ErrIdentity
		}
		var b Bundle
		b.CA, err = readTrustFile(filepath.Join(o.Source, "ca.crt"), 64<<10)
		if err != nil {
			return ErrIdentity
		}
		b.Certificate, err = readTrustFile(filepath.Join(o.Source, "identity.crt"), 64<<10)
		if err != nil {
			return ErrIdentity
		}
		b.Key, err = readIdentityFile(filepath.Join(o.Source, "identity.key"), 64<<10, true)
		if err != nil {
			return ErrIdentity
		}
		defer clear(b.Key)
		record, err = PublishIdentity(ctx, o.CAFile, o.IdentityFile, o.Role, o.ID, o.ExpectedSHA256, b, now)
	case "renew-identity":
		// Keep authority and activation locks independent. Neither may be a
		// symlink, so string equality also catches the supported alias case.
		if o.Source != "" || o.ExpectedSHA256 == "" || filepath.Dir(o.IdentityFile) == o.Authority {
			return ErrIdentity
		}
		hours := o.LifetimeHours
		if hours == 0 {
			hours = 30 * 24
		}
		if hours < 1 || hours > 90*24 {
			return ErrIdentity
		}
		var old Bundle
		var prior IdentityRecord
		old, prior, err = readIdentity(o.CAFile, o.IdentityFile, o.Role, o.ID, now, true)
		if err != nil {
			return err
		}
		defer clear(old.Key)
		if prior.CertificateSHA256 != o.ExpectedSHA256 {
			return ErrIdentity
		}
		var leaf *x509.Certificate
		leaf, err = parseCertificate(old.Certificate)
		if err != nil {
			return err
		}
		names := append([]string{}, leaf.DNSNames...)
		for _, ip := range leaf.IPAddresses {
			names = append(names, ip.String())
		}
		err = IssueRegistered(ctx, o.Authority, o.Role, o.ID, names, now, time.Duration(hours)*time.Hour, func(b Bundle, crl []byte) error {
			root, e := parseCertificate(b.CA)
			pinned, e2 := parseCertificate(old.CA)
			if e != nil || e2 != nil || !bytes.Equal(root.Raw, pinned.Raw) {
				return ErrIdentity
			}
			list, e := parseCRL(crl, root)
			if e != nil {
				return e
			}
			for _, entry := range list.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
					return ErrRevocation
				}
			}
			record, e = PublishIdentity(ctx, o.CAFile, o.IdentityFile, o.Role, o.ID, o.ExpectedSHA256, b, now)
			return e
		})
	default:
		return ErrIdentity
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(record)
}
