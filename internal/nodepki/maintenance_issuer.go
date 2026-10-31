package nodepki

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"time"
)

// Caller holds the durable trust lock. The immutable installation anchor is
// always checked, even when the active identity belongs to its successor.
func maintenanceIssuerMaterial(caFile, directory, issuer string, now time.Time) ([]byte, []byte, error) {
	anchor, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return nil, nil, ErrIdentity
	}
	pinned, err := readIdentityFile(filepath.Join(directory, "ca.crt"), 64<<10, true)
	if err != nil || !bytes.Equal(bytes.TrimSpace(anchor), bytes.TrimSpace(pinned)) {
		return nil, nil, ErrIdentity
	}
	s, _, err := readRootSetSnapshot(directory, anchor)
	if err != nil {
		return nil, nil, err
	}
	if s.Format == 1 {
		if _, err := newRootSet(anchor, s, now, true); err != nil {
			return nil, nil, err
		}
		return rootMaintenanceIssuer(anchor, s, issuer)
	}
	sha, err := RootFingerprint(anchor)
	if err != nil || sha != issuer {
		return nil, nil, ErrIdentity
	}
	crl, err := readIdentityFile(filepath.Join(directory, "ca.crl"), MaxCRLBytes, true)
	return anchor, crl, err
}

func rootMaintenanceIssuer(anchor []byte, s RootSetSnapshot, issuer string) ([]byte, []byte, error) {
	if sha, err := RootFingerprint(s.Dual.NewCA); err == nil && sha == issuer {
		return s.Dual.NewCA, s.NewCRL, nil
	}
	if sha, err := RootFingerprint(anchor); err == nil && sha == issuer && s.Final == nil {
		return anchor, s.OldCRL, nil
	}
	return nil, nil, ErrRootRotation
}

// Advance only an already approved issuer's revocations. This cannot begin a
// rotation, finalize one, change membership or authorize a new CA. Publication
// and its validation share the real root floor lock; no second trust store.
func publishRootMaintenanceCRL(ctx context.Context, caFile, directory, issuer string, raw []byte, now time.Time, validate func([]byte) error) (CRLReceipt, bool, error) {
	anchor, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return CRLReceipt{}, false, err
	}
	s, _, err := readRootSetSnapshot(directory, anchor)
	if err != nil {
		return CRLReceipt{}, false, err
	}
	if s.Format == 0 {
		return CRLReceipt{}, false, nil
	}
	if _, err := newRootSet(anchor, s, now, true); err != nil {
		return CRLReceipt{}, true, err
	}
	ca, prior, err := rootMaintenanceIssuer(anchor, s, issuer)
	if err != nil || ValidateCRLAdvance(ca, prior, raw, now) != nil || validate(ca) != nil {
		return CRLReceipt{}, true, ErrRevocation
	}
	if bytes.Equal(ca, anchor) {
		s.OldCRL = raw
	} else {
		s.NewCRL = raw
	}
	encoded, _ := json.Marshal(s)
	_, err = publishRootSetAuthorized(ctx, directory, anchor, encoded, now, false, func(_, current RootSetSnapshot) error {
		ca, crl, err := rootMaintenanceIssuer(anchor, current, issuer)
		if err != nil || !bytes.Equal(crl, raw) {
			return ErrRevocation
		}
		return validate(ca)
	})
	if err != nil {
		return CRLReceipt{}, true, err
	}
	root, _ := parseCertificate(ca)
	list, err := parseCRL(raw, root)
	if err != nil {
		return CRLReceipt{}, true, err
	}
	return CRLReceipt{publicSHA(raw), list.Number.Text(10), list.NextUpdate}, true, nil
}

// RefreshIdentityIssuerCRL advances only signed revocations for a durably
// approved issuer. It cannot begin/finalize a rotation or authorize a leaf.
func RefreshIdentityIssuerCRL(ctx context.Context, caFile, directory, issuer string, raw []byte, now time.Time) (bool, error) {
	_, rotated, err := publishRootMaintenanceCRL(ctx, caFile, directory, issuer, raw, now, func(ca []byte) error {
		sha, err := RootFingerprint(ca)
		if err != nil || sha != issuer {
			return ErrRootRotation
		}
		return nil
	})
	return rotated, err
}
