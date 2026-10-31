package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"webscan/internal/nodepki"
)

func rootMemberCertificateSHA(m rootRotationMember) (string, error) {
	cert, err := provisioningCertificate(m.Certificate)
	if err != nil {
		return "", errRootRotationTask
	}
	return digest(cert.Raw), nil
}

func (s *Store) authorizeRootTask(ctx context.Context, c Config, v *Vault, l Lease, id string) (rootRotationTask, error) {
	j, err := s.checkRootTask(ctx, c, v, l, id)
	if err != nil {
		return j, err
	}
	if j.Roots != nil {
		return j, nil
	}
	if j.Status != "prepared" {
		return rootRotationTask{}, errRootRotationTask
	}
	if err := nodepki.EnsureSuccessorAuthority(ctx, c.NodePKI.AuthorityDirectory, time.Now()); err != nil {
		return rootRotationTask{}, err
	}
	for _, directory := range []string{c.NodePKI.AuthorityDirectory, nodepki.SuccessorAuthorityDirectory(c.NodePKI.AuthorityDirectory)} {
		if _, _, _, err := nodepki.RefreshCRL(ctx, directory, time.Now(), 6*time.Hour, 24*time.Hour); err != nil {
			return rootRotationTask{}, err
		}
	}
	var out rootRotationTask
	err = nodepki.AuthorizeStoredRootSet(ctx, c.NodePKI.AuthorityDirectory, j.Anchor, j.ID, j.MembersSHA256, nil, "", time.Now(), func(roots nodepki.RootSetSnapshot) error {
		var err error
		out, err = s.rootTaskCheckpoint(ctx, c, v, l, j, func(current *rootRotationTask, tx *sql.Tx) error {
			if current.Status != "prepared" || current.Roots != nil {
				return errRootRotationTask
			}
			for _, issuer := range []struct{ ca, crl []byte }{{j.Anchor, roots.OldCRL}, {roots.Dual.NewCA, roots.NewCRL}} {
				if err := registerRootTaskIssuerTx(ctx, tx, issuer.ca, issuer.crl); err != nil {
					return err
				}
			}
			current.Roots, current.Status = &roots, "dual"
			return nil
		})
		return err
	})
	return out, err
}

func registerRootTaskIssuerTx(ctx context.Context, tx *sql.Tx, ca, crl []byte) error {
	cert, err := provisioningCertificate(ca)
	if err != nil {
		return errRootRotationTask
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_pki_authorities(sha256,certificate,crl) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, digest(cert.Raw), ca, crl); err != nil {
		return err
	}
	var known, floor []byte
	if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR UPDATE`, digest(cert.Raw)).Scan(&known, &floor); err != nil {
		return err
	}
	if !bytes.Equal(known, ca) || nodepki.ValidateCRLAdvance(ca, floor, crl, time.Now()) != nil {
		return errRootRotationTask
	}
	_, err = tx.ExecContext(ctx, `UPDATE v3_pki_authorities SET crl=$2,updated_at=clock_timestamp() WHERE sha256=$1`, digest(cert.Raw), crl)
	return err
}

func (s *Store) refreshRootTask(ctx context.Context, c Config, v *Vault, l Lease, id string) (rootRotationTask, error) {
	j, err := s.checkRootTask(ctx, c, v, l, id)
	if err != nil || j.Roots == nil {
		return rootRotationTask{}, errRootRotationTask
	}
	updated := *j.Roots
	if updated.Final == nil {
		ca, crl, _, err := nodepki.RefreshCRL(ctx, c.NodePKI.AuthorityDirectory, time.Now(), 6*time.Hour, 24*time.Hour)
		if err != nil || !bytes.Equal(ca, j.Anchor) {
			return rootRotationTask{}, errRootRotationTask
		}
		updated.OldCRL = crl
	}
	ca, crl, _, err := nodepki.RefreshCRL(ctx, nodepki.SuccessorAuthorityDirectory(c.NodePKI.AuthorityDirectory), time.Now(), 6*time.Hour, 24*time.Hour)
	if err != nil || !bytes.Equal(ca, updated.Dual.NewCA) {
		return rootRotationTask{}, errRootRotationTask
	}
	updated.NewCRL = crl
	if nodepki.ValidateRootSetAdvance(j.Anchor, *j.Roots, updated, time.Now()) != nil {
		return rootRotationTask{}, errRootRotationTask
	}
	previous, _ := json.Marshal(j.Roots)
	next, _ := json.Marshal(updated)
	if bytes.Equal(previous, next) {
		return j, nil
	}
	return s.rootTaskCheckpoint(ctx, c, v, l, j, func(current *rootRotationTask, tx *sql.Tx) error {
		if updated.Final == nil {
			if err := registerRootTaskIssuerTx(ctx, tx, j.Anchor, updated.OldCRL); err != nil {
				return err
			}
		}
		if err := registerRootTaskIssuerTx(ctx, tx, updated.Dual.NewCA, updated.NewCRL); err != nil {
			return err
		}
		current.Roots = &updated
		return nil
	})
}

func (s *Store) admitRootTaskRequest(ctx context.Context, c Config, v *Vault, l Lease, j rootRotationTask, index int, raw []byte) (rootRotationTask, error) {
	if index < 0 || index >= len(j.Members) || j.Roots == nil || j.Roots.Final != nil {
		return rootRotationTask{}, errRootRotationTask
	}
	m := j.Members[index]
	r, err := nodepki.ParseRootIdentityRequest(raw)
	expected, parseErr := rootMemberCertificateSHA(m)
	if err != nil || parseErr != nil || r.Role != m.Role || r.ID != m.ID || r.CertificateSHA256 != expected || !bytes.Equal(r.Certificate, m.Certificate) || r.Authorization != nodepki.RootAuthorizationSHA256(j.Roots.Dual) {
		return rootRotationTask{}, errRootRotationTask
	}
	if nodepki.ValidateRootIdentityRequest(j.Anchor, *j.Roots, r, time.Now()) != nil {
		return rootRotationTask{}, errRootRotationTask
	}
	return s.rootTaskCheckpoint(ctx, c, v, l, j, func(current *rootRotationTask, _ *sql.Tx) error {
		state := &current.State[index]
		if !state.Trust {
			return errRootRotationTask
		}
		if len(state.Request) != 0 && !bytes.Equal(state.Request, raw) {
			return ErrConflict
		}
		state.Request = append([]byte(nil), raw...)
		return nil
	})
}

func (s *Store) signRootTaskMember(ctx context.Context, c Config, v *Vault, l Lease, id string, index int) (rootRotationTask, error) {
	j, err := s.checkRootTask(ctx, c, v, l, id)
	if err != nil || index < 0 || index >= len(j.Members) || j.Roots == nil || j.Roots.Final != nil {
		return rootRotationTask{}, errRootRotationTask
	}
	state := j.State[index]
	r, err := nodepki.ParseRootIdentityRequest(state.Request)
	if err != nil || !state.Trust {
		return rootRotationTask{}, errRootRotationTask
	}
	if len(state.Certificate) != 0 {
		if nodepki.ValidateRootIdentityCertificate(j.Anchor, *j.Roots, r, state.Certificate, time.Now()) != nil {
			return rootRotationTask{}, errRootRotationTask
		}
		return j, nil
	}
	var out rootRotationTask
	err = nodepki.SignRootIdentityRegistered(ctx, nodepki.SuccessorAuthorityDirectory(c.NodePKI.AuthorityDirectory), j.Anchor, *j.Roots, r, time.Now(), 90*24*time.Hour, func(b nodepki.Bundle) error {
		if len(b.Key) != 0 || !bytes.Equal(b.CA, j.Roots.Dual.NewCA) || nodepki.ValidateRootIdentityCertificate(j.Anchor, *j.Roots, r, b.Certificate, time.Now()) != nil {
			return errRootRotationTask
		}
		var err error
		out, err = s.rootTaskCheckpoint(ctx, c, v, l, j, func(current *rootRotationTask, tx *sql.Tx) error {
			if len(current.State[index].Certificate) != 0 || !bytes.Equal(current.State[index].Request, state.Request) {
				return errRootRotationTask
			}
			current.State[index].Certificate = append([]byte(nil), b.Certificate...)
			leaf, err := provisioningCertificate(b.Certificate)
			issuer, issuerErr := provisioningCertificate(b.CA)
			if err != nil || issuerErr != nil {
				return errRootRotationTask
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO v3_root_identity_issuances(task,role,subject,authority,parent_sha256,request_sha256,certificate,certificate_sha256,serial,not_after) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, j.ID, r.Role, r.ID, digest(issuer.Raw), r.CertificateSHA256, r.SHA256(), b.Certificate, digest(leaf.Raw), leaf.SerialNumber.Text(16), leaf.NotAfter)
			return err
		})
		return err
	})
	return out, err
}

func publishCollectorRootTask(ctx context.Context, c Config, j rootRotationTask, index int) error {
	if index < 0 || index >= len(j.Members) || j.Members[index].Role != nodepki.Collector || j.Roots == nil {
		return errRootRotationTask
	}
	m := j.Members[index]
	var b nodepki.Bundle
	var record nodepki.IdentityRecord
	var err error
	if j.Roots.Final == nil && len(j.State[index].Certificate) != 0 {
		request, parseErr := nodepki.ParseRootIdentityRequest(j.State[index].Request)
		if parseErr != nil {
			return errRootRotationTask
		}
		b, record, err = nodepki.ReadRootActivationIdentity(c.Collector.CAFile, c.Collector.IdentityFile, c.Collector.RevocationStateDirectory, nodepki.Collector, m.ID, *j.Roots, request, j.State[index].Certificate, time.Now())
	} else {
		b, record, err = nodepki.ReadIdentityWithRootState(c.Collector.CAFile, c.Collector.IdentityFile, c.Collector.RevocationStateDirectory, nodepki.Collector, m.ID, time.Now())
	}
	defer clear(b.Key)
	if err != nil {
		return errRootRotationTask
	}
	leaf, err := provisioningCertificate(b.Certificate)
	roots, rootErr := nodepki.NewRootSet(j.Anchor, *j.Roots, time.Now())
	if err != nil || rootErr != nil {
		return errRootRotationTask
	}
	expected, err := rootMemberCertificateSHA(m)
	if err != nil {
		return err
	}
	if record.CertificateSHA256 != expected {
		cert, err := provisioningCertificate(j.State[index].Certificate)
		if err != nil || record.CertificateSHA256 != digest(cert.Raw) {
			return errRootRotationTask
		}
		if roots.Verify(leaf, nodepki.Collector, m.ID, time.Now()) != nil {
			return errRootRotationTask
		}
	} else if roots.Verify(leaf, nodepki.Collector, m.ID, time.Now()) != nil && len(j.State[index].Certificate) == 0 {
		return errRootRotationTask
	}
	delivery, err := nodepki.AuthorizeStoredRootDelivery(ctx, c.NodePKI.AuthorityDirectory, j.Anchor, *j.Roots, m.Role, m.ID, m.Configuration, record.CertificateSHA256, time.Now())
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(j.Roots)
	_, err = nodepki.PublishDeliveredRootSet(ctx, c.Collector.RevocationStateDirectory, j.Anchor, raw, delivery, m.Role, m.ID, m.Configuration, record.CertificateSHA256, time.Now())
	return err
}
