package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"time"

	"webscan/internal/nodepki"
)

type nodeRenewalSigningInput struct {
	Snapshot      string
	RuntimeEpoch  int64
	LifetimeHours int
	Request       nodepki.NodeRenewalRequest
}

type nodeRenewalReceipt struct {
	Node              string    `json:"node"`
	Snapshot          string    `json:"snapshot"`
	RuntimeEpoch      int64     `json:"runtime_epoch"`
	AuthoritySHA256   string    `json:"authority_sha256"`
	ParentSHA256      string    `json:"parent_sha256"`
	RequestSHA256     string    `json:"request_sha256"`
	CertificateSHA256 string    `json:"certificate_sha256"`
	Serial            string    `json:"serial"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type signedNodeRenewal struct {
	Receipt     nodeRenewalReceipt
	Certificate []byte
	CRL         []byte
}

func nodeRenewalResource(node string) string { return "node-renewal:" + node }

// This is a host-issuer operation, not an API or collector handler. The caller
// needs the explicitly configured authority key and a dedicated durable lease.
// No Vault or collector private identity is used. Delivery/scheduling is kept
// separate: a certificate may only leave this function after its SQL commit.
func (s *Store) signNodeRenewal(ctx context.Context, c Config, l Lease, in nodeRenewalSigningInput) (signedNodeRenewal, error) {
	return s.signNodeCertificate(ctx, c, l, in, nil)
}

func (s *Store) signNodeCertificate(ctx context.Context, c Config, l Lease, in nodeRenewalSigningInput, recovery *nodeIdentityRecoverySigningGuard) (signedNodeRenewal, error) {
	return s.signNodeCertificateAuthorized(ctx, c, l, in, recovery, nil)
}

// The private name-operation guard supplies a separately authorized request. The
// renewal-shaped input carries ancestry/runtime fields only in that case; its
// synthetic hash/proof is never validated, registered or accepted over RPC.
func (s *Store) signNodeCertificateAuthorized(ctx context.Context, c Config, l Lease, in nodeRenewalSigningInput, recovery *nodeIdentityRecoverySigningGuard, nameGuard nodeNameSigningGuard) (signedNodeRenewal, error) {
	var empty signedNodeRenewal
	r := in.Request
	var nameBinding nodeNameSigningBinding
	if nameGuard != nil {
		nameBinding = nameGuard.binding()
	}
	requestSHA, requestKind := r.SHA256(), "renewal"
	if nameGuard != nil {
		if (nameBinding.Kind != "name-change" && nameBinding.Kind != "name-pruning") || recovery != nil || r.Node != nameBinding.Node || r.AuthoritySHA256 != nameBinding.AuthoritySHA256 || r.CertificateSHA256 != nameBinding.ParentSHA256 || !bytes.Equal(r.Certificate, nameBinding.Certificate) || in.Snapshot != nameBinding.Snapshot || in.RuntimeEpoch != nameBinding.RuntimeEpoch || in.LifetimeHours != nameBinding.LifetimeHours {
			return empty, nameGuard.failure()
		}
		requestSHA, requestKind = nameBinding.RequestSHA256, nameBinding.Kind
	}
	parentPolicy := func(ca, crl []byte, trust *nodepki.Trust, now time.Time) error {
		if nameGuard != nil {
			return nameGuard.validateRequest(ca, crl, now)
		}
		return renewalParentPolicy(ca, crl, trust, r, recovery, now)
	}
	if !c.NodePKI.Enabled || c.NodePKI.validate() != nil || !identifier.MatchString(r.Node) || !identifier.MatchString(in.Snapshot) || in.RuntimeEpoch < 1 || in.LifetimeHours < 1 || in.LifetimeHours > 90*24 || requestSHA == "" || l.Resource != nodeRenewalResource(r.Node) {
		return empty, errNodeIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return empty, err
	} else if held {
		return empty, ErrMigrationPending
	}
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return empty, err
	}
	if recovery != nil {
		if err := recoveryActorTx(ctx, tx, recovery.job); err != nil {
			return empty, err
		}
	}
	if nameGuard != nil {
		if err := nameGuard.actor(ctx, tx); err != nil {
			return empty, err
		}
	}
	// Use the same node lock and ordering as deployment. Saved but unapplied
	// hostname/endpoint changes must never influence an active renewal.
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT runtime_generation FROM v3_nodes WHERE id=$1 FOR UPDATE`, r.Node).Scan(&generation); err != nil {
		if err == sql.ErrNoRows {
			return empty, ErrConflict
		}
		return empty, err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return empty, err
	}
	exceptRecovery := ""
	if recovery != nil {
		if err := recovery.check(ctx, tx); err != nil {
			return empty, err
		}
		exceptRecovery = recovery.job.ID
	}
	if nameGuard != nil {
		if err := nameGuard.check(ctx, tx); err != nil {
			return empty, err
		}
		exceptRecovery = nameBinding.ID
	}
	if busy, err := nodeIdentityRecoveryBusyTx(ctx, tx, r.Node, exceptRecovery); err != nil {
		return empty, err
	} else if busy {
		return empty, errNodeRenewalPaused
	}
	var snapshot, serverName string
	var epoch int64
	var enabled bool
	if err := tx.QueryRowContext(ctx, `SELECT r.snapshot,r.epoch,c.server_name,c.enabled FROM v3_node_runtime r JOIN v3_node_configurations c ON c.node=r.node AND c.id=r.snapshot WHERE r.node=$1`, r.Node).Scan(&snapshot, &epoch, &serverName, &enabled); err != nil {
		if err == sql.ErrNoRows {
			return empty, ErrConflict
		}
		return empty, err
	}
	if !enabled || epoch != generation || epoch != in.RuntimeEpoch || snapshot != in.Snapshot {
		return empty, ErrConflict
	}
	var busy bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND status NOT IN ('succeeded','rolled_back') AND (status IN ('queued','running') OR recovery_required))`, r.Node).Scan(&busy); err != nil {
		return empty, err
	}
	if busy {
		return empty, ErrConflict
	}
	now := time.Now().UTC().Truncate(time.Second)
	old, err := provisioningCertificate(r.Certificate)
	if err != nil || digest(old.Raw) != r.CertificateSHA256 || old.VerifyHostname(serverName) != nil {
		return empty, errNodeIdentity
	}
	// An otherwise valid CA leaf is not enough: it must descend from a durable
	// initial issuance or an earlier committed local-key renewal for this node.
	var known []byte
	err = tx.QueryRowContext(ctx, `SELECT certificate FROM v3_node_certificates WHERE node=$1 AND authority=$2 AND serial=$3
 UNION ALL SELECT certificate FROM v3_node_certificate_renewals WHERE node=$1 AND authority=$2 AND serial=$3 LIMIT 1`, r.Node, r.AuthoritySHA256, old.SerialNumber.Text(16)).Scan(&known)
	if err != nil {
		if err == sql.ErrNoRows {
			return empty, errNodeIdentity
		}
		return empty, err
	}
	prior, err := provisioningCertificate(known)
	if err != nil || !bytes.Equal(prior.Raw, old.Raw) {
		return empty, errNodeIdentity
	}
	var pinnedCA, floor []byte
	if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1`, r.AuthoritySHA256).Scan(&pinnedCA, &floor); err != nil {
		if err == sql.ErrNoRows {
			return empty, errNodeIdentity
		}
		return empty, err
	}
	root, err := provisioningCertificate(pinnedCA)
	if err != nil || digest(root.Raw) != r.AuthoritySHA256 {
		return empty, errNodeIdentity
	}
	// Replays also consult the current managed CRL and the shared SQL floor;
	// an old receipt cannot bypass a newer revocation on another issuer host.
	crl, err := readTrustData(filepath.Join(c.NodePKI.AuthorityDirectory, "ca.crl"), true, nodepki.MaxCRLBytes)
	if err != nil || nodepki.ValidateCRLAdvance(pinnedCA, floor, crl, now) != nil {
		return empty, errNodeIdentity
	}
	trust, err := nodepki.NewTrust(pinnedCA, crl, now)
	if err != nil || parentPolicy(pinnedCA, crl, trust, now) != nil {
		return empty, errNodeIdentity
	}
	out := signedNodeRenewal{CRL: crl}
	var hours int
	var storedKind string
	receipt := &out.Receipt
	err = tx.QueryRowContext(ctx, `SELECT node,snapshot,runtime_epoch,authority,parent_sha256,request_sha256,certificate_sha256,serial,not_after,lifetime_hours,certificate,request_kind FROM v3_node_certificate_renewals WHERE node=$1 AND parent_sha256=$2`, r.Node, r.CertificateSHA256).Scan(&receipt.Node, &receipt.Snapshot, &receipt.RuntimeEpoch, &receipt.AuthoritySHA256, &receipt.ParentSHA256, &receipt.RequestSHA256, &receipt.CertificateSHA256, &receipt.Serial, &receipt.ExpiresAt, &hours, &out.Certificate, &storedKind)
	if err == nil {
		receipt.ExpiresAt = receipt.ExpiresAt.UTC()
		// Do not hold the authority SQL lock before taking a signing file lock.
		// Initial issuance uses file -> SQL ordering too. A replay takes no file
		// lock, but must recheck the floor under SQL serialization.
		if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR UPDATE`, r.AuthoritySHA256).Scan(&pinnedCA, &floor); err != nil {
			return empty, err
		}
		crl, err = readTrustData(filepath.Join(c.NodePKI.AuthorityDirectory, "ca.crl"), true, nodepki.MaxCRLBytes)
		if err != nil || nodepki.ValidateCRLAdvance(pinnedCA, floor, crl, now) != nil {
			return empty, errNodeIdentity
		}
		trust, err = nodepki.NewTrust(pinnedCA, crl, now)
		if err != nil || parentPolicy(pinnedCA, crl, trust, now) != nil {
			return empty, errNodeIdentity
		}
		out.CRL = crl
		cert, err := provisioningCertificate(out.Certificate)
		// A separately authorized SSH task may reconcile the same local CSR
		// after a runtime change. Keep the original issuance audit immutable;
		// the fresh recovery task supplies current version/epoch authority.
		bindingChanged := recovery == nil && (nameGuard == nil || len(nameBinding.Continuation) == 0) && (receipt.Snapshot != snapshot || receipt.RuntimeEpoch != epoch)
		if err != nil || storedKind != requestKind || receipt.RequestSHA256 != requestSHA || receipt.AuthoritySHA256 != r.AuthoritySHA256 || bindingChanged || hours != in.LifetimeHours || receipt.CertificateSHA256 != digest(cert.Raw) || receipt.Serial != cert.SerialNumber.Text(16) || !receipt.ExpiresAt.Equal(cert.NotAfter) || !cert.NotAfter.After(old.NotAfter) || cert.VerifyHostname(serverName) != nil || trust.Verify(cert, nodepki.Node, r.Node, now) != nil {
			return empty, errNodeIdentity
		}
		if nameGuard != nil && nameGuard.validateCertificate(pinnedCA, crl, out.Certificate, now) != nil {
			return empty, nameGuard.failure()
		}

		if nameGuard != nil && len(nameBinding.Continuation) != 0 && !bytes.Equal(out.Certificate, nameBinding.Continuation) {
			return empty, nameGuard.failure()
		}
		if recovery != nil && len(recovery.request.ContinuationCertificate) != 0 && !bytes.Equal(out.Certificate, recovery.request.ContinuationCertificate) {
			return empty, errNodeIdentityRecovery
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_pki_authorities SET crl=$2,updated_at=clock_timestamp() WHERE sha256=$1`, r.AuthoritySHA256, crl); err != nil {
			return empty, err
		}
	} else if err == sql.ErrNoRows {
		issue := func(accept func(nodepki.Bundle, []byte) error) error {
			if nameGuard != nil {
				return nameGuard.issue(ctx, c, now, accept)
			}
			if recovery != nil {
				return nodepki.SignNodeRecoveryRegistered(ctx, c.NodePKI.AuthorityDirectory, recovery.request, recovery.job.Intent, now, time.Duration(in.LifetimeHours)*time.Hour, accept)
			}
			return nodepki.SignNodeRenewalRegistered(ctx, c.NodePKI.AuthorityDirectory, r, now, time.Duration(in.LifetimeHours)*time.Hour, accept)
		}
		err = issue(func(b nodepki.Bundle, currentCRL []byte) error {
			if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR UPDATE`, r.AuthoritySHA256).Scan(&pinnedCA, &floor); err != nil {
				return err
			}
			ca, err := provisioningCertificate(b.CA)
			if err != nil || len(b.Key) != 0 || !bytes.Equal(ca.Raw, root.Raw) || nodepki.ValidateCRLAdvance(pinnedCA, floor, currentCRL, now) != nil {
				return errNodeIdentity
			}
			cert, err := provisioningCertificate(b.Certificate)
			policy, trustErr := nodepki.NewTrust(pinnedCA, currentCRL, now)
			if err != nil || trustErr != nil || parentPolicy(pinnedCA, currentCRL, policy, now) != nil || policy.Verify(cert, nodepki.Node, r.Node, now) != nil || cert.VerifyHostname(serverName) != nil {
				return errNodeIdentity
			}
			if nameGuard != nil && nameGuard.validateCertificate(pinnedCA, currentCRL, b.Certificate, now) != nil {
				return nameGuard.failure()
			}

			*receipt = nodeRenewalReceipt{Node: r.Node, Snapshot: snapshot, RuntimeEpoch: epoch, AuthoritySHA256: r.AuthoritySHA256, ParentSHA256: r.CertificateSHA256, RequestSHA256: requestSHA, CertificateSHA256: digest(cert.Raw), Serial: cert.SerialNumber.Text(16), ExpiresAt: cert.NotAfter}
			if _, err := tx.ExecContext(ctx, `INSERT INTO v3_node_certificate_renewals(node,authority,parent_sha256,request_sha256,snapshot,runtime_epoch,lifetime_hours,certificate,certificate_sha256,serial,not_after,request_kind) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, r.Node, r.AuthoritySHA256, r.CertificateSHA256, requestSHA, snapshot, epoch, in.LifetimeHours, b.Certificate, receipt.CertificateSHA256, receipt.Serial, receipt.ExpiresAt, requestKind); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE v3_pki_authorities SET crl=$2,updated_at=clock_timestamp() WHERE sha256=$1`, r.AuthoritySHA256, currentCRL); err != nil {
				return err
			}
			metadata, _ := json.Marshal(receipt)
			actor, kind := "system-pki", "renew-node-certificate"
			if recovery != nil {
				actor, kind = recovery.job.User, "recover-node-certificate"
			}
			if nameGuard != nil {
				actor, kind = nameBinding.User, nameBinding.AuditKind
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,$2,$3,$4)`, actor, kind, r.Node, metadata); err != nil {
				return err
			}
			out.Certificate = append([]byte{}, b.Certificate...)
			out.CRL = append([]byte{}, currentCRL...)
			return nil
		})
		if err != nil {
			return empty, err
		}
	} else {
		return empty, err
	}
	// File/SQL waits can outlive a parent leaf or CRL even while the task and
	// signing lease remain valid. Recheck CURRENT time and the latest monotonic
	// trust floor immediately before final task/fence checks and commit. A
	// failed check rolls back issuance/audit; no public receipt leaves here.
	if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR UPDATE`, r.AuthoritySHA256).Scan(&pinnedCA, &floor); err != nil {
		return empty, err
	}
	currentNow := time.Now().UTC()
	currentCRL, err := readTrustData(filepath.Join(c.NodePKI.AuthorityDirectory, "ca.crl"), true, nodepki.MaxCRLBytes)
	if err != nil || nodepki.ValidateCRLAdvance(pinnedCA, floor, currentCRL, currentNow) != nil {
		return empty, errNodeIdentity
	}
	currentTrust, err := nodepki.NewTrust(pinnedCA, currentCRL, currentNow)
	cert, certificateErr := provisioningCertificate(out.Certificate)
	if err != nil || certificateErr != nil || parentPolicy(pinnedCA, currentCRL, currentTrust, currentNow) != nil || currentTrust.Verify(cert, nodepki.Node, r.Node, currentNow) != nil || cert.VerifyHostname(serverName) != nil {
		return empty, errNodeIdentity
	}
	if nameGuard != nil && nameGuard.validateCertificate(pinnedCA, currentCRL, out.Certificate, currentNow) != nil {
		return empty, nameGuard.failure()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v3_pki_authorities SET crl=$2,updated_at=clock_timestamp() WHERE sha256=$1`, r.AuthoritySHA256, currentCRL); err != nil {
		return empty, err
	}
	out.CRL = currentCRL
	// Expiry can pass while waiting for the authority lock or SQL. Never return
	// a public certificate from a transaction whose fencing has expired.
	if err := s.Fence(ctx, tx, l); err != nil {
		return empty, err
	}
	if recovery != nil {
		if err := recovery.check(ctx, tx); err != nil {
			return empty, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_identity_recoveries SET status='signed',updated_at=clock_timestamp() WHERE id=$1 AND status='requested'`, recovery.job.ID); err != nil {
			return empty, err
		}
	}
	if nameGuard != nil {
		if err := nameGuard.check(ctx, tx); err != nil {
			return empty, err
		}
		if err := nameGuard.markSigned(ctx, tx); err != nil {
			return empty, err
		}
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return out, nil
}

func renewalParentPolicy(ca, crl []byte, trust *nodepki.Trust, r nodepki.NodeRenewalRequest, recovery *nodeIdentityRecoverySigningGuard, now time.Time) error {
	if recovery != nil {
		return nodepki.ValidateNodeRecoveryRequest(ca, crl, recovery.request, recovery.job.Intent, now)
	}
	old, err := provisioningCertificate(r.Certificate)
	if err != nil {
		return errNodeIdentity
	}
	return trust.Verify(old, nodepki.Node, r.Node, now)
}
