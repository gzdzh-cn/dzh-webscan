package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"webscan/internal/nodepki"
)

var errNodeRenewalPaused = errors.New("节点部署维护中，暂缓身份证书续期")

type nodeRenewalJob struct {
	Node, ParentSHA256, RequestSHA256, Snapshot string
	RuntimeEpoch                                int64
	LifetimeHours                               int
	Request                                     []byte
	Activated                                   bool
}

const nodeRenewalJobColumns = `node,parent_sha256,request_sha256,snapshot,runtime_epoch,lifetime_hours,request,activated_at IS NOT NULL`

func scanNodeRenewalJob(row interface{ Scan(...any) error }) (j nodeRenewalJob, err error) {
	err = row.Scan(&j.Node, &j.ParentSHA256, &j.RequestSHA256, &j.Snapshot, &j.RuntimeEpoch, &j.LifetimeHours, &j.Request, &j.Activated)
	return
}

// Hold deployment relations and the node before taking runtime/queue locks.
// Both relay writes and delivery use the live shard fence, never a saved draft.
func (s *Store) renewalRuntimeTx(ctx context.Context, tx *sql.Tx, n Node, l Lease) (string, error) {
	if held, err := migrationHeld(ctx, tx); err != nil {
		return "", err
	} else if held {
		return "", ErrMigrationPending
	}
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return "", err
	}
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT runtime_generation FROM v3_nodes WHERE id=$1 FOR UPDATE`, n.ID).Scan(&generation); err != nil {
		if err == sql.ErrNoRows {
			return "", ErrLeaseLost
		}
		return "", err
	}
	if err := s.FenceNode(ctx, tx, n, l); err != nil {
		return "", err
	}
	var snapshot string
	var epoch int64
	if err := tx.QueryRowContext(ctx, `SELECT snapshot,epoch FROM v3_node_runtime WHERE node=$1`, n.ID).Scan(&snapshot, &epoch); err != nil {
		return "", err
	}
	if epoch != generation || epoch != n.RuntimeEpoch {
		return "", ErrLeaseLost
	}
	var busy bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND status NOT IN ('succeeded','rolled_back') AND (status IN ('queued','running') OR recovery_required)) OR EXISTS(SELECT 1 FROM v3_node_identity_recoveries WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_changes WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_prunings WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp())`, n.ID).Scan(&busy); err != nil {
		return "", err
	}
	if busy {
		return "", errNodeRenewalPaused
	}
	return snapshot, nil
}

func (s *Store) checkRenewalRuntime(ctx context.Context, n Node, l Lease) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := s.renewalRuntimeTx(ctx, tx, n, l); err != nil {
		return err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return err
	}
	return tx.Commit()
}

// Validate the entire public request and its registered ancestry before it can
// consume durable signing work. This helper never reads the authority key.
func validateRenewalJobTx(ctx context.Context, tx *sql.Tx, n Node, raw []byte, now time.Time) (nodepki.NodeRenewalRequest, error) {
	r, err := nodepki.ParseNodeRenewalRequest(raw)
	if err != nil || r.Node != n.ID {
		return nodepki.NodeRenewalRequest{}, errNodeIdentity
	}
	var ca, crl []byte
	if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR SHARE`, r.AuthoritySHA256).Scan(&ca, &crl); err != nil {
		if err == sql.ErrNoRows {
			return nodepki.NodeRenewalRequest{}, errNodeIdentity
		}
		return nodepki.NodeRenewalRequest{}, err
	}
	old, err := provisioningCertificate(r.Certificate)
	if err != nil || old.VerifyHostname(n.ServerName) != nil || nodepki.ValidateNodeRenewalRequest(ca, crl, r, now) != nil {
		return nodepki.NodeRenewalRequest{}, errNodeIdentity
	}
	var known []byte
	err = tx.QueryRowContext(ctx, `SELECT certificate FROM v3_node_certificates WHERE node=$1 AND authority=$2 AND serial=$3
 UNION ALL SELECT certificate FROM v3_node_certificate_renewals WHERE node=$1 AND authority=$2 AND serial=$3 UNION ALL SELECT certificate FROM v3_root_identity_issuances WHERE role='node' AND subject=$1 AND authority=$2 AND serial=$3 LIMIT 1`, r.Node, r.AuthoritySHA256, old.SerialNumber.Text(16)).Scan(&known)
	if err != nil {
		if err == sql.ErrNoRows {
			return nodepki.NodeRenewalRequest{}, errNodeIdentity
		}
		return nodepki.NodeRenewalRequest{}, err
	}
	prior, err := provisioningCertificate(known)
	if err != nil || !bytes.Equal(prior.Raw, old.Raw) {
		return nodepki.NodeRenewalRequest{}, errNodeIdentity
	}
	return r, nil
}

func (s *Store) queueNodeRenewal(ctx context.Context, n Node, l Lease, raw []byte, lifetimeHours int) (nodeRenewalJob, error) {
	var empty nodeRenewalJob
	if lifetimeHours < 1 || lifetimeHours > 90*24 {
		return empty, errNodeIdentity
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	snapshot, err := s.renewalRuntimeTx(ctx, tx, n, l)
	if err != nil {
		return empty, err
	}
	r, err := validateRenewalJobTx(ctx, tx, n, raw, time.Now())
	if err != nil {
		return empty, err
	}
	j, err := scanNodeRenewalJob(tx.QueryRowContext(ctx, `INSERT INTO v3_node_renewal_jobs(node,parent_sha256,request_sha256,snapshot,runtime_epoch,lifetime_hours,request)
 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(node,parent_sha256) DO UPDATE SET
 snapshot=excluded.snapshot,runtime_epoch=excluded.runtime_epoch,updated_at=CASE WHEN v3_node_renewal_jobs.snapshot<>excluded.snapshot OR v3_node_renewal_jobs.runtime_epoch<>excluded.runtime_epoch THEN clock_timestamp() ELSE v3_node_renewal_jobs.updated_at END
 WHERE v3_node_renewal_jobs.request_sha256=excluded.request_sha256 AND v3_node_renewal_jobs.request=excluded.request AND v3_node_renewal_jobs.lifetime_hours=excluded.lifetime_hours
 RETURNING `+nodeRenewalJobColumns, r.Node, r.CertificateSHA256, r.SHA256(), snapshot, n.RuntimeEpoch, lifetimeHours, raw))
	if err == sql.ErrNoRows {
		return empty, ErrConflict
	} else if err != nil {
		return empty, err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return j, nil
}

// The host reads bounded public work. Stale bindings are not signed: the live
// collector must rebind the exact same pending CSR under its new shard fence.
// No row lock is kept while the host obtains its dedicated signing lease.
func (s *Store) pendingNodeRenewals(ctx context.Context, limit int) ([]nodeRenewalJob, error) {
	if limit < 1 || limit > 1000 {
		return nil, errNodeIdentity
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT j.node,j.parent_sha256,j.request_sha256,j.snapshot,j.runtime_epoch,j.lifetime_hours,j.request,false
 FROM v3_node_renewal_jobs j JOIN v3_node_runtime r ON r.node=j.node AND r.snapshot=j.snapshot AND r.epoch=j.runtime_epoch
 JOIN v3_nodes n ON n.id=j.node AND n.runtime_generation=r.epoch
 JOIN v3_node_configurations c ON c.node=r.node AND c.id=r.snapshot
 WHERE j.activated_at IS NULL AND c.enabled AND j.next_attempt_at<=clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM v3_node_certificate_renewals x WHERE x.node=j.node AND x.parent_sha256=j.parent_sha256)
 AND NOT EXISTS(SELECT 1 FROM v3_node_identity_recoveries i WHERE i.node=j.node AND i.status IN ('prepared','requested','signed') AND i.expires_at>clock_timestamp())
 AND NOT EXISTS(SELECT 1 FROM v3_node_name_changes i WHERE i.node=j.node AND i.status IN ('prepared','requested','signed') AND i.expires_at>clock_timestamp())
 AND NOT EXISTS(SELECT 1 FROM v3_node_name_prunings i WHERE i.node=j.node AND i.status IN ('prepared','requested','signed') AND i.expires_at>clock_timestamp())
 AND NOT EXISTS(SELECT 1 FROM v3_deployment_jobs d WHERE d.node=j.node AND d.status NOT IN ('succeeded','rolled_back') AND (d.status IN ('queued','running') OR d.recovery_required))
 ORDER BY j.next_attempt_at,j.node LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []nodeRenewalJob{}
	for rows.Next() {
		j, err := scanNodeRenewalJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// Delivery deliberately does not re-sign or rewrite an issuance's original
// snapshot/epoch. It validates that receipt against the current runtime, node,
// public request and current shared CRL; a harmless config update cannot strand
// the node-local pending key or cause a second certificate to be issued.
func (s *Store) nodeRenewalDelivery(ctx context.Context, n Node, l Lease, parent, request string) (signedNodeRenewal, error) {
	var empty signedNodeRenewal
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	snapshot, err := s.renewalRuntimeTx(ctx, tx, n, l)
	if err != nil {
		return empty, err
	}
	j, err := scanNodeRenewalJob(tx.QueryRowContext(ctx, `SELECT `+nodeRenewalJobColumns+` FROM v3_node_renewal_jobs WHERE node=$1 AND parent_sha256=$2`, n.ID, parent))
	if err != nil {
		return empty, err
	}
	if j.RequestSHA256 != request || j.RuntimeEpoch != n.RuntimeEpoch || j.Snapshot != snapshot {
		return empty, ErrConflict
	}
	r, err := validateRenewalJobTx(ctx, tx, n, j.Request, time.Now())
	if err != nil {
		return empty, err
	}
	if r.CertificateSHA256 != parent || r.SHA256() != request {
		return empty, errNodeIdentity
	}
	out, err := renewalReceiptTx(ctx, tx, n, r, j.LifetimeHours)
	if err != nil {
		return empty, err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return out, nil
}

func renewalReceiptTx(ctx context.Context, tx *sql.Tx, n Node, r nodepki.NodeRenewalRequest, hours int) (signedNodeRenewal, error) {
	var empty, out signedNodeRenewal
	x := &out.Receipt
	var lifetime int
	err := tx.QueryRowContext(ctx, `SELECT node,snapshot,runtime_epoch,authority,parent_sha256,request_sha256,certificate_sha256,serial,not_after,lifetime_hours,certificate FROM v3_node_certificate_renewals WHERE node=$1 AND parent_sha256=$2 AND request_kind='renewal'`, n.ID, r.CertificateSHA256).Scan(&x.Node, &x.Snapshot, &x.RuntimeEpoch, &x.AuthoritySHA256, &x.ParentSHA256, &x.RequestSHA256, &x.CertificateSHA256, &x.Serial, &x.ExpiresAt, &lifetime, &out.Certificate)
	if err != nil {
		return empty, err
	}
	x.ExpiresAt = x.ExpiresAt.UTC()
	var ca []byte
	if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR SHARE`, r.AuthoritySHA256).Scan(&ca, &out.CRL); err != nil {
		return empty, err
	}
	now := time.Now()
	trust, err := nodepki.NewTrust(ca, out.CRL, now)
	cert, parseErr := provisioningCertificate(out.Certificate)
	old, oldErr := provisioningCertificate(r.Certificate)
	if err != nil || parseErr != nil || oldErr != nil || x.AuthoritySHA256 != r.AuthoritySHA256 || x.RequestSHA256 != r.SHA256() || lifetime != hours || x.CertificateSHA256 != digest(cert.Raw) || x.Serial != cert.SerialNumber.Text(16) || !x.ExpiresAt.Equal(cert.NotAfter) || !cert.NotAfter.After(old.NotAfter) || cert.VerifyHostname(n.ServerName) != nil || trust.Verify(cert, nodepki.Node, n.ID, now) != nil {
		return empty, errNodeIdentity
	}
	return out, nil
}

// After a lost activation response the next authenticated Capabilities read can
// finish the same job. The receipt must be an exact, still-valid committed leaf.
// Parent expiry no longer matters here: this records an already active successor
// and cannot sign or deliver anything using an expired parent identity.
func (s *Store) confirmNodeRenewal(ctx context.Context, n Node, l Lease, certificate string, expiresAt int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := s.renewalRuntimeTx(ctx, tx, n, l); err != nil {
		return err
	}
	var raw []byte
	var hours int
	err = tx.QueryRowContext(ctx, `SELECT j.request,j.lifetime_hours FROM v3_node_renewal_jobs j
 JOIN v3_node_certificate_renewals x ON x.node=j.node AND x.parent_sha256=j.parent_sha256 AND x.request_sha256=j.request_sha256 AND x.request_kind='renewal'
 WHERE j.node=$1 AND x.certificate_sha256=$2 AND extract(epoch FROM x.not_after)::bigint=$3`, n.ID, certificate, expiresAt).Scan(&raw, &hours)
	if err != nil {
		return err
	}
	r, err := nodepki.ParseNodeRenewalRequest(raw)
	if err != nil || r.Node != n.ID {
		return errNodeIdentity
	}
	if _, err := renewalReceiptTx(ctx, tx, n, r, hours); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE v3_node_renewal_jobs SET activated_at=clock_timestamp(),last_error='',updated_at=clock_timestamp() WHERE node=$1 AND parent_sha256=$2 AND activated_at IS NULL`, n.ID, r.CertificateSHA256)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count == 1 {
		metadata, _ := json.Marshal(map[string]string{"certificate_sha256": certificate, "request_sha256": r.SHA256()})
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES('system-pki','activate-node-certificate',$1,$2)`, n.ID, metadata); err != nil {
			return err
		}
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return err
	}
	return tx.Commit()
}
