package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"webscan/internal/deploy"
	"webscan/internal/nodepki"
)

var errNodeIdentityRecovery = errors.New("身份恢复任务已过期或账号、节点、运行配置及 SSH 凭据已变化，请重新检查")

type nodeIdentityRecoveryInput struct {
	Node, Credential, AuthoritySHA256, ParentSHA256 string
	Expected                                        int64
	LifetimeHours                                   int
	Certificate                                     []byte
}

// Internal host task, never a browser response. Only public certificate/CSR
// bytes and immutable encrypted credential references belong in this row.
type nodeIdentityRecoveryJob struct {
	ID, Node, User, ConfigSHA256, Snapshot, Credential, CredentialProof string
	AuthoritySHA256, ParentSHA256, Status, RequestSHA256                string
	ActorRevision, NodeVersion, RuntimeEpoch                            int64
	LifetimeHours                                                       int
	Intent                                                              nodepki.NodeRecoveryIntent
	ExpiresAt                                                           time.Time
	Request                                                             []byte
}

const nodeIdentityRecoveryColumns = `id,node,username,actor_revision,node_version,config_sha256,snapshot,runtime_epoch,credential,credential_proof,authority,parent_sha256,lifetime_hours,intent,expires_at,status,request,request_sha256`

func scanNodeIdentityRecovery(row interface{ Scan(...any) error }) (j nodeIdentityRecoveryJob, err error) {
	var raw []byte
	err = row.Scan(&j.ID, &j.Node, &j.User, &j.ActorRevision, &j.NodeVersion, &j.ConfigSHA256, &j.Snapshot, &j.RuntimeEpoch, &j.Credential, &j.CredentialProof, &j.AuthoritySHA256, &j.ParentSHA256, &j.LifetimeHours, &raw, &j.ExpiresAt, &j.Status, &j.Request, &j.RequestSHA256)
	if err == nil && json.Unmarshal(raw, &j.Intent) != nil {
		err = errNodeIdentityRecovery
	}
	j.ExpiresAt = j.ExpiresAt.UTC()
	return
}

// All administrator certificate operations share the same node exclusion.
// Callers hold the configuration gate and node lock before invoking this.
func nodeIdentityRecoveryBusyTx(ctx context.Context, tx *sql.Tx, node, except string) (bool, error) {
	var busy bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_node_identity_recoveries WHERE ($1='' OR node=$1) AND id<>$2 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_changes WHERE ($1='' OR node=$1) AND id<>$2 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_prunings WHERE ($1='' OR node=$1) AND id<>$2 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp())`, node, except).Scan(&busy)
	return busy, err
}

// Account -> node -> task -> credential/authority is the lock order shared by
// preparation, request admission and signing. Callers hold the operation gate.
func recoveryNodeStateTx(ctx context.Context, tx *sql.Tx, node string, expected int64) (Node, string, int64, error) {
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR UPDATE`, node))
	if err != nil || !n.Enabled || n.Version != expected || n.AppliedVersion == 0 {
		return Node{}, "", 0, errNodeIdentityRecovery
	}
	var snapshot string
	var serverName string
	var epoch, generation int64
	var enabled bool
	err = tx.QueryRowContext(ctx, `SELECT r.snapshot,r.epoch,n.runtime_generation,c.enabled,c.server_name FROM v3_node_runtime r JOIN v3_nodes n ON n.id=r.node JOIN v3_node_configurations c ON c.node=r.node AND c.id=r.snapshot WHERE r.node=$1`, node).Scan(&snapshot, &epoch, &generation, &enabled, &serverName)
	if err != nil || !enabled || epoch < 1 || epoch != generation || n.ServerName != serverName {
		return Node{}, "", 0, errNodeIdentityRecovery
	}
	var busy bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND status NOT IN ('succeeded','rolled_back') AND (status IN ('queued','running') OR recovery_required))`, node).Scan(&busy); err != nil {
		return Node{}, "", 0, err
	}
	if busy {
		return Node{}, "", 0, ErrDeploymentBusy
	}
	return n, snapshot, epoch, nil
}

func recoveryActorTx(ctx context.Context, tx *sql.Tx, j nodeIdentityRecoveryJob) error {
	rev, err := deploymentPreviewAccount(ctx, tx, j.User)
	if err != nil || rev != j.ActorRevision {
		return errNodeIdentityRecovery
	}
	return nil
}

// The separately stored intent, not a request-supplied copy, is authoritative.
// Recheck even on signed receipt replay; revocation/lease checks are additional.
func checkNodeIdentityRecoveryTx(ctx context.Context, tx *sql.Tx, v *Vault, original nodeIdentityRecoveryJob) (nodeIdentityRecoveryJob, error) {
	var empty nodeIdentityRecoveryJob
	if held, err := migrationHeld(ctx, tx); err != nil {
		return empty, err
	} else if held {
		return empty, ErrMigrationPending
	}
	n, snapshot, epoch, err := recoveryNodeStateTx(ctx, tx, original.Node, original.NodeVersion)
	if err != nil {
		return empty, err
	}
	j, err := scanNodeIdentityRecovery(tx.QueryRowContext(ctx, `SELECT `+nodeIdentityRecoveryColumns+` FROM v3_node_identity_recoveries WHERE id=$1 AND expires_at>clock_timestamp() FOR UPDATE`, original.ID))
	if err != nil || j.Node != original.Node || j.User != original.User || j.ActorRevision != original.ActorRevision || j.NodeVersion != original.NodeVersion || j.ConfigSHA256 != digest(n.Config) || j.Snapshot != snapshot || j.RuntimeEpoch != epoch || (j.Status != "prepared" && j.Status != "requested" && j.Status != "signed" && j.Status != "completed") || !j.Intent.ExpiresAt.Equal(j.ExpiresAt) || j.Intent.Node != j.Node || j.Intent.AuthoritySHA256 != j.AuthoritySHA256 || j.Intent.CertificateSHA256 != j.ParentSHA256 {
		return empty, errNodeIdentityRecovery
	}
	proof, err := provisioningCredentialTx(ctx, tx, v, j.Credential, j.Node)
	if err != nil || proof != j.CredentialProof {
		return empty, errNodeIdentityRecovery
	}
	return j, nil
}

func (s *Store) nodeIdentityRecovery(ctx context.Context, v *Vault, id string) (nodeIdentityRecoveryJob, error) {
	var empty nodeIdentityRecoveryJob
	if !identifier.MatchString(id) || v == nil {
		return empty, errNodeIdentityRecovery
	}
	initial, err := scanNodeIdentityRecovery(s.DB.QueryRowContext(ctx, `SELECT `+nodeIdentityRecoveryColumns+` FROM v3_node_identity_recoveries WHERE id=$1`, id))
	if err != nil {
		return empty, errNodeIdentityRecovery
	}
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
	if err := recoveryActorTx(ctx, tx, initial); err != nil {
		return empty, err
	}
	j, err := checkNodeIdentityRecoveryTx(ctx, tx, v, initial)
	if err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return j, nil
}

// This only admits an explicit administrator task. It performs no SSH, signs
// nothing and never decrypts an initial node key. The pinned SSH reference is
// re-opened and compared for every later phase, including signing replays.
func (s *Store) prepareNodeIdentityRecovery(ctx context.Context, c Config, v *Vault, user, key string, in nodeIdentityRecoveryInput) (nodeIdentityRecoveryJob, error) {
	var empty nodeIdentityRecoveryJob
	if !c.NodePKI.Enabled || c.NodePKI.validate() != nil || v == nil || !identifier.MatchString(in.Node) || !identifier.MatchString(in.Credential) || in.Expected < 1 || !releaseDigest(in.AuthoritySHA256) || !releaseDigest(in.ParentSHA256) || len(in.Certificate) == 0 || len(in.Certificate) > 16<<10 || in.LifetimeHours < 1 || in.LifetimeHours > 2160 {
		return empty, errNodeIdentityRecovery
	}
	var actor int64
	var n Node
	var snapshot, proof string
	var epoch int64
	raw, err := s.guardedMutation(ctx, user, key, "prepare-node-identity-recovery", in.Node, in, func(tx *sql.Tx) error {
		if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
			return err
		}
		var err error
		actor, err = deploymentPreviewAccount(ctx, tx, user)
		if err != nil {
			return errNodeIdentityRecovery
		}
		n, snapshot, epoch, err = recoveryNodeStateTx(ctx, tx, in.Node, in.Expected)
		if err != nil {
			return err
		}
		proof, err = provisioningCredentialTx(ctx, tx, v, in.Credential, in.Node)
		return err
	}, func(tx *sql.Tx) (any, error) {
		// Expired tasks retain their evidence, but no longer reserve the node.
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_identity_recoveries SET status='canceled',updated_at=clock_timestamp() WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at<=clock_timestamp()`, in.Node); err != nil {
			return nil, err
		}
		if busy, err := nodeIdentityRecoveryBusyTx(ctx, tx, in.Node, ""); err != nil {
			return nil, err
		} else if busy {
			return nil, ErrDeploymentBusy
		}
		var ca, crl, parent []byte
		if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR SHARE`, in.AuthoritySHA256).Scan(&ca, &crl); err != nil {
			return nil, errNodeIdentityRecovery
		}
		cert, err := provisioningCertificate(in.Certificate)
		if err != nil || digest(cert.Raw) != in.ParentSHA256 || time.Now().Before(cert.NotAfter) || cert.VerifyHostname(n.ServerName) != nil {
			return nil, errNodeIdentityRecovery
		}
		if err := tx.QueryRowContext(ctx, `SELECT certificate FROM v3_node_certificates WHERE node=$1 AND authority=$2 AND serial=$3 UNION ALL SELECT certificate FROM v3_node_certificate_renewals WHERE node=$1 AND authority=$2 AND serial=$3 UNION ALL SELECT certificate FROM v3_root_identity_issuances WHERE role='node' AND subject=$1 AND authority=$2 AND serial=$3 LIMIT 1`, in.Node, in.AuthoritySHA256, cert.SerialNumber.Text(16)).Scan(&parent); err != nil {
			return nil, errNodeIdentityRecovery
		}
		now := time.Now().UTC().Truncate(time.Second)
		root, err := provisioningCertificate(ca)
		if err != nil || digest(root.Raw) != in.AuthoritySHA256 {
			return nil, errNodeIdentityRecovery
		}
		current, err := provisioningIssuerCRL(c, ca, now)
		if err != nil || nodepki.ValidateCRLAdvance(ca, crl, current, now) != nil {
			return nil, errNodeIdentityRecovery
		}
		crl = current
		registered, err := provisioningCertificate(parent)
		if err != nil || !bytes.Equal(registered.Raw, cert.Raw) {
			return nil, errNodeIdentityRecovery
		}
		if err := nodepki.ValidateNodeRecoveryParent(ca, crl, in.Certificate, in.Node, now); err != nil {
			return nil, errNodeIdentityRecovery
		}
		intent, err := nodepki.NewNodeRecoveryIntent(in.Node, in.AuthoritySHA256, in.ParentSHA256, now)
		if err != nil {
			return nil, err
		}
		intentRaw, _ := json.Marshal(intent)
		id := token()
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_node_identity_recoveries(id,node,username,actor_revision,node_version,config_sha256,snapshot,runtime_epoch,credential,credential_proof,authority,parent_sha256,lifetime_hours,intent,expires_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'prepared')`, id, in.Node, user, actor, n.Version, digest(n.Config), snapshot, epoch, in.Credential, proof, in.AuthoritySHA256, in.ParentSHA256, in.LifetimeHours, intentRaw, intent.ExpiresAt); err != nil {
			return nil, err
		}
		return map[string]any{"id": id, "node": in.Node, "status": "prepared"}, nil
	})
	if err != nil {
		return empty, err
	}
	var receipt struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &receipt) != nil {
		return empty, errNodeIdentityRecovery
	}
	return s.nodeIdentityRecovery(ctx, v, receipt.ID)
}

// The host calls this only for a response obtained over the pinned task SSH
// connection. Root-key proof alone never grants permission to create a task.
func (s *Store) admitNodeIdentityRecovery(ctx context.Context, v *Vault, l Lease, id string, raw []byte) (nodeIdentityRecoveryJob, error) {
	var empty nodeIdentityRecoveryJob
	j, err := s.nodeIdentityRecovery(ctx, v, id)
	if err != nil || l.Resource != nodeRenewalResource(j.Node) {
		return empty, errNodeIdentityRecovery
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return empty, err
	}
	if err := recoveryActorTx(ctx, tx, j); err != nil {
		return empty, err
	}
	j, err = checkNodeIdentityRecoveryTx(ctx, tx, v, j)
	if err != nil {
		return empty, err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return empty, err
	}
	r, err := nodepki.ParseNodeRecoveryRequest(raw)
	if err != nil || r.Renewal.SHA256() == "" {
		return empty, errNodeIdentityRecovery
	}
	var ca, crl []byte
	if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR SHARE`, j.AuthoritySHA256).Scan(&ca, &crl); err != nil || nodepki.ValidateNodeRecoveryRequest(ca, crl, r, j.Intent, time.Now()) != nil {
		return empty, errNodeIdentityRecovery
	}
	if len(r.ContinuationCertificate) != 0 {
		// A current-key proof is only reconciliation of this original public
		// issuance. It must not manufacture a new signing request or let an
		// otherwise valid same-CSR certificate replace the committed receipt.
		var known []byte
		var authority, requestSHA string
		var hours int
		if err := tx.QueryRowContext(ctx, `SELECT certificate,authority,request_sha256,lifetime_hours FROM v3_node_certificate_renewals WHERE node=$1 AND parent_sha256=$2 AND request_kind='renewal'`, j.Node, j.ParentSHA256).Scan(&known, &authority, &requestSHA, &hours); err != nil || !bytes.Equal(known, r.ContinuationCertificate) || authority != j.AuthoritySHA256 || requestSHA != r.Renewal.SHA256() || hours != j.LifetimeHours {
			return empty, errNodeIdentityRecovery
		}
	}
	if j.Status != "prepared" {
		if j.RequestSHA256 != r.SHA256() || !bytes.Equal(j.Request, raw) {
			return empty, ErrConflict
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_identity_recoveries SET request=$2,request_sha256=$3,status='requested',updated_at=clock_timestamp() WHERE id=$1`, j.ID, raw, r.SHA256()); err != nil {
			return empty, err
		}
		metadata, _ := json.Marshal(map[string]string{"id": j.ID, "request_sha256": r.SHA256()})
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'request-node-identity-recovery',$2,$3)`, j.User, j.Node, metadata); err != nil {
			return empty, err
		}
		j.Status, j.Request, j.RequestSHA256 = "requested", append([]byte{}, raw...), r.SHA256()
	}
	if _, err := checkNodeIdentityRecoveryTx(ctx, tx, v, j); err != nil {
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

type nodeIdentityRecoverySigningGuard struct {
	job     nodeIdentityRecoveryJob
	vault   *Vault
	request nodepki.NodeRecoveryRequest
}

func (g *nodeIdentityRecoverySigningGuard) check(ctx context.Context, tx *sql.Tx) error {
	j, err := checkNodeIdentityRecoveryTx(ctx, tx, g.vault, g.job)
	if err != nil {
		return err
	}
	if (j.Status != "requested" && j.Status != "signed") || j.RequestSHA256 != g.request.SHA256() || !bytes.Equal(j.Request, g.job.Request) {
		return errNodeIdentityRecovery
	}
	return nil
}

// Same public ledger and node signing lease as ordinary renewal. A caller
// cannot turn an online request into an expired-parent signing operation.
func (s *Store) signNodeIdentityRecovery(ctx context.Context, c Config, v *Vault, l Lease, id string) (signedNodeRenewal, error) {
	var empty signedNodeRenewal
	j, err := s.nodeIdentityRecovery(ctx, v, id)
	if err != nil {
		return empty, err
	}
	r, err := nodepki.ParseNodeRecoveryRequest(j.Request)
	if err != nil || r.SHA256() != j.RequestSHA256 || (j.Status != "requested" && j.Status != "signed") {
		return empty, errNodeIdentityRecovery
	}
	in := nodeRenewalSigningInput{Snapshot: j.Snapshot, RuntimeEpoch: j.RuntimeEpoch, LifetimeHours: j.LifetimeHours, Request: r.Renewal}
	return s.signNodeCertificate(ctx, c, l, in, &nodeIdentityRecoverySigningGuard{job: j, vault: v, request: r})
}

// The host must supply the leaf observed on its actual authenticated mTLS
// readiness connection. A node's JSON claim or an activation response alone is
// not an observation. This method is not exposed as a browser/Agent endpoint.
func (s *Store) confirmNodeIdentityRecovery(ctx context.Context, c Config, v *Vault, l Lease, id string, peer *x509.Certificate) error {
	if peer == nil {
		return errNodeIdentityRecovery
	}
	j, err := s.nodeIdentityRecovery(ctx, v, id)
	if err != nil || l.Resource != nodeRenewalResource(j.Node) {
		return errNodeIdentityRecovery
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return err
	}
	if err := recoveryActorTx(ctx, tx, j); err != nil {
		return err
	}
	j, err = checkNodeIdentityRecoveryTx(ctx, tx, v, j)
	if err != nil {
		return err
	}
	if j.Status != "signed" && j.Status != "completed" {
		return errNodeIdentityRecovery
	}
	r, err := nodepki.ParseNodeRecoveryRequest(j.Request)
	if err != nil || r.SHA256() != j.RequestSHA256 {
		return errNodeIdentityRecovery
	}
	var known, ca, floor []byte
	var requestSHA string
	if err := tx.QueryRowContext(ctx, `SELECT certificate,request_sha256 FROM v3_node_certificate_renewals WHERE node=$1 AND parent_sha256=$2 AND request_kind='renewal'`, j.Node, j.ParentSHA256).Scan(&known, &requestSHA); err != nil {
		return errNodeIdentityRecovery
	}
	cert, err := provisioningCertificate(known)
	if err != nil || !bytes.Equal(cert.Raw, peer.Raw) || requestSHA != r.Renewal.SHA256() {
		return errNodeIdentityRecovery
	}
	if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR UPDATE`, j.AuthoritySHA256).Scan(&ca, &floor); err != nil {
		return errNodeIdentityRecovery
	}
	current, err := provisioningIssuerCRL(c, ca, time.Now())
	if err != nil || nodepki.ValidateCRLAdvance(ca, floor, current, time.Now()) != nil {
		return errNodeIdentityRecovery
	}
	policy, err := nodepki.NewTrust(ca, current, time.Now())
	if err != nil || policy.Verify(peer, nodepki.Node, j.Node, time.Now()) != nil {
		return errNodeIdentityRecovery
	}
	if j.Status != "completed" {
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_identity_recoveries SET status='completed',updated_at=clock_timestamp() WHERE id=$1`, j.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_renewal_jobs SET activated_at=COALESCE(activated_at,clock_timestamp()),last_error='',updated_at=clock_timestamp() WHERE node=$1 AND parent_sha256=$2 AND request_sha256=$3`, j.Node, j.ParentSHA256, r.Renewal.SHA256()); err != nil {
			return err
		}
		metadata, _ := json.Marshal(map[string]string{"id": j.ID, "certificate_sha256": digest(peer.Raw)})
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'complete-node-identity-recovery',$2,$3)`, j.User, j.Node, metadata); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v3_pki_authorities SET crl=$2,updated_at=clock_timestamp() WHERE sha256=$1`, j.AuthoritySHA256, current); err != nil {
		return err
	}
	if _, err := checkNodeIdentityRecoveryTx(ctx, tx, v, j); err != nil {
		return err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) cancelNodeIdentityRecovery(ctx context.Context, user, key, id string) (json.RawMessage, error) {
	if !identifier.MatchString(id) {
		return nil, errNodeIdentityRecovery
	}
	return s.guardedMutation(ctx, user, key, "cancel-node-identity-recovery", id, id, func(tx *sql.Tx) error {
		if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
			return err
		}
		_, err := deploymentPreviewAccount(ctx, tx, user)
		return err
	}, func(tx *sql.Tx) (any, error) {
		var node string
		if err := tx.QueryRowContext(ctx, `SELECT node FROM v3_node_identity_recoveries WHERE id=$1`, id).Scan(&node); err != nil {
			return nil, errNodeIdentityRecovery
		}
		var version int64
		if err := tx.QueryRowContext(ctx, `SELECT version FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR UPDATE`, node).Scan(&version); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_identity_recoveries SET status='canceled',updated_at=clock_timestamp() WHERE id=$1 AND status IN ('prepared','requested','signed')`, id); err != nil {
			return nil, err
		}
		return map[string]string{"id": id, "node": node, "message": "已停止后续恢复步骤，已签发证书及节点当前数据保留"}, nil
	})
}

func (s *Store) checkNodeIdentityRecoveryLease(ctx context.Context, v *Vault, l Lease, id string) (nodeIdentityRecoveryJob, error) {
	var empty nodeIdentityRecoveryJob
	j, err := s.nodeIdentityRecovery(ctx, v, id)
	if err != nil || l.Resource != nodeRenewalResource(j.Node) || j.Status == "completed" {
		return empty, errNodeIdentityRecovery
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return empty, err
	}
	if err := recoveryActorTx(ctx, tx, j); err != nil {
		return empty, err
	}
	j, err = checkNodeIdentityRecoveryTx(ctx, tx, v, j)
	if err != nil {
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

// Read-only root SSH authentication with an immutable, verified host pin. The
// host runner must still use fixed commands and recheck this task/fence before
// every remote phase. This never trusts a first-use key or changes known_hosts.
func (s *Store) connectNodeIdentityRecoverySSH(ctx context.Context, v *Vault, l Lease, id string) (*deploy.Remote, error) {
	j, err := s.checkNodeIdentityRecoveryLease(ctx, v, l, id)
	if err != nil {
		return nil, err
	}
	c, err := s.ReadCredential(ctx, v, j.Credential, j.Node)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, j.ExpiresAt)
	defer cancel()
	remote, err := connectCredentialSSH(ctx, c)
	if err != nil {
		return nil, err
	}
	if _, err := s.checkNodeIdentityRecoveryLease(ctx, v, l, id); err != nil {
		remote.Close()
		return nil, err
	}
	return remote, nil
}
