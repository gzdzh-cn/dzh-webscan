package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"webscan/internal/nodepki"
)

var errNodeNameChange = errors.New("名称变更任务已过期或账号、目标配置、运行配置及 SSH 凭据已变化，请重新检查")

type nodeNameChangeInput struct {
	Node, Credential, AuthoritySHA256, ParentSHA256 string
	Expected                                        int64
	LifetimeHours                                   int
	Certificate                                     []byte
}

// Internal host task, never a browser response. Only public certificate/CSR
// bytes and immutable encrypted credential references belong in this row.
type nodeNameChangeJob struct {
	ID, Node, User, ConfigSHA256, Snapshot, Credential, CredentialProof string
	AuthoritySHA256, ParentSHA256, Status, RequestSHA256                string
	TargetSnapshot, SourceName, TargetName                              string
	ActorRevision, NodeVersion, RuntimeEpoch                            int64
	LifetimeHours                                                       int
	Intent                                                              nodepki.NodeNameChangeIntent
	ExpiresAt                                                           time.Time
	Request                                                             []byte
}

const nodeNameChangeColumns = `id,node,username,actor_revision,node_version,config_sha256,snapshot,runtime_epoch,target_snapshot,source_name,target_name,credential,credential_proof,authority,parent_sha256,lifetime_hours,intent,expires_at,status,request,request_sha256`

func scanNodeNameChange(row interface{ Scan(...any) error }) (j nodeNameChangeJob, err error) {
	var raw []byte
	err = row.Scan(&j.ID, &j.Node, &j.User, &j.ActorRevision, &j.NodeVersion, &j.ConfigSHA256, &j.Snapshot, &j.RuntimeEpoch, &j.TargetSnapshot, &j.SourceName, &j.TargetName, &j.Credential, &j.CredentialProof, &j.AuthoritySHA256, &j.ParentSHA256, &j.LifetimeHours, &raw, &j.ExpiresAt, &j.Status, &j.Request, &j.RequestSHA256)
	if err == nil && json.Unmarshal(raw, &j.Intent) != nil {
		err = errNodeNameChange
	}
	j.ExpiresAt = j.ExpiresAt.UTC()
	return
}

// Account -> node -> task -> credential/authority is the lock order shared by
// preparation, request admission and signing. Callers hold the operation gate.
func nameChangeNodeStateTx(ctx context.Context, tx *sql.Tx, node string, expected int64) (Node, string, int64, string, string, error) {
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR UPDATE`, node))
	if err != nil || !n.Enabled || n.Version != expected || n.AppliedVersion == 0 {
		return Node{}, "", 0, "", "", errNodeNameChange
	}
	var snapshot, sourceName, targetSnapshot string
	var epoch, generation int64
	var enabled bool
	err = tx.QueryRowContext(ctx, `SELECT r.snapshot,r.epoch,n.runtime_generation,c.enabled,c.server_name FROM v3_node_runtime r JOIN v3_nodes n ON n.id=r.node JOIN v3_node_configurations c ON c.node=r.node AND c.id=r.snapshot WHERE r.node=$1`, node).Scan(&snapshot, &epoch, &generation, &enabled, &sourceName)
	if err != nil || !enabled || epoch < 1 || epoch != generation || sourceName == n.ServerName {
		return Node{}, "", 0, "", "", errNodeNameChange
	}
	// Bind the entire saved target, independently of the active source. Never
	// relax the recovery/ordinary-renewal requirement on the active TLS name.
	err = tx.QueryRowContext(ctx, `SELECT c.id FROM v3_node_configurations c JOIN v3_nodes n ON n.id=c.node WHERE n.id=$1 AND NOT EXISTS(SELECT 1 FROM v3_node_history_retirements h WHERE h.node=c.node AND h.snapshot=c.id) AND ROW(n.version,n.name,n.endpoint,n.server_name,n.enabled,n.mode,n.shard,n.config)=ROW(c.version,c.name,c.endpoint,c.server_name,c.enabled,c.mode,c.shard,c.config) ORDER BY c.id LIMIT 1`, node).Scan(&targetSnapshot)
	if err != nil {
		return Node{}, "", 0, "", "", errNodeNameChange
	}
	var busy bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND status NOT IN ('succeeded','rolled_back') AND (status IN ('queued','running') OR recovery_required))`, node).Scan(&busy); err != nil {
		return Node{}, "", 0, "", "", err
	}
	if busy {
		return Node{}, "", 0, "", "", ErrDeploymentBusy
	}
	return n, snapshot, epoch, targetSnapshot, sourceName, nil
}

func nameChangeActorTx(ctx context.Context, tx *sql.Tx, j nodeNameChangeJob) error {
	rev, err := deploymentPreviewAccount(ctx, tx, j.User)
	if err != nil || rev != j.ActorRevision {
		return errNodeNameChange
	}
	return nil
}

// The separately stored intent, not a request-supplied copy, is authoritative.
// Recheck even on signed receipt replay; revocation/lease checks are additional.
func checkNodeNameChangeTx(ctx context.Context, tx *sql.Tx, v *Vault, original nodeNameChangeJob) (nodeNameChangeJob, error) {
	var empty nodeNameChangeJob
	if held, err := migrationHeld(ctx, tx); err != nil {
		return empty, err
	} else if held {
		return empty, ErrMigrationPending
	}
	n, snapshot, epoch, targetSnapshot, sourceName, err := nameChangeNodeStateTx(ctx, tx, original.Node, original.NodeVersion)
	if err != nil {
		return empty, err
	}
	j, err := scanNodeNameChange(tx.QueryRowContext(ctx, `SELECT `+nodeNameChangeColumns+` FROM v3_node_name_changes WHERE id=$1 AND expires_at>clock_timestamp() FOR UPDATE`, original.ID))
	if err != nil || j.Node != original.Node || j.User != original.User || j.ActorRevision != original.ActorRevision || j.NodeVersion != original.NodeVersion || j.ConfigSHA256 != digest(n.Config) || j.Snapshot != snapshot || j.RuntimeEpoch != epoch || j.TargetSnapshot != targetSnapshot || j.SourceName != sourceName || j.TargetName != n.ServerName || j.Intent.ServerName != j.TargetName || (j.Status != "prepared" && j.Status != "requested" && j.Status != "signed" && j.Status != "completed") || !j.Intent.ExpiresAt.Equal(j.ExpiresAt) || j.Intent.Node != j.Node || j.Intent.AuthoritySHA256 != j.AuthoritySHA256 || j.Intent.CertificateSHA256 != j.ParentSHA256 {
		return empty, errNodeNameChange
	}
	proof, err := provisioningCredentialTx(ctx, tx, v, j.Credential, j.Node)
	if err != nil || proof != j.CredentialProof {
		return empty, errNodeNameChange
	}
	return j, nil
}

func (s *Store) nodeNameChange(ctx context.Context, v *Vault, id string) (nodeNameChangeJob, error) {
	var empty nodeNameChangeJob
	if !identifier.MatchString(id) || v == nil {
		return empty, errNodeNameChange
	}
	initial, err := scanNodeNameChange(s.DB.QueryRowContext(ctx, `SELECT `+nodeNameChangeColumns+` FROM v3_node_name_changes WHERE id=$1`, id))
	if err != nil {
		return empty, errNodeNameChange
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
	if err := nameChangeActorTx(ctx, tx, initial); err != nil {
		return empty, err
	}
	j, err := checkNodeNameChangeTx(ctx, tx, v, initial)
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
func (s *Store) prepareNodeNameChange(ctx context.Context, c Config, v *Vault, user, key string, in nodeNameChangeInput) (nodeNameChangeJob, error) {
	var empty nodeNameChangeJob
	if !c.NodePKI.Enabled || c.NodePKI.validate() != nil || v == nil || !identifier.MatchString(in.Node) || !identifier.MatchString(in.Credential) || in.Expected < 1 || !releaseDigest(in.AuthoritySHA256) || !releaseDigest(in.ParentSHA256) || len(in.Certificate) == 0 || len(in.Certificate) > 16<<10 || in.LifetimeHours < 1 || in.LifetimeHours > 2160 {
		return empty, errNodeNameChange
	}
	var actor int64
	var n Node
	var snapshot, proof, targetSnapshot, sourceName string
	var epoch int64
	raw, err := s.guardedMutation(ctx, user, key, "prepare-node-name-change", in.Node, in, func(tx *sql.Tx) error {
		if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
			return err
		}
		var err error
		actor, err = deploymentPreviewAccount(ctx, tx, user)
		if err != nil {
			return errNodeNameChange
		}
		n, snapshot, epoch, targetSnapshot, sourceName, err = nameChangeNodeStateTx(ctx, tx, in.Node, in.Expected)
		if err != nil {
			return err
		}
		proof, err = provisioningCredentialTx(ctx, tx, v, in.Credential, in.Node)
		return err
	}, func(tx *sql.Tx) (any, error) {
		// Expired tasks retain their evidence, but no longer reserve the node.
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_name_changes SET status='canceled',updated_at=clock_timestamp() WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at<=clock_timestamp()`, in.Node); err != nil {
			return nil, err
		}
		if busy, err := nodeIdentityRecoveryBusyTx(ctx, tx, in.Node, ""); err != nil {
			return nil, err
		} else if busy {
			return nil, ErrDeploymentBusy
		}
		var ca, crl, parent []byte
		if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR SHARE`, in.AuthoritySHA256).Scan(&ca, &crl); err != nil {
			return nil, errNodeNameChange
		}
		cert, err := provisioningCertificate(in.Certificate)
		if err != nil || digest(cert.Raw) != in.ParentSHA256 || cert.VerifyHostname(sourceName) != nil || cert.VerifyHostname(n.ServerName) == nil {
			return nil, errNodeNameChange
		}
		if err := tx.QueryRowContext(ctx, `SELECT certificate FROM v3_node_certificates WHERE node=$1 AND authority=$2 AND serial=$3 UNION ALL SELECT certificate FROM v3_node_certificate_renewals WHERE node=$1 AND authority=$2 AND serial=$3 UNION ALL SELECT certificate FROM v3_root_identity_issuances WHERE role='node' AND subject=$1 AND authority=$2 AND serial=$3 LIMIT 1`, in.Node, in.AuthoritySHA256, cert.SerialNumber.Text(16)).Scan(&parent); err != nil {
			return nil, errNodeNameChange
		}
		now := time.Now().UTC().Truncate(time.Second)
		root, err := provisioningCertificate(ca)
		if err != nil || digest(root.Raw) != in.AuthoritySHA256 {
			return nil, errNodeNameChange
		}
		current, err := provisioningIssuerCRL(c, ca, now)
		if err != nil || nodepki.ValidateCRLAdvance(ca, crl, current, now) != nil {
			return nil, errNodeNameChange
		}
		crl = current
		registered, err := provisioningCertificate(parent)
		if err != nil || !bytes.Equal(registered.Raw, cert.Raw) {
			return nil, errNodeNameChange
		}
		original, issued, priorErr := nameChangePriorIssuance(ctx, tx, in.Node, in.AuthoritySHA256, in.ParentSHA256, n.ServerName, in.LifetimeHours)
		if priorErr == sql.ErrNoRows {
			if err := validateNameChangeParent(ca, crl, in.Certificate, in.Node, now); err != nil {
				return nil, errNodeNameChange
			}
		} else if priorErr != nil || !bytes.Equal(original.Certificate, in.Certificate) || nodepki.ValidateNodeNameChangeReceipt(ca, crl, original, issued, now) != nil {
			return nil, errNodeNameChange
		}
		intent, err := nodepki.NewNodeNameChangeIntent(in.Node, in.AuthoritySHA256, in.ParentSHA256, n.ServerName, now)
		if err != nil {
			return nil, err
		}
		intentRaw, _ := json.Marshal(intent)
		id := token()
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_node_name_changes(id,node,username,actor_revision,node_version,config_sha256,snapshot,runtime_epoch,target_snapshot,source_name,target_name,credential,credential_proof,authority,parent_sha256,lifetime_hours,intent,expires_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'prepared')`, id, in.Node, user, actor, n.Version, digest(n.Config), snapshot, epoch, targetSnapshot, sourceName, n.ServerName, in.Credential, proof, in.AuthoritySHA256, in.ParentSHA256, in.LifetimeHours, intentRaw, intent.ExpiresAt); err != nil {
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
		return empty, errNodeNameChange
	}
	return s.nodeNameChange(ctx, v, receipt.ID)
}

// The host calls this only for a response obtained over the pinned task SSH
// connection. Root-key proof alone never grants permission to create a task.
func (s *Store) admitNodeNameChange(ctx context.Context, v *Vault, l Lease, id string, raw []byte) (nodeNameChangeJob, error) {
	var empty nodeNameChangeJob
	j, err := s.nodeNameChange(ctx, v, id)
	if err != nil || l.Resource != nodeRenewalResource(j.Node) {
		return empty, errNodeNameChange
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return empty, err
	}
	if err := nameChangeActorTx(ctx, tx, j); err != nil {
		return empty, err
	}
	j, err = checkNodeNameChangeTx(ctx, tx, v, j)
	if err != nil {
		return empty, err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return empty, err
	}
	r, err := nodepki.ParseNodeNameChangeRequest(raw)
	if err != nil || r.SHA256() == "" {
		return empty, errNodeNameChange
	}
	var ca, crl []byte
	if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR SHARE`, j.AuthoritySHA256).Scan(&ca, &crl); err != nil || nodepki.ValidateNodeNameChangeRequest(ca, crl, r, j.Intent, time.Now()) != nil {
		return empty, errNodeNameChange
	}
	if err := checkNameChangeContinuationIssuance(ctx, tx, j, r); err != nil {
		return empty, err
	}
	if j.Status != "prepared" {
		if j.RequestSHA256 != r.SHA256() || !bytes.Equal(j.Request, raw) {
			return empty, ErrConflict
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_name_changes SET request=$2,request_sha256=$3,status='requested',updated_at=clock_timestamp() WHERE id=$1`, j.ID, raw, r.SHA256()); err != nil {
			return empty, err
		}
		metadata, _ := json.Marshal(map[string]string{"id": j.ID, "request_sha256": r.SHA256()})
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'request-node-name-change',$2,$3)`, j.User, j.Node, metadata); err != nil {
			return empty, err
		}
		j.Status, j.Request, j.RequestSHA256 = "requested", append([]byte{}, raw...), r.SHA256()
	}
	if _, err := checkNodeNameChangeTx(ctx, tx, v, j); err != nil {
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

type nodeNameChangeSigningGuard struct {
	job     nodeNameChangeJob
	vault   *Vault
	request nodepki.NodeNameChangeRequest
}

func (g *nodeNameChangeSigningGuard) check(ctx context.Context, tx *sql.Tx) error {
	j, err := checkNodeNameChangeTx(ctx, tx, g.vault, g.job)
	if err != nil {
		return err
	}
	if (j.Status != "requested" && j.Status != "signed") || j.RequestSHA256 != g.request.SHA256() || !bytes.Equal(j.Request, g.job.Request) {
		return errNodeNameChange
	}
	return checkNameChangeContinuationIssuance(ctx, tx, j, g.request)
}

// Same public ledger and node signing lease as ordinary renewal. A caller
// cannot turn an online request into a name-expanding signing operation.
func (s *Store) signNodeNameChange(ctx context.Context, c Config, v *Vault, l Lease, id string) (signedNodeRenewal, error) {
	var empty signedNodeRenewal
	j, err := s.nodeNameChange(ctx, v, id)
	if err != nil {
		return empty, err
	}
	r, err := nodepki.ParseNodeNameChangeRequest(j.Request)
	if err != nil || r.SHA256() != j.RequestSHA256 || (j.Status != "requested" && j.Status != "signed") {
		return empty, errNodeNameChange
	}
	in := nodeRenewalSigningInput{Snapshot: j.Snapshot, RuntimeEpoch: j.RuntimeEpoch, LifetimeHours: j.LifetimeHours, Request: nodepki.NodeRenewalRequest{Format: 1, Node: j.Node, AuthoritySHA256: j.AuthoritySHA256, CertificateSHA256: j.ParentSHA256, Certificate: r.Certificate}}
	return s.signNodeCertificateAuthorized(ctx, c, l, in, nil, &nodeNameChangeSigningGuard{job: j, vault: v, request: r})
}

// Only the host's fresh, normally verified mTLS observation may confirm a
// locally activated identity. This is not an Agent/browser handler and does
// not publish the target configuration or change a listener/service. Applying
// that saved target still needs its own checked deployment transition.
func (s *Store) confirmNodeNameChange(ctx context.Context, c Config, v *Vault, l Lease, id string, peer *x509.Certificate) error {
	if peer == nil {
		return errNodeNameChange
	}
	j, err := s.nodeNameChange(ctx, v, id)
	if err != nil || l.Resource != nodeRenewalResource(j.Node) {
		return errNodeNameChange
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return err
	}
	if err := nameChangeActorTx(ctx, tx, j); err != nil {
		return err
	}
	j, err = checkNodeNameChangeTx(ctx, tx, v, j)
	if err != nil {
		return err
	}
	if j.Status != "signed" && j.Status != "completed" {
		return errNodeNameChange
	}
	r, err := nodepki.ParseNodeNameChangeRequest(j.Request)
	if err != nil || r.SHA256() != j.RequestSHA256 {
		return errNodeNameChange
	}
	var known, ca, floor []byte
	var requestSHA, snapshot string
	var epoch int64
	var hours int
	if err := tx.QueryRowContext(ctx, `SELECT certificate,request_sha256,snapshot,runtime_epoch,lifetime_hours FROM v3_node_certificate_renewals WHERE node=$1 AND parent_sha256=$2 AND authority=$3 AND request_kind='name-change'`, j.Node, j.ParentSHA256, j.AuthoritySHA256).Scan(&known, &requestSHA, &snapshot, &epoch, &hours); err != nil {
		return errNodeNameChange
	}
	cert, err := provisioningCertificate(known)
	if err != nil || !bytes.Equal(cert.Raw, peer.Raw) || requestSHA != r.IssuanceSHA256() || (len(r.ContinuationCertificate) == 0 && (snapshot != j.Snapshot || epoch != j.RuntimeEpoch)) || hours != j.LifetimeHours || peer.VerifyHostname(j.SourceName) != nil || peer.VerifyHostname(j.TargetName) != nil {
		return errNodeNameChange
	}
	if err := checkNameChangeContinuationIssuance(ctx, tx, j, r); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR UPDATE`, j.AuthoritySHA256).Scan(&ca, &floor); err != nil {
		return errNodeNameChange
	}
	now := time.Now()
	current, err := provisioningIssuerCRL(c, ca, time.Now())
	if err != nil || nodepki.ValidateCRLAdvance(ca, floor, current, now) != nil || nodepki.ValidateNodeNameChangeCertificate(ca, current, r, j.Intent, known, now) != nil {
		return errNodeNameChange
	}
	if j.Status != "completed" {
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_name_changes SET status='completed',updated_at=clock_timestamp() WHERE id=$1`, j.ID); err != nil {
			return err
		}
		metadata, _ := json.Marshal(map[string]string{"id": j.ID, "certificate_sha256": digest(peer.Raw)})
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'complete-node-name-change',$2,$3)`, j.User, j.Node, metadata); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v3_pki_authorities SET crl=$2,updated_at=clock_timestamp() WHERE sha256=$1`, j.AuthoritySHA256, current); err != nil {
		return err
	}
	if _, err := checkNodeNameChangeTx(ctx, tx, v, j); err != nil {
		return err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) cancelNodeNameChange(ctx context.Context, user, key, id string) (json.RawMessage, error) {
	if !identifier.MatchString(id) {
		return nil, errNodeNameChange
	}
	return s.guardedMutation(ctx, user, key, "cancel-node-name-change", id, id, func(tx *sql.Tx) error {
		if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
			return err
		}
		_, err := deploymentPreviewAccount(ctx, tx, user)
		return err
	}, func(tx *sql.Tx) (any, error) {
		var node string
		if err := tx.QueryRowContext(ctx, `SELECT node FROM v3_node_name_changes WHERE id=$1`, id).Scan(&node); err != nil {
			return nil, errNodeNameChange
		}
		var version int64
		if err := tx.QueryRowContext(ctx, `SELECT version FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR UPDATE`, node).Scan(&version); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_name_changes SET status='canceled',updated_at=clock_timestamp() WHERE id=$1 AND status IN ('prepared','requested','signed')`, id); err != nil {
			return nil, err
		}
		return map[string]string{"id": id, "node": node, "message": "已停止后续名称变更步骤，已签发证书及节点当前数据保留"}, nil
	})
}

// Public trust validation at preparation does not prove possession; admission
// later requires the exact administrator intent countersigned by the live key.
func validateNameChangeParent(ca, crl, certificate []byte, node string, now time.Time) error {
	cert, err := provisioningCertificate(certificate)
	if err != nil {
		return errNodeNameChange
	}
	trust, err := nodepki.NewTrust(ca, crl, now)
	if err != nil {
		return errNodeNameChange
	}
	return trust.Verify(cert, nodepki.Node, node, now)
}
