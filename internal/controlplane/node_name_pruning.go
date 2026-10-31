package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"webscan/internal/nodepki"
)

type nodeNamePruningInput struct {
	Node, Credential string
	Expected         int64
	LifetimeHours    int
	Certificate      []byte
}

// Internal durable authorization, not a browser response or user-editable
// plan. All names and dependencies are derived from the protected PG state.
type nodeNamePruningJob struct {
	ID, Node, User, Snapshot, Credential, CredentialProof, AuthoritySHA256, ParentSHA256, Status, RequestSHA256 string
	ActorRevision, NodeVersion                                                                                  int64
	LifetimeHours                                                                                               int
	Certificate, Request                                                                                        []byte
	Plan                                                                                                        nodeNamePruningPlan
	Intent                                                                                                      nodepki.NodeNamePruningIntent
	ExpiresAt                                                                                                   time.Time
}

const nodeNamePruningColumns = `id,node,username,actor_revision,node_version,snapshot,credential,credential_proof,authority,parent_sha256,lifetime_hours,certificate,plan,intent,expires_at,status,request,request_sha256`

func scanNodeNamePruning(row interface{ Scan(...any) error }) (j nodeNamePruningJob, err error) {
	var plan, intent []byte
	err = row.Scan(&j.ID, &j.Node, &j.User, &j.ActorRevision, &j.NodeVersion, &j.Snapshot, &j.Credential, &j.CredentialProof, &j.AuthoritySHA256, &j.ParentSHA256, &j.LifetimeHours, &j.Certificate, &plan, &intent, &j.ExpiresAt, &j.Status, &j.Request, &j.RequestSHA256)
	if err == nil && (json.Unmarshal(plan, &j.Plan) != nil || json.Unmarshal(intent, &j.Intent) != nil) {
		err = errNodeNamePruning
	}
	j.ExpiresAt = j.ExpiresAt.UTC()
	return
}

func pruningActorTx(ctx context.Context, tx *sql.Tx, j nodeNamePruningJob) error {
	revision, err := deploymentPreviewAccount(ctx, tx, j.User)
	if err != nil || revision != j.ActorRevision {
		return errNodeNamePruning
	}
	return nil
}

func checkNodeNamePruningTx(ctx context.Context, tx *sql.Tx, c Config, v *Vault, original nodeNamePruningJob) (nodeNamePruningJob, error) {
	var empty nodeNamePruningJob
	p, err := namePruningPolicyTx(ctx, tx, c, original.User, original.Node, original.NodeVersion, original.Certificate, original.ID)
	if err != nil {
		return empty, err
	}
	j, err := scanNodeNamePruning(tx.QueryRowContext(ctx, `SELECT `+nodeNamePruningColumns+` FROM v3_node_name_prunings WHERE id=$1 AND expires_at>clock_timestamp() FOR UPDATE`, original.ID))
	if err != nil || j.Node != original.Node || j.User != original.User || j.ActorRevision != original.ActorRevision || j.NodeVersion != original.NodeVersion || j.Snapshot != original.Snapshot || j.Credential != original.Credential || j.CredentialProof != original.CredentialProof || j.AuthoritySHA256 != original.AuthoritySHA256 || j.ParentSHA256 != original.ParentSHA256 || j.LifetimeHours != original.LifetimeHours || !bytes.Equal(j.Certificate, original.Certificate) || !reflect.DeepEqual(j.Plan, original.Plan) || !reflect.DeepEqual(j.Plan, p) || j.Intent.SHA256() != original.Intent.SHA256() || !j.ExpiresAt.Equal(original.ExpiresAt) || !j.ExpiresAt.Equal(j.Intent.ExpiresAt) || (j.Status != "prepared" && j.Status != "requested" && j.Status != "signed" && j.Status != "completed") {
		return empty, errNodeNamePruning
	}
	i := j.Intent
	if i.Node != p.Node || i.AuthoritySHA256 != p.AuthoritySHA256 || i.CertificateSHA256 != p.ParentSHA256 || i.ConfigurationSHA256 != p.ConfigurationSHA256 || i.RuntimeEpoch != p.RuntimeEpoch || i.ActiveName != p.ActiveName || !reflect.DeepEqual(i.Names, p.Names) || j.ActorRevision != p.ActorRevision || j.Snapshot != p.Snapshot || j.AuthoritySHA256 != p.AuthoritySHA256 || j.ParentSHA256 != p.ParentSHA256 || len(p.RemovableNames) == 0 {
		return empty, errNodeNamePruning
	}
	proof, err := provisioningCredentialTx(ctx, tx, v, j.Credential, j.Node)
	if err != nil || proof != j.CredentialProof {
		return empty, errNodeNamePruning
	}
	return j, nil
}

func (s *Store) nodeNamePruning(ctx context.Context, c Config, v *Vault, id string) (nodeNamePruningJob, error) {
	var empty nodeNamePruningJob
	if !c.NodePKI.Enabled || c.NodePKI.validate() != nil || v == nil || !identifier.MatchString(id) {
		return empty, errNodeNamePruning
	}
	j, err := scanNodeNamePruning(s.DB.QueryRowContext(ctx, `SELECT `+nodeNamePruningColumns+` FROM v3_node_name_prunings WHERE id=$1`, id))
	if err != nil {
		return empty, errNodeNamePruning
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	j, err = checkNodeNamePruningTx(ctx, tx, c, v, j)
	if err != nil {
		return empty, err
	}
	return j, tx.Commit()
}

// Prepare only persists an explicit administrator intent. It cannot connect,
// mint a leaf, choose user-supplied SANs, retire history or change configuration.
func (s *Store) prepareNodeNamePruning(ctx context.Context, c Config, v *Vault, user, key string, in nodeNamePruningInput) (nodeNamePruningJob, error) {
	var empty nodeNamePruningJob
	if !c.NodePKI.Enabled || c.NodePKI.validate() != nil || v == nil || !identifier.MatchString(in.Node) || !identifier.MatchString(in.Credential) || in.Expected < 1 || len(in.Certificate) == 0 || len(in.Certificate) > 16<<10 || in.LifetimeHours < 1 || in.LifetimeHours > 2160 {
		return empty, errNodeNamePruning
	}
	raw, err := s.guardedMutation(ctx, user, key, "prepare-node-name-pruning", in.Node, in, func(tx *sql.Tx) error {
		if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
			return err
		}
		_, err := deploymentPreviewAccount(ctx, tx, user)
		return err
	}, func(tx *sql.Tx) (any, error) {
		p, err := namePruningPolicyTx(ctx, tx, c, user, in.Node, in.Expected, in.Certificate, "")
		if err != nil {
			return nil, err
		}
		if len(p.RemovableNames) == 0 {
			return nil, errNodeNamePruning
		}
		if _, _, hours, err := namePruningPriorIssuance(ctx, tx, p); err != sql.ErrNoRows && (err != nil || hours != in.LifetimeHours) {
			return nil, errNodeNamePruning
		}
		proof, err := provisioningCredentialTx(ctx, tx, v, in.Credential, in.Node)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_name_prunings SET status='canceled',updated_at=clock_timestamp() WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at<=clock_timestamp()`, in.Node); err != nil {
			return nil, err
		}
		i, err := nodepki.NewNodeNamePruningIntent(in.Node, p.AuthoritySHA256, p.ParentSHA256, p.ConfigurationSHA256, p.RuntimeEpoch, p.ActiveName, p.Names, time.Now().UTC().Truncate(time.Second))
		if err != nil {
			return nil, err
		}
		plan, _ := json.Marshal(p)
		intent, _ := json.Marshal(i)
		id := token()
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_node_name_prunings(id,node,username,actor_revision,node_version,snapshot,credential,credential_proof,authority,parent_sha256,lifetime_hours,certificate,plan,intent,expires_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'prepared')`, id, in.Node, user, p.ActorRevision, p.NodeVersion, p.Snapshot, in.Credential, proof, p.AuthoritySHA256, p.ParentSHA256, in.LifetimeHours, in.Certificate, plan, intent, i.ExpiresAt); err != nil {
			return nil, err
		}
		return map[string]string{"id": id, "node": in.Node, "status": "prepared"}, nil
	})
	if err != nil {
		return empty, err
	}
	var receipt struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &receipt) != nil {
		return empty, errNodeNamePruning
	}
	return s.nodeNamePruning(ctx, c, v, receipt.ID)
}

func (s *Store) admitNodeNamePruning(ctx context.Context, c Config, v *Vault, l Lease, id string, raw []byte) (nodeNamePruningJob, error) {
	var empty nodeNamePruningJob
	j, err := s.nodeNamePruning(ctx, c, v, id)
	if err != nil || l.Resource != nodeRenewalResource(j.Node) || j.Status == "completed" {
		return empty, errNodeNamePruning
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	j, err = checkNodeNamePruningTx(ctx, tx, c, v, j)
	if err != nil {
		return empty, err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return empty, err
	}
	r, err := nodepki.ParseNodeNamePruningRequest(raw)
	if err != nil || !bytes.Equal(r.Certificate, j.Certificate) {
		return empty, errNodeNamePruning
	}
	var ca, crl []byte
	if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1`, j.AuthoritySHA256).Scan(&ca, &crl); err != nil || nodepki.ValidateNodeNamePruningRequest(ca, crl, r, j.Intent, time.Now()) != nil {
		return empty, errNodeNamePruning
	}
	if err := checkNamePruningContinuationIssuance(ctx, tx, j, r); err != nil {
		return empty, err
	}
	if j.Status != "prepared" {
		if j.RequestSHA256 != r.SHA256() || !bytes.Equal(j.Request, raw) {
			return empty, ErrConflict
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_name_prunings SET status='requested',request=$2,request_sha256=$3,updated_at=clock_timestamp() WHERE id=$1`, j.ID, raw, r.SHA256()); err != nil {
			return empty, err
		}
		metadata, _ := json.Marshal(map[string]string{"id": j.ID, "request_sha256": r.SHA256()})
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'request-node-name-pruning',$2,$3)`, j.User, j.Node, metadata); err != nil {
			return empty, err
		}
		j.Status, j.Request, j.RequestSHA256 = "requested", append([]byte(nil), raw...), r.SHA256()
	}
	if _, err := checkNodeNamePruningTx(ctx, tx, c, v, j); err != nil {
		return empty, err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return empty, err
	}
	return j, tx.Commit()
}

type nodeNamePruningSigningGuard struct {
	job     nodeNamePruningJob
	config  Config
	vault   *Vault
	request nodepki.NodeNamePruningRequest
}

func (g *nodeNamePruningSigningGuard) binding() nodeNameSigningBinding {
	j := g.job
	return nodeNameSigningBinding{ID: j.ID, Node: j.Node, User: j.User, AuthoritySHA256: j.AuthoritySHA256, ParentSHA256: j.ParentSHA256, Snapshot: j.Snapshot, RequestSHA256: g.request.IssuanceSHA256(), Kind: "name-pruning", AuditKind: "prune-node-certificate-names", RuntimeEpoch: j.Plan.RuntimeEpoch, LifetimeHours: j.LifetimeHours, Certificate: g.request.Certificate, Continuation: g.request.ContinuationCertificate}
}
func (g *nodeNamePruningSigningGuard) failure() error { return errNodeNamePruning }
func (g *nodeNamePruningSigningGuard) actor(ctx context.Context, tx *sql.Tx) error {
	return pruningActorTx(ctx, tx, g.job)
}
func (g *nodeNamePruningSigningGuard) check(ctx context.Context, tx *sql.Tx) error {
	j, err := checkNodeNamePruningTx(ctx, tx, g.config, g.vault, g.job)
	if err != nil {
		return err
	}
	if (j.Status != "requested" && j.Status != "signed") || j.RequestSHA256 != g.request.SHA256() || !bytes.Equal(j.Request, g.job.Request) {
		return errNodeNamePruning
	}
	return checkNamePruningContinuationIssuance(ctx, tx, j, g.request)
}
func (g *nodeNamePruningSigningGuard) validateRequest(ca, crl []byte, now time.Time) error {
	return nodepki.ValidateNodeNamePruningRequest(ca, crl, g.request, g.job.Intent, now)
}
func (g *nodeNamePruningSigningGuard) validateCertificate(ca, crl, cert []byte, now time.Time) error {
	return nodepki.ValidateNodeNamePruningCertificate(ca, crl, g.request, g.job.Intent, cert, now)
}
func (g *nodeNamePruningSigningGuard) issue(ctx context.Context, c Config, now time.Time, accept func(nodepki.Bundle, []byte) error) error {
	return nodepki.SignNodeNamePruningRegistered(ctx, c.NodePKI.AuthorityDirectory, g.request, g.job.Intent, now, time.Duration(g.job.LifetimeHours)*time.Hour, accept)
}
func (g *nodeNamePruningSigningGuard) markSigned(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `UPDATE v3_node_name_prunings SET status='signed',updated_at=clock_timestamp() WHERE id=$1 AND status='requested'`, g.job.ID)
	return err
}

func (s *Store) signNodeNamePruning(ctx context.Context, c Config, v *Vault, l Lease, id string) (signedNodeRenewal, error) {
	var empty signedNodeRenewal
	j, err := s.nodeNamePruning(ctx, c, v, id)
	if err != nil {
		return empty, err
	}
	r, err := nodepki.ParseNodeNamePruningRequest(j.Request)
	if err != nil || r.SHA256() != j.RequestSHA256 || (j.Status != "requested" && j.Status != "signed") {
		return empty, errNodeNamePruning
	}
	in := nodeRenewalSigningInput{Snapshot: j.Snapshot, RuntimeEpoch: j.Plan.RuntimeEpoch, LifetimeHours: j.LifetimeHours, Request: nodepki.NodeRenewalRequest{Format: 1, Node: j.Node, AuthoritySHA256: j.AuthoritySHA256, CertificateSHA256: j.ParentSHA256, Certificate: r.Certificate}}
	return s.signNodeCertificateAuthorized(ctx, c, l, in, nil, &nodeNamePruningSigningGuard{j, c, v, r})
}

// The fixed host runner must supply a fresh normally verified peer, not a
// certificate claimed by an Agent response. No public handler calls this.
func (s *Store) confirmNodeNamePruning(ctx context.Context, c Config, v *Vault, l Lease, id string, peer *x509.Certificate) error {
	if peer == nil {
		return errNodeNamePruning
	}
	j, err := s.nodeNamePruning(ctx, c, v, id)
	if err != nil || l.Resource != nodeRenewalResource(j.Node) {
		return errNodeNamePruning
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	j, err = checkNodeNamePruningTx(ctx, tx, c, v, j)
	if err != nil {
		return err
	}
	if j.Status != "signed" && j.Status != "completed" {
		return errNodeNamePruning
	}
	r, err := nodepki.ParseNodeNamePruningRequest(j.Request)
	if err != nil || r.SHA256() != j.RequestSHA256 {
		return errNodeNamePruning
	}
	var known, ca, floor []byte
	var request, snapshot string
	var epoch int64
	var hours int
	if err := tx.QueryRowContext(ctx, `SELECT certificate,request_sha256,snapshot,runtime_epoch,lifetime_hours FROM v3_node_certificate_renewals WHERE node=$1 AND authority=$2 AND parent_sha256=$3 AND request_kind='name-pruning'`, j.Node, j.AuthoritySHA256, j.ParentSHA256).Scan(&known, &request, &snapshot, &epoch, &hours); err != nil {
		return errNodeNamePruning
	}
	cert, err := provisioningCertificate(known)
	if err != nil || !bytes.Equal(peer.Raw, cert.Raw) || request != r.IssuanceSHA256() || snapshot != j.Snapshot || epoch != j.Plan.RuntimeEpoch || hours != j.LifetimeHours {
		return errNodeNamePruning
	}
	if err := checkNamePruningContinuationIssuance(ctx, tx, j, r); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR UPDATE`, j.AuthoritySHA256).Scan(&ca, &floor); err != nil {
		return errNodeNamePruning
	}
	now := time.Now()
	crl, err := provisioningIssuerCRL(c, ca, now)
	if err != nil || nodepki.ValidateCRLAdvance(ca, floor, crl, now) != nil || nodepki.ValidateNodeNamePruningCertificate(ca, crl, r, j.Intent, known, now) != nil {
		return errNodeNamePruning
	}
	if j.Status != "completed" {
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_name_prunings SET status='completed',updated_at=clock_timestamp() WHERE id=$1`, j.ID); err != nil {
			return err
		}
		metadata, _ := json.Marshal(map[string]string{"id": j.ID, "certificate_sha256": digest(peer.Raw)})
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'complete-node-name-pruning',$2,$3)`, j.User, j.Node, metadata); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v3_pki_authorities SET crl=$2,updated_at=clock_timestamp() WHERE sha256=$1`, j.AuthoritySHA256, crl); err != nil {
		return err
	}
	if _, err := checkNodeNamePruningTx(ctx, tx, c, v, j); err != nil {
		return err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) cancelNodeNamePruning(ctx context.Context, user, key, id string) (json.RawMessage, error) {
	if !identifier.MatchString(id) {
		return nil, errNodeNamePruning
	}
	return s.guardedMutation(ctx, user, key, "cancel-node-name-pruning", id, id, func(tx *sql.Tx) error {
		if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
			return err
		}
		_, err := deploymentPreviewAccount(ctx, tx, user)
		return err
	}, func(tx *sql.Tx) (any, error) {
		var node, status string
		if err := tx.QueryRowContext(ctx, `SELECT node FROM v3_node_name_prunings WHERE id=$1 AND username=$2`, id, user).Scan(&node); err != nil {
			return nil, errNodeNamePruning
		}
		var version int64
		if err := tx.QueryRowContext(ctx, `SELECT version FROM v3_nodes WHERE id=$1 FOR UPDATE`, node).Scan(&version); err != nil {
			return nil, err
		}
		if err := tx.QueryRowContext(ctx, `SELECT status FROM v3_node_name_prunings WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
			return nil, err
		}
		if status == "completed" {
			return nil, ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_node_name_prunings SET status='canceled',updated_at=clock_timestamp() WHERE id=$1 AND status IN ('prepared','requested','signed')`, id); err != nil {
			return nil, err
		}
		return map[string]string{"id": id, "node": node, "message": "已停止后续名称裁剪步骤，已签发证书及节点当前数据保留"}, nil
	})
}
