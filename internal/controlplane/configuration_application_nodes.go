package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"sort"
	"strings"

	"webscan/internal/common"
)

// A child lease alone cannot authorize work belonging to a configuration
// application. The in-process capability is never accepted from an API or
// serialized; every transaction reauthenticates the parent's actual lease and
// the durable link before looking at the child's journal.
type applicationNodeScopeKey struct{}
type applicationNodeScope struct {
	vault  *Vault
	parent privateConfigurationApplication
	node   string
	child  string
}
type applicationNodeLink struct {
	Node, Child, Plan, Proof string
	Ordinal                  int
	ParentEpoch              int64
}

func (applicationNodeScope) String() string   { return "[private application node capability]" }
func (applicationNodeScope) GoString() string { return "[private application node capability]" }
func (applicationNodeScope) MarshalJSON() ([]byte, error) {
	return nil, errConfigurationApplication
}

func applicationNodeProof(v *Vault, key string, p privateConfigurationApplication, l applicationNodeLink) (string, error) {
	if v == nil || len(v.receiptKeys[key]) == 0 {
		return "", errConfigurationApplication
	}
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/configuration-application/node-link/v1\x00"))
	h.Write(common.JSON([]any{p.ID, p.planProof, l.Node, l.Child, l.Ordinal, l.ParentEpoch, l.Plan}))
	return key + ":" + hex.EncodeToString(h.Sum(nil)), nil
}

func applicationNodeTargetProof(v *Vault, key string, p privateConfigurationApplication, release, manifest string) (string, error) {
	if v == nil || len(v.receiptKeys[key]) == 0 {
		return "", errConfigurationApplication
	}
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/configuration-application/node-target/v1\x00"))
	h.Write(common.JSON([]any{p.ID, p.planProof, release, manifest}))
	return key + ":" + hex.EncodeToString(h.Sum(nil)), nil
}

// Pin a single verified release manifest for all children, including after a
// process restart. Native and Docker have distinct artifacts in that manifest;
// a newly installed executor cannot silently mix releases halfway through.
func checkApplicationNodeTargetTx(ctx context.Context, tx *sql.Tx, v *Vault, p privateConfigurationApplication, in DeploymentRequest, create bool) error {
	var release, manifest, proof string
	err := tx.QueryRowContext(ctx, `SELECT release,manifest_sha256,proof FROM v3_configuration_application_targets WHERE application=$1 FOR UPDATE`, p.ID).Scan(&release, &manifest, &proof)
	if err == sql.ErrNoRows && create {
		var linked bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_configuration_application_nodes WHERE application=$1)`, p.ID).Scan(&linked); err != nil {
			return err
		}
		if linked || !releaseDigest(in.ManifestSHA256) {
			return errConfigurationApplication
		}
		proof, err = applicationNodeTargetProof(v, v.active, p, in.Release, in.ManifestSHA256)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO v3_configuration_application_targets(application,release,manifest_sha256,proof) VALUES($1,$2,$3,$4)`, p.ID, in.Release, in.ManifestSHA256, proof)
		return err
	}
	if err != nil {
		return errConfigurationApplication
	}
	key, _, ok := strings.Cut(proof, ":")
	want, err := applicationNodeTargetProof(v, key, p, release, manifest)
	if !ok || err != nil || !hmac.Equal([]byte(proof), []byte(want)) {
		return errConfigurationApplication
	}
	if release != in.Release || manifest != in.ManifestSHA256 {
		return ErrRequestConflict
	}
	return nil
}

func readApplicationNodeTx(ctx context.Context, tx *sql.Tx, v *Vault, p privateConfigurationApplication, node string) (applicationNodeLink, error) {
	var l applicationNodeLink
	err := tx.QueryRowContext(ctx, `SELECT node,child,ordinal,parent_epoch,plan_digest,proof FROM v3_configuration_application_nodes WHERE application=$1 AND node=$2 FOR UPDATE`, p.ID, node).Scan(&l.Node, &l.Child, &l.Ordinal, &l.ParentEpoch, &l.Plan, &l.Proof)
	if err != nil {
		return l, err
	}
	key, _, ok := strings.Cut(l.Proof, ":")
	want, err := applicationNodeProof(v, key, p, l)
	if !ok || err != nil || !hmac.Equal([]byte(want), []byte(l.Proof)) || l.ParentEpoch < 1 || l.ParentEpoch > p.epoch || l.Ordinal < 0 || !releaseDigest(l.Plan) {
		return applicationNodeLink{}, errConfigurationApplication
	}
	return l, nil
}

func writeApplicationNodeTx(ctx context.Context, tx *sql.Tx, v *Vault, p privateConfigurationApplication, l applicationNodeLink, insert bool) error {
	proof, err := applicationNodeProof(v, v.active, p, l)
	if err != nil {
		return err
	}
	if insert {
		_, err = tx.ExecContext(ctx, `INSERT INTO v3_configuration_application_nodes(application,node,child,ordinal,parent_epoch,plan_digest,proof) VALUES($1,$2,$3,$4,$5,$6,$7)`, p.ID, l.Node, l.Child, l.Ordinal, l.ParentEpoch, l.Plan, proof)
	} else {
		var res sql.Result
		res, err = tx.ExecContext(ctx, `UPDATE v3_configuration_application_nodes SET parent_epoch=$3,proof=$4 WHERE application=$1 AND node=$2 AND child=$5 AND plan_digest=$6`, p.ID, l.Node, l.ParentEpoch, proof, l.Child, l.Plan)
		if err == nil {
			err = deploymentAffected(res, nil)
		}
	}
	return err
}

func applicationNodeMatches(doc configurationDocument, n Node) bool {
	want, ok := doc.Nodes[n.ID]
	profile, profileOK := doc.Profiles[want.Profile]
	return ok && profileOK && n.Name == want.Name && n.Endpoint == want.Endpoint && n.ServerName == want.ServerName && n.Enabled == want.Enabled && n.Mode == want.Mode && n.Version == want.Version && configurationJSONEqual(n.Config, common.JSON(profile.Config))
}

func lockedApplicationNodeParentTx(ctx context.Context, tx *sql.Tx, v *Vault, p privateConfigurationApplication, node string) (privateConfigurationApplication, configurationDocument, error) {
	p, err := lockedApplication(ctx, tx, v, p)
	if err != nil {
		return p, configurationDocument{}, err
	}
	if !p.RecoveryRequired || p.phase() != "nodes" && p.phase() != "restore-nodes" {
		return p, configurationDocument{}, errConfigurationApplication
	}
	_, doc, err := applicationSavedEvidenceTx(ctx, tx, v, p)
	if err != nil {
		return p, doc, err
	}
	want, ok := doc.Nodes[node]
	if !ok || !want.Enabled {
		return p, doc, errConfigurationApplication
	}
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR SHARE`, node))
	if err != nil || !applicationNodeMatches(doc, n) {
		return p, doc, ErrConflict
	}
	return p, doc, nil
}

// Use only for an exact child journal operation. Public edits, trusted setup
// and ordinary queueing always use the non-scoped relation gate instead.
func lockDeploymentJournalTx(ctx context.Context, tx *sql.Tx, j DeploymentJob) error {
	if handled, err := lockMonitoringDeploymentJournalTx(ctx, tx, j); handled || err != nil {
		return err
	}
	scope, _ := ctx.Value(applicationNodeScopeKey{}).(*applicationNodeScope)
	if scope == nil {
		if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
			return err
		}
		var linked bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_configuration_application_nodes WHERE child=$1)`, j.ID).Scan(&linked); err != nil {
			return err
		}
		if linked {
			return errConfigurationApplication
		}
		return nil
	}
	if scope.child != j.ID || scope.node != j.Node || scope.child == "" {
		return errConfigurationApplication
	}
	p, _, err := lockedApplicationNodeParentTx(ctx, tx, scope.vault, scope.parent, j.Node)
	if err != nil {
		return err
	}
	l, err := readApplicationNodeTx(ctx, tx, scope.vault, p, j.Node)
	if err != nil || l.Child != j.ID || l.Plan != j.PlanDigest || l.ParentEpoch != p.epoch || j.Direction != p.Direction {
		return errConfigurationApplication
	}
	return checkApplicationNodeTargetTx(ctx, tx, scope.vault, p, j.Plan.Request, false)
}

// Reserve one existing deployment journal and its before-deploy archive in the
// same commit as the authenticated link. Preparation is local and outside the
// relation gate; final validation uses the saved parent source, never a form.
func (s *Store) queueApplicationNodeDeployment(ctx context.Context, c Config, t *deploymentTrust, p privateConfigurationApplication, in DeploymentRequest) (DeploymentJob, error) {
	var empty DeploymentJob
	if t == nil || t.vault == nil || in.validate() != nil || p.Direction != "forward" {
		return empty, errConfigurationApplication
	}
	m, err := s.localDeploymentMaterial(ctx, c, t, in)
	if err != nil {
		return empty, err
	}
	defer clear(m.Key)
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
	p, doc, err := lockedApplicationNodeParentTx(ctx, tx, t.vault, p, in.Node)
	if err != nil {
		return empty, err
	}
	if err = checkApplicationNodeTargetTx(ctx, tx, t.vault, p, in, true); err != nil {
		return empty, err
	}
	l, err := readApplicationNodeTx(ctx, tx, t.vault, p, in.Node)
	if err == nil {
		j, err := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1 FOR UPDATE`, l.Child))
		if err != nil || j.Node != in.Node || j.PlanDigest != l.Plan || !sameDeploymentRequest(j.Plan.Request, in) {
			return empty, ErrRequestConflict
		}
		return j, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return empty, err
	}
	keys := make([]string, 0, len(doc.Nodes))
	for id, n := range doc.Nodes {
		if n.Enabled {
			keys = append(keys, id)
		}
	}
	sort.Strings(keys)
	ordinal := sort.SearchStrings(keys, in.Node)
	for _, earlier := range keys[:ordinal] {
		// An earlier no-op must already have this exact version delivered.
		n, err := scanActiveNode(tx.QueryRowContext(ctx, `SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE id=$1`, earlier))
		if err != nil || !applicationNodeMatches(doc, n) || n.AppliedVersion != n.Version {
			return empty, ErrDeploymentBusy
		}
		var unfinished bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_configuration_application_nodes l JOIN v3_deployment_jobs d ON d.id=l.child WHERE l.application=$1 AND l.node=$2 AND d.status<>'succeeded')`, p.ID, earlier).Scan(&unfinished); err != nil {
			return empty, err
		}
		if unfinished {
			return empty, ErrDeploymentBusy
		}
	}
	raw, err := insertDeploymentWithBackup(ctx, tx, p.Controller, in, func(tx *sql.Tx, n Node) error {
		if !applicationNodeMatches(doc, n) {
			return ErrConflict
		}
		return validateLocalDeploymentTx(ctx, tx, c, t, p.Controller, in, m, n)
	}, &deploymentConfigurationBackup{t.vault, c})
	if err != nil {
		return empty, err
	}
	receipt, ok := raw.(map[string]any)
	if !ok {
		return empty, errConfigurationApplication
	}
	id, _ := receipt["id"].(string)
	j, err := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1`, id))
	if err != nil {
		return empty, err
	}
	l = applicationNodeLink{Node: j.Node, Child: j.ID, Ordinal: ordinal, ParentEpoch: p.epoch, Plan: j.PlanDigest}
	if err = writeApplicationNodeTx(ctx, tx, t.vault, p, l, true); err != nil {
		return empty, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-application-node',$2,$3)`, p.Controller, p.ID, common.JSON(map[string]any{"node": j.Node, "job": j.ID, "ordinal": ordinal})); err != nil {
		return empty, err
	}
	return j, tx.Commit()
}

func sameDeploymentRequest(a, b DeploymentRequest) bool {
	return string(common.JSON(a)) == string(common.JSON(b))
}

// A new parent epoch fences a live old child immediately. The remote adapter
// still has to acquire its host lock and reconcile its durable checkpoint.
// A current parent cannot steal a live child from its own concurrent worker.
func (s *Store) claimApplicationNodeDeployment(ctx context.Context, v *Vault, p privateConfigurationApplication, node, owner string) (DeploymentJob, context.Context, error) {
	var empty DeploymentJob
	if !identifier.MatchString(owner) {
		return empty, ctx, errConfigurationApplication
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, ctx, err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return empty, ctx, err
	} else if held {
		return empty, ctx, ErrMigrationPending
	}
	p, _, err = lockedApplicationNodeParentTx(ctx, tx, v, p, node)
	if err != nil {
		return empty, ctx, err
	}
	l, err := readApplicationNodeTx(ctx, tx, v, p, node)
	if err != nil {
		return empty, ctx, err
	}
	j, err := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1 FOR UPDATE`, l.Child))
	if err != nil || j.Node != node || j.PlanDigest != l.Plan {
		return empty, ctx, errConfigurationApplication
	}
	if err = checkApplicationNodeTargetTx(ctx, tx, v, p, j.Plan.Request, false); err != nil {
		return empty, ctx, err
	}
	if p.Direction == "forward" && j.Status == "succeeded" || p.Direction == "rollback" && j.Status == "rolled_back" {
		return j, ctx, tx.Commit()
	}
	if p.Direction == "forward" && (j.Status == "rolled_back" || j.Direction != "forward") {
		return empty, ctx, ErrDeploymentState
	}
	var live bool
	if j.LeaseUntil.Valid {
		if err = tx.QueryRowContext(ctx, `SELECT $1::timestamptz>clock_timestamp()`, j.LeaseUntil).Scan(&live); err != nil {
			return empty, ctx, err
		}
	}
	if j.Status == "running" && live && l.ParentEpoch == p.epoch {
		return empty, ctx, sql.ErrNoRows
	}
	if p.Direction == "rollback" {
		if err = applicationNodeRollbackOrderTx(ctx, tx, v, p, l); err != nil {
			return empty, ctx, err
		}
		if !j.RecoveryRequired && j.Step <= 2 {
			// Recovery is armed before the first service-changing operation.
			// Thus an unarmed preflight/stage job can be settled without making
			// up a remote restore receipt. The original runtime must still match.
			if err = checkDeploymentRuntimeTx(ctx, tx, j); err != nil {
				return empty, ctx, err
			}
			j.Status, j.Direction, j.RollbackStep = "rolled_back", "rollback", len(rollbackPhases)
			j.Epoch++
			if _, err = tx.ExecContext(ctx, `UPDATE v3_deployment_jobs SET status='rolled_back',direction='rollback',rollback_step=$2,lease_epoch=$3,lease_owner=NULL,lease_until=NULL,recovery_required=false,error_code='',finished_at=clock_timestamp() WHERE id=$1`, j.ID, j.RollbackStep, j.Epoch); err != nil {
				return empty, ctx, err
			}
			l.ParentEpoch = p.epoch
			if err = writeApplicationNodeTx(ctx, tx, v, p, l, false); err != nil {
				return empty, ctx, err
			}
			if err = deploymentLog(ctx, tx, &j, "verify-rollback", "rolled-back"); err != nil {
				return empty, ctx, err
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-application-node-unchanged',$2,$3)`, p.Controller, p.ID, common.JSON(map[string]any{"node": j.Node, "job": j.ID, "service_changed": false})); err != nil {
				return empty, ctx, err
			}
			return j, ctx, tx.Commit()
		}
		if !j.RecoveryRequired && j.Status != "succeeded" {
			return empty, ctx, ErrDeploymentState
		}
		// A succeeded child deliberately retained its rollback pin for this
		// parent. Reopen that same immutable plan, never create a new backup
		// whose baseline would already be the unsuccessful parent's target.
		j.RecoveryRequired = true
		if j.Direction != "rollback" {
			j.RollbackStep = 0
		}
		j.Direction = "rollback"
	}
	if err = checkDeploymentConfigurationTx(ctx, tx, j); err != nil {
		return empty, ctx, err
	}
	j.Epoch++
	j.Status = "running"
	j.Owner = sql.NullString{String: owner, Valid: true}
	if err = tx.QueryRowContext(ctx, `UPDATE v3_deployment_jobs SET status='running',lease_owner=$2,lease_epoch=$3,lease_until=clock_timestamp()+interval '30 seconds',error_code='',finished_at=NULL,direction=$4,rollback_step=$5,recovery_required=$6 WHERE id=$1 RETURNING lease_until`, j.ID, owner, j.Epoch, j.Direction, j.RollbackStep, j.RecoveryRequired).Scan(&j.LeaseUntil); err != nil {
		return empty, ctx, err
	}
	l.ParentEpoch = p.epoch
	if err = writeApplicationNodeTx(ctx, tx, v, p, l, false); err != nil {
		return empty, ctx, err
	}
	code := "claimed"
	if j.Epoch > 1 {
		code = "takeover"
	}
	if err = deploymentLog(ctx, tx, &j, j.Phase(), code); err != nil {
		return empty, ctx, err
	}
	if err = tx.Commit(); err != nil {
		return empty, ctx, err
	}
	scoped := context.WithValue(ctx, applicationNodeScopeKey{}, &applicationNodeScope{v, p, node, j.ID})
	return j, scoped, nil
}

func applicationNodeRollbackOrderTx(ctx context.Context, tx *sql.Tx, v *Vault, p privateConfigurationApplication, current applicationNodeLink) error {
	rows, err := tx.QueryContext(ctx, `SELECT node FROM v3_configuration_application_nodes WHERE application=$1 AND ordinal>$2 ORDER BY ordinal DESC`, p.ID, current.Ordinal)
	if err != nil {
		return err
	}
	var nodes []string
	for rows.Next() {
		var node string
		if err = rows.Scan(&node); err != nil {
			rows.Close()
			return err
		}
		nodes = append(nodes, node)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, node := range nodes {
		l, err := readApplicationNodeTx(ctx, tx, v, p, node)
		if err != nil {
			return err
		}
		j, err := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1 FOR SHARE`, l.Child))
		if err != nil || j.PlanDigest != l.Plan || j.Node != l.Node {
			return errConfigurationApplication
		}
		if j.Status != "rolled_back" {
			return ErrDeploymentBusy
		}
	}
	return nil
}

// Called inside the parent's terminal checkpoint transaction, never from a
// child's success. A partial/failed rollback cannot release any archive pins.
func releaseApplicationNodeConfigurationsTx(ctx context.Context, tx *sql.Tx, v *Vault, p privateConfigurationApplication) error {
	if err := verifyApplicationRegistrationsTx(ctx, tx, v, p); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT node FROM v3_configuration_application_nodes WHERE application=$1 ORDER BY ordinal`, p.ID)
	if err != nil {
		return err
	}
	var nodes []string
	for rows.Next() {
		var node string
		if err = rows.Scan(&node); err != nil {
			rows.Close()
			return err
		}
		nodes = append(nodes, node)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, node := range nodes {
		l, err := readApplicationNodeTx(ctx, tx, v, p, node)
		if err != nil {
			return err
		}
		j, err := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1 FOR UPDATE`, l.Child))
		if err != nil || j.Node != node || j.PlanDigest != l.Plan || j.RecoveryRequired || p.Direction == "forward" && j.Status != "succeeded" || p.Direction == "rollback" && j.Status != "rolled_back" {
			return errConfigurationApplication
		}
		if err = checkApplicationNodeTargetTx(ctx, tx, v, p, j.Plan.Request, false); err != nil {
			return err
		}
		if _, _, err = loadConfigurationBackup(ctx, tx, v, j.Plan.BeforeBackup, false); err != nil {
			return errDeploymentConfigurationBackup
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM v3_configuration_backup_pins WHERE backup=$1 AND kind IN ('deployment','rollback') AND reference=$2`, j.Plan.BeforeBackup, "job:"+j.ID)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return errDeploymentConfigurationBackup
		}
	}
	return nil
}

func (s *Store) verifyApplicationNodeOutcomesTx(ctx context.Context, tx *sql.Tx, v *Vault, p privateConfigurationApplication) error {
	if err := verifyApplicationRegistrationsTx(ctx, tx, v, p); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT node FROM v3_configuration_application_nodes WHERE application=$1 ORDER BY ordinal`, p.ID)
	if err != nil {
		return err
	}
	var nodes []string
	for rows.Next() {
		var node string
		if err = rows.Scan(&node); err != nil {
			rows.Close()
			return err
		}
		nodes = append(nodes, node)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, node := range nodes {
		l, err := readApplicationNodeTx(ctx, tx, v, p, node)
		if err != nil {
			return err
		}
		j, err := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1 FOR SHARE`, l.Child))
		if err != nil || j.Node != node || j.PlanDigest != l.Plan || j.RecoveryRequired || j.Direction != p.Direction || p.Direction == "forward" && j.Status != "succeeded" || p.Direction == "rollback" && j.Status != "rolled_back" {
			return errConfigurationApplication
		}
		if err = checkApplicationNodeTargetTx(ctx, tx, v, p, j.Plan.Request, false); err != nil {
			return err
		}
		if p.Direction == "forward" {
			// Acquire the collector fence before runtime node rows, matching the
			// collector/ordinary deployment verification lock order.
			if err = s.deploymentReady(ctx, tx, j); err != nil {
				return err
			}
		}
		if p.Direction == "rollback" && j.Step <= 2 {
			current, err := runtimeBaselineTx(ctx, tx, node)
			if err != nil || j.Plan.PreviousRuntime == nil || *current != *j.Plan.PreviousRuntime {
				return ErrConflict
			}
		} else if err = checkDeploymentRuntimeTx(ctx, tx, j); err != nil {
			return err
		}
		var applied int64
		if err = tx.QueryRowContext(ctx, `SELECT applied_version FROM v3_nodes WHERE removed_at IS NULL AND id=$1`, node).Scan(&applied); err != nil {
			return err
		}
		want := j.NodeVersion
		if p.Direction == "rollback" {
			want = j.Plan.Node.AppliedVersion
		}
		if applied != want {
			return ErrConflict
		}
	}
	return nil
}
