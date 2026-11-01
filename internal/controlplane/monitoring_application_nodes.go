package controlplane

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
)

type monitoringDeploymentScopeKey struct{}
type monitoringDeploymentScope struct {
	vault       *Vault
	parent      monitoringApplication
	node, child string
}

func (monitoringDeploymentScope) String() string { return "[private monitoring deployment capability]" }
func (monitoringDeploymentScope) GoString() string {
	return "[private monitoring deployment capability]"
}
func (monitoringDeploymentScope) MarshalJSON() ([]byte, error) { return nil, errMonitoringApplication }
func monitoringScope(ctx context.Context) *monitoringDeploymentScope {
	v, _ := ctx.Value(monitoringDeploymentScopeKey{}).(*monitoringDeploymentScope)
	return v
}
func (p monitoringApplication) node(id string) (monitoringApplicationPlanNode, bool) {
	for _, n := range p.Plan.Nodes {
		if n.Node.ID == id {
			return n, true
		}
	}
	return monitoringApplicationPlanNode{}, false
}
func monitoringNodeContext(ctx context.Context, v *Vault, p monitoringApplication, node, child string) context.Context {
	return context.WithValue(ctx, monitoringDeploymentScopeKey{}, &monitoringDeploymentScope{v, p, node, child})
}

// Call with the node row locked, before every ordinary node mutation/queue.
func checkMonitoringNodeReservationTx(ctx context.Context, tx *sql.Tx, node string) error {
	var parent string
	e := tx.QueryRowContext(ctx, `SELECT application FROM v3_monitoring_application_nodes WHERE node=$1 AND reserved`, node).Scan(&parent)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}
	scope := monitoringScope(ctx)
	if scope != nil && scope.node == node && scope.parent.ID == parent {
		return nil
	}
	return ErrDeploymentBusy
}
func lockMonitoringParentTx(ctx context.Context, tx *sql.Tx, v *Vault, expected monitoringApplication) (monitoringApplication, error) {
	if e := lockMonitoringWriteTx(ctx, tx); e != nil {
		return monitoringApplication{}, e
	}
	p, e := scanMonitoringApplication(tx.QueryRowContext(ctx, `SELECT `+monitoringApplicationColumns+` FROM v3_monitoring_applications WHERE id=$1 FOR UPDATE`, expected.ID))
	if e != nil {
		return p, e
	}
	if e = openMonitoringApplication(v, &p); e != nil {
		return p, e
	}
	var live bool
	if e = tx.QueryRowContext(ctx, `SELECT lease_until>clock_timestamp() AND NOT recovery_hold FROM v3_monitoring_applications WHERE id=$1`, p.ID).Scan(&live); e != nil {
		return p, e
	}
	if p.Status != "running" || !live || p.Epoch != expected.Epoch || !p.Owner.Valid || p.Owner.String != expected.Owner.String || p.Digest != expected.Digest {
		return p, ErrLeaseLost
	}
	rev, e := deploymentPreviewAccount(ctx, tx, p.Controller)
	if e != nil || rev != p.ControllerRevision {
		return p, errMonitoringApplication
	}
	return p, nil
}
func monitoringNodeLinkProof(v *Vault, key string, p monitoringApplication, node, child, plan string, epoch int64) string {
	return monitoringApplicationMAC(v, key, "node-link/v1", []any{p.ID, p.Digest, node, child, plan, epoch})
}
func checkMonitoringNodeLink(v *Vault, p monitoringApplication, node, child, plan, proof string, epoch int64) error {
	key, _, ok := strings.Cut(proof, ":")
	want := monitoringNodeLinkProof(v, key, p, node, child, plan, epoch)
	if !ok || want == "" || !hmac.Equal([]byte(want), []byte(proof)) || epoch < 1 || epoch > p.Epoch {
		return errMonitoringApplication
	}
	return nil
}

// Returns handled=true for owned children and prevents public recovery from
// bypassing the parent. Every journal operation rechecks the real parent lease.
func lockMonitoringDeploymentJournalTx(ctx context.Context, tx *sql.Tx, j DeploymentJob) (bool, error) {
	scope := monitoringScope(ctx)
	if scope == nil {
		var linked bool
		e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_monitoring_application_nodes WHERE child=$1)`, j.ID).Scan(&linked)
		if e != nil {
			return true, e
		}
		if linked {
			return true, errMonitoringApplication
		}
		return false, nil
	}
	if scope.child == "" || scope.child != j.ID || scope.node != j.Node {
		return true, errMonitoringApplication
	}
	if e := lockMonitoringWriteTx(ctx, tx); e != nil {
		return true, e
	}
	p, e := lockMonitoringParentTx(ctx, tx, scope.vault, scope.parent)
	if e != nil {
		return true, e
	}
	var child, plan, proof string
	var epoch int64
	var reserved bool
	e = tx.QueryRowContext(ctx, `SELECT coalesce(child,''),child_plan_digest,proof,parent_epoch,reserved FROM v3_monitoring_application_nodes WHERE application=$1 AND node=$2 FOR UPDATE`, p.ID, j.Node).Scan(&child, &plan, &proof, &epoch, &reserved)
	if e != nil {
		return true, e
	}
	if !reserved || child != j.ID || plan != j.PlanDigest || epoch != p.Epoch {
		return true, errMonitoringApplication
	}
	if e = checkMonitoringNodeLink(scope.vault, p, j.Node, child, plan, proof, epoch); e != nil {
		return true, e
	}
	target, ok := p.node(j.Node)
	if !ok || j.Plan.Request.ManifestSHA256 != p.Manifest || j.Plan.Request.Release != p.Release || j.Plan.Request.Credential != target.Credential || j.Plan.Request.Kind != "upgrade" || j.Plan.ConfigDigest != target.TargetDigest {
		return true, fmt.Errorf("monitoring child binding (%t/%t/%t/%t/%t/%t): %w", ok, j.Plan.Request.ManifestSHA256 == p.Manifest, j.Plan.Request.Release == p.Release, j.Plan.Request.Credential == target.Credential, j.Plan.Request.Kind == "upgrade", j.Plan.ConfigDigest == target.TargetDigest, errMonitoringApplication)
	}
	return true, nil
}

// Preserve successful child archives while a partial parent can still roll back.
func releaseMonitoringDeploymentConfigurationTx(ctx context.Context, tx *sql.Tx, j DeploymentJob) (bool, error) {
	var held bool
	e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_monitoring_application_nodes n JOIN v3_monitoring_applications p ON p.id=n.application WHERE n.child=$1 AND p.status NOT IN ('succeeded','rolled_back','expired'))`, j.ID).Scan(&held)
	return held, e
}
func (s *Store) prepareMonitoringNode(ctx context.Context, c Config, t *deploymentTrust, p monitoringApplication, node string) (Node, error) {
	item, ok := p.node(node)
	if !ok {
		return Node{}, errMonitoringApplication
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Node{}, e
	}
	defer tx.Rollback()
	if e = lockMonitoringWriteTx(ctx, tx); e != nil {
		return Node{}, e
	}
	n, e := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR UPDATE`, node))
	if e != nil {
		return n, e
	}
	p, e = lockMonitoringParentTx(ctx, tx, t.vault, p)
	if e != nil {
		return n, e
	}
	// A pinned generation never silently adopts subsequently saved global rules.
	d, e := readSettingsDraftTx(ctx, tx, false)
	if e != nil {
		return n, e
	}
	if checkSettingsDraftProof(t.vault, d) != nil || strconv.FormatInt(d.Generation, 10) != p.Generation {
		return n, ErrConflict
	}
	_, credentialState, e := monitoringApplicationCredentialTx(ctx, tx, node)
	if e != nil || credentialState != item.CredentialState {
		return n, ErrCredentialUnavailable
	}
	if !n.Enabled {
		return n, ErrConflict
	}
	if n.Version == item.Node.Version && configurationJSONEqual(n.Config, item.Before) {
		state, _, _, e := monitoringDeploymentState(ctx, tx, n)
		if e != nil {
			return n, e
		}
		if state != item.State {
			return n, ErrConflict
		}
		b := &configurationEditBackup{vault: t.vault, bootstrap: c}
		if e = b.capture(ctx, tx, p.Controller, "monitoring-application-node", node); e != nil {
			return n, e
		}
		if configurationJSONEqual(item.Before, item.Target) {
			_, e = tx.ExecContext(ctx, `UPDATE v3_monitoring_application_nodes SET state='preparing',updated_at=clock_timestamp() WHERE application=$1 AND node=$2`, p.ID, node)
		} else {
			_, e = tx.ExecContext(ctx, `UPDATE v3_nodes SET config=$2,version=version+1,updated_at=clock_timestamp() WHERE id=$1 AND version=$3`, node, item.Target, n.Version)
			if e == nil {
				_, e = captureSavedNodeTx(ctx, tx, node)
			}
			n.Config = append(json.RawMessage{}, item.Target...)
			n.Version++
		}
		if e != nil {
			return n, e
		}
	} else if n.Version != item.Node.Version+1 || !configurationJSONEqual(n.Config, item.Target) {
		return n, ErrConflict
	}
	if e = signMonitoringNodeStateTx(ctx, tx, t.vault, p, node, "preparing", ""); e != nil {
		return n, e
	}
	if e = tx.Commit(); e != nil {
		return n, e
	}
	return n, nil
}
func (s *Store) queueMonitoringNode(ctx context.Context, c Config, t *deploymentTrust, p monitoringApplication, in DeploymentRequest) (DeploymentJob, error) {
	var empty DeploymentJob
	item, ok := p.node(in.Node)
	if !ok || in.Release != p.Release || in.ManifestSHA256 != p.Manifest || in.Credential != item.Credential || in.Kind != "upgrade" {
		return empty, errMonitoringApplication
	}
	m, e := s.localDeploymentMaterial(ctx, c, t, in)
	if e != nil {
		return empty, e
	}
	defer clear(m.Key)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	if e = lockMonitoringWriteTx(ctx, tx); e != nil {
		return empty, e
	}
	n, e := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 FOR UPDATE`, in.Node))
	if e != nil {
		return empty, e
	}
	p, e = lockMonitoringParentTx(ctx, tx, t.vault, p)
	if e != nil {
		return empty, e
	}
	if n.Version != item.Node.Version+1 || !configurationJSONEqual(n.Config, item.Target) {
		return empty, ErrConflict
	}
	var existing sql.NullString
	if e = tx.QueryRowContext(ctx, `SELECT child FROM v3_monitoring_application_nodes WHERE application=$1 AND node=$2 AND reserved FOR UPDATE`, p.ID, in.Node).Scan(&existing); e != nil {
		return empty, e
	}
	if existing.Valid {
		j, e := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1`, existing.String))
		if e == nil && !sameDeploymentRequest(j.Plan.Request, in) {
			return empty, ErrRequestConflict
		}
		if e != nil {
			return j, e
		}
		return j, tx.Commit()
	}
	raw, e := insertDeploymentWithBackup(ctx, tx, p.Controller, in, func(tx *sql.Tx, n Node) error {
		return validateLocalDeploymentTx(ctx, tx, c, t, p.Controller, in, m, n)
	}, &deploymentConfigurationBackup{t.vault, c})
	if e != nil {
		return empty, e
	}
	receipt, ok := raw.(map[string]any)
	if !ok {
		return empty, errMonitoringApplication
	}
	id, _ := receipt["id"].(string)
	j, e := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1`, id))
	if e != nil {
		return empty, e
	}
	proof := monitoringNodeLinkProof(t.vault, t.vault.active, p, in.Node, j.ID, j.PlanDigest, p.Epoch)
	_, e = tx.ExecContext(ctx, `UPDATE v3_monitoring_application_nodes SET child=$3,child_plan_digest=$4,parent_epoch=$5,proof=$6,state='running',updated_at=clock_timestamp() WHERE application=$1 AND node=$2`, p.ID, in.Node, j.ID, j.PlanDigest, p.Epoch, proof)
	if e != nil {
		return empty, e
	}
	if e = signMonitoringNodeStateTx(ctx, tx, t.vault, p, in.Node, "running", ""); e != nil {
		return empty, e
	}
	return j, tx.Commit()
}
func (s *Store) claimMonitoringNode(ctx context.Context, v *Vault, p monitoringApplication, node string) (DeploymentJob, context.Context, error) {
	var empty DeploymentJob
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return empty, ctx, e
	}
	defer tx.Rollback()
	if e = lockMonitoringWriteTx(ctx, tx); e != nil {
		return empty, ctx, e
	}
	if _, e = tx.ExecContext(ctx, `SELECT id FROM v3_nodes WHERE id=$1 FOR UPDATE`, node); e != nil {
		return empty, ctx, e
	}
	p, e = lockMonitoringParentTx(ctx, tx, v, p)
	if e != nil {
		return empty, ctx, e
	}
	target, ok := p.node(node)
	if !ok {
		return empty, ctx, ErrConflict
	}
	var savedVersion int64
	var savedConfig []byte
	if e = tx.QueryRowContext(ctx, `SELECT version,config FROM v3_nodes WHERE id=$1`, node).Scan(&savedVersion, &savedConfig); e != nil {
		return empty, ctx, e
	}
	if savedVersion != target.Node.Version+1 || !configurationJSONEqual(savedConfig, target.Target) {
		return empty, ctx, ErrConflict
	}
	_, credentialState, e := monitoringApplicationCredentialTx(ctx, tx, node)
	if e != nil || credentialState != target.CredentialState {
		return empty, ctx, ErrCredentialUnavailable
	}

	var id, plan, proof string
	var epoch int64
	e = tx.QueryRowContext(ctx, `SELECT child,child_plan_digest,proof,parent_epoch FROM v3_monitoring_application_nodes WHERE application=$1 AND node=$2 AND reserved FOR UPDATE`, p.ID, node).Scan(&id, &plan, &proof, &epoch)
	if e != nil {
		return empty, ctx, e
	}
	if e = checkMonitoringNodeLink(v, p, node, id, plan, proof, epoch); e != nil {
		return empty, ctx, e
	}
	j, e := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1 FOR UPDATE`, id))
	if e != nil {
		return empty, ctx, e
	}
	if j.Node != node || j.PlanDigest != plan {
		return empty, ctx, errMonitoringApplication
	}
	if p.Direction == "forward" && j.Status == "succeeded" || p.Direction == "rollback" && j.Status == "rolled_back" {
		return j, ctx, tx.Commit()
	}
	if p.Direction == "forward" && (j.Direction != "forward" || j.Status == "rolled_back") {
		return empty, ctx, ErrDeploymentState
	}
	if j.Status == "running" && j.LeaseUntil.Valid && j.LeaseUntil.Time.After(time.Now()) && epoch == p.Epoch {
		return empty, ctx, ErrDeploymentBusy
	}
	if p.Direction == "rollback" {
		if !j.RecoveryRequired && j.Step <= 2 {
			if e = checkDeploymentRuntimeTx(ctx, tx, j); e != nil {
				return empty, ctx, e
			}
			j.Status = "rolled_back"
			j.Direction = "rollback"
			j.RollbackStep = len(rollbackPhases)
			j.Epoch++
			_, e = tx.ExecContext(ctx, `UPDATE v3_deployment_jobs SET status='rolled_back',direction='rollback',rollback_step=$2,lease_epoch=$3,lease_owner=NULL,lease_until=NULL,recovery_required=false,error_code='',finished_at=clock_timestamp() WHERE id=$1`, j.ID, j.RollbackStep, j.Epoch)
			if e != nil {
				return empty, ctx, e
			}
			if e = deploymentLog(ctx, tx, &j, "verify-rollback", "rolled-back"); e != nil {
				return empty, ctx, e
			}
			return j, ctx, tx.Commit()
		}
		if !j.RecoveryRequired && j.Status != "succeeded" {
			return empty, ctx, ErrDeploymentState
		}
		j.RecoveryRequired = true
		if j.Direction != "rollback" {
			j.RollbackStep = 0
		}
		j.Direction = "rollback"
	}
	if e = checkDeploymentConfigurationTx(ctx, tx, j); e != nil {
		return empty, ctx, e
	}
	j.Epoch++
	j.Status = "running"
	j.Owner = sql.NullString{String: p.Owner.String, Valid: true}
	e = tx.QueryRowContext(ctx, `UPDATE v3_deployment_jobs SET status='running',lease_owner=$2,lease_epoch=$3,lease_until=clock_timestamp()+interval '30 seconds',error_code='',finished_at=NULL,direction=$4,rollback_step=$5,recovery_required=$6 WHERE id=$1 RETURNING lease_until`, j.ID, j.Owner.String, j.Epoch, j.Direction, j.RollbackStep, j.RecoveryRequired).Scan(&j.LeaseUntil)
	if e != nil {
		return empty, ctx, e
	}
	proof = monitoringNodeLinkProof(v, v.active, p, node, j.ID, j.PlanDigest, p.Epoch)
	_, e = tx.ExecContext(ctx, `UPDATE v3_monitoring_application_nodes SET parent_epoch=$3,proof=$4,state='running',error_code='',updated_at=clock_timestamp() WHERE application=$1 AND node=$2`, p.ID, node, p.Epoch, proof)
	if e != nil {
		return empty, ctx, e
	}
	if e = signMonitoringNodeStateTx(ctx, tx, v, p, node, "running", ""); e != nil {
		return empty, ctx, e
	}
	if e = deploymentLog(ctx, tx, &j, j.Phase(), "claimed"); e != nil {
		return empty, ctx, e
	}
	if e = tx.Commit(); e != nil {
		return empty, ctx, e
	}
	return j, monitoringNodeContext(ctx, v, p, node, j.ID), nil
}
func finishMonitoringNodeTx(ctx context.Context, tx *sql.Tx, v *Vault, p monitoringApplication, node string, workErr error) error {
	p, e := lockMonitoringParentTx(ctx, tx, v, p)
	if e != nil {
		return e
	}
	state := "failed"
	code := "monitoring-application-failed"
	var child sql.NullString
	if e = tx.QueryRowContext(ctx, `SELECT child FROM v3_monitoring_application_nodes WHERE application=$1 AND node=$2 FOR UPDATE`, p.ID, node).Scan(&child); e != nil {
		return e
	}
	if child.Valid {
		var actual string
		if e = tx.QueryRowContext(ctx, `SELECT status FROM v3_deployment_jobs WHERE id=$1`, child.String).Scan(&actual); e != nil {
			return e
		}
		if actual == "succeeded" || actual == "rolled_back" {
			state = actual
			code = ""
		}
	} else if workErr == nil {
		state = "succeeded"
		code = ""
		if p.Direction == "rollback" {
			state = "rolled_back"
		}
	}
	return signMonitoringNodeStateTx(ctx, tx, v, p, node, state, code)
}
func releaseMonitoringApplicationTx(ctx context.Context, tx *sql.Tx, v *Vault, p monitoringApplication) error {
	if _, e := monitoringApplicationWorkTx(ctx, tx, v, p, true); e != nil {
		return e
	}
	// Release only at a terminal checkpoint after every exact child outcome is
	// verified. Archives are retained throughout partial failures and recovery.
	rows, e := tx.QueryContext(ctx, `SELECT d.id,d.plan->>'before_configuration_backup' FROM v3_monitoring_application_nodes n JOIN v3_deployment_jobs d ON d.id=n.child WHERE n.application=$1 AND d.status NOT IN ('succeeded','rolled_back')`, p.ID)
	if e != nil {
		return e
	}
	unfinished := rows.Next()
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if unfinished {
		return ErrDeploymentBusy
	}
	_, e = tx.ExecContext(ctx, `DELETE FROM v3_configuration_backup_pins pin USING v3_monitoring_application_nodes n JOIN v3_deployment_jobs d ON d.id=n.child WHERE n.application=$1 AND pin.backup=d.plan->>'before_configuration_backup' AND pin.reference='job:'||d.id AND pin.kind IN ('deployment','rollback')`, p.ID)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE v3_monitoring_application_nodes SET reserved=false WHERE application=$1`, p.ID)
	return e
}

var _ = common.JSON

func lockMonitoringWriteTx(ctx context.Context, tx *sql.Tx) error {
	if e := lockConfigurationOperationTx(ctx, tx, true); e != nil {
		return e
	}
	if e := advanceConfigurationOperationTx(ctx, tx); e != nil {
		return e
	}
	return lockDeploymentWriteRelationsTx(ctx, tx)
}

type monitoringNodeCheckpoint struct {
	node, state, child, plan, proof, stateProof string
	ordinal, batch                              int
	epoch, stateEpoch                           int64
	reserved                                    bool
}

func readMonitoringNodeCheckpointTx(ctx context.Context, tx *sql.Tx, p monitoringApplication, node string) (monitoringNodeCheckpoint, error) {
	var l monitoringNodeCheckpoint
	e := tx.QueryRowContext(ctx, `SELECT node,ordinal,batch_index,reserved,state,coalesce(child,''),child_plan_digest,parent_epoch,proof,state_proof,state_epoch FROM v3_monitoring_application_nodes WHERE application=$1 AND node=$2 FOR UPDATE`, p.ID, node).Scan(&l.node, &l.ordinal, &l.batch, &l.reserved, &l.state, &l.child, &l.plan, &l.epoch, &l.proof, &l.stateProof, &l.stateEpoch)
	return l, e
}
func monitoringStateProof(v *Vault, key string, p monitoringApplication, l monitoringNodeCheckpoint) string {
	return monitoringApplicationMAC(v, key, "node-state/v1", []any{p.ID, p.Digest, l.node, l.ordinal, l.batch, l.state, l.child, l.plan, l.epoch, l.stateEpoch})
}
func verifyMonitoringNodeCheckpoint(v *Vault, p monitoringApplication, l monitoringNodeCheckpoint) error {
	if !l.reserved {
		return errMonitoringApplication
	}
	if l.stateProof == "" {
		if l.state != "pending" || l.child != "" || l.plan != "" || l.proof != "" || l.epoch != 0 || l.stateEpoch != 0 {
			return errMonitoringApplication
		}
		return nil
	}
	key, _, ok := strings.Cut(l.stateProof, ":")
	want := monitoringStateProof(v, key, p, l)
	if !ok || want == "" || !hmac.Equal([]byte(want), []byte(l.stateProof)) || l.stateEpoch < 1 || l.stateEpoch > p.Epoch {
		return errMonitoringApplication
	}
	if l.child == "" {
		if l.plan != "" || l.proof != "" || l.epoch != 0 {
			return errMonitoringApplication
		}
		return nil
	}
	return checkMonitoringNodeLink(v, p, l.node, l.child, l.plan, l.proof, l.epoch)
}
func signMonitoringNodeStateTx(ctx context.Context, tx *sql.Tx, v *Vault, p monitoringApplication, node, state, code string) error {
	l, e := readMonitoringNodeCheckpointTx(ctx, tx, p, node)
	if e != nil {
		return e
	}
	l.state = state
	l.stateEpoch = p.Epoch
	proof := monitoringStateProof(v, v.active, p, l)
	if proof == "" {
		return errMonitoringApplication
	}
	_, e = tx.ExecContext(ctx, `UPDATE v3_monitoring_application_nodes SET state=$3,error_code=$4,state_proof=$5,state_epoch=$6,updated_at=clock_timestamp() WHERE application=$1 AND node=$2`, p.ID, node, state, code, proof, l.stateEpoch)
	return e
}
func monitoringNodeRuntimeMatchesTx(ctx context.Context, tx *sql.Tx, node string, version int64, config []byte) error {
	active, e := scanActiveNode(tx.QueryRowContext(ctx, `SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE id=$1`, node))
	if e != nil {
		return e
	}
	if active.Version != version || !active.Enabled || !configurationJSONEqual(active.Config, config) {
		return ErrConflict
	}
	return nil
}

// Every immutable target must have a present, reserved and authenticated
// checkpoint. Mutable state strings never constitute completion evidence.
func monitoringApplicationWorkTx(ctx context.Context, tx *sql.Tx, v *Vault, p monitoringApplication, terminal bool) ([]monitoringNodeWork, error) {
	var count int
	if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_monitoring_application_nodes WHERE application=$1`, p.ID).Scan(&count); e != nil {
		return nil, e
	}
	if count != len(p.Plan.Nodes) {
		return nil, errMonitoringApplication
	}
	out := []monitoringNodeWork{}
	for ordinal, item := range p.Plan.Nodes {
		l, e := readMonitoringNodeCheckpointTx(ctx, tx, p, item.Node.ID)
		if e != nil {
			return nil, e
		}
		if l.ordinal != ordinal || l.batch != ordinal/20 {
			return nil, errMonitoringApplication
		}
		if e = verifyMonitoringNodeCheckpoint(v, p, l); e != nil {
			return nil, e
		}
		n, e := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR SHARE`, l.node))
		if e != nil {
			return nil, e
		}
		before := n.Version == item.Node.Version && configurationJSONEqual(n.Config, item.Before)
		target := n.Version == item.Node.Version+1 && configurationJSONEqual(n.Config, item.Target)
		if !n.Enabled || n.Endpoint != item.Node.Endpoint || n.Mode != item.Node.Mode || n.ServerName != item.Node.ServerName || !before && !target {
			return nil, ErrConflict
		}
		complete := false
		if l.child == "" {
			if l.stateProof == "" && !before {
				return nil, errMonitoringApplication
			}
			if l.state == "succeeded" {
				if !configurationJSONEqual(item.Before, item.Target) || !before || n.AppliedVersion != item.Node.AppliedVersion {
					return nil, errMonitoringApplication
				}
				if e = monitoringNodeRuntimeMatchesTx(ctx, tx, l.node, item.Node.Version, item.Before); e != nil {
					return nil, e
				}
				complete = p.Direction == "forward"
			} else if l.state == "rolled_back" {
				if n.AppliedVersion != item.Node.AppliedVersion {
					return nil, errMonitoringApplication
				}
				if e = monitoringNodeRuntimeMatchesTx(ctx, tx, l.node, item.Node.Version, item.Before); e != nil {
					return nil, e
				}
				complete = p.Direction == "rollback"
			}
		} else {
			j, e := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1 FOR SHARE`, l.child))
			if e != nil {
				return nil, e
			}
			if j.Node != l.node || j.PlanDigest != l.plan || j.Kind != "upgrade" || j.NodeVersion != item.Node.Version+1 || j.Plan.ConfigDigest != item.TargetDigest || j.Plan.Request.Credential != item.Credential || j.Plan.Request.ManifestSHA256 != p.Manifest || j.Plan.Request.Release != p.Release {
				return nil, errMonitoringApplication
			}
			if l.state == "succeeded" || l.state == "rolled_back" {
				if j.Status != l.state || j.RecoveryRequired {
					return nil, errMonitoringApplication
				}
				if l.state == "succeeded" {
					if j.Direction != "forward" || !target || n.AppliedVersion != j.NodeVersion {
						return nil, errMonitoringApplication
					}
					if e = monitoringNodeRuntimeMatchesTx(ctx, tx, l.node, j.NodeVersion, item.Target); e != nil {
						return nil, e
					}
					complete = p.Direction == "forward"
				} else {
					if j.Direction != "rollback" || n.AppliedVersion != item.Node.AppliedVersion {
						return nil, errMonitoringApplication
					}
					if e = monitoringNodeRuntimeMatchesTx(ctx, tx, l.node, item.Node.Version, item.Before); e != nil {
						return nil, e
					}
					complete = p.Direction == "rollback"
				}
			}
		}
		if terminal {
			if !complete {
				return nil, errMonitoringApplication
			}
			continue
		}
		if p.Selected != "" && p.Selected != l.node {
			continue
		}
		if !complete {
			out = append(out, monitoringNodeWork{l.node, l.state, l.child, l.batch})
		}
	}
	if p.Direction == "rollback" {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out, nil
}
