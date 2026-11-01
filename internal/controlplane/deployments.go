package controlplane

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
	"webscan/internal/nodeconfig"
	"webscan/internal/nodeops"
)

var ErrDeploymentBusy = errors.New("该节点存在未完成部署，请先继续或回退原任务")
var ErrDeploymentState = errors.New("部署状态已变化，请刷新任务")
var releaseVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?$`)

var deploymentPhases = []string{"preflight", "stage", "backup", "activate", "verify", "finalize"}
var rollbackPhases = []string{"restore", "verify-rollback"}

// Only typed, bounded public status codes may enter logs. SSH command output,
// remote errors and agent configuration are never copied into this channel.
var deploymentCodes = map[string]bool{
	"queued": true, "claimed": true, "takeover": true, "phase-complete": true,
	"resumed": true, "rollback-requested": true, "succeeded": true, "rolled-back": true,
	"preflight-failed": true, "artifact-invalid": true, "backup-failed": true,
	"activation-failed": true, "verification-failed": true, "remote-unavailable": true,
	"remote-conflict": true, "remote-state-unknown": true, "interrupted": true,
	"recovery-protected": true, "configuration-conflict": true, "executor-unavailable": true,
}

type DeploymentRequest struct {
	Node            string           `json:"node"`
	Kind            string           `json:"kind"`
	Expected        int64            `json:"expected_version"`
	Credential      string           `json:"credential"`
	Release         string           `json:"release"`
	SHA256          string           `json:"sha256"`
	ManifestSHA256  string           `json:"manifest_sha256,omitempty"`
	RuntimeArtifact *ReleaseArtifact `json:"runtime_artifact,omitempty"`
}

func (in DeploymentRequest) validate() error {
	sha, err := hex.DecodeString(in.SHA256)
	if !identifier.MatchString(in.Node) || in.Expected < 1 || !identifier.MatchString(in.Credential) || (in.Kind != "install" && in.Kind != "upgrade" && in.Kind != "uninstall") || !releaseVersion.MatchString(in.Release) || len(in.Release) > 128 || err != nil || len(sha) != 32 || hex.EncodeToString(sha) != in.SHA256 {
		return errors.New("节点、部署类型、配置版本、凭据或目标版本校验值不正确")
	}
	if in.ManifestSHA256 != "" && !releaseDigest(in.ManifestSHA256) {
		return errors.New("发布清单校验值不正确")
	}
	if a := in.RuntimeArtifact; a != nil {
		if !releaseDigest(a.SHA256) || a.Bytes < 1 || a.Bytes > nodeconfig.MaxBytes || in.ManifestSHA256 == "" {
			return errors.New("节点运行配置包校验值不正确")
		}
	}
	return nil
}

// DeploymentPlan is immutable. No request can supply shell commands, arbitrary
// artifact paths or secret values. The SSH runtime requires a signature-verified
// release manifest bound to this plan, including helper and target checksums.
type DeploymentPlan struct {
	Request             DeploymentRequest           `json:"request"`
	Node                Node                        `json:"node"`
	ConfigDigest        string                      `json:"config_digest"`
	BeforeBackup        string                      `json:"before_configuration_backup,omitempty"`
	PreviousRuntime     *deploymentRuntimeBaseline  `json:"previous_runtime,omitempty"`
	TargetRuntime       string                      `json:"target_runtime,omitempty"`
	TargetRuntimeDigest string                      `json:"target_runtime_digest,omitempty"`
	Recovery            *deploymentRecoveryPlan     `json:"recovery,omitempty"`
	Uninstall           *deploymentUninstallPlan    `json:"uninstall,omitempty"`
	Reinstall           *nodeops.ReinstallReference `json:"reinstall,omitempty"`
	PreviousLifecycle   *deploymentLifecycleState   `json:"previous_lifecycle,omitempty"`
}
type DeploymentJob struct {
	ID               string         `json:"id"`
	Node             string         `json:"node"`
	Username         string         `json:"username"`
	Kind             string         `json:"kind"`
	Status           string         `json:"status"`
	Direction        string         `json:"direction"`
	NodeVersion      int64          `json:"node_version"`
	PlanDigest       string         `json:"plan_digest"`
	Step             int            `json:"step"`
	RollbackStep     int            `json:"rollback_step"`
	Owner            sql.NullString `json:"-"`
	Epoch            int64          `json:"-"`
	LeaseUntil       sql.NullTime   `json:"-"`
	RecoveryRequired bool           `json:"recovery_required"`
	ErrorCode        string         `json:"error_code"`
	LogCursor        int64          `json:"log_cursor"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	FinishedAt       *time.Time     `json:"finished_at"`
	Plan             DeploymentPlan `json:"-"`
}

func (j DeploymentJob) Phase() string {
	if j.Direction == "rollback" {
		if j.RollbackStep < len(rollbackPhases) {
			return rollbackPhases[j.RollbackStep]
		}
		return "complete"
	}
	if j.Step < len(deploymentPhases) {
		return deploymentPhases[j.Step]
	}
	return "complete"
}
func (j DeploymentJob) CanRecover() bool {
	return j.RecoveryRequired && (j.Status == "failed" || j.Status == "interrupted")
}

const deploymentColumns = `id,node,username,kind,status,direction,node_version,plan_digest,step,rollback_step,lease_owner,lease_epoch,lease_until,recovery_required,error_code,log_cursor,created_at,updated_at,finished_at,plan`

func scanDeployment(row interface{ Scan(...any) error }) (j DeploymentJob, err error) {
	var raw []byte
	err = row.Scan(&j.ID, &j.Node, &j.Username, &j.Kind, &j.Status, &j.Direction, &j.NodeVersion, &j.PlanDigest, &j.Step, &j.RollbackStep, &j.Owner, &j.Epoch, &j.LeaseUntil, &j.RecoveryRequired, &j.ErrorCode, &j.LogCursor, &j.CreatedAt, &j.UpdatedAt, &j.FinishedAt, &raw)
	if err == nil {
		err = json.Unmarshal(raw, &j.Plan)
		if err == nil && digest(raw) != j.PlanDigest {
			err = errors.New("部署计划校验失败")
		}
		// Older v3 journals retained the historical switch-protection bit on
		// success. A terminal job no longer owns live recovery responsibility.
		if j.Status == "succeeded" || j.Status == "rolled_back" {
			j.RecoveryRequired = false
		}
	}
	return
}
func deploymentLog(ctx context.Context, tx *sql.Tx, j *DeploymentJob, phase, code string) error {
	if !deploymentCodes[code] {
		return errors.New("部署日志状态代码不正确")
	}
	j.LogCursor++
	if _, err := tx.ExecContext(ctx, "UPDATE v3_deployment_jobs SET log_cursor=$2,updated_at=clock_timestamp() WHERE id=$1", j.ID, j.LogCursor); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO v3_deployment_logs(job,cursor,epoch,phase,code) VALUES($1,$2,$3,$4,$5)", j.ID, j.LogCursor, j.Epoch, phase, code)
	return err
}

func (s *Store) CreateDeployment(ctx context.Context, user, key string, in DeploymentRequest) (json.RawMessage, error) {
	return s.createDeployment(ctx, user, key, in, nil)
}

func (s *Store) createDeployment(ctx context.Context, user, key string, in DeploymentRequest, guard func(*sql.Tx, Node) error) (json.RawMessage, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	return s.guardedMutation(ctx, user, key, "create-deployment", in.Node, in, func(tx *sql.Tx) error {
		return lockDeploymentWriteRelationsTx(ctx, tx)
	}, func(tx *sql.Tx) (any, error) {
		return insertDeployment(ctx, tx, user, in, guard)
	})
}

// Shared by trusted local queueing and account-bound preview confirmation.
// The caller owns the transaction containing the receipt, preview and audit.
func insertDeployment(ctx context.Context, tx *sql.Tx, user string, in DeploymentRequest, guard func(*sql.Tx, Node) error) (any, error) {
	return insertDeploymentWithBackup(ctx, tx, user, in, guard, nil)
}

func insertDeploymentWithBackup(ctx context.Context, tx *sql.Tx, user string, in DeploymentRequest, guard func(*sql.Tx, Node) error, before *deploymentConfigurationBackup) (any, error) {
	n, err := scanNode(tx.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR UPDATE", in.Node))
	if err == sql.ErrNoRows {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	if err = checkMonitoringNodeReservationTx(ctx, tx, n.ID); err != nil {
		return nil, err
	}
	if in.Kind == "uninstall" {
		if before == nil || before.vault == nil {
			return nil, errNodeUninstall
		}
		return insertUninstallDeploymentTx(ctx, tx, user, in, n, guard, before)
	}
	if !n.Enabled || n.Version != in.Expected || in.Kind == "upgrade" && n.AppliedVersion == 0 || in.Kind == "install" && n.AppliedVersion != 0 {
		return nil, ErrConflict
	}
	if guard != nil {
		if err := guard(tx, n); err != nil {
			return nil, err
		}
	}
	var busy, credential bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND status NOT IN ('succeeded','rolled_back') AND (status IN ('queued','running') OR recovery_required)) OR EXISTS(SELECT 1 FROM v3_node_identity_recoveries WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_changes WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_prunings WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp())", in.Node).Scan(&busy); err != nil {
		return nil, err
	}
	if busy {
		return nil, ErrDeploymentBusy
	}
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_credentials WHERE id=$1 AND node=$2)", in.Credential, in.Node).Scan(&credential); err != nil {
		return nil, err
	}
	if !credential {
		return nil, ErrCredentialUnavailable
	}
	plan := DeploymentPlan{Request: in, Node: n, ConfigDigest: digest(n.Config)}
	if before != nil && before.vault != nil {
		plan.PreviousLifecycle, err = readNodeLifecycleTx(ctx, tx, before.vault, n.ID)
		if err != nil {
			return nil, err
		}
		if prior := plan.PreviousLifecycle; prior != nil && prior.State == "uninstalled" {
			if in.Kind != "install" {
				return nil, errNodeUninstall
			}
			old, removal, e := authenticatedUninstalledTx(ctx, tx, before.vault, n, prior)
			if e != nil {
				return nil, e
			}
			plan.Reinstall = &nodeops.ReinstallReference{SourceJob: old.ID, SourcePlanDigest: old.PlanDigest, TombstoneSHA256: removal.TombstoneSHA256}
		}
	}
	plan.PreviousRuntime, err = runtimeBaselineTx(ctx, tx, n.ID)
	if err != nil {
		return nil, err
	}
	plan.TargetRuntime, err = captureSavedNodeTx(ctx, tx, n.ID)
	if err != nil {
		return nil, err
	}
	var targetJSON []byte
	if err = tx.QueryRowContext(ctx, `SELECT to_jsonb(c) FROM v3_node_configurations c WHERE id=$1`, plan.TargetRuntime).Scan(&targetJSON); err != nil {
		return nil, err
	}
	plan.TargetRuntimeDigest = digest(targetJSON)
	if plan.BeforeBackup, err = before.archive(ctx, tx, user); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	// PostgreSQL jsonb normalizes object order and whitespace. Digest the
	// same canonical representation that later reads return.
	var canonical []byte
	if err = tx.QueryRowContext(ctx, "SELECT $1::jsonb", raw).Scan(&canonical); err != nil {
		return nil, err
	}
	j := DeploymentJob{ID: token(), Node: n.ID, Username: user, Kind: in.Kind, NodeVersion: n.Version, Status: "queued", Direction: "forward", PlanDigest: digest(canonical), Plan: plan}
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_deployment_jobs(id,node,username,kind,node_version,credential,plan,plan_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", j.ID, n.ID, user, in.Kind, n.Version, in.Credential, canonical, j.PlanDigest); err != nil {
		return nil, err
	}
	if before != nil && before.vault != nil {
		if err = recordLifecycleAuthorizationTx(ctx, tx, before.vault, j); err != nil {
			return nil, err
		}
	}
	if err = deploymentLog(ctx, tx, &j, "preflight", "queued"); err != nil {
		return nil, err
	}
	if err = pinDeploymentConfigurationTx(ctx, tx, user, j); err != nil {
		return nil, err
	}
	return map[string]any{"id": j.ID, "node": n.ID, "status": "queued", "message": "已创建部署任务，等待环境检查"}, nil
}
func (s *Store) Deployment(ctx context.Context, id string) (DeploymentJob, error) {
	return scanDeployment(s.DB.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM v3_deployment_jobs WHERE id=$1", id))
}
func (s *Store) Deployments(ctx context.Context, before time.Time, beforeID, node string, limit int) ([]DeploymentJob, error) {
	if limit < 1 || limit > 200 {
		return nil, errors.New("每页数量须为 1～200")
	}
	if before.IsZero() {
		before = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		beforeID = ""
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+deploymentColumns+" FROM v3_deployment_jobs WHERE (created_at,id)<($1,$2) AND ($3='' OR node=$3) ORDER BY created_at DESC,id DESC LIMIT $4", before, beforeID, node, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeploymentJob{}
	for rows.Next() {
		j, err := scanDeployment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

type DeploymentLog struct {
	Cursor    int64     `json:"cursor"`
	Phase     string    `json:"phase"`
	Code      string    `json:"code"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) DeploymentLogs(ctx context.Context, id string, after int64, limit int) ([]DeploymentLog, error) {
	if after < 0 || limit < 1 || limit > 200 {
		return nil, errors.New("日志游标或数量不正确")
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT cursor,phase,code,created_at FROM v3_deployment_logs WHERE job=$1 AND cursor>$2 ORDER BY cursor LIMIT $3", id, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeploymentLog{}
	for rows.Next() {
		var v DeploymentLog
		if err = rows.Scan(&v.Cursor, &v.Phase, &v.Code, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) ClaimDeployment(ctx context.Context, owner string) (DeploymentJob, error) {
	if !identifier.MatchString(owner) {
		return DeploymentJob{}, errors.New("执行器身份不正确")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return DeploymentJob{}, err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return DeploymentJob{}, err
	} else if held {
		return DeploymentJob{}, ErrMigrationPending
	}
	if err = lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		if errors.Is(err, errConfigurationApplicationBusy) {
			return DeploymentJob{}, sql.ErrNoRows
		}
		return DeploymentJob{}, err
	}
	j, err := scanDeployment(tx.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM v3_deployment_jobs d WHERE (status='queued' OR (status='running' AND lease_until<=clock_timestamp())) AND NOT EXISTS(SELECT 1 FROM v3_configuration_application_nodes l WHERE l.child=d.id) AND NOT EXISTS(SELECT 1 FROM v3_monitoring_application_nodes l WHERE l.child=d.id) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1"))
	if err != nil {
		return j, err
	}
	if err = checkDeploymentConfigurationTx(ctx, tx, j); err != nil {
		return j, err
	}
	code := "claimed"
	if j.Epoch > 0 {
		code = "takeover"
	}
	j.Epoch++
	j.Status = "running"
	j.Owner = sql.NullString{String: owner, Valid: true}
	if err = tx.QueryRowContext(ctx, "UPDATE v3_deployment_jobs SET status='running',lease_owner=$2,lease_epoch=$3,lease_until=clock_timestamp()+interval '30 seconds',error_code='' WHERE id=$1 RETURNING lease_until", j.ID, owner, j.Epoch).Scan(&j.LeaseUntil); err != nil {
		return j, err
	}
	if err = deploymentLog(ctx, tx, &j, j.Phase(), code); err != nil {
		return j, err
	}
	return j, tx.Commit()
}
func (s *Store) RenewDeployment(ctx context.Context, j DeploymentJob) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockDeploymentJournalTx(ctx, tx, j); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, "UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()+interval '30 seconds' WHERE id=$1 AND status='running' AND lease_owner=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp()", j.ID, j.Owner.String, j.Epoch)
	if err = deploymentAffected(res, err); err != nil {
		return err
	}
	return tx.Commit()
}
func deploymentAffected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrLeaseLost
	}
	return nil
}
func lockedDeployment(ctx context.Context, tx *sql.Tx, j DeploymentJob) (DeploymentJob, error) {
	current, err := scanDeployment(tx.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM v3_deployment_jobs WHERE id=$1 AND status='running' AND lease_owner=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp() FOR UPDATE", j.ID, j.Owner.String, j.Epoch))
	if err == sql.ErrNoRows {
		return current, ErrLeaseLost
	}
	if err == nil && (current.Step != j.Step || current.RollbackStep != j.RollbackStep || current.Direction != j.Direction) {
		return current, ErrDeploymentState
	}
	return current, err
}

// CompleteDeploymentPhase commits only after a runtime adapter has verified a
// remote checkpoint bound to the job, plan, phase and epoch. It never restores
// an old database snapshot or deletes newly created agent events.
func (s *Store) CompleteDeploymentPhase(ctx context.Context, j DeploymentJob) error {
	return s.completeDeploymentPhase(ctx, j, nil, nil)
}

func (s *Store) completeDeploymentPhase(ctx context.Context, j DeploymentJob, vault *Vault, proof *RemoteDeploymentCheckpoint) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return err
	} else if held {
		return ErrMigrationPending
	}
	if err = lockDeploymentJournalTx(ctx, tx, j); err != nil {
		return err
	}
	current, err := lockedDeployment(ctx, tx, j)
	if err != nil {
		return err
	}
	phase := current.Phase()
	if current.Kind == "recover" || current.Plan.Recovery != nil {
		if proof == nil || !proof.matches(current) || proof.State != "complete" {
			return errDeploymentRecovery
		}
		if _, err = readDeploymentRecoveryTx(ctx, tx, vault, current, map[string]bool{}); err != nil {
			return err
		}
	}
	if phase == "complete" || (current.Direction == "rollback" || current.Step >= 2) && !current.RecoveryRequired {
		return ErrDeploymentState
	}
	if current.Kind != "uninstall" && current.Direction == "forward" && (phase == "verify" || phase == "finalize") {
		if err = s.deploymentReady(ctx, tx, current); err != nil {
			return err
		}
	}
	// Inserting proof takes an FK lock on the node. Acquire the collector
	// lease first, just as readiness/collection do, before taking that lock.
	if current.Kind != "uninstall" && proof != nil && (proof.Removal != nil || proof.Restoration != nil) {
		return errNodeUninstall
	}
	if proof != nil && (proof.Installation != nil || proof.Spec != nil) {
		if err = recordDeploymentInstallationTx(ctx, tx, vault, current, *proof); err != nil {
			if errors.Is(err, errDeploymentInstallation) {
				return DeploymentFailure{"verification-failed"}
			}
			return err
		}
	}
	// Verification must acquire the collector lease before any runtime node
	// locks, matching FenceNode even while a lease renewal is queued.
	if err = checkDeploymentRuntimeTx(ctx, tx, current); err != nil {
		return err
	}
	if err = s.deploymentRuntimePhaseTx(ctx, tx, current, phase); err != nil {
		return err
	}
	if current.Kind == "uninstall" {
		if err = recordUninstallCompletionTx(ctx, tx, vault, current, proof); err != nil {
			return err
		}
	}
	if current.Kind != "uninstall" {
		if err = recordInstalledLifecycleTx(ctx, tx, vault, current, proof, phase); err != nil {
			return err
		}
	}
	code := "phase-complete"
	if current.Direction == "forward" {
		current.Step++
		if current.Step == len(deploymentPhases) {
			current.Status = "succeeded"
			code = "succeeded"
			res, err := tx.ExecContext(ctx, "UPDATE v3_nodes SET applied_version=CASE WHEN $3='uninstall' THEN 0 ELSE $2 END WHERE id=$1 AND version=$2", current.Node, current.NodeVersion, current.Kind)
			if err != nil {
				return err
			}
			count, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if count != 1 {
				return ErrConflict
			}
		}
	} else {
		current.RollbackStep++
		if current.RollbackStep == len(rollbackPhases) {
			current.Status = "rolled_back"
			code = "rolled-back"
			if current.Plan.PreviousRuntime != nil {
				applied := current.Plan.Node.AppliedVersion
				if current.Plan.Recovery != nil {
					applied = current.Plan.Recovery.RestoreAppliedVersion
				}
				res, err := tx.ExecContext(ctx, `UPDATE v3_nodes SET applied_version=$2 WHERE id=$1 AND version=$3`, current.Node, applied, current.NodeVersion)
				if err != nil {
					return err
				}
				count, err := res.RowsAffected()
				if err != nil {
					return err
				}
				if count != 1 {
					return ErrConflict
				}
			}
		}
	}
	res, err := tx.ExecContext(ctx, `UPDATE v3_deployment_jobs SET step=$2,rollback_step=$3,status=$4,error_code='',recovery_required=CASE WHEN $4 IN ('succeeded','rolled_back') THEN false ELSE recovery_required END,finished_at=CASE WHEN $4 IN ('succeeded','rolled_back') THEN clock_timestamp() ELSE NULL END,lease_until=CASE WHEN $4 IN ('succeeded','rolled_back') THEN NULL ELSE lease_until END WHERE id=$1 AND lease_owner=$5 AND lease_epoch=$6 AND lease_until>clock_timestamp()`, current.ID, current.Step, current.RollbackStep, current.Status, current.Owner.String, current.Epoch)
	if err = deploymentAffected(res, err); err != nil {
		return err
	}
	if err = deploymentLog(ctx, tx, &current, phase, code); err != nil {
		return err
	}
	if current.Status == "succeeded" || current.Status == "rolled_back" {
		if err = releaseDeploymentConfigurationTx(ctx, tx, current); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) FailDeployment(ctx context.Context, j DeploymentJob, code string) error {
	if !deploymentCodes[code] || code == "queued" || code == "claimed" || code == "takeover" || code == "phase-complete" || code == "recovery-protected" || code == "resumed" || code == "rollback-requested" || code == "succeeded" || code == "rolled-back" {
		return errors.New("部署失败代码不正确")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockDeploymentJournalTx(ctx, tx, j); err != nil {
		return err
	}
	current, err := lockedDeployment(ctx, tx, j)
	if err != nil {
		return err
	}
	status := "failed"
	if code == "interrupted" {
		status = "interrupted"
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_deployment_jobs SET status=$2,error_code=$3,lease_until=NULL,finished_at=CASE WHEN recovery_required THEN NULL ELSE clock_timestamp() END WHERE id=$1", j.ID, status, code); err != nil {
		return err
	}
	if err = deploymentLog(ctx, tx, &current, current.Phase(), code); err != nil {
		return err
	}
	if !current.RecoveryRequired {
		if err = releaseDeploymentConfigurationTx(ctx, tx, current); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) RecoverDeployment(ctx context.Context, user, key, id, direction, planDigest string, logCursor int64) (json.RawMessage, error) {
	return s.recoverDeployment(ctx, user, key, id, direction, planDigest, logCursor, false)
}

func (s *Store) recoverDeployment(ctx context.Context, user, key, id, direction, planDigest string, logCursor int64, admin bool) (json.RawMessage, error) {
	return s.recoverDeploymentWithTrust(ctx, user, key, id, direction, planDigest, logCursor, admin, nil)
}

func (s *Store) recoverDeploymentWithTrust(ctx context.Context, user, key, id, direction, planDigest string, logCursor int64, admin bool, vault *Vault) (json.RawMessage, error) {
	if !identifier.MatchString(id) || direction != "forward" && direction != "rollback" || len(planDigest) != 64 || logCursor < 1 {
		return nil, ErrDeploymentState
	}
	input := struct {
		ID, Direction, Digest string
		Cursor                int64
	}{id, direction, planDigest, logCursor}
	return s.guardedMutation(ctx, user, key, "recover-deployment", id, input, func(tx *sql.Tx) error {
		if admin {
			if err := provisioningAdmin(ctx, tx, user); err != nil {
				return err
			}
		}
		return lockDeploymentJournalTx(ctx, tx, DeploymentJob{ID: id})
	}, func(tx *sql.Tx) (any, error) {
		j, err := scanDeployment(tx.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM v3_deployment_jobs WHERE id=$1 FOR UPDATE", id))
		if err == sql.ErrNoRows {
			return nil, ErrDeploymentState
		}
		if err != nil {
			return nil, err
		}
		terminalUninstall := admin && direction == "rollback" && j.Kind == "uninstall" && j.Status == "succeeded"
		if (!j.CanRecover() && !terminalUninstall) || j.PlanDigest != planDigest || j.LogCursor != logCursor || j.Direction == "rollback" && direction != "rollback" {
			return nil, ErrDeploymentState
		}
		if terminalUninstall {
			if err = authorizeCompletedUninstallRollbackTx(ctx, tx, vault, j, true); err != nil {
				return nil, err
			}
			j.RecoveryRequired = true
		}
		if err = checkDeploymentConfigurationTx(ctx, tx, j); err != nil {
			return nil, err
		}
		j.Direction = direction
		code := "resumed"
		if direction == "rollback" {
			code = "rollback-requested"
		}
		if _, err = tx.ExecContext(ctx, "UPDATE v3_deployment_jobs SET status='queued',direction=$2,error_code='',lease_owner=NULL,lease_until=NULL,recovery_required=true,finished_at=NULL WHERE id=$1", id, direction); err != nil {
			return nil, err
		}
		if err = deploymentLog(ctx, tx, &j, j.Phase(), code); err != nil {
			return nil, err
		}
		return map[string]any{"id": id, "status": "queued", "direction": direction}, nil
	})
}

// ArmDeploymentRecovery runs before any phase that can stop or change the old
// service. If the process dies between arming and the action, recovery remains
// conservatively required. Preflight/staging failures can be retried as new jobs.
func (s *Store) ArmDeploymentRecovery(ctx context.Context, j DeploymentJob) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockDeploymentJournalTx(ctx, tx, j); err != nil {
		return err
	}
	current, err := lockedDeployment(ctx, tx, j)
	if err != nil {
		return err
	}
	if current.RecoveryRequired {
		if err = checkDeploymentConfigurationTx(ctx, tx, current); err != nil {
			return err
		}
		return tx.Commit()
	}
	if current.Direction != "forward" || current.Step != 2 {
		return ErrDeploymentState
	}
	if err = armDeploymentConfigurationTx(ctx, tx, current); err != nil {
		return err
	}
	if current.Kind == "uninstall" {
		if err = pauseUninstallRuntimeTx(ctx, tx, current); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_deployment_jobs SET recovery_required=true WHERE id=$1", j.ID); err != nil {
		return err
	}
	if err = deploymentLog(ctx, tx, &current, current.Phase(), "recovery-protected"); err != nil {
		return err
	}
	return tx.Commit()
}
