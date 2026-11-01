package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"webscan/internal/nodeops"
)

// RemoteDeploymentCheckpoint is evidence from the node, not an assumption made
// from a local task log. Unknown requires operator recovery, never blind replay.
type RemoteDeploymentCheckpoint struct {
	Job          string
	PlanDigest   string
	Phase        string
	Epoch        int64
	State        string                        // absent, complete, unknown
	Spec         *nodeops.Spec                 `json:"-"`
	Installation *nodeops.InstallationEvidence `json:"-"`
	Removal      *nodeops.RemovalEvidence      `json:"-"`
	Restoration  *nodeops.RestorationEvidence  `json:"-"`
}

func (p RemoteDeploymentCheckpoint) matches(j DeploymentJob) bool {
	return p.Job == j.ID && p.PlanDigest == j.PlanDigest && p.Phase == j.Phase() && p.Epoch == j.Epoch
}

// DeploymentRuntime must persist and fence the epoch on the remote host before
// returning Inspect. The host operation lock must outlive an SSH disconnect:
// advancing an epoch cannot run concurrently with the previous operation.
// Apply must be idempotent for (job, plan, phase), produce a verified remote
// receipt, and preserve live databases/events during restore. No legacy CLI
// adapter is supplied: its local JSON journal cannot meet this contract.
type DeploymentRuntime interface {
	Inspect(context.Context, DeploymentJob) (RemoteDeploymentCheckpoint, error)
	Apply(context.Context, DeploymentJob) (RemoteDeploymentCheckpoint, error)
}

// Partial runtimes must declare their boundary before recovery protection is
// armed. An unsupported phase has performed no operation requiring rollback.
type DeploymentPhaseSupport interface {
	SupportsDeploymentPhase(string) bool
}

type DeploymentFailure struct{ Code string }

func (e DeploymentFailure) Error() string {
	return "节点部署阶段失败（" + safeDeploymentFailure(e.Code) + "）"
}
func safeDeploymentFailure(code string) string {
	switch code {
	case "preflight-failed", "artifact-invalid", "backup-failed", "activation-failed", "verification-failed", "remote-unavailable", "remote-conflict", "remote-state-unknown", "configuration-conflict", "executor-unavailable":
		return code
	default:
		return "remote-unavailable"
	}
}
func deploymentFailureCode(err error) string {
	if errors.Is(err, errDeploymentConfigurationBackup) {
		return "backup-failed"
	}
	var e DeploymentFailure
	if errors.As(err, &e) {
		return safeDeploymentFailure(e.Code)
	}
	return "remote-unavailable"
}

type DeploymentRunner struct {
	Store       *Store
	Instance    string
	Concurrency int
	Runtime     DeploymentRuntime
	Vault       *Vault
	Manifest    string
}

func (w *DeploymentRunner) Run(ctx context.Context) error {
	if w.Store == nil || w.Runtime == nil || !identifier.MatchString(w.Instance) {
		return errors.New("部署执行器配置不完整，未启动")
	}
	concurrency := w.Concurrency
	if concurrency == 0 {
		concurrency = 4
	}
	if concurrency < 1 || concurrency > 32 {
		return errors.New("部署并发须为 1～32")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	active := make(chan struct{}, concurrency)
	defer wg.Wait()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		reason := ""
		for len(active) < concurrency {
			op, stop := context.WithTimeout(ctx, 5*time.Second)
			job, err := w.Store.ClaimDeployment(op, w.Instance)
			stop()
			if err == sql.ErrNoRows {
				break
			}
			if err != nil {
				reason = "部署任务读取失败，请检查数据库"
				if errors.Is(err, ErrMigrationPending) {
					reason = "数据迁移尚未完成，部署任务已暂停"
				}
				break
			}
			active <- struct{}{}
			wg.Add(1)
			go func(j DeploymentJob) { defer wg.Done(); defer func() { <-active }(); _ = w.Execute(ctx, j) }(job)
		}
		op, stop := context.WithTimeout(ctx, 3*time.Second)
		_, heartbeatError := w.Store.DB.ExecContext(op, `INSERT INTO v3_role_status(role,instance,heartbeat,error,details) VALUES('executor',$1,clock_timestamp(),$2,jsonb_build_object('active',$3::integer,'concurrency',$4::integer,'manifest',$5::text,'vault',$6::text)) ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error,details=excluded.details`, w.Instance, reason, len(active), concurrency, w.Manifest, vaultKeyID(w.Vault))
		if reason == "" && heartbeatError == nil {
			runtimeReady(ctx, "executor")
		}
		stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	return ctx.Err()
}

func (s *Store) checkDeploymentPlan(ctx context.Context, j DeploymentJob) error {
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
	n, err := scanNode(tx.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE id=$1 FOR SHARE", j.Node))
	if err != nil {
		return err
	}
	if j.Kind != "uninstall" && !n.Enabled || n.Version != j.NodeVersion || digest(n.Config) != current.Plan.ConfigDigest || n.Endpoint != current.Plan.Node.Endpoint || n.ServerName != current.Plan.Node.ServerName || n.Mode != current.Plan.Node.Mode || n.Name != current.Plan.Node.Name || n.Shard != current.Plan.Node.Shard {
		return ErrConflict
	}
	if err = checkDeploymentRuntimeTx(ctx, tx, current); err != nil {
		return err
	}
	return tx.Commit()
}

// Execute requires an already claimed job. DB renewal failure cancels remote
// work; only a current owner can commit checkpoints. Each restart first probes
// the remote receipt to reconcile a response lost after a successful action.
func (w *DeploymentRunner) Execute(parent context.Context, j DeploymentJob) error {
	if w.Runtime == nil {
		return errors.New("部署执行器未接通")
	}
	ctx, cancel := context.WithCancel(parent)
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				op, stop := context.WithTimeout(ctx, 3*time.Second)
				err := w.Store.RenewDeployment(op, j)
				stop()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()
	// The renewal goroutine uses only the immutable lease, not advancing steps.
	// Capture the initial value before running any phase below.
	defer func() { cancel(); <-renewed }()
	current := j
	archiveChecked := false
	for current.Status == "running" {
		var proof RemoteDeploymentCheckpoint
		op, stop := context.WithTimeout(ctx, 5*time.Second)
		err := w.Store.checkDeploymentPlan(op, current)
		stop()
		if err == nil && (current.Kind == "recover" || current.Plan.Recovery != nil) {
			op, stop = context.WithTimeout(ctx, 5*time.Second)
			_, err = w.Store.recoveryRequest(op, w.Vault, current, "inspect")
			stop()
		}
		if err == nil && current.Kind == "uninstall" {
			op, stop = context.WithTimeout(ctx, 5*time.Second)
			_, err = w.Store.uninstallRequest(op, w.Vault, current, "inspect")
			stop()
		}
		if err == nil {
			err = w.Store.checkLifecycleAuthorization(ctx, w.Vault, current)
		}
		if supported, ok := w.Runtime.(DeploymentPhaseSupport); err == nil && ok && !supported.SupportsDeploymentPhase(current.Phase()) {
			err = DeploymentFailure{"executor-unavailable"}
		}
		if err == nil && current.Plan.BeforeBackup != "" && (!archiveChecked || current.Phase() == "backup" || current.Phase() == "restore") {
			op, stop = context.WithTimeout(ctx, 10*time.Second)
			err = w.Store.checkDeploymentConfigurationArchive(op, w.Vault, current)
			stop()
			archiveChecked = err == nil
		}
		if err == nil && current.Direction == "forward" && current.Step == 2 && !current.RecoveryRequired {
			op, stop = context.WithTimeout(ctx, 5*time.Second)
			err = w.Store.ArmDeploymentRecovery(op, current)
			stop()
			if err == nil {
				current.RecoveryRequired = true
			}
		}
		if err == nil {
			proof, err = w.Runtime.Inspect(ctx, current)
			if err == nil {
				if !proof.matches(current) || proof.State == "unknown" {
					err = DeploymentFailure{"remote-state-unknown"}
				} else if proof.State == "absent" {
					proof, err = w.Runtime.Apply(ctx, current)
					if err == nil && (!proof.matches(current) || proof.State != "complete") {
						err = DeploymentFailure{"remote-state-unknown"}
					}
				} else if proof.State != "complete" {
					err = DeploymentFailure{"remote-state-unknown"}
				}
			}
		}
		if ctx.Err() != nil {
			if parent.Err() != nil {
				recovery, finish := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
				_ = w.Store.FailDeployment(recovery, current, "interrupted")
				finish()
			}
			return ctx.Err()
		}
		if err != nil {
			if errors.Is(err, ErrMigrationPending) {
				return err
			}
			if errors.Is(err, ErrLeaseLost) || errors.Is(err, ErrDeploymentState) {
				return err
			}
			code := deploymentFailureCode(err)
			if errors.Is(err, ErrConflict) {
				code = "configuration-conflict"
			}
			op, stop := context.WithTimeout(ctx, 5*time.Second)
			saved := w.Store.FailDeployment(op, current, code)
			stop()
			if saved != nil {
				return saved
			}
			return DeploymentFailure{code}
		}
		err = w.completePhaseWithEvidence(ctx, current, proof)
		if err != nil {
			if errors.Is(err, ErrMigrationPending) {
				return err
			}
			if parent.Err() != nil {
				recovery, finish := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
				_ = w.Store.FailDeployment(recovery, current, "interrupted")
				finish()
				return ctx.Err()
			}
			var failure DeploymentFailure
			if errors.Is(err, ErrConflict) {
				failure = DeploymentFailure{"configuration-conflict"}
			}
			if failure.Code != "" || errors.As(err, &failure) {
				op, stop = context.WithTimeout(ctx, 5*time.Second)
				saved := w.Store.FailDeployment(op, current, failure.Code)
				stop()
				if saved != nil {
					return saved
				}
			}
			return err
		} // May have committed: takeover reconciles remotely.
		op, stop = context.WithTimeout(ctx, 5*time.Second)
		current, err = w.Store.Deployment(op, current.ID)
		stop()
		if err != nil {
			return err
		}
		if current.Owner.String != j.Owner.String || current.Epoch != j.Epoch {
			return ErrLeaseLost
		}
	}
	return nil
}

func vaultKeyID(v *Vault) string {
	if v == nil {
		return ""
	}
	return v.active
}
