package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"

	"webscan/internal/common"
)

func insertUninstallDeploymentTx(ctx context.Context, tx *sql.Tx, user string, in DeploymentRequest, n Node, guard func(*sql.Tx, Node) error, before *deploymentConfigurationBackup) (any, error) {
	if n.Version != in.Expected || in.RuntimeArtifact != nil {
		return nil, ErrConflict
	}
	if guard != nil {
		if err := guard(tx, n); err != nil {
			return nil, err
		}
	}
	if _, _, _, err := deploymentPreviewState(ctx, tx, n, DeploymentRequest{}); err != nil {
		return nil, err
	}
	if err := uninstallMaintenanceAvailableTx(ctx, tx, n.ID); err != nil {
		return nil, err
	}
	source, err := installedSourceTx(ctx, tx, before.vault, n)
	if err != nil {
		return nil, err
	}
	if err = uninstallCredentialMatchesTx(ctx, tx, before.vault, source, in.Credential); err != nil {
		return nil, err
	}
	plan := DeploymentPlan{Request: in, Node: n, ConfigDigest: digest(n.Config), Uninstall: &deploymentUninstallPlan{Source: source}}
	plan.PreviousRuntime, err = runtimeBaselineTx(ctx, tx, n.ID)
	if err != nil {
		return nil, err
	}
	plan.PreviousLifecycle, err = readNodeLifecycleTx(ctx, tx, before.vault, n.ID)
	if err != nil {
		return nil, err
	}
	plan.BeforeBackup, err = before.archive(ctx, tx, user)
	if err != nil {
		return nil, err
	}
	var canonical []byte
	if err = tx.QueryRowContext(ctx, `SELECT $1::jsonb`, common.JSON(plan)).Scan(&canonical); err != nil {
		return nil, err
	}
	j := DeploymentJob{ID: token(), Node: n.ID, Username: user, Kind: "uninstall", Status: "queued", Direction: "forward", NodeVersion: n.Version, PlanDigest: digest(canonical), Plan: plan}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_deployment_jobs(id,node,username,kind,node_version,credential,plan,plan_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, j.ID, n.ID, user, j.Kind, n.Version, in.Credential, canonical, j.PlanDigest); err != nil {
		return nil, err
	}
	proof, err := uninstallPlanProof(before.vault, before.vault.active, j)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_deployment_uninstalls(job,source,key_id,proof) VALUES($1,$2,$3,$4)`, j.ID, source.Job, before.vault.active, proof); err != nil {
		return nil, err
	}
	if err = deploymentLog(ctx, tx, &j, "preflight", "queued"); err != nil {
		return nil, err
	}
	if err = pinDeploymentConfigurationTx(ctx, tx, user, j); err != nil {
		return nil, err
	}
	return map[string]any{"id": j.ID, "node": n.ID, "status": "queued", "message": "已创建卸载任务；确认远端结果后才会标记已卸载，数据和中心记录保留"}, nil
}

func uninstallMaintenanceAvailableTx(ctx context.Context, tx *sql.Tx, node string) error {
	if err := checkMonitoringNodeReservationTx(ctx, tx, node); err != nil {
		return err
	}
	var busy bool
	if err := tx.QueryRowContext(ctx, `SELECT
 EXISTS(SELECT 1 FROM v3_node_renewal_jobs WHERE node=$1 AND activated_at IS NULL) OR
 EXISTS(SELECT 1 FROM v3_node_identity_recoveries WHERE node=$1 AND status NOT IN ('completed','canceled')) OR
 EXISTS(SELECT 1 FROM v3_node_name_changes WHERE node=$1 AND status NOT IN ('completed','canceled')) OR
 EXISTS(SELECT 1 FROM v3_node_name_prunings WHERE node=$1 AND status NOT IN ('completed','canceled'))`, node).Scan(&busy); err != nil {
		return err
	}
	if busy {
		return ErrDeploymentBusy
	}
	return nil
}

func uninstallCredentialMatchesTx(ctx context.Context, tx *sql.Tx, v *Vault, source deploymentInstalledSource, id string) error {
	current, _, err := (&Store{}).uninstallCredentialTx(ctx, tx, v, source)
	if err != nil {
		return err
	}
	if current != id {
		return ErrCredentialUnavailable
	}
	return nil
}

func checkUninstallRuntimeTx(ctx context.Context, tx *sql.Tx, j DeploymentJob) error {
	if j.Kind != "uninstall" || j.Plan.Uninstall == nil || j.Plan.PreviousRuntime == nil || j.Plan.TargetRuntime != "" || j.Plan.Recovery != nil || j.Plan.Reinstall != nil {
		return errNodeUninstall
	}
	// Follow collection's lease -> node ordering. Offline nodes need no live
	// lease to uninstall, but an existing lease must still serialize renewal.
	var epoch int64
	if err := tx.QueryRowContext(ctx, `SELECT epoch FROM v3_leases WHERE resource=$1 FOR SHARE`, shardResource(j.Plan.Uninstall.Source.Node.Shard)).Scan(&epoch); err != nil && err != sql.ErrNoRows {
		return err
	}
	b := *j.Plan.PreviousRuntime
	if b.Snapshot != "" {
		if err := requireNodeSnapshotAvailableTx(ctx, tx, j.Node, b.Snapshot); err != nil {
			return err
		}
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT to_jsonb(c) FROM v3_node_configurations c WHERE node=$1 AND id=$2 FOR SHARE`, j.Node, b.Snapshot).Scan(&raw); err != nil {
			return err
		}
		if digest(raw) != b.Digest {
			return ErrConflict
		}
	}
	current, err := runtimeBaselineTx(ctx, tx, j.Node)
	if err != nil {
		return err
	}
	if !j.RecoveryRequired {
		if *current != b {
			return ErrConflict
		}
		return nil
	}
	want := deploymentRuntimeBaseline{Epoch: b.Epoch + 1}
	if j.Direction == "rollback" && j.RollbackStep > 0 {
		want = b
		want.Epoch = b.Epoch + 2
	}
	if *current != want {
		return ErrConflict
	}
	return nil
}

// Arming fences in-flight reads and suspends this node's actual registration.
// The editable enabled flag and saved target configuration are untouched.
func pauseUninstallRuntimeTx(ctx context.Context, tx *sql.Tx, j DeploymentJob) error {
	if err := checkUninstallRuntimeTx(ctx, tx, j); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1 WHERE id=$1`, j.Node); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v3_node_runtime WHERE node=$1`, j.Node); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v3_node_readiness WHERE node=$1`, j.Node); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v3_node_status SET sampled_at=NULL,metrics='{}',info='{}',error='',metrics_error='',events_error='',protocol_error='',updated_at=clock_timestamp() WHERE node=$1`, j.Node); err != nil {
		return err
	}
	return disableNodeHealthTx(ctx, tx, j.Node)
}

func restoreUninstallRuntimeTx(ctx context.Context, tx *sql.Tx, j DeploymentJob) error {
	if err := checkUninstallRuntimeTx(ctx, tx, j); err != nil {
		return err
	}
	b := j.Plan.PreviousRuntime
	if b.Snapshot != "" {
		return publishNodeRuntimeTx(ctx, tx, j.Node, b.Snapshot, b.Delivered)
	}
	_, err := tx.ExecContext(ctx, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1 WHERE id=$1`, j.Node)
	return err
}

func recordUninstallCompletionTx(ctx context.Context, tx *sql.Tx, v *Vault, j DeploymentJob, remote *RemoteDeploymentCheckpoint) error {
	if remote == nil || !remote.matches(j) || remote.State != "complete" || remote.Installation != nil || remote.Spec != nil {
		return errNodeUninstall
	}
	if err := readUninstallPlanTx(ctx, tx, v, j); err != nil {
		return err
	}
	source := j.Plan.Uninstall.Source
	state := deploymentLifecycleState{Node: j.Node, Job: j.ID, Source: &source}
	switch {
	case j.Direction == "forward" && j.Phase() == "finalize":
		if remote.Removal == nil || !remote.Removal.Valid() || remote.Restoration != nil {
			return errNodeUninstall
		}
		if err := recordLifecycleReceiptTx(ctx, tx, v, j, "removal", remote.Removal); err != nil {
			return err
		}
		state.State = "uninstalled"
	case j.Direction == "rollback" && j.Phase() == "verify-rollback":
		if remote.Restoration == nil || !remote.Restoration.Valid() || remote.Removal != nil {
			return errNodeUninstall
		}
		if err := recordLifecycleReceiptTx(ctx, tx, v, j, "restoration", remote.Restoration); err != nil {
			return err
		}
		source.Restoration = &deploymentSourceRestoration{Job: j.ID, PlanDigest: j.PlanDigest, Evidence: *remote.Restoration}
		state.Source, state.State = &source, "installed"
	default:
		if remote.Removal != nil || remote.Restoration != nil {
			return errNodeUninstall
		}
		return nil
	}
	return writeNodeLifecycleTx(ctx, tx, v, state)
}

func recordInstalledLifecycleTx(ctx context.Context, tx *sql.Tx, v *Vault, j DeploymentJob, proof *RemoteDeploymentCheckpoint, phase string) error {
	if v == nil {
		return nil
	} // Existing low-level journals do not invent proof.
	if j.Direction == "forward" && phase == "finalize" && proof != nil && proof.Installation != nil && proof.Spec != nil {
		row, err := readDeploymentInstallationTx(ctx, tx, v, j)
		if err != nil {
			return err
		}
		source := sourceFromInstallation(j, row)
		return writeNodeLifecycleTx(ctx, tx, v, deploymentLifecycleState{Node: j.Node, Job: j.ID, State: "installed", Source: &source})
	}
	if j.Direction == "rollback" && phase == "verify-rollback" && j.Plan.PreviousLifecycle != nil {
		if err := readLifecycleAuthorizationTx(ctx, tx, v, j); err != nil {
			return err
		}
		prior := *j.Plan.PreviousLifecycle
		// The original authenticated lifecycle remains in this immutable plan.
		// Re-sign it with today's runtime fence after verified restoration.
		return writeNodeLifecycleTx(ctx, tx, v, prior)
	}
	if (j.Direction == "rollback" && phase == "verify-rollback") || j.Kind == "recover" && phase == "verify-rollback" {
		_, err := tx.ExecContext(ctx, `DELETE FROM v3_node_lifecycle WHERE node=$1`, j.Node)
		return err
	}
	return nil
}

func deploymentStateWithTrust(ctx context.Context, tx *sql.Tx, t *deploymentTrust, n Node, in DeploymentRequest) (string, *DeploymentTarget, string, error) {
	state, current, comparison, err := deploymentPreviewState(ctx, tx, n, in)
	if err != nil || in.Kind != "uninstall" {
		return state, current, comparison, err
	}
	if t == nil {
		return "", nil, "", errNodeUninstall
	}
	if err := uninstallMaintenanceAvailableTx(ctx, tx, n.ID); err != nil {
		return "", nil, "", err
	}
	source, err := installedSourceTx(ctx, tx, t.vault, n)
	if err != nil {
		return "", nil, "", err
	}
	if err := uninstallCredentialMatchesTx(ctx, tx, t.vault, source, in.Credential); err != nil {
		return "", nil, "", err
	}
	sha := source.Spec.BundleSHA256
	if source.Spec.Mode == "docker" {
		sha = source.Spec.AgentImage[len(source.Spec.AgentImage)-64:]
	}
	return digest(common.JSON([]any{state, source})), &DeploymentTarget{Release: source.Spec.Release, SHA256: sha, Mode: source.Spec.Mode}, "uninstall-preserve-data", nil
}

// decodeUninstallPreparation recovers the operation from private, sealed input;
// confirmation cannot change the scope of its source preview.
func decodeUninstallPreparation(raw []byte) (webDeploymentInput, error) {
	var in webDeploymentInput
	if json.Unmarshal(raw, &in) != nil {
		return in, errWebDeployment
	}
	return in, nil
}
