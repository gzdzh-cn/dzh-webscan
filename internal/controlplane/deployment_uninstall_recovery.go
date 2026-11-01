package controlplane

import (
	"context"
	"database/sql"
)

// A successful removal can be explicitly undone while it is still the exact
// current lifecycle. This is not generic recovery of arbitrary terminal jobs.
func authorizeCompletedUninstallRollbackTx(ctx context.Context, tx *sql.Tx, v *Vault, j DeploymentJob, pin bool) error {
	if v == nil || j.Kind != "uninstall" || j.Status != "succeeded" || j.Direction != "forward" || j.Step != len(deploymentPhases) || j.RollbackStep != 0 || j.Plan.BeforeBackup == "" {
		return errNodeUninstall
	}
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR SHARE`, j.Node))
	if err != nil || n.Version != j.NodeVersion || digest(n.Config) != j.Plan.ConfigDigest || n.Name != j.Plan.Node.Name || n.Endpoint != j.Plan.Node.Endpoint || n.ServerName != j.Plan.Node.ServerName || n.Mode != j.Plan.Node.Mode || n.Enabled != j.Plan.Node.Enabled {
		return ErrConflict
	}
	prior, err := readNodeLifecycleTx(ctx, tx, v, n.ID)
	if err != nil || prior == nil || prior.Job != j.ID {
		return errNodeUninstall
	}
	if _, _, err = authenticatedUninstalledTx(ctx, tx, v, n, prior); err != nil {
		return err
	}
	// A later reinstall can return to the same tombstone with a newer fence.
	// The original removal journal cannot restore across that intervening task;
	// doing so would authorize a restore whose fixed checkpoint cannot run.
	if j.Plan.PreviousRuntime == nil || prior.RuntimeGeneration != j.Plan.PreviousRuntime.Epoch+1 {
		return ErrConflict
	}
	var busy bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND id<>$2 AND (status IN ('queued','running') OR status NOT IN ('succeeded','rolled_back') AND recovery_required)) OR EXISTS(SELECT 1 FROM v3_deployment_history_archives WHERE deployment=$2)`, n.ID, j.ID).Scan(&busy); err != nil {
		return err
	}
	if busy {
		return ErrDeploymentBusy
	}
	if err := uninstallMaintenanceAvailableTx(ctx, tx, n.ID); err != nil {
		return err
	}
	if _, _, err := loadConfigurationBackup(ctx, tx, v, j.Plan.BeforeBackup, false); err != nil {
		return errDeploymentConfigurationBackup
	}
	if pin {
		_, err = tx.ExecContext(ctx, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference) VALUES($1,'rollback',$2) ON CONFLICT DO NOTHING`, j.Plan.BeforeBackup, "job:"+j.ID)
	}
	return err
}
