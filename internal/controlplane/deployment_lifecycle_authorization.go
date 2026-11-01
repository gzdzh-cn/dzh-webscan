package controlplane

import (
	"context"
	"crypto/hmac"
	"database/sql"

	"webscan/internal/nodeops"
)

// A plain plan digest detects corruption, but cannot authorize reuse of a
// previous signed lifecycle after restoration. Bind that permission to Vault.
func lifecycleAuthorizationProof(v *Vault, key string, j DeploymentJob) (string, error) {
	return lifecycleProof(v, key, "deployment-lifecycle-authorization", []any{j.ID, j.Node, j.PlanDigest, j.Plan.PreviousLifecycle, j.Plan.Reinstall})
}

func recordLifecycleAuthorizationTx(ctx context.Context, tx *sql.Tx, v *Vault, j DeploymentJob) error {
	if j.Plan.PreviousLifecycle == nil && j.Plan.Reinstall == nil {
		return nil
	}
	if v == nil || j.Plan.PreviousLifecycle == nil {
		return errNodeUninstall
	}
	proof, err := lifecycleAuthorizationProof(v, v.active, j)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_deployment_lifecycle_authorizations(job,source,key_id,proof) VALUES($1,$2,$3,$4)`, j.ID, j.Plan.PreviousLifecycle.Job, v.active, proof)
	return err
}

func readLifecycleAuthorizationTx(ctx context.Context, tx *sql.Tx, v *Vault, j DeploymentJob) error {
	if j.Plan.PreviousLifecycle == nil && j.Plan.Reinstall == nil {
		return nil
	}
	if j.Plan.PreviousLifecycle == nil {
		return errNodeUninstall
	}
	var source, key, proof string
	if err := tx.QueryRowContext(ctx, `SELECT source,key_id,proof FROM v3_deployment_lifecycle_authorizations WHERE job=$1 FOR SHARE`, j.ID).Scan(&source, &key, &proof); err != nil {
		return err
	}
	want, err := lifecycleAuthorizationProof(v, key, j)
	if err != nil || source != j.Plan.PreviousLifecycle.Job || !hmac.Equal([]byte(want), []byte(proof)) {
		return errNodeUninstall
	}
	return nil
}

func authenticatedUninstalledTx(ctx context.Context, tx *sql.Tx, v *Vault, n Node, prior *deploymentLifecycleState) (DeploymentJob, nodeops.RemovalEvidence, error) {
	var empty DeploymentJob
	var receipt nodeops.RemovalEvidence
	if prior == nil || prior.Node != n.ID || prior.State != "uninstalled" || prior.Source == nil || n.AppliedVersion != 0 {
		return empty, receipt, errNodeUninstall
	}
	b, err := runtimeBaselineTx(ctx, tx, n.ID)
	if err != nil || b.Snapshot != "" || b.Epoch != prior.RuntimeGeneration {
		return empty, receipt, errNodeUninstall
	}
	j, err := readRecoveryJobTx(ctx, tx, prior.Job)
	if err != nil || j.Kind != "uninstall" || j.Node != n.ID || j.Status != "succeeded" || j.Direction != "forward" || j.Step != len(deploymentPhases) || j.Plan.Uninstall == nil {
		return empty, receipt, errNodeUninstall
	}
	if err := readUninstallPlanTx(ctx, tx, v, j); err != nil {
		return empty, receipt, err
	}
	if err := readLifecycleReceiptTx(ctx, tx, v, j, "removal", &receipt); err != nil || !receipt.Valid() {
		return empty, receipt, errNodeUninstall
	}
	return j, receipt, nil
}

func (s *Store) checkLifecycleAuthorization(ctx context.Context, v *Vault, j DeploymentJob) error {
	if j.Kind == "uninstall" || j.Plan.PreviousLifecycle == nil && j.Plan.Reinstall == nil {
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := readLifecycleAuthorizationTx(ctx, tx, v, j); err != nil {
		return err
	}
	return tx.Commit()
}
