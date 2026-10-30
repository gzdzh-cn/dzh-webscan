package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"webscan/internal/common"
)

var errDeploymentConfigurationBackup = errors.New("部署前配置备份或任务引用不可用，未继续切换服务；请检查独立密钥、数据库与备份资料")

type deploymentConfigurationBackup struct {
	vault     *Vault
	bootstrap Config
}

// Reserve the eventual DML table modes before taking node/job row locks.
// Ordinary executors remain concurrent (ROW EXCLUSIVE is compatible with
// itself), while restore/edit snapshot gates can never invert this ordering.
func lockDeploymentWriteRelationsTx(ctx context.Context, tx *sql.Tx) error {
	if err := lockConfigurationOperationTx(ctx, tx, false); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `LOCK TABLE v3_nodes,v3_deployment_jobs IN ROW EXCLUSIVE MODE`)
	if err != nil {
		return err
	}
	return configurationApplicationAvailableTx(ctx, tx)
}

// Deployment creation uses a repeatable-read snapshot: capturing the complete
// desired configuration must not take a global write lock while another
// executor is completing a different node. No remote action occurs in this
// retryable transaction. The original receipt still commits exactly once.
func retryDeploymentConfigurationMutation(ctx context.Context, change func() (json.RawMessage, error)) (json.RawMessage, error) {
	for attempt := 0; ; attempt++ {
		out, err := change()
		var pg *pgconn.PgError
		if err == nil || !errors.As(err, &pg) || pg.Code != "40001" && pg.Code != "40P01" || attempt >= 4 {
			return out, err
		}
		if !waitRetry(ctx, time.Duration(10<<attempt)*time.Millisecond) {
			return nil, ctx.Err()
		}
	}
}

func (b *deploymentConfigurationBackup) archive(ctx context.Context, tx *sql.Tx, user string) (string, error) {
	if b == nil {
		return "", nil // Low-level setup/tests and pre-existing plans.
	}
	c := b.bootstrap
	if c.Validate() != nil || b.vault == nil || b.vault.keys[b.vault.active] == nil {
		return "", errDeploymentConfigurationBackup
	}
	doc, err := captureConfigurationDocumentTx(ctx, tx, c, b.vault)
	if err != nil {
		return "", errDeploymentConfigurationBackup
	}
	backup, err := insertConfigurationBackup(ctx, tx, b.vault, user, "before_deploy", doc)
	if err != nil {
		return "", errDeploymentConfigurationBackup
	}
	return backup.ID, nil
}

func pinDeploymentConfigurationTx(ctx context.Context, tx *sql.Tx, user string, j DeploymentJob) error {
	if j.Plan.BeforeBackup == "" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference) VALUES($1,'deployment',$2)`, j.Plan.BeforeBackup, "job:"+j.ID); err != nil {
		return errDeploymentConfigurationBackup
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-backup-before-deploy',$2,$3)`, user, j.Plan.BeforeBackup, common.JSON(map[string]any{"operation": "deployment-job", "node": j.Node, "job": j.ID}))
	if err != nil {
		return errDeploymentConfigurationBackup
	}
	return nil
}

// Check only a plan-bound archive and its exact durable reference. A missing
// reference cannot be repaired by trusting a caller's ID or by using another
// job's pin. Hold shared row locks until the state transition commits.
func checkDeploymentConfigurationTx(ctx context.Context, tx *sql.Tx, j DeploymentJob) error {
	if j.Plan.BeforeBackup == "" {
		return nil
	}
	kind := "deployment"
	if j.RecoveryRequired {
		kind = "rollback"
	}
	var id string
	err := tx.QueryRowContext(ctx, `SELECT b.id FROM v3_configuration_backups b JOIN v3_configuration_backup_pins p ON p.backup=b.id WHERE b.id=$1 AND b.source='before_deploy' AND p.kind=$2 AND p.reference=$3 AND p.expires_at IS NULL FOR SHARE OF b,p`, j.Plan.BeforeBackup, kind, "job:"+j.ID).Scan(&id)
	if err != nil {
		return errDeploymentConfigurationBackup
	}
	return nil
}

func armDeploymentConfigurationTx(ctx context.Context, tx *sql.Tx, j DeploymentJob) error {
	if j.Plan.BeforeBackup == "" {
		return nil
	}
	if err := checkDeploymentConfigurationTx(ctx, tx, j); err != nil {
		return err
	}
	if j.RecoveryRequired {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference) VALUES($1,'rollback',$2)`, j.Plan.BeforeBackup, "job:"+j.ID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM v3_configuration_backup_pins WHERE backup=$1 AND kind='deployment' AND reference=$2`, j.Plan.BeforeBackup, "job:"+j.ID)
	return err
}

func releaseDeploymentConfigurationTx(ctx context.Context, tx *sql.Tx, j DeploymentJob) error {
	if j.Plan.BeforeBackup == "" {
		return nil
	}
	var linked bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_configuration_application_nodes WHERE child=$1)`, j.ID).Scan(&linked); err != nil {
		return err
	}
	if linked {
		// A later parent phase may still need to restore this successful child.
		// The parent releases the exact rollback pin only at its own terminal
		// checkpoint, after checking every linked child outcome.
		return nil
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM v3_configuration_backup_pins WHERE backup=$1 AND kind IN ('deployment','rollback') AND reference=$2`, j.Plan.BeforeBackup, "job:"+j.ID)
	return err
}

// Authenticate the archive with this executor's independent key, rather than
// treating the existence of ciphertext/pins as proof of a usable backup. This
// is read-only and runs before any remote call after takeover, and again before
// backup/restore can stop a service. It cannot reconstruct lost key material.
func (s *Store) checkDeploymentConfigurationArchive(ctx context.Context, v *Vault, j DeploymentJob) error {
	if j.Plan.BeforeBackup == "" {
		return nil
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
	if err = checkDeploymentConfigurationTx(ctx, tx, current); err != nil {
		return err
	}
	doc, _, err := loadConfigurationBackup(ctx, tx, v, current.Plan.BeforeBackup, false)
	if err != nil {
		return errDeploymentConfigurationBackup
	}
	n, ok := doc.Nodes[current.Node]
	wanted := current.Plan.Node
	if !ok || n.Version != current.NodeVersion || n.Name != wanted.Name || n.Endpoint != wanted.Endpoint || n.ServerName != wanted.ServerName || n.Mode != wanted.Mode || n.Enabled != wanted.Enabled {
		return errDeploymentConfigurationBackup
	}
	// Match the canonical PostgreSQL JSONB representation used by the saved
	// node's immutable plan digest, preserving large JSON numbers exactly.
	var canonical []byte
	if err = tx.QueryRowContext(ctx, `SELECT $1::jsonb`, common.JSON(doc.Profiles[n.Profile].Config)).Scan(&canonical); err != nil {
		return errDeploymentConfigurationBackup
	}
	if digest(canonical) != current.Plan.ConfigDigest {
		return errDeploymentConfigurationBackup
	}
	return tx.Commit()
}
