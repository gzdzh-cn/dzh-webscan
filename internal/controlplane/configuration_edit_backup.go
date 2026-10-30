package controlplane

import (
	"context"
	"database/sql"
	"errors"

	"webscan/internal/common"
)

var errConfigurationBeforeEdit = errors.New("编辑前配置备份失败，配置未保存；请检查独立密钥、数据库和可用空间")

// Public configuration writes require this context. Low-level store mutations
// remain usable by internal import/setup code, which has its own backup gates.
// Never obtain the bootstrap snapshot from a subsequently edited disk YAML or
// from the process config carrying a transient lease identity.
type configurationEditBackup struct {
	vault     *Vault
	bootstrap Config
}

func (a *API) configurationEditBackup() (*configurationEditBackup, error) {
	if a.bootstrapConfig == nil || a.bootstrapConfig.Validate() != nil {
		return nil, errConfigurationBeforeEdit
	}
	v, err := OpenVault(a.Config.DeploymentTrust.VaultKeyFile, a.Config.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		return nil, errConfigurationBeforeEdit
	}
	return &configurationEditBackup{vault: v, bootstrap: *a.bootstrapConfig}, nil
}

func (b *configurationEditBackup) lock(ctx context.Context, tx *sql.Tx, user string) error {
	if b == nil {
		return lockDeploymentWriteRelationsTx(ctx, tx)
	}
	if b.bootstrap.Validate() != nil || b.vault == nil || b.vault.keys[b.vault.active] == nil {
		return errConfigurationBeforeEdit
	}
	// Take the relation gate before row locks/receipts. READ COMMITTED then
	// captures the actual state after any earlier writer finishes, including
	// node edits, applied-version updates, setup imports and restore staging.
	if err := lockConfigurationRestoreStateTx(ctx, tx); err != nil {
		return err
	}
	return configurationBackupAdmin(ctx, tx, user)
}

func (b *configurationEditBackup) capture(ctx context.Context, tx *sql.Tx, user, operation, resource string) error {
	if b == nil {
		return nil
	}
	doc, err := captureConfigurationDocumentTx(ctx, tx, b.bootstrap, b.vault)
	if err != nil {
		return errConfigurationBeforeEdit
	}
	archive, err := insertConfigurationBackup(ctx, tx, b.vault, user, "before_edit", doc)
	if err != nil {
		return errConfigurationBeforeEdit
	}
	// The backup, mutation, original idempotency receipt and both audits share
	// one commit. No endpoints, content, passwords, key IDs or digests enter it.
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-backup-before-edit',$2,$3)`, user, archive.ID, common.JSON(map[string]any{"operation": operation, "resource": resource}))
	if err != nil {
		return errConfigurationBeforeEdit
	}
	return nil
}
