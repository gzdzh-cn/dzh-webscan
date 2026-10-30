package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"webscan/internal/common"
)

var errConfigurationRestorePending = errors.New("已有未完成的配置恢复，请先查看或取消原恢复记录")
var errConfigurationRestoreBlocked = errors.New("恢复配置需补全，或涉及专用迁移／卸载；请先处理预览中的阻止项")

// This safe receipt records an intent. It is not a live eligibility check or a
// promise that an existing service, local path or credential has been checked.
type configurationRestoreStage struct {
	ID              string     `json:"id"`
	Username        string     `json:"username"`
	Backup          string     `json:"backup"`
	BeforeBackup    string     `json:"before_backup"`
	SettingsVersion int64      `json:"settings_version"`
	Status          string     `json:"status"`
	Message         string     `json:"message"`
	Created         time.Time  `json:"created_at"`
	Updated         time.Time  `json:"updated_at"`
	Finished        *time.Time `json:"finished_at"`
	CancelledBy     string     `json:"cancelled_by"`
	// Only current read projections populate this field. Original mutation
	// receipts remain immutable records of saving intent, never live status.
	Application *configurationApplicationJob `json:"application,omitempty"`
}

const configurationStageColumns = `id,username,backup,before_backup,settings_version,status,message,created_at,updated_at,finished_at,cancelled_by`

func scanConfigurationStage(row interface{ Scan(...any) error }) (s configurationRestoreStage, err error) {
	err = row.Scan(&s.ID, &s.Username, &s.Backup, &s.BeforeBackup, &s.SettingsVersion, &s.Status, &s.Message, &s.Created, &s.Updated, &s.Finished, &s.CancelledBy)
	return
}

// Use only inside a READ COMMITTED transaction, before reading desired state.
// This database-enforced gate blocks all INSERT/UPDATE/DELETE entry points,
// including direct SQL and legacy import; an advisory lock alone would not.
// Shared reads and event/metric/notification transactions remain available.
// RR/serializable snapshots acquired before a lock wait could be stale, so they
// are deliberately rejected here. After locking, all relevant rows are stable.
func lockConfigurationRestoreStateTx(ctx context.Context, tx *sql.Tx) error {
	if err := lockConfigurationRestoreRelationsTx(ctx, tx); err != nil {
		return err
	}
	return configurationApplicationAvailableTx(ctx, tx)
}

// Application coordination uses this relation gate, then authenticates its
// exact job and current lease. Ordinary writers additionally check availability.
func lockConfigurationRestoreRelationsTx(ctx context.Context, tx *sql.Tx) error {
	var isolation string
	if err := tx.QueryRowContext(ctx, `SHOW transaction_isolation`).Scan(&isolation); err != nil {
		return err
	}
	if isolation != "read committed" {
		return errors.New("恢复提交必须使用受事务表锁保护的读已提交事务")
	}
	if err := lockConfigurationOperationTx(ctx, tx, true); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `LOCK TABLE v3_settings,v3_settings_drafts,v3_bootstrap_drafts,v3_nodes,v3_deployment_jobs,v3_configuration_applications IN SHARE ROW EXCLUSIVE MODE`)
	return err
}

// stageConfigurationRestore persists a pending-validation intent. It performs
// no local file reads, SSH, live configuration write, deployment or notification.
// The before-restore archive, pins, consumed capability, receipt and audit commit
// together. A later application workflow must validate and recheck all proofs.
func (s *Store) stageConfigurationRestore(ctx context.Context, v *Vault, c Config, user, key, preview string) (json.RawMessage, error) {
	if !validArchiveSource(preview) || c.Validate() != nil {
		return nil, errConfigurationRestorePreview
	}
	op, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	hash := digest([]byte(preview))
	return s.guardedMutation(op, user, key, "configuration-restore-stage", hash, []string{hash}, func(tx *sql.Tx) error {
		if err := lockConfigurationRestoreStateTx(op, tx); err != nil {
			return err
		}
		return configurationBackupAdmin(op, tx, user)
	}, func(tx *sql.Tx) (any, error) {
		var pending bool
		if err := tx.QueryRowContext(op, `SELECT EXISTS(SELECT 1 FROM v3_configuration_restore_stages WHERE status IN ('pending_validation','pending_application'))`).Scan(&pending); err != nil {
			return nil, err
		}
		if pending {
			return nil, errConfigurationRestorePending
		}
		plan, err := revalidateConfigurationRestoreTx(op, tx, v, c, user, preview)
		if err != nil {
			return nil, err
		}
		if !plan.Summary.CanPrepare {
			return nil, errConfigurationRestoreBlocked
		}
		// Capture again inside the same relational gate. Its new timestamp does
		// not change the state proof; settings/nodes cannot change until commit.
		current, err := captureConfigurationDocumentTx(op, tx, c, v)
		if err != nil {
			return nil, err
		}
		before, err := insertConfigurationBackup(op, tx, v, user, "before_restore", current)
		if err != nil {
			return nil, err
		}
		id := token()
		stage, err := scanConfigurationStage(tx.QueryRowContext(op, `INSERT INTO v3_configuration_restore_stages(id,username,account_revision,preview_hash,backup,before_backup,options,archive_proof,state_proof,summary,settings_version)
 SELECT $1,username,account_revision,token_hash,backup,$2,options,archive_proof,state_proof,$3,$4 FROM v3_configuration_restore_previews
 WHERE token_hash=$5 AND username=$6 AND expires_at>clock_timestamp() RETURNING `+configurationStageColumns,
			id, before.ID, common.JSON(plan.Summary), current.SettingsVersion, hash, user))
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errConfigurationRestorePreview
		}
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(op, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference) VALUES($1,'restore',$3),($2,'restore',$4)`, stage.Backup, before.ID, "stage:"+id+":source", "stage:"+id+":before"); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(op, `DELETE FROM v3_configuration_backup_pins WHERE kind='restore' AND reference=$1;`, "preview:"+hash); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(op, `DELETE FROM v3_configuration_restore_previews WHERE token_hash=$1`, hash); err != nil {
			return nil, err
		}
		return stage, nil
	})
}

// Re-read the actual persisted status after a receipt or process restart. Current
// administrators may inspect/cancel an abandoned intent owned by a demoted or
// unavailable administrator; none may apply it using the owner's old identity.
func (s *Store) configurationRestoreStage(ctx context.Context, user, id string) (configurationRestoreStage, configurationRestoreSummary, error) {
	var summary configurationRestoreSummary
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return configurationRestoreStage{}, summary, err
	}
	defer tx.Rollback()
	if err = configurationBackupAdmin(ctx, tx, user); err != nil {
		return configurationRestoreStage{}, summary, err
	}
	if !validArchiveSource(id) {
		return configurationRestoreStage{}, summary, sql.ErrNoRows
	}
	stage, err := scanConfigurationStage(tx.QueryRowContext(ctx, `SELECT `+configurationStageColumns+` FROM v3_configuration_restore_stages WHERE id=$1 FOR SHARE`, id))
	if err != nil {
		return stage, summary, err
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT summary FROM v3_configuration_restore_stages WHERE id=$1`, id).Scan(&raw); err != nil {
		return configurationRestoreStage{}, summary, err
	}
	if json.Unmarshal(raw, &summary) != nil {
		return configurationRestoreStage{}, summary, errConfigurationDocument
	}
	return stage, summary, tx.Commit()
}

// Internal continuation prerequisite. Reconstruct from authenticated archives,
// never from the display summary or an old in-memory candidate. Holding the
// relational gate through the caller's final transaction excludes all writers;
// local material validation and saved/applied version commits remain separate
// required steps. This function performs neither of those steps.
func revalidateConfigurationStageTx(ctx context.Context, tx *sql.Tx, v *Vault, c Config, user, id string) (configurationRestorePlan, error) {
	var empty configurationRestorePlan
	if !validArchiveSource(id) || c.Validate() != nil {
		return empty, errConfigurationRestorePreview
	}
	if held, err := migrationHeld(ctx, tx); err != nil {
		return empty, err
	} else if held {
		return empty, ErrMigrationPending
	}
	if err := lockConfigurationRestoreStateTx(ctx, tx); err != nil {
		return empty, err
	}
	revision, err := configurationRestoreAccount(ctx, tx, user)
	if err != nil {
		return empty, err
	}
	var source, before, archiveProof, stateProof, phase string
	var account int64
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT backup,before_backup,account_revision,options,archive_proof,state_proof,status FROM v3_configuration_restore_stages WHERE id=$1 AND username=$2 AND status IN ('pending_validation','pending_application') FOR UPDATE`, id, user).Scan(&source, &before, &account, &raw, &archiveProof, &stateProof, &phase)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, errConfigurationRestorePreview
	}
	if err != nil {
		return empty, err
	}
	var options configurationRestoreOptions
	if revision != account || json.Unmarshal(raw, &options) != nil {
		return empty, errConfigurationRestorePreview
	}
	doc, _, err := loadConfigurationBackup(ctx, tx, v, source, false)
	if err != nil {
		return empty, err
	}
	if !configurationRestoreProofMatches(v, archiveProof, "archive", user, revision, options, doc, common.JSON(source)) {
		return empty, errConfigurationRestorePreview
	}
	current, err := captureConfigurationDocumentTx(ctx, tx, c, v)
	if err != nil {
		return empty, err
	}
	deployments, err := configurationRestoreDeployments(ctx, tx)
	if err != nil {
		return empty, err
	}
	if !configurationRestoreProofMatches(v, stateProof, "state", user, revision, options, current, deployments) {
		return empty, errConfigurationRestorePreview
	}
	prior, _, err := loadConfigurationBackup(ctx, tx, v, before, false)
	if err != nil {
		return empty, err
	}
	if !configurationRestoreProofMatches(v, stateProof, "state", user, revision, options, prior, deployments) {
		return empty, errConfigurationRestorePreview
	}
	var pins int
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_configuration_backup_pins WHERE kind='restore' AND expires_at IS NULL AND ((backup=$1 AND reference=$3) OR (backup=$2 AND reference=$4))`, source, before, "stage:"+id+":source", "stage:"+id+":before").Scan(&pins)
	if err != nil {
		return empty, err
	}
	if pins != 2 {
		return empty, errConfigurationRestorePreview
	}
	plan, err := prepareConfigurationRestore(doc, current, options)
	if err != nil {
		return empty, err
	}
	if phase == "pending_application" {
		r, candidate, err := validateConfigurationRevisionTx(ctx, tx, v, id, user, revision, options, stateProof, plan.Candidate)
		if err != nil {
			return empty, err
		}
		plan.Candidate = candidate
		plan.Revision = r
	}
	return plan, nil
}

// Cancelling drops only the intent's pins. Backups, live state and all business
// history remain intact. A terminal receipt cannot create a new restore intent.
func (s *Store) cancelConfigurationRestore(ctx context.Context, user, key, id string) (json.RawMessage, error) {
	if !validArchiveSource(id) {
		return nil, errConfigurationRestorePreview
	}
	return s.guardedMutation(ctx, user, key, "configuration-restore-cancel", id, []string{id}, func(tx *sql.Tx) error {
		if err := lockConfigurationRestoreStateTx(ctx, tx); err != nil {
			return err
		}
		return configurationBackupAdmin(ctx, tx, user)
	}, func(tx *sql.Tx) (any, error) {
		stage, err := scanConfigurationStage(tx.QueryRowContext(ctx, `SELECT `+configurationStageColumns+` FROM v3_configuration_restore_stages WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return nil, err
		}
		if stage.Status != "pending_validation" && stage.Status != "pending_application" {
			return stage, nil
		}
		stage, err = scanConfigurationStage(tx.QueryRowContext(ctx, `UPDATE v3_configuration_restore_stages SET status='cancelled',message='已取消恢复；运行配置未修改',cancelled_by=$2,updated_at=clock_timestamp(),finished_at=clock_timestamp() WHERE id=$1 RETURNING `+configurationStageColumns, id, user))
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM v3_configuration_backup_pins WHERE kind='restore' AND reference IN($1,$2)`, "stage:"+id+":source", "stage:"+id+":before"); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v3_configuration_revisions SET status='cancelled',message='已取消待应用配置；运行配置未修改',updated_at=clock_timestamp(),finished_at=clock_timestamp() WHERE stage=$1 AND status='pending_application'`, id); err != nil {
			return nil, err
		}
		return stage, nil
	})
}
