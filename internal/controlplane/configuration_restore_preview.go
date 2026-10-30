package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"webscan/internal/common"
)

var errConfigurationRestorePreview = errors.New("恢复预览已过期或账号、备份、配置、部署状态已变化，请重新预览")
var errConfigurationRestoreQuota = errors.New("当前账号有效恢复预览已达 100 个，请等待预览过期后重试")

type configurationRestorePreview struct {
	Token   string                      `json:"token"`
	Backup  string                      `json:"backup"`
	Expires time.Time                   `json:"expires_at"`
	Summary configurationRestoreSummary `json:"summary"`
}

// Bypass the document's deliberate public JSON prohibition only inside this
// private HMAC boundary. The raw bytes never become a receipt, audit or error.
func configurationRestoreProof(v *Vault, keyID, domain, user string, revision int64, options configurationRestoreOptions, doc configurationDocument, evidence json.RawMessage) (string, error) {
	if v == nil || len(v.receiptKeys[keyID]) == 0 || domain != "archive" && domain != "state" && domain != "candidate" {
		return "", ErrConfigurationBackupKey
	}
	if domain != "archive" {
		// Capture time changes on every read; versions and configuration do not.
		doc.Created = "2000-01-01T00:00:00Z"
	}
	type privateDocument configurationDocument
	raw, err := json.Marshal(struct {
		User     string
		Revision int64
		Options  configurationRestoreOptions
		Document privateDocument
		Evidence json.RawMessage
	}{user, revision, options, privateDocument(doc), evidence})
	if err != nil {
		return "", errConfigurationDocument
	}
	defer clear(raw)
	h := hmac.New(sha256.New, v.receiptKeys[keyID])
	h.Write([]byte("webscan-v3/configuration-restore/" + domain + "/v1\x00"))
	h.Write(raw)
	return keyID + ":" + hex.EncodeToString(h.Sum(nil)), nil
}

func configurationRestoreProofMatches(v *Vault, proof, domain, user string, revision int64, options configurationRestoreOptions, doc configurationDocument, deployments json.RawMessage) bool {
	keyID, _, ok := strings.Cut(proof, ":")
	if !ok || len(proof) > 128 {
		return false
	}
	expected, err := configurationRestoreProof(v, keyID, domain, user, revision, options, doc, deployments)
	return err == nil && hmac.Equal([]byte(expected), []byte(proof))
}

// Snapshot deployment evidence, without remote operations or decrypting SSH
// credentials. Bind the latest job per node, including completed work: a task
// that ran between preview and confirmation also invalidates the explanation.
func configurationRestoreDeployments(ctx context.Context, tx *sql.Tx) (json.RawMessage, error) {
	var busy bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE status NOT IN ('succeeded','rolled_back') AND (status IN ('queued','running') OR recovery_required)) OR EXISTS(SELECT 1 FROM v3_node_identity_recoveries WHERE status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_changes WHERE status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_prunings WHERE status IN ('prepared','requested','signed') AND expires_at>clock_timestamp())`).Scan(&busy); err != nil {
		return nil, err
	}
	if busy {
		return nil, ErrDeploymentBusy
	}
	var raw json.RawMessage
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_array(node,id,status,plan_digest,direction,step,rollback_step,lease_epoch,updated_at) ORDER BY node),'[]'::jsonb)
 FROM (SELECT DISTINCT ON(node) node,id,status,plan_digest,direction,step,rollback_step,lease_epoch,updated_at FROM v3_deployment_jobs ORDER BY node,created_at DESC,id DESC) j`).Scan(&raw)
	return raw, err
}

func configurationRestoreAccount(ctx context.Context, tx *sql.Tx, user string) (int64, error) {
	if err := configurationBackupAdmin(ctx, tx, user); err != nil {
		return 0, err
	}
	var revision int64
	err := tx.QueryRowContext(ctx, `SELECT revision FROM v3_accounts WHERE username=$1 FOR SHARE`, user).Scan(&revision)
	return revision, err
}

// Internal only until the staged settings/application workflow is complete.
// Does not read local paths, write live configuration or enqueue deployments.
func (s *Store) previewConfigurationRestore(ctx context.Context, v *Vault, c Config, user, id string, options configurationRestoreOptions) (configurationRestorePreview, error) {
	var out configurationRestorePreview
	if !validArchiveSource(id) || c.Validate() != nil {
		return out, errConfigurationRestorePreview
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	revision, err := configurationRestoreAccount(ctx, tx, user)
	if err != nil {
		return out, err
	}
	if held, err := migrationHeld(ctx, tx); err != nil {
		return out, err
	} else if held {
		return out, ErrMigrationPending
	}
	// A row update (rather than just an advisory lock in an old RR snapshot)
	// makes concurrent quota checks serialize or fail for a fresh retry.
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_history_gates(username,version) VALUES($1,1) ON CONFLICT(username) DO UPDATE SET version=v3_history_gates.version+1`, user); err != nil {
		return out, err
	}
	var active int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_configuration_restore_previews WHERE username=$1 AND expires_at>clock_timestamp()`, user).Scan(&active); err != nil {
		return out, err
	}
	if active >= 100 {
		return out, errConfigurationRestoreQuota
	}
	doc, _, err := loadConfigurationBackup(ctx, tx, v, id, false)
	if err != nil {
		return out, err
	}
	var deleting bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_configuration_delete_items WHERE backup=$1 AND status='pending')`, id).Scan(&deleting); err != nil {
		return out, err
	}
	if deleting {
		return out, ErrConflict
	}
	current, err := captureConfigurationDocumentTx(ctx, tx, c, v)
	if err != nil {
		return out, err
	}
	deployments, err := configurationRestoreDeployments(ctx, tx)
	if err != nil {
		return out, err
	}
	plan, err := prepareConfigurationRestore(doc, current, options)
	if err != nil {
		return out, err
	}
	var archiveProof, stateProof string
	if v == nil {
		return out, ErrConfigurationBackupKey
	}
	if archiveProof, err = configurationRestoreProof(v, v.active, "archive", user, revision, options, doc, common.JSON(id)); err != nil {
		return out, err
	}
	if stateProof, err = configurationRestoreProof(v, v.active, "state", user, revision, options, current, deployments); err != nil {
		return out, err
	}
	out.Token, out.Backup, out.Summary = token(), id, plan.Summary
	hash := digest([]byte(out.Token))
	if err = tx.QueryRowContext(ctx, `INSERT INTO v3_configuration_restore_previews(token_hash,username,account_revision,backup,options,archive_proof,state_proof,summary) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING expires_at`, hash, user, revision, id, common.JSON(options), archiveProof, stateProof, common.JSON(out.Summary)).Scan(&out.Expires); err != nil {
		return configurationRestorePreview{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference,expires_at) VALUES($1,'restore',$2,$3)`, id, "preview:"+hash, out.Expires); err != nil {
		return configurationRestorePreview{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-restore-preview',$2,$3)`, user, id, common.JSON(common.Map{"settings_version": current.SettingsVersion, "added": out.Summary.Added, "updated": out.Summary.Updated, "removed": out.Summary.Removed, "can_prepare": out.Summary.CanPrepare, "requires_local_validation": true})); err != nil {
		return configurationRestorePreview{}, err
	}
	return out, tx.Commit()
}

// Staging must call this after excluding every desired-state writer and
// deployment creator (the read-committed relation gate), or use a repeatable-read
// transaction for snapshot-only verification. A valid return revalidates a
// snapshot. It does not itself acquire that global exclusion,
// consume the preview, validate local files, stage, apply or authorize deployment.
func revalidateConfigurationRestoreTx(ctx context.Context, tx *sql.Tx, v *Vault, c Config, user, preview string) (configurationRestorePlan, error) {
	var empty configurationRestorePlan
	if !validArchiveSource(preview) || c.Validate() != nil {
		return empty, errConfigurationRestorePreview
	}
	revision, err := configurationRestoreAccount(ctx, tx, user)
	if err != nil {
		return empty, err
	}
	if held, err := migrationHeld(ctx, tx); err != nil {
		return empty, err
	} else if held {
		return empty, ErrMigrationPending
	}
	var id, archiveProof, stateProof string
	var accountRevision int64
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT backup,account_revision,options,archive_proof,state_proof FROM v3_configuration_restore_previews WHERE token_hash=$1 AND username=$2 AND expires_at>clock_timestamp() FOR UPDATE`, digest([]byte(preview)), user).Scan(&id, &accountRevision, &raw, &archiveProof, &stateProof)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, errConfigurationRestorePreview
	}
	if err != nil {
		return empty, err
	}
	var options configurationRestoreOptions
	if accountRevision != revision || json.Unmarshal(raw, &options) != nil {
		return empty, errConfigurationRestorePreview
	}
	doc, _, err := loadConfigurationBackup(ctx, tx, v, id, false)
	if err != nil {
		return empty, err
	}
	if !configurationRestoreProofMatches(v, archiveProof, "archive", user, revision, options, doc, common.JSON(id)) {
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
	// Never trust the stored summary as executable configuration.
	plan, err := prepareConfigurationRestore(doc, current, options)
	if err != nil {
		return empty, err
	}
	// Planning a large document may take time. Recheck the real database clock
	// after planning, including the preview's own source pin.
	var valid bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_configuration_restore_previews p JOIN v3_configuration_backup_pins b ON b.backup=p.backup AND b.kind='restore' AND b.reference='preview:'||p.token_hash WHERE p.token_hash=$1 AND p.expires_at>clock_timestamp() AND b.expires_at>clock_timestamp())`, digest([]byte(preview))).Scan(&valid)
	if err != nil {
		return empty, err
	}
	if !valid {
		return empty, errConfigurationRestorePreview
	}
	return plan, nil
}
