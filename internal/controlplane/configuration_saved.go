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

var errConfigurationSaved = errors.New("恢复提交或已保存配置校验失败，请重新预览；运行配置未修改")

type configurationSavedReceipt struct {
	Stage                 string              `json:"stage"`
	Revision              string              `json:"revision"`
	Generation            int64               `json:"generation,string"`
	Settings              settingsDraftState  `json:"settings"`
	Bootstrap             bootstrapDraftState `json:"bootstrap"`
	NodesChanged          int                 `json:"nodes_changed"`
	RequiresCenterRestart bool                `json:"requires_center_restart"`
	Status                string              `json:"status"`
	Message               string              `json:"message"`
	Created               time.Time           `json:"created_at"`
}

// Normalize through JSONB before signing: PostgreSQL legitimately rewrites
// number spellings. The authenticated candidate remains lossless; the saved
// proof describes the actual representation stored by all configuration tables.
func configurationSavedProofTx(ctx context.Context, tx *sql.Tx, v *Vault, key string, r privateConfigurationRevision, options configurationRestoreOptions, doc configurationDocument, result, deployments, archives []byte) (string, error) {
	if v == nil || len(v.receiptKeys[key]) == 0 {
		return "", ErrConfigurationBackupKey
	}
	doc.Created = "2000-01-01T00:00:00Z"
	type privateDocument configurationDocument
	raw, err := json.Marshal([]any{r.ID, r.Stage, r.Generation, r.Username, r.AccountRevision, options, privateDocument(doc), json.RawMessage(result), json.RawMessage(deployments), json.RawMessage(archives)})
	if err != nil {
		return "", errConfigurationSaved
	}
	defer clear(raw)
	var normalized []byte
	if err = tx.QueryRowContext(ctx, `SELECT $1::jsonb`, raw).Scan(&normalized); err != nil {
		return "", err
	}
	defer clear(normalized)
	value, err := common.Decode(normalized)
	if err != nil || !doc.complete() || doc.validate() != nil {
		return "", errConfigurationSaved
	}
	// Profile IDs are storage-local aliases. JSONB may also merge profiles
	// whose only difference was a number spelling. Bind their normalized body,
	// not an arbitrary p1/p2 name or empty/null omission-list representation.
	parts, ok := value.([]any)
	if !ok || len(parts) != 10 {
		return "", errConfigurationSaved
	}
	body := common.M(parts[6])
	delete(body, "Omitted")
	profiles := common.M(body["Profiles"])
	canonical := map[string]any{}
	aliases := map[string]string{}
	for id, raw := range profiles {
		p := common.M(raw)
		delete(p, "Omitted")
		hash := digest(common.JSON(p))
		aliases[id] = hash
		canonical[hash] = p
	}
	for _, raw := range common.M(body["Nodes"]) {
		n := common.M(raw)
		delete(n, "Omitted")
		alias, ok := aliases[common.S(n["Profile"])]
		if !ok {
			return "", errConfigurationSaved
		}
		n["Profile"] = alias
	}
	body["Profiles"] = canonical
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/configuration-saved/v1\x00"))
	h.Write(common.JSON(value))
	return key + ":" + hex.EncodeToString(h.Sum(nil)), nil
}

// Materialize an authenticated candidate into the real saved-state tables.
// Startup changes remain in PostgreSQL, settings remain drafts, and node
// snapshots are not published. No runtime workers, SSH or YAML writes run here.
func (s *Store) commitConfigurationRestoreSaved(ctx context.Context, v *Vault, c Config, user, key, stage string, generation int64) (json.RawMessage, error) {
	if !validArchiveSource(stage) || generation < 1 || c.Validate() != nil {
		return nil, errConfigurationSaved
	}
	op, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.guardedMutationOptions(op, &sql.TxOptions{Isolation: sql.LevelReadCommitted}, user, key, "configuration-restore-commit", stage, []any{stage, generation}, func(tx *sql.Tx) error {
		if err := lockConfigurationRestoreStateTx(op, tx); err != nil {
			return err
		}
		return configurationBackupAdmin(op, tx, user)
	}, func(tx *sql.Tx) (any, error) {
		var phase string
		if err := tx.QueryRowContext(op, `SELECT status FROM v3_configuration_restore_stages WHERE id=$1 AND username=$2 FOR UPDATE`, stage, user).Scan(&phase); err != nil {
			return nil, err
		}
		if phase == "saved" {
			receipt, _, err := loadSavedConfigurationTx(op, tx, v, c, user, stage, false)
			if err == nil && receipt.Generation != generation {
				return nil, errConfigurationSaved
			}
			return receipt, err
		}
		if phase != "pending_application" {
			return nil, errConfigurationSaved
		}
		plan, err := revalidateConfigurationStageTx(op, tx, v, c, user, stage)
		if err != nil {
			return nil, err
		}
		if !plan.Summary.CanPrepare {
			return nil, errConfigurationRestoreBlocked
		}
		// Revalidation already authenticated and locked this exact revision in
		// this transaction. Reuse it instead of decoding a large candidate twice.
		r := plan.Revision
		if r.Stage != stage || r.Generation != generation || r.Status != "pending_application" {
			return nil, errConfigurationSaved
		}
		report, err := checkConfigurationLocalMaterial(op, plan.Candidate, v, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		if !report.LocalChecksPassed {
			return nil, configurationLocalFailure{report}
		}
		settings, err := readSettingsDraftTx(op, tx, true)
		if err != nil {
			return nil, err
		}
		if err = checkSettingsDraftProof(v, settings); err != nil {
			return nil, err
		}
		bootstrap, err := readBootstrapDraftTx(op, tx, v, c)
		if err != nil {
			return nil, err
		}
		receipt := configurationSavedReceipt{Stage: stage, Revision: r.ID, Generation: generation, Settings: settings.settingsDraftState, Bootstrap: bootstrap.bootstrapDraftState,
			Status: "saved_pending_application", Message: "已恢复到保存配置，待应用；运行设置、中心进程及节点采集未切换", Created: time.Now().UTC()}
		if plan.Summary.SettingsChanged {
			receipt.Settings, err = putSettingsDraftTx(op, tx, v, common.JSON(plan.Candidate.Settings), settings.RuntimeVersion, settings.Runtime)
			if err != nil {
				return nil, err
			}
		}
		if plan.Summary.BootstrapChanged {
			receipt.Bootstrap, err = putBootstrapDraftTx(op, tx, v, c, plan.Candidate.Bootstrap)
			if err != nil {
				return nil, err
			}
		}
		receipt.RequiresCenterRestart = receipt.Bootstrap.Pending
		receipt.NodesChanged, err = materializeRestoredNodesTx(op, tx, plan, c.Collector.Shards)
		if err != nil {
			return nil, err
		}
		current, err := captureConfigurationDocumentTx(op, tx, c, v)
		if err != nil {
			return nil, err
		}
		deployments, err := configurationRestoreDeployments(op, tx)
		if err != nil {
			return nil, err
		}
		result := common.JSON(receipt)
		options, err := readConfigurationStageOptions(op, tx, stage)
		if err != nil {
			return nil, err
		}
		var source, before string
		if err = tx.QueryRowContext(op, `SELECT backup,before_backup FROM v3_configuration_restore_stages WHERE id=$1`, stage).Scan(&source, &before); err != nil {
			return nil, err
		}
		archives := common.JSON([]string{source, before})
		proof, err := configurationSavedProofTx(op, tx, v, v.active, r, options, current, result, deployments, archives)
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(op, `INSERT INTO v3_configuration_restore_commits(stage,revision,username,account_revision,result,deployments,archives,proof) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, stage, r.ID, user, r.AccountRevision, result, []byte(deployments), archives, proof); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(op, `UPDATE v3_configuration_revisions SET status='saved',message='已恢复到保存配置，待应用；运行配置未修改',updated_at=clock_timestamp(),finished_at=clock_timestamp() WHERE id=$1 AND status='pending_application'`, r.ID); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(op, `UPDATE v3_configuration_restore_stages SET status='saved',message='已恢复到保存配置，待应用；运行配置未修改',updated_at=clock_timestamp(),finished_at=clock_timestamp() WHERE id=$1 AND status='pending_application'`, stage); err != nil {
			return nil, err
		}
		pins, err := tx.ExecContext(op, `UPDATE v3_configuration_backup_pins SET kind='rollback',reference='restore:'||$1||CASE WHEN reference=$2 THEN ':source' ELSE ':before' END WHERE kind='restore' AND reference IN($2,$3)`, stage, "stage:"+stage+":source", "stage:"+stage+":before")
		if err != nil {
			return nil, err
		}
		count, err := pins.RowsAffected()
		if err != nil {
			return nil, err
		}
		if count != 2 {
			return nil, errConfigurationSaved
		}
		return receipt, nil
	})
}

// Read only an already validated server-side options row. Errors are returned
// by the helper's caller, never converted to an implicit default choice.
func readConfigurationStageOptions(ctx context.Context, tx *sql.Tx, stage string) (configurationRestoreOptions, error) {
	var options configurationRestoreOptions
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT options FROM v3_configuration_restore_stages WHERE id=$1`, stage).Scan(&raw); err != nil {
		return options, err
	}
	if json.Unmarshal(raw, &options) != nil {
		return options, errConfigurationSaved
	}
	return options, nil
}

// Reconstruct the originally saved state from the authenticated immutable
// candidate and safe receipt. Historical idempotent reads remain possible after
// later edits; an application check additionally compares the current state.
func loadSavedConfigurationTx(ctx context.Context, tx *sql.Tx, v *Vault, c Config, user, stage string, checkCurrent bool) (configurationSavedReceipt, configurationDocument, error) {
	return loadSavedConfigurationForApplicationTx(ctx, tx, v, c, user, stage, checkCurrent, nil)
}

// An application's exact, live authenticated lease can enter its own relation
// gate. This is not a generic bypass for editors or a client-supplied job ID.
func loadSavedConfigurationForApplicationTx(ctx context.Context, tx *sql.Tx, v *Vault, c Config, user, stage string, checkCurrent bool, application *privateConfigurationApplication) (configurationSavedReceipt, configurationDocument, error) {
	var out configurationSavedReceipt
	var empty configurationDocument
	if checkCurrent {
		gate := lockConfigurationRestoreStateTx
		if application != nil {
			gate = lockConfigurationRestoreRelationsTx
		}
		if err := gate(ctx, tx); err != nil {
			return out, empty, err
		}
		if application != nil {
			if application.Username != user || application.Stage != stage || application.Direction != "forward" || application.step != 0 {
				return out, empty, errConfigurationApplication
			}
			if _, err := lockedApplication(ctx, tx, v, *application); err != nil {
				return out, empty, err
			}
		}
	}
	account, err := configurationRestoreAccount(ctx, tx, user)
	if err != nil {
		return out, empty, err
	}
	return authenticateSavedConfigurationTx(ctx, tx, v, c, user, stage, account, checkCurrent)
}

// The caller supplies historical authority only after authenticating an exact
// live application lease and its current controller. This validates immutable
// evidence; it never grants the former account permission to execute work.
func authenticateSavedConfigurationTx(ctx context.Context, tx *sql.Tx, v *Vault, c Config, user, stage string, account int64, checkCurrent bool) (configurationSavedReceipt, configurationDocument, error) {
	var out configurationSavedReceipt
	var empty configurationDocument
	r, doc, err := loadConfigurationRevisionTx(ctx, tx, v, stage)
	if err != nil {
		return out, empty, err
	}
	if r.Username != user || r.AccountRevision != account || r.Status != "saved" {
		return out, empty, errConfigurationSaved
	}
	options, err := readConfigurationStageOptions(ctx, tx, stage)
	if err != nil {
		return out, empty, err
	}
	if !configurationRestoreProofMatches(v, r.CandidateProof, "candidate", user, account, options, doc, common.JSON([]any{r.ID, r.Stage, r.Generation})) {
		return out, empty, errConfigurationSaved
	}
	var result, deployments, summary, archives []byte
	var proof, owner, revision, phase string
	var rev int64
	err = tx.QueryRowContext(ctx, `SELECT j.result,j.deployments,j.proof,j.username,j.account_revision,j.revision,s.summary,s.status,j.archives FROM v3_configuration_restore_commits j JOIN v3_configuration_restore_stages s ON s.id=j.stage WHERE j.stage=$1 FOR SHARE OF j,s`, stage).Scan(&result, &deployments, &proof, &owner, &rev, &revision, &summary, &phase, &archives)
	if err != nil {
		return out, empty, err
	}
	if json.Unmarshal(result, &out) != nil || out.Stage != stage || out.Revision != r.ID || out.Generation != r.Generation || out.Status != "saved_pending_application" || owner != user || rev != account || revision != r.ID || phase != "saved" {
		return out, empty, errConfigurationSaved
	}
	var changes configurationRestoreSummary
	if json.Unmarshal(summary, &changes) != nil {
		return out, empty, errConfigurationSaved
	}
	for _, change := range changes.Nodes {
		n, exists := doc.Nodes[change.Node]
		if !exists {
			return out, empty, errConfigurationSaved
		}
		switch change.Action {
		case "update":
			n.Version++
		case "add":
		default:
			return out, empty, errConfigurationSaved
		}
		doc.Nodes[change.Node] = n
	}
	doc.SettingsGeneration = out.Settings.Generation
	doc.BootstrapGeneration = out.Bootstrap.Generation
	id, _, ok := strings.Cut(proof, ":")
	if !ok {
		return out, empty, errConfigurationSaved
	}
	expected, err := configurationSavedProofTx(ctx, tx, v, id, r, options, doc, result, deployments, archives)
	if err != nil || !hmac.Equal([]byte(expected), []byte(proof)) {
		return out, empty, errConfigurationSaved
	}
	if checkCurrent {
		if err := validateSavedConfigurationArchivesTx(ctx, tx, v, r, options, archives, deployments); err != nil {
			return out, empty, err
		}
		current, err := captureConfigurationDocumentTx(ctx, tx, c, v)
		if err != nil {
			return out, empty, err
		}
		live, err := configurationRestoreDeployments(ctx, tx)
		if err != nil {
			return out, empty, err
		}
		expected, err = configurationSavedProofTx(ctx, tx, v, id, r, options, current, result, live, archives)
		if err != nil || !hmac.Equal([]byte(expected), []byte(proof)) {
			return out, empty, errConfigurationSaved
		}
	}
	return out, doc, nil
}

func validateSavedConfigurationArchivesTx(ctx context.Context, tx *sql.Tx, v *Vault, r privateConfigurationRevision, options configurationRestoreOptions, archives, deployments []byte) error {
	var ids []string
	if json.Unmarshal(archives, &ids) != nil || len(ids) != 2 || !validArchiveSource(ids[0]) || !validArchiveSource(ids[1]) {
		return errConfigurationSaved
	}
	var source, before, archiveProof, owner string
	var account int64
	if err := tx.QueryRowContext(ctx, `SELECT backup,before_backup,archive_proof,username,account_revision FROM v3_configuration_restore_stages WHERE id=$1`, r.Stage).Scan(&source, &before, &archiveProof, &owner, &account); err != nil {
		return err
	}
	if source != ids[0] || before != ids[1] || owner != r.Username || account != r.AccountRevision {
		return errConfigurationSaved
	}
	doc, _, err := loadConfigurationBackup(ctx, tx, v, source, false)
	if err != nil {
		return err
	}
	if !configurationRestoreProofMatches(v, archiveProof, "archive", r.Username, r.AccountRevision, options, doc, common.JSON(source)) {
		return errConfigurationSaved
	}
	doc, _, err = loadConfigurationBackup(ctx, tx, v, before, false)
	if err != nil {
		return err
	}
	if !configurationRestoreProofMatches(v, r.StateProof, "state", r.Username, r.AccountRevision, options, doc, deployments) {
		return errConfigurationSaved
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_configuration_backup_pins WHERE kind='rollback' AND expires_at IS NULL AND ((backup=$1 AND reference=$3) OR (backup=$2 AND reference=$4))`, source, before, "restore:"+r.Stage+":source", "restore:"+r.Stage+":before").Scan(&count); err != nil {
		return err
	}
	if count != 2 {
		return errConfigurationSaved
	}
	return nil
}
