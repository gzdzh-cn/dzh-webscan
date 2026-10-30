package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"webscan/internal/common"
)

var errConfigurationRevision = errors.New("待应用配置校验失败或基准已变化，请取消原恢复并重新预览；运行配置未修改")

// Generation orders saved candidates; it is not an active settings/node version
// and does not claim delivery/application. Public clients must retain it exactly.
type configurationRevision struct {
	ID                  string     `json:"id"`
	Generation          int64      `json:"generation,string"`
	Stage               string     `json:"stage"`
	Username            string     `json:"username"`
	BaseSettingsVersion int64      `json:"base_settings_version"`
	Status              string     `json:"status"`
	Message             string     `json:"message"`
	Created             time.Time  `json:"created_at"`
	Updated             time.Time  `json:"updated_at"`
	Finished            *time.Time `json:"finished_at"`
}

type privateConfigurationRevision struct {
	configurationRevision
	AccountRevision int64
	DocumentCreated string
	NodeCount       int
	CandidateProof  string
	StateProof      string
	KeyID           string
	Nonce           []byte
	Bytes           int
}

func (privateConfigurationRevision) String() string   { return "[private pending configuration]" }
func (privateConfigurationRevision) GoString() string { return "[private pending configuration]" }
func (privateConfigurationRevision) MarshalJSON() ([]byte, error) {
	return nil, errConfigurationRevision
}

const configurationRevisionColumns = `id,generation,stage,username,base_settings_version,status,message,created_at,updated_at,finished_at`

func scanConfigurationRevision(row interface{ Scan(...any) error }) (r configurationRevision, err error) {
	err = row.Scan(&r.ID, &r.Generation, &r.Stage, &r.Username, &r.BaseSettingsVersion, &r.Status, &r.Message, &r.Created, &r.Updated, &r.Finished)
	return
}

func configurationRevisionAAD(r privateConfigurationRevision) []byte {
	return common.JSON([]any{"webscan-v3/configuration-revision/v1", r.ID, r.Generation, r.Stage, r.Username, r.AccountRevision, r.BaseSettingsVersion, r.DocumentCreated, r.NodeCount, r.CandidateProof, r.StateProof, r.KeyID})
}

// A failure carries only the safe local diagnostic, never the candidate.
type configurationLocalFailure struct{ Report configurationLocalReport }

func (configurationLocalFailure) Error() string {
	return "本机资料检查未通过；待应用配置未保存，运行配置未修改"
}

// saveConfigurationRestorePending is a real durable candidate save, separate
// from all tables read by live workers. It is internal until the complete apply
// workflow exists. A successful local report is never accepted as an input.
func (s *Store) saveConfigurationRestorePending(ctx context.Context, v *Vault, c Config, user, key, stage string) (json.RawMessage, error) {
	if !validArchiveSource(stage) || c.Validate() != nil {
		return nil, errConfigurationRevision
	}
	op, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.guardedMutationOptions(op, &sql.TxOptions{Isolation: sql.LevelReadCommitted}, user, key, "configuration-restore-save", stage, []string{stage}, func(tx *sql.Tx) error {
		if err := lockConfigurationRestoreStateTx(op, tx); err != nil {
			return err
		}
		return configurationBackupAdmin(op, tx, user)
	}, func(tx *sql.Tx) (any, error) {
		plan, err := revalidateConfigurationStageTx(op, tx, v, c, user, stage)
		if err != nil {
			return nil, err
		}
		if !plan.Summary.CanPrepare {
			return nil, errConfigurationRestoreBlocked
		}
		report, err := checkConfigurationLocalMaterial(op, plan.Candidate, v, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		if !report.LocalChecksPassed {
			return nil, configurationLocalFailure{report}
		}
		var phase string
		if err = tx.QueryRowContext(op, `SELECT status FROM v3_configuration_restore_stages WHERE id=$1`, stage).Scan(&phase); err != nil {
			return nil, err
		}
		if phase == "pending_application" {
			// Another explicitly keyed confirmation still cannot create a second
			// candidate. Revalidation above checked the stored authenticated body.
			return scanConfigurationRevision(tx.QueryRowContext(op, `SELECT `+configurationRevisionColumns+` FROM v3_configuration_revisions WHERE stage=$1 AND status='pending_application'`, stage))
		}
		if phase != "pending_validation" {
			return nil, errConfigurationRevision
		}
		var r privateConfigurationRevision
		r.ID, r.Stage, r.Username = token(), stage, user
		r.BaseSettingsVersion = plan.Candidate.SettingsVersion
		r.DocumentCreated, r.NodeCount = plan.Candidate.Created, len(plan.Candidate.Nodes)
		err = tx.QueryRowContext(op, `SELECT account_revision,state_proof FROM v3_configuration_restore_stages WHERE id=$1`, stage).Scan(&r.AccountRevision, &r.StateProof)
		if err != nil {
			return nil, err
		}
		if err = tx.QueryRowContext(op, `SELECT nextval(pg_get_serial_sequence('v3_configuration_revisions','generation'))`).Scan(&r.Generation); err != nil {
			return nil, err
		}
		var rawOptions []byte
		if err = tx.QueryRowContext(op, `SELECT options FROM v3_configuration_restore_stages WHERE id=$1`, stage).Scan(&rawOptions); err != nil {
			return nil, err
		}
		var options configurationRestoreOptions
		if json.Unmarshal(rawOptions, &options) != nil {
			return nil, errConfigurationRevision
		}
		r.CandidateProof, err = configurationRestoreProof(v, v.active, "candidate", user, r.AccountRevision, options, plan.Candidate, common.JSON([]any{r.ID, r.Stage, r.Generation}))
		if err != nil {
			return nil, err
		}
		return insertConfigurationRevisionTx(op, tx, v, r, plan.Candidate)
	})
}

func insertConfigurationRevisionTx(ctx context.Context, tx *sql.Tx, v *Vault, r privateConfigurationRevision, doc configurationDocument) (configurationRevision, error) {
	var empty configurationRevision
	if v == nil || v.keys[v.active] == nil {
		return empty, ErrConfigurationBackupKey
	}
	raw, err := marshalConfigurationDocument(doc)
	if err != nil {
		return empty, err
	}
	defer clear(raw)
	aead := v.keys[v.active]
	r.KeyID = v.active
	r.Nonce = make([]byte, aead.NonceSize())
	if _, err = rand.Read(r.Nonce); err != nil {
		return empty, errConfigurationRevision
	}
	sealed := aead.Seal(nil, r.Nonce, raw, configurationRevisionAAD(r))
	defer clear(sealed)
	r.Bytes = len(sealed)
	out, err := scanConfigurationRevision(tx.QueryRowContext(ctx, `INSERT INTO v3_configuration_revisions(id,generation,stage,username,account_revision,base_settings_version,document_created_at,node_count,candidate_proof,state_proof,key_id,nonce,ciphertext_bytes)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING `+configurationRevisionColumns, r.ID, r.Generation, r.Stage, r.Username, r.AccountRevision, r.BaseSettingsVersion, r.DocumentCreated, r.NodeCount, r.CandidateProof, r.StateProof, r.KeyID, r.Nonce, r.Bytes))
	if err != nil {
		return empty, err
	}
	for part, offset := 0, 0; offset < len(sealed); part, offset = part+1, offset+configurationBackupPartSize {
		end := min(offset+configurationBackupPartSize, len(sealed))
		if _, err = tx.ExecContext(ctx, `INSERT INTO v3_configuration_revision_parts(revision,part,payload) VALUES($1,$2,$3)`, r.ID, part, sealed[offset:end]); err != nil {
			return empty, err
		}
	}
	res, err := tx.ExecContext(ctx, `UPDATE v3_configuration_restore_stages SET status='pending_application',message='恢复配置已保存，待应用；运行配置未修改',updated_at=clock_timestamp() WHERE id=$1 AND status='pending_validation'`, r.Stage)
	if err != nil {
		return empty, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return empty, errConfigurationRevision
	}
	return out, nil
}

func loadConfigurationRevisionTx(ctx context.Context, tx *sql.Tx, v *Vault, stage string) (privateConfigurationRevision, configurationDocument, error) {
	var r privateConfigurationRevision
	var empty configurationDocument
	err := tx.QueryRowContext(ctx, `SELECT id,generation,stage,username,base_settings_version,status,message,created_at,updated_at,finished_at,account_revision,document_created_at,node_count,candidate_proof,state_proof,key_id,nonce,ciphertext_bytes FROM v3_configuration_revisions WHERE stage=$1 FOR SHARE`, stage).Scan(&r.ID, &r.Generation, &r.Stage, &r.Username, &r.BaseSettingsVersion, &r.Status, &r.Message, &r.Created, &r.Updated, &r.Finished, &r.AccountRevision, &r.DocumentCreated, &r.NodeCount, &r.CandidateProof, &r.StateProof, &r.KeyID, &r.Nonce, &r.Bytes)
	if err != nil {
		return r, empty, err
	}
	if v == nil || v.keys[r.KeyID] == nil || r.Bytes < 17 || r.Bytes > configurationDocumentLimit+16 || len(r.Nonce) != v.keys[r.KeyID].NonceSize() {
		return r, empty, ErrConfigurationBackupKey
	}
	rows, err := tx.QueryContext(ctx, `SELECT part,payload FROM v3_configuration_revision_parts WHERE revision=$1 ORDER BY part`, r.ID)
	if err != nil {
		return r, empty, err
	}
	defer rows.Close()
	sealed := make([]byte, 0, r.Bytes)
	defer func() { clear(sealed) }()
	part := 0
	for rows.Next() {
		var index int
		var raw []byte
		if err = rows.Scan(&index, &raw); err != nil {
			return r, empty, err
		}
		if index != part || len(raw) < 1 || len(raw) > configurationBackupPartSize || len(sealed)+len(raw) > r.Bytes {
			return r, empty, ErrConfigurationBackupKey
		}
		sealed = append(sealed, raw...)
		part++
	}
	if err = rows.Err(); err != nil {
		return r, empty, err
	}
	if len(sealed) != r.Bytes || part != (r.Bytes+configurationBackupPartSize-1)/configurationBackupPartSize {
		return r, empty, ErrConfigurationBackupKey
	}
	raw, err := v.keys[r.KeyID].Open(nil, r.Nonce, sealed, configurationRevisionAAD(r))
	if err != nil {
		return r, empty, ErrConfigurationBackupKey
	}
	defer clear(raw)
	doc, err := parseConfigurationDocument(raw)
	if err != nil || !doc.complete() || doc.Created != r.DocumentCreated || doc.SettingsVersion != r.BaseSettingsVersion || len(doc.Nodes) != r.NodeCount {
		return r, empty, ErrConfigurationBackupKey
	}
	return r, doc, nil
}

// Recompute from authenticated source/baseline first; only then compare the
// stored candidate. A database summary, ciphertext swap, partial body or state
// change cannot redirect a later apply. Capture timestamps are not versions.
func validateConfigurationRevisionTx(ctx context.Context, tx *sql.Tx, v *Vault, stage, user string, account int64, options configurationRestoreOptions, stateProof string, want configurationDocument) (privateConfigurationRevision, configurationDocument, error) {
	r, doc, err := loadConfigurationRevisionTx(ctx, tx, v, stage)
	if err != nil {
		return privateConfigurationRevision{}, configurationDocument{}, err
	}
	evidence := common.JSON([]any{r.ID, r.Stage, r.Generation})
	if r.Status != "pending_application" || r.Stage != stage || r.Username != user || r.AccountRevision != account || !hmac.Equal([]byte(stateProof), []byte(r.StateProof)) || !configurationRestoreProofMatches(v, r.CandidateProof, "candidate", user, account, options, doc, evidence) || !configurationRestoreProofMatches(v, r.CandidateProof, "candidate", user, account, options, want, evidence) {
		return privateConfigurationRevision{}, configurationDocument{}, errConfigurationRevision
	}
	return r, doc, nil
}

// Safe current status, distinct from historical idempotency receipts. Other
// current administrators may inspect/cancel an abandoned intent, not apply it.
func (s *Store) configurationRevision(ctx context.Context, user, id string) (configurationRevision, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return configurationRevision{}, err
	}
	defer tx.Rollback()
	if err = configurationBackupAdmin(ctx, tx, user); err != nil {
		return configurationRevision{}, err
	}
	if !validArchiveSource(id) {
		return configurationRevision{}, sql.ErrNoRows
	}
	r, err := scanConfigurationRevision(tx.QueryRowContext(ctx, `SELECT `+configurationRevisionColumns+` FROM v3_configuration_revisions WHERE id=$1 FOR SHARE`, id))
	if err != nil {
		return configurationRevision{}, err
	}
	return r, tx.Commit()
}
