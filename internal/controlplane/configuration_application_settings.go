package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"webscan/internal/common"
)

const configurationApplicationSettingsSchema = `
CREATE TABLE v3_configuration_application_settings(
 job text NOT NULL REFERENCES v3_configuration_applications(id),
 phase text NOT NULL CHECK(phase IN ('settings','restore-settings')),
 key_id text NOT NULL,nonce bytea NOT NULL,ciphertext bytea NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(job,phase),CHECK(octet_length(ciphertext) BETWEEN 17 AND 10485776)
);
INSERT INTO v3_schema(version) VALUES(23);
`

// These receipts contain credentials and therefore have no public projection.
// Encryption binds the exact immutable application plan, independently of its
// replaceable process/epoch. A receipt survives takeover but is not authority.
type applicationSettingsSnapshot privateSettingsDraft
type privateApplicationSettingsReceipt struct {
	Epoch         int64
	Before, After applicationSettingsSnapshot
}

func (privateApplicationSettingsReceipt) String() string {
	return "[private settings application receipt]"
}
func (privateApplicationSettingsReceipt) GoString() string {
	return "[private settings application receipt]"
}
func (privateApplicationSettingsReceipt) MarshalJSON() ([]byte, error) {
	return nil, errConfigurationApplication
}

func applicationSettingsAAD(j privateConfigurationApplication, phase, key string) []byte {
	return common.JSON([]any{"webscan-v3/configuration-application/settings/v1", j.ID, j.planProof, j.Stage, j.Generation, j.member, phase, key})
}

func readApplicationSettingsTx(ctx context.Context, tx *sql.Tx, v *Vault, j privateConfigurationApplication, phase string) (privateApplicationSettingsReceipt, error) {
	var r privateApplicationSettingsReceipt
	var key string
	var nonce, sealed []byte
	if err := tx.QueryRowContext(ctx, `SELECT key_id,nonce,ciphertext FROM v3_configuration_application_settings WHERE job=$1 AND phase=$2 FOR SHARE`, j.ID, phase).Scan(&key, &nonce, &sealed); err != nil {
		return r, err
	}
	if v == nil || v.keys[key] == nil || len(nonce) != v.keys[key].NonceSize() || len(sealed) < 17 || len(sealed) > (10<<20)+16 {
		return r, errConfigurationApplication
	}
	raw, err := v.keys[key].Open(nil, nonce, sealed, applicationSettingsAAD(j, phase, key))
	if err != nil {
		return r, errConfigurationApplication
	}
	defer clear(raw)
	type body privateApplicationSettingsReceipt
	if json.Unmarshal(raw, (*body)(&r)) != nil || r.Epoch < 1 || r.Epoch > j.epoch || !validApplicationSettingsSnapshot(r.Before) || !validApplicationSettingsSnapshot(r.After) {
		return privateApplicationSettingsReceipt{}, errConfigurationApplication
	}
	return r, nil
}

func validApplicationSettingsSnapshot(s applicationSettingsSnapshot) bool {
	return s.Generation >= 0 && s.AppliedGeneration >= 0 && s.AppliedGeneration <= s.Generation && s.RuntimeVersion > 0 && s.BaseRuntime == s.RuntimeVersion && len(s.Desired) <= 2<<20 && len(s.Runtime) <= 2<<20 && json.Valid(s.Desired) && json.Valid(s.Runtime)
}

func writeApplicationSettingsTx(ctx context.Context, tx *sql.Tx, v *Vault, j privateConfigurationApplication, before, after privateSettingsDraft) error {
	if v == nil || v.keys[v.active] == nil {
		return errConfigurationApplication
	}
	r := privateApplicationSettingsReceipt{j.epoch, applicationSettingsSnapshot(before), applicationSettingsSnapshot(after)}
	if !validApplicationSettingsSnapshot(r.Before) || !validApplicationSettingsSnapshot(r.After) {
		return errConfigurationApplication
	}
	type body privateApplicationSettingsReceipt
	raw, err := json.Marshal(body(r))
	if err != nil || len(raw) > 10<<20 {
		clear(raw)
		return errConfigurationApplication
	}
	defer clear(raw)
	aead := v.keys[v.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return errConfigurationApplication
	}
	sealed := aead.Seal(nil, nonce, raw, applicationSettingsAAD(j, j.phase(), v.active))
	defer clear(sealed)
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_configuration_application_settings(job,phase,key_id,nonce,ciphertext) VALUES($1,$2,$3,$4,$5)`, j.ID, j.phase(), v.active, nonce, sealed); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-application-settings',$2,$3)`, j.Controller, j.ID, common.JSON(map[string]any{"phase": j.phase(), "runtime_version": after.RuntimeVersion, "pending": after.Pending}))
	return err
}

func sameApplicationSettings(a, b privateSettingsDraft) bool {
	return a.Generation == b.Generation && a.AppliedGeneration == b.AppliedGeneration && a.RuntimeVersion == b.RuntimeVersion && a.BaseRuntime == b.BaseRuntime && a.BaseDigest == b.BaseDigest && configurationJSONEqual(a.Desired, b.Desired) && configurationJSONEqual(a.Runtime, b.Runtime)
}

// The settings phase changes the actual policy read by workers. Its encrypted
// before/after receipt and audit commit in the SAME transaction as that change.
// It intentionally supports no nodes/bootstrap/verify phase and is not enabled
// in Serve until the complete application/rollback runtime exists.
type configurationSettingsRuntime struct {
	store     *Store
	vault     *Vault
	bootstrap Config
}

func (r configurationSettingsRuntime) SupportsConfigurationPhase(phase string) bool {
	return phase == "settings" || phase == "restore-settings"
}
func (r configurationSettingsRuntime) InspectConfigurationPhase(ctx context.Context, j privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	return r.settingsPhase(ctx, j, false)
}
func (r configurationSettingsRuntime) ApplyConfigurationPhase(ctx context.Context, j privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	return r.settingsPhase(ctx, j, true)
}

func (r configurationSettingsRuntime) settingsPhase(ctx context.Context, expected privateConfigurationApplication, apply bool) (configurationApplicationCheckpoint, error) {
	var empty configurationApplicationCheckpoint
	if r.store == nil || r.vault == nil || !r.SupportsConfigurationPhase(expected.phase()) || r.bootstrap.Validate() != nil || expected.member != r.bootstrap.Central.Instance {
		return empty, errConfigurationApplication
	}
	op, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := r.store.DB.BeginTx(op, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if held, e := migrationHeld(op, tx); e != nil {
		return empty, e
	} else if held {
		return empty, ErrMigrationPending
	}
	j, err := lockedApplication(op, tx, r.vault, expected)
	if err != nil {
		return empty, err
	}
	if j.member != r.bootstrap.Central.Instance || !j.RecoveryRequired || j.Direction == "forward" && j.phase() != "settings" || j.Direction == "rollback" && j.phase() != "restore-settings" {
		return empty, errConfigurationApplication
	}
	saved, doc, err := applicationSavedEvidenceTx(op, tx, r.vault, j)
	if err != nil {
		return empty, err
	}
	d, err := readSettingsDraftTx(op, tx, true)
	if err != nil {
		return empty, err
	}
	if err = checkSettingsDraftProof(r.vault, d); err != nil {
		return empty, err
	}
	receipt, err := readApplicationSettingsTx(op, tx, r.vault, j, j.phase())
	if err == nil {
		if !sameApplicationSettings(d, privateSettingsDraft(receipt.After)) {
			return empty, errConfigurationApplication
		}
		return configurationApplicationCheckpoint{j.ID, j.planProof, j.phase(), "complete", j.epoch}, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return empty, err
	}
	var forward privateApplicationSettingsReceipt
	if j.Direction == "rollback" {
		forward, err = readApplicationSettingsTx(op, tx, r.vault, j, "settings")
		if err == nil {
			if !sameApplicationSettings(d, privateSettingsDraft(forward.After)) {
				return empty, errConfigurationApplication
			}
		} else if !errors.Is(err, sql.ErrNoRows) || j.step > 3 {
			return empty, errConfigurationApplication
		}
	}
	// No committed effect: verify the exact saved generation and original live
	// version. Neither drift nor a missing receipt means implicit success.
	if j.Direction == "forward" || errors.Is(err, sql.ErrNoRows) {
		if d.Generation != saved.Settings.Generation || d.AppliedGeneration != saved.Settings.AppliedGeneration || d.RuntimeVersion != saved.Settings.RuntimeVersion || !configurationJSONEqual(d.Desired, common.JSON(doc.Settings)) || validateSettingsDraft(r.bootstrap, d.Desired) != nil {
			return empty, errConfigurationApplication
		}
	}
	if !apply {
		return configurationApplicationCheckpoint{j.ID, j.planProof, j.phase(), "absent", j.epoch}, tx.Commit()
	}
	before := d
	if j.Direction == "forward" && d.Pending {
		if _, err = applySettingsDraftTx(op, tx, &configurationEditBackup{vault: r.vault, bootstrap: r.bootstrap}, d); err != nil {
			return empty, err
		}
	} else if j.Direction == "rollback" && forward.Epoch > 0 && !sameApplicationSettings(privateSettingsDraft(forward.Before), privateSettingsDraft(forward.After)) {
		// Keep the restored desired draft available for review, but restore the
		// frozen original runtime. No generation is reused and runtime versions
		// advance, so old worker/configuration requests cannot overwrite it.
		base := privateSettingsDraft(forward.Before)
		if validateSettingsDraft(r.bootstrap, base.Runtime) != nil {
			return empty, errConfigurationApplication
		}
		if _, err = tx.ExecContext(op, `UPDATE v3_settings SET version=version+1,payload=$1,updated_at=clock_timestamp() WHERE id=1`, []byte(base.Runtime)); err != nil {
			return empty, err
		}
		baseDigest, e := settingsPayloadDigest(base.Runtime)
		if e != nil {
			return empty, e
		}
		proof, e := settingsDraftProof(r.vault, r.vault.active, d.Generation, d.RuntimeVersion+1, baseDigest, d.Desired)
		if e != nil {
			return empty, e
		}
		if _, err = tx.ExecContext(op, `UPDATE v3_settings_drafts SET applied_generation=$1,runtime_version=$2,runtime_digest=$3,proof=$4,updated_at=clock_timestamp() WHERE id=1`, base.AppliedGeneration, d.RuntimeVersion+1, baseDigest, proof); err != nil {
			return empty, err
		}
	}
	after, err := readSettingsDraftTx(op, tx, false)
	if err != nil {
		return empty, err
	}
	if err = checkSettingsDraftProof(r.vault, after); err != nil {
		return empty, err
	}
	// An effect that ran past its lease is rolled back with the transaction.
	// Relation/row locks serialize takeovers, while this final check prevents
	// slow database work from committing under an expired execution lease.
	if _, err = lockedApplication(op, tx, r.vault, j); err != nil {
		return empty, err
	}
	if err = writeApplicationSettingsTx(op, tx, r.vault, j, before, after); err != nil {
		return empty, err
	}
	return configurationApplicationCheckpoint{j.ID, j.planProof, j.phase(), "complete", j.epoch}, tx.Commit()
}
