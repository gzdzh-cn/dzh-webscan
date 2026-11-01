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

var errSettingsDraft = errors.New("待应用设置或运行版本已变化，请重新读取并确认；运行设置未修改")

type settingsDraftState struct {
	Generation        int64     `json:"generation,string"`
	AppliedGeneration int64     `json:"applied_generation,string"`
	RuntimeVersion    int64     `json:"runtime_version"`
	Pending           bool      `json:"pending"`
	Updated           time.Time `json:"updated_at"`
}

type privateSettingsDraft struct {
	settingsDraftState
	BaseRuntime int64
	BaseDigest  string
	Desired     json.RawMessage
	Runtime     json.RawMessage
	Proof       string
}

func (privateSettingsDraft) String() string               { return "[private settings draft]" }
func (privateSettingsDraft) GoString() string             { return "[private settings draft]" }
func (privateSettingsDraft) MarshalJSON() ([]byte, error) { return nil, errSettingsDraft }

// Call after the configuration relation gate for writes. Lock the always-present
// live row first: two writers cannot race to create the initially absent draft.
func readSettingsDraftTx(ctx context.Context, tx *sql.Tx, lock bool) (privateSettingsDraft, error) {
	var d privateSettingsDraft
	query := `SELECT s.version,s.payload,COALESCE(d.generation,0),COALESCE(d.applied_generation,0),COALESCE(d.runtime_version,s.version),COALESCE(d.payload,s.payload),COALESCE(d.updated_at,s.updated_at),COALESCE(d.proof,''),COALESCE(d.runtime_digest,'') FROM v3_settings s LEFT JOIN v3_settings_drafts d ON d.id=s.id WHERE s.id=1`
	if lock {
		query += ` FOR UPDATE OF s`
	}
	err := tx.QueryRowContext(ctx, query).Scan(&d.RuntimeVersion, &d.Runtime, &d.Generation, &d.AppliedGeneration, &d.BaseRuntime, &d.Desired, &d.Updated, &d.Proof, &d.BaseDigest)
	d.Pending = d.Generation > d.AppliedGeneration
	return d, err
}

func settingsDraftProof(v *Vault, keyID string, generation, base int64, baseDigest string, raw []byte) (string, error) {
	if v == nil || len(v.receiptKeys[keyID]) == 0 {
		return "", ErrConfigurationBackupKey
	}
	var normalized configurationValues
	if decodeConfigurationObject(raw, &normalized) != nil {
		return "", errSettingsDraft
	}
	h := hmac.New(sha256.New, v.receiptKeys[keyID])
	h.Write([]byte("webscan-v3/settings-draft/v1\x00"))
	h.Write(common.JSON([]any{generation, base, baseDigest, normalized}))
	return keyID + ":" + hex.EncodeToString(h.Sum(nil)), nil
}
func checkSettingsDraftProof(v *Vault, d privateSettingsDraft) error {
	if d.Generation == 0 {
		return nil
	}
	if d.BaseRuntime != d.RuntimeVersion {
		return errSettingsDraft
	}
	id, _, ok := strings.Cut(d.Proof, ":")
	if !ok {
		return errSettingsDraft
	}
	proof, err := settingsDraftProof(v, id, d.Generation, d.BaseRuntime, d.BaseDigest, d.Desired)
	if err != nil || !hmac.Equal([]byte(proof), []byte(d.Proof)) {
		return errSettingsDraft
	}
	if hash, e := settingsPayloadDigest(d.Runtime); e != nil || hash != d.BaseDigest {
		return errSettingsDraft
	}
	if d.AppliedGeneration == d.Generation && !configurationJSONEqual(d.Desired, d.Runtime) {
		return errSettingsDraft
	}
	return nil
}
func configurationJSONEqual(a, b []byte) bool {
	var x, y configurationValues
	return decodeConfigurationObject(a, &x) == nil && decodeConfigurationObject(b, &y) == nil && configurationRestoreEqual(x, y)
}

func settingsPayloadDigest(raw []byte) (string, error) {
	var m configurationValues
	if err := decodeConfigurationObject(raw, &m); err != nil {
		return "", err
	}
	return digest(common.JSON(m)), nil
}

func putSettingsDraftTx(ctx context.Context, tx *sql.Tx, v *Vault, raw []byte, runtimeVersion int64, runtimeRaw []byte) (settingsDraftState, error) {
	var d settingsDraftState
	var stored []byte
	if v == nil {
		return d, ErrConfigurationBackupKey
	}
	baseDigest, err := settingsPayloadDigest(runtimeRaw)
	if err != nil {
		return d, err
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO v3_settings_drafts(id,runtime_version,payload,proof,runtime_digest) VALUES(1,$1,$2,'',$3)
 ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,runtime_version=excluded.runtime_version,runtime_digest=excluded.runtime_digest,payload=excluded.payload,updated_at=clock_timestamp()
 RETURNING generation,applied_generation,runtime_version,updated_at,payload`, runtimeVersion, raw, baseDigest).Scan(&d.Generation, &d.AppliedGeneration, &d.RuntimeVersion, &d.Updated, &stored)
	if err != nil {
		return d, err
	}
	// JSONB normalizes exponents and negative zero. Authenticate the exact
	// stored representation, so a valid client number cannot invalidate its
	// own proof when PostgreSQL reads it back. UseNumber preserves precision.
	proof, err := settingsDraftProof(v, v.active, d.Generation, runtimeVersion, baseDigest, stored)
	if err != nil {
		return d, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE v3_settings_drafts SET proof=$1 WHERE id=1`, proof)
	d.Pending = d.Generation > d.AppliedGeneration
	return d, err
}

func validateSettingsDraft(c Config, raw []byte) error {
	// Reuse the complete configuration codec, including strict object parsing,
	// notification parameters, retention ranges and credential-mask rejection.
	if _, err := newConfigurationDocument(c, raw, 1, nil, time.Now().UTC()); err != nil {
		return errConfigurationDocument
	}
	return nil
}

// Internal primitive for ordinary settings and authenticated configuration
// restore. Public form/restore handlers still need their own account-bound
// preview. Neither save nor this receipt starts a notifier or deployment.
func (s *Store) saveSettingsDraft(ctx context.Context, user, key string, raw []byte, expectedGeneration, expectedRuntime int64, before *configurationEditBackup) (json.RawMessage, error) {
	if before == nil || before.vault == nil || expectedGeneration < 0 || expectedRuntime < 1 || len(raw) > 2<<20 || validateSettingsDraft(before.bootstrap, raw) != nil {
		return nil, errSettingsDraft
	}
	input := []any{digest(raw), expectedGeneration, expectedRuntime}
	return s.guardedMutation(ctx, user, key, "settings-save", "settings", input, func(tx *sql.Tx) error {
		return before.lock(ctx, tx, user)
	}, func(tx *sql.Tx) (any, error) {
		d, err := readSettingsDraftTx(ctx, tx, true)
		if err != nil {
			return nil, err
		}
		if err = checkSettingsDraftProof(before.vault, d); err != nil {
			return nil, err
		}
		if d.Generation != expectedGeneration || d.RuntimeVersion != expectedRuntime || d.BaseRuntime != d.RuntimeVersion {
			return nil, errSettingsDraft
		}
		if err = before.capture(ctx, tx, user, "settings-save", "settings"); err != nil {
			return nil, err
		}
		return putSettingsDraftTx(ctx, tx, before.vault, raw, d.RuntimeVersion, d.Runtime)
	})
}

// The complete apply validates the current bytes again under the relational
// gate. A caller's earlier successful check is never treated as authorization.
// Bootstrap changes and remote node deployment are deliberately separate.
func (s *Store) applySettingsDraft(ctx context.Context, user, key string, expectedGeneration, expectedRuntime int64, before *configurationEditBackup) (json.RawMessage, error) {
	if before == nil || before.vault == nil || expectedGeneration < 1 || expectedRuntime < 1 {
		return nil, errSettingsDraft
	}
	return s.guardedMutation(ctx, user, key, "settings-apply", "settings", []any{expectedGeneration, expectedRuntime}, func(tx *sql.Tx) error {
		return before.lock(ctx, tx, user)
	}, func(tx *sql.Tx) (any, error) {
		d, err := readSettingsDraftTx(ctx, tx, true)
		if err != nil {
			return nil, err
		}
		if err = checkSettingsDraftProof(before.vault, d); err != nil {
			return nil, err
		}
		if d.Generation != expectedGeneration || d.RuntimeVersion != expectedRuntime || d.BaseRuntime != d.RuntimeVersion || validateSettingsDraft(before.bootstrap, d.Desired) != nil {
			return nil, errSettingsDraft
		}
		if !d.Pending {
			return d.settingsDraftState, nil
		}
		if err = before.capture(ctx, tx, user, "settings-apply", "settings"); err != nil {
			return nil, err
		}
		return applySettingsDraftTx(ctx, tx, before, d)
	})
}

// History settings explicitly apply only the five retention periods. If an
// ordinary draft exists, merge those same periods into it without activating
// any pending notification/rule changes. The new generation invalidates old
// apply confirmations. Call before committing the live retention update.
func mergeRetentionIntoDraftTx(ctx context.Context, tx *sql.Tx, v *Vault, p RetentionPolicy, oldRuntime int64) error {
	d, err := readSettingsDraftTx(ctx, tx, true)
	if err != nil {
		return err
	}
	if d.Generation == 0 {
		return nil
	}
	if err = checkSettingsDraftProof(v, d); err != nil {
		return err
	}
	if d.RuntimeVersion != oldRuntime || d.BaseRuntime != oldRuntime {
		return errSettingsDraft
	}
	var desired, runtime configurationValues
	if decodeConfigurationObject(d.Desired, &desired) != nil || decodeConfigurationObject(d.Runtime, &runtime) != nil {
		return errSettingsDraft
	}
	for _, root := range []configurationValues{desired, runtime} {
		r := common.M(root["retention"])
		root["retention"] = r
		for k, v := range map[string]int{"sqlite_events_days": p.Events, "security_events_days": p.Security, "website_incidents_days": p.Websites, "server_alerts_days": p.Servers, "delivery_records_days": p.Notifications} {
			r[k] = v
		}
	}
	saved, err := putSettingsDraftTx(ctx, tx, v, common.JSON(desired), oldRuntime+1, common.JSON(runtime))
	if err != nil {
		return err
	}
	if configurationRestoreEqual(desired, runtime) {
		_, err = tx.ExecContext(ctx, `UPDATE v3_settings_drafts SET applied_generation=$1 WHERE id=1`, saved.Generation)
	}
	return err
}

// Caller holds the configuration relation gate and has validated the draft and
// captured its before-edit backup in this same transaction.
func applySettingsDraftTx(ctx context.Context, tx *sql.Tx, before *configurationEditBackup, d privateSettingsDraft) (settingsDraftState, error) {
	var err error
	if _, err = prepareSettingsFromConfigTx(ctx, tx, before.bootstrap, d.RuntimeVersion, d.RuntimeVersion+1); err != nil {
		return settingsDraftState{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v3_settings SET version=version+1,payload=$1,updated_at=clock_timestamp() WHERE id=1`, []byte(d.Desired)); err != nil {
		return settingsDraftState{}, err
	}
	baseDigest, err := settingsPayloadDigest(d.Desired)
	if err != nil {
		return settingsDraftState{}, err
	}
	proof, err := settingsDraftProof(before.vault, before.vault.active, d.Generation, d.RuntimeVersion+1, baseDigest, d.Desired)
	if err != nil {
		return settingsDraftState{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v3_settings_drafts SET applied_generation=generation,runtime_version=$1,proof=$2,runtime_digest=$3,updated_at=clock_timestamp() WHERE id=1`, d.RuntimeVersion+1, proof, baseDigest); err != nil {
		return settingsDraftState{}, err
	}
	d, err = readSettingsDraftTx(ctx, tx, false)
	return d.settingsDraftState, err
}
