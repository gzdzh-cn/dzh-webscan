package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/common"
)

var errBootstrapDraft = errors.New("已保存的中心启动配置或运行基准校验失败，请重新确认；运行配置未修改")

type bootstrapDraftState struct {
	Generation        int64     `json:"generation,string"`
	AppliedGeneration int64     `json:"applied_generation,string"`
	Pending           bool      `json:"pending"`
	Updated           time.Time `json:"updated_at"`
}

// The bootstrap contains private addresses and references, never external file
// contents. It remains private even when nested into another diagnostic value.
type privateBootstrapDraft struct {
	bootstrapDraftState
	Desired       configurationValues
	Runtime       configurationValues
	RuntimeDigest string
	Proof         string
}

func (privateBootstrapDraft) String() string               { return "[private startup configuration]" }
func (privateBootstrapDraft) GoString() string             { return "[private startup configuration]" }
func (privateBootstrapDraft) MarshalJSON() ([]byte, error) { return nil, errBootstrapDraft }

func configurationBootstrapValues(c Config) (configurationValues, error) {
	if c.Validate() != nil {
		return nil, errBootstrapDraft
	}
	raw, err := yaml.Marshal(c)
	var m configurationValues
	if err != nil || yaml.Unmarshal(raw, &m) != nil {
		return nil, errBootstrapDraft
	}
	return m, nil
}

func bootstrapDraftProof(v *Vault, key, instance string, generation, applied int64, base string, desired configurationValues) (string, error) {
	if v == nil || len(v.receiptKeys[key]) == 0 {
		return "", ErrConfigurationBackupKey
	}
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/bootstrap-draft/v1\x00"))
	h.Write(common.JSON([]any{instance, generation, applied, base, desired}))
	return key + ":" + hex.EncodeToString(h.Sum(nil)), nil
}

func readBootstrapDraftTx(ctx context.Context, tx *sql.Tx, v *Vault, c Config) (privateBootstrapDraft, error) {
	var d privateBootstrapDraft
	runtime, err := configurationBootstrapValues(c)
	if err != nil {
		return d, err
	}
	d.Runtime = runtime
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT generation,applied_generation,runtime_digest,payload,proof,updated_at FROM v3_bootstrap_drafts WHERE instance=$1`, c.Central.Instance).Scan(&d.Generation, &d.AppliedGeneration, &d.RuntimeDigest, &raw, &d.Proof, &d.Updated)
	if errors.Is(err, sql.ErrNoRows) {
		d.Desired = runtime
		return d, nil
	}
	if err != nil {
		return d, err
	}
	if decodeConfigurationObject(raw, &d.Desired) != nil || d.RuntimeDigest != digest(common.JSON(runtime)) {
		return d, errBootstrapDraft
	}
	if v == nil {
		v, err = OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
		if err != nil {
			return d, errBootstrapDraft
		}
	}
	id, _, ok := strings.Cut(d.Proof, ":")
	proof, err := bootstrapDraftProof(v, id, c.Central.Instance, d.Generation, d.AppliedGeneration, d.RuntimeDigest, d.Desired)
	if !ok || err != nil || !hmac.Equal([]byte(proof), []byte(d.Proof)) || d.AppliedGeneration == d.Generation && !configurationRestoreEqual(d.Desired, d.Runtime) {
		return d, errBootstrapDraft
	}
	d.Pending = d.AppliedGeneration < d.Generation
	return d, nil
}

// Caller holds the configuration relation gate and has validated local material.
// No disk YAML is written and no process is restarted by this saved-state write.
func putBootstrapDraftTx(ctx context.Context, tx *sql.Tx, v *Vault, c Config, desired configurationValues) (bootstrapDraftState, error) {
	var d bootstrapDraftState
	current, err := readBootstrapDraftTx(ctx, tx, v, c)
	if err != nil {
		return d, err
	}
	if v == nil {
		return d, ErrConfigurationBackupKey
	}
	base := digest(common.JSON(current.Runtime))
	var stored []byte
	err = tx.QueryRowContext(ctx, `INSERT INTO v3_bootstrap_drafts(instance,runtime_digest,payload,proof) VALUES($1,$2,$3,'')
 ON CONFLICT(instance) DO UPDATE SET generation=excluded.generation,runtime_digest=excluded.runtime_digest,payload=excluded.payload,updated_at=clock_timestamp()
 RETURNING generation,applied_generation,updated_at,payload`, c.Central.Instance, base, common.JSON(desired)).Scan(&d.Generation, &d.AppliedGeneration, &d.Updated, &stored)
	if err != nil {
		return d, err
	}
	var normalized configurationValues
	if decodeConfigurationObject(stored, &normalized) != nil {
		return d, errBootstrapDraft
	}
	if configurationRestoreEqual(normalized, current.Runtime) {
		d.AppliedGeneration = d.Generation
	}
	proof, err := bootstrapDraftProof(v, v.active, c.Central.Instance, d.Generation, d.AppliedGeneration, base, normalized)
	if err != nil {
		return d, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE v3_bootstrap_drafts SET applied_generation=$2,proof=$3 WHERE instance=$1`, c.Central.Instance, d.AppliedGeneration, proof)
	d.Pending = d.Generation > d.AppliedGeneration
	return d, err
}
