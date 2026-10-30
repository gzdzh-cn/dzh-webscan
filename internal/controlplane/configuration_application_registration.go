package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"webscan/internal/common"
)

const configurationApplicationRegistrationSchema = `
CREATE TABLE v3_configuration_application_registrations(
 application text NOT NULL REFERENCES v3_configuration_applications(id),
 node text NOT NULL REFERENCES v3_nodes(id),
 phase text NOT NULL CHECK(phase IN ('nodes','restore-nodes')),
 key_id text NOT NULL,nonce bytea NOT NULL,ciphertext bytea NOT NULL,
 PRIMARY KEY(application,node,phase),
 CHECK(octet_length(ciphertext) BETWEEN 17 AND 16384)
);
INSERT INTO v3_schema(version) VALUES(26);
`

// Registration changes only central collection. In particular, disabling a
// node cannot claim that the remote agent received or applied a new version.
// These encrypted receipts are atomic with the pointer, cache invalidation and
// audit. They never restore notification queues or historical observations.
type applicationRegistrationState struct {
	Runtime deploymentRuntimeBaseline
	Applied int64
}

type privateApplicationRegistrationReceipt struct {
	Epoch         int64
	Before, After applicationRegistrationState
}

func (privateApplicationRegistrationReceipt) String() string { return "[private registration receipt]" }
func (privateApplicationRegistrationReceipt) GoString() string {
	return "[private registration receipt]"
}
func (privateApplicationRegistrationReceipt) MarshalJSON() ([]byte, error) {
	return nil, errConfigurationApplication
}

func applicationRegistrationAAD(p privateConfigurationApplication, node, phase, key string) []byte {
	return common.JSON([]any{"webscan-v3/configuration-application/registration/v1", p.ID, p.planProof, p.member, node, phase, key})
}

func validApplicationRegistrationState(s applicationRegistrationState) bool {
	b := s.Runtime
	if s.Applied < 0 || b.Epoch < 0 || b.Version < 0 || b.Delivered < 0 {
		return false
	}
	if b.Snapshot == "" {
		return b.Version == 0 && b.Delivered == 0 && b.Digest == ""
	}
	validSnapshot := validArchiveSource(b.Snapshot) || strings.HasPrefix(b.Snapshot, "migration-") && identifier.MatchString(strings.TrimPrefix(b.Snapshot, "migration-"))
	return validSnapshot && b.Version > 0 && releaseDigest(b.Digest)
}

func readApplicationRegistrationTx(ctx context.Context, tx *sql.Tx, v *Vault, p privateConfigurationApplication, node, phase string) (privateApplicationRegistrationReceipt, error) {
	var r privateApplicationRegistrationReceipt
	var key string
	var nonce, sealed []byte
	if err := tx.QueryRowContext(ctx, `SELECT key_id,nonce,ciphertext FROM v3_configuration_application_registrations WHERE application=$1 AND node=$2 AND phase=$3 FOR SHARE`, p.ID, node, phase).Scan(&key, &nonce, &sealed); err != nil {
		return r, err
	}
	if v == nil || v.keys[key] == nil || len(nonce) != v.keys[key].NonceSize() || len(sealed) < 17 || len(sealed) > 16384 {
		return r, errConfigurationApplication
	}
	raw, err := v.keys[key].Open(nil, nonce, sealed, applicationRegistrationAAD(p, node, phase, key))
	if err != nil {
		return r, errConfigurationApplication
	}
	defer clear(raw)
	type body privateApplicationRegistrationReceipt
	if json.Unmarshal(raw, (*body)(&r)) != nil || r.Epoch < 1 || r.Epoch > p.epoch || !validApplicationRegistrationState(r.Before) || !validApplicationRegistrationState(r.After) {
		return privateApplicationRegistrationReceipt{}, errConfigurationApplication
	}
	return r, nil
}

func writeApplicationRegistrationTx(ctx context.Context, tx *sql.Tx, v *Vault, p privateConfigurationApplication, node string, before, after applicationRegistrationState) error {
	if v == nil || v.keys[v.active] == nil || !validApplicationRegistrationState(before) || !validApplicationRegistrationState(after) {
		return errConfigurationApplication
	}
	type body privateApplicationRegistrationReceipt
	raw, err := json.Marshal(body{p.epoch, before, after})
	if err != nil {
		return err
	}
	defer clear(raw)
	aead := v.keys[v.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return errConfigurationApplication
	}
	sealed := aead.Seal(nil, nonce, raw, applicationRegistrationAAD(p, node, p.phase(), v.active))
	defer clear(sealed)
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_configuration_application_registrations(application,node,phase,key_id,nonce,ciphertext) VALUES($1,$2,$3,$4,$5,$6)`, p.ID, node, p.phase(), v.active, nonce, sealed); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-application-registration',$2,$3)`, p.Controller, p.ID, common.JSON(map[string]any{"node": node, "phase": p.phase(), "changed": before != after, "remote_changed": false}))
	return err
}

func applicationRegistrationStateTx(ctx context.Context, tx *sql.Tx, node string) (applicationRegistrationState, error) {
	var state applicationRegistrationState
	b, err := runtimeBaselineTx(ctx, tx, node)
	if err != nil {
		return state, err
	}
	state.Runtime = *b
	err = tx.QueryRowContext(ctx, `SELECT applied_version FROM v3_nodes WHERE removed_at IS NULL AND id=$1`, node).Scan(&state.Applied)
	return state, err
}

// Authenticate the immutable snapshot as well as the current pointer. Merely
// having a signed receipt does not prove its effect is still live.
func verifyApplicationRegistrationStateTx(ctx context.Context, tx *sql.Tx, node string, want applicationRegistrationState) error {
	if !validApplicationRegistrationState(want) {
		return errConfigurationApplication
	}
	if b := want.Runtime; b.Snapshot != "" {
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT to_jsonb(c) FROM v3_node_configurations c WHERE node=$1 AND id=$2 FOR SHARE`, node, b.Snapshot).Scan(&raw); err != nil {
			return err
		}
		if digest(raw) != b.Digest {
			return ErrConflict
		}
	}
	got, err := applicationRegistrationStateTx(ctx, tx, node)
	if err != nil {
		return err
	}
	if got != want {
		return ErrConflict
	}
	return nil
}

// Requires the authenticated, live parent and its saved document under the
// exclusive operation gate. Inspection never writes a receipt or registration.
func applicationRegistrationTx(ctx context.Context, tx *sql.Tx, v *Vault, p privateConfigurationApplication, doc configurationDocument, node string, apply bool) (bool, error) {
	want, ok := doc.Nodes[node]
	if !ok || want.Enabled || p.Direction == "forward" && p.phase() != "nodes" || p.Direction == "rollback" && p.phase() != "restore-nodes" {
		return false, errConfigurationApplication
	}
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR UPDATE`, node))
	if err != nil || !applicationNodeMatches(doc, n) {
		return false, ErrConflict
	}
	var linked bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_configuration_application_nodes WHERE application=$1 AND node=$2)`, p.ID, node).Scan(&linked); err != nil {
		return false, err
	}
	if linked {
		return false, errConfigurationApplication
	}
	receipt, err := readApplicationRegistrationTx(ctx, tx, v, p, node, p.phase())
	if err == nil {
		return true, verifyApplicationRegistrationStateTx(ctx, tx, node, receipt.After)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	before, err := applicationRegistrationStateTx(ctx, tx, node)
	if err != nil {
		return false, err
	}
	var forward privateApplicationRegistrationReceipt
	if p.Direction == "rollback" {
		forward, err = readApplicationRegistrationTx(ctx, tx, v, p, node, "nodes")
		if err == nil {
			if err = verifyApplicationRegistrationStateTx(ctx, tx, node, forward.After); err != nil {
				return false, err
			}
		} else if !errors.Is(err, sql.ErrNoRows) || p.step > 1 {
			return false, errConfigurationApplication
		}
	}
	if !apply {
		return false, nil
	}
	if p.Direction == "forward" {
		snapshot, e := captureSavedNodeTx(ctx, tx, node)
		if e != nil {
			return false, e
		}
		// Preserve the last remotely delivered/applied versions even though the
		// registered snapshot now has the newer disabled desired version.
		if err = publishNodeRuntimeTx(ctx, tx, node, snapshot, before.Runtime.Delivered); err != nil {
			return false, err
		}
	} else if forward.Epoch > 0 {
		base := forward.Before.Runtime
		if base.Snapshot != "" {
			var raw []byte
			if err = tx.QueryRowContext(ctx, `SELECT to_jsonb(c) FROM v3_node_configurations c WHERE node=$1 AND id=$2 FOR SHARE`, node, base.Snapshot).Scan(&raw); err != nil {
				return false, err
			}
			if digest(raw) != base.Digest {
				return false, ErrConflict
			}
			if err = publishNodeRuntimeTx(ctx, tx, node, base.Snapshot, base.Delivered); err != nil {
				return false, err
			}
		} else {
			// A never-installed node returns to no registration with a new fence.
			if _, err = tx.ExecContext(ctx, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1 WHERE id=$1`, node); err != nil {
				return false, err
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM v3_node_runtime WHERE node=$1`, node); err != nil {
				return false, err
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM v3_node_readiness WHERE node=$1`, node); err != nil {
				return false, err
			}
		}
	}
	after, err := applicationRegistrationStateTx(ctx, tx, node)
	if err != nil {
		return false, err
	}
	if before.Applied != after.Applied || before.Runtime.Delivered != after.Runtime.Delivered && p.Direction == "forward" {
		return false, ErrConflict
	}
	if err = writeApplicationRegistrationTx(ctx, tx, v, p, node, before, after); err != nil {
		return false, err
	}
	// Check after every write, including the audit, so a delayed insert cannot
	// commit an effect under a lease that expired during database work.
	if _, err = lockedApplication(ctx, tx, v, p); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) applyApplicationRegistration(ctx context.Context, v *Vault, expected privateConfigurationApplication, node string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if held, e := migrationHeld(ctx, tx); e != nil {
		return e
	} else if held {
		return ErrMigrationPending
	}
	p, err := lockedApplication(ctx, tx, v, expected)
	if err != nil {
		return err
	}
	if !p.RecoveryRequired {
		return errConfigurationApplication
	}
	_, doc, err := applicationSavedEvidenceTx(ctx, tx, v, p)
	if err != nil {
		return err
	}
	if _, err = applicationRegistrationTx(ctx, tx, v, p, doc, node, true); err != nil {
		return err
	}
	return tx.Commit()
}

// Called for phase and final verification. A checkpoint cannot certify an
// unapplied disabled registration; a completed forward phase cannot lose its
// receipts and then silently skip rollback.
func verifyApplicationRegistrationsTx(ctx context.Context, tx *sql.Tx, v *Vault, p privateConfigurationApplication) error {
	_, doc, err := applicationSavedEvidenceTx(ctx, tx, v, p)
	if err != nil {
		return err
	}
	phase := "nodes"
	if p.Direction == "rollback" {
		phase = "restore-nodes"
	}
	for node, n := range doc.Nodes {
		if n.Enabled {
			continue
		}
		r, err := readApplicationRegistrationTx(ctx, tx, v, p, node, phase)
		if errors.Is(err, sql.ErrNoRows) && p.Direction == "rollback" && p.step <= 1 {
			if _, e := readApplicationRegistrationTx(ctx, tx, v, p, node, "nodes"); errors.Is(e, sql.ErrNoRows) {
				continue
			}
		}
		if err != nil {
			return errConfigurationApplication
		}
		if err = verifyApplicationRegistrationStateTx(ctx, tx, node, r.After); err != nil {
			return err
		}
	}
	return nil
}
