package controlplane

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"

	"webscan/internal/common"
)

// Private host-only evidence. Paths and the actual sink never enter a public
// receipt. A prior successful report alone cannot release a migration fence.
type MigrationCutoverInput struct {
	FreezeManifest string
	Consumer       string
	LegacySink     *MigrationLegacySink
	LegacyEvidence MigrationLegacyProjectionEvidence
	Vault          *Vault
	Config         Config
	Metrics        *Metrics
}

func migrationVerifyFrozenTx(ctx context.Context, tx *sql.Tx, state MigrationSession, path string, observe migrationFreezeObserver) error {
	m, hash, err := readMigrationFreezeManifest(path, state.ID)
	if err != nil || len(m.Sources) != len(state.Roles) || !releaseDigest(state.FreezeDigest) {
		return ErrMigrationSession
	}
	for i, source := range m.Sources {
		if source.Role != state.Roles[i] {
			return ErrMigrationSession
		}
		var revision, manifest, evidence string
		if tx.QueryRowContext(ctx, `SELECT revision,manifest_digest,evidence_digest FROM v3_migration_freezes WHERE session=$1 AND role=$2`, state.ID, source.Role).Scan(&revision, &manifest, &evidence) != nil || manifest != hash {
			return ErrMigrationSession
		}
		observed, e := observe(ctx, source)
		if e != nil || observed != evidence {
			return ErrMigrationSession
		}
		var latest string
		if tx.QueryRowContext(ctx, `SELECT id FROM v3_migration_revisions WHERE session=$1 AND role=$2 ORDER BY sequence DESC LIMIT 1`, state.ID, source.Role).Scan(&latest) != nil || latest != revision || verifyMigrationRevisionIndex(ctx, tx, revision) != nil {
			return ErrMigrationSession
		}
		if migrationVerifySourceContents(ctx, tx, revision, source.SQLite) != nil {
			return ErrMigrationSession
		}
		again, e := observe(ctx, source)
		if e != nil || again != observed {
			return ErrMigrationSession
		}
	}
	return nil
}

func migrationVerifyCutoverTx(ctx context.Context, tx *sql.Tx, state MigrationSession, in MigrationCutoverInput, observe migrationFreezeObserver) error {
	if in.Vault == nil || in.LegacySink == nil || !identifier.MatchString(in.Consumer) || in.LegacyEvidence.Phase != "baseline" {
		return ErrMigrationCutoverProtected
	}
	if err := migrationVerifyFrozenTx(ctx, tx, state, in.FreezeManifest, observe); err != nil {
		return err
	}
	verified, err := VerifyMigrationFinalDomainsTx(ctx, tx, state.ID, in.Vault)
	if err != nil {
		return err
	}
	if !verified {
		return ErrMigrationCutoverProtected
	}
	// Recheck the actual currently configured history store, not a past replay
	// receipt. Source runs or VM samples changed after final mapping block cutover.
	revisions, err := migrationFinalRevisionsTx(ctx, tx, state)
	if err != nil {
		return err
	}
	for _, revision := range revisions {
		var samples int64
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_migration_revision_rows WHERE revision=$1 AND table_name='samples'`, revision.ID).Scan(&samples); err != nil {
			return err
		}
		if samples > 0 {
			ok, e := VerifyMigrationMetricStoreTx(ctx, tx, state.ID, revision.ID, in.Metrics)
			if e != nil {
				return e
			}
			if !ok {
				return ErrMigrationCutoverProtected
			}
		}
	}
	verified, err = VerifyMigrationLegacyEvidenceTx(ctx, tx, state.ID, in.Consumer, in.LegacyEvidence, in.LegacySink, in.Vault)
	if err != nil {
		return err
	}
	if !verified {
		return ErrMigrationCutoverProtected
	}
	if err = verifyMigrationNodesCutoverTx(ctx, tx, state, in.Vault, in.Config, false, in.FreezeManifest); err != nil {
		return err
	}
	return verifyMigrationTargetArmedTx(ctx, tx, state.ID)
}

func migrationCutoverProof(v *Vault, key, session, action string, request, finished int64, evidence []byte) string {
	var parsed MigrationLegacyProjectionEvidence
	if singleDecode(evidence, &parsed) != nil {
		return ""
	}
	return migrationNodesMAC(v, key, common.JSON([]any{"webscan-v3/cutover/v1", session, action, request, finished, parsed}))
}

func (s *Store) ActivateMigrationSessionWithEvidence(ctx context.Context, id string, expected int64, in MigrationCutoverInput) error {
	return safeMigrationSessionError(s.migrationCutover(ctx, id, expected, in, "activate", observeMigrationFrozenSource))
}
func (s *Store) RollbackMigrationSessionWithEvidence(ctx context.Context, id string, expected int64, in MigrationCutoverInput) error {
	return safeMigrationSessionError(s.migrationCutover(ctx, id, expected, in, "rollback", observeMigrationFrozenSource))
}

func (s *Store) migrationCutover(ctx context.Context, id string, expected int64, in MigrationCutoverInput, action string, observe migrationFreezeObserver) error {
	if in.Vault == nil || action != "activate" && action != "rollback" {
		return ErrMigrationCutoverProtected
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(773376002)`); err != nil {
		return err
	}
	if err = migrationSessionLock(ctx, tx, id); err != nil {
		return err
	}
	state, err := migrationSessionTx(ctx, tx, id)
	if err != nil || state.RecoveryHold {
		return ErrMigrationSession
	}
	var requested, finished int64
	var key, proof string
	var evidence []byte
	err = tx.QueryRowContext(ctx, `SELECT request_version,finished_version,evidence,key_id,proof FROM v3_migration_cutovers WHERE session=$1 AND action=$2`, id, action).Scan(&requested, &finished, &evidence, &key, &proof)
	if err == nil {
		phase := "active"
		if action == "rollback" {
			phase = "rolled_back"
		}
		mac := migrationCutoverProof(in.Vault, key, id, action, requested, finished, evidence)
		if state.Phase != phase || state.Version != finished || expected != requested && expected != finished || mac == "" || subtle.ConstantTimeCompare([]byte(mac), []byte(proof)) != 1 {
			return ErrMigrationSession
		}
		// Re-read actual output on a repeated rollback, even after a lost reply.
		if action == "rollback" {
			var old MigrationLegacyProjectionEvidence
			if singleDecode(evidence, &old) != nil {
				return ErrMigrationSession
			}
			ok, e := VerifyMigrationLegacyEvidenceTx(ctx, tx, id, old.Consumer, old, in.LegacySink, in.Vault, in.Config)
			if e != nil {
				return e
			}
			if !ok {
				return ErrMigrationCutoverProtected
			}
		}
		return tx.Commit()
	}
	if err != sql.ErrNoRows {
		return err
	}
	if state.Version != expected {
		return ErrConflict
	}
	if action == "activate" {
		if state.Phase != "frozen" && state.Phase != "reconciled" {
			return ErrMigrationCutoverProtected
		}
		if err = migrationVerifyCutoverTx(ctx, tx, state, in, observe); err != nil {
			return err
		}
		// Include only authenticated source snapshots and their stable aliases.
		revisions, e := migrationFinalRevisionsTx(ctx, tx, state)
		if e != nil {
			return e
		}
		sources := []string{id}
		for _, r := range revisions {
			sources = append(sources, r.Source, r.Alias)
		}
		// No unrelated migration session/domain may be released by this task.
		var foreign bool
		if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_migration_domains d WHERE d.pending AND d.domain<>$2 AND NOT (d.source=ANY($1::text[]) OR d.related_source=ANY($1::text[])))`, sources, "session:"+id).Scan(&foreign) != nil || foreign {
			return ErrMigrationCutoverProtected
		}
		if err = verifyMigrationNodesCutoverTx(ctx, tx, state, in.Vault, in.Config, true, in.FreezeManifest); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v3_migration_domains SET pending=false WHERE pending AND (domain=$2 OR source=ANY($1::text[]) OR related_source=ANY($1::text[]))`, sources, "session:"+id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v3_notifications SET migration_pending=false WHERE migration_pending AND migration_source=ANY($1::text[])`, sources); err != nil {
			return err
		}
	} else {
		if state.Phase != "active" || in.LegacyEvidence.Phase != "rollback" {
			return ErrMigrationCutoverProtected
		}
		if err = migrationVerifyFrozenTx(ctx, tx, state, in.FreezeManifest, observe); err != nil {
			return err
		}
		ok, e := VerifyMigrationLegacyEvidenceTx(ctx, tx, id, in.Consumer, in.LegacyEvidence, in.LegacySink, in.Vault, in.Config)
		if e != nil {
			return e
		}
		if !ok {
			return ErrMigrationCutoverProtected
		}
		// Sealing has already drained target writers and restored the fence.
		var held bool
		if tx.QueryRowContext(ctx, `SELECT pending AND source=$2 FROM v3_migration_domains WHERE domain=$1`, "session:"+id, id).Scan(&held) != nil || !held {
			return ErrMigrationSession
		}
	}
	evidence, _ = json.Marshal(in.LegacyEvidence)
	key = in.Vault.active
	finished = expected + 1
	proof = migrationCutoverProof(in.Vault, key, id, action, expected, finished, evidence)
	if proof == "" {
		return ErrCredentialUnavailable
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_migration_cutovers(session,action,request_version,finished_version,evidence,key_id,proof) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, action, expected, finished, evidence, key, proof); err != nil {
		return err
	}
	phase := "active"
	if action == "rollback" {
		phase = "rolled_back"
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET phase=$2,version=$3,updated_at=clock_timestamp() WHERE id=$1`, id, phase, finished); err != nil {
		return err
	}
	return tx.Commit()
}
