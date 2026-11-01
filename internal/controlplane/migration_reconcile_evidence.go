package controlplane

import "context"

// Reconciliation remains diagnostic. The transition repeats these checks while
// holding the same transaction which releases the target write fence.
func (s *Store) ReconcileMigrationSessionWithEvidence(ctx context.Context, id string, expected int64, in MigrationCutoverInput) (MigrationReconciliationReport, error) {
	return s.reconcileMigrationSessionWithEvidence(ctx, id, expected, in, observeMigrationFrozenSource)
}
func (s *Store) reconcileMigrationSessionWithEvidence(ctx context.Context, id string, expected int64, in MigrationCutoverInput, observe migrationFreezeObserver) (out MigrationReconciliationReport, err error) {
	defer func() {
		if err != nil {
			err = safeMigrationSessionError(err)
		}
	}()
	out, err = s.reconcileMigrationSession(ctx, id, expected)
	if err != nil {
		return out, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(773376002)`); err != nil {
		return out, err
	}
	if err = migrationSessionLock(ctx, tx, id); err != nil {
		return out, err
	}
	state, err := migrationSessionTx(ctx, tx, id)
	if err != nil || state.RecoveryHold || state.Version != out.SessionVersion {
		return out, ErrConflict
	}
	if err = migrationVerifyCutoverTx(ctx, tx, state, in, observe); err != nil {
		return out, err
	}
	remaining := []MigrationReconciliationConflict{}
	for _, conflict := range out.Conflicts {
		if conflict.Category != "final_domain_mapping_unverified" && conflict.Category != "lossless_reverse_mapping_unverified" {
			remaining = append(remaining, conflict)
		}
	}
	out.Conflicts = remaining
	out.ReadyForCutover = len(remaining) == 0
	out.SHA256 = migrationReconciliationDigest(out)
	return out, tx.Commit()
}
