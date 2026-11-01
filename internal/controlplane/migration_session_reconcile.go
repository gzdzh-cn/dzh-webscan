package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
)

type MigrationReconciliationRole struct {
	Role           string                `json:"role"`
	Revision       string                `json:"revision"`
	SnapshotSHA256 string                `json:"snapshot_sha256"`
	IndexSHA256    string                `json:"index_sha256"`
	Tables         int64                 `json:"tables"`
	Records        int64                 `json:"records"`
	Archived       int64                 `json:"archived"`
	MappedRecords  int64                 `json:"mapped_records"`
	Delta          *MigrationDeltaReport `json:"delta,omitempty"`
}
type MigrationReconciliationConflict struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}
type MigrationReconciliationReport struct {
	ID              string                            `json:"id"`
	Session         string                            `json:"session"`
	SessionVersion  int64                             `json:"session_version"`
	FreezeDigest    string                            `json:"freeze_digest"`
	Roles           []MigrationReconciliationRole     `json:"roles"`
	Conflicts       []MigrationReconciliationConflict `json:"conflicts"`
	Protected       bool                              `json:"protected"`
	ReadyForCutover bool                              `json:"ready_for_cutover"`
	SHA256          string                            `json:"sha256"`
}

func (s *Store) ReconcileMigrationSession(ctx context.Context, id string, expected int64) (MigrationReconciliationReport, error) {
	r, e := s.reconcileMigrationSession(ctx, id, expected)
	if e != nil {
		return MigrationReconciliationReport{}, safeMigrationSessionError(e)
	}
	return r, nil
}
func (s *Store) reconcileMigrationSession(ctx context.Context, id string, expected int64) (MigrationReconciliationReport, error) {
	out := MigrationReconciliationReport{Session: id, Protected: true, Roles: []MigrationReconciliationRole{}, Conflicts: []MigrationReconciliationConflict{}}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if e = migrationSessionLock(ctx, tx, id); e != nil {
		return out, e
	}
	state, e := migrationSessionTx(ctx, tx, id)
	if e != nil || state.RecoveryHold {
		return out, ErrMigrationSession
	}
	if state.Phase == "reconciled" {
		var raw []byte
		if tx.QueryRowContext(ctx, `SELECT report FROM v3_migration_reconciliations WHERE session=$1 AND session_version=$2 ORDER BY created_at DESC LIMIT 1`, id, state.Version).Scan(&raw) != nil || json.Unmarshal(raw, &out) != nil || expected != state.Version && expected != state.Version-1 {
			return out, ErrConflict
		}
		if migrationReconciliationDigest(out) != out.SHA256 || out.Session != id || !out.Protected || out.ReadyForCutover {
			return out, ErrMigrationSession
		}
		// Recheck immutable evidence before returning a lost-response receipt.
		for _, role := range out.Roles {
			if verifyMigrationRevisionIndex(ctx, tx, role.Revision) != nil {
				return out, ErrMigrationSession
			}
		}
		return out, tx.Commit()
	}
	if state.Version != expected {
		return out, ErrConflict
	}
	if state.Phase != "frozen" || !releaseDigest(state.FreezeDigest) {
		return out, ErrMigrationSession
	}
	var busy bool
	if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_migration_deltas WHERE session=$1 AND state='comparing') OR EXISTS(SELECT 1 FROM v3_migration_revisions WHERE session=$1 AND state='indexing')`, id).Scan(&busy) != nil || busy {
		return out, ErrMigrationSession
	}
	out.SessionVersion = expected + 1
	out.FreezeDigest = state.FreezeDigest
	conflicts := map[string]int64{"final_domain_mapping_unverified": 1, "lossless_reverse_mapping_unverified": 1}
	for _, role := range state.Roles {
		var revision, manifest, evidence string
		if tx.QueryRowContext(ctx, `SELECT revision,manifest_digest,evidence_digest FROM v3_migration_freezes WHERE session=$1 AND role=$2`, id, role).Scan(&revision, &manifest, &evidence) != nil || !releaseDigest(manifest) || !releaseDigest(evidence) {
			return out, ErrMigrationSession
		}
		var latest string
		if tx.QueryRowContext(ctx, `SELECT id FROM v3_migration_revisions WHERE session=$1 AND role=$2 ORDER BY sequence DESC LIMIT 1`, id, role).Scan(&latest) != nil || latest != revision || verifyMigrationRevisionIndex(ctx, tx, revision) != nil {
			return out, ErrMigrationSession
		}
		r, e := migrationRevisionTx(ctx, tx, revision)
		if e != nil {
			return out, e
		}
		rr := MigrationReconciliationRole{Role: role, Revision: revision, SnapshotSHA256: r.Source, IndexSHA256: r.Digest, Records: r.Records}
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_migration_revision_tables WHERE revision=$1`, revision).Scan(&rr.Tables) != nil || tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_legacy_records WHERE source=$1`, r.Source).Scan(&rr.Archived) != nil || rr.Archived != rr.Records {
			return out, ErrMigrationSession
		}
		if tx.QueryRowContext(ctx, `SELECT coalesce(sum(imported),0) FROM v3_domain_imports WHERE source=$1`, r.Source).Scan(&rr.MappedRecords) != nil {
			return out, ErrMigrationSession
		}
		if r.Sequence > 1 {
			var delta string
			e = tx.QueryRowContext(ctx, `SELECT d.id FROM v3_migration_deltas d JOIN v3_migration_revisions b ON b.id=d.base WHERE d.session=$1 AND d.target=$2 AND b.sequence=1 AND d.state='ready'`, id, revision).Scan(&delta)
			if e == sql.ErrNoRows {
				conflicts["final_delta_unverified"]++
			} else if e != nil {
				return out, e
			} else {
				d, e := migrationDeltaTx(ctx, tx, delta)
				if e != nil || verifyMigrationDeltaCheckpoint(ctx, tx, d) != nil {
					return out, ErrMigrationSession
				}
				rr.Delta = &d
				if d.SchemaChanges > 0 {
					conflicts["schema_changes_require_mapping"] += d.SchemaChanges
				}
			}
		}
		var foreign int64
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_migration_domains WHERE source IN (SELECT snapshot_sha256 FROM v3_migration_revisions WHERE session=$1 AND role=$2) AND source<>$3`, id, role, r.Source).Scan(&foreign) != nil {
			return out, ErrMigrationSession
		}
		if foreign > 0 {
			conflicts["target_domain_requires_final_delta"] += foreign
		}
		out.Roles = append(out.Roles, rr)
	}
	categories := []string{}
	for category := range conflicts {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	for _, category := range categories {
		out.Conflicts = append(out.Conflicts, MigrationReconciliationConflict{category, conflicts[category]})
	}
	out.ID = digest([]byte(id + ":" + state.FreezeDigest + ":" + string(commonJSONInt(expected))))
	out.SHA256 = migrationReconciliationDigest(out)
	raw, _ := json.Marshal(out)
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_reconciliations(id,session,session_version,report) VALUES($1,$2,$3,$4)`, out.ID, id, out.SessionVersion, raw); e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,phase='reconciled',updated_at=clock_timestamp() WHERE id=$1`, id); e != nil {
		return out, e
	}
	if e = tx.Commit(); e != nil {
		return out, e
	}
	return out, nil
}
func migrationReconciliationDigest(r MigrationReconciliationReport) string {
	r.SHA256 = ""
	raw, _ := json.Marshal(r)
	return digest(raw)
}
