package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"reflect"

	"webscan/internal/common"
)

func migrationFinalSeal(v *Vault, aad string, raw []byte) (string, []byte, []byte, error) {
	if v == nil || v.keys[v.active] == nil || len(raw) > 64<<20 {
		return "", nil, nil, ErrCredentialUnavailable
	}
	a := v.keys[v.active]
	nonce := make([]byte, a.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return "", nil, nil, e
	}
	return v.active, nonce, a.Seal(nil, nonce, raw, []byte("webscan-v3/migration-final/v1\x00"+aad)), nil
}
func migrationFinalOpen(v *Vault, key, aad string, nonce, sealed []byte) ([]byte, error) {
	if v == nil || v.keys[key] == nil || len(nonce) != v.keys[key].NonceSize() || len(sealed) > 64<<20 {
		return nil, ErrCredentialUnavailable
	}
	return v.keys[key].Open(nil, nonce, sealed, []byte("webscan-v3/migration-final/v1\x00"+aad))
}

func migrationFinalReceiptMAC(v *Vault, key string, report MigrationFinalMappingReport, revisions, rows string) string {
	return migrationNodesMAC(v, key, common.JSON([]any{"webscan-v3/final-domains-receipt/v1", report, revisions, rows}))
}
func migrationFinalVerifyReceiptTx(ctx context.Context, tx *sql.Tx, v *Vault, report MigrationFinalMappingReport, revisions string, owned map[string]migrationFinalRow) error {
	var key, rows, mac string
	if e := tx.QueryRowContext(ctx, `SELECT key_id,candidate_digest,evidence_digest FROM v3_migration_final_batches WHERE id=$1 AND session=$2 AND revision_digest=$3`, report.Batch, report.Session, revisions).Scan(&key, &rows, &mac); e != nil {
		return ErrMigrationSession
	}
	actual := migrationFinalReceiptMAC(v, key, report, revisions, rows)
	if !releaseDigest(rows) || actual == "" || subtle.ConstantTimeCompare([]byte(actual), []byte(mac)) != 1 || migrationFinalDigestRows(owned) != rows {
		return ErrMigrationSession
	}
	return nil
}

// Caller holds the global migration gate and session lock. This verifies the
// current final snapshot generation and actual owned business rows, rather than
// treating a historical success receipt as current cutover authorization.
func VerifyMigrationFinalDomainsTx(ctx context.Context, tx *sql.Tx, session string, v *Vault) (bool, error) {
	state, e := migrationSessionTx(ctx, tx, session)
	if e != nil || state.RecoveryHold {
		return false, ErrMigrationSession
	}
	if state.Phase != "frozen" && state.Phase != "reconciled" {
		return false, nil
	}
	revisions, e := migrationFinalRevisionsTx(ctx, tx, state)
	if e != nil {
		return false, e
	}
	for _, r := range revisions {
		var frozen string
		if e = tx.QueryRowContext(ctx, `SELECT revision FROM v3_migration_freezes WHERE session=$1 AND role=$2`, session, r.Role).Scan(&frozen); e != nil || frozen != r.ID {
			return false, ErrMigrationSession
		}
		var metricCount int64
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_migration_revision_rows WHERE revision=$1 AND table_name='samples'`, r.ID).Scan(&metricCount); e != nil {
			return false, e
		}
		if metricCount > 0 {
			verified, e := MigrationMetricHistoryEvidenceTx(ctx, tx, session, r.ID)
			if e != nil || !verified {
				return false, e
			}
		}
		var count int64
		tables := []string{}
		for name, role := range migrationLegacyHistoryTables {
			if role == r.Role {
				tables = append(tables, name)
			}
		}
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_migration_revision_rows WHERE revision=$1 AND table_name=ANY($2::text[])`, r.ID, tables).Scan(&count); e != nil {
			return false, e
		}
		if count > 0 {
			verified, e := VerifyLegacyHistoryTx(ctx, tx, session, r.ID, v)
			if e != nil || !verified {
				return false, e
			}
		}
	}
	revisionDigest := digest(common.JSON(revisions))
	var raw []byte
	e = tx.QueryRowContext(ctx, `SELECT report FROM v3_migration_final_batches WHERE session=$1 AND revision_digest=$2 ORDER BY finished_version DESC LIMIT 1`, session, revisionDigest).Scan(&raw)
	if e == sql.ErrNoRows {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	var report MigrationFinalMappingReport
	if singleDecode(raw, &report) != nil || report.Session != session || report.SessionVersion > state.Version || !report.Protected || report.ReadyForCutover {
		return false, ErrMigrationSession
	}
	if !report.Complete || len(report.Pending) > 0 || len(report.Conflicts) > 0 {
		return false, nil
	}
	var live string
	if e = tx.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&live); e != nil {
		return false, e
	}
	metadata, e := migrationFinalMetadataTx(ctx, tx, live)
	if e != nil {
		return false, e
	}
	owned, e := migrationFinalLoadOwnedTx(ctx, tx, v, session, metadata)
	if e != nil {
		return false, e
	}
	if e = migrationFinalVerifyReceiptTx(ctx, tx, v, report, revisionDigest, owned); e != nil {
		return false, e
	}
	for _, row := range owned {
		current, e := migrationFinalCurrentTx(ctx, tx, live, row)
		if e != nil || !reflect.DeepEqual(current, row.Data) {
			return false, ErrConflict
		}
	}
	return true, nil
}
