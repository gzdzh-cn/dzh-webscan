package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

// The caller holds the exclusive global migration gate (773376002), followed
// by the session lock, and keeps this transaction open until activation commits.
// Table locks close the gap between this verification and releasing the fence.
func verifyMigrationTargetArmedTx(ctx context.Context, tx *sql.Tx, id string) error {
	state, e := migrationSessionTx(ctx, tx, id)
	if e != nil || state.RecoveryHold {
		return ErrMigrationSession
	}
	var protected bool
	if tx.QueryRowContext(ctx, `SELECT pending AND source=$2 FROM v3_migration_domains WHERE domain=$1`, "session:"+id, id).Scan(&protected) != nil || !protected {
		return ErrMigrationSession
	}
	r, e := migrationTargetStateTx(ctx, tx, id)
	if e != nil || r.State != "armed" {
		return ErrMigrationSession
	}
	tables, e := migrationTargetTablesTx(ctx, tx)
	if e != nil || len(tables) == 0 || migrationTargetTableLocks(ctx, tx, tables) != nil {
		return ErrMigrationSession
	}
	var manifest string
	if tx.QueryRowContext(ctx, `SELECT schema_manifest FROM v3_migration_target_journals WHERE session=$1 FOR UPDATE`, id).Scan(&manifest) != nil || manifest != migrationTargetManifest(tables) {
		return ErrMigrationSession
	}
	_, count, hash, e := migrationTargetBaselineDigest(ctx, tx, id, manifest)
	if e != nil || count != r.BaselineRows || hash != r.BaselineSHA256 {
		return ErrMigrationSession
	}
	if verifyMigrationTargetCapture(ctx, tx, id, tables) != nil || verifyMigrationTargetConvergence(ctx, tx, id, tables) != nil {
		return ErrMigrationSession
	}
	if _, _, _, e = migrationTargetChangesDigest(ctx, tx, id, hash); e != nil {
		return ErrMigrationSession
	}
	return nil
}

func verifyMigrationTargetCapture(ctx context.Context, tx *sql.Tx, id string, tables []migrationTargetTable) error {
	var schema, body string
	var config []byte
	if tx.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&schema) != nil {
		return ErrMigrationSession
	}
	definition := migrationTargetCaptureFunction(schema)
	parts := strings.Split(definition, "$capture$")
	if len(parts) != 3 {
		return ErrMigrationSession
	}
	if tx.QueryRowContext(ctx, `SELECT p.prosrc,to_jsonb(p.proconfig) FROM pg_proc p WHERE p.pronamespace=current_schema()::regnamespace AND p.proname='v3_migration_capture_change' AND p.pronargs=0 AND NOT p.prosecdef`).Scan(&body, &config) != nil || strings.TrimSpace(body) != strings.TrimSpace(parts[1]) {
		return ErrMigrationSession
	}
	var options []string
	if json.Unmarshal(config, &options) != nil || len(options) != 1 || options[0] != "search_path=pg_catalog" {
		return ErrMigrationSession
	}
	var registered int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_migration_target_tables WHERE session=$1`, id).Scan(&registered) != nil || registered != len(tables) {
		return ErrMigrationSession
	}
	for _, t := range tables {
		var keys, definition []byte
		if tx.QueryRowContext(ctx, `SELECT primary_keys,definition FROM v3_migration_target_tables WHERE session=$1 AND table_name=$2`, id, t.Name).Scan(&keys, &definition) != nil || string(keys) != string(t.Keys) || string(definition) != string(t.Definition) {
			return ErrMigrationSession
		}
		var valid int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid=(quote_ident(current_schema())||'.'||quote_ident($1))::regclass AND NOT t.tgisinternal AND t.tgenabled='A' AND p.pronamespace=current_schema()::regnamespace AND p.proname='v3_migration_capture_change' AND t.tgargs=convert_to($1,'UTF8')||decode('00','hex') AND ((t.tgname='v3_migration_target_capture' AND t.tgtype=29) OR (t.tgname='v3_migration_target_no_truncate' AND t.tgtype=34))`, t.Name).Scan(&valid) != nil || valid != 2 {
			return ErrMigrationSession
		}
	}
	return nil
}

// Folding the journal back onto its baseline must match every current target
// row. This detects disabled/missing triggers, missed partitions and metadata
// drift before declaring the finite rollback input complete.
func verifyMigrationTargetConvergence(ctx context.Context, tx *sql.Tx, id string, tables []migrationTargetTable) error {
	temp := quotePG("migration_reconstructed_" + token()[:12])
	query := `CREATE TEMP TABLE ` + temp + ` ON COMMIT DROP AS WITH actions AS (SELECT table_name,record_key,row_data,false deleted,0::bigint sequence,0 priority FROM v3_migration_target_baselines WHERE session=$1 UNION ALL SELECT table_name,before_key,before_data,true,sequence,0 FROM v3_migration_target_changes WHERE session=$1 AND operation IN ('UPDATE','DELETE') UNION ALL SELECT table_name,after_key,after_data,false,sequence,1 FROM v3_migration_target_changes WHERE session=$1 AND operation IN ('ADD','UPDATE')) SELECT DISTINCT ON(table_name,record_key) table_name,record_key,row_data,deleted FROM actions ORDER BY table_name,record_key,sequence DESC,priority DESC`
	if _, e := tx.ExecContext(ctx, query, id); e != nil {
		return ErrMigrationSession
	}
	for _, t := range tables {
		var keys []string
		if json.Unmarshal(t.Keys, &keys) != nil {
			return ErrMigrationSession
		}
		pieces := []string{}
		for _, key := range keys {
			pieces = append(pieces, "'"+key+"',to_jsonb(t."+quotePG(key)+")")
		}
		source := `SELECT jsonb_build_object(` + strings.Join(pieces, ",") + `) record_key,to_jsonb(t) row_data FROM ` + quotePG(t.Name) + ` t`
		var mismatch bool
		if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM (SELECT record_key,row_data FROM `+temp+` WHERE table_name=$1 AND NOT deleted) e FULL JOIN (`+source+`) a USING(record_key) WHERE e.record_key IS NULL OR a.record_key IS NULL OR e.row_data IS DISTINCT FROM a.row_data)`, t.Name).Scan(&mismatch) != nil || mismatch {
			return ErrMigrationSession
		}
	}
	return nil
}
