package controlplane

import (
	"context"
	"database/sql"
	"strings"
)

func migrationTargetRecoveryGuardFunction(schema string) string {
	return `CREATE FUNCTION ` + quotePG(schema) + `.v3_migration_recovery_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$ BEGIN RAISE EXCEPTION 'migration_recovery_requires_reauthorization'; END $guard$;`
}

// Logical backups preserve journal evidence, but do not recreate its dynamic
// capture triggers. Install a separate unconditional guard before committing a
// restored database. Clearing recovery_hold alone cannot enable target writes.
// The restore caller holds the global migration gate and calls this last, after
// setting every restored session's recovery_hold and pending fence.
func installMigrationTargetRecoveryGuardsTx(ctx context.Context, tx *sql.Tx) error {
	var exists bool
	if tx.QueryRowContext(ctx, `SELECT to_regclass('v3_migration_target_journals') IS NOT NULL`).Scan(&exists) != nil {
		return ErrMigrationSession
	}
	if !exists {
		return nil
	}
	rows, e := tx.QueryContext(ctx, `SELECT session FROM v3_migration_target_journals ORDER BY session`)
	if e != nil {
		return ErrMigrationSession
	}
	var sessions []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || !validArchiveSource(id) {
			rows.Close()
			return ErrMigrationSession
		}
		sessions = append(sessions, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(sessions) > 1 {
		return ErrMigrationSession
	}
	if len(sessions) == 0 {
		return nil
	}
	id := sessions[0]
	var held bool
	if tx.QueryRowContext(ctx, `SELECT s.recovery_hold AND d.pending AND d.source=s.id FROM v3_migration_sessions s JOIN v3_migration_domains d ON d.domain='session:'||s.id WHERE s.id=$1`, id).Scan(&held) != nil || !held {
		return ErrMigrationSession
	}
	tables, e := migrationTargetTablesTx(ctx, tx)
	if e != nil || len(tables) == 0 || migrationTargetTableLocks(ctx, tx, tables) != nil {
		return ErrMigrationSession
	}
	var manifest, schema string
	if tx.QueryRowContext(ctx, `SELECT schema_manifest,current_schema() FROM v3_migration_target_journals WHERE session=$1`, id).Scan(&manifest, &schema) != nil || !identifier.MatchString(schema) || manifest != migrationTargetManifest(tables) {
		return ErrMigrationSession
	}
	definition := migrationTargetRecoveryGuardFunction(schema)
	var body string
	var known bool
	if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND proname='v3_migration_recovery_guard')`).Scan(&known) != nil {
		return ErrMigrationSession
	}
	if known {
		var valid bool
		if tx.QueryRowContext(ctx, `SELECT p.prosrc,p.pronargs=0 AND NOT p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog']::text[] FROM pg_proc p WHERE p.pronamespace=current_schema()::regnamespace AND p.proname='v3_migration_recovery_guard'`).Scan(&body, &valid) != nil || !valid || strings.TrimSpace(body) != strings.TrimSpace(strings.Split(definition, "$guard$")[1]) {
			return ErrMigrationSession
		}
	} else if _, e = tx.ExecContext(ctx, definition); e != nil {
		return ErrMigrationSession
	}
	// Statement triggers are not inherited by PostgreSQL partitions. Guard all
	// existing descendants as well, so a direct partition write cannot bypass it.
	guardTables := make([]string, 0, len(tables))
	for _, table := range tables {
		guardTables = append(guardTables, table.Name)
		partitions, e := tx.QueryContext(ctx, `WITH RECURSIVE children AS (SELECT inhrelid FROM pg_inherits WHERE inhparent=(quote_ident(current_schema())||'.'||quote_ident($1))::regclass UNION ALL SELECT i.inhrelid FROM pg_inherits i JOIN children c ON c.inhrelid=i.inhparent) SELECT c.relname,c.relnamespace=current_schema()::regnamespace FROM children x JOIN pg_class c ON c.oid=x.inhrelid ORDER BY c.relname COLLATE "C"`, table.Name)
		if e != nil {
			return ErrMigrationSession
		}
		for partitions.Next() {
			var name string
			var owned bool
			if partitions.Scan(&name, &owned) != nil || !owned || !identifier.MatchString(name) {
				partitions.Close()
				return ErrMigrationSession
			}
			guardTables = append(guardTables, name)
		}
		e = partitions.Err()
		partitions.Close()
		if e != nil {
			return ErrMigrationSession
		}
	}
	for _, table := range guardTables {
		var count int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_trigger t WHERE t.tgrelid=(quote_ident(current_schema())||'.'||quote_ident($1))::regclass AND t.tgname='v3_migration_target_recovery_guard' AND NOT t.tgisinternal`, table).Scan(&count) != nil {
			return ErrMigrationSession
		}
		if count == 0 {
			if _, e = tx.ExecContext(ctx, `CREATE TRIGGER v3_migration_target_recovery_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON `+quotePG(schema)+`.`+quotePG(table)+` FOR EACH STATEMENT EXECUTE FUNCTION `+quotePG(schema)+`.v3_migration_recovery_guard();ALTER TABLE `+quotePG(schema)+`.`+quotePG(table)+` ENABLE ALWAYS TRIGGER v3_migration_target_recovery_guard`); e != nil {
				return ErrMigrationSession
			}
		}
		var valid int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid=(quote_ident(current_schema())||'.'||quote_ident($1))::regclass AND t.tgname='v3_migration_target_recovery_guard' AND NOT t.tgisinternal AND t.tgenabled='A' AND t.tgtype=62 AND octet_length(t.tgargs)=0 AND p.pronamespace=current_schema()::regnamespace AND p.proname='v3_migration_recovery_guard'`, table).Scan(&valid) != nil || valid != 1 {
			return ErrMigrationSession
		}
	}
	return nil
}
