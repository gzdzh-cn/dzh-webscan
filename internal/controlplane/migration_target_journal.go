package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type MigrationTargetJournalReport struct {
	Session        string `json:"session"`
	State          string `json:"state"`
	Tables         int64  `json:"tables"`
	BaselineRows   int64  `json:"baseline_rows"`
	BaselineSHA256 string `json:"baseline_sha256"`
	Changes        int64  `json:"changes"`
	UpperSequence  string `json:"upper_sequence"`
	SealSHA256     string `json:"seal_sha256,omitempty"`
	SessionVersion int64  `json:"session_version"`
}
type migrationTargetTable struct {
	Name             string
	Keys, Definition json.RawMessage
}

func migrationTargetExcluded(name string) bool {
	if strings.HasPrefix(name, "v3_migration_") {
		return true
	}
	switch name {
	case "v3_schema", "v3_leases", "v3_role_status", "v3_configuration_operation_gate", "v3_imports", "v3_domain_imports", "v3_legacy_records":
		return true
	}
	return false
}

// Only existing root tables in the current private PostgreSQL schema can be
// managed. Partitions inherit their parent's row trigger and are not doubled.
func migrationTargetTablesTx(ctx context.Context, tx *sql.Tx) ([]migrationTargetTable, error) {
	rows, e := tx.QueryContext(ctx, `SELECT c.relname,coalesce((SELECT jsonb_agg(a.attname ORDER BY k.ordinality) FROM pg_constraint p CROSS JOIN LATERAL unnest(p.conkey) WITH ORDINALITY k(attnum,ordinality) JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=k.attnum WHERE p.conrelid=c.oid AND p.contype='p'),'[]'::jsonb),(SELECT jsonb_agg(jsonb_build_array(a.attnum,a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.attidentity,a.attgenerated,coalesce(pg_get_expr(d.adbin,d.adrelid),'')) ORDER BY a.attnum) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) FROM pg_class c WHERE c.relnamespace=current_schema()::regnamespace AND c.relkind IN ('r','p') AND c.relname LIKE 'v3\_%' ESCAPE '\' AND NOT EXISTS(SELECT 1 FROM pg_inherits i WHERE i.inhrelid=c.oid) ORDER BY c.relname COLLATE "C"`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []migrationTargetTable{}
	for rows.Next() {
		var table migrationTargetTable
		if e = rows.Scan(&table.Name, &table.Keys, &table.Definition); e != nil {
			return nil, e
		}
		if migrationTargetExcluded(table.Name) {
			continue
		}
		var keys []string
		if !identifier.MatchString(table.Name) || json.Unmarshal(table.Keys, &keys) != nil || len(keys) == 0 || len(keys) > 16 || len(table.Definition) > 256<<10 {
			return nil, ErrMigrationSession
		}
		for _, key := range keys {
			if !identifier.MatchString(key) {
				return nil, ErrMigrationSession
			}
		}
		out = append(out, table)
	}
	return out, rows.Err()
}
func migrationTargetManifest(tables []migrationTargetTable) string {
	raw, _ := json.Marshal(tables)
	return digest(raw)
}
func migrationTargetTableLocks(ctx context.Context, tx *sql.Tx, tables []migrationTargetTable) error {
	for _, t := range tables {
		if _, e := tx.ExecContext(ctx, `LOCK TABLE `+quotePG(t.Name)+` IN SHARE ROW EXCLUSIVE MODE`); e != nil {
			return e
		}
	}
	return nil
}
func migrationTargetStateTx(ctx context.Context, tx *sql.Tx, id string) (MigrationTargetJournalReport, error) {
	out := MigrationTargetJournalReport{Session: id}
	var upper int64
	e := tx.QueryRowContext(ctx, `SELECT state,baseline_rows,baseline_digest,change_count,upper_sequence,seal_digest,(SELECT count(*) FROM v3_migration_target_tables WHERE session=$1) FROM v3_migration_target_journals WHERE session=$1`, id).Scan(&out.State, &out.BaselineRows, &out.BaselineSHA256, &out.Changes, &upper, &out.SealSHA256, &out.Tables)
	out.UpperSequence = strconv.FormatInt(upper, 10)
	return out, e
}
func (s *Store) MigrationTargetJournal(ctx context.Context, id string) (MigrationTargetJournalReport, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return MigrationTargetJournalReport{}, ErrMigrationSession
	}
	defer tx.Rollback()
	if migrationSessionLock(ctx, tx, id) != nil {
		return MigrationTargetJournalReport{}, ErrMigrationSession
	}
	state, e := migrationSessionTx(ctx, tx, id)
	if e != nil {
		return MigrationTargetJournalReport{}, ErrMigrationSession
	}
	out, e := migrationTargetStateTx(ctx, tx, id)
	if e != nil {
		return out, ErrMigrationSession
	}
	out.SessionVersion = state.Version
	if e = tx.Commit(); e != nil {
		return MigrationTargetJournalReport{}, ErrMigrationSession
	}
	return out, nil
}
func (s *Store) ArmMigrationTargetJournal(ctx context.Context, id string, expected int64) (MigrationTargetJournalReport, error) {
	r, e := s.armMigrationTargetJournal(ctx, id, expected)
	if e != nil {
		return MigrationTargetJournalReport{}, safeMigrationSessionError(e)
	}
	return r, nil
}
func (s *Store) armMigrationTargetJournal(ctx context.Context, id string, expected int64) (MigrationTargetJournalReport, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return MigrationTargetJournalReport{}, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(773376002)`); e != nil {
		return MigrationTargetJournalReport{}, e
	}
	if e = migrationSessionLock(ctx, tx, id); e != nil {
		return MigrationTargetJournalReport{}, e
	}
	state, e := migrationSessionTx(ctx, tx, id)
	if e != nil || state.RecoveryHold {
		return MigrationTargetJournalReport{}, ErrMigrationSession
	}
	var protected bool
	if tx.QueryRowContext(ctx, `SELECT pending AND source=$2 FROM v3_migration_domains WHERE domain=$1`, "session:"+id, id).Scan(&protected) != nil || !protected {
		return MigrationTargetJournalReport{}, ErrMigrationSession
	}
	var request, armed int64
	e = tx.QueryRowContext(ctx, `SELECT request_version,armed_version FROM v3_migration_target_journals WHERE session=$1`, id).Scan(&request, &armed)
	if e == nil {
		if expected != state.Version && (expected != request || state.Version != armed) {
			return MigrationTargetJournalReport{}, ErrConflict
		}
		if verifyMigrationTargetArmedTx(ctx, tx, id) != nil {
			return MigrationTargetJournalReport{}, ErrMigrationSession
		}
		r, e := migrationTargetStateTx(ctx, tx, id)
		if e != nil {
			return r, e
		}
		r.SessionVersion = state.Version
		return r, tx.Commit()
	}
	if e != sql.ErrNoRows {
		return MigrationTargetJournalReport{}, e
	}
	if state.Version != expected {
		return MigrationTargetJournalReport{}, ErrConflict
	}
	if state.Phase != "frozen" && state.Phase != "reconciled" {
		return MigrationTargetJournalReport{}, ErrMigrationSession
	}
	tables, e := migrationTargetTablesTx(ctx, tx)
	if e != nil || len(tables) == 0 {
		return MigrationTargetJournalReport{}, ErrMigrationSession
	}
	if e = migrationTargetTableLocks(ctx, tx, tables); e != nil {
		return MigrationTargetJournalReport{}, e
	}
	manifest := migrationTargetManifest(tables)
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_target_journals(session,state,request_version,armed_version,schema_manifest,baseline_digest,began_at) VALUES($1,'armed',$2,$3,$4,$4,clock_timestamp())`, id, expected, expected+1, manifest); e != nil {
		return MigrationTargetJournalReport{}, e
	}
	var schema string
	if tx.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&schema) != nil || !identifier.MatchString(schema) {
		return MigrationTargetJournalReport{}, ErrMigrationSession
	}
	if _, e = tx.ExecContext(ctx, migrationTargetCaptureFunction(schema)); e != nil {
		return MigrationTargetJournalReport{}, e
	}
	for _, table := range tables {
		if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_target_tables(session,table_name,primary_keys,definition) VALUES($1,$2,$3,$4)`, id, table.Name, table.Keys, table.Definition); e != nil {
			return MigrationTargetJournalReport{}, e
		}
		// Quoted identifiers come only from the inspected private schema/PK list.
		var keys []string
		_ = json.Unmarshal(table.Keys, &keys)
		pieces := []string{}
		for _, key := range keys {
			pieces = append(pieces, "'"+key+"',to_jsonb(t."+quotePG(key)+")")
		}
		keyExpr := `jsonb_build_object(` + strings.Join(pieces, ",") + `)`
		query := `INSERT INTO v3_migration_target_baselines(session,table_name,record_key,row_data,row_digest) SELECT $1,$2,` + keyExpr + `,to_jsonb(t),encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') FROM ` + quotePG(table.Name) + ` t`
		if _, e = tx.ExecContext(ctx, query, id, table.Name); e != nil {
			return MigrationTargetJournalReport{}, e
		}
		trigger := quotePG("v3_migration_target_capture")
		guard := quotePG("v3_migration_target_no_truncate")
		if _, e = tx.ExecContext(ctx, `CREATE TRIGGER `+trigger+` AFTER INSERT OR UPDATE OR DELETE ON `+quotePG(table.Name)+` FOR EACH ROW EXECUTE FUNCTION `+quotePG(schema)+`.v3_migration_capture_change('`+table.Name+`'); CREATE TRIGGER `+guard+` BEFORE TRUNCATE ON `+quotePG(table.Name)+` FOR EACH STATEMENT EXECUTE FUNCTION `+quotePG(schema)+`.v3_migration_capture_change('`+table.Name+`'); ALTER TABLE `+quotePG(table.Name)+` ENABLE ALWAYS TRIGGER `+trigger+`; ALTER TABLE `+quotePG(table.Name)+` ENABLE ALWAYS TRIGGER `+guard); e != nil {
			return MigrationTargetJournalReport{}, e
		}
	}
	rows, count, hash, e := migrationTargetBaselineDigest(ctx, tx, id, manifest)
	_ = rows
	if e != nil {
		return MigrationTargetJournalReport{}, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_target_journals SET baseline_rows=$2,baseline_digest=$3 WHERE session=$1`, id, count, hash); e != nil {
		return MigrationTargetJournalReport{}, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,updated_at=clock_timestamp() WHERE id=$1`, id); e != nil {
		return MigrationTargetJournalReport{}, e
	}
	out, e := migrationTargetStateTx(ctx, tx, id)
	if e != nil {
		return out, e
	}
	out.SessionVersion = expected + 1
	return out, tx.Commit()
}
func migrationTargetCaptureFunction(schema string) string {
	q := quotePG(schema)
	return fmt.Sprintf(`CREATE FUNCTION %s.v3_migration_capture_change() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $capture$
 DECLARE j record;meta record;actual jsonb;previous jsonb:='null';following jsonb:='null';pkbefore jsonb:='null';pkafter jsonb:='null';op text;raw jsonb;
 BEGIN
 SELECT session,state INTO j FROM %s.v3_migration_target_journals FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'migration_target_journal_missing'; END IF;
 IF j.state<>'armed' OR EXISTS(SELECT 1 FROM %s.v3_migration_sessions WHERE id=j.session AND recovery_hold) THEN RAISE EXCEPTION 'migration_target_writes_frozen'; END IF;
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'migration_target_truncate_protected'; END IF;
 SELECT primary_keys,definition INTO meta FROM %s.v3_migration_target_tables WHERE session=j.session AND table_name=TG_ARGV[0];
 IF NOT FOUND THEN RAISE EXCEPTION 'migration_target_table_not_bound'; END IF;
 SELECT jsonb_agg(jsonb_build_array(a.attnum,a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.attidentity,a.attgenerated,coalesce(pg_get_expr(d.adbin,d.adrelid),'')) ORDER BY a.attnum) INTO actual FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=TG_RELID AND a.attnum>0 AND NOT a.attisdropped;
 IF actual<>meta.definition THEN RAISE EXCEPTION 'migration_target_schema_changed'; END IF;
 IF TG_OP<>'INSERT' THEN previous:=to_jsonb(OLD);SELECT jsonb_object_agg(k,previous->k) INTO pkbefore FROM jsonb_array_elements_text(meta.primary_keys) k; END IF;
 IF TG_OP<>'DELETE' THEN following:=to_jsonb(NEW);SELECT jsonb_object_agg(k,following->k) INTO pkafter FROM jsonb_array_elements_text(meta.primary_keys) k; END IF;
 op:=CASE TG_OP WHEN 'INSERT' THEN 'ADD' WHEN 'UPDATE' THEN 'UPDATE' ELSE 'DELETE' END;
 raw:=jsonb_build_array(TG_ARGV[0],op,pkbefore,pkafter,previous,following);
 IF octet_length(raw::text)>16777216 THEN RAISE EXCEPTION 'migration_target_row_exceeds_limit'; END IF;
 INSERT INTO %s.v3_migration_target_changes(session,table_name,operation,before_key,after_key,before_data,after_data,change_digest) VALUES(j.session,TG_ARGV[0],op,pkbefore,pkafter,previous,following,encode(sha256(convert_to(raw::text,'UTF8')),'hex'));
 RETURN NULL;
 END $capture$;`, q, q, q, q, q)
}
func migrationTargetBaselineDigest(ctx context.Context, tx *sql.Tx, id, seed string) (int64, int64, string, error) {
	rows, e := tx.QueryContext(ctx, `SELECT table_name,record_key::text,row_digest,encode(sha256(convert_to(row_data::text,'UTF8')),'hex') FROM v3_migration_target_baselines WHERE session=$1 ORDER BY table_name COLLATE "C",record_key::text COLLATE "C"`, id)
	if e != nil {
		return 0, 0, "", e
	}
	defer rows.Close()
	hash := seed
	var count int64
	for rows.Next() {
		var table, key, stored, actual string
		if e = rows.Scan(&table, &key, &stored, &actual); e != nil {
			return 0, 0, "", e
		}
		if stored != actual {
			return 0, 0, "", ErrMigrationSession
		}
		raw, _ := json.Marshal([]string{hash, table, key, stored})
		hash = digest(raw)
		count++
	}
	return count, count, hash, rows.Err()
}
func migrationTargetChangesDigest(ctx context.Context, tx *sql.Tx, id, seed string) (int64, int64, string, error) {
	rows, e := tx.QueryContext(ctx, `SELECT sequence,change_digest,encode(sha256(convert_to(jsonb_build_array(table_name,operation,before_key,after_key,before_data,after_data)::text,'UTF8')),'hex') FROM v3_migration_target_changes WHERE session=$1 ORDER BY sequence`, id)
	if e != nil {
		return 0, 0, "", e
	}
	defer rows.Close()
	hash := seed
	var count, upper int64
	for rows.Next() {
		var sequence int64
		var stored, actual string
		if e = rows.Scan(&sequence, &stored, &actual); e != nil {
			return 0, 0, "", e
		}
		if stored != actual || sequence <= upper {
			return 0, 0, "", ErrMigrationSession
		}
		raw, _ := json.Marshal([]string{hash, strconv.FormatInt(sequence, 10), stored})
		hash = digest(raw)
		count++
		upper = sequence
	}
	return count, upper, hash, rows.Err()
}
func (s *Store) SealMigrationTargetJournal(ctx context.Context, id string, expected int64) (MigrationTargetJournalReport, error) {
	r, e := s.sealMigrationTargetJournal(ctx, id, expected)
	if e != nil {
		return MigrationTargetJournalReport{}, safeMigrationSessionError(e)
	}
	return r, nil
}
func (s *Store) sealMigrationTargetJournal(ctx context.Context, id string, expected int64) (MigrationTargetJournalReport, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return MigrationTargetJournalReport{}, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(773376002)`); e != nil {
		return MigrationTargetJournalReport{}, e
	}
	if e = migrationSessionLock(ctx, tx, id); e != nil {
		return MigrationTargetJournalReport{}, e
	}
	state, e := migrationSessionTx(ctx, tx, id)
	if e != nil || state.RecoveryHold {
		return MigrationTargetJournalReport{}, ErrMigrationSession
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_domains SET pending=true WHERE domain=$1 AND source=$2`, "session:"+id, id); e != nil {
		return MigrationTargetJournalReport{}, e
	}
	var protected bool
	if tx.QueryRowContext(ctx, `SELECT pending AND source=$2 FROM v3_migration_domains WHERE domain=$1`, "session:"+id, id).Scan(&protected) != nil || !protected {
		return MigrationTargetJournalReport{}, ErrMigrationSession
	}
	r, e := migrationTargetStateTx(ctx, tx, id)
	if e != nil {
		return r, e
	}
	r.SessionVersion = state.Version
	if r.State == "sealed" {
		var finished int64
		if tx.QueryRowContext(ctx, `SELECT sealed_version FROM v3_migration_target_journals WHERE session=$1`, id).Scan(&finished) != nil || expected != state.Version && expected != finished-1 {
			return r, ErrConflict
		}
		if verifyMigrationTargetJournal(ctx, tx, id) != nil {
			return r, ErrMigrationSession
		}
		return r, tx.Commit()
	}
	if state.Version != expected {
		return r, ErrConflict
	}
	tables, e := migrationTargetTablesTx(ctx, tx)
	if e != nil {
		return r, e
	}
	if e = migrationTargetTableLocks(ctx, tx, tables); e != nil {
		return r, e
	}
	var manifest string
	if tx.QueryRowContext(ctx, `SELECT schema_manifest FROM v3_migration_target_journals WHERE session=$1 FOR UPDATE`, id).Scan(&manifest) != nil || manifest != migrationTargetManifest(tables) {
		return r, ErrMigrationSession
	}
	_, count, hash, e := migrationTargetBaselineDigest(ctx, tx, id, manifest)
	if e != nil || count != r.BaselineRows || hash != r.BaselineSHA256 {
		return r, ErrMigrationSession
	}
	if verifyMigrationTargetCapture(ctx, tx, id, tables) != nil || verifyMigrationTargetConvergence(ctx, tx, id, tables) != nil {
		return r, ErrMigrationSession
	}
	changes, upper, seal, e := migrationTargetChangesDigest(ctx, tx, id, hash)
	if e != nil {
		return r, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_target_journals SET state='sealed',change_count=$2,upper_sequence=$3,seal_digest=$4,sealed_version=$5,sealed_at=clock_timestamp() WHERE session=$1`, id, changes, upper, seal, expected+1); e != nil {
		return r, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,updated_at=clock_timestamp() WHERE id=$1`, id); e != nil {
		return r, e
	}
	r, e = migrationTargetStateTx(ctx, tx, id)
	if e != nil {
		return r, e
	}
	r.SessionVersion = expected + 1
	return r, tx.Commit()
}
func verifyMigrationTargetJournal(ctx context.Context, tx *sql.Tx, id string) error {
	r, e := migrationTargetStateTx(ctx, tx, id)
	if e != nil || r.State != "sealed" {
		return ErrMigrationSession
	}
	var manifest string
	tables, e := migrationTargetTablesTx(ctx, tx)
	if e != nil {
		return e
	}
	if tx.QueryRowContext(ctx, `SELECT schema_manifest FROM v3_migration_target_journals WHERE session=$1`, id).Scan(&manifest) != nil || manifest != migrationTargetManifest(tables) {
		return ErrMigrationSession
	}
	_, count, hash, e := migrationTargetBaselineDigest(ctx, tx, id, manifest)
	if e != nil || count != r.BaselineRows || hash != r.BaselineSHA256 {
		return ErrMigrationSession
	}
	if verifyMigrationTargetCapture(ctx, tx, id, tables) != nil || verifyMigrationTargetConvergence(ctx, tx, id, tables) != nil {
		return ErrMigrationSession
	}
	changes, upper, seal, e := migrationTargetChangesDigest(ctx, tx, id, hash)
	if e != nil || changes != r.Changes || strconv.FormatInt(upper, 10) != r.UpperSequence || seal != r.SealSHA256 {
		return ErrMigrationSession
	}
	return nil
}
