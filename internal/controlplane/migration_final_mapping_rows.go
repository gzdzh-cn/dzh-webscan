package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"webscan/internal/common"
)

type migrationFinalRow struct {
	Table, Logical string
	Key            common.Map
	Data           common.Map
}
type migrationFinalTable struct {
	Name          string
	Columns, Keys []string
}
type migrationFinalChange struct{ Before, After *migrationFinalRow }

func migrationFinalRowID(table, logical string) string { return table + ":" + logical }
func migrationFinalMetadataTx(ctx context.Context, tx *sql.Tx, live string) (map[string]migrationFinalTable, error) {
	out := map[string]migrationFinalTable{}
	for _, table := range migrationFinalTables {
		var columns, keys []byte
		e := tx.QueryRowContext(ctx, `SELECT (SELECT jsonb_agg(attname ORDER BY attnum) FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped AND attgenerated=''),(SELECT jsonb_agg(a.attname ORDER BY k.ordinality) FROM pg_index p CROSS JOIN LATERAL unnest(p.indkey) WITH ORDINALITY k(attnum,ordinality) JOIN pg_attribute a ON a.attrelid=p.indrelid AND a.attnum=k.attnum WHERE p.indrelid=$1::regclass AND p.indisprimary)`, migrationFinalQualified(live, table)).Scan(&columns, &keys)
		m := migrationFinalTable{Name: table}
		if e != nil || json.Unmarshal(columns, &m.Columns) != nil || json.Unmarshal(keys, &m.Keys) != nil || len(m.Keys) == 0 {
			return nil, ErrMigrationSession
		}
		out[table] = m
	}
	return out, nil
}
func migrationFinalKey(m migrationFinalTable, data common.Map) (common.Map, error) {
	out := common.Map{}
	for _, k := range m.Keys {
		value, ok := data[k]
		if !ok || value == nil {
			return nil, ErrMigrationSession
		}
		out[k] = value
	}
	return out, nil
}
func migrationFinalLoadOwnedTx(ctx context.Context, tx *sql.Tx, v *Vault, session string, metadata map[string]migrationFinalTable) (map[string]migrationFinalRow, error) {
	rows, e := tx.QueryContext(ctx, `SELECT table_name,logical_key,key_data,key_id,nonce,ciphertext FROM v3_migration_final_owned WHERE session=$1 ORDER BY table_name,logical_key`, session)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]migrationFinalRow{}
	for rows.Next() {
		var table, logical, key string
		var storedKey, nonce, sealed []byte
		if e = rows.Scan(&table, &logical, &storedKey, &key, &nonce, &sealed); e != nil {
			return nil, e
		}
		m, ok := metadata[table]
		if !ok {
			return nil, ErrMigrationSession
		}
		raw, e := migrationFinalOpen(v, key, session+":"+table+":"+logical, nonce, sealed)
		if e != nil {
			return nil, e
		}
		parsed, e := common.Decode(raw)
		clear(raw)
		if e != nil {
			return nil, e
		}
		data := common.M(parsed)
		pk, e := migrationFinalKey(m, data)
		if e != nil {
			return nil, e
		}
		given, e := common.Decode(storedKey)
		if e != nil || !reflect.DeepEqual(pk, common.M(given)) {
			return nil, ErrMigrationSession
		}
		out[migrationFinalRowID(table, logical)] = migrationFinalRow{table, logical, pk, data}
	}
	return out, rows.Err()
}
func migrationFinalCurrentTx(ctx context.Context, tx *sql.Tx, live string, row migrationFinalRow) (common.Map, error) {
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT to_jsonb(t) FROM `+migrationFinalQualified(live, row.Table)+` t WHERE to_jsonb(t) @> $1::jsonb FOR UPDATE`, common.JSON(row.Key)).Scan(&raw)
	if e != nil {
		return nil, e
	}
	parsed, e := common.Decode(raw)
	return common.M(parsed), e
}

func migrationFinalLogical(table string, data common.Map, noticeKeys map[string]string) (string, error) {
	var names []string
	switch table {
	case "v3_notifications":
		names = []string{"node", "event_id", "channel", "recipient"}
	case "v3_notification_attempts":
		names = []string{"migration_source", "migration_table", "migration_record"}
	case "v3_notification_public":
		key, ok := noticeKeys[common.S(data["notification"])]
		if !ok {
			return "", ErrMigrationSession
		}
		return key, nil
	case "v3_audit":
		names = []string{"resource", "kind"}
	case "v3_events":
		names = []string{"node", "id"}
	default:
		return "", nil
	}
	key := common.Map{}
	for _, name := range names {
		value, ok := data[name]
		if !ok {
			return "", ErrMigrationSession
		}
		key[name] = value
	}
	return string(common.JSON(key)), nil
}

func migrationFinalReadCandidateTx(ctx context.Context, tx *sql.Tx, live, scratch string, owned map[string]migrationFinalRow, metadata map[string]migrationFinalTable) (map[string]migrationFinalRow, error) {
	out := map[string]migrationFinalRow{}
	noticeIDs, noticeKeys := map[string]any{}, map[string]string{}
	for _, table := range migrationFinalTables {
		rows, e := tx.QueryContext(ctx, `SELECT to_jsonb(t) FROM `+migrationFinalQualified(scratch, table)+` t ORDER BY to_jsonb(t)::text LIMIT 250001`)
		if e != nil {
			return nil, e
		}
		batch := []common.Map{}
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				break
			}
			parsed, e := common.Decode(raw)
			if e != nil {
				rows.Close()
				return nil, e
			}
			batch = append(batch, common.M(parsed))
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return nil, e
		}
		if len(batch) > 250000 {
			return nil, ErrMigrationSession
		}
		for _, data := range batch {
			logical, e := migrationFinalLogical(table, data, noticeKeys)
			if e != nil {
				return nil, e
			}
			if logical == "" {
				pk, e := migrationFinalKey(metadata[table], data)
				if e != nil {
					return nil, e
				}
				logical = string(common.JSON(pk))
			}
			identity := migrationFinalRowID(table, logical)
			previous, exists := owned[identity]
			switch table {
			case "v3_notifications", "v3_notification_attempts", "v3_audit":
				original := common.S(data["id"])
				if exists {
					data["id"] = previous.Data["id"]
				} else {
					var id int64
					if e = tx.QueryRowContext(ctx, `SELECT nextval(pg_get_serial_sequence($1,'id'))`, migrationFinalQualified(live, table)).Scan(&id); e != nil {
						return nil, e
					}
					data["id"] = json.Number(strconv.FormatInt(id, 10))
				}
				if table == "v3_notifications" {
					noticeIDs[original] = data["id"]
					noticeKeys[original] = logical
				}
			case "v3_notification_public":
				mapped, ok := noticeIDs[common.S(data["notification"])]
				if !ok {
					return nil, ErrMigrationSession
				}
				data["notification"] = mapped
			}
			if table == "v3_notification_attempts" {
				mapped, ok := noticeIDs[common.S(data["notification"])]
				if !ok {
					return nil, ErrMigrationSession
				}
				data["notification"] = mapped
			}
			for _, field := range []string{"updated_at", "projected_at"} {
				if _, ok := data[field]; ok && exists {
					data[field] = previous.Data[field]
				}
			}
			key, e := migrationFinalKey(metadata[table], data)
			if e != nil {
				return nil, e
			}
			if _, duplicate := out[identity]; duplicate {
				return nil, ErrMigrationSession
			}
			out[identity] = migrationFinalRow{table, logical, key, data}
		}
	}
	return out, nil
}
func migrationFinalDigestRows(rows map[string]migrationFinalRow) string {
	keys := make([]string, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	data := []any{}
	for _, key := range keys {
		data = append(data, []any{key, rows[key].Key, rows[key].Data})
	}
	return digest(common.JSON(data))
}
func migrationFinalWriteRowTx(ctx context.Context, tx *sql.Tx, live string, m migrationFinalTable, before *migrationFinalRow, after migrationFinalRow) error {
	qualified := migrationFinalQualified(live, m.Name)
	if before == nil {
		_, e := tx.ExecContext(ctx, `INSERT INTO `+qualified+` SELECT * FROM jsonb_populate_record(NULL::`+qualified+`,$1::jsonb)`, common.JSON(after.Data))
		return e
	}
	fields := []string{}
	for _, column := range m.Columns {
		fields = append(fields, quotePG(column)+`=s.`+quotePG(column))
	}
	res, e := tx.ExecContext(ctx, `UPDATE `+qualified+` t SET `+strings.Join(fields, ",")+` FROM jsonb_populate_record(NULL::`+qualified+`,$1::jsonb) s WHERE to_jsonb(t) @> $2::jsonb`, common.JSON(after.Data), common.JSON(before.Key))
	if e != nil {
		return e
	}
	count, e := res.RowsAffected()
	if e != nil || count != 1 {
		return ErrMigrationSession
	}
	return nil
}
func migrationFinalSaveOwnedTx(ctx context.Context, tx *sql.Tx, v *Vault, session, batch string, row migrationFinalRow) error {
	raw := common.JSON(row.Data)
	defer clear(raw)
	key, nonce, sealed, e := migrationFinalSeal(v, session+":"+row.Table+":"+row.Logical, raw)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_final_owned(session,table_name,logical_key,key_data,key_id,nonce,ciphertext,batch) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(session,table_name,logical_key) DO UPDATE SET key_data=excluded.key_data,key_id=excluded.key_id,nonce=excluded.nonce,ciphertext=excluded.ciphertext,batch=excluded.batch`, session, row.Table, row.Logical, common.JSON(row.Key), key, nonce, sealed, batch)
	return e
}
func migrationFinalSaveChangeTx(ctx context.Context, tx *sql.Tx, v *Vault, batch, table, logical string, before, after *migrationFinalRow) error {
	operation := "UPDATE"
	if before == nil {
		operation = "ADD"
	}
	if after == nil {
		operation = "DELETE"
	}
	raw := common.JSON(migrationFinalChange{before, after})
	defer clear(raw)
	key, nonce, sealed, e := migrationFinalSeal(v, batch+":"+table+":"+logical, raw)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_final_changes(batch,table_name,logical_key,operation,key_id,nonce,ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7)`, batch, table, logical, operation, key, nonce, sealed)
	return e
}
