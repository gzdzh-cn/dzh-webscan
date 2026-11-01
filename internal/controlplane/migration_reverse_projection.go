package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"webscan/internal/common"
)

type migrationLegacyProjection struct {
	Role, Table string
	Keys        []string
	Values      common.Map
}

func migrationLegacyTime(v any, nanos bool) (any, error) {
	if v == nil {
		return nil, nil
	}
	stamp, e := time.Parse(time.RFC3339Nano, common.S(v))
	if e != nil {
		return nil, ErrMigrationSession
	}
	if nanos {
		return stamp.UnixNano(), nil
	}
	return float64(stamp.Unix()) + float64(stamp.Nanosecond())/1e9, nil
}
func migrationLegacyProjectionOf(table string, data common.Map) (migrationLegacyProjection, bool, error) {
	p := migrationLegacyProjection{Role: "central", Values: common.Map{}}
	fields := map[string]string{}
	switch table {
	case "v3_accounts":
		if common.S(data["role"]) != "admin" {
			return p, false, nil
		}
		p.Table = "website_admin"
		p.Keys = []string{"id"}
		p.Values["id"] = int64(1)
		p.Values["modified"] = int64(0)
		fields = map[string]string{"username": "username", "password_hash": "password_hash", "revision": "revision"}
	case "v3_sessions":
		p.Table = "website_sessions"
		p.Keys = []string{"token_hash"}
		fields = map[string]string{"token_hash": "token_hash", "revision": "revision", "csrf": "csrf"}
		v, e := migrationLegacyTime(data["expires_at"], false)
		if e != nil {
			return p, false, e
		}
		p.Values["expires"] = int64(v.(float64))
		v, e = migrationLegacyTime(data["created_at"], true)
		if e != nil {
			return p, false, e
		}
		p.Values["created"] = v
	case "v3_websites":
		p.Table = "websites"
		p.Keys = []string{"id"}
		for _, f := range []string{"id", "name", "url", "node", "keyword", "slow", "paused", "deleted", "version", "state"} {
			fields[f] = f
		}
	case "v3_website_incidents":
		p.Table = "website_incidents"
		p.Keys = []string{"id"}
		for _, f := range []string{"id", "site", "kind", "started", "ended", "reason"} {
			fields[f] = f
		}
	case "v3_website_outbox":
		p.Table = "website_outbox"
		p.Keys = []string{"id"}
		for _, f := range []string{"id", "site", "node", "kind", "message", "created"} {
			fields[f] = f
		}
	case "v3_events":
		p.Table = "events"
		p.Keys = []string{"node", "id"}
		fields = map[string]string{"node": "node", "id": "id", "payload": "payload"}
		_, hash, e := canonicalEvent(common.M(data["payload"]))
		if e != nil {
			return p, false, e
		}
		p.Values["digest"] = hash
		at, e := migrationLegacyTime(data["received_at"], false)
		if e != nil {
			return p, false, e
		}
		p.Values["received"] = at
	case "v3_imported_events":
		p.Table = "migrated_logs"
		p.Keys = []string{"id"}
		fields = map[string]string{"id": "id", "node": "node", "operation": "operation", "payload": "payload"}
		at, e := migrationLegacyTime(data["received_at"], false)
		if e != nil {
			return p, false, e
		}
		p.Values["time"] = at
	case "v3_health_rules":
		p.Role = "health"
		p.Table = "health_rules"
		p.Keys = []string{"key"}
		for _, f := range []string{"key", "node", "kind", "phase", "since", "last", "recovery", "reminder", "payload"} {
			fields[f] = f
		}
	case "v3_health_events":
		p.Role = "health"
		p.Table = "health_events"
		p.Keys = []string{"id"}
		for _, f := range []string{"id", "node", "kind", "phase", "time", "message", "payload"} {
			fields[f] = f
		}
	case "v3_health_batches":
		p.Role = "health"
		p.Table = "alert_batches"
		p.Keys = []string{"id"}
		for _, f := range []string{"id", "node", "phase", "message", "created"} {
			fields[f] = f
		}
		done, e := migrationLegacyTime(data["done_at"], false)
		if e != nil {
			return p, false, e
		}
		p.Values["done"] = done
	case "v3_health_outbox":
		p.Role = "health"
		p.Table = "alert_outbox"
		p.Keys = []string{"id"}
		for _, f := range []string{"id", "node", "phase", "message", "created"} {
			fields[f] = f
		}
		done, e := migrationLegacyTime(data["done_at"], false)
		if e != nil {
			return p, false, e
		}
		p.Values["done"] = done
	default:
		return p, false, nil
	}
	for from, to := range fields {
		value, ok := data[from]
		if !ok {
			return p, false, ErrMigrationSession
		}
		switch v := value.(type) {
		case map[string]any, []any:
			value = string(common.JSON(v))
		case bool:
			if v {
				value = int64(1)
			} else {
				value = int64(0)
			}
		case json.Number:
			n, e := v.Int64()
			if e != nil {
				return p, false, ErrMigrationSession
			}
			value = n
		}
		p.Values[to] = value
	}
	return p, true, nil
}
func migrationLegacyIdentity(row MigrationTargetReplayRow) string {
	key := row.AfterKey
	if row.Operation == "DELETE" {
		key = row.BeforeKey
	}
	return digest(append([]byte(row.Table+":"), key...))
}
func migrationLegacySourceKey(table string, key common.Map) string {
	return digest(common.JSON([]any{table, key}))
}
func (s *MigrationLegacySink) migrationLegacyApplyTx(ctx context.Context, tx *sql.Tx, row MigrationTargetReplayRow) error {
	identity := migrationLegacyIdentity(row)
	if row.Operation != "BASELINE" && row.Operation != "ADD" && row.Operation != "UPDATE" && row.Operation != "DELETE" {
		return ErrMigrationSession
	}
	raw := row.After
	if row.Operation == "DELETE" {
		raw = row.Before
	}
	decoded, e := common.Decode(raw)
	if e != nil {
		return e
	}
	data := common.M(decoded)
	if len(data) == 0 {
		return ErrMigrationSession
	}
	pending := func(reason string) error {
		if row.Operation == "DELETE" {
			_, e := tx.ExecContext(ctx, `DELETE FROM migration_pending WHERE table_name=? AND identity=?`, row.Table, identity)
			return e
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO migration_pending VALUES(?,?,?) ON CONFLICT(table_name,identity) DO UPDATE SET reason=excluded.reason`, row.Table, identity, reason)
		return e
	}
	if row.Operation == "BASELINE" && row.Table != "v3_event_keys" {
		parsedKey, e := common.Decode(row.AfterKey)
		if e != nil {
			return e
		}
		var sourceDigest string
		e = tx.QueryRowContext(ctx, `SELECT digest FROM migration_source_baselines WHERE identity=?`, migrationLegacySourceKey(row.Table, common.M(parsedKey))).Scan(&sourceDigest)
		if e == nil && sourceDigest == digest(common.JSON(data)) {
			if row.Table == "v3_notifications" {
				return s.migrationLegacyNoticeIdentityTx(ctx, tx, data)
			}
			return nil
		}
		if e != nil && e != sql.ErrNoRows {
			return e
		}
	}
	if allowed, err := migrationLegacyActivationImageTx(ctx, tx, row, data); err != nil {
		return err
	} else if allowed {
		_, err = tx.ExecContext(ctx, `DELETE FROM migration_pending WHERE table_name=? AND identity=?`, row.Table, identity)
		return err
	}
	if supported, err := s.migrationLegacyRuntimeTx(ctx, tx, row, data); supported {
		if reason, ok := err.(migrationLegacyPendingError); ok {
			return pending(string(reason))
		}
		if err == ErrConflict {
			return pending("reverse_runtime_sample_conflict")
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM migration_pending WHERE table_name=? AND identity=?`, row.Table, identity)
		return err
	}
	// These are strictly derived, without mutable business facts. Their source
	// records are mapped separately and event-key consistency is checked Report.
	switch row.Table {
	case "v3_legacy_history":
		return pending("reverse_legacy_history_changed_requires_explicit_mapping")
	case "v3_settings":
		e := s.migrationLegacySettingsTx(ctx, tx, row.Operation, data)
		if why, ok := e.(migrationLegacyPendingError); ok {
			return pending(string(why))
		}
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `DELETE FROM migration_pending WHERE table_name=? AND identity=?`, row.Table, identity)
		return e
	case "v3_event_keys":
		if row.Operation == "DELETE" {
			_, e = tx.ExecContext(ctx, `DELETE FROM migration_event_keys WHERE node=? AND id=?`, common.S(data["node"]), common.S(data["id"]))
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO migration_event_keys VALUES(?,?,?) ON CONFLICT(node,id) DO UPDATE SET digest=excluded.digest`, common.S(data["node"]), common.S(data["id"]), common.S(data["digest"]))
		return e
	case "v3_notification_public":
		return nil
	case "v3_node_identities":
		return nil
	case "v3_notifications", "v3_notification_attempts", "v3_notification_rates":
		var e error
		switch row.Table {
		case "v3_notifications":
			e = s.migrationLegacyNotificationTx(ctx, tx, row.Operation, data)
		case "v3_notification_attempts":
			e = s.migrationLegacyAttemptTx(ctx, tx, row.Operation, data)
		case "v3_notification_rates":
			e = s.migrationLegacyRatesTx(ctx, tx, row.Operation, data)
		}
		if why, ok := e.(migrationLegacyPendingError); ok {
			return pending(string(why))
		}
		if e == ErrConflict {
			return pending("reverse_notification_origin_conflict")
		}
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `DELETE FROM migration_pending WHERE table_name=? AND identity=?`, row.Table, identity)
		return e
	}
	projection, supported, e := migrationLegacyProjectionOf(row.Table, data)
	if e != nil {
		return e
	}
	if !supported {
		return pending("reverse_business_semantics_unmapped")
	}
	if !s.roles[projection.Role] {
		return pending("reverse_required_legacy_database_missing")
	}
	if e = migrationLegacyWriteTx(ctx, tx, projection, row.Operation); e != nil {
		if e == ErrConflict {
			return pending("reverse_existing_record_conflict")
		}
		return e
	}
	if row.Table == "v3_health_outbox" {
		// Membership lives in its own actual legacy table, never in a mirror.
		if _, e = tx.ExecContext(ctx, `DELETE FROM health.alert_members WHERE event=?`, common.S(data["id"])); e != nil {
			return e
		}
		if row.Operation != "DELETE" && data["batch"] != nil {
			if _, e = tx.ExecContext(ctx, `INSERT INTO health.alert_members VALUES(?,?)`, common.S(data["id"]), common.S(data["batch"])); e != nil {
				return e
			}
		}
	}
	_, e = tx.ExecContext(ctx, `DELETE FROM migration_pending WHERE table_name=? AND identity=?`, row.Table, identity)
	return e
}
func migrationLegacyWriteTx(ctx context.Context, tx *sql.Tx, p migrationLegacyProjection, operation string) error {
	fields := make([]string, 0, len(p.Values))
	for field := range p.Values {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	qualified := quotePG(migrationLegacyAlias(p.Role)) + "." + quotePG(p.Table)
	where := []string{}
	keyArgs := []any{}
	for _, k := range p.Keys {
		where = append(where, quotePG(k)+"=?")
		keyArgs = append(keyArgs, p.Values[k])
	}
	if operation == "DELETE" {
		_, e := tx.ExecContext(ctx, `DELETE FROM `+qualified+` WHERE `+strings.Join(where, " AND "), keyArgs...)
		return e
	}
	cols, marks, args := []string{}, []string{}, []any{}
	for _, field := range fields {
		cols = append(cols, quotePG(field))
		marks = append(marks, "?")
		args = append(args, p.Values[field])
	}
	if operation == "BASELINE" || operation == "ADD" {
		values := make([]any, len(fields))
		dest := make([]any, len(fields))
		for i := range values {
			dest[i] = &values[i]
		}
		e := tx.QueryRowContext(ctx, `SELECT `+strings.Join(cols, ",")+` FROM `+qualified+` WHERE `+strings.Join(where, " AND "), keyArgs...).Scan(dest...)
		if e == nil {
			for i, field := range fields {
				if !migrationLegacyValueEqual(values[i], p.Values[field]) {
					return ErrConflict
				}
			}
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO `+qualified+` (`+strings.Join(cols, ",")+`) VALUES (`+strings.Join(marks, ",")+`)`, args...)
		return e
	}
	sets := []string{}
	for _, field := range fields {
		sets = append(sets, quotePG(field)+"=?")
	}
	args = append(args, keyArgs...)
	result, e := tx.ExecContext(ctx, `UPDATE `+qualified+` SET `+strings.Join(sets, ",")+` WHERE `+strings.Join(where, " AND "), args...)
	if e != nil {
		return e
	}
	count, e := result.RowsAffected()
	if e != nil || count != 1 {
		return ErrConflict
	}
	return nil
}
func migrationLegacyValueEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if bytes, ok := a.([]byte); ok {
		a = string(bytes)
	}
	sa, sb := fmt.Sprint(a), fmt.Sprint(b)
	if sa == sb {
		return true
	}
	// JSON payload key order is immaterial, while integer values retain Number.
	da, ea := common.Decode([]byte(sa))
	db, eb := common.Decode([]byte(sb))
	return ea == nil && eb == nil && string(common.JSON(da)) == string(common.JSON(db))
}
