package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
	"webscan/internal/common"
	configuration "webscan/internal/config"
)

func migrationLegacySourceYAMLTx(ctx context.Context, tx *sql.Tx, session string, v *Vault) (raw []byte, baselines map[string]string, err error) {
	baselines = map[string]string{}
	if v == nil {
		return nil, baselines, nil
	}
	rows, e := tx.QueryContext(ctx, `SELECT DISTINCT ON(source_id) id,key_id,nonce,ciphertext,content_hmac FROM v3_migration_node_sources WHERE session=$1 ORDER BY source_id,sequence DESC`, session)
	if e != nil {
		return nil, nil, e
	}
	type source struct {
		id, key, mac  string
		nonce, sealed []byte
	}
	sources := []source{}
	for rows.Next() {
		var s source
		if e = rows.Scan(&s.id, &s.key, &s.nonce, &s.sealed, &s.mac); e != nil {
			rows.Close()
			return nil, nil, e
		}
		sources = append(sources, s)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	for _, s := range sources {
		plain, e := migrationNodesOpen(v, s.key, s.id, s.nonce, s.sealed)
		if e != nil {
			return nil, nil, e
		}
		if migrationNodesMAC(v, s.key, plain) != s.mac {
			clear(plain)
			return nil, nil, ErrMigrationSession
		}
		if len(raw) > 0 && !reflect.DeepEqual(raw, plain) {
			clear(plain)
			clear(raw)
			return nil, nil, ErrMigrationSession
		}
		if len(raw) == 0 {
			raw = append([]byte{}, plain...)
		}
		clear(plain)
		changes, e := migrationNodeChangesTx(ctx, tx, v, s.id)
		if e != nil {
			return nil, nil, e
		}
		for id, change := range changes {
			if change.Retired {
				continue
			}
			current, e := migrationNodeCurrentTx(ctx, tx, id)
			if e != nil || !migrationNodeSame(current, change.After) {
				return nil, nil, ErrConflict
			}
			var data []byte
			if e = tx.QueryRowContext(ctx, `SELECT to_jsonb(n) FROM v3_nodes n WHERE id=$1`, id).Scan(&data); e != nil {
				return nil, nil, e
			}
			decoded, e := common.Decode(data)
			if e != nil {
				return nil, nil, e
			}
			baselines[migrationLegacySourceKey("v3_nodes", common.Map{"id": id})] = digest(common.JSON(decoded))
			// The encrypted node image authenticates the exact retained SSH
			// credential. v2 already represents it in its source YAML; only
			// unchanged credential/link rows qualify as baseline no-ops.
			if current.CredentialID != "" {
				credential, e := common.Decode(current.Credential)
				if e != nil {
					return nil, nil, e
				}
				baselines[migrationLegacySourceKey("v3_credentials", common.Map{"id": current.CredentialID})] = digest(common.JSON(credential))
				var link []byte
				if e = tx.QueryRowContext(ctx, `SELECT to_jsonb(w) FROM v3_web_node_credentials w WHERE node=$1 AND credential=$2`, id, current.CredentialID).Scan(&link); e != nil {
					return nil, nil, e
				}
				linked, e := common.Decode(link)
				if e != nil {
					return nil, nil, e
				}
				baselines[migrationLegacySourceKey("v3_web_node_credentials", common.Map{"node": id})] = digest(common.JSON(linked))
			}

		}
	}
	if len(raw) == 0 {
		return nil, baselines, nil
	}
	settings, _, e := legacySettings(raw)
	if e != nil {
		clear(raw)
		return nil, nil, e
	}
	var saved []byte
	if e = tx.QueryRowContext(ctx, `SELECT to_jsonb(s) FROM v3_settings s WHERE id=1`).Scan(&saved); e != nil {
		return nil, nil, e
	}
	decoded, e := common.Decode(saved)
	if e != nil {
		return nil, nil, e
	}
	if migrationLegacyValueEqual(string(common.JSON(common.M(decoded)["payload"])), string(common.JSON(settings))) {
		baselines[migrationLegacySourceKey("v3_settings", common.Map{"id": int64(1)})] = digest(common.JSON(decoded))
	}
	return raw, baselines, nil
}

// Translate the supported runtime settings back into a valid, complete v2
// program configuration. Round-trip comparison catches fields that v2 cannot
// express, rather than dropping them from the rollback configuration.
func migrationLegacySettingsYAML(original []byte, payload common.Map) ([]byte, error) {
	var root common.Map
	if yaml.Unmarshal(original, &root) != nil {
		return nil, ErrMigrationSession
	}
	for key := range payload {
		switch key {
		case "retention", "backup", "monitoring", "website_monitor", "feishu", "email", "collector":
		default:
			return nil, migrationLegacyPendingError("reverse_setting_has_no_legacy_representation")
		}
	}
	for _, key := range []string{"retention", "backup", "feishu", "email"} {
		if value, ok := payload[key]; ok {
			root[key] = value
		}
	}
	center := common.M(root["central"])
	if center == nil {
		return nil, ErrMigrationSession
	}
	root["central"] = center
	if value, ok := payload["website_monitor"]; ok {
		website := common.M(center["website_monitor"])
		if website == nil {
			website = common.Map{}
		}
		for key, value := range common.M(value) {
			website[key] = value
		}
		center["website_monitor"] = website
	}
	monitor := common.M(payload["monitoring"])
	health := common.M(root["health"])
	if health == nil {
		health = common.Map{}
	}
	root["health"] = health
	if monitor != nil {
		for key := range monitor {
			switch key {
			case "mode", "raw_hours", "history_days", "interval_seconds", "alerts", "repeat_hours", "group_wait_seconds", "group_interval_seconds", "alert_on_inotify_overflow", "alert_on_dropped_events":
			default:
				return nil, migrationLegacyPendingError("reverse_monitoring_setting_has_no_legacy_representation")
			}
		}
		legacy := common.M(center["monitoring"])
		if legacy == nil {
			legacy = common.Map{}
		}
		center["monitoring"] = legacy
		for _, key := range []string{"mode", "raw_hours", "history_days"} {
			if value, ok := monitor[key]; ok {
				legacy[key] = value
			}
		}
		for from, to := range map[string]string{"interval_seconds": "metrics_scrape_seconds", "alerts": "alerts", "alert_on_inotify_overflow": "alert_on_inotify_overflow", "alert_on_dropped_events": "alert_on_dropped_events"} {
			if value, ok := monitor[from]; ok {
				health[to] = value
			}
		}
		alert := common.M(health["alertmanager"])
		if alert == nil {
			alert = common.Map{}
		}
		health["alertmanager"] = alert
		for from, to := range map[string]string{"repeat_hours": "repeat_interval_hours", "group_wait_seconds": "group_wait_seconds", "group_interval_seconds": "group_interval_seconds"} {
			if value, ok := monitor[from]; ok {
				alert[to] = value
			}
		}
	}
	if collector := common.M(payload["collector"]); len(collector) > 0 {
		if len(collector) != 1 || collector["interval_seconds"] == nil {
			return nil, migrationLegacyPendingError("reverse_collector_setting_has_no_legacy_representation")
		}
		if monitor["interval_seconds"] != nil && common.I(collector["interval_seconds"]) != common.I(monitor["interval_seconds"]) {
			return nil, migrationLegacyPendingError("reverse_distinct_collector_interval_not_legacy")
		}
		health["metrics_scrape_seconds"] = collector["interval_seconds"]
	}
	normalized, e := migrationLegacyYAMLNumbers(root)
	if e != nil {
		return nil, e
	}
	raw, e := yaml.Marshal(normalized)
	if e != nil || len(raw) > 2<<20 {
		return nil, ErrMigrationSession
	}
	if _, e = configuration.Parse(raw, ""); e != nil {
		return nil, migrationLegacyPendingError("reverse_configuration_rejected_by_legacy_schema")
	}
	roundtrip, _, e := legacySettings(raw)
	if e != nil {
		return nil, e
	}
	expected := common.Clone(payload)
	delete(expected, "collector")
	// Compare only sections supplied by the v3 runtime; untouched source-only
	// installation values (paths, SSH/registry material) stay exactly in YAML.
	for key, value := range expected {
		if !migrationLegacyValueEqual(string(common.JSON(value)), string(common.JSON(roundtrip[key]))) {
			return nil, migrationLegacyPendingError("reverse_configuration_roundtrip_difference")
		}
	}
	return raw, nil
}

// JSON-backed values keep exact decimal tokens, which yaml.v3 otherwise emits
// as strings. Restore scalar types before producing a legacy configuration.
func migrationLegacyYAMLNumbers(value any) (any, error) {
	switch v := value.(type) {
	case json.Number:
		if n, e := v.Int64(); e == nil {
			return n, nil
		}
		n, e := v.Float64()
		return n, e
	case map[string]any:
		out := common.Map{}
		for key, item := range v {
			n, e := migrationLegacyYAMLNumbers(item)
			if e != nil {
				return nil, e
			}
			out[key] = n
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			n, e := migrationLegacyYAMLNumbers(item)
			if e != nil {
				return nil, e
			}
			out[i] = n
		}
		return out, nil
	default:
		return value, nil
	}
}
func (s *MigrationLegacySink) migrationLegacySettingsTx(ctx context.Context, tx *sql.Tx, operation string, data common.Map) error {
	if operation == "DELETE" {
		return migrationLegacyPendingError("reverse_settings_deletion_not_legacy")
	}
	var original []byte
	if e := tx.QueryRowContext(ctx, `SELECT payload FROM migration_yaml WHERE id=1`).Scan(&original); e != nil {
		return migrationLegacyPendingError("reverse_legacy_yaml_source_missing")
	}
	defer clear(original)
	raw, e := migrationLegacySettingsYAML(original, common.M(data["payload"]))
	if e != nil {
		return e
	}
	defer clear(raw)
	_, e = tx.ExecContext(ctx, `UPDATE migration_yaml SET payload=?,digest=? WHERE id=1`, raw, digest(raw))
	return e
}
func (s *MigrationLegacySink) migrationLegacyExportYAML(ctx context.Context) error {
	var raw []byte
	var hash string
	e := s.db.QueryRowContext(ctx, `SELECT payload,digest FROM migration_yaml WHERE id=1`).Scan(&raw, &hash)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}
	defer clear(raw)
	if digest(raw) != hash {
		return ErrMigrationSession
	}
	if _, e = configuration.Parse(raw, ""); e != nil {
		return ErrMigrationSession
	}
	// This export can always be regenerated from the same committed SQL row
	// after a crash between SQLite commit and atomic file replacement.
	if strings.TrimSpace(s.output) == "" {
		return ErrMigrationSession
	}
	return metricsRetentionAtomicFile(s.output, "configuration.yaml", raw)
}
