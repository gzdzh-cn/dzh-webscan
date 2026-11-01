package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"time"

	"webscan/internal/common"
)

func migrationLegacyHistoryArchive(raw []byte, hash string) (archivedRecord, json.RawMessage, error) {
	if len(raw) > 8<<20 {
		return nil, nil, ErrMigrationSession
	}
	parsed, e := common.Decode(raw)
	if e != nil {
		return nil, nil, e
	}
	canonical := common.JSON(parsed)
	if digest(canonical) != hash {
		return nil, nil, ErrMigrationSession
	}
	var r archivedRecord
	if json.Unmarshal(canonical, &r) != nil {
		return nil, nil, ErrMigrationSession
	}
	return r, canonical, nil
}
func migrationLegacyHistoryCandidatesTx(ctx context.Context, tx *sql.Tx, session, sourceID string, rev MigrationRevisionReport, in MigrationLegacyHistoryInput, v *Vault) (map[string]migrationLegacyHistoryRow, map[string]int64, error) {
	tables := make([]string, 0, len(migrationLegacyHistoryTables))
	for name := range migrationLegacyHistoryTables {
		tables = append(tables, name)
	}
	rows, e := tx.QueryContext(ctx, `SELECT i.table_name,i.record_key,a.payload,i.digest FROM v3_migration_revision_rows i JOIN v3_legacy_records a ON a.source=$2 AND a.table_name=i.table_name AND a.record_key=i.record_key::text AND a.digest=i.digest WHERE i.revision=$1 AND i.table_name=ANY($3::text[]) ORDER BY i.table_name,i.record_key LIMIT 250001`, rev.ID, rev.Source, tables)
	if e != nil {
		return nil, nil, e
	}
	type candidate struct {
		table, hash string
		key         int64
		raw         []byte
	}
	input := []candidate{}
	for rows.Next() {
		var c candidate
		if e = rows.Scan(&c.table, &c.key, &c.raw, &c.hash); e != nil {
			rows.Close()
			return nil, nil, e
		}
		if _, supported := migrationLegacyHistoryTables[c.table]; supported {
			input = append(input, c)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(input) > 250000 {
		return nil, nil, ErrMigrationSession
	}
	out := map[string]migrationLegacyHistoryRow{}
	pending := map[string]int64{}
	for _, c := range input {
		if migrationLegacyHistoryTables[c.table] != rev.Role {
			pending["legacy_history_in_wrong_source_role"]++
			continue
		}
		rec, canonical, e := migrationLegacyHistoryArchive(c.raw, c.hash)
		if e != nil {
			return nil, nil, e
		}
		pub, reason, e := migrationLegacyHistoryProjection(ctx, tx, session, sourceID, rev, c.table, c.key, rec)
		if e != nil {
			return nil, nil, e
		}
		r := migrationLegacyHistoryRow{ID: migrationLegacyHistoryID(session, sourceID, c.table, c.key), SourceID: sourceID, Role: rev.Role, Revision: rev.ID, Table: c.table, RecordKey: c.key, ArchiveDigest: c.hash, Envelope: migrationLegacyHistoryEnvelope{Source: canonical, Public: pub}}
		if reason != "" {
			pending[reason]++
		}
		if c.table == "config_backups" {
			artifact, restored, reason, e := migrationLegacyHistoryArtifact(ctx, tx, session, r.ID, rec, in, v)
			if e != nil {
				return nil, nil, e
			}
			r.Envelope.Artifact = artifact
			r.Envelope.RestoredSHA256 = restored
			pub["artifact_available"] = len(artifact) > 0
			pub["restore_verified"] = restored != ""
			if reason != "" {
				pending[reason]++
			}
		}
		out[r.ID] = r
	}
	return out, pending, nil
}
func migrationLegacyHistoryRecordIdentity(r archivedRecord, field string) (string, error) {
	v, e := archiveText(r, field, 512)
	if e != nil || v == "" {
		return "", ErrMigrationSession
	}
	return v, nil
}
func migrationLegacyHistoryParent(sourceID, table, id string) string {
	return digest(common.JSON([]any{"v2-history-parent", sourceID, table, id}))
}
func migrationLegacyHistoryProjection(ctx context.Context, tx *sql.Tx, session, sourceID string, rev MigrationRevisionReport, table string, key int64, r archivedRecord) (common.Map, string, error) {
	p := common.Map{"legacy_table": table, "record_key": key, "read_only": true, "can_resume": false, "can_rollback": false, "original_encrypted": true}
	reason := ""
	addTime := func(field, output string) error {
		stamp, e := r.timestamp(field, true)
		if e != nil {
			return e
		}
		if stamp != nil {
			p[output] = stamp.Format(time.RFC3339Nano)
		}
		return nil
	}
	addID := func(field string) error {
		id, e := migrationLegacyHistoryRecordIdentity(r, field)
		if e != nil {
			return e
		}
		p["identity"] = migrationLegacyHistoryParent(sourceID, table, id)
		return nil
	}
	parent := func(field, target string) error {
		id, e := migrationLegacyHistoryRecordIdentity(r, field)
		if e != nil {
			return e
		}
		p["parent"] = migrationLegacyHistoryParent(sourceID, target, id)
		var n int64
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_legacy_records WHERE source=$1 AND table_name=$2 AND payload->'id'->>'value'=$3`, rev.Source, target, id).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			reason = "legacy_history_parent_missing"
		}
		return nil
	}
	switch table {
	case "jobs":
		if e := addID("id"); e != nil {
			return nil, "", e
		}
		status, e := archiveText(r, "status", 64)
		if e != nil {
			return nil, "", e
		}
		p["status"] = "unknown"
		switch status {
		case "complete", "failed", "interrupted", "queued", "running":
			p["status"] = status
		}
		if status != "complete" {
			reason = "legacy_deployment_requires_original_resume_or_rollback"
		}
		kind, e := archiveText(r, "kind", 64)
		if e != nil {
			return nil, "", e
		}
		switch kind {
		case "apply", "add-node", "upgrade-node", "resume", "rollback", "remove-nodes", "external":
			p["kind"] = kind
		default:
			p["kind"] = "legacy"
		}
		if e = addTime("created", "created_at"); e != nil {
			return nil, "", e
		}
		if e = addTime("updated", "updated_at"); e != nil {
			return nil, "", e
		}
	case "logs":
		if e := parent("job", "jobs"); e != nil {
			return nil, "", e
		}
		if e := addTime("time", "created_at"); e != nil {
			return nil, "", e
		}
		p["message_available"] = true
	case "job_workflow", "job_progress", "upgrade_jobs":
		if e := parent("job", "jobs"); e != nil {
			return nil, "", e
		}
		if table == "job_progress" {
			if e := addTime("time", "created_at"); e != nil {
				return nil, "", e
			}
			step, e := r.integer("step")
			if e != nil || step < 0 {
				return nil, "", ErrMigrationSession
			}
			p["step"] = step
		}
	case "config_backups":
		if e := addID("id"); e != nil {
			return nil, "", e
		}
		if e := addTime("time", "created_at"); e != nil {
			return nil, "", e
		}
		p["kind"] = "configuration-backup"
	case "config_backup_details":
		if e := parent("id", "config_backups"); e != nil {
			return nil, "", e
		}
		restored, e := r.integer("restored")
		if e != nil || restored < 0 {
			return nil, "", ErrMigrationSession
		}
		p["previously_restored"] = restored > 0
		omitted, e := archiveText(r, "omitted", 1<<20)
		if e != nil {
			return nil, "", e
		}
		var fields []string
		if json.Unmarshal([]byte(omitted), &fields) != nil {
			return nil, "", ErrMigrationSession
		}
		p["omitted_fields"] = len(fields)
	case "config_backup_previews", "recovery_previews", "upgrade_previews", "node_removal_previews", "website_backup_pins":
		expiry, e := r.integer("expires")
		if e != nil || expiry < 0 {
			return nil, "", ErrMigrationSession
		}
		p["authorization_imported"] = false
		p["status"] = "expired"
		if expiry > time.Now().Unix() {
			p["status"] = "active-legacy"
			reason = "legacy_authorization_still_active"
		}
		if table == "config_backup_previews" {
			if e := parent("backup", "config_backups"); e != nil {
				return nil, "", e
			}
		}
	case "node_removals":
		if e := parent("job", "jobs"); e != nil {
			return nil, "", e
		}
		complete, e := r.boolean("complete")
		if e != nil {
			return nil, "", e
		}
		p["complete"] = complete
		if !complete {
			reason = "legacy_node_removal_not_complete"
		}
	case "job_archives":
		if e := parent("id", "jobs"); e != nil {
			return nil, "", e
		}
		if e := addTime("time", "created_at"); e != nil {
			return nil, "", e
		}
		p["archived"] = true
	case "backup_import_attempts":
		count, e := r.integer("count")
		if e != nil || count < 0 {
			return nil, "", ErrMigrationSession
		}
		until, e := r.integer("until")
		if e != nil || until < 0 {
			return nil, "", ErrMigrationSession
		}
		p["failed_attempts"] = count
		p["active_rate_limit"] = until > time.Now().Unix()
		if until > time.Now().Unix() {
			reason = "legacy_backup_import_rate_limit_active"
		}
	case "watchdog_state":
		if e := addID("id"); e != nil {
			return nil, "", e
		}
		phase, e := archiveText(r, "phase", 64)
		if e != nil {
			return nil, "", e
		}
		switch phase {
		case "healthy", "firing", "resolved", "unknown", "down", "up":
			p["phase"] = phase
		default:
			p["phase"] = "legacy"
		}
		if e := addTime("since", "observed_at"); e != nil {
			return nil, "", e
		}
		p["current_health_evidence"] = false
	case "watchdog_outbox":
		if e := addID("id"); e != nil {
			return nil, "", e
		}
		done, e := r.boolean("done")
		if e != nil {
			return nil, "", e
		}
		p["done"] = done
		if !done {
			reason = "legacy_watchdog_notification_not_confirmed"
		}
		if e := addTime("created", "created_at"); e != nil {
			return nil, "", e
		}
	case "probes":
		if e := addID("node"); e != nil {
			return nil, "", e
		}
		if e := addTime("received", "observed_at"); e != nil {
			return nil, "", e
		}
		p["current_health_evidence"] = false
	case "website_incident_origins":
		// Old labels are historical context, not today's website/node identity.
		id, e := r.integer("id")
		if e != nil || id < 1 {
			return nil, "", ErrMigrationSession
		}
		p["incident_id"] = strconv.FormatInt(id, 10)
	default:
		return nil, "", ErrMigrationSession
	}
	return p, reason, nil
}
