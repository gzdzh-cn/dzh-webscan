package controlplane

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"sort"
	"strconv"

	"webscan/internal/common"
)

type MigrationLegacyHistoryInput struct {
	ConfigurationBackupDirectories map[string]string `json:"-"`
	RestoreVerificationDirectory   string            `json:"-"`
}
type MigrationLegacyHistoryReport struct {
	Session           string                            `json:"session"`
	Revision          string                            `json:"revision"`
	Role              string                            `json:"role"`
	SessionVersion    int64                             `json:"session_version"`
	Records           int64                             `json:"records"`
	Artifacts         int64                             `json:"artifacts"`
	RestoredArtifacts int64                             `json:"restored_artifacts"`
	Pending           []MigrationReconciliationConflict `json:"pending"`
	Complete          bool                              `json:"complete"`
	ReadOnlyHistory   bool                              `json:"read_only_history"`
	ReadyForCutover   bool                              `json:"ready_for_cutover"`
}
type migrationLegacyHistoryEnvelope struct {
	Source         json.RawMessage `json:"source"`
	Public         common.Map      `json:"public"`
	Artifact       []byte          `json:"artifact,omitempty"`
	RestoredSHA256 string          `json:"restored_sha256,omitempty"`
}
type migrationLegacyHistoryRow struct {
	ID, SourceID, Role, Table, Revision, ArchiveDigest string
	RecordKey                                          int64
	Envelope                                           migrationLegacyHistoryEnvelope
}

var migrationLegacyHistoryTables = map[string]string{
	"jobs": "host-manager", "logs": "host-manager", "job_workflow": "host-manager", "job_progress": "host-manager", "recovery_previews": "host-manager", "upgrade_previews": "host-manager", "upgrade_jobs": "host-manager", "node_removal_previews": "host-manager", "node_removals": "host-manager", "config_backups": "host-manager", "config_backup_details": "host-manager", "config_backup_previews": "host-manager", "job_archives": "host-manager", "backup_import_attempts": "host-manager", "watchdog_state": "host-manager", "watchdog_outbox": "host-manager",
	"probes": "central", "website_backup_pins": "central", "website_incident_origins": "central",
}

func migrationLegacyHistoryAAD(session, id string) string {
	return "legacy-history:" + session + ":" + id
}
func migrationLegacyHistoryID(session, source, table string, key int64) string {
	return digest(common.JSON([]any{"v2-history", session, source, table, key}))
}
func migrationLegacyHistoryMAC(v *Vault, key string, report MigrationLegacyHistoryReport, rows string) string {
	return migrationNodesMAC(v, key, common.JSON([]any{"webscan-v3/legacy-history-receipt/v1", report, rows}))
}
func migrationLegacyHistoryRowsDigest(rows map[string]migrationLegacyHistoryRow) string {
	keys := make([]string, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := []any{}
	for _, key := range keys {
		r := rows[key]
		out = append(out, []any{key, r.SourceID, r.Role, r.Table, r.RecordKey, r.Revision, r.ArchiveDigest, digest(common.JSON(r.Envelope.Public)), digest(r.Envelope.Artifact), r.Envelope.RestoredSHA256})
	}
	return digest(common.JSON(out))
}

// Source-complete history is deliberately separate from signed v3 lifecycle
// tasks. Nothing imported here can be resumed, claimed or executed remotely.
func (s *Store) MapMigrationLegacyHistory(ctx context.Context, session string, expected int64, revision string, in MigrationLegacyHistoryInput, v *Vault) (report MigrationLegacyHistoryReport, err error) {
	defer func() {
		if err != nil {
			report = MigrationLegacyHistoryReport{}
			err = safeMigrationSessionError(err)
		}
	}()
	if !validArchiveSource(session) || !validArchiveSource(revision) || expected < 1 || v == nil {
		return report, ErrMigrationSession
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return report, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(773376002)`); e != nil {
		return report, e
	}
	if e = migrationSessionLock(ctx, tx, session); e != nil {
		return report, e
	}
	state, e := migrationSessionTx(ctx, tx, session)
	if e != nil || state.RecoveryHold || (state.Phase != "indexed" && state.Phase != "frozen" && state.Phase != "reconciled") {
		return report, ErrMigrationSession
	}
	if state.Version != expected {
		var raw []byte
		var requestVersion, finishedVersion int64
		e = tx.QueryRowContext(ctx, `SELECT report,request_version,finished_version FROM v3_migration_legacy_history_runs WHERE session=$1 AND revision=$2`, session, revision).Scan(&raw, &requestVersion, &finishedVersion)
		if e == nil && requestVersion == expected && finishedVersion <= state.Version {
			verified, verifyErr := VerifyLegacyHistoryTx(ctx, tx, session, revision, v)
			if verifyErr != nil {
				return report, verifyErr
			}
			if verified && singleDecode(raw, &report) == nil && report.SessionVersion == finishedVersion {
				return report, tx.Commit()
			}
		}
		return report, ErrConflict
	}
	rev, e := migrationRevisionTx(ctx, tx, revision)
	if e != nil || rev.State != "ready" {
		return report, ErrMigrationSession
	}
	var sourceID, owner, latest string
	if e = tx.QueryRowContext(ctx, `SELECT source_id,session FROM v3_migration_revisions WHERE id=$1`, revision).Scan(&sourceID, &owner); e != nil || owner != session {
		return report, ErrMigrationSession
	}
	if e = tx.QueryRowContext(ctx, `SELECT id FROM v3_migration_revisions WHERE session=$1 AND role=$2 ORDER BY sequence DESC LIMIT 1`, session, rev.Role).Scan(&latest); e != nil || latest != revision {
		return report, ErrMigrationSession
	}
	if e = verifyMigrationRevisionIndex(ctx, tx, revision); e != nil {
		return report, e
	}
	if _, e = tx.ExecContext(ctx, `LOCK TABLE v3_legacy_history IN SHARE ROW EXCLUSIVE MODE`); e != nil {
		return report, e
	}
	previous, e := migrationLegacyHistoryLoadTx(ctx, tx, session, sourceID, v, rev.Role)
	if e != nil {
		return report, e
	}
	if e = migrationLegacyHistoryPreviousTx(ctx, tx, session, sourceID, rev.Role, previous, v); e != nil {
		return report, e
	}
	candidate, pending, e := migrationLegacyHistoryCandidatesTx(ctx, tx, session, sourceID, rev, in, v)
	if e != nil {
		return report, e
	}
	// Compare against the authenticated prior public image before any delta.
	for id, row := range previous {
		var current []byte
		if e = tx.QueryRowContext(ctx, `SELECT payload FROM v3_legacy_history WHERE id=$1 FOR UPDATE`, id).Scan(&current); e != nil || !migrationLegacyValueEqual(string(current), string(common.JSON(row.Envelope.Public))) {
			return report, ErrConflict
		}
	}
	for id, row := range candidate {
		if _, owned := previous[id]; !owned {
			var exists bool
			if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_legacy_history WHERE id=$1)`, id).Scan(&exists); e != nil {
				return report, e
			}
			if exists {
				return report, ErrConflict
			}
		}
		key, nonce, sealed, e := migrationFinalSeal(v, migrationLegacyHistoryAAD(session, id), common.JSON(row.Envelope))
		if e != nil {
			return report, e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO v3_legacy_history(id,session,source_id,role,table_name,record_key,payload) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload`, id, session, sourceID, rev.Role, row.Table, row.RecordKey, common.JSON(row.Envelope.Public)); e != nil {
			return report, e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_legacy_history_rows VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,archive_digest=excluded.archive_digest,key_id=excluded.key_id,nonce=excluded.nonce,ciphertext=excluded.ciphertext`, id, revision, row.ArchiveDigest, key, nonce, sealed); e != nil {
			return report, e
		}
	}
	for id := range previous {
		if _, present := candidate[id]; !present {
			if _, e = tx.ExecContext(ctx, `DELETE FROM v3_legacy_history WHERE id=$1`, id); e != nil {
				return report, e
			}
		}
	}
	report = MigrationLegacyHistoryReport{Session: session, Revision: revision, Role: rev.Role, SessionVersion: expected + 1, Records: int64(len(candidate)), Pending: migrationFinalIssues(pending), ReadOnlyHistory: true}
	for _, r := range candidate {
		if len(r.Envelope.Artifact) > 0 {
			report.Artifacts++
			if r.Envelope.RestoredSHA256 == digest(r.Envelope.Artifact) {
				report.RestoredArtifacts++
			}
		}
	}
	report.Complete = len(report.Pending) == 0
	rowsDigest := migrationLegacyHistoryRowsDigest(candidate)
	mac := migrationLegacyHistoryMAC(v, v.active, report, rowsDigest)
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_legacy_history_runs VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(session,revision) DO UPDATE SET report=excluded.report,key_id=excluded.key_id,evidence_digest=excluded.evidence_digest,rows_digest=excluded.rows_digest,request_version=excluded.request_version,finished_version=excluded.finished_version`, session, revision, sourceID, rev.Role, common.JSON(report), v.active, mac, rowsDigest, expected, expected+1); e != nil {
		return report, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,updated_at=clock_timestamp() WHERE id=$1`, session); e != nil {
		return report, e
	}
	return report, tx.Commit()
}

func migrationLegacyHistoryLoadTx(ctx context.Context, tx *sql.Tx, session, sourceID string, v *Vault, roles ...string) (map[string]migrationLegacyHistoryRow, error) {
	role := ""
	if len(roles) > 0 {
		role = roles[0]
	}
	rows, e := tx.QueryContext(ctx, `SELECT h.id,h.source_id,h.role,h.table_name,h.record_key,r.revision,r.archive_digest,r.key_id,r.nonce,r.ciphertext FROM v3_legacy_history h JOIN v3_migration_legacy_history_rows r USING(id) WHERE h.session=$1 AND h.source_id=$2 AND ($3='' OR h.role=$3) ORDER BY h.id`, session, sourceID, role)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]migrationLegacyHistoryRow{}
	for rows.Next() {
		var r migrationLegacyHistoryRow
		var key string
		var nonce, sealed []byte
		if e = rows.Scan(&r.ID, &r.SourceID, &r.Role, &r.Table, &r.RecordKey, &r.Revision, &r.ArchiveDigest, &key, &nonce, &sealed); e != nil {
			return nil, e
		}
		raw, e := migrationFinalOpen(v, key, migrationLegacyHistoryAAD(session, r.ID), nonce, sealed)
		if e != nil {
			return nil, e
		}
		e = singleDecode(raw, &r.Envelope)
		clear(raw)
		if e != nil || r.ID != migrationLegacyHistoryID(session, r.SourceID, r.Table, r.RecordKey) || digest(r.Envelope.Source) != r.ArchiveDigest {
			return nil, ErrMigrationSession
		}
		out[r.ID] = r
	}
	return out, rows.Err()
}

// The caller holds the migration gate. Recheck the current revision, original
// archived rows, private authenticated payloads and the actual public history.
func VerifyLegacyHistoryTx(ctx context.Context, tx *sql.Tx, session, revision string, v *Vault) (bool, error) {
	var sourceID, role, key, rowsDigest, mac string
	var reportRaw []byte
	e := tx.QueryRowContext(ctx, `SELECT source_id,role,report,key_id,rows_digest,evidence_digest FROM v3_migration_legacy_history_runs WHERE session=$1 AND revision=$2`, session, revision).Scan(&sourceID, &role, &reportRaw, &key, &rowsDigest, &mac)
	if e == sql.ErrNoRows {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	var report MigrationLegacyHistoryReport
	if singleDecode(reportRaw, &report) != nil || report.Session != session || report.Revision != revision || report.Role != role || !report.ReadOnlyHistory || report.ReadyForCutover {
		return false, ErrMigrationSession
	}
	actual := migrationLegacyHistoryMAC(v, key, report, rowsDigest)
	if actual == "" || subtle.ConstantTimeCompare([]byte(actual), []byte(mac)) != 1 {
		return false, ErrMigrationSession
	}
	if !report.Complete || len(report.Pending) > 0 {
		return false, nil
	}
	var latest, source, indexedSource string
	if e = tx.QueryRowContext(ctx, `SELECT id,snapshot_sha256,source_id FROM v3_migration_revisions WHERE session=$1 AND role=$2 ORDER BY sequence DESC LIMIT 1`, session, role).Scan(&latest, &source, &indexedSource); e != nil || latest != revision || indexedSource != sourceID {
		return false, ErrMigrationSession
	}
	if e = verifyMigrationRevisionIndex(ctx, tx, revision); e != nil {
		return false, e
	}
	rows, e := migrationLegacyHistoryLoadTx(ctx, tx, session, sourceID, v, role)
	if e != nil {
		return false, e
	}
	if int64(len(rows)) != report.Records || migrationLegacyHistoryRowsDigest(rows) != rowsDigest {
		return false, ErrMigrationSession
	}
	var expected int64
	for table, expectedRole := range migrationLegacyHistoryTables {
		if expectedRole == role {
			var count int64
			if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_migration_revision_rows WHERE revision=$1 AND table_name=$2`, revision, table).Scan(&count); e != nil {
				return false, e
			}
			expected += count
		}
	}
	if expected != report.Records {
		return false, ErrMigrationSession
	}
	for id, row := range rows {
		if row.Revision != revision || row.Role != role {
			return false, ErrMigrationSession
		}
		var original, current []byte
		var archived string
		if e = tx.QueryRowContext(ctx, `SELECT payload,digest FROM v3_legacy_records WHERE source=$1 AND table_name=$2 AND record_key=$3`, source, row.Table, strconv.FormatInt(row.RecordKey, 10)).Scan(&original, &archived); e != nil || archived != row.ArchiveDigest {
			return false, ErrMigrationSession
		}
		if _, _, e = migrationLegacyHistoryArchive(original, archived); e != nil {
			return false, e
		}
		if e = tx.QueryRowContext(ctx, `SELECT payload FROM v3_legacy_history WHERE id=$1`, id).Scan(&current); e != nil || !migrationLegacyValueEqual(string(current), string(common.JSON(row.Envelope.Public))) {
			return false, ErrConflict
		}
		if len(row.Envelope.Artifact) > 0 && row.Envelope.RestoredSHA256 != digest(row.Envelope.Artifact) {
			return false, ErrMigrationSession
		}
	}
	return true, nil
}

func migrationLegacyHistoryPreviousTx(ctx context.Context, tx *sql.Tx, session, sourceID, role string, rows map[string]migrationLegacyHistoryRow, v *Vault) error {
	var raw []byte
	var key, hash, mac string
	e := tx.QueryRowContext(ctx, `SELECT report,key_id,rows_digest,evidence_digest FROM v3_migration_legacy_history_runs WHERE session=$1 AND source_id=$2 AND role=$3 ORDER BY finished_version DESC LIMIT 1`, session, sourceID, role).Scan(&raw, &key, &hash, &mac)
	if e == sql.ErrNoRows {
		if len(rows) > 0 {
			return ErrMigrationSession
		}
		return nil
	}
	if e != nil {
		return e
	}
	var report MigrationLegacyHistoryReport
	if singleDecode(raw, &report) != nil || report.Session != session || report.Role != role || report.Records != int64(len(rows)) || hash != migrationLegacyHistoryRowsDigest(rows) {
		return ErrMigrationSession
	}
	actual := migrationLegacyHistoryMAC(v, key, report, hash)
	if actual == "" || subtle.ConstantTimeCompare([]byte(actual), []byte(mac)) != 1 {
		return ErrMigrationSession
	}
	return nil
}
