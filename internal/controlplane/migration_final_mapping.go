package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sort"

	"github.com/jackc/pgx/v5/pgconn"
	"webscan/internal/common"
)

// MapMigrationFinalDomains applies additions, modifications and deletions from
// the latest verified snapshots to real business tables. Only rows recorded in
// this session's authenticated ownership journal may be replaced or removed.
// It deliberately leaves all migration fences and notification holds enabled.
func (s *Store) MapMigrationFinalDomains(ctx context.Context, session string, expected int64, in MigrationFinalMappingInput, v *Vault) (report MigrationFinalMappingReport, err error) {
	return s.mapMigrationFinalDomains(ctx, session, expected, in, v)
}
func (s *Store) mapMigrationFinalDomains(ctx context.Context, session string, expected int64, in MigrationFinalMappingInput, v *Vault) (report MigrationFinalMappingReport, err error) {
	defer func() {
		if err != nil {
			err = safeMigrationSessionError(err)
			report.Added = 0
			report.Modified = 0
			report.Deleted = 0
			report.Unchanged = 0
			report.Complete = false
		}
	}()
	report = MigrationFinalMappingReport{Session: session, Protected: true, Pending: []MigrationReconciliationConflict{}, Conflicts: []MigrationReconciliationConflict{}}
	if v == nil {
		return report, ErrCredentialUnavailable
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
	if e != nil {
		return report, e
	}
	report.SessionVersion = state.Version
	if state.RecoveryHold || (state.Phase != "indexed" && state.Phase != "frozen" && state.Phase != "reconciled") {
		return report, ErrMigrationSession
	}
	revisions, e := migrationFinalRevisionsTx(ctx, tx, state)
	if e != nil {
		return report, e
	}
	revisionDigest := digest(common.JSON(revisions))
	report.Batch = digest([]byte("final-domains:" + session + ":" + revisionDigest))
	var live string
	if e = tx.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&live); e != nil {
		return report, e
	}
	// Protect conflict detection from writers which do not use migrationHeld.
	// The migration fence remains the normal coordination path for all workers.
	for _, table := range migrationFinalTables {
		if _, e = tx.ExecContext(ctx, `LOCK TABLE `+migrationFinalQualified(live, table)+` IN SHARE ROW EXCLUSIVE MODE`); e != nil {
			return report, e
		}
	}
	metadata, e := migrationFinalMetadataTx(ctx, tx, live)
	if e != nil {
		return report, e
	}
	owned, e := migrationFinalLoadOwnedTx(ctx, tx, v, session, metadata)
	if e != nil {
		return report, e
	}
	conflicts := map[string]int64{}
	for _, row := range owned {
		current, e := migrationFinalCurrentTx(ctx, tx, live, row)
		if e != nil && e != sql.ErrNoRows {
			return report, e
		}
		if e == sql.ErrNoRows || !reflect.DeepEqual(current, row.Data) {
			conflicts["owned_row_changed"]++
		}
	}
	if len(conflicts) > 0 {
		report.Conflicts = migrationFinalIssues(conflicts)
		return report, ErrConflict
	}
	var previous []byte
	var requested, finished int64
	e = tx.QueryRowContext(ctx, `SELECT report,request_version,finished_version FROM v3_migration_final_batches WHERE revision_digest=$1 AND session=$2 ORDER BY finished_version DESC LIMIT 1`, revisionDigest, session).Scan(&previous, &requested, &finished)
	if e == nil {
		var old MigrationFinalMappingReport
		if singleDecode(previous, &old) != nil {
			return report, ErrMigrationSession
		}
		if e = migrationFinalVerifyReceiptTx(ctx, tx, v, old, revisionDigest, owned); e != nil {
			return report, e
		}
		if !old.Complete {
			// An absent external backup or metrics replay can be supplied later.
			// Retrying incomplete work requires the current session generation.
			if expected != state.Version {
				return report, ErrConflict
			}
			report.Batch = digest([]byte(report.Batch + ":" + common.S(state.Version)))
		} else {
			// A durable receipt is not current external-evidence authority.
			// Recheck rows and source binding after a lost-response retry too.
			for _, r := range revisions {
				var metricCount int64
				if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_migration_revision_rows WHERE revision=$1 AND table_name='samples'`, r.ID).Scan(&metricCount); e != nil {
					return report, e
				}
				if metricCount > 0 {
					verified, e := MigrationMetricHistoryEvidenceTx(ctx, tx, session, r.ID)
					if e != nil || !verified {
						return report, ErrMigrationSession
					}
				}
				tables := []string{}
				for table, role := range migrationLegacyHistoryTables {
					if role == r.Role {
						tables = append(tables, table)
					}
				}
				var historyCount int64
				if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_migration_revision_rows WHERE revision=$1 AND table_name=ANY($2::text[])`, r.ID, tables).Scan(&historyCount); e != nil {
					return report, e
				}
				if historyCount > 0 {
					verified, e := VerifyLegacyHistoryTx(ctx, tx, session, r.ID, v)
					if e != nil || !verified {
						return report, ErrMigrationSession
					}
				}
			}
			if expected != state.Version && !(expected == requested && state.Version == finished) {
				return report, ErrConflict
			}
			if singleDecode(previous, &report) != nil {
				return report, ErrMigrationSession
			}
			report.SessionVersion = state.Version
			return report, tx.Commit()
		}
	}
	if e != nil && e != sql.ErrNoRows {
		return report, e
	}
	if expected != state.Version {
		return report, ErrConflict
	}
	scratch := "migration_final_" + token()[:16]
	metricVerified := map[string]bool{}
	historyVerified := map[string]bool{}
	for _, revision := range revisions {
		verified, checkErr := VerifyLegacyHistoryTx(ctx, tx, session, revision.ID, v)
		if checkErr != nil {
			return report, checkErr
		}
		historyVerified[revision.ID] = verified
		if revision.Role == "health" {
			verified, checkErr := MigrationMetricHistoryEvidenceTx(ctx, tx, session, revision.ID)
			if checkErr != nil {
				return report, checkErr
			}
			metricVerified[revision.ID] = verified
		}
	}
	if e = migrationFinalScratchTx(ctx, tx, live, scratch); e != nil {
		return report, e
	}
	pending, e := migrationFinalBuildCandidatesTx(ctx, tx, live, revisions, in, metricVerified, historyVerified)
	if e != nil {
		return report, e
	}
	candidate, e := migrationFinalReadCandidateTx(ctx, tx, live, scratch, owned, metadata)
	if e != nil {
		return report, e
	}
	if _, e = tx.ExecContext(ctx, `SELECT set_config('search_path',$1,true)`, quotePG(live)); e != nil {
		return report, e
	}
	for id, row := range candidate {
		if _, ok := owned[id]; ok {
			continue
		}
		_, e = migrationFinalCurrentTx(ctx, tx, live, row)
		if e == nil {
			conflicts["unowned_target_row"]++
		} else if e != sql.ErrNoRows {
			return report, e
		}
	}
	if len(conflicts) > 0 {
		report.Conflicts = migrationFinalIssues(conflicts)
		return report, ErrConflict
	}
	// Deleting a notification would cascade; never allow foreign children to
	// disappear merely because their parent happens to be migration-owned.
	if e = migrationFinalCascadeCheckTx(ctx, tx, live, owned, candidate); e != nil {
		return report, e
	}
	if e = bindMigrationDomain(ctx, tx, "final-domains", session, "", nil); e != nil {
		return report, e
	}
	// Historical identities have no mutable payload and are shared by domains.
	if _, e = tx.ExecContext(ctx, `INSERT INTO `+migrationFinalQualified(live, "v3_node_identities")+` SELECT * FROM `+migrationFinalQualified(scratch, "v3_node_identities")+` ON CONFLICT DO NOTHING`); e != nil {
		return report, e
	}
	report.Pending = migrationFinalIssues(pending)
	report.Complete = len(report.Pending) == 0
	report.SessionVersion = state.Version + 1
	// Insert the parent ledger first; all business changes and encrypted images
	// become visible atomically with this receipt and the session generation.
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_final_batches(id,session,request_version,finished_version,revision_digest,report) VALUES($1,$2,$3,$4,$5,'{}')`, report.Batch, session, expected, report.SessionVersion, revisionDigest); e != nil {
		return report, e
	}
	// Children are deleted first. Never delete and reinsert rows that only changed.
	for i := len(migrationFinalTables) - 1; i >= 0; i-- {
		table := migrationFinalTables[i]
		for _, id := range migrationFinalSorted(owned, table) {
			row := owned[id]
			if _, ok := candidate[id]; ok {
				continue
			}
			if _, e = tx.ExecContext(ctx, `DELETE FROM `+migrationFinalQualified(live, table)+` t WHERE to_jsonb(t) @> $1::jsonb`, common.JSON(row.Key)); e != nil {
				return report, migrationFinalSQLError(e)
			}
			if e = migrationFinalSaveChangeTx(ctx, tx, v, report.Batch, table, row.Logical, &row, nil); e != nil {
				return report, e
			}
			if _, e = tx.ExecContext(ctx, `DELETE FROM v3_migration_final_owned WHERE session=$1 AND table_name=$2 AND logical_key=$3`, session, table, row.Logical); e != nil {
				return report, e
			}
			report.Deleted++
		}
	}
	for _, table := range migrationFinalTables {
		for _, id := range migrationFinalSorted(candidate, table) {
			row := candidate[id]
			var before *migrationFinalRow
			if prior, ok := owned[id]; ok {
				if reflect.DeepEqual(prior.Data, row.Data) {
					report.Unchanged++
					continue
				}
				before = &prior
				report.Modified++
			} else {
				report.Added++
			}
			if e = migrationFinalWriteRowTx(ctx, tx, live, metadata[table], before, row); e != nil {
				return report, migrationFinalSQLError(e)
			}
			if e = migrationFinalSaveChangeTx(ctx, tx, v, report.Batch, table, row.Logical, before, &row); e != nil {
				return report, e
			}
			if e = migrationFinalSaveOwnedTx(ctx, tx, v, session, report.Batch, row); e != nil {
				return report, e
			}
		}
	}
	if _, e = tx.ExecContext(ctx, `DROP SCHEMA `+quotePG(scratch)+` CASCADE`); e != nil {
		return report, e
	}
	if e = migrationFinalSequencesTx(ctx, tx, live, metadata); e != nil {
		return report, e
	}
	candidateDigest := migrationFinalDigestRows(candidate)
	evidence := migrationFinalReceiptMAC(v, v.active, report, revisionDigest, candidateDigest)
	if evidence == "" {
		return report, ErrCredentialUnavailable
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_final_batches SET report=$2,key_id=$3,candidate_digest=$4,evidence_digest=$5 WHERE id=$1`, report.Batch, common.JSON(report), v.active, candidateDigest, evidence); e != nil {
		return report, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,updated_at=clock_timestamp() WHERE id=$1`, session); e != nil {
		return report, e
	}
	return report, tx.Commit()
}
func migrationFinalSorted(rows map[string]migrationFinalRow, table string) []string {
	out := []string{}
	for id, row := range rows {
		if row.Table == table {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
func migrationFinalSQLError(e error) error {
	var pg *pgconn.PgError
	if errors.As(e, &pg) && (pg.Code == "23503" || pg.Code == "23505") {
		return ErrConflict
	}
	return e
}
func migrationFinalCascadeCheckTx(ctx context.Context, tx *sql.Tx, live string, owned, candidate map[string]migrationFinalRow) error {
	for id, row := range owned {
		if row.Table != "v3_notifications" {
			continue
		}
		if _, keep := candidate[id]; keep {
			continue
		}
		for _, table := range []string{"v3_notification_attempts", "v3_notification_public"} {
			rows, e := tx.QueryContext(ctx, `SELECT to_jsonb(t) FROM `+migrationFinalQualified(live, table)+` t WHERE notification=$1`, row.Data["id"])
			if e != nil {
				return e
			}
			for rows.Next() {
				var raw []byte
				if e = rows.Scan(&raw); e != nil {
					rows.Close()
					return e
				}
				parsed, e := common.Decode(raw)
				if e != nil {
					rows.Close()
					return e
				}
				found := false
				for _, child := range owned {
					if child.Table == table && reflect.DeepEqual(child.Data, common.M(parsed)) {
						found = true
						break
					}
				}
				if !found {
					rows.Close()
					return ErrConflict
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
		}
	}
	return nil
}
func migrationFinalSequencesTx(ctx context.Context, tx *sql.Tx, live string, metadata map[string]migrationFinalTable) error {
	for _, table := range migrationFinalTables {
		for _, column := range metadata[table].Columns {
			var sequence sql.NullString
			if e := tx.QueryRowContext(ctx, `SELECT pg_get_serial_sequence($1,$2)`, migrationFinalQualified(live, table), column).Scan(&sequence); e != nil {
				return e
			}
			if !sequence.Valid {
				continue
			}
			var max sql.NullInt64
			if e := tx.QueryRowContext(ctx, `SELECT max(`+quotePG(column)+`) FROM `+migrationFinalQualified(live, table)).Scan(&max); e != nil {
				return e
			}
			if max.Valid {
				if _, e := tx.ExecContext(ctx, `SELECT setval($1::regclass,GREATEST($2,(SELECT last_value FROM `+sequence.String+`)),true)`, sequence.String, max.Int64); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
