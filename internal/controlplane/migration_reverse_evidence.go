package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"sort"

	"webscan/internal/common"
)

type MigrationLegacyProjectionEvidence struct {
	Session        string                            `json:"session"`
	Consumer       string                            `json:"consumer"`
	Phase          string                            `json:"phase"`
	RevisionSHA256 string                            `json:"revision_sha256"`
	JournalSHA256  string                            `json:"journal_sha256"`
	ReplaySHA256   string                            `json:"replay_sha256"`
	OutputSHA256   string                            `json:"output_sha256"`
	MetricsSHA256  string                            `json:"metrics_sha256,omitempty"`
	Coverage       string                            `json:"coverage,omitempty"`
	Rows           int64                             `json:"rows"`
	Pending        []MigrationReconciliationConflict `json:"pending"`
	Verified       bool                              `json:"verified"`
	KeyID          string                            `json:"key_id"`
	SHA256         string                            `json:"sha256"`
}

func migrationLegacyEvidenceMAC(v *Vault, e MigrationLegacyProjectionEvidence) string {
	e.SHA256 = ""
	return migrationNodesMAC(v, e.KeyID, common.JSON([]any{"webscan-v3/actual-legacy-output/v1", e}))
}
func (s *MigrationLegacySink) migrationLegacyActualDigest(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := sha256.New()
	artifacts, e := s.migrationLegacyArtifactDigest(ctx)
	if e != nil {
		return "", e
	}
	h.Write(common.JSON([]any{"configuration-backup-artifacts", artifacts}))
	metrics, e := s.migrationReverseMetricsArtifactDigest(ctx)
	if e != nil {
		return "", e
	}
	h.Write(common.JSON([]any{"actual-metric-artifacts", metrics}))
	roles := []string{}
	for role := range s.roles {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	var yamlDigest string
	if e := s.db.QueryRowContext(ctx, `SELECT digest FROM migration_yaml WHERE id=1`).Scan(&yamlDigest); e != nil && e != sql.ErrNoRows {
		return "", e
	}
	h.Write(common.JSON([]any{"legacy-configuration-yaml", yamlDigest}))
	for _, role := range roles {
		alias := quotePG(migrationLegacyAlias(role))
		var integrity string
		if e := s.db.QueryRowContext(ctx, `PRAGMA `+alias+`.integrity_check`).Scan(&integrity); e != nil || integrity != "ok" {
			return "", ErrMigrationSession
		}
		fk, e := s.db.QueryContext(ctx, `PRAGMA `+alias+`.foreign_key_check`)
		if e != nil {
			return "", e
		}
		bad := fk.Next()
		e = fk.Err()
		fk.Close()
		if bad || e != nil {
			return "", ErrMigrationSession
		}
		tables, e := s.db.QueryContext(ctx, `SELECT name,sql FROM `+alias+`.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
		if e != nil {
			return "", e
		}
		type table struct{ name, ddl string }
		all := []table{}
		for tables.Next() {
			var t table
			if e = tables.Scan(&t.name, &t.ddl); e != nil {
				tables.Close()
				return "", e
			}
			all = append(all, t)
		}
		e = tables.Err()
		tables.Close()
		if e != nil {
			return "", e
		}
		h.Write(common.JSON([]any{role, all}))
		for _, t := range all {
			h.Write(common.JSON([]any{t.name, t.ddl}))
			rows, e := s.db.QueryContext(ctx, `SELECT rowid,* FROM `+alias+`.`+quotePG(t.name)+` ORDER BY rowid`)
			if e != nil {
				return "", e
			}
			cols, e := rows.Columns()
			if e != nil {
				rows.Close()
				return "", e
			}
			for rows.Next() {
				values := make([]any, len(cols))
				dest := make([]any, len(cols))
				for i := range values {
					dest[i] = &values[i]
				}
				if e = rows.Scan(dest...); e != nil {
					rows.Close()
					return "", e
				}
				_, raw, e := migrationArchiveRow(cols, values)
				if e != nil {
					rows.Close()
					return "", e
				}
				h.Write(common.JSON([]any{values[0], digest(raw)}))
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return "", e
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Baseline projection is a dry reverse into real private v2 databases while
// source writers and target notification senders remain frozen. It proves no
// post-cutover replay and never marks an armed journal as sealed.
func (s *Store) ProjectMigrationLegacyBaseline(ctx context.Context, session string, expected int64, consumer string, sink *MigrationLegacySink, v *Vault) (out MigrationLegacyProjectionEvidence, err error) {
	defer func() {
		if err != nil {
			err = safeMigrationSessionError(err)
		}
	}()
	if sink == nil || sink.session != session || v == nil || !identifier.MatchString(consumer) {
		return out, ErrMigrationSession
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(773376002)`); e != nil {
		return out, e
	}
	if e = migrationSessionLock(ctx, tx, session); e != nil {
		return out, e
	}
	state, e := migrationSessionTx(ctx, tx, session)
	if e != nil || state.RecoveryHold {
		return out, ErrMigrationSession
	}
	if expected != state.Version {
		return out, ErrConflict
	}
	journal, e := migrationTargetStateTx(ctx, tx, session)
	if e != nil || journal.State != "armed" || verifyMigrationTargetArmedTx(ctx, tx, session) != nil {
		return out, ErrMigrationSession
	}
	revisions, e := migrationFinalRevisionsTx(ctx, tx, state)
	if e != nil {
		return out, e
	}
	checkpoint := migrationTargetReplayCheckpoint{}
	checkpoint.State = "baseline"
	checkpoint.SHA256 = migrationTargetReplaySeed(session, consumer+"_baseline", journal.BaselineSHA256)
	for {
		rows, e := migrationTargetReplayRows(ctx, tx, session, checkpoint)
		if e != nil {
			return out, e
		}
		if len(rows) == 0 {
			break
		}
		next := checkpoint
		for _, row := range rows {
			next.SHA256 = migrationTargetReplayStep(next.SHA256, row)
			next.Rows++
			next.table = row.Table
			next.key = string(row.AfterKey)
		}
		id := digest(common.JSON([]any{session, consumer, "baseline", checkpoint.SHA256, next.SHA256}))
		receipt, e := sink.ApplyMigrationJournal(ctx, MigrationTargetReplayBatch{session, consumer + "_baseline", id, next.SHA256, "baseline", rows})
		if e != nil || receipt.ID != id || receipt.SHA256 != next.SHA256 || receipt.Rows != int64(len(rows)) {
			return out, ErrMigrationSession
		}
		checkpoint = next
	}
	if checkpoint.Rows != journal.BaselineRows {
		return out, ErrMigrationSession
	}
	report, e := sink.Report(ctx)
	if e != nil {
		return out, e
	}
	if e = VerifyMigrationLegacyArtifactsTx(ctx, tx, session, sink, v); e != nil {
		return out, e
	}
	if e = VerifyMigrationLegacyNodeActivationsTx(ctx, tx, session, sink, v); e != nil {
		return out, e
	}
	actual, e := sink.migrationLegacyActualDigest(ctx)
	if e != nil {
		return out, e
	}
	out = MigrationLegacyProjectionEvidence{Session: session, Consumer: consumer, Phase: "baseline", RevisionSHA256: digest(common.JSON(revisions)), JournalSHA256: journal.BaselineSHA256, ReplaySHA256: checkpoint.SHA256, OutputSHA256: actual, Rows: checkpoint.Rows, Pending: report.Pending, Verified: len(report.Pending) == 0, KeyID: v.active}
	out.SHA256 = migrationLegacyEvidenceMAC(v, out)
	if out.SHA256 == "" {
		return out, ErrCredentialUnavailable
	}
	return out, tx.Commit()
}

// Call after the sealed journal's durable ReplayMigrationTargetJournal has
// completed against this same sink. The receipt binds the exact replay chain
// to the actual v2 business contents, including post-cutover additions.
func (s *Store) VerifyMigrationLegacyRollback(ctx context.Context, session string, expected int64, consumer string, sink *MigrationLegacySink, v *Vault, configs ...Config) (out MigrationLegacyProjectionEvidence, err error) {
	defer func() {
		if err != nil {
			err = safeMigrationSessionError(err)
		}
	}()
	if sink == nil || sink.session != session || v == nil || len(configs) > 1 {
		return out, ErrMigrationSession
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if e = migrationSessionLock(ctx, tx, session); e != nil {
		return out, e
	}
	state, e := migrationSessionTx(ctx, tx, session)
	if e != nil || state.RecoveryHold {
		return out, ErrMigrationSession
	}
	if state.Version != expected {
		return out, ErrConflict
	}
	journal, e := migrationTargetStateTx(ctx, tx, session)
	if e != nil || journal.State != "sealed" || verifyMigrationTargetJournal(ctx, tx, session) != nil {
		return out, ErrMigrationSession
	}
	replay, e := migrationTargetReplayTx(ctx, tx, session, consumer)
	if e != nil || replay.State != "complete" || verifyMigrationTargetReplayCheckpoint(ctx, tx, session, consumer, journal.SealSHA256, replay) != nil {
		return out, ErrMigrationSession
	}
	if replay.Rows != journal.BaselineRows+journal.Changes {
		return out, ErrMigrationSession
	}
	var applied int64
	var last bool
	if e = sink.db.QueryRowContext(ctx, `SELECT coalesce(sum(rows),0),coalesce(max(CASE WHEN digest=? THEN 1 ELSE 0 END),0)=1 FROM migration_receipts WHERE consumer=?`, replay.SHA256, consumer).Scan(&applied, &last); e != nil || applied != replay.Rows || !last {
		return out, ErrMigrationSession
	}
	revisions, e := migrationFinalRevisionsTx(ctx, tx, state)
	if e != nil {
		return out, e
	}
	report, e := sink.Report(ctx)
	if e != nil {
		return out, e
	}
	if e = VerifyMigrationLegacyArtifactsTx(ctx, tx, session, sink, v); e != nil {
		return out, e
	}
	if e = VerifyMigrationLegacyNodeActivationsTx(ctx, tx, session, sink, v); e != nil {
		return out, e
	}
	coverage, metricDigest := "legacy-business-only", ""
	if len(configs) == 1 {
		metricDigest, e = VerifyMigrationReverseMetricsTx(ctx, tx, configs[0], session, sink, v)
		if e != nil || !releaseDigest(metricDigest) {
			return out, ErrMigrationCutoverProtected
		}
		coverage = "legacy-business-and-metric-archive"
	}
	actual, e := sink.migrationLegacyActualDigest(ctx)
	if e != nil {
		return out, e
	}
	out = MigrationLegacyProjectionEvidence{Session: session, Consumer: consumer, Phase: "rollback", RevisionSHA256: digest(common.JSON(revisions)), JournalSHA256: journal.SealSHA256, ReplaySHA256: replay.SHA256, OutputSHA256: actual, Rows: replay.Rows, Pending: report.Pending, Verified: len(report.Pending) == 0, KeyID: v.active}
	out.Coverage, out.MetricsSHA256 = coverage, metricDigest
	out.SHA256 = migrationLegacyEvidenceMAC(v, out)
	if out.SHA256 == "" {
		return out, ErrCredentialUnavailable
	}
	return out, tx.Commit()
}

func VerifyMigrationLegacyEvidenceTx(ctx context.Context, tx *sql.Tx, session, consumer string, evidence MigrationLegacyProjectionEvidence, sink *MigrationLegacySink, v *Vault, configs ...Config) (bool, error) {
	if sink == nil || sink.session != session || evidence.Session != session || evidence.Consumer != consumer || v == nil {
		return false, ErrMigrationSession
	}
	mac := migrationLegacyEvidenceMAC(v, evidence)
	if mac == "" || subtle.ConstantTimeCompare([]byte(mac), []byte(evidence.SHA256)) != 1 {
		return false, ErrMigrationSession
	}
	if !evidence.Verified || len(evidence.Pending) > 0 {
		return false, nil
	}
	state, e := migrationSessionTx(ctx, tx, session)
	if e != nil || state.RecoveryHold {
		return false, ErrMigrationSession
	}
	revisions, e := migrationFinalRevisionsTx(ctx, tx, state)
	if e != nil || digest(common.JSON(revisions)) != evidence.RevisionSHA256 {
		return false, ErrMigrationSession
	}
	journal, e := migrationTargetStateTx(ctx, tx, session)
	if e != nil {
		return false, e
	}
	switch evidence.Phase {
	case "baseline":
		if journal.State != "armed" || journal.BaselineSHA256 != evidence.JournalSHA256 || journal.BaselineRows != evidence.Rows || verifyMigrationTargetArmedTx(ctx, tx, session) != nil {
			return false, ErrMigrationSession
		}
	case "rollback":
		if journal.State != "sealed" || journal.SealSHA256 != evidence.JournalSHA256 || verifyMigrationTargetJournal(ctx, tx, session) != nil {
			return false, ErrMigrationSession
		}
		replay, e := migrationTargetReplayTx(ctx, tx, session, consumer)
		if e != nil || replay.State != "complete" || replay.SHA256 != evidence.ReplaySHA256 || replay.Rows != evidence.Rows || verifyMigrationTargetReplayCheckpoint(ctx, tx, session, consumer, journal.SealSHA256, replay) != nil {
			return false, ErrMigrationSession
		}
		if len(configs) > 0 {
			if len(configs) != 1 || evidence.Coverage != "legacy-business-and-metric-archive" || !releaseDigest(evidence.MetricsSHA256) {
				return false, ErrMigrationCutoverProtected
			}
			actual, e := VerifyMigrationReverseMetricsTx(ctx, tx, configs[0], session, sink, v)
			if e != nil || actual != evidence.MetricsSHA256 {
				return false, ErrMigrationCutoverProtected
			}
		} else if evidence.MetricsSHA256 != "" {
			return false, ErrMigrationCutoverProtected
		}
	default:
		return false, ErrMigrationSession
	}
	report, e := sink.Report(ctx)
	if e != nil || len(report.Pending) > 0 {
		return false, ErrMigrationSession
	}
	if e = VerifyMigrationLegacyArtifactsTx(ctx, tx, session, sink, v); e != nil {
		return false, e
	}
	if e = VerifyMigrationLegacyNodeActivationsTx(ctx, tx, session, sink, v); e != nil {
		return false, e
	}
	actual, e := sink.migrationLegacyActualDigest(ctx)
	if e != nil || actual != evidence.OutputSHA256 {
		return false, ErrMigrationSession
	}
	return true, nil
}
