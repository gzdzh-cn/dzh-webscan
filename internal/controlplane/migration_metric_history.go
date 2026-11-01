package controlplane

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

var ErrMigrationMetricHistory = errors.New("旧指标归档、迁移保护、版本或时序库核对不一致；历史尚未确认完成，未修改当前采集状态")

// Registration, backup and restore are owned by the shared schema entrypoint.
const migrationMetricHistorySchema = `
CREATE TABLE v3_migration_metric_runs(id text PRIMARY KEY,session text NOT NULL REFERENCES v3_migration_sessions(id),revision text NOT NULL REFERENCES v3_migration_revisions(id),source text NOT NULL,revision_digest text NOT NULL,target_sha256 text NOT NULL,state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','verified')),records bigint NOT NULL CHECK(records>=0),projected_digest text NOT NULL DEFAULT '',verified_at timestamptz,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(session,revision));
CREATE TABLE v3_migration_metric_rows(run text NOT NULL REFERENCES v3_migration_metric_runs(id),record_key bigint NOT NULL,archive_digest text NOT NULL,node text NOT NULL,sampled bigint NOT NULL CHECK(sampled>0),resolution integer NOT NULL CHECK(resolution IN (0,300)),origin text NOT NULL CHECK(origin IN ('native','legacy')),point jsonb NOT NULL,projected_digest text NOT NULL,samples bigint NOT NULL CHECK(samples>0),verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(run,record_key),UNIQUE(run,node,sampled,resolution));
`

type MigrationMetricHistoryReport struct {
	Session          string `json:"session"`
	Generation       string `json:"generation"`
	Revision         string `json:"revision"`
	Source           string `json:"source"`
	RevisionSHA256   string `json:"revision_sha256"`
	TargetSHA256     string `json:"target_sha256"`
	State            string `json:"state"`
	Records          int64  `json:"records"`
	VerifiedRecords  int64  `json:"verified_records"`
	ProjectedSamples int64  `json:"projected_samples"`
	FirstSample      int64  `json:"first_sample_unix_ms,omitempty"`
	LastSample       int64  `json:"last_sample_unix_ms,omitempty"`
	ProjectedSHA256  string `json:"projected_sha256,omitempty"`
	ReadOnlyHistory  bool   `json:"read_only_history"`
	ReadyForCutover  bool   `json:"ready_for_cutover"`
}

func migrationMetricSessionTx(ctx context.Context, tx *sql.Tx, session string, expected int64) error {
	if !validArchiveSource(session) || expected < 1 {
		return ErrMigrationMetricHistory
	}
	if migrationSessionLock(ctx, tx, session) != nil {
		return ErrMigrationMetricHistory
	}
	state, err := migrationSessionTx(ctx, tx, session)
	if err != nil || state.Version != expected || state.RecoveryHold {
		return ErrMigrationMetricHistory
	}
	held, err := migrationHeld(ctx, tx)
	if err != nil || !held {
		return ErrMigrationMetricHistory
	}
	return nil
}

func migrationMetricRevisionTx(ctx context.Context, tx *sql.Tx, session, revision string) (MigrationRevisionReport, int64, error) {
	var count int64
	r, err := migrationRevisionTx(ctx, tx, revision)
	if err != nil || r.Role != "health" || r.State != "ready" {
		return r, 0, ErrMigrationMetricHistory
	}
	var owner string
	if tx.QueryRowContext(ctx, "SELECT session FROM v3_migration_revisions WHERE id=$1", revision).Scan(&owner) != nil || owner != session {
		return r, 0, ErrMigrationMetricHistory
	}
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM v3_migration_revision_rows WHERE revision=$1 AND table_name='samples'", revision).Scan(&count) != nil {
		return r, 0, ErrMigrationMetricHistory
	}
	return r, count, nil
}

func migrationMetricReportTx(ctx context.Context, tx *sql.Tx, session, generation string) (MigrationMetricHistoryReport, error) {
	out := MigrationMetricHistoryReport{Session: session, Generation: generation, ReadOnlyHistory: true}
	if !validArchiveSource(session) || !validArchiveSource(generation) {
		return out, ErrMigrationMetricHistory
	}
	err := tx.QueryRowContext(ctx, `SELECT revision,source,revision_digest,target_sha256,state,records,projected_digest FROM v3_migration_metric_runs WHERE id=$1 AND session=$2 FOR UPDATE`, generation, session).Scan(&out.Revision, &out.Source, &out.RevisionSHA256, &out.TargetSHA256, &out.State, &out.Records, &out.ProjectedSHA256)
	if err != nil {
		return out, ErrMigrationMetricHistory
	}
	err = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(samples),0),coalesce(min(sampled),0)*1000,coalesce(max(sampled),0)*1000 FROM v3_migration_metric_rows WHERE run=$1`, generation).Scan(&out.VerifiedRecords, &out.ProjectedSamples, &out.FirstSample, &out.LastSample)
	return out, err
}

func (s *Store) PrepareMigrationMetricHistory(ctx context.Context, m *Metrics, session string, expected int64, revision string) (MigrationMetricHistoryReport, error) {
	target, err := migrationMetricTarget(m)
	if err != nil {
		return MigrationMetricHistoryReport{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
	}
	defer tx.Rollback()
	if migrationMetricSessionTx(ctx, tx, session, expected) != nil {
		return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
	}
	r, count, err := migrationMetricRevisionTx(ctx, tx, session, revision)
	if err != nil || verifyMigrationRevisionIndex(ctx, tx, revision) != nil {
		return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
	}
	generation := digest([]byte("legacy-metric-v1:" + session + ":" + revision + ":" + r.Digest))
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_migration_metric_runs(id,session,revision,source,revision_digest,target_sha256,records) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(session,revision) DO NOTHING`, generation, session, revision, r.Source, r.Digest, target, count); err != nil {
		return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
	}
	out, err := migrationMetricReportTx(ctx, tx, session, generation)
	if err != nil || out.Records != count || out.Source != r.Source || out.RevisionSHA256 != r.Digest || out.TargetSHA256 != target {
		return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
	}
	if count == 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE v3_migration_metric_runs SET state='verified',projected_digest=$2,verified_at=clock_timestamp() WHERE id=$1", generation, digest(nil)); err != nil {
			return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
		}
		out.State, out.ProjectedSHA256 = "verified", digest(nil)
	}
	if err := tx.Commit(); err != nil {
		return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
	}
	return out, nil
}

func (s *Store) MigrationMetricHistoryReport(ctx context.Context, session, generation string) (MigrationMetricHistoryReport, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
	}
	defer tx.Rollback()
	out, err := migrationMetricReportTx(ctx, tx, session, generation)
	if err != nil {
		return out, ErrMigrationMetricHistory
	}
	return out, tx.Commit()
}

// One call is bounded to 100 archive rows and two minutes. The same generation
// and original timestamps are reused after any lost VM or PostgreSQL response.
func (s *Store) RunMigrationMetricHistory(ctx context.Context, m *Metrics, session string, expected int64, generation string) (MigrationMetricHistoryReport, error) {
	target, err := migrationMetricTarget(m)
	if err != nil {
		return MigrationMetricHistoryReport{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
	}
	defer conn.Close()
	var locked bool
	resource := "migration-metric-history:" + generation
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", resource).Scan(&locked); err != nil || !locked {
		return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		if _, err := conn.ExecContext(cleanup, "SELECT pg_advisory_unlock(hashtextextended($1,0))", resource); err != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	for attempt := 0; attempt < 100; attempt++ {
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
		}
		if migrationMetricSessionTx(ctx, tx, session, expected) != nil {
			tx.Rollback()
			return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
		}
		out, err := migrationMetricReportTx(ctx, tx, session, generation)
		r, count, revisionErr := migrationMetricRevisionTx(ctx, tx, session, out.Revision)
		if err != nil || revisionErr != nil || out.TargetSHA256 != target || out.Source != r.Source || out.RevisionSHA256 != r.Digest || out.Records != count {
			tx.Rollback()
			return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
		}
		if attempt == 0 && verifyMigrationRevisionIndex(ctx, tx, out.Revision) != nil {
			tx.Rollback()
			return MigrationMetricHistoryReport{}, ErrMigrationMetricHistory
		}
		var key int64
		var raw []byte
		var archived string
		err = tx.QueryRowContext(ctx, `SELECT i.record_key,a.payload,a.digest FROM v3_migration_revision_rows i JOIN v3_legacy_records a ON a.source=$2 AND a.table_name=i.table_name AND a.record_key=i.record_key::text AND a.digest=i.digest WHERE i.revision=$1 AND i.table_name='samples' AND NOT EXISTS(SELECT 1 FROM v3_migration_metric_rows done WHERE done.run=$3 AND done.record_key=i.record_key) ORDER BY i.record_key LIMIT 1`, out.Revision, out.Source, generation).Scan(&key, &raw, &archived)
		if err == sql.ErrNoRows {
			if verifyMigrationRevisionIndex(ctx, tx, out.Revision) != nil {
				tx.Rollback()
				return out, ErrMigrationMetricHistory
			}
			verified, hash, err := migrationMetricRowsVerifiedTx(ctx, tx, out)
			if err != nil || !verified {
				tx.Rollback()
				return out, ErrMigrationMetricHistory
			}
			if _, err := tx.ExecContext(ctx, "UPDATE v3_migration_metric_runs SET state='verified',projected_digest=$2,verified_at=clock_timestamp() WHERE id=$1", generation, hash); err != nil {
				tx.Rollback()
				return out, ErrMigrationMetricHistory
			}
			if err := tx.Commit(); err != nil {
				return out, ErrMigrationMetricHistory
			}
			return s.MigrationMetricHistoryReport(ctx, session, generation)
		}
		if err != nil {
			tx.Rollback()
			return out, ErrMigrationMetricHistory
		}
		record, err := decodedArchiveRecord(raw, archived)
		if err != nil {
			tx.Rollback()
			return out, ErrMigrationMetricHistory
		}
		point, err := migrationMetricPointFromArchive(record)
		if err != nil {
			tx.Rollback()
			return out, ErrMigrationMetricHistory
		}
		payload, lines, err := point.project(generation)
		if err != nil {
			tx.Rollback()
			return out, ErrMigrationMetricHistory
		}
		op, stop := context.WithTimeout(ctx, 15*time.Second)
		err = m.writeMetricPayload(op, m.WriteURL, payload)
		if err == nil {
			err = migrationMetricVerifyVM(op, m, point.selector(generation), point.Sampled, point.Sampled, lines)
		}
		stop()
		if err != nil {
			tx.Rollback()
			return out, ErrMigrationMetricHistory
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_migration_metric_rows(run,record_key,archive_digest,node,sampled,resolution,origin,point,projected_digest,samples) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, generation, key, archived, point.Node, point.Sampled, point.Resolution, point.Origin, point.Raw, digest(payload), len(lines)); err != nil {
			tx.Rollback()
			return out, ErrMigrationMetricHistory
		}
		if err := tx.Commit(); err != nil {
			return out, ErrMigrationMetricHistory
		}
	}
	return s.MigrationMetricHistoryReport(ctx, session, generation)
}

func migrationMetricRowsVerifiedTx(ctx context.Context, tx *sql.Tx, out MigrationMetricHistoryReport) (bool, string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT i.record_key,i.digest,coalesce(r.archive_digest,''),coalesce(r.projected_digest,''),a.payload,r.node,r.sampled,r.resolution,r.origin,r.point,r.samples FROM v3_migration_revision_rows i LEFT JOIN v3_migration_metric_rows r ON r.run=$2 AND r.record_key=i.record_key LEFT JOIN v3_legacy_records a ON a.source=$3 AND a.table_name=i.table_name AND a.record_key=i.record_key::text AND a.digest=i.digest WHERE i.revision=$1 AND i.table_name='samples' ORDER BY i.record_key`, out.Revision, out.Generation, out.Source)
	if err != nil {
		return false, "", err
	}
	defer rows.Close()
	hash := digest(nil)
	var count int64
	for rows.Next() {
		var key int64
		var archived, actual, projected string
		var raw, saved []byte
		var node, origin sql.NullString
		var sampled, resolution, samples sql.NullInt64
		if err := rows.Scan(&key, &archived, &actual, &projected, &raw, &node, &sampled, &resolution, &origin, &saved, &samples); err != nil {
			return false, "", err
		}
		if archived != actual || !releaseDigest(projected) {
			return false, "", nil
		}
		record, err := decodedArchiveRecord(raw, archived)
		if err != nil {
			return false, "", err
		}
		point, err := migrationMetricPointFromArchive(record)
		if err != nil || !node.Valid || !sampled.Valid || !resolution.Valid || !origin.Valid || !samples.Valid || point.Node != node.String || point.Sampled != sampled.Int64 || int64(point.Resolution) != resolution.Int64 || point.Origin != origin.String {
			return false, "", ErrMigrationMetricHistory
		}
		payload, lines, err := point.project(out.Generation)
		var originalValue, savedValue any
		if err != nil || digest(payload) != projected || int64(len(lines)) != samples.Int64 || json.Unmarshal(point.Raw, &originalValue) != nil || json.Unmarshal(saved, &savedValue) != nil {
			return false, "", ErrMigrationMetricHistory
		}
		originalJSON, _ := json.Marshal(originalValue)
		savedJSON, _ := json.Marshal(savedValue)
		if digest(originalJSON) != digest(savedJSON) {
			return false, "", ErrMigrationMetricHistory
		}
		hash = digest([]byte(hash + ":" + strconv.FormatInt(key, 10) + ":" + archived + ":" + projected))
		count++
	}
	if err := rows.Err(); err != nil {
		return false, "", err
	}
	return count == out.Records && out.VerifiedRecords == out.Records, hash, nil
}

// A final mapper may consume this receipt only after the immutable SQLite
// archive is still byte-identical and every projected row was exported from VM.
// This never activates the migration or changes current metric cursors.
func MigrationMetricHistoryEvidenceTx(ctx context.Context, tx *sql.Tx, session, revision string) (bool, error) {
	r, count, err := migrationMetricRevisionTx(ctx, tx, session, revision)
	if err != nil {
		return false, ErrMigrationMetricHistory
	}
	if verifyMigrationRevisionIndex(ctx, tx, revision) != nil {
		return false, ErrMigrationMetricHistory
	}
	if count == 0 {
		return true, nil
	}
	var generation string
	if err := tx.QueryRowContext(ctx, "SELECT id FROM v3_migration_metric_runs WHERE session=$1 AND revision=$2", session, revision).Scan(&generation); err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, ErrMigrationMetricHistory
	}
	out, err := migrationMetricReportTx(ctx, tx, session, generation)
	if err != nil || out.State != "verified" || out.Source != r.Source || out.RevisionSHA256 != r.Digest || out.Records != count {
		return false, ErrMigrationMetricHistory
	}
	verified, hash, err := migrationMetricRowsVerifiedTx(ctx, tx, out)
	if err != nil {
		return false, ErrMigrationMetricHistory
	}
	return verified && hash == out.ProjectedSHA256, nil
}
