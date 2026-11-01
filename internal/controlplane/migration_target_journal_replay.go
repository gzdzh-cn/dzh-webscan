package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
)

// Payloads exist only in a private, fixed Go mapper call. JSON receipts omit
// row keys, accounts, credentials, notification text and complete row values.
type MigrationTargetReplayRow struct {
	Table     string          `json:"-"`
	Operation string          `json:"-"`
	Sequence  int64           `json:"-"`
	BeforeKey json.RawMessage `json:"-"`
	AfterKey  json.RawMessage `json:"-"`
	Before    json.RawMessage `json:"-"`
	After     json.RawMessage `json:"-"`
	SHA256    string          `json:"-"`
}
type MigrationTargetReplayBatch struct {
	Session  string                     `json:"session"`
	Consumer string                     `json:"consumer"`
	ID       string                     `json:"id"`
	SHA256   string                     `json:"sha256"`
	Phase    string                     `json:"phase"`
	Rows     []MigrationTargetReplayRow `json:"-"`
}
type MigrationTargetReplayReceipt struct {
	ID, SHA256 string
	Rows       int64
}

// The sink must atomically apply a batch and persist ID/SHA256, returning the
// identical receipt on replay. A response loss cannot authorize another apply.
// The production sink must map into the actual v2 schema; an opaque archive or
// mirror is useful evidence but is not a successful legacy rollback.
type MigrationTargetReplaySink interface {
	ApplyMigrationJournal(context.Context, MigrationTargetReplayBatch) (MigrationTargetReplayReceipt, error)
}
type MigrationTargetReplayReport struct {
	Session        string `json:"session"`
	Consumer       string `json:"consumer"`
	State          string `json:"state"`
	Rows           int64  `json:"rows"`
	SHA256         string `json:"sha256"`
	SessionVersion int64  `json:"session_version"`
}
type migrationTargetReplayCheckpoint struct {
	MigrationTargetReplayReport
	table, key                 string
	sequence                   int64
	request, started, finished int64
}

func migrationTargetReplayTx(ctx context.Context, tx *sql.Tx, id, consumer string) (migrationTargetReplayCheckpoint, error) {
	out := migrationTargetReplayCheckpoint{MigrationTargetReplayReport: MigrationTargetReplayReport{Session: id, Consumer: consumer}}
	e := tx.QueryRowContext(ctx, `SELECT state,rows,digest,cursor_table,cursor_key,cursor_sequence,request_version,started_version,finished_version FROM v3_migration_target_replays WHERE session=$1 AND consumer=$2`, id, consumer).Scan(&out.State, &out.Rows, &out.SHA256, &out.table, &out.key, &out.sequence, &out.request, &out.started, &out.finished)
	return out, e
}
func migrationTargetReplaySeed(id, consumer, seal string) string {
	raw, _ := json.Marshal([]string{"webscan-v3/target-replay/v1", id, consumer, seal})
	return digest(raw)
}
func migrationTargetReplayStep(hash string, row MigrationTargetReplayRow) string {
	raw, _ := json.Marshal([]string{hash, row.Table, row.Operation, strconv.FormatInt(row.Sequence, 10), string(row.BeforeKey), string(row.AfterKey), row.SHA256})
	return digest(raw)
}
func migrationTargetReplayRows(ctx context.Context, tx *sql.Tx, id string, checkpoint migrationTargetReplayCheckpoint) ([]MigrationTargetReplayRow, error) {
	query := `SELECT table_name,'BASELINE',0::bigint,'null'::jsonb,record_key,'null'::jsonb,row_data,row_digest FROM v3_migration_target_baselines WHERE session=$1 AND ($2='' OR table_name COLLATE "C">$2 COLLATE "C" OR table_name=$2 AND record_key::text COLLATE "C">$3 COLLATE "C") ORDER BY table_name COLLATE "C",record_key::text COLLATE "C" LIMIT 250`
	args := []any{id, checkpoint.table, checkpoint.key}
	if checkpoint.State == "changes" {
		query = `SELECT table_name,operation,sequence,before_key,after_key,before_data,after_data,change_digest FROM v3_migration_target_changes WHERE session=$1 AND sequence>$2 ORDER BY sequence LIMIT 250`
		args = []any{id, checkpoint.sequence}
	}
	rows, e := tx.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []MigrationTargetReplayRow{}
	size := 0
	for rows.Next() {
		var row MigrationTargetReplayRow
		if e = rows.Scan(&row.Table, &row.Operation, &row.Sequence, &row.BeforeKey, &row.AfterKey, &row.Before, &row.After, &row.SHA256); e != nil {
			return nil, e
		}
		bytes := len(row.Before) + len(row.After) + len(row.BeforeKey) + len(row.AfterKey)
		if bytes > 32<<20 {
			return nil, ErrMigrationSession
		}
		if len(out) > 0 && size+bytes > 32<<20 {
			break
		}
		size += bytes
		out = append(out, row)
	}
	return out, rows.Err()
}
func verifyMigrationTargetReplayCheckpoint(ctx context.Context, tx *sql.Tx, id, consumer, seal string, c migrationTargetReplayCheckpoint) error {
	hash := migrationTargetReplaySeed(id, consumer, seal)
	var count int64
	query := `SELECT table_name,'BASELINE',0::bigint,'null'::jsonb,record_key,row_digest FROM v3_migration_target_baselines WHERE session=$1`
	args := []any{id}
	if c.State == "baseline" {
		query += ` AND $2<>'' AND (table_name COLLATE "C"<$2 COLLATE "C" OR table_name=$2 AND record_key::text COLLATE "C"<=$3 COLLATE "C")`
		args = append(args, c.table, c.key)
	}
	query += ` ORDER BY table_name COLLATE "C",record_key::text COLLATE "C"`
	consume := func(query string, args ...any) error {
		rows, e := tx.QueryContext(ctx, query, args...)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var row MigrationTargetReplayRow
			if e = rows.Scan(&row.Table, &row.Operation, &row.Sequence, &row.BeforeKey, &row.AfterKey, &row.SHA256); e != nil {
				return e
			}
			hash = migrationTargetReplayStep(hash, row)
			count++
		}
		return rows.Err()
	}
	if consume(query, args...) != nil {
		return ErrMigrationSession
	}
	if c.State != "baseline" {
		if consume(`SELECT table_name,operation,sequence,before_key,after_key,change_digest FROM v3_migration_target_changes WHERE session=$1 AND ($2 OR sequence<=$3) ORDER BY sequence`, id, c.State == "complete", c.sequence) != nil {
			return ErrMigrationSession
		}
	}
	if count != c.Rows || hash != c.SHA256 {
		return ErrMigrationSession
	}
	return nil
}
func (s *Store) MigrationTargetReplay(ctx context.Context, id, consumer string) (MigrationTargetReplayReport, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return MigrationTargetReplayReport{}, ErrMigrationSession
	}
	defer tx.Rollback()
	if migrationSessionLock(ctx, tx, id) != nil {
		return MigrationTargetReplayReport{}, ErrMigrationSession
	}
	state, e := migrationSessionTx(ctx, tx, id)
	if e != nil {
		return MigrationTargetReplayReport{}, ErrMigrationSession
	}
	r, e := migrationTargetReplayTx(ctx, tx, id, consumer)
	if e != nil {
		return MigrationTargetReplayReport{}, ErrMigrationSession
	}
	r.SessionVersion = state.Version
	if tx.Commit() != nil {
		return MigrationTargetReplayReport{}, ErrMigrationSession
	}
	return r.MigrationTargetReplayReport, nil
}
func (s *Store) ReplayMigrationTargetJournal(ctx context.Context, id string, expected int64, consumer string, sink MigrationTargetReplaySink) (MigrationTargetReplayReport, error) {
	r, e := s.replayMigrationTargetJournal(ctx, id, expected, consumer, sink)
	if e != nil {
		return MigrationTargetReplayReport{}, safeMigrationSessionError(e)
	}
	return r, nil
}
func (s *Store) replayMigrationTargetJournal(ctx context.Context, id string, expected int64, consumer string, sink MigrationTargetReplaySink) (MigrationTargetReplayReport, error) {
	if !identifier.MatchString(consumer) || sink == nil {
		return MigrationTargetReplayReport{}, ErrMigrationSession
	}
	verified := false
	for {
		tx, e := s.DB.BeginTx(ctx, nil)
		if e != nil {
			return MigrationTargetReplayReport{}, e
		}
		if e = migrationSessionLock(ctx, tx, id); e != nil {
			tx.Rollback()
			return MigrationTargetReplayReport{}, e
		}
		state, e := migrationSessionTx(ctx, tx, id)
		if e != nil || state.RecoveryHold {
			tx.Rollback()
			return MigrationTargetReplayReport{}, ErrMigrationSession
		}
		journal, e := migrationTargetStateTx(ctx, tx, id)
		if e != nil || journal.State != "sealed" {
			tx.Rollback()
			return MigrationTargetReplayReport{}, ErrMigrationSession
		}
		checkpoint, e := migrationTargetReplayTx(ctx, tx, id, consumer)
		if e == sql.ErrNoRows {
			if state.Version != expected {
				tx.Rollback()
				return MigrationTargetReplayReport{}, ErrConflict
			}
			if verifyMigrationTargetJournal(ctx, tx, id) != nil {
				tx.Rollback()
				return MigrationTargetReplayReport{}, ErrMigrationSession
			}
			seed := migrationTargetReplaySeed(id, consumer, journal.SealSHA256)
			if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_target_replays(session,consumer,request_version,started_version,state,digest) VALUES($1,$2,$3,$4,'baseline',$5)`, id, consumer, expected, expected+1, seed); e != nil {
				tx.Rollback()
				return MigrationTargetReplayReport{}, e
			}
			if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,updated_at=clock_timestamp() WHERE id=$1`, id); e != nil {
				tx.Rollback()
				return MigrationTargetReplayReport{}, e
			}
			if e = tx.Commit(); e != nil {
				return MigrationTargetReplayReport{}, e
			}
			expected++
			continue
		}
		if e != nil {
			tx.Rollback()
			return MigrationTargetReplayReport{}, e
		}
		if checkpoint.State == "complete" {
			if expected != state.Version && (expected != checkpoint.request && expected != checkpoint.started || state.Version != checkpoint.finished) {
				tx.Rollback()
				return MigrationTargetReplayReport{}, ErrConflict
			}
			if verifyMigrationTargetJournal(ctx, tx, id) != nil || verifyMigrationTargetReplayCheckpoint(ctx, tx, id, consumer, journal.SealSHA256, checkpoint) != nil {
				tx.Rollback()
				return MigrationTargetReplayReport{}, ErrMigrationSession
			}
			checkpoint.SessionVersion = state.Version
			if e = tx.Commit(); e != nil {
				return MigrationTargetReplayReport{}, e
			}
			return checkpoint.MigrationTargetReplayReport, nil
		}
		if expected != state.Version && !(state.Version == checkpoint.started && expected == checkpoint.request) {
			tx.Rollback()
			return MigrationTargetReplayReport{}, ErrConflict
		}
		expected = state.Version
		if !verified {
			if verifyMigrationTargetJournal(ctx, tx, id) != nil || verifyMigrationTargetReplayCheckpoint(ctx, tx, id, consumer, journal.SealSHA256, checkpoint) != nil {
				tx.Rollback()
				return MigrationTargetReplayReport{}, ErrMigrationSession
			}
			verified = true
		}
		items, e := migrationTargetReplayRows(ctx, tx, id, checkpoint)
		if e != nil {
			tx.Rollback()
			return MigrationTargetReplayReport{}, e
		}
		if len(items) == 0 {
			phase := "changes"
			finished := int64(0)
			if checkpoint.State == "changes" {
				phase = "complete"
				finished = expected + 1
			}
			if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_target_replays SET state=$3,finished_version=$4 WHERE session=$1 AND consumer=$2`, id, consumer, phase, finished); e != nil {
				tx.Rollback()
				return MigrationTargetReplayReport{}, e
			}
			if phase == "complete" {
				if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,updated_at=clock_timestamp() WHERE id=$1`, id); e != nil {
					tx.Rollback()
					return MigrationTargetReplayReport{}, e
				}
			}
			if e = tx.Commit(); e != nil {
				return MigrationTargetReplayReport{}, e
			}
			if phase == "complete" {
				expected++
			}
			continue
		}
		next := checkpoint
		for _, item := range items {
			next.SHA256 = migrationTargetReplayStep(next.SHA256, item)
			next.Rows++
			if checkpoint.State == "baseline" {
				next.table, next.key = item.Table, string(item.AfterKey)
			} else {
				next.sequence = item.Sequence
			}
		}
		bound, _ := json.Marshal([]string{id, consumer, journal.SealSHA256, checkpoint.State, checkpoint.SHA256, next.SHA256, strconv.FormatInt(int64(len(items)), 10)})
		batch := MigrationTargetReplayBatch{Session: id, Consumer: consumer, ID: digest(bound), SHA256: next.SHA256, Phase: checkpoint.State, Rows: items}
		receipt, e := sink.ApplyMigrationJournal(ctx, batch)
		if e != nil || receipt.ID != batch.ID || receipt.SHA256 != batch.SHA256 || receipt.Rows != int64(len(items)) {
			tx.Rollback()
			return MigrationTargetReplayReport{}, ErrMigrationSession
		}
		if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_target_replays SET cursor_table=$3,cursor_key=$4,cursor_sequence=$5,rows=$6,digest=$7 WHERE session=$1 AND consumer=$2`, id, consumer, next.table, next.key, next.sequence, next.Rows, next.SHA256); e != nil {
			tx.Rollback()
			return MigrationTargetReplayReport{}, e
		}
		if e = tx.Commit(); e != nil {
			return MigrationTargetReplayReport{}, e
		}
	}
}
