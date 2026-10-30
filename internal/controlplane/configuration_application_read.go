package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var errApplicationCursor = errors.New("配置应用日志游标不正确")
var errApplicationActor = errors.New("当前账号不能继续此配置应用，请由原操作账号继续或由管理员回退")

type configurationApplicationActions struct {
	CanResume   bool `json:"can_resume"`
	CanRollback bool `json:"can_rollback"`
	CanCancel   bool `json:"can_cancel"`
}
type configurationApplicationView struct {
	Job configurationApplicationJob `json:"job"`
	configurationApplicationActions
}

// Hints only, computed with the authenticated journal in the same snapshot.
// A write still rechecks current state, actor and the confirmed log cursor.
func applicationActionsTx(ctx context.Context, tx *sql.Tx, c *Config, user string, j privateConfigurationApplication) (configurationApplicationActions, error) {
	var out configurationApplicationActions
	if c == nil || !c.Executor.Enabled || !c.Executor.ApplicationsEnabled || c.Central.Instance != j.member || j.Finished != nil {
		return out, nil
	}
	rev, err := configurationRestoreAccount(ctx, tx, user)
	if err != nil {
		return out, err
	}
	var live bool
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE($1::timestamptz>clock_timestamp(),false)`, j.leaseUntil).Scan(&live); err != nil {
		return out, err
	}
	if j.Status == "running" && live && !j.RecoveryHold {
		return out, nil
	}
	out.CanCancel = !j.RecoveryRequired
	out.CanRollback = j.RecoveryRequired
	out.CanResume = (j.Status == "failed" || j.Status == "running" || j.RecoveryHold) && (j.Direction == "rollback" || user == j.Username && rev == j.accountRevision)
	return out, nil
}

func (s *Store) configurationApplicationDetail(ctx context.Context, v *Vault, user, id string, c *Config) (configurationApplicationView, error) {
	var out configurationApplicationView
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err = configurationBackupAdmin(ctx, tx, user); err != nil {
		return out, err
	}
	j, err := readApplicationTx(ctx, tx, v, id, false)
	if err != nil {
		return out, err
	}
	out.Job = j.public()
	out.configurationApplicationActions, err = applicationActionsTx(ctx, tx, c, user, j)
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}

type configurationApplicationLog struct {
	Cursor    int64     `json:"cursor,string"`
	Direction string    `json:"direction"`
	Phase     string    `json:"phase"`
	Code      string    `json:"code"`
	Created   time.Time `json:"created_at"`
}

func validApplicationLog(l configurationApplicationLog) bool {
	if l.Cursor < 1 || l.Direction != "forward" && l.Direction != "rollback" || l.Created.IsZero() {
		return false
	}
	phaseOK := l.Phase == "complete"
	phases := configurationApplicationForward
	if l.Direction == "rollback" {
		phases = configurationApplicationRollback
	}
	for _, p := range phases {
		if l.Phase == p {
			phaseOK = true
		}
	}
	switch l.Code {
	case "queued", "claimed", "takeover", "phase-complete", "recovery-armed", "resumed", "rollback-requested", "cancelled", "succeeded", "rolled-back", "environment-failed", "deployment-failed", "bootstrap-failed", "settings-failed", "verification-failed", "state-conflict", "runtime-unavailable", "interrupted":
		return phaseOK
	}
	return false
}

// Read metadata and bounded logs under the same snapshot. Journal signatures
// authenticate the upper cursor; fixed codes and continuity prevent a raw SQL
// log payload or missing record from becoming a misleading public progress log.
func (s *Store) configurationApplicationLogs(ctx context.Context, v *Vault, user, id string, after int64, limit int) (configurationApplicationJob, []configurationApplicationLog, error) {
	view, logs, err := s.configurationApplicationLogView(ctx, v, user, id, after, limit, nil)
	return view.Job, logs, err
}
func (s *Store) configurationApplicationLogView(ctx context.Context, v *Vault, user, id string, after int64, limit int, c *Config) (configurationApplicationView, []configurationApplicationLog, error) {
	var empty configurationApplicationView
	if after < 0 || limit < 1 || limit > 200 {
		return empty, nil, errApplicationCursor
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return empty, nil, err
	}
	defer tx.Rollback()
	if err = configurationBackupAdmin(ctx, tx, user); err != nil {
		return empty, nil, err
	}
	j, err := readApplicationTx(ctx, tx, v, id, false)
	if err != nil {
		return empty, nil, err
	}
	if after > j.LogCursor {
		return empty, nil, errApplicationCursor
	}
	rows, err := tx.QueryContext(ctx, `SELECT cursor,direction,phase,code,created_at FROM v3_configuration_application_logs WHERE job=$1 AND cursor>$2 AND cursor<=$3 ORDER BY cursor LIMIT $4`, id, after, j.LogCursor, limit)
	if err != nil {
		return empty, nil, err
	}
	logs := make([]configurationApplicationLog, 0)
	for rows.Next() {
		var l configurationApplicationLog
		if err = rows.Scan(&l.Cursor, &l.Direction, &l.Phase, &l.Code, &l.Created); err != nil {
			rows.Close()
			return empty, nil, err
		}
		if !validApplicationLog(l) || l.Cursor != after+int64(len(logs))+1 {
			rows.Close()
			return empty, nil, errConfigurationApplication
		}
		logs = append(logs, l)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return empty, nil, err
	}
	want := j.LogCursor - after
	if want > int64(limit) {
		want = int64(limit)
	}
	if int64(len(logs)) != want {
		return empty, nil, errConfigurationApplication
	}
	actions, err := applicationActionsTx(ctx, tx, c, user, j)
	if err != nil {
		return empty, nil, err
	}
	return configurationApplicationView{j.public(), actions}, logs, tx.Commit()
}

func (s *Store) configurationApplications(ctx context.Context, user string, before retentionCursor, stage string, limit int, load configurationApplicationVault) ([]configurationApplicationJob, error) {
	if limit < 1 || limit > 200 || stage != "" && !validArchiveSource(stage) {
		return nil, errConfigurationApplication
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = configurationBackupAdmin(ctx, tx, user); err != nil {
		return nil, err
	}
	stamp := before.Time
	if stamp.IsZero() {
		stamp = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+configurationApplicationColumns+` FROM v3_configuration_applications WHERE (created_at,id)<($1,$2) AND ($3='' OR stage=$3) ORDER BY created_at DESC,id DESC LIMIT $4`, stamp, before.ID, stage, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]configurationApplicationJob, 0)
	var v *Vault
	for rows.Next() {
		j, err := scanApplication(rows)
		if err != nil {
			return nil, err
		}
		if v == nil {
			if load == nil {
				return nil, errConfigurationApplication
			}
			v, err = load()
			if err != nil || v == nil {
				return nil, errConfigurationApplication
			}
		}
		if err = validateApplicationProof(v, j); err != nil {
			return nil, err
		}
		out = append(out, j.public())
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return out, tx.Commit()
}
