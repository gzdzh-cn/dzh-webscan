package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

var ErrMigrationSession = errors.New("迁移会话、来源、检查点或冻结证据不匹配；迁移保护保持启用")
var ErrMigrationCutoverProtected = errors.New("最终映射及保留新增数据的回退尚未验收，禁止解除迁移保护")

type MigrationSession struct {
	ID               string                    `json:"id"`
	Version          int64                     `json:"version"`
	Roles            []string                  `json:"roles"`
	RecoveryHold     bool                      `json:"recovery_hold"`
	Phase            string                    `json:"phase"`
	Protected        bool                      `json:"protected"`
	ProtectionReason string                    `json:"protection_reason"`
	FreezeDigest     string                    `json:"freeze_digest,omitempty"`
	FreezeAt         *time.Time                `json:"freeze_at,omitempty"`
	Revisions        []MigrationRevisionReport `json:"revisions"`
}

func migrationRoles(roles []string) ([]string, error) {
	if len(roles) == 0 || len(roles) > 8 {
		return nil, ErrMigrationSession
	}
	out := append([]string{}, roles...)
	sort.Strings(out)
	for i, v := range out {
		if v != "central" && v != "health" && v != "host-manager" {
			return nil, ErrMigrationSession
		}
		if i > 0 && v == out[i-1] {
			return nil, ErrMigrationSession
		}
	}
	return out, nil
}
func migrationSessionLock(ctx context.Context, tx *sql.Tx, id string) error {
	if !validArchiveSource(id) {
		return ErrMigrationSession
	}
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "migration-session:"+id)
	return err
}
func migrationSessionTx(ctx context.Context, tx *sql.Tx, id string) (MigrationSession, error) {
	out := MigrationSession{ID: id, Protected: true, ProtectionReason: "cutover_and_lossless_rollback_not_verified", Revisions: []MigrationRevisionReport{}}
	var roles []byte
	var freeze sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT version,roles,phase,freeze_digest,freeze_at,recovery_hold FROM v3_migration_sessions WHERE id=$1 FOR UPDATE`, id).Scan(&out.Version, &roles, &out.Phase, &out.FreezeDigest, &freeze, &out.RecoveryHold)
	if err != nil {
		return out, err
	}
	if json.Unmarshal(roles, &out.Roles) != nil {
		return out, ErrMigrationSession
	}
	if freeze.Valid {
		out.FreezeAt = &freeze.Time
	}
	if out.Phase == "active" && !out.RecoveryHold {
		var held bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending)`).Scan(&held); err != nil {
			return out, err
		}
		if !held {
			out.Protected, out.ProtectionReason = false, ""
		}
	}
	if out.Phase == "rolled_back" {
		out.ProtectionReason = "legacy_output_verified_target_remains_frozen"
	}
	return out, nil
}
func (s *Store) beginMigrationSession(ctx context.Context, id string, expected int64, roles []string) (MigrationSession, error) {
	if expected != 0 {
		return MigrationSession{}, ErrConflict
	}
	roles, err := migrationRoles(roles)
	if err != nil {
		return MigrationSession{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return MigrationSession{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(773376002)`); err != nil {
		return MigrationSession{}, err
	}
	if err = migrationSessionLock(ctx, tx, id); err != nil {
		return MigrationSession{}, err
	}
	raw, _ := json.Marshal(roles)
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_migration_sessions(id,roles) VALUES($1,$2) ON CONFLICT(id) DO NOTHING`, id, raw); err != nil {
		return MigrationSession{}, err
	}
	out, err := migrationSessionTx(ctx, tx, id)
	if err != nil {
		return out, err
	}
	if out.RecoveryHold || out.Phase == "active" || out.Phase == "rolled_back" {
		return out, ErrMigrationSession
	}
	got, _ := json.Marshal(out.Roles)
	if string(got) != string(raw) {
		return out, ErrMigrationSession
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_migration_domains(domain,source,pending) VALUES($1,$2,true) ON CONFLICT(domain) DO NOTHING`, "session:"+id, id); err != nil {
		return out, err
	}
	var protected bool
	if tx.QueryRowContext(ctx, `SELECT pending AND source=$2 FROM v3_migration_domains WHERE domain=$1`, "session:"+id, id).Scan(&protected) != nil || !protected {
		return out, ErrMigrationSession
	}
	return out, tx.Commit()
}
func (s *Store) migrationSession(ctx context.Context, id string) (MigrationSession, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return MigrationSession{}, err
	}
	defer tx.Rollback()
	if err = migrationSessionLock(ctx, tx, id); err != nil {
		return MigrationSession{}, err
	}
	out, err := migrationSessionTx(ctx, tx, id)
	if err != nil {
		return out, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,role,snapshot_sha256,sequence,state,records,index_digest FROM v3_migration_revisions WHERE session=$1 ORDER BY role,sequence`, id)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var r MigrationRevisionReport
		if err = rows.Scan(&r.ID, &r.Role, &r.Source, &r.Sequence, &r.State, &r.Records, &r.Digest); err != nil {
			break
		}
		r.SessionVersion = out.Version
		out.Revisions = append(out.Revisions, r)
	}
	e := rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if e != nil {
		return out, e
	}
	return out, tx.Commit()
}
func migrationSessionRole(s MigrationSession, role string) bool {
	for _, v := range s.Roles {
		if v == role {
			return true
		}
	}
	return false
}

// A caller without private freeze, Vault and actual reverse-output evidence
// cannot authorize either transition. Host CLI uses the WithEvidence methods.
func (s *Store) ActivateMigrationSession(context.Context, string, int64) error {
	return ErrMigrationCutoverProtected
}
func (s *Store) RollbackMigrationSession(context.Context, string, int64) error {
	return ErrMigrationCutoverProtected
}
