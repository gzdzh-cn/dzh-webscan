package controlplane

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type retentionCursor struct {
	Time time.Time `json:"time"`
	ID   string    `json:"id"`
}

func (c retentionCursor) encode() string {
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}
func decodeRetentionCursor(raw string) (retentionCursor, error) {
	var c retentionCursor
	if raw == "" {
		return c, nil
	}
	if len(raw) > 512 {
		return c, errors.New("分页游标不正确")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(b, &c) != nil || c.Time.IsZero() || !validArchiveSource(c.ID) {
		return c, errors.New("分页游标不正确")
	}
	return c, nil
}
func (s *Store) RetentionJobs(ctx context.Context, before retentionCursor, limit int) ([]RetentionJob, error) {
	if limit < 1 || limit > 200 {
		return nil, errors.New("每页数量须为 1～200")
	}
	stamp := before.Time
	if stamp.IsZero() {
		stamp = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+retentionJobColumns+" FROM v3_retention_jobs WHERE (created_at,id)<($1,$2) ORDER BY created_at DESC,id DESC LIMIT $3", stamp, before.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []RetentionJob{}
	for rows.Next() {
		j, e := scanRetentionJob(rows)
		if e != nil {
			return nil, e
		}
		items = append(items, j)
	}
	return items, rows.Err()
}

type RetentionStatus struct {
	Policy       RetentionPolicyView `json:"policy"`
	Last         *RetentionJob       `json:"last_job"`
	StorageBytes int64               `json:"managed_storage_bytes"`
	Heartbeat    *time.Time          `json:"worker_heartbeat"`
	Healthy      *bool               `json:"worker_healthy"`
	Reason       string              `json:"reason"`
}

func (s *Store) RetentionStatus(ctx context.Context) (RetentionStatus, error) {
	var st RetentionStatus
	v, err := s.RetentionPolicy(ctx)
	if err != nil {
		return st, err
	}
	st.Policy = v
	jobs, err := s.RetentionJobs(ctx, retentionCursor{}, 1)
	if err != nil {
		return st, err
	}
	if len(jobs) > 0 {
		st.Last = &jobs[0]
	}
	// Sum only this application's tables and their indexes, not other projects
	// sharing a PostgreSQL instance. Reusable dead tuples remain counted.
	if err = s.DB.QueryRowContext(ctx, `SELECT COALESCE(sum(pg_total_relation_size(oid)),0)::bigint FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN ('r','p') AND left(relname,3)='v3_'`).Scan(&st.StorageBytes); err != nil {
		return st, err
	}
	var heartbeat time.Time
	var healthy bool
	err = s.DB.QueryRowContext(ctx, `SELECT heartbeat,error,heartbeat>clock_timestamp()-interval '20 seconds' AND error='' FROM v3_role_status WHERE role='retention' AND COALESCE(details->>'state','active')<>'standby' ORDER BY heartbeat DESC LIMIT 1`).Scan(&heartbeat, &st.Reason, &healthy)
	if err == nil {
		st.Heartbeat = &heartbeat
		st.Healthy = &healthy
	} else if err != sql.ErrNoRows {
		return st, err
	}
	return st, nil
}

func (a *API) retentionRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	if a.historyRoutes(w, r, id) {
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v3/retention/") {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	switch r.URL.Path {
	case "/api/v3/retention/policy":
		if r.Method == "GET" {
			v, err := a.Store.RetentionPolicy(ctx)
			if err != nil {
				failure(w, 503, "query_failed", "保留期限暂时不可用")
			} else {
				reply(w, 200, v)
			}
			return true
		}
		if r.Method != "PUT" {
			failure(w, 405, "method_not_allowed", "请使用 GET 或 PUT")
			return true
		}
		if id.Role != "admin" {
			failure(w, 403, "permission_denied", "只有管理员可以修改保留期限")
			return true
		}
		var in struct {
			Policy   RetentionPolicy `json:"policy"`
			Expected int64           `json:"expected_version"`
		}
		if decode(w, r, &in) != nil || in.Policy.Validate() != nil || in.Expected < 1 || !identifier.MatchString(r.Header.Get("Idempotency-Key")) {
			failure(w, 400, "invalid_policy", "保留期限须为 1～3650 天整数，并提供配置版本与幂等键")
			return true
		}
		before, err := a.configurationEditBackup()
		if err != nil {
			failure(w, 503, "before_edit_backup_failed", errConfigurationBeforeEdit.Error())
			return true
		}
		v, err := a.Store.saveRetentionPolicy(ctx, id.Username, r.Header.Get("Idempotency-Key"), in.Policy, in.Expected, before)
		switch {
		case err == nil:
			reply(w, 200, v)
		case errors.Is(err, errConfigurationBeforeEdit):
			failure(w, 503, "before_edit_backup_failed", errConfigurationBeforeEdit.Error())
		case errors.Is(err, ErrConfigurationBackupPermission):
			failure(w, 403, "permission_denied", "只有管理员可以修改保留期限")
		case errors.Is(err, ErrConflict) || errors.Is(err, ErrRequestConflict):
			failure(w, 409, "configuration_conflict", "配置或幂等请求已变化，请重新读取后提交")
		case errors.Is(err, ErrMigrationPending):
			failure(w, 503, "migration_pending", err.Error())
		default:
			failure(w, 503, "save_failed", "保留期限保存失败，未变更配置")
		}
	case "/api/v3/retention/status":
		if r.Method != "GET" {
			failure(w, 405, "method_not_allowed", "请使用 GET")
			return true
		}
		v, err := a.Store.RetentionStatus(ctx)
		if err != nil {
			failure(w, 503, "query_failed", "历史清理状态暂时不可用")
		} else {
			reply(w, 200, v)
		}
	case "/api/v3/retention/jobs":
		if r.Method != "GET" {
			failure(w, 405, "method_not_allowed", "请使用 GET")
			return true
		}
		limit, err := pageSize(r, 20)
		if err != nil {
			failure(w, 400, "invalid_limit", err.Error())
			return true
		}
		cursor, err := decodeRetentionCursor(r.URL.Query().Get("cursor"))
		if err != nil {
			failure(w, 400, "invalid_cursor", err.Error())
			return true
		}
		jobs, err := a.Store.RetentionJobs(ctx, cursor, limit)
		if err != nil {
			failure(w, 503, "query_failed", "清理历史暂时不可用")
			return true
		}
		next := ""
		if len(jobs) == limit {
			last := jobs[len(jobs)-1]
			next = (retentionCursor{last.Created, last.ID}).encode()
		}
		reply(w, 200, map[string]any{"items": jobs, "next_cursor": next, "limit": limit})
	default:
		failure(w, 404, "not_found", "接口不存在")
	}
	return true
}
