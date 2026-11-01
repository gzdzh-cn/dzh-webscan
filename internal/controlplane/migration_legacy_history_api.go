package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

type migrationHistorySessionItem struct {
	ID             string          `json:"id"`
	Phase          string          `json:"phase"`
	CreatedAt      time.Time       `json:"created_at"`
	HistoryRecords int64           `json:"history_records"`
	Generations    json.RawMessage `json:"generations"`
}

// Public reads contain no private source paths, original logs, credentials or
// executable authority. A listed session is not an activation permit.
func (a *API) legacyMigrationHistory(w http.ResponseWriter, r *http.Request, id identity, sessions bool) {
	if r.Method != http.MethodGet {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return
	}
	if id.Role != "admin" {
		failure(w, 403, "permission_denied", "只有管理员可以核对旧版迁移历史")
		return
	}
	q := r.URL.Query()
	allowed := map[string]bool{"session": true, "role": true, "table": true, "cursor": true, "limit": true}
	for key, values := range q {
		if sessions || !allowed[key] || len(values) != 1 || len(values[0]) > 128 {
			failure(w, 400, "invalid_migration_history_query", "迁移历史查询参数不正确")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if sessions {
		rows, err := a.Store.DB.QueryContext(ctx, `SELECT s.id,s.phase,s.created_at,(SELECT count(*) FROM v3_legacy_history h WHERE h.session=s.id),coalesce((SELECT jsonb_agg(jsonb_build_object('generation',m.id,'revision',m.revision,'state',m.state) ORDER BY m.created_at DESC) FROM v3_migration_metric_runs m WHERE m.session=s.id),'[]'::jsonb) FROM v3_migration_sessions s ORDER BY s.created_at DESC,s.id LIMIT 100`)
		if err != nil {
			failure(w, 503, "migration_history_unavailable", "迁移历史暂不可用")
			return
		}
		defer rows.Close()
		items := []migrationHistorySessionItem{}
		for rows.Next() {
			var v migrationHistorySessionItem
			if rows.Scan(&v.ID, &v.Phase, &v.CreatedAt, &v.HistoryRecords, &v.Generations) != nil {
				failure(w, 503, "migration_history_unavailable", "迁移历史暂不可用")
				return
			}
			items = append(items, v)
		}
		if rows.Err() != nil {
			failure(w, 503, "migration_history_unavailable", "迁移历史暂不可用")
			return
		}
		reply(w, 200, map[string]any{"items": items, "limit": 100, "read_only": true})
		return
	}
	limit := 20
	if text := q.Get("limit"); text != "" {
		var err error
		limit, err = strconv.Atoi(text)
		if err != nil || limit < 1 || limit > 200 {
			failure(w, 400, "invalid_migration_history_query", "每页支持1至200条")
			return
		}
	}
	if !validArchiveSource(q.Get("session")) || q.Get("cursor") != "" && !validArchiveSource(q.Get("cursor")) || q.Get("role") != "" && q.Get("role") != "central" && q.Get("role") != "host-manager" {
		failure(w, 400, "invalid_migration_history_query", "迁移会话、来源或游标不正确")
		return
	}
	if table := q.Get("table"); table != "" {
		if _, ok := migrationLegacyHistoryTables[table]; !ok {
			failure(w, 400, "invalid_migration_history_query", "请选择固定历史类型")
			return
		}
	}
	result, err := a.Store.ListMigrationLegacyHistory(ctx, q.Get("session"), q.Get("role"), q.Get("table"), q.Get("cursor"), limit)
	if err != nil {
		failure(w, 503, "migration_history_unavailable", "迁移历史暂不可用，已有结果保留")
		return
	}
	reply(w, 200, result)
}
