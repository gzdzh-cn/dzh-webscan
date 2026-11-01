package controlplane

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// A staged generation is visible only through an administrator's explicit
// selection. It never silently becomes a live metric or changes a cursor.
func (a *API) migrationMetricHistory(w http.ResponseWriter, r *http.Request, id identity) {
	if r.Method != http.MethodGet {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return
	}
	if id.Role != "admin" {
		failure(w, 403, "permission_denied", "只有管理员可以核对迁移历史")
		return
	}
	q, queryError := url.ParseQuery(r.URL.RawQuery)
	if queryError != nil {
		failure(w, 400, "invalid_migration_history_query", "查询参数编码不正确")
		return
	}
	allowed := map[string]bool{"session": true, "generation": true, "node": true, "metric": true, "dimension": true, "start": true, "end": true}
	for name, values := range q {
		if !allowed[name] || len(values) != 1 || len(values[0]) > 512 {
			failure(w, 400, "invalid_migration_history_query", "请使用唯一的迁移历史查询参数")
			return
		}
	}
	for _, name := range []string{"session", "generation", "node", "metric", "start", "end"} {
		if q.Get(name) == "" {
			failure(w, 400, "invalid_migration_history_query", "请选择迁移会话、已核对批次、节点、指标和时间范围")
			return
		}
	}
	start, end, err := timeRange(r)
	key := q.Get("metric")
	if q.Get("dimension") != "" {
		key += ":" + q.Get("dimension")
	}
	_, _, _, metricOK := migrationLegacyMetric(key)
	if err != nil || !end.After(start) || end.Sub(start) > 31*24*time.Hour || !validArchiveSource(q.Get("session")) || !validArchiveSource(q.Get("generation")) || !identifier.MatchString(q.Get("node")) || !metricOK {
		failure(w, 400, "invalid_migration_history_query", "迁移历史参数不正确；仅支持固定指标及最多31天范围")
		return
	}
	if a.Metrics == nil {
		failure(w, 503, "metrics_unavailable", "历史指标服务暂不可用")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	result, err := a.Store.MigrationMetricHistory(ctx, a.Metrics, q.Get("session"), q.Get("generation"), q.Get("node"), q.Get("metric"), q.Get("dimension"), start, end)
	if err != nil {
		failure(w, 409, "migration_history_unverified", "旧历史尚未通过一致性核对，或迁移批次、时序库状态已变化")
		return
	}
	reply(w, 200, result)
}
