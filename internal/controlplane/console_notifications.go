package controlplane

import (
	"context"
	"net/http"
	"time"
)

// Fixed seven-day buckets, scoped to the same channel/node as the history list.
// Only counts leave the database; delivery payloads and provider replies do not.
func (a *API) consoleNotificationStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return
	}
	channel, node := r.URL.Query().Get("channel"), r.URL.Query().Get("node")
	if (channel != "feishu" && channel != "email") || (node != "" && !eventText(node, 512)) {
		failure(w, 400, "invalid_filter", "通知通道或服务器筛选不正确")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rows, err := a.Store.DB.QueryContext(ctx, `WITH days AS (
 SELECT generate_series((clock_timestamp() AT TIME ZONE 'Asia/Shanghai')::date-6,(clock_timestamp() AT TIME ZONE 'Asia/Shanghai')::date,interval '1 day')::date AS day
 ), totals AS (
 SELECT (created_at AT TIME ZONE 'Asia/Shanghai')::date AS day,
 count(*) FILTER(WHERE done_at IS NOT NULL) delivered,
 count(*) FILTER(WHERE done_at IS NULL AND attempts=0) pending,
 count(*) FILTER(WHERE done_at IS NULL AND attempts>0) retrying
 FROM v3_notifications WHERE channel=$1 AND ($2='' OR node=$2)
 AND created_at>=((clock_timestamp() AT TIME ZONE 'Asia/Shanghai')::date-6)::timestamp AT TIME ZONE 'Asia/Shanghai'
 AND created_at<=clock_timestamp() GROUP BY 1
 ) SELECT days.day::text,COALESCE(t.delivered,0),COALESCE(t.pending,0),COALESCE(t.retrying,0) FROM days LEFT JOIN totals t USING(day) ORDER BY days.day`, channel, node)
	if err != nil {
		failure(w, 503, "query_failed", "通知统计暂时不可用")
		return
	}
	defer rows.Close()
	type bucket struct {
		Day       string `json:"day"`
		Delivered int64  `json:"delivered"`
		Pending   int64  `json:"pending"`
		Retrying  int64  `json:"retrying"`
	}
	items := []bucket{}
	for rows.Next() {
		var b bucket
		if err = rows.Scan(&b.Day, &b.Delivered, &b.Pending, &b.Retrying); err != nil {
			failure(w, 503, "query_failed", "通知统计暂时不可用")
			return
		}
		items = append(items, b)
	}
	if rows.Err() != nil {
		failure(w, 503, "query_failed", "通知统计暂时不可用")
		return
	}
	reply(w, 200, map[string]any{"items": items, "timezone": "Asia/Shanghai", "group_by": "created_at", "node": node, "channel": channel})
}
