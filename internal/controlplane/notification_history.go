package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// Delivery payloads and provider responses may contain credentials or tokens.
// This read model deliberately exposes only the historical delivery metadata.
type NotificationRecord struct {
	State        string     `json:"state"`
	NextTry      *time.Time `json:"next_try"`
	ID           string     `json:"id"`
	Node         string     `json:"node"`
	Event        string     `json:"event_id"`
	Channel      string     `json:"channel"`
	Recipient    string     `json:"recipient"`
	Created      time.Time  `json:"created_at"`
	Completed    *time.Time `json:"done_at"`
	Attempts     int        `json:"attempts"`
	RecordKey    string     `json:"record_key"`
	CanDelete    bool       `json:"can_delete"`
	DeleteReason string     `json:"delete_reason"`
}
type notificationCursor struct {
	Time time.Time `json:"time"`
	ID   string    `json:"id"`
}

func (c notificationCursor) encode() string {
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}
func decodeNotificationCursor(raw string) (notificationCursor, error) {
	var c notificationCursor
	if raw == "" {
		return c, nil
	}
	if len(raw) > 512 {
		return c, errors.New("通知分页游标不正确")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(b, &c) != nil || c.Time.IsZero() {
		return c, errors.New("通知分页游标不正确")
	}
	n, err := strconv.ParseInt(c.ID, 10, 64)
	if err != nil || n < 1 || strconv.FormatInt(n, 10) != c.ID {
		return c, errors.New("通知分页游标不正确")
	}
	return c, nil
}

func (s *Store) NotificationHistory(ctx context.Context, channel, node, state string, start, end time.Time, before notificationCursor, limit int) ([]NotificationRecord, error) {
	if (channel != "feishu" && channel != "email") || (state != "" && state != "pending" && state != "completed") || limit < 1 || limit > 200 || start.IsZero() || !end.After(start) || end.Sub(start) > 31*24*time.Hour || (node != "" && !eventText(node, 512)) {
		return nil, ErrHistoryInput
	}
	if before.Time.IsZero() {
		before.Time = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		before.ID = "1"
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT t.id::text,t.node,t.event_id,t.channel,t.recipient,t.created_at,t.done_at,t.attempts,
 CASE WHEN t.done_at IS NOT NULL THEN 'completed'
 WHEN t.migration_pending THEN 'migration_pending'
 WHEN NOT COALESCE((SELECT payload->$1->'enabled'='true'::jsonb FROM v3_settings WHERE id=1),false) THEN 'paused'
 WHEN t.lease_owner IS NOT NULL AND t.lease_until>clock_timestamp() THEN 'sending'
 WHEN EXISTS(SELECT 1 FROM v3_notifications older WHERE older.node=t.node AND older.channel=t.channel AND older.recipient=t.recipient AND older.id<t.id AND older.done_at IS NULL) THEN 'waiting'
 WHEN t.attempts>0 THEN 'retrying' ELSE 'pending' END,
 CASE WHEN t.done_at IS NULL THEN t.next_try ELSE NULL END,`+historyDeleteReasonSQL(6, "t")+` FROM v3_notifications t WHERE t.channel=$1 AND ($2='' OR t.node=$2) AND ($3='' OR ($3='pending' AND t.done_at IS NULL) OR ($3='completed' AND t.done_at IS NOT NULL)) AND t.created_at >= $4 AND t.created_at <= $5 AND (t.created_at,t.id)<($6,$7::bigint) ORDER BY t.created_at DESC,t.id DESC LIMIT $8`, channel, node, state, start, end, before.Time, before.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotificationRecord{}
	for rows.Next() {
		var v NotificationRecord
		if err = rows.Scan(&v.ID, &v.Node, &v.Event, &v.Channel, &v.Recipient, &v.Created, &v.Completed, &v.Attempts, &v.State, &v.NextTry, &v.DeleteReason); err != nil {
			return nil, err
		}
		v.RecordKey = "notification:" + v.ID
		v.CanDelete = v.DeleteReason == ""
		out = append(out, v)
	}
	return out, rows.Err()
}

func (a *API) notificationHistoryRoutes(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/api/v3/notifications/stats" {
		a.consoleNotificationStats(w, r)
		return true
	}
	if r.URL.Path != "/api/v3/notifications" {
		return false
	}
	if r.Method != "GET" {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return true
	}
	limit, err := pageSize(r, 20)
	if err != nil {
		failure(w, 400, "invalid_limit", err.Error())
		return true
	}
	start, end, err := timeRange(r)
	if err != nil {
		failure(w, 400, "invalid_time", "时间范围不正确，最多 31 天")
		return true
	}
	before, err := decodeNotificationCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		failure(w, 400, "invalid_cursor", err.Error())
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	items, err := a.Store.NotificationHistory(ctx, r.URL.Query().Get("channel"), r.URL.Query().Get("node"), r.URL.Query().Get("state"), start, end, before, limit)
	if err != nil {
		historyFailure(w, err)
		return true
	}
	next := ""
	if len(items) == limit {
		last := items[len(items)-1]
		next = (notificationCursor{last.Created, last.ID}).encode()
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next, "start": start, "end": end, "limit": limit})
	return true
}
