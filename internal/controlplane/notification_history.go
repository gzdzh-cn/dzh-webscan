package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"
)

// Delivery payloads and provider responses may contain credentials or tokens.
// This read model exposes delivery metadata and verified, bounded business text.
type NotificationRecord struct {
	Source        string     `json:"source"`
	Subject       string     `json:"subject"`
	Summary       string     `json:"summary"`
	ContentState  string     `json:"content_state"`
	ContentReason string     `json:"content_reason"`
	Truncated     bool       `json:"truncated"`
	State         string     `json:"state"`
	NextTry       *time.Time `json:"next_try"`
	ID            string     `json:"id"`
	Node          string     `json:"node"`
	Event         string     `json:"event_id"`
	Channel       string     `json:"channel"`
	Recipient     string     `json:"recipient"`
	Created       time.Time  `json:"created_at"`
	Completed     *time.Time `json:"done_at"`
	Attempts      int        `json:"attempts"`
	RecordKey     string     `json:"record_key"`
	CanDelete     bool       `json:"can_delete"`
	DeleteReason  string     `json:"delete_reason"`
}

type NotificationFilter struct {
	Channel, Node, State, DeliveryState, Source, Q, Recipient string
	Start, End                                                time.Time
	Before                                                    notificationCursor
	Limit                                                     int
}

func validNotificationDeliveryState(s string) bool {
	switch s {
	case "", "completed", "migration_pending", "paused", "sending", "waiting", "retrying", "pending":
		return true
	}
	return false
}

func (f NotificationFilter) valid() bool {
	return (f.Channel == "feishu" || f.Channel == "email") && (f.State == "" || f.State == "pending" || f.State == "completed") && validNotificationDeliveryState(f.DeliveryState) && (f.Source == "" || validNotificationSource(f.Source)) && f.Limit >= 1 && f.Limit <= 200 && !f.Start.IsZero() && f.End.After(f.Start) && f.End.Sub(f.Start) <= 31*24*time.Hour && (f.Node == "" || eventText(f.Node, 512)) && utf8.ValidString(f.Q) && len(f.Q) <= 200 && (f.Q == "" || eventText(f.Q, 200)) && (f.Recipient == "" || eventText(f.Recipient, 254))
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
	return s.NotificationHistoryFiltered(ctx, NotificationFilter{Channel: channel, Node: node, State: state, Start: start, End: end, Before: before, Limit: limit})
}

const notificationDeliveryStateSQL = `CASE WHEN t.done_at IS NOT NULL THEN 'completed'
 WHEN t.migration_pending THEN 'migration_pending'
 WHEN NOT COALESCE((SELECT payload->t.channel->'enabled'='true'::jsonb FROM v3_settings WHERE id=1),false) THEN 'paused'
 WHEN t.lease_owner IS NOT NULL AND t.lease_until>clock_timestamp() THEN 'sending'
 WHEN EXISTS(SELECT 1 FROM v3_notifications older WHERE older.node=t.node AND older.channel=t.channel AND older.recipient=t.recipient AND older.id<t.id AND older.done_at IS NULL) THEN 'waiting'
 WHEN t.attempts>0 THEN 'retrying' ELSE 'pending' END`

const notificationRecordColumns = `t.id::text,t.node,t.event_id,t.channel,t.recipient,t.created_at,t.done_at,t.attempts,t.delivery_state,
 CASE WHEN t.done_at IS NULL THEN t.next_try ELSE NULL END,t.public_delete_reason,t.public_source,t.public_subject,t.public_summary,t.public_content_state,t.public_content_reason,t.public_truncated`

func scanNotificationRecord(row interface{ Scan(...any) error }) (NotificationRecord, error) {
	var v NotificationRecord
	err := row.Scan(&v.ID, &v.Node, &v.Event, &v.Channel, &v.Recipient, &v.Created, &v.Completed, &v.Attempts, &v.State, &v.NextTry, &v.DeleteReason, &v.Source, &v.Subject, &v.Summary, &v.ContentState, &v.ContentReason, &v.Truncated)
	v.RecordKey = "notification:" + v.ID
	v.CanDelete = v.DeleteReason == ""
	return v, err
}

func notificationHistoryReadSQL() string {
	return `(SELECT t.*,` + notificationDeliveryStateSQL + ` delivery_state FROM ` + notificationPublicReadSQL() + ` t)`
}

func (s *Store) NotificationHistoryFiltered(ctx context.Context, f NotificationFilter) ([]NotificationRecord, error) {
	if !f.valid() {
		return nil, ErrHistoryInput
	}
	before := f.Before
	if before.Time.IsZero() {
		before.Time = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		before.ID = "1"
	}
	if _, err := decodeNotificationCursor(before.encode()); err != nil {
		return nil, ErrHistoryInput
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT `+notificationRecordColumns+` FROM `+notificationHistoryReadSQL()+` t WHERE t.channel=$1 AND ($2='' OR t.node=$2) AND ($3='' OR ($3='pending' AND t.done_at IS NULL) OR ($3='completed' AND t.done_at IS NOT NULL)) AND t.created_at >= $4 AND t.created_at <= $5 AND (t.created_at,t.id)<($6,$7::bigint)
 AND ($8='' OR t.public_source=$8) AND ($9='' OR t.recipient=$9) AND ($10='' OR t.delivery_state=$10)
 AND ($11='' OR (t.public_content_state='available' AND strpos(lower(t.public_subject||E'\n'||t.public_summary||E'\n'||t.public_body),lower($11))>0))
 ORDER BY t.created_at DESC,t.id DESC LIMIT $12`, f.Channel, f.Node, f.State, f.Start, f.End, before.Time, before.ID, f.Source, f.Recipient, f.DeliveryState, f.Q, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotificationRecord{}
	for rows.Next() {
		v, e := scanNotificationRecord(rows)
		if e != nil {
			return nil, e
		}
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
	q := r.URL.Query()
	items, err := a.Store.NotificationHistoryFiltered(ctx, NotificationFilter{Channel: q.Get("channel"), Node: q.Get("node"), State: q.Get("state"), Source: q.Get("source"), Q: q.Get("q"), Recipient: q.Get("recipient"), DeliveryState: q.Get("delivery_state"), Start: start, End: end, Before: before, Limit: limit})
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
